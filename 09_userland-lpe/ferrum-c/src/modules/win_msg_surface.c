/*
 * win_msg_surface.c — Window Message / WM_COPYDATA Cross-IL Surface Audit
 *
 * WHY THIS IS A 0-DAY GOLDMINE:
 *   Windows User Interface Privilege Isolation (UIPI) prevents lower-IL
 *   processes from sending messages to higher-IL windows. However, if a
 *   High-IL process explicitly calls:
 *
 *     ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ALLOW)        [per-process, deprecated]
 *     ChangeWindowMessageFilterEx(hwnd, WM_COPYDATA, MSGFLT_ALLOW, NULL) [per-window]
 *
 *   Then any Medium-IL (standard user) process can send WM_COPYDATA to that
 *   High-IL window and trigger arbitrary command execution.
 *
 * HISTORICAL 0-DAY IN THIS RESEARCH:
 *   ArmourySwAgent.exe (ASUS Armoury Crate) — discovered in this same project:
 *   - High IL process with ChangeWindowMessageFilter(WM_COPYDATA, MSGFLT_ALLOW)
 *   - WM_COPYDATA dwData=163 → LaunchProgram → ShellExecuteEx at High IL
 *   - Path check bypass via forward slashes
 *   - Full Medium → High IL escalation, no UAC prompt
 *
 * DETECTION METHODOLOGY:
 *   1. Enumerate all top-level windows (EnumWindows)
 *   2. GetWindowThreadProcessId → check owner process integrity level
 *   3. For High-IL windows: probe WM_COPYDATA via SendMessageTimeout
 *      - If NOT blocked (no ERROR_ACCESS_DENIED): UIPI filter is relaxed
 *      - Windows with relaxed WM_COPYDATA filter = attack surface
 *   4. Also probe: WM_DDE_INITIATE (DDE cross-IL injection), WM_DROPFILES
 *
 * EXPLOIT CLASS:
 *   - Map window class → owning module (GetWindowModuleFileNameW)
 *   - Reverse the message handler: switch(dwData) dispatch table
 *   - Each command ID is a separate attack vector
 *   - Look for: ShellExecute/CreateProcess with user-controlled path
 *     (especially when the "validation" is string-based like ":\\" check)
 *
 * ADDITIONAL SURFACES CHECKED:
 *   - DDE (Dynamic Data Exchange): WM_DDE_INITIATE cross-IL
 *   - WM_DROPFILES: drag-and-drop injection (older technique)
 *   - Broadcast messages to all windows (HWND_BROADCAST abuse)
 *
 * REFERENCES:
 *   ArmourySwAgent 0-day: researchhh/0DAY_ARMOURY_SWAGENT_LPE.md
 *   UIPI: https://docs.microsoft.com/en-us/windows/win32/winmsg/window-message-filter
 *   ChangeWindowMessageFilterEx: KB2765212
 */

#include "../common.h"

#define WM_COPYDATA     0x004A
#define WM_DDE_INITIATE 0x03E0
#define WM_DROPFILES    0x0233

/* Integrity level RIDs */
#define SECURITY_MANDATORY_MEDIUM_RID 0x2000
#define SECURITY_MANDATORY_HIGH_RID   0x3000
#define SECURITY_MANDATORY_SYSTEM_RID 0x4000

/* Per-window: tracks accessible High-IL windows */
typedef struct {
    DWORD   findings;
    DWORD   highILCount;
    DWORD   accessibleWmCopy;
    DWORD   accessibleDDE;
} WMsgCtx;

/* -----------------------------------------------------------------------
 * Get integrity level RID of a process
 * --------------------------------------------------------------------- */
static DWORD GetProcIL(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return 0;
    DWORD rid = GetProcessIntegrityRID(hProc);
    CloseHandle(hProc);
    return rid;
}

/* -----------------------------------------------------------------------
 * Probe: can Medium-IL send WM_COPYDATA to this window?
 * Uses benign null payload; timeout = 50ms to avoid hangs.
 * --------------------------------------------------------------------- */
static BOOL ProbeWmCopyData(HWND hwnd) {
    COPYDATASTRUCT cds = { 0, 0, NULL };
    SetLastError(0);
    DWORD_PTR result = 0;
    SendMessageTimeoutW(hwnd, WM_COPYDATA, (WPARAM)NULL, (LPARAM)&cds,
                        SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT, 50, &result);
    DWORD err = GetLastError();
    /* UIPI blocks → err == ERROR_ACCESS_DENIED (5)
       UIPI allows  → err == 0 or any other non-5 code               */
    return (err != ERROR_ACCESS_DENIED);
}

/* -----------------------------------------------------------------------
 * Probe: can Medium-IL send WM_DDE_INITIATE?
 * --------------------------------------------------------------------- */
static BOOL ProbeWmDDE(HWND hwnd) {
    SetLastError(0);
    DWORD_PTR result = 0;
    SendMessageTimeoutW(hwnd, WM_DDE_INITIATE, (WPARAM)NULL, (LPARAM)NULL,
                        SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT, 50, &result);
    return (GetLastError() != ERROR_ACCESS_DENIED);
}

/* -----------------------------------------------------------------------
 * Get the owning process EXE path for a window
 * --------------------------------------------------------------------- */
static void GetWindowExePath(DWORD pid, LPWSTR buf, DWORD cch) {
    buf[0] = L'\0';
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;
    DWORD cb = cch;
    QueryFullProcessImageNameW(h, 0, buf, &cb);
    CloseHandle(h);
}

/* -----------------------------------------------------------------------
 * EnumWindows callback
 * --------------------------------------------------------------------- */
static BOOL CALLBACK WindowEnumProc(HWND hwnd, LPARAM lParam) {
    WMsgCtx *ctx = (WMsgCtx *)lParam;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (!pid) return TRUE;

    DWORD il = GetProcIL(pid);

    /* Only care about High IL and above (3000 = High, 4000 = System) */
    if (il < SECURITY_MANDATORY_HIGH_RID) return TRUE;
    ctx->highILCount++;

    /* Get window class and title for identification */
    wchar_t className[256] = {0};
    wchar_t title[256]     = {0};
    GetClassNameW(hwnd, className, _countof(className));
    GetWindowTextW(hwnd, title, _countof(title));

    /* Get owner module */
    wchar_t exePath[MAX_PATH * 2] = {0};
    GetWindowExePath(pid, exePath, _countof(exePath));

    /* Extract just the EXE filename */
    wchar_t *exeName = wcsrchr(exePath, L'\\');
    if (exeName) exeName++; else exeName = exePath;

    /* Probe WM_COPYDATA */
    BOOL copyOk = ProbeWmCopyData(hwnd);
    BOOL ddeOk  = ProbeWmDDE(hwnd);

    if (copyOk) {
        ctx->accessibleWmCopy++;
        ctx->findings++;

        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"WIN_MSG");
        _snwprintf(f.target, _countof(f.target),
            L"[WM_COPYDATA] HWND:0x%p  PID:%lu  %s",
            (void*)hwnd, pid, exeName);
        _snwprintf(f.reason, _countof(f.reason),
            L"HIGH-IL window ACCEPTS WM_COPYDATA from Medium IL. "
            L"Process: %s (IL=0x%04lX)\n"
            L"        Class: '%s'  Title: '%s'\n"
            L"        RESEARCH: Reverse %s → find window proc → switch(dwData) dispatch.\n"
            L"        Look for: ShellExecute/CreateProcess with user-controlled parameter.\n"
            L"        PoC: FindWindow(\"%s\") → SendMessage(hwnd, WM_COPYDATA, 0, &cds)\n"
            L"        Technique: ArmourySwAgent class (see 0DAY_ARMOURY_SWAGENT_LPE.md)",
            exePath, il, className, title,
            exeName, className);
        PrintFinding(&f);
    }

    if (ddeOk && !copyOk) {
        /* DDE accessible but WM_COPYDATA wasn't → still interesting */
        ctx->accessibleDDE++;
        ctx->findings++;

        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"WIN_MSG");
        _snwprintf(f.target, _countof(f.target),
            L"[WM_DDE_INITIATE] HWND:0x%p  PID:%lu  %s",
            (void*)hwnd, pid, exeName);
        _snwprintf(f.reason, _countof(f.reason),
            L"High-IL window accepts WM_DDE_INITIATE from Medium IL. "
            L"Process: %s (IL=0x%04lX)  Class: '%s'\n"
            L"        DDE cross-IL: can initiate DDE conversation → inject commands.\n"
            L"        Technique: DDE server impersonation / command injection.",
            exePath, il, className);
        PrintFinding(&f);
    }

    return TRUE; /* continue enum */
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_WinMsgSurface(void) {
    PrintHeader(
        L"WINDOW MESSAGE CROSS-IL SURFACE  [WM_COPYDATA / DDE UIPI bypass audit]");

    PrintInfo(
        L"  Probes High-IL process windows for relaxed UIPI message filters.\n"
        L"  A High-IL window accepting WM_COPYDATA from Medium IL = LPE surface.\n"
        L"  Class: ArmourySwAgent 0-day (discovered in this project).\n\n");

    WMsgCtx ctx = {0};
    EnumWindows(WindowEnumProc, (LPARAM)&ctx);

    PrintInfo(L"  High-IL windows enumerated: %lu\n", ctx.highILCount);
    PrintInfo(L"  WM_COPYDATA accessible:     %lu\n", ctx.accessibleWmCopy);
    PrintInfo(L"  WM_DDE_INITIATE accessible: %lu\n\n", ctx.accessibleDDE);

    if (ctx.findings == 0) {
        PrintInfo(L"  No accessible cross-IL message windows found.\n");
    } else {
        PrintInfo(
            L"  EXPLOITATION WORKFLOW:\n"
            L"    1. Identify the window class and title of the flagged window\n"
            L"    2. Load owning EXE/DLL in IDA Pro or dnSpy (.NET)\n"
            L"    3. Find WndProc or message handler:\n"
            L"       - For Win32: search for WM_COPYDATA (0x4A) in switch tables\n"
            L"       - For .NET: find WndProc override, look for switch on Message.LParam.dwData\n"
            L"    4. For each command ID in the switch table:\n"
            L"       - Trace to what it executes (CreateProcess/ShellExecute/WinExec)\n"
            L"       - Check if the path/command is user-controlled or validated\n"
            L"       - Common validation bypass: string-based checks ('.Contains()') "
            L"          vs canonical path normalization\n"
            L"    5. Craft minimal PoC:\n"
            L"       FindWindowW(L\"<ClassName>\", NULL) → SendMessage WM_COPYDATA\n"
            L"    6. Test from Medium IL process (standard cmd.exe)\n"
            L"    Reference: 0DAY_ARMOURY_SWAGENT_LPE.md for full worked example\n");
    }
}

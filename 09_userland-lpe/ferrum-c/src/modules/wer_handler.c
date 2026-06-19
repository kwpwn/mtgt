/*
 * wer_handler.c — Windows Error Reporting / AeDebug Surface Audit
 *
 * WHY THIS IS UNEXPLORED 0-DAY SURFACE:
 *   No public automated tool (WinPEAS, PowerUp, Seatbelt, Ferrum-Go) checks
 *   the Windows Error Reporting (WER) and Just-In-Time (JIT) debugger attack surface.
 *
 * SURFACE 1: AeDebug — Just-In-Time (JIT) Debugger
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\Debugger
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug\Auto
 *
 *   When ANY process crashes, Windows (as SYSTEM) launches the debugger
 *   specified in AeDebug\Debugger. If:
 *     a) The Debugger path is writable → replace with payload → wait for crash → SYSTEM
 *     b) The AeDebug key is writable → change Debugger to our payload
 *     c) Auto = 1 → debugger launches without prompting user
 *
 *   Format: "debugger.exe -p %ld -e %ld -g" (%ld = PID / event handle)
 *
 * SURFACE 2: WER RuntimeExceptionHelperModules
 *   HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules\
 *   Contains DLLs loaded by WER service (WerSvc, runs as SYSTEM) when processing crashes.
 *   Third-party crash handlers (game anti-cheats, monitoring tools) register here.
 *   If any registered DLL is writable → SYSTEM code execution on crash.
 *
 * SURFACE 3: WER LocalDumps — Custom Dump Handler
 *   HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\
 *   HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\<app.exe>\
 *   DumpFolder = path where crash dumps are written (SYSTEM creates files here)
 *   DumpType   = 2 = full dump
 *   If DumpFolder is user-writable: SYSTEM writes files there → TOCTOU opportunity
 *
 * SURFACE 4: WER Consent / WerSvc DLL loading
 *   WerSvc loads various helper DLLs from paths registered under WER.
 *   Any such DLL in a writable location = SYSTEM code exec on crash trigger.
 *
 * SURFACE 5: Custom Crash Handlers via WER Registered Executables
 *   HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\<app>\
 *   CustomDumpFlags, DumpFolder: can redirect dump path
 *   Some third-party installers set these to user-writable paths.
 *
 * TRIGGER:
 *   For AeDebug: simply crash any process → taskkill /f /pid <any_pid>
 *   For WER DLLs: crash a process → WerSvc activates → loads registered DLLs
 *   Easy reproducible crash: rundll32.exe ThisDLLDoesNotExist,Foo
 *
 * REFERENCES:
 *   AeDebug: https://docs.microsoft.com/en-us/windows/win32/debug/configuring-automatic-debugging
 *   WER: https://docs.microsoft.com/en-us/windows/win32/wer/
 *   MITRE ATT&CK: T1546.012 — Event Triggered Execution: Image File Execution Options
 *   lolbas: wercontr.exe, werfault.exe (WER-related lolbins)
 */

#include "../common.h"

#define AEDBUG_KEY    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug"
#define WER_KEY       L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"
#define WER_RTEH_KEY  L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\RuntimeExceptionHelperModules"
#define WER_DUMPS_KEY L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps"

/* -----------------------------------------------------------------------
 * Surface 1: AeDebug JIT Debugger
 * --------------------------------------------------------------------- */
static void AuditAeDebug(DWORD *findings) {
    PrintInfo(L"  [1] AeDebug JIT Debugger:\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, AEDBUG_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        PrintInfo(L"    AeDebug key not accessible.\n\n");
        return;
    }

    wchar_t debugger[MAX_PATH * 2] = {0};
    wchar_t autoVal[8]             = {0};
    DWORD cb = sizeof(debugger), type = 0;

    RegQueryValueExW(hKey, L"Debugger", NULL, &type, (LPBYTE)debugger, &cb);
    cb = sizeof(autoVal);
    RegQueryValueExW(hKey, L"Auto",     NULL, &type, (LPBYTE)autoVal, &cb);
    RegCloseKey(hKey);

    PrintInfo(L"    Debugger: %s\n", *debugger ? debugger : L"(not set)");
    PrintInfo(L"    Auto:     %s\n\n", *autoVal ? autoVal : L"(not set)");

    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, AEDBUG_KEY);

    if (keyWritable) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"WER");
        wcscpy(f.target, L"[KEY WRITABLE] AeDebug JIT Debugger registry");
        _snwprintf(f.reason, _countof(f.reason),
            L"AeDebug registry key is WRITABLE by current user. "
            L"Change Debugger value to payload → ANY process crash → SYSTEM code exec. "
            L"Current: '%s'  Auto='%s'\n"
            L"        Attack:\n"
            L"          reg add \"HKLM\\%s\" /v Debugger /d \"C:\\payload.exe -p %%ld -e %%ld\" /f\n"
            L"          reg add \"HKLM\\%s\" /v Auto /d \"1\" /f\n"
            L"          rundll32.exe FakeLib,Crash  [trigger crash]\n"
            L"        payload.exe runs as SYSTEM (via WerFault.exe elevated launch)",
            debugger, autoVal, AEDBUG_KEY, AEDBUG_KEY);
        PrintFinding(&f);
        (*findings)++;
        return;
    }

    /* Check if the debugger EXE path is writable */
    if (*debugger) {
        wchar_t exePath[MAX_PATH * 2] = {0};
        ExtractExePath(debugger, exePath, _countof(exePath));
        if (*exePath && IsFileWritable(exePath)) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"WER");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE DEBUGGER] AeDebug: %s", exePath);
            _snwprintf(f.reason, _countof(f.reason),
                L"AeDebug JIT Debugger EXE is WRITABLE: %s\n"
                L"        Replace this EXE with payload → any process crash → "
                L"payload runs as SYSTEM (via WerFault.exe with elevated token).\n"
                L"        Auto=%s (1 = no user prompt = silent execution).",
                exePath, autoVal);
            PrintFinding(&f);
            (*findings)++;
        }
    }
}

/* -----------------------------------------------------------------------
 * Surface 2: WER RuntimeExceptionHelperModules
 * --------------------------------------------------------------------- */
static void AuditWERHelperModules(DWORD *findings) {
    PrintInfo(L"  [2] WER RuntimeExceptionHelperModules:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WER_RTEH_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (key not present)\n\n");
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t valueName[MAX_PATH * 2];
    DWORD   nameCch;
    wchar_t valueData[MAX_PATH * 2];
    DWORD   dataCb;
    DWORD   type;

    while (TRUE) {
        nameCch = _countof(valueName);
        dataCb  = sizeof(valueData);
        LONG r = RegEnumValueW(hRoot, idx++, valueName, &nameCch,
                               NULL, &type, (LPBYTE)valueData, &dataCb);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        /* valueName IS the DLL path in some Windows versions */
        wchar_t dllPath[MAX_PATH * 2] = {0};
        if (type == REG_SZ && *valueData)
            wcsncpy(dllPath, valueData, _countof(dllPath) - 1);
        else
            wcsncpy(dllPath, valueName, _countof(dllPath) - 1);

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));

        PrintInfo(L"    DLL: %s\n", expanded);

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        if (writable) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"WER");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] WER RuntimeExceptionHelper: %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"WER RuntimeExceptionHelperModule DLL is WRITABLE. "
                L"WerSvc (SYSTEM) loads this DLL when processing crash reports. "
                L"Replace DLL → SYSTEM code execution on next crash.\n"
                L"        Trigger: taskkill /f /im <any_process.exe> "
                L"OR: invoke-expression '& {[System.Runtime.InteropServices.Marshal]::WriteIntPtr([System.IntPtr]::Zero, [System.IntPtr]::Zero)}'");
            PrintFinding(&f);
            (*findings)++;
        } else if (!exists) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"WER");
            _snwprintf(f.target, _countof(f.target),
                L"[MISSING] WER RuntimeExceptionHelper: %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"WER helper DLL not found: %s — phantom load. "
                L"Plant DLL in searched path → SYSTEM code execution on crash.",
                expanded);
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hRoot);
    if (count == 0) PrintInfo(L"    (no entries)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Surface 3: WER LocalDumps DumpFolder writability
 * --------------------------------------------------------------------- */
static void AuditWERDumpFolders(DWORD *findings) {
    PrintInfo(L"  [3] WER LocalDumps DumpFolder paths:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WER_DUMPS_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (key not present)\n\n");
        return;
    }

    /* Check global DumpFolder */
    wchar_t dumpFolder[MAX_PATH * 2] = {0};
    DWORD cb = sizeof(dumpFolder), type = 0;
    if (RegQueryValueExW(hRoot, L"DumpFolder", NULL, &type,
                         (LPBYTE)dumpFolder, &cb) == ERROR_SUCCESS && *dumpFolder) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dumpFolder, expanded, _countof(expanded));
        BOOL writable = IsDirWritable(expanded);
        PrintInfo(L"    Global DumpFolder: %s  [writable: %s]\n",
                  expanded, writable ? L"YES" : L"No");
        if (writable) {
            Finding f;
            f.severity = SEV_MEDIUM;
            wcscpy(f.module, L"WER");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE DUMPDIR] WER DumpFolder: %s", expanded);
            wcscpy(f.reason,
                L"WER DumpFolder is writable. SYSTEM writes crash dump files here. "
                L"TOCTOU: oplock on expected dump filename → junction attack. "
                L"Or: monitor for when SYSTEM creates predictable dump filenames.");
            PrintFinding(&f);
            (*findings)++;
        }
    }

    /* Check per-application DumpFolder */
    DWORD idx = 0;
    wchar_t appName[256];
    DWORD   nameCch;
    while (TRUE) {
        nameCch = _countof(appName);
        LONG r = RegEnumKeyExW(hRoot, idx++, appName, &nameCch, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        HKEY hApp = NULL;
        wchar_t appKeyPath[512];
        _snwprintf(appKeyPath, _countof(appKeyPath), L"%s\\%s", WER_DUMPS_KEY, appName);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, appKeyPath, 0, KEY_READ, &hApp) != ERROR_SUCCESS)
            continue;

        wchar_t appFolder[MAX_PATH * 2] = {0};
        cb = sizeof(appFolder); type = 0;
        RegQueryValueExW(hApp, L"DumpFolder", NULL, &type, (LPBYTE)appFolder, &cb);
        RegCloseKey(hApp);

        if (*appFolder) {
            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(appFolder, expanded, _countof(expanded));
            BOOL w = IsDirWritable(expanded);
            if (w) {
                PrintInfo(L"    [%s] DumpFolder: %s [WRITABLE]\n", appName, expanded);
                (*findings)++;
            }
        }
    }

    RegCloseKey(hRoot);
    PrintInfo(L"\n");
}

void Module_WERHandler(void) {
    PrintHeader(L"WER / AeDebug SURFACE  [JIT Debugger + Crash Handler DLLs — No public tool checks this]");

    PrintInfo(
        L"  Checks Windows Error Reporting and JIT debugger attack surfaces.\n"
        L"  AeDebug: SYSTEM launches debugger on any crash — writable path = SYSTEM exec.\n"
        L"  WER DLLs: loaded by WerSvc (SYSTEM) on crash — writable = SYSTEM exec.\n\n");

    DWORD findings = 0;

    AuditAeDebug(&findings);
    AuditWERHelperModules(&findings);
    AuditWERDumpFolders(&findings);

    if (findings == 0)
        PrintInfo(L"  No WER/AeDebug LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);

    PrintInfo(
        L"\n  CRASH TRIGGER METHODS:\n"
        L"    Userland process crash:  rundll32.exe FakeLib,FakeEntry\n"
        L"    PowerShell crash:        Add-Type -TypeDefinition 'class X { static void Main() {}}'\n"
        L"                             $p=[System.Diagnostics.Process]::Start('powershell','-c [System.Runtime.InteropServices.Marshal]::WriteIntPtr([IntPtr]::Zero,[IntPtr]::Zero)')\n"
        L"    C crash:                 *(int*)0 = 0  (null ptr dereference)\n"
        L"    Easy: NotePad.exe → close without saving → triggers WER dialog\n");
}

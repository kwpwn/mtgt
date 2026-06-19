/*
 * ifeo_hijack.c — Image File Execution Options (IFEO) Hijacking Surface
 *
 * MITRE ATT&CK: T1546.012 — Image File Execution Options Injection
 *
 * WHAT IFEO IS:
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe}
 *   Windows reads this key when launching any process. Key sub-values:
 *
 *   Debugger = "C:\path\to\debugger.exe"
 *     → Windows prepends the debugger to the command line: debugger.exe target.exe
 *     → ANY process launch (including SYSTEM, High-IL) will launch the debugger first
 *     → If a SYSTEM process is set to use a writable debugger → SYSTEM exec
 *
 *   VerifierDlls = "payload.dll"
 *     → Application Verifier DLLs loaded into the target process at startup
 *     → Loaded from the executable's directory or PATH
 *     → If target is a privileged process and VerifierDll path is writable → code exec
 *
 *   GlobalFlag = 0x200  (FLG_USER_STACK_TRACE_DB causes additional DLL loads)
 *     → Various flags that trigger debug heap/stack trace/loader behavior
 *
 * LPE ANGLE:
 *   1. If IFEO key for a SYSTEM/High-IL process is WRITABLE by current user:
 *      → Set Debugger to payload.exe → next time that process launches → payload as SYSTEM
 *   2. Existing Debugger values pointing to WRITABLE executables:
 *      → Replace the debugger binary → SYSTEM on next process launch
 *   3. VerifierDlls in IFEO for privileged processes:
 *      → If VerifierDll path is writable → plant DLL → code exec when process launches
 *   4. SilentProcessExit handler (WerFault redirect):
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\{exe}
 *      → MonitorProcess value: runs a specified process when the target exits
 *      → If a SYSTEM process exits and MonitorProcess path is writable → SYSTEM exec
 *
 * ACCESSIBILITY BACKDOOR (sethc.exe, utilman.exe):
 *   Classic backdoor: IFEO Debugger on sethc.exe / utilman.exe / osk.exe / magnify.exe
 *   → At lock screen (before logon), pressing Shift×5 or Win+U launches these
 *   → If Debugger is set to cmd.exe → SYSTEM shell at lock screen
 *   → Detected here: existing suspicious Debugger values on accessibility EXEs
 *
 * REAL-WORLD CASES:
 *   - Carbanak malware: IFEO Debugger on msiexec.exe for persistence/LPE
 *   - Various APT groups use IFEO for persistence across reboots
 *   - CVE-2020-0752: Microsoft Edge process isolation bypass via IFEO
 *   - Red team tool: SetWindowsHookEx + IFEO combo for token theft
 *
 * REFERENCES:
 *   MITRE T1546.012: https://attack.mitre.org/techniques/T1546/012/
 *   Hexacorn: IFEO and SilentProcessExit research
 *   James Forshaw: Application Verifier DLL loading via IFEO
 */

#include "../common.h"

#define IFEO_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define SPE_KEY  L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit"

/* Accessibility EXEs commonly abused for backdoor IFEO */
static const wchar_t *ACCESSIBILITY_EXES[] = {
    L"sethc.exe", L"utilman.exe", L"osk.exe", L"magnify.exe",
    L"narrator.exe", L"DisplaySwitch.exe", L"AtBroker.exe", NULL
};

/* High-value SYSTEM processes to check IFEO key writability for */
static const wchar_t *SYSTEM_PROCS[] = {
    L"lsass.exe", L"services.exe", L"winlogon.exe", L"csrss.exe",
    L"smss.exe", L"wininit.exe", L"spoolsv.exe", L"svchost.exe",
    L"taskhostw.exe", L"dwm.exe", L"fontdrvhost.exe", NULL
};

/* -----------------------------------------------------------------------
 * Check if IFEO key for given EXE name is writable
 * --------------------------------------------------------------------- */
static BOOL IsIFEOKeyWritable(LPCWSTR exeName) {
    wchar_t keyPath[512];
    _snwprintf(keyPath, _countof(keyPath), L"%s\\%s", IFEO_KEY, exeName);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0,
                      KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    /* Also try parent key writability (create subkey) */
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IFEO_KEY, 0,
                      KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Enumerate all IFEO entries and check for suspicious/writable Debugger values
 * --------------------------------------------------------------------- */
static void AuditIFEOEntries(DWORD *findings) {
    PrintInfo(L"  [1] Scanning IFEO entries (Debugger/VerifierDlls):\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IFEO_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open IFEO key\n\n");
        return;
    }

    DWORD idx = 0, scanned = 0, suspicious = 0;
    wchar_t exeName[256];
    DWORD   exeNameCch;

    while (TRUE) {
        exeNameCch = _countof(exeName);
        LONG r = RegEnumKeyExW(hRoot, idx++, exeName, &exeNameCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        scanned++;

        wchar_t subPath[512];
        _snwprintf(subPath, _countof(subPath), L"%s\\%s", IFEO_KEY, exeName);

        HKEY hSub = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
            continue;

        wchar_t debugger[MAX_PATH * 2] = {0};
        wchar_t verDlls[MAX_PATH * 2]  = {0};
        DWORD   cb = sizeof(debugger), type = 0;
        RegQueryValueExW(hSub, L"Debugger", NULL, &type, (LPBYTE)debugger, &cb);
        cb = sizeof(verDlls);
        RegQueryValueExW(hSub, L"VerifierDlls", NULL, &type, (LPBYTE)verDlls, &cb);
        RegCloseKey(hSub);

        /* Check Debugger value */
        if (*debugger) {
            wchar_t debugExe[MAX_PATH * 2] = {0};
            ExtractExePath(debugger, debugExe, _countof(debugExe));
            if (!*debugExe) wcsncpy(debugExe, debugger, _countof(debugExe)-1);

            BOOL exists   = (GetFileAttributesW(debugExe) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(debugExe);

            /* Check for accessibility EXE backdoor */
            BOOL isAccessibility = FALSE;
            for (int ai = 0; ACCESSIBILITY_EXES[ai]; ai++) {
                if (_wcsicmp(exeName, ACCESSIBILITY_EXES[ai]) == 0) {
                    isAccessibility = TRUE;
                    break;
                }
            }

            if (writable || isAccessibility || !exists) {
                suspicious++;
                PrintInfo(L"    [!] IFEO Debugger: %s → %s%s%s\n",
                          exeName, debugger,
                          isAccessibility ? L" [ACCESSIBILITY BACKDOOR!]" : L"",
                          writable ? L" [DEBUGGER WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

                Finding f;
                f.severity = isAccessibility ? SEV_CRITICAL :
                             writable        ? SEV_CRITICAL : SEV_HIGH;
                wcscpy(f.module, L"IFEO");

                if (isAccessibility) {
                    _snwprintf(f.target, _countof(f.target),
                        L"[ACCESSIBILITY BACKDOOR] IFEO Debugger on %s → %s",
                        exeName, debugger);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"IFEO Debugger set on accessibility EXE %s.\n"
                        L"        Debugger: %s\n"
                        L"        LOCK SCREEN EXPLOIT: Press Shift×5 (sethc) or Win+U (utilman)\n"
                        L"        at Windows login screen → launches debugger as SYSTEM without auth.\n"
                        L"        This is a classic persistence backdoor used by attackers.",
                        exeName, debugger);
                } else {
                    _snwprintf(f.target, _countof(f.target),
                        L"[%s] IFEO Debugger: %s → %s",
                        writable ? L"WRITABLE" : L"MISSING", exeName, debugger);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"IFEO Debugger for %s points to %s EXE: %s\n"
                        L"        Any launch of %s triggers the debugger first.\n"
                        L"        If %s is a SYSTEM process → payload runs as SYSTEM.\n"
                        L"        %s → code exec next time %s is launched.",
                        exeName,
                        writable ? L"WRITABLE" : L"missing",
                        debugExe, exeName, exeName,
                        writable ? L"Replace debugger EXE with payload" : L"Plant payload at path",
                        exeName);
                }
                PrintFinding(&f);
                (*findings)++;
            }
        }

        /* Check VerifierDlls */
        if (*verDlls) {
            PrintInfo(L"    [*] IFEO VerifierDlls: %s → %s\n", exeName, verDlls);

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(verDlls, expanded, _countof(expanded));
            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);

            if (writable || !exists) {
                suspicious++;
                Finding f;
                f.severity = SEV_HIGH;
                wcscpy(f.module, L"IFEO");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] IFEO VerifierDll: %s → %s",
                    writable ? L"WRITABLE" : L"MISSING", exeName, expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"IFEO VerifierDlls for %s: %s\n"
                    L"        Application Verifier DLLs are loaded into %s at startup.\n"
                    L"        If %s is a privileged process, %s DLL in it → code exec.\n"
                    L"        %s → DLL loaded on next %s launch.",
                    exeName, expanded, exeName, exeName, expanded,
                    writable ? L"Replace DLL" : L"Plant DLL at path", exeName);
                PrintFinding(&f);
                (*findings)++;
            }
        }
    }

    RegCloseKey(hRoot);
    PrintInfo(L"    IFEO entries scanned: %lu | Suspicious: %lu\n\n",
              scanned, suspicious);
}

/* -----------------------------------------------------------------------
 * Check if IFEO keys for SYSTEM processes are writable (allow adding Debugger)
 * --------------------------------------------------------------------- */
static void AuditIFEOKeyWritability(DWORD *findings) {
    PrintInfo(L"  [2] IFEO key writability for SYSTEM processes:\n");

    /* Check parent IFEO key - if writable, can add debugger for ANY process */
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, IFEO_KEY, 0,
                      KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        PrintInfo(L"    [CRITICAL] IFEO parent key is WRITABLE — can inject Debugger for ANY process!\n");

        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"IFEO");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE PARENT] HKLM\\...\\Image File Execution Options is WRITABLE");
        wcscpy(f.reason,
            L"The IFEO parent registry key is writable by current user.\n"
            L"        Can create {exe}\\Debugger entry for ANY process including SYSTEM services.\n"
            L"        Attack: reg add \"HKLM\\...\\IFEO\\lsass.exe\" /v Debugger /t REG_SZ /d payload.exe\n"
            L"        Next lsass restart or reboot → payload.exe runs as SYSTEM.\n"
            L"        Also effective for sethc.exe → lock screen SYSTEM shell.");
        PrintFinding(&f);
        (*findings)++;
    } else {
        DWORD writable = 0;
        for (int i = 0; SYSTEM_PROCS[i]; i++) {
            if (IsIFEOKeyWritable(SYSTEM_PROCS[i])) {
                writable++;
                PrintInfo(L"    [WRITABLE] IFEO\\%s\n", SYSTEM_PROCS[i]);
                Finding f;
                f.severity = SEV_HIGH;
                wcscpy(f.module, L"IFEO");
                _snwprintf(f.target, _countof(f.target),
                    L"[WRITABLE IFEO KEY] IFEO\\%s — can add Debugger", SYSTEM_PROCS[i]);
                _snwprintf(f.reason, _countof(f.reason),
                    L"IFEO subkey for %s is writable.\n"
                    L"        Set Debugger value → payload runs as SYSTEM next time %s launches.\n"
                    L"        Trigger: svchost.exe starts on many events; lsass restart = reboot.",
                    SYSTEM_PROCS[i], SYSTEM_PROCS[i]);
                PrintFinding(&f);
                (*findings)++;
            }
        }
        if (writable == 0)
            PrintInfo(L"    IFEO keys for system processes: not writable (good)\n");
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * SilentProcessExit audit — MonitorProcess runs on target EXE exit
 * --------------------------------------------------------------------- */
static void AuditSilentProcessExit(DWORD *findings) {
    PrintInfo(L"  [3] SilentProcessExit (MonitorProcess) audit:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SPE_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (no SilentProcessExit entries)\n\n");
        return;
    }

    DWORD idx = 0, found = 0;
    wchar_t exeName[256];
    DWORD   exeNameCch;

    while (TRUE) {
        exeNameCch = _countof(exeName);
        LONG r = RegEnumKeyExW(hRoot, idx++, exeName, &exeNameCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        wchar_t subPath[512];
        _snwprintf(subPath, _countof(subPath), L"%s\\%s", SPE_KEY, exeName);
        HKEY hSub = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
            continue;

        wchar_t monProc[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(monProc), type = 0;
        RegQueryValueExW(hSub, L"MonitorProcess", NULL, &type, (LPBYTE)monProc, &cb);
        RegCloseKey(hSub);

        if (!*monProc) continue;
        found++;

        wchar_t monExe[MAX_PATH * 2] = {0};
        ExtractExePath(monProc, monExe, _countof(monExe));
        if (!*monExe) wcsncpy(monExe, monProc, _countof(monExe)-1);

        BOOL exists   = (GetFileAttributesW(monExe) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(monExe);

        PrintInfo(L"    SPE: %s → MonitorProcess: %s%s\n",
                  exeName, monProc,
                  writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

        if (writable || !exists) {
            Finding f;
            f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"IFEO");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] SilentProcessExit MonitorProcess: %s → %s",
                writable ? L"WRITABLE" : L"MISSING", exeName, monExe);
            _snwprintf(f.reason, _countof(f.reason),
                L"SilentProcessExit MonitorProcess for %s points to %s EXE.\n"
                L"        When %s exits unexpectedly, Windows launches MonitorProcess.\n"
                L"        If %s is a SYSTEM process → MonitorProcess runs as SYSTEM.\n"
                L"        %s → code exec on next %s crash/exit.",
                exeName, writable ? L"WRITABLE" : L"missing",
                exeName, exeName,
                writable ? L"Replace MonitorProcess EXE" : L"Plant EXE at path",
                exeName);
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hRoot);
    if (found == 0) PrintInfo(L"    (no MonitorProcess entries)\n");
    PrintInfo(L"\n");
}

void Module_IFEOHijack(void) {
    PrintHeader(L"IFEO HIJACKING  [Image File Execution Options — T1546.012 — Debugger/VerifierDll injection]");

    PrintInfo(
        L"  IFEO Debugger: Windows prepends debugger.exe to ANY process launch.\n"
        L"  Writable IFEO key for SYSTEM process = SYSTEM exec on next process start.\n"
        L"  Accessibility EXE IFEO (sethc/utilman) = SYSTEM shell at lock screen.\n\n");

    DWORD findings = 0;
    AuditIFEOEntries(&findings);
    AuditIFEOKeyWritability(&findings);
    AuditSilentProcessExit(&findings);

    if (findings == 0)
        PrintInfo(L"  No IFEO LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOITATION:\n"
            L"    # Add debugger to SYSTEM process:\n"
            L"    reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            L"\\Image File Execution Options\\svchost.exe\" /v Debugger /t REG_SZ /d C:\\payload.exe\n"
            L"    # Lock screen backdoor:\n"
            L"    reg add \"HKLM\\...\\IFEO\\sethc.exe\" /v Debugger /t REG_SZ /d cmd.exe\n"
            L"    # Trigger: press Shift×5 at Windows login screen → cmd.exe as SYSTEM\n");
    }
}

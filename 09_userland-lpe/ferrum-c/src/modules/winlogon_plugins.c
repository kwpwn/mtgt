/*
 * winlogon_plugins.c — Winlogon Notification/Plugin DLL and Shell Hijacking
 *
 * MITRE ATT&CK: T1547.004 — Winlogon Helper DLL
 *
 * WINLOGON ATTACK SURFACES:
 *
 *   1. WINLOGON NOTIFICATION PACKAGES:
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\{name}
 *      DllName REG_SZ = "notification.dll"
 *      Winlogon.exe (running as SYSTEM) loads these DLLs and calls them for logon/logoff events.
 *      If DLL path is writable → code execution as SYSTEM at logon/logoff.
 *      Note: Notify subkey was removed from Vista+ but some enterprise software re-adds it.
 *
 *   2. USERINIT MODIFICATION:
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
 *      Default: "C:\Windows\system32\userinit.exe,"
 *      Comma-separated list of processes launched by winlogon when user logs on.
 *      If value is writable or points to writable EXE → code exec at user logon.
 *      Added EXEs run in the user's context (not SYSTEM) but executed at logon.
 *
 *   3. SHELL MODIFICATION:
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
 *      Default: "explorer.exe"
 *      The Windows shell process. If writable or points to writable EXE → code exec at logon.
 *      HKCU override: HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
 *      HKCU Shell runs as logged-on user — persistence even without admin.
 *
 *   4. TASKMAN (TASK MANAGER REPLACEMENT):
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman
 *      Alternative task manager launched by Ctrl+Alt+Del.
 *      If set and writable → code exec on Ctrl+Alt+Del.
 *
 *   5. MPNOTIFY:
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\MPNotify
 *      Message provider notification executable — runs at logon in SYSTEM context.
 *
 *   6. CREDENTIAL PROVIDER FILTERS:
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authentication\Credential Provider Filters
 *      Filter DLLs evaluated before credential providers — writable DLL = logon interception.
 *
 * WHY WINLOGON IS HIGH VALUE:
 *   - winlogon.exe runs at SYSTEM integrity level
 *   - It handles ALL logon/logoff events for every user
 *   - Notification DLLs run in winlogon.exe address space as SYSTEM
 *   - On session 0 (pre-Vista style) it was the primary session host
 *   - Modern Windows: winlogon still loads registry-specified DLLs
 *
 * REFERENCES:
 *   MITRE T1547.004: https://attack.mitre.org/techniques/T1547/004/
 *   Harmj0y: Winlogon hijacking for persistence
 *   Trend Micro: APT groups abusing Winlogon Notify (Turla, Carbanak)
 */

#include "../common.h"

#define WINLOGON_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
#define NOTIFY_KEY   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"
#define AUTH_KEY     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Authentication\\Credential Provider Filters"

/* -----------------------------------------------------------------------
 * Audit Winlogon Notify DLLs
 * --------------------------------------------------------------------- */
static void AuditWinlogonNotify(DWORD *findings) {
    PrintInfo(L"  [1] Winlogon Notification DLLs:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NOTIFY_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (Winlogon\\Notify key not present — normal on modern Windows)\n\n");
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t notifyName[256];
    DWORD   notifyNameCch;

    while (TRUE) {
        notifyNameCch = _countof(notifyName);
        LONG r = RegEnumKeyExW(hRoot, idx++, notifyName, &notifyNameCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        wchar_t subPath[512];
        _snwprintf(subPath, _countof(subPath), L"%s\\%s", NOTIFY_KEY, notifyName);
        HKEY hSub = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hSub) != ERROR_SUCCESS)
            continue;

        wchar_t dllName[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(dllName), type = 0;
        RegQueryValueExW(hSub, L"DllName", NULL, &type, (LPBYTE)dllName, &cb);
        RegCloseKey(hSub);

        if (!*dllName) continue;

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dllName, expanded, _countof(expanded));
        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        PrintInfo(L"    Notify[%s]: %s%s\n",
                  notifyName, expanded,
                  writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

        if (writable || !exists) {
            Finding f;
            f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
            wcscpy(f.module, L"WINLOGON");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] Winlogon Notify DLL: %s → %s",
                writable ? L"WRITABLE" : L"MISSING", notifyName, expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Winlogon Notify package '%s' DLL is %s: %s\n"
                L"        winlogon.exe (SYSTEM) loads this DLL and calls it on logon/logoff events.\n"
                L"        %s → SYSTEM code execution on next user logon.",
                notifyName, writable ? L"WRITABLE" : L"MISSING", expanded,
                writable ? L"Replace DLL with payload" : L"Plant DLL at registered path");
            PrintFinding(&f);
            (*findings)++;
        }
    }
    RegCloseKey(hRoot);
    if (count == 0) PrintInfo(L"    (no Notify entries)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit Winlogon main key values (Userinit, Shell, Taskman, MPNotify)
 * --------------------------------------------------------------------- */
static void AuditWinlogonValues(DWORD *findings) {
    PrintInfo(L"  [2] Winlogon key values (Userinit/Shell/Taskman):\n");

    static const struct {
        const wchar_t *valueName;
        const wchar_t *description;
        BOOL           isSystem;  /* runs as SYSTEM vs user */
    } VALUES[] = {
        { L"Userinit",   L"processes launched at logon (user context)", FALSE },
        { L"Shell",      L"Windows shell (explorer.exe replacement)",   FALSE },
        { L"Taskman",    L"Task manager replacement (Ctrl+Alt+Del)",    TRUE  },
        { L"MPNotify",   L"MP notification executable (SYSTEM)",        TRUE  },
        { NULL, NULL, FALSE }
    };

    /* Check HKLM */
    for (HKEY hiveRoot = HKEY_LOCAL_MACHINE;;) {
        HKEY hWL = NULL;
        if (RegOpenKeyExW(hiveRoot, WINLOGON_KEY, 0, KEY_READ, &hWL) != ERROR_SUCCESS) {
            if (hiveRoot == HKEY_LOCAL_MACHINE) { hiveRoot = HKEY_CURRENT_USER; continue; }
            break;
        }

        const wchar_t *hiveName = (hiveRoot == HKEY_LOCAL_MACHINE) ? L"HKLM" : L"HKCU";

        for (int vi = 0; VALUES[vi].valueName; vi++) {
            wchar_t val[MAX_PATH * 2] = {0};
            DWORD   cb = sizeof(val), type = 0;
            if (RegQueryValueExW(hWL, VALUES[vi].valueName, NULL, &type,
                                 (LPBYTE)val, &cb) != ERROR_SUCCESS) continue;

            /* Parse comma-separated paths (Userinit uses commas) */
            wchar_t copy[MAX_PATH * 2];
            wcsncpy(copy, val, _countof(copy)-1);

            PrintInfo(L"    [%s] %s = %s\n", hiveName, VALUES[vi].valueName, val);

            wchar_t *wctx = NULL;
            wchar_t *token = wcstok(copy, L",", &wctx);
            while (token) {
                while (*token == L' ') token++;
                if (!*token) { token = wcstok(NULL, L",", &wctx); continue; }

                wchar_t exePath[MAX_PATH * 2] = {0};
                ExtractExePath(token, exePath, _countof(exePath));
                if (!*exePath) wcsncpy(exePath, token, _countof(exePath)-1);

                BOOL exists   = (GetFileAttributesW(exePath) != INVALID_FILE_ATTRIBUTES);
                BOOL writable = exists && IsFileWritable(exePath);

                /* Check for non-standard additions (more than just userinit.exe/explorer.exe) */
                BOOL isNonStandard = (!WcsContainsI(exePath, L"\\Windows\\system32\\userinit.exe")
                                   && !WcsContainsI(exePath, L"\\Windows\\explorer.exe")
                                   && *exePath);

                if (writable || !exists || isNonStandard) {
                    PrintInfo(L"      → %s%s%s\n",
                              exePath,
                              isNonStandard ? L" [NON-STANDARD]" : L"",
                              writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

                    Finding f;
                    f.severity = isNonStandard ? (writable ? SEV_CRITICAL : SEV_HIGH) :
                                 writable ? SEV_HIGH : SEV_MEDIUM;
                    wcscpy(f.module, L"WINLOGON");
                    _snwprintf(f.target, _countof(f.target),
                        L"[%s%s] %s\\Winlogon\\%s: %s",
                        isNonStandard ? L"NON-STD " : L"",
                        writable ? L"WRITABLE" : (!exists ? L"MISSING" : L"SUSPICIOUS"),
                        hiveName, VALUES[vi].valueName, exePath);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"Winlogon %s value in %s includes non-standard or %s path: %s\n"
                        L"        This EXE runs as %s at every user logon.\n"
                        L"        %s",
                        VALUES[vi].valueName, hiveName,
                        writable ? L"writable" : (!exists ? L"missing" : L"suspicious"),
                        exePath,
                        VALUES[vi].isSystem ? L"SYSTEM" : L"logged-on user",
                        writable ? L"Replace EXE with payload → exec at next logon." :
                        !exists  ? L"Plant EXE at path → exec at next logon." :
                                   L"Suspicious non-standard entry — investigate.");
                    PrintFinding(&f);
                    (*findings)++;
                }
                token = wcstok(NULL, L",", &wctx);
            }
        }

        /* Check key writability itself (can modify Userinit/Shell) */
        HKEY hWLW = NULL;
        if (RegOpenKeyExW(hiveRoot, WINLOGON_KEY, 0, KEY_WRITE, &hWLW) == ERROR_SUCCESS) {
            RegCloseKey(hWLW);
            PrintInfo(L"    [!] Winlogon key in %s is WRITABLE — can modify Shell/Userinit!\n",
                      hiveName);
            if (hiveRoot == HKEY_LOCAL_MACHINE) {
                Finding f;
                f.severity = SEV_CRITICAL;
                wcscpy(f.module, L"WINLOGON");
                _snwprintf(f.target, _countof(f.target),
                    L"[WRITABLE KEY] %s\\Winlogon is writable", hiveName);
                wcscpy(f.reason,
                    L"Winlogon registry key is writable by current user.\n"
                    L"        Can modify Shell, Userinit, or Taskman values to point to payload.\n"
                    L"        Payload runs at every user logon (Shell/Userinit = user context).\n"
                    L"        Taskman/MPNotify may run in SYSTEM context.");
                PrintFinding(&f);
                (*findings)++;
            }
        }

        RegCloseKey(hWL);
        if (hiveRoot == HKEY_LOCAL_MACHINE) hiveRoot = HKEY_CURRENT_USER;
        else break;
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit Credential Provider Filter DLLs
 * --------------------------------------------------------------------- */
static void AuditCredProvFilters(DWORD *findings) {
    PrintInfo(L"  [3] Credential Provider Filter DLLs:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, AUTH_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (no credential provider filters)\n\n");
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t clsid[64];
    DWORD   clsidCch;

    while (TRUE) {
        clsidCch = _countof(clsid);
        LONG r = RegEnumKeyExW(hRoot, idx++, clsid, &clsidCch, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        /* Resolve CLSID to DLL path */
        wchar_t clsKeyPath[512];
        _snwprintf(clsKeyPath, _countof(clsKeyPath),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);
        HKEY hCls = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsKeyPath, 0, KEY_READ, &hCls) != ERROR_SUCCESS)
            continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(dllPath), type = 0;
        RegQueryValueExW(hCls, NULL, NULL, &type, (LPBYTE)dllPath, &cb);
        RegCloseKey(hCls);

        if (!*dllPath) continue;

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));
        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        PrintInfo(L"    Filter %s: %s%s\n",
                  clsid, expanded,
                  writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

        if (writable || !exists) {
            Finding f;
            f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
            wcscpy(f.module, L"WINLOGON");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] CredProvider Filter %s: %s",
                writable ? L"WRITABLE" : L"MISSING", clsid, expanded);
            wcscpy(f.reason,
                L"Credential Provider Filter DLL is writable/missing.\n"
                L"        Filter DLLs are evaluated before credential providers during logon.\n"
                L"        Loaded by winlogon.exe (SYSTEM) → code exec + credential intercept.");
            PrintFinding(&f);
            (*findings)++;
        }
    }
    RegCloseKey(hRoot);
    if (count == 0) PrintInfo(L"    (no filter entries)\n");
    PrintInfo(L"\n");
}

void Module_WinlogonPlugins(void) {
    PrintHeader(L"WINLOGON PLUGINS  [T1547.004 — Notify DLL / Userinit / Shell hijacking]");

    PrintInfo(
        L"  winlogon.exe runs as SYSTEM and loads DLLs + executables at logon/logoff.\n"
        L"  Notify DLLs run in SYSTEM space; Shell/Userinit run as logged-on user.\n"
        L"  Used by APT groups (Turla, Carbanak) for persistent SYSTEM access.\n\n");

    DWORD findings = 0;
    AuditWinlogonNotify(&findings);
    AuditWinlogonValues(&findings);
    AuditCredProvFilters(&findings);

    if (findings == 0)
        PrintInfo(L"  No Winlogon hijacking surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  PERSISTENCE VIA SHELL:\n"
            L"    reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"\n"
            L"            /v Shell /t REG_SZ /d \"explorer.exe,payload.exe\"\n"
            L"    [Note: HKCU Shell runs at YOUR logon — no admin needed for HKCU]\n\n"
            L"  SYSTEM SHELL VIA TASKMAN:\n"
            L"    reg add \"HKLM\\...\\Winlogon\" /v Taskman /t REG_SZ /d payload.exe\n"
            L"    Trigger: Ctrl+Alt+Del → payload.exe runs in session context\n");
    }
}

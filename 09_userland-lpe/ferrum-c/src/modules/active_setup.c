/*
 * active_setup.c — Active Setup StubPath Abuse
 *
 * WHAT ACTIVE SETUP IS:
 *   Active Setup is a Windows mechanism for per-user software initialization.
 *   Registry path: HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{GUID}
 *   Values: StubPath, Version, ComponentID, Locale, IsInstalled
 *
 *   On EVERY USER LOGON, winlogon compares HKLM and HKCU versions for each component.
 *   If HKLM version > HKCU version (or HKCU entry missing), StubPath is EXECUTED
 *   in the context of the newly logged-on user.
 *
 * WHY THIS IS AN LPE SURFACE:
 *
 *   1. WRITABLE StubPath EXE:
 *      If StubPath points to a writable EXE → replace it → runs on next user logon.
 *      If a privileged user (admin/SYSTEM) logs on → code exec in their context.
 *      On servers with auto-logon or terminal servers: executes for EACH logon.
 *
 *   2. WRITABLE HKLM Active Setup KEY:
 *      If key is writable → add new component with malicious StubPath.
 *      Creates persistence that fires for EVERY user who logs on.
 *      Runs as the logging-on user — if admin auto-logons → admin exec without elevation.
 *
 *   3. HKCU MANIPULATION (version tricks):
 *      If HKLM component has valid StubPath but HKCU version is deleted/lowered:
 *      → Forces StubPath execution on next logon even if previously "installed".
 *
 *   4. CROSS-USER TRIGGER:
 *      Unique property: Active Setup fires for EVERY user, not just the installer.
 *      Plant in HKLM → runs when ANY user (including admins) logs in.
 *
 * KNOWN LEGITIMATE COMPONENTS:
 *   - Internet Explorer setup (iernonce.dll)
 *   - Windows Media Player setup
 *   - DirectX setup
 *   - Various application first-run initialization
 *
 * REAL-WORLD ABUSE:
 *   - BITS-based malware uses Active Setup for persistence
 *   - Commonly used by commodity malware for per-user DLL injection
 *   - APT41: documented Active Setup abuse for cross-user persistence
 *
 * REFERENCES:
 *   MITRE T1547.014 — Active Setup
 *   Hexacorn blog: "Beyond good ol' Run key" series
 *   APT41 report: FireEye/Mandiant 2020
 */

#include "../common.h"

#define ACTIVE_SETUP_KEY L"SOFTWARE\\Microsoft\\Active Setup\\Installed Components"
#define ACTIVE_SETUP_KEY_WOW L"SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components"

/* -----------------------------------------------------------------------
 * Audit Active Setup components
 * --------------------------------------------------------------------- */
static void AuditActiveSetupComponents(HKEY hiveRoot, LPCWSTR rootName,
                                        LPCWSTR keyPath, DWORD *findings) {
    HKEY hRoot = NULL;
    if (RegOpenKeyExW(hiveRoot, keyPath,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) return;

    DWORD idx = 0, count = 0, suspect = 0;
    wchar_t compGUID[128];
    DWORD   compGUIDCch;

    while (TRUE) {
        compGUIDCch = _countof(compGUID);
        LONG r = RegEnumKeyExW(hRoot, idx++, compGUID, &compGUIDCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        wchar_t compPath[512];
        _snwprintf(compPath, _countof(compPath), L"%s\\%s", keyPath, compGUID);

        HKEY hComp = NULL;
        if (RegOpenKeyExW(hiveRoot, compPath, 0, KEY_READ, &hComp) != ERROR_SUCCESS)
            continue;

        wchar_t stubPath[MAX_PATH * 2] = {0};
        wchar_t compName[256] = {0};
        wchar_t version[64] = {0};
        DWORD   isInstalled = 0;
        DWORD   cb = sizeof(stubPath), type = 0;

        RegQueryValueExW(hComp, L"StubPath",    NULL, &type, (LPBYTE)stubPath,    &cb);
        cb = sizeof(compName);
        RegQueryValueExW(hComp, NULL,            NULL, &type, (LPBYTE)compName,    &cb);
        cb = sizeof(version);
        RegQueryValueExW(hComp, L"Version",      NULL, &type, (LPBYTE)version,     &cb);
        cb = sizeof(DWORD);
        RegQueryValueExW(hComp, L"IsInstalled",  NULL, &type, (LPBYTE)&isInstalled,&cb);
        RegCloseKey(hComp);

        if (!*stubPath) continue;

        /* Extract EXE from StubPath (may have arguments) */
        wchar_t stubExe[MAX_PATH * 2] = {0};
        ExtractExePath(stubPath, stubExe, _countof(stubExe));
        if (!*stubExe) wcsncpy(stubExe, stubPath, _countof(stubExe)-1);

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(stubExe, expanded, _countof(expanded));

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        /* Detect non-system32 paths */
        BOOL isNonSystem = (*stubPath && !WcsContainsI(stubPath, L"%SystemRoot%")
                         && !WcsContainsI(stubPath, L"%windir%")
                         && !WcsContainsI(stubPath, L"C:\\Windows")
                         && !WcsContainsI(stubPath, L"rundll32"));

        if (writable || !exists) {
            suspect++;
            PrintInfo(L"    [!] %s [%s] %s\n",
                      compGUID, *compName ? compName : L"(no name)", stubPath);
            PrintInfo(L"        EXE: %s%s\n",
                      expanded, writable ? L" [WRITABLE!]" : L" [MISSING]");

            Finding f;
            f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"ACTIVESETUP");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] Active Setup StubPath [%s]: %s",
                writable ? L"WRITABLE" : L"MISSING", compGUID, expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Active Setup component '%s' StubPath EXE is %s: %s\n"
                L"        StubPath runs at EVERY user logon (HKLM version > HKCU version).\n"
                L"        If an admin/privileged user logs on → code exec in their context.\n"
                L"        %s → executed on next logon for any user without HKCU version entry.\n"
                L"        Component: %s | Version: %s",
                *compName ? compName : compGUID,
                writable ? L"WRITABLE" : L"MISSING",
                expanded,
                writable ? L"Replace EXE with payload" : L"Plant EXE at path",
                compGUID, *version ? version : L"(none)");
            PrintFinding(&f);
            (*findings)++;
        } else if (isNonSystem && *stubPath) {
            PrintInfo(L"    [?] %s %s (non-system path)\n", compGUID, stubPath);
        }
    }

    RegCloseKey(hRoot);
    PrintInfo(L"    [%s\\%s] Components: %lu | Suspicious: %lu\n\n",
              rootName, keyPath, count, suspect);
}

/* -----------------------------------------------------------------------
 * Check if Active Setup HKLM key is writable (can add own component)
 * --------------------------------------------------------------------- */
static void AuditActiveSetupKeyWritability(DWORD *findings) {
    PrintInfo(L"  [2] Active Setup key writability:\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ACTIVE_SETUP_KEY,
                      0, KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        PrintInfo(L"    [CRITICAL] HKLM Active Setup key is WRITABLE!\n\n");

        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"ACTIVESETUP");
        wcscpy(f.target, L"[WRITABLE] HKLM\\Active Setup\\Installed Components — can add component");
        _snwprintf(f.reason, _countof(f.reason),
            L"HKLM Active Setup key is writable — can register new component.\n"
            L"        Registered StubPath executes for EVERY user at logon.\n"
            L"        Attack:\n"
            L"          reg add \"HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{GUID}\"\n"
            L"                  /v StubPath /t REG_SZ /d \"C:\\payload.exe\"\n"
            L"          [Next any-user logon → payload.exe runs as that user]\n"
            L"          [If admin logs on → admin-level persistence without elevation prompt]");
        PrintFinding(&f);
        (*findings)++;
    } else {
        PrintInfo(L"    HKLM Active Setup key not writable (expected)\n\n");
    }

    /* HKCU key (always writable by current user — persistence for own logon) */
    PrintInfo(L"  [3] HKCU Active Setup (own-user version manipulation):\n");
    PrintInfo(L"    HKCU\\Active Setup can be modified by current user to re-trigger\n"
              L"    any HKLM Active Setup component on next logon (delete HKCU version entry).\n");
    PrintInfo(L"    HKCU Version is checked against HKLM. Deleting HKCU version\n"
              L"    causes StubPath to re-run on next logon — useful for persistence.\n\n");
}

void Module_ActiveSetup(void) {
    PrintHeader(L"ACTIVE SETUP  [T1547.014 — StubPath writable EXE hijacking at user logon]");

    PrintInfo(
        L"  Active Setup fires for EVERY user logon — HKLM component StubPath.\n"
        L"  Writable StubPath EXE → code exec when any (including admin) user logs on.\n"
        L"  Commonly abused by malware (APT41) for cross-user persistence.\n\n");

    DWORD findings = 0;

    PrintInfo(L"  [1] HKLM Active Setup components (StubPath writability):\n");
    AuditActiveSetupComponents(HKEY_LOCAL_MACHINE, L"HKLM",
                                ACTIVE_SETUP_KEY, &findings);
    AuditActiveSetupComponents(HKEY_LOCAL_MACHINE, L"HKLM(WoW)",
                                ACTIVE_SETUP_KEY_WOW, &findings);
    AuditActiveSetupKeyWritability(&findings);

    if (findings == 0)
        PrintInfo(L"  No Active Setup LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  RESET ACTIVE SETUP TRIGGER (forces re-execution):\n"
            L"    reg delete \"HKCU\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{GUID}\" /f\n"
            L"    [Next logon of any user without HKCU entry → StubPath runs]\n");
    }
}

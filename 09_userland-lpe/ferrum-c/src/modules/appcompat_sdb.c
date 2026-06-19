/*
 * appcompat_sdb.c — Application Compatibility Shim Database (SDB) Audit
 *
 * WHY APPCOMPAT SDB IS A NOVEL ATTACK SURFACE:
 *   Windows Application Compatibility Infrastructure (apphelp.dll) allows
 *   custom "shim databases" (.sdb files) to intercept and modify process
 *   behavior. Shims can:
 *     - Redirect DLL loads (replace ntdll, kernel32 functions with custom stubs)
 *     - Inject arbitrary DLLs into any matching process (InjectDLL shim)
 *     - Redirect file paths (redirect filesystem calls)
 *     - Patch process memory at load time
 *
 *   If an attacker can install a custom SDB or modify an existing one:
 *   → Inject arbitrary DLL into ANY process (including SYSTEM services)
 *   → Even code-signed binaries are vulnerable (shims run before most integrity checks)
 *
 * ATTACK PATHS:
 *   1. Installed SDB file in user-writable location
 *      → Modify the .sdb to add InjectDLL pointing to payload
 *      → Target process loads payload DLL at startup
 *
 *   2. Custom key writable (per-EXE shim configuration)
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\
 *      Contains per-EXE SDB GUIDs — if writable, can add our SDB entry
 *
 *   3. SDB registration with writable SDB file
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\
 *      → Replace registered SDB file with malicious one
 *
 * SHIM TYPES OF INTEREST:
 *   - InjectDLL: inject arbitrary DLL into matching processes
 *   - RedirectEXE: redirect process launch to attacker EXE
 *   - CorrectFilePaths: redirect file path → TOCTOU bypass
 *
 * HISTORICAL USE:
 *   - Used by Duqu 2.0 malware for persistence (custom SDB installation)
 *   - PowerShell Empire uses sdbinst for persistence
 *   - CVE-2015-0096: Windows Shell LPE via AppCompat shim
 *
 * SHIM DATABASE FILE FORMAT:
 *   .sdb files are binary format; creation tools:
 *   - sdbinst.exe (built-in Windows tool)
 *   - CFF Explorer with SDB plugin
 *   - PowerShell: Install-ApplicationCompatibilityShim (custom module)
 *
 * REFERENCES:
 *   Jon Erickson: "Persistence via Application Shimming" (Derbycon 2014)
 *   MITRE ATT&CK: T1546.011 — Application Shimming
 *   https://www.exploit-db.com/docs/english/17556-application-shimming.pdf
 */

#include "../common.h"

#define APPCOMPAT_INSTALLED_SDB \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"
#define APPCOMPAT_CUSTOM \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom"

/* -----------------------------------------------------------------------
 * Check InstalledSDB entries
 * --------------------------------------------------------------------- */
static void AuditInstalledSDBs(DWORD *findings) {
    PrintInfo(L"  [1] InstalledSDB registry entries:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, APPCOMPAT_INSTALLED_SDB,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (key not present — no installed SDBs)\n\n");
        return;
    }

    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, APPCOMPAT_INSTALLED_SDB);
    if (keyWritable) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"APPCOMPAT");
        wcscpy(f.target, L"[KEY WRITABLE] InstalledSDB registry key");
        wcscpy(f.reason,
            L"AppCompatFlags\\InstalledSDB key is WRITABLE. "
            L"Can register a custom .sdb shim database targeting any process. "
            L"Attack: sdbinst.exe evil.sdb → installs shim → "
            L"next launch of target process → InjectDLL shim loads payload DLL. "
            L"Create SDB: use 'Compatibility Administrator' (free tool from MS) "
            L"or manual binary SDB format.");
        PrintFinding(&f);
        (*findings)++;
    }

    DWORD idx = 0;
    wchar_t subKey[256];
    DWORD   subKeyCch;

    while (TRUE) {
        subKeyCch = _countof(subKey);
        LONG r = RegEnumKeyExW(hRoot, idx++, subKey, &subKeyCch, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        /* Each subkey is a GUID → contains DatabasePath */
        wchar_t keyPath[512];
        _snwprintf(keyPath, _countof(keyPath), L"%s\\%s", APPCOMPAT_INSTALLED_SDB, subKey);

        HKEY hSDB = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hSDB) != ERROR_SUCCESS)
            continue;

        wchar_t dbPath[MAX_PATH * 2] = {0};
        wchar_t dbDesc[256]          = {0};
        DWORD   cb = sizeof(dbPath), type = 0;

        RegQueryValueExW(hSDB, L"DatabasePath",        NULL, &type, (LPBYTE)dbPath, &cb);
        cb = sizeof(dbDesc);
        RegQueryValueExW(hSDB, L"DatabaseDescription", NULL, &type, (LPBYTE)dbDesc, &cb);
        RegCloseKey(hSDB);

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dbPath, expanded, _countof(expanded));

        PrintInfo(L"    SDB [%s]: %s\n", *dbDesc ? dbDesc : subKey, expanded);

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);
        BOOL inUser   = IsUserWritablePath(expanded);

        if (writable) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"APPCOMPAT");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE SDB] %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"INSTALLED SHIM DATABASE FILE IS WRITABLE: %s\n"
                L"        Description: %s  GUID: %s\n"
                L"        Replace this .sdb file with a malicious one containing:\n"
                L"          InjectDLL shim → payload.dll loaded into every targeted process.\n"
                L"        OR: RedirectEXE → redirect target process launch.\n"
                L"        Targets any executable listed in the original SDB.",
                expanded, *dbDesc ? dbDesc : L"(unknown)", subKey);
            PrintFinding(&f);
            (*findings)++;
        } else if (!exists) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"APPCOMPAT");
            _snwprintf(f.target, _countof(f.target),
                L"[MISSING SDB] %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Registered SDB file not found: %s — phantom registration. "
                L"GUID: %s. Plant a crafted .sdb at this path.",
                expanded, subKey);
            PrintFinding(&f);
            (*findings)++;
        } else if (inUser) {
            Finding f;
            f.severity = SEV_MEDIUM;
            wcscpy(f.module, L"APPCOMPAT");
            _snwprintf(f.target, _countof(f.target),
                L"[USER-PATH SDB] %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Registered SDB in user-accessible path: %s — verify ACL directly.",
                expanded);
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hRoot);
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check AppCompatFlags\Custom for per-EXE shim entries
 * --------------------------------------------------------------------- */
static void AuditCustomShims(DWORD *findings) {
    PrintInfo(L"  [2] Per-EXE Custom shim entries:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, APPCOMPAT_CUSTOM,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (key not present)\n\n");
        return;
    }

    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, APPCOMPAT_CUSTOM);
    if (keyWritable) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"APPCOMPAT");
        wcscpy(f.target, L"[KEY WRITABLE] AppCompatFlags\\Custom");
        wcscpy(f.reason,
            L"Per-EXE AppCompat Custom key is WRITABLE. "
            L"Can add custom shim entries for ANY executable by adding "
            L"<ExeName> subkey with SDB GUID reference. "
            L"When target EXE runs, our shim DB is consulted → DLL injection.");
        PrintFinding(&f);
        (*findings)++;
    }

    DWORD idx = 0, total = 0;
    wchar_t exeName[256];
    DWORD   nameCch;

    while (TRUE) {
        nameCch = _countof(exeName);
        LONG r = RegEnumKeyExW(hRoot, idx++, exeName, &nameCch, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        total++;
    }

    PrintInfo(L"    Per-EXE shim entries found: %lu\n\n", total);
    RegCloseKey(hRoot);
}

/* -----------------------------------------------------------------------
 * Check default SDB location files
 * --------------------------------------------------------------------- */
static void AuditDefaultSDBPath(DWORD *findings) {
    PrintInfo(L"  [3] Default AppPatch directory:\n");

    wchar_t winDir[MAX_PATH] = {0};
    GetWindowsDirectoryW(winDir, _countof(winDir));

    wchar_t patchDir[MAX_PATH * 2] = {0};
    _snwprintf(patchDir, _countof(patchDir), L"%s\\AppPatch", winDir);

    BOOL dirWritable = IsDirWritable(patchDir);
    PrintInfo(L"    %s  [writable: %s]\n\n",
              patchDir, dirWritable ? L"YES — CRITICAL" : L"No (expected)");

    if (dirWritable) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"APPCOMPAT");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE] AppPatch directory: %s", patchDir);
        _snwprintf(f.reason, _countof(f.reason),
            L"Windows AppPatch directory is WRITABLE. "
            L"Default SDB files (sysmain.sdb, etc.) are loaded by apphelp.dll "
            L"for ALL processes. Can replace system SDB with malicious one. "
            L"Impact: shim injection into every Windows process.");
        PrintFinding(&f);
        (*findings)++;
    }
}

void Module_AppCompatSDB(void) {
    PrintHeader(L"APPCOMPAT SDB  [Application Compatibility Shim Database — DLL injection vector]");

    PrintInfo(
        L"  Shim databases can inject DLLs into ANY process at startup.\n"
        L"  Used by Duqu 2.0 malware for persistence (custom SDB + InjectDLL shim).\n"
        L"  MITRE ATT&CK: T1546.011 — Application Shimming.\n\n");

    DWORD findings = 0;

    AuditInstalledSDBs(&findings);
    AuditCustomShims(&findings);
    AuditDefaultSDBPath(&findings);

    if (findings == 0)
        PrintInfo(L"  No AppCompat SDB LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  CREATE MALICIOUS SDB WORKFLOW:\n"
            L"    1. Download 'Compatibility Administrator' (free from MS Application Compat Toolkit)\n"
            L"    2. Create new database → add Application → add Fix\n"
            L"    3. Fix type: 'InjectDLL' → specify payload.dll path\n"
            L"    4. Matching criteria: set to target EXE (e.g. svchost.exe)\n"
            L"    5. Save as .sdb → sdbinst.exe malicious.sdb\n"
            L"    6. Next launch of target EXE → payload.dll loaded\n"
            L"    Alternative: PowerShell Empire 'shim_persistence' module\n");
    }
}

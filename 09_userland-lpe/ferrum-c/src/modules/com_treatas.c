/*
 * com_treatas.c — COM TreatAs/AutoConvertTo CLSID Redirection
 *
 * RESEARCH SOURCES:
 *   - COM TreatAs: HKLM\SOFTWARE\Classes\CLSID\{GUID}\TreatAs = {other GUID}
 *     Documented in MSDN: "Treating One Object as Another"
 *     Causes CoCreateInstance({orig}) to actually create {TreatAs target}
 *   - COM AutoConvertTo: HKLM\SOFTWARE\Classes\CLSID\{GUID}\AutoConvertTo = {other GUID}
 *     Used for embedded object class migration (OLE2 document conversion)
 *   - COM Elevation Moniker:
 *     HKLM\SOFTWARE\Classes\Elevation\ClsId\{GUID}
 *     UAC Elevation objects — if {GUID} → InprocServer32 is writable → elevated code exec
 *   - Research:
 *     - James Forshaw (Project Zero): COM object hijacking via TreatAs/AutoConvertTo
 *       https://bugs.chromium.org/p/project-zero/issues/detail?id=1231
 *     - Casey Smith: COM TreatAs persistence (subtecnique of T1546.015)
 *     - HKCU\Software\Classes\CLSID\{GUID}\TreatAs — user-writable by default
 *       → overrides HKLM CLSID without elevation → UAC bypass vector
 *     - Elevation Moniker CLSIDs documented by Jonathan Morin (@MOTHack)
 *
 * ATTACK SURFACE:
 *   1. TreatAs HKLM writable → redirect any CLSID activation to attacker CLSID
 *   2. AutoConvertTo HKLM writable → redirect embedded OLE object activation
 *   3. HKCU TreatAs → redirect HKLM CLSID without admin rights (user-level)
 *      If target HKLM CLSID is used by a SYSTEM service → SYSTEM exec
 *   4. COM Elevation Moniker CLSID → auto-elevated COM object:
 *      CoCreateInstanceEx with CLSCTX_ENABLE_COM_ELEVATION_MONIKER
 *      If InprocServer32 is writable → elevated code exec through COM
 *
 * HOW TREATAS WORKS:
 *   CoCreateInstance({A}) → registry lookup: CLSID\{A}\TreatAs = {B}
 *   → Actually instantiates {B} instead → loads {B}'s InprocServer32 DLL
 *   Applications using {A} transparently get {B}'s code running
 *
 * REFERENCES:
 *   MSDN: TreatAs, AutoConvertTo
 *   MSDN: The COM Elevation Moniker
 *   MITRE T1546.015 — COM Object Hijacking
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Check if a CLSID has TreatAs or AutoConvertTo redirection
 * --------------------------------------------------------------------- */
static void AuditCLSIDRedirection(DWORD *findings) {
    PrintInfo(L"  [1] HKCU TreatAs CLSID redirection (user-level COM hijack):\n");
    PrintInfo(L"      Attack: HKCU\\Software\\Classes\\CLSID\\{GUID}\\TreatAs redirects\n");
    PrintInfo(L"      HKLM CLSID without admin rights. Abuse if target CLSID is used by SYSTEM.\n\n");

    /* Check if HKCU CLSID root exists and is writable */
    HKEY hHKCU = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
                      L"Software\\Classes\\CLSID",
                      0, KEY_READ | KEY_WRITE, &hHKCU) == ERROR_SUCCESS) {
        PrintInfo(L"    HKCU\\Software\\Classes\\CLSID: WRITABLE (expected for current user)\n");
        PrintInfo(L"    → Can set TreatAs under any CLSID in HKCU to redirect COM activation\n");
        RegCloseKey(hHKCU);
    }

    /* Key SYSTEM service CLSIDs that use COM — check if they have TreatAs already */
    static const struct { const wchar_t *clsid; const wchar_t *service; } SYS_CLSIDS[] = {
        { L"{F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}", L"BITS" },
        { L"{9BA05972-F6A8-11CF-A442-00A0C90A8F39}", L"Shell folder (IShellFolder)" },
        { L"{49BD2028-1523-11D1-AD79-00C04FD8FDFF}", L"Task Scheduler 2.0" },
        { L"{B9AE1F7A-D8E9-4B62-8D3E-87A1B5ABB0A6}", L"Windows Firewall" },
        { NULL, NULL }
    };

    PrintInfo(L"    Key SYSTEM service CLSIDs — checking for TreatAs:\n");
    for (int i = 0; SYS_CLSIDS[i].clsid; i++) {
        wchar_t treatAsKey[512];
        _snwprintf(treatAsKey, _countof(treatAsKey),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\TreatAs", SYS_CLSIDS[i].clsid);

        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, treatAsKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t targetCLSID[128] = {0};
            DWORD cb = sizeof(targetCLSID);
            RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)targetCLSID, &cb);
            RegCloseKey(hKey);
            PrintInfo(L"      [!] %s (%s) → TreatAs → %s [SUSPICIOUS!]\n",
                      SYS_CLSIDS[i].clsid, SYS_CLSIDS[i].service, targetCLSID);

            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"COMTREATAS");
            _snwprintf(f.target, _countof(f.target),
                L"[SUSPICIOUS] COM TreatAs redirect: %s (%s) → %s",
                SYS_CLSIDS[i].clsid, SYS_CLSIDS[i].service, targetCLSID);
            _snwprintf(f.reason, _countof(f.reason),
                L"SYSTEM service CLSID %s (%s) has TreatAs → %s\n"
                L"        CoCreateInstance({%s}) is actually creating {%s}.\n"
                L"        If target CLSID InprocServer32 DLL is attacker-controlled → SYSTEM exec.\n"
                L"        This may be a persistence backdoor — review target CLSID.",
                SYS_CLSIDS[i].clsid, SYS_CLSIDS[i].service, targetCLSID,
                SYS_CLSIDS[i].clsid, targetCLSID);
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit COM Elevation Moniker CLSIDs for writable InprocServer32
 * --------------------------------------------------------------------- */
static void AuditElevationMonikerCLSIDs(DWORD *findings) {
    PrintInfo(L"  [2] COM Elevation Moniker CLSIDs (auto-elevated COM objects):\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Classes\\Elevation\\ClsId",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    Elevation\\ClsId not found\n\n");
        return;
    }

    DWORD idx = 0, total = 0, vulnCount = 0;
    wchar_t clsid[128];
    DWORD   clsidCch;

    while (TRUE) {
        clsidCch = _countof(clsid);
        LONG r = RegEnumKeyExW(hRoot, idx++, clsid, &clsidCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        total++;

        /* Resolve to InprocServer32 */
        wchar_t clsidKey[512];
        _snwprintf(clsidKey, _countof(clsidKey),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);

        HKEY hCLSID = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidKey, 0, KEY_READ, &hCLSID) != ERROR_SUCCESS)
            continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        DWORD cb = sizeof(dllPath);
        RegQueryValueExW(hCLSID, NULL, NULL, NULL, (LPBYTE)dllPath, &cb);
        RegCloseKey(hCLSID);
        if (!*dllPath) continue;

        wchar_t dllExe[MAX_PATH * 2] = {0};
        ExtractExePath(dllPath, dllExe, _countof(dllExe));
        if (!*dllExe) {
            ExpandEnvironmentStringsW(dllPath, dllExe, _countof(dllExe));
        }

        BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(dllExe);

        if (writable || !exists) {
            vulnCount++;
            PrintInfo(L"    [!] Elevation CLSID %s → %s%s\n",
                      clsid, dllExe, writable ? L" [WRITABLE!]" : L" [MISSING]");

            Finding f;
            f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
            wcscpy(f.module, L"COMTREATAS");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] Elevation Moniker CLSID %s → %s",
                writable ? L"WRITABLE" : L"MISSING", clsid, dllExe);
            _snwprintf(f.reason, _countof(f.reason),
                L"COM Elevation Moniker CLSID %s has %s InprocServer32 DLL: %s\n"
                L"        Elevation Moniker CLSIDs are auto-elevated through UAC without prompt.\n"
                L"        Application calls: CoCreateInstanceEx(CLSCTX_ENABLE_COM_ELEVATION_MONIKER)\n"
                L"        → Windows auto-elevates via consent.exe → elevated COM server\n"
                L"        %s → HIGH integrity code exec (UAC bypass) or SYSTEM depending on caller.",
                clsid,
                writable ? L"WRITABLE" : L"MISSING (plant)",
                dllExe,
                writable ? L"Replace DLL" : L"Plant DLL");
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hRoot);
    PrintInfo(L"    Total Elevation CLSIDs: %lu | Vulnerable: %lu\n\n", total, vulnCount);
}

/* -----------------------------------------------------------------------
 * Check if HKLM CLSID key is writable (can set TreatAs globally)
 * --------------------------------------------------------------------- */
static void AuditHKLMCLSIDWritability(DWORD *findings) {
    PrintInfo(L"  [3] HKLM CLSID root key writability:\n");

    static const wchar_t *CLSID_KEYS[] = {
        L"SOFTWARE\\Classes\\CLSID",
        L"SOFTWARE\\WOW6432Node\\Classes\\CLSID",
        NULL
    };

    for (int i = 0; CLSID_KEYS[i]; i++) {
        HKEY hKey = NULL;
        BOOL writable = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CLSID_KEYS[i],
                                        0, KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey) == ERROR_SUCCESS);
        if (writable) RegCloseKey(hKey);

        PrintInfo(L"    HKLM\\%s: %s\n", CLSID_KEYS[i],
                  writable ? L"WRITABLE! [can set TreatAs on any CLSID]" : L"not writable (expected)");

        if (writable) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"COMTREATAS");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] HKLM\\%s", CLSID_KEYS[i]);
            wcscpy(f.reason,
                L"HKLM CLSID root key is writable — can set TreatAs on ANY registered CLSID.\n"
                L"        Attack: Set TreatAs on a SYSTEM service CLSID → points to attacker CLSID.\n"
                L"        When SYSTEM service instantiates the target CLSID → attacker code runs.\n"
                L"        Can also set AutoConvertTo for OLE document embedded objects.\n"
                L"        Stealth: no new key creation, just adds TreatAs value under existing CLSID.");
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

void Module_COMTreatAs(void) {
    PrintHeader(L"COM TREATAS/ELEVATION  [CLSID redirection + COM Elevation Moniker auto-elevate]");

    PrintInfo(
        L"  COM TreatAs/AutoConvertTo redirect CoCreateInstance to different CLSID.\n"
        L"  COM Elevation Moniker CLSIDs are auto-elevated through UAC without user prompt.\n"
        L"  HKCU TreatAs can redirect HKLM CLSIDs without admin rights.\n\n");

    DWORD findings = 0;
    AuditCLSIDRedirection(&findings);
    AuditElevationMonikerCLSIDs(&findings);
    AuditHKLMCLSIDWritability(&findings);

    if (findings == 0)
        PrintInfo(L"  No COM TreatAs/Elevation Moniker LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

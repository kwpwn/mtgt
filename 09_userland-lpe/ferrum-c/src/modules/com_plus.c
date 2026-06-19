/*
 * com_plus.c — COM+ / Component Services LPE Surface
 *
 * WHAT COM+ IS:
 *   COM+ (Component Object Model Plus) extends COM with transaction support,
 *   object pooling, and role-based security. COM+ applications run in
 *   "dllhost.exe" surrogate processes (by default) or as NT services.
 *   The COM+ Catalog stores application configuration in:
 *   C:\Windows\system32\clbcatq.dll (runtime) and
 *   HKLM\SOFTWARE\Classes\AppID + COM+ catalog database.
 *
 * WHY COM+ IS AN LPE SURFACE:
 *
 *   1. COM+ SERVER APPLICATION "RUN AS" ACCOUNT:
 *      COM+ server applications can be configured to run as a specific account,
 *      including "Local System" (SYSTEM) or "Local Service".
 *      If the COM+ application's DLL is in a user-writable path:
 *      → Replace DLL → next COM+ activation → code exec as configured account.
 *
 *   2. COM+ LIBRARY APPLICATIONS (in-process):
 *      Library applications run in the client process context.
 *      If loaded into a High-IL process → code exec at High IL.
 *
 *   3. COM+ APPLICATION EXE PATH:
 *      COM+ server applications configured as NT Services have ImagePath.
 *      If ImagePath is writable → service replacement → SYSTEM.
 *
 *   4. COM+ COMPONENT DLL REGISTRATION:
 *      Each COM+ component has a DLL registered in the catalog.
 *      HKCR\CLSID\{GUID}\InprocServer32 — if writable → DLL replacement.
 *      (Different from DCOM_HIJACK: this specifically targets COM+ catalog)
 *
 *   5. ROLE-BASED SECURITY MISCONFIGURATION:
 *      COM+ applications may have roles granting access to "Everyone" or
 *      "Authenticated Users" — if the interface exposes privileged operations
 *      to these roles → privilege escalation via COM+ method calls.
 *
 * REGISTRY PATHS:
 *   HKLM\SOFTWARE\Classes\AppID\{GUID}: COM+ AppID
 *   HKLM\SOFTWARE\Classes\CLSID\{GUID}: COM+ component CLSIDs
 *   HKLM\SYSTEM\CurrentControlSet\Services: COM+ NT service registrations
 *
 * COM+ CATALOG DLL:
 *   C:\Windows\system32\clbcatq.dll (Catalog Services DLL)
 *   Loaded into EVERY COM+ application process — if writable → universal SYSTEM inject.
 *
 * REAL-WORLD CASES:
 *   - Enterprise middleware (Oracle, SAP, MQ Series) uses COM+ extensively
 *   - IIS (Internet Information Services) COM+ application pools
 *   - .NET Enterprise Services (System.EnterpriseServices) uses COM+
 *   - Various legacy Windows Server applications
 *
 * REFERENCES:
 *   COM+ documentation: https://docs.microsoft.com/en-us/windows/win32/cossdk/
 *   MITRE ATT&CK: T1546.015 — Component Object Model Hijacking
 *   COM+ Security: Interface-level and component-level security
 */

#include "../common.h"

/* COM+ application type flags */
#define COMPLUS_APP_TYPE_SERVER   1
#define COMPLUS_APP_TYPE_LIBRARY  2

/* COM+ related AppID keys */
#define COMPLUS_APPID_KEY L"SOFTWARE\\Classes\\AppID"

/* -----------------------------------------------------------------------
 * Check if a COM AppID is a COM+ server application with writable DLL
 * --------------------------------------------------------------------- */
static void AuditCOMPlusAppID(LPCWSTR appID, DWORD *findings) {
    wchar_t keyPath[256];
    _snwprintf(keyPath, _countof(keyPath), L"SOFTWARE\\Classes\\AppID\\%s", appID);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS) return;

    wchar_t appName[256] = {0};
    wchar_t runAs[128]   = {0};
    wchar_t localSrv[MAX_PATH * 2] = {0};
    DWORD   cb = sizeof(appName), type = 0;

    RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)appName, &cb);
    cb = sizeof(runAs);
    RegQueryValueExW(hKey, L"RunAs", NULL, &type, (LPBYTE)runAs, &cb);
    cb = sizeof(localSrv);
    RegQueryValueExW(hKey, L"LocalService", NULL, &type, (LPBYTE)localSrv, &cb);

    /* Check for COM+ marker */
    BOOL isCOMPlus = FALSE;
    HKEY hSub = NULL;
    wchar_t subPath[512];
    _snwprintf(subPath, _countof(subPath), L"%s\\COMPlusApplication", keyPath);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hSub)
            == ERROR_SUCCESS) {
        isCOMPlus = TRUE;
        RegCloseKey(hSub);
    }

    RegCloseKey(hKey);

    /* Only process COM+ server apps with SYSTEM/Network Service RunAs */
    if (!isCOMPlus && !*localSrv) return;
    if (!WcsContainsI(runAs, L"system") &&
        !WcsContainsI(runAs, L"service") &&
        !*localSrv) return;

    /* Find component CLSIDs for this AppID and check DLL paths */
    HKEY hClsRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hClsRoot)
            != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t clsid[64];
    DWORD   clsidCch;

    while (TRUE) {
        clsidCch = _countof(clsid);
        LONG r = RegEnumKeyExW(hClsRoot, idx++, clsid, &clsidCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        /* Check if this CLSID belongs to our AppID */
        wchar_t clsKeyPath[512];
        _snwprintf(clsKeyPath, _countof(clsKeyPath),
                   L"SOFTWARE\\Classes\\CLSID\\%s", clsid);

        HKEY hCls = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsKeyPath, 0, KEY_READ, &hCls)
                != ERROR_SUCCESS) continue;

        wchar_t clsAppID[64] = {0};
        DWORD   acb = sizeof(clsAppID);
        RegQueryValueExW(hCls, L"AppID", NULL, &type, (LPBYTE)clsAppID, &acb);
        RegCloseKey(hCls);

        if (_wcsicmp(clsAppID, appID) != 0) continue;

        /* Check InprocServer32 / LocalServer32 */
        static const wchar_t *serverKeys[] = {
            L"InprocServer32", L"LocalServer32", NULL
        };

        for (int si = 0; serverKeys[si]; si++) {
            wchar_t srvKeyPath[512];
            _snwprintf(srvKeyPath, _countof(srvKeyPath),
                       L"SOFTWARE\\Classes\\CLSID\\%s\\%s", clsid, serverKeys[si]);

            HKEY hSrv = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, srvKeyPath,
                              0, KEY_READ, &hSrv) != ERROR_SUCCESS) continue;

            wchar_t dllPath[MAX_PATH * 2] = {0};
            cb = sizeof(dllPath);
            RegQueryValueExW(hSrv, NULL, NULL, &type, (LPBYTE)dllPath, &cb);
            RegCloseKey(hSrv);

            if (!*dllPath) continue;

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));

            wchar_t exePath[MAX_PATH * 2] = {0};
            ExtractExePath(dllPath, exePath, _countof(exePath));
            if (!*exePath) wcsncpy(exePath, expanded, _countof(exePath) - 1);

            BOOL exists   = (GetFileAttributesW(exePath) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(exePath);

            if (!writable && !(!exists)) continue;

            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"COM_PLUS");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] COM+ DLL %s [%s]: %s",
                writable ? L"WRITABLE" : L"MISSING",
                clsid, *appName ? appName : appID, exePath);
            _snwprintf(f.reason, _countof(f.reason),
                L"COM+ component DLL is %s: %s\n"
                L"        AppID: %s  Name: %s  RunAs: %s\n"
                L"        COM+ app runs as: %s\n"
                L"        %s → code exec as %s on COM+ activation.",
                writable ? L"WRITABLE" : L"MISSING",
                exePath, appID, *appName ? appName : L"(unknown)",
                *runAs ? runAs : (*localSrv ? localSrv : L"(no RunAs)"),
                *runAs ? runAs : (*localSrv ? localSrv : L"caller"),
                writable ? L"Replace DLL" : L"Plant DLL at path",
                *runAs ? runAs : L"configured account");
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hClsRoot);
}

/* -----------------------------------------------------------------------
 * Check COM+ Catalog DLL writability
 * --------------------------------------------------------------------- */
static void AuditCOMPlusCatalog(DWORD *findings) {
    PrintInfo(L"  [1] COM+ Catalog DLL (clbcatq.dll):\n");

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, _countof(sysDir));

    wchar_t catDll[MAX_PATH * 2] = {0};
    _snwprintf(catDll, _countof(catDll), L"%s\\clbcatq.dll", sysDir);

    BOOL exists   = (GetFileAttributesW(catDll) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(catDll);

    PrintInfo(L"    %s: %s\n\n",
              catDll, !exists ? L"(not found)" : writable ? L"WRITABLE! (CRITICAL)" : L"ok");

    if (writable) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"COM_PLUS");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE] COM+ Catalog DLL: %s", catDll);
        wcscpy(f.reason,
            L"COM+ Catalog DLL (clbcatq.dll) is WRITABLE! "
            L"This DLL is loaded into EVERY COM+ application process. "
            L"Replace it → code execution in every COM+ app, including SYSTEM services. "
            L"Restart any COM+ application or IIS → payload runs as SYSTEM.");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Module entry: enumerate COM+ AppIDs
 * --------------------------------------------------------------------- */
void Module_ComPlus(void) {
    PrintHeader(L"COM+ APPLICATION SURFACE  [COM+ server apps running as SYSTEM with writable DLLs]");

    PrintInfo(
        L"  COM+ server applications can run as SYSTEM/NetworkService.\n"
        L"  Writable component DLLs = SYSTEM code execution on COM+ activation.\n"
        L"  Widely used by enterprise middleware (Oracle, SAP, IIS) = high hit rate.\n\n");

    DWORD findings = 0;

    AuditCOMPlusCatalog(&findings);

    PrintInfo(L"  [2] COM+ AppID server applications:\n");

    HKEY hAppID = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, COMPLUS_APPID_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hAppID)
            == ERROR_SUCCESS) {
        DWORD idx = 0, checked = 0;
        wchar_t appID[64];
        DWORD   appIDCch;

        while (TRUE) {
            appIDCch = _countof(appID);
            LONG r = RegEnumKeyExW(hAppID, idx++, appID, &appIDCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            if (appID[0] != L'{') continue;
            checked++;
            AuditCOMPlusAppID(appID, &findings);
        }
        RegCloseKey(hAppID);
        PrintInfo(L"    AppIDs checked: %lu\n\n", checked);
    }

    if (findings == 0)
        PrintInfo(L"  No COM+ LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  ACTIVATION TRIGGER:\n"
            L"    PowerShell: [Activator]::CreateInstance([Type]::GetTypeFromCLSID('{CLSID}'))\n"
            L"    Component Services (dcomcnfg.exe) → COM+ Applications → right-click → Start\n"
            L"    IIS: iisreset → reloads all COM+ app pools\n"
            L"    sc start <ComPlusNTService> → if configured as NT service\n");
    }
}

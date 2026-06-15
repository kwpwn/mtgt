/*
 * comsurrogate.c — COM Surrogate (dllhost.exe) DLL Audit
 *
 * COM Surrogate overview:
 *   When a COM class is activated out-of-process via AppID\DllSurrogate,
 *   Windows launches dllhost.exe which loads the InprocServer32 DLL.
 *   dllhost.exe can run at various integrity levels depending on:
 *     - The AppID's RunAs value (can be SYSTEM, or specific user)
 *     - Whether the COM object is auto-elevating
 *     - The calling context
 *
 * LPE surface:
 *   If an AppID has DllSurrogate="" (empty = use default dllhost) and:
 *     a) The InprocServer32 DLL is in a user-writable location
 *     b) The AppID has RunAs = "nt authority\system" or similar
 *   → Replace/plant DLL → activation triggers dllhost loading it at SYSTEM
 *
 * This is different from in-process COM hijacking (doc 01) because:
 *   - The code runs in a SEPARATE process (dllhost.exe)
 *   - Dllhost spawned by DCOMLAUNCH (SYSTEM) → inherits SYSTEM-ish context
 *   - Harder to detect (just looks like normal COM activation)
 *
 * Also checks: custom surrogate paths (DllSurrogate = "custom.exe")
 *   If the custom surrogate binary is user-writable → replace it.
 *
 * References:
 *   https://docs.microsoft.com/en-us/windows/win32/com/dll-surrogates
 *   AppID registry: HKCR\AppID\{guid}\DllSurrogate
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Internal: for a given AppID GUID, check DllSurrogate + RunAs
 * and correlate with InprocServer32 DLL paths.
 * --------------------------------------------------------------------- */
static void CheckAppID(LPCWSTR appidGuid, DWORD *findings) {
    wchar_t appidPath[256];
    _snwprintf(appidPath, _countof(appidPath), L"SOFTWARE\\Classes\\AppID\\%s", appidGuid);

    HKEY hAppID = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, appidPath, 0, KEY_READ, &hAppID)
            != ERROR_SUCCESS)
        return;

    /* Check DllSurrogate value */
    wchar_t surrogatePath[MAX_PATH] = {0};
    DWORD   cb = sizeof(surrogatePath), type = 0;
    BOOL    hasSurrogate = (RegQueryValueExW(hAppID, L"DllSurrogate", NULL, &type,
                                              (LPBYTE)surrogatePath,
                                              &cb) == ERROR_SUCCESS);

    /* Check RunAs value */
    wchar_t runAs[128] = {0};
    cb = sizeof(runAs);
    RegQueryValueExW(hAppID, L"RunAs", NULL, &type, (LPBYTE)runAs, &cb);

    RegCloseKey(hAppID);

    if (!hasSurrogate) return;

    /* DllSurrogate = "" → use default dllhost.exe
     * DllSurrogate = "path\to\custom.exe" → custom surrogate  */
    BOOL isDefaultSurrogate = (*surrogatePath == L'\0');
    BOOL isSystemRunAs      = WcsContainsI(runAs, L"system") ||
                               WcsContainsI(runAs, L"LocalSystem") ||
                               *runAs == L'\0';  /* empty RunAs + auto-elev = often SYSTEM */

    /* -- If custom surrogate binary is writable -- */
    if (!isDefaultSurrogate) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(surrogatePath, expanded, _countof(expanded));

        if (IsUserWritablePath(expanded) || IsFileWritable(expanded)) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"COMSURROGATE");
            wcsncpy(f.target, appidGuid, _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Custom COM surrogate binary is WRITABLE. "
                L"Replace → runs when any COM class with this AppID is activated. "
                L"RunAs: %s  Surrogate: %s",
                *runAs ? runAs : L"(default)", expanded);
            PrintFinding(&f);
            (*findings)++;
        }
        return;   /* custom surrogate doesn't load InprocServer32 DLL */
    }

    /* -- Default surrogate (dllhost.exe): find all InprocServer32 DLLs
     *    that reference this AppID and check their paths.             -- */
    /* Enumerate HKLM\SOFTWARE\Classes\CLSID to find classes with this AppID */
    HKEY hClsid = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hClsid)
            != ERROR_SUCCESS)
        return;

    DWORD   idx = 0;
    wchar_t clsidGuid[128];
    DWORD   clsidCch;

    while (TRUE) {
        clsidCch = _countof(clsidGuid);
        LONG ret = RegEnumKeyExW(hClsid, idx++, clsidGuid, &clsidCch,
                                  NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS)       continue;

        /* Check AppID value of this CLSID */
        wchar_t clsidPath[256];
        _snwprintf(clsidPath, _countof(clsidPath),
            L"SOFTWARE\\Classes\\CLSID\\%s", clsidGuid);

        HKEY hCls = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidPath, 0, KEY_READ, &hCls)
                != ERROR_SUCCESS)
            continue;

        wchar_t clsAppID[128] = {0};
        cb = sizeof(clsAppID);
        RegQueryValueExW(hCls, L"AppID", NULL, &type, (LPBYTE)clsAppID, &cb);
        RegCloseKey(hCls);

        if (_wcsicmp(clsAppID, appidGuid) != 0) continue;

        /* This CLSID uses our AppID with DllSurrogate → check its DLL */
        wchar_t inprocPath[256];
        _snwprintf(inprocPath, _countof(inprocPath),
            L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsidGuid);

        HKEY hInproc = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, inprocPath, 0, KEY_READ, &hInproc)
                != ERROR_SUCCESS)
            continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        cb = sizeof(dllPath);
        RegQueryValueExW(hInproc, NULL, NULL, &type, (LPBYTE)dllPath, &cb);
        RegCloseKey(hInproc);

        if (!*dllPath) continue;

        wchar_t dllExpanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dllPath, dllExpanded, _countof(dllExpanded));

        /* Only report if RunAs is SYSTEM-ish (LPE relevant) */
        if (!isSystemRunAs) continue;

        if (IsUserWritablePath(dllExpanded) || IsFileWritable(dllExpanded) ||
            GetFileAttributesW(dllExpanded) == INVALID_FILE_ATTRIBUTES)
        {
            const wchar_t *reason;
            Severity sev;
            if (IsFileWritable(dllExpanded)) {
                sev    = SEV_CRITICAL;
                reason = L"DLL is WRITABLE";
            } else if (GetFileAttributesW(dllExpanded) == INVALID_FILE_ATTRIBUTES) {
                sev    = SEV_HIGH;
                reason = L"DLL NOT FOUND (phantom load)";
            } else {
                sev    = SEV_HIGH;
                reason = L"DLL in user-writable location";
            }

            Finding f;
            f.severity = sev;
            wcscpy(f.module, L"COMSURROGATE");
            _snwprintf(f.target, _countof(f.target),
                L"CLSID:%s  AppID:%s", clsidGuid, appidGuid);
            _snwprintf(f.reason, _countof(f.reason),
                L"%s — loaded by dllhost.exe (COM surrogate) with RunAs:%s. "
                L"DLL: %s  "
                L"Trigger: CoCreateInstance({%s}, CLSCTX_LOCAL_SERVER, ...)",
                reason, *runAs ? runAs : L"System",
                dllExpanded, clsidGuid);
            PrintFinding(&f);
            (*findings)++;
        }
    }
    RegCloseKey(hClsid);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_ComSurrogate(void) {
    PrintHeader(L"COM SURROGATE (dllhost.exe) DLL AUDIT");

    PrintInfo(
        L"  Checking AppIDs with DllSurrogate + SYSTEM RunAs.\n"
        L"  These DLLs load in dllhost.exe activated by DCOMLAUNCH (SYSTEM).\n\n");

    HKEY hAppIdRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Classes\\AppID",
        0, KEY_READ | KEY_ENUMERATE_SUB_KEYS,
        &hAppIdRoot) != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open HKLM\\SOFTWARE\\Classes\\AppID\n");
        return;
    }

    DWORD idx = 0, total = 0;
    wchar_t appidGuid[128];
    DWORD   guidCch;

    while (TRUE) {
        guidCch = _countof(appidGuid);
        LONG ret = RegEnumKeyExW(hAppIdRoot, idx++, appidGuid, &guidCch,
                                  NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS)       continue;

        /* Only process GUID-format keys (e.g. {xxxxxxxx-...}) */
        if (appidGuid[0] != L'{') continue;

        CheckAppID(appidGuid, &total);
    }
    RegCloseKey(hAppIdRoot);

    if (total == 0)
        PrintInfo(L"  No COM surrogate DLL issues found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", total);
}

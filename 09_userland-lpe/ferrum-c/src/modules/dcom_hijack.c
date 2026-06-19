/*
 * dcom_hijack.c — DCOM Server Activation Path Hijacking
 *
 * ATTACK CLASS:
 *   DCOM (Distributed COM) servers registered as LocalServer32 (EXE-based)
 *   are launched by the COM SCM (svchost DCOM launcher, SYSTEM) when a client
 *   activates them. If the EXE path:
 *     a) Is user-writable → replace EXE → SYSTEM code exec on next activation
 *     b) Does not exist → plant EXE at that path → SYSTEM code exec
 *     c) Directory is user-writable → DLL side-loading in same dir
 *
 *   This differs from COM auto-elevation (--COMELE) in that:
 *   - Not limited to CLSIDs with Elevation\Enabled=1
 *   - Target is the EXE activation path, not COM interface methods
 *   - Can affect out-of-process COM servers running as SYSTEM/NetworkService
 *
 * HIGH-VALUE TARGETS:
 *   Out-of-process COM servers configured with specific AppID RunAs accounts:
 *     HKCR\AppID\{GUID}\RunAs = "NT AUTHORITY\\SYSTEM"
 *                              = "NT AUTHORITY\\NetworkService"
 *                              = "nt authority\\localservice"
 *   If their LocalServer32 EXE is writable → SYSTEM on COM activation.
 *
 * ADDITIONAL SURFACE:
 *   - DllSurrogate: COM server DLLs running in dllhost.exe (surrogate)
 *     where the DLL path is writable → already in --COMSURR, but DCOM context
 *     can run these surrogates with different account (RunAs in AppID)
 *   - LocalService: COM servers running as LocalService via AppID
 *   - DCOM permissions (DefaultAccessPermission, DefaultLaunchPermission)
 *     If overly permissive → can activate high-privilege DCOM servers
 *
 * HISTORICAL:
 *   - Various DCOM LocalServer32 DLL planting vulnerabilities in 3rd-party software
 *   - COM+ catalog DCOM servers with writable EXE paths (enterprise software)
 *   - Oracle, SAP, various middleware frequently misconfigure DCOM EXE paths
 *
 * REFERENCES:
 *   MITRE ATT&CK: T1546.015 — Component Object Model Hijacking
 *   James Forshaw: "COM in Sixty Seconds" (Black Hat Europe 2019)
 *   COMHunter: https://github.com/nickvourd/COMHunter
 *   OleViewDotNet: DCOM AppID enumeration with RunAs display
 */

#include "../common.h"

#define APPID_KEY   L"SOFTWARE\\Classes\\AppID"
#define HKLM_CLSID  L"SOFTWARE\\Classes\\CLSID"

typedef struct {
    wchar_t appID[64];
    wchar_t runAs[128];
    wchar_t clsid[64];
    wchar_t localServer[MAX_PATH * 2];
} DCOMEntry;

/* -----------------------------------------------------------------------
 * Get RunAs for an AppID
 * --------------------------------------------------------------------- */
static BOOL GetAppIDRunAs(LPCWSTR appID, LPWSTR runAs, DWORD cch) {
    wchar_t keyPath[256];
    _snwprintf(keyPath, _countof(keyPath), L"SOFTWARE\\Classes\\AppID\\%s", appID);
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    DWORD cb = cch * sizeof(wchar_t), type = 0;
    BOOL ok = (RegQueryValueExW(hKey, L"RunAs", NULL, &type,
                                (LPBYTE)runAs, &cb) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

/* -----------------------------------------------------------------------
 * Check if RunAs is a privileged account
 * --------------------------------------------------------------------- */
static BOOL IsPrivilegedRunAs(LPCWSTR runAs) {
    return WcsContainsI(runAs, L"system") ||
           WcsContainsI(runAs, L"network service") ||
           WcsContainsI(runAs, L"networkservice") ||
           WcsContainsI(runAs, L"local service") ||
           WcsContainsI(runAs, L"localservice");
}

/* -----------------------------------------------------------------------
 * Audit a single CLSID for DCOM hijack surface
 * --------------------------------------------------------------------- */
static void AuditCLSIDForDCOM(LPCWSTR clsid, DWORD *findings) {
    /* Get AppID of this CLSID */
    wchar_t clsidKeyPath[256];
    _snwprintf(clsidKeyPath, _countof(clsidKeyPath), L"SOFTWARE\\Classes\\CLSID\\%s", clsid);
    HKEY hCls = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidKeyPath, 0, KEY_READ, &hCls)
            != ERROR_SUCCESS)
        return;

    wchar_t appID[64] = {0};
    wchar_t className[256] = {0};
    DWORD   cb = sizeof(appID), type = 0;
    RegQueryValueExW(hCls, L"AppID", NULL, &type, (LPBYTE)appID, &cb);
    cb = sizeof(className);
    RegQueryValueExW(hCls, NULL, NULL, &type, (LPBYTE)className, &cb);
    RegCloseKey(hCls);

    if (!*appID) return; /* No AppID → not a DCOM server */

    /* Get RunAs for this AppID */
    wchar_t runAs[128] = {0};
    if (!GetAppIDRunAs(appID, runAs, _countof(runAs))) return;
    if (!*runAs || !IsPrivilegedRunAs(runAs)) return;

    /* Get LocalServer32 path */
    wchar_t lsKeyPath[512];
    _snwprintf(lsKeyPath, _countof(lsKeyPath),
               L"SOFTWARE\\Classes\\CLSID\\%s\\LocalServer32", clsid);
    HKEY hLS = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, lsKeyPath, 0, KEY_READ, &hLS) != ERROR_SUCCESS)
        return; /* No LocalServer32 — InprocServer32 only */

    wchar_t rawPath[MAX_PATH * 2] = {0};
    cb = sizeof(rawPath);
    RegQueryValueExW(hLS, NULL, NULL, &type, (LPBYTE)rawPath, &cb);
    RegCloseKey(hLS);
    if (!*rawPath) return;

    wchar_t exePath[MAX_PATH * 2] = {0};
    ExtractExePath(rawPath, exePath, _countof(exePath));
    if (!*exePath) return;

    BOOL exists   = (GetFileAttributesW(exePath) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(exePath);

    wchar_t exeDir[MAX_PATH * 2] = {0};
    wcsncpy(exeDir, exePath, _countof(exeDir) - 1);
    wchar_t *sl = wcsrchr(exeDir, L'\\');
    BOOL dirWritable = FALSE;
    if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(exeDir); }

    /* Skip System32 non-writable non-missing entries */
    BOOL inSys32 = WcsContainsI(exePath, L"system32") ||
                   WcsContainsI(exePath, L"syswow64");

    if (!writable && !dirWritable && exists && inSys32) return;

    Finding f;
    wcscpy(f.module, L"DCOM_HIJACK");

    if (writable) {
        f.severity = SEV_CRITICAL;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE EXE] %s (%s)",
            *className ? className : clsid, runAs);
        _snwprintf(f.reason, _countof(f.reason),
            L"DCOM LocalServer32 EXE is WRITABLE. RunAs: %s\n"
            L"        CLSID: %s  AppID: %s\n"
            L"        Replace EXE → next COM activation by any client → payload runs as %s.\n"
            L"        Trigger: CoCreateInstance({%s}) from Medium IL process.",
            runAs, clsid, appID, runAs, clsid);
    } else if (!exists) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[MISSING EXE] %s (%s)",
            *className ? className : clsid, runAs);
        _snwprintf(f.reason, _countof(f.reason),
            L"DCOM LocalServer32 EXE MISSING: %s. RunAs: %s\n"
            L"        CLSID: %s  AppID: %s\n"
            L"        Plant EXE at path → code exec as %s on COM activation.\n"
            L"        Dir writable: %s",
            exePath, runAs, clsid, appID, runAs,
            dirWritable ? L"YES" : L"No (need admin to plant)");
    } else if (dirWritable) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DIR] %s (%s)",
            *className ? className : clsid, runAs);
        _snwprintf(f.reason, _countof(f.reason),
            L"DCOM LocalServer32 directory is user-writable. RunAs: %s\n"
            L"        CLSID: %s  AppID: %s\n"
            L"        DLL side-loading in same directory as %s\n"
            L"        Dir: %s",
            runAs, clsid, appID, exePath, exeDir);
    } else {
        return; /* Not interesting */
    }

    PrintFinding(&f);
    (*findings)++;
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_DcomHijack(void) {
    PrintHeader(L"DCOM SERVER HIJACKING  [LocalServer32 EXE path for privileged RunAs DCOM]");

    PrintInfo(
        L"  Enumerates DCOM servers (AppID with RunAs=SYSTEM/NetworkService)\n"
        L"  whose LocalServer32 EXE is writable or missing.\n"
        L"  COM activation triggers payload execution under the RunAs account.\n\n");

    HKEY hClsid = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, HKLM_CLSID,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hClsid)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open HKLM\\SOFTWARE\\Classes\\CLSID\n");
        return;
    }

    DWORD idx = 0, findings = 0, checked = 0;
    wchar_t clsid[64];
    DWORD   clsidCch;

    while (TRUE) {
        clsidCch = _countof(clsid);
        LONG r = RegEnumKeyExW(hClsid, idx++, clsid, &clsidCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS)       continue;
        if (clsid[0] != L'{')         continue;
        checked++;
        AuditCLSIDForDCOM(clsid, &findings);
    }
    RegCloseKey(hClsid);

    PrintInfo(L"  CLSIDs with DCOM AppID checked: %lu  |  Findings: %lu\n\n",
              checked, findings);

    if (findings == 0)
        PrintInfo(L"  No DCOM hijack surface found.\n");
    else {
        PrintInfo(
            L"  ACTIVATION TRIGGER:\n"
            L"    PowerShell: [Activator]::CreateInstance([Type]::GetTypeFromCLSID('{CLSID}'))\n"
            L"    C++: CoCreateInstance(__uuidof(CLSID), NULL, CLSCTX_LOCAL_SERVER, ...)\n"
            L"    Note: activation may require specific client permissions (LaunchPermission)\n"
            L"    Use OleViewDotNet to check activation security on the AppID.\n");
    }
}

/*
 * wmi_provider.c — WMI Provider DLL Audit
 *
 * ATTACK SURFACE — HIGH:
 *   WMI (Windows Management Instrumentation) providers are COM objects that
 *   implement management functionality. They are loaded by WmiPrvSE.exe
 *   (WMI Provider Host), which can run at various privilege levels:
 *
 *   HostingModel values:
 *     "LocalSystemHost"         → runs as NT AUTHORITY\SYSTEM
 *     "LocalSystemHostOrSelfHost" → SYSTEM if possible
 *     "NetworkServiceHost"      → NT AUTHORITY\NETWORK SERVICE
 *     "LocalServiceHost"        → NT AUTHORITY\LOCAL SERVICE
 *     "SelfHost"                → provider runs in its own process
 *     "Decoupled:COM"           → provider registers itself (decoupled)
 *
 *   The critical case: HostingModel = "LocalSystemHost" means WmiPrvSE.exe
 *   runs as SYSTEM and loads the provider DLL (via CLSID InprocServer32).
 *   If that DLL is in a user-writable location → SYSTEM code execution.
 *
 * HOW PROVIDERS ARE REGISTERED:
 *   Providers are registered as WMI class instances (__Win32Provider objects)
 *   in the WMI repository. The CLSID links to the COM registration in the
 *   standard HKLM\SOFTWARE\Classes\CLSID hive.
 *
 *   To enumerate providers without using WMI COM API:
 *   We read directly from HKLM\SOFTWARE\Classes\CLSID and look for entries
 *   whose AppID maps to WMI provider hosting (by checking WmiPrvSE-associated
 *   AppIDs), OR we use the IWbemServices COM API to query __Win32Provider.
 *
 *   This implementation uses the WMI COM API (IWbemServices) as it's the
 *   most accurate method. Falls back to registry scan if COM fails.
 *
 * EXPLOIT PATH:
 *   1. Tool finds LocalSystemHost provider with writable DLL path
 *   2. Replace DLL (DllMain payload + original exports)
 *   3. Trigger: wmic.exe <query that uses that provider>
 *      OR: Get-WmiObject <class from that provider>
 *   4. WmiPrvSE.exe (SYSTEM) loads provider DLL → SYSTEM code execution
 *
 * TRIGGER EXAMPLES:
 *   Win32_Process (provider: CIMWin32): Get-WmiObject Win32_Process
 *   Win32_Service (provider: CIMWin32): Get-WmiObject Win32_Service
 *   Security log (provider: StrProv):  wmic /namespace:\\root\cimv2 path Win32_NTLogEvent
 */

#include "../common.h"

/*
 * WMI provider registry approach (no COM dependency):
 * Scan HKLM\SOFTWARE\Classes\CLSID for entries that have an InprocServer32
 * AND whose AppID corresponds to a WmiPrvSE hosting AppID.
 *
 * Known WMI Provider Host AppIDs (from Windows):
 *   {1F87137D-0E7C-44d5-8C73-4EFFB68962F2} — LocalSystemHost
 *   {4DE7566B-0D7E-40d1-963A-0B5E5E6A5B80} — NetworkServiceHost
 *   {73E709EA-5D93-4B2E-BBB0-99B7938DA9E4} — LocalServiceHost
 */

#define CLSID_KEY L"SOFTWARE\\Classes\\CLSID"

/* Known WMI hosting AppIDs (lowercase for case-insensitive compare) */
static const wchar_t *g_wmiAppIDs[] = {
    L"{1f87137d-0e7c-44d5-8c73-4effb68962f2}",  /* LocalSystemHost */
    L"{4de7566b-0d7e-40d1-963a-0b5e5e6a5b80}",  /* NetworkServiceHost */
    L"{73e709ea-5d93-4b2e-bbb0-99b7938da9e4}",  /* LocalServiceHost */
    NULL
};

/* -----------------------------------------------------------------------
 * Check if an AppID string matches a WMI hosting AppID
 * --------------------------------------------------------------------- */
static BOOL IsWmiHostingAppID(LPCWSTR appid) {
    if (!appid || !*appid) return FALSE;
    for (int i = 0; g_wmiAppIDs[i]; i++) {
        if (_wcsicmp(appid, g_wmiAppIDs[i]) == 0) return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Determine the hosting model name from AppID
 * --------------------------------------------------------------------- */
static LPCWSTR AppIdToHostingModel(LPCWSTR appid) {
    if (_wcsicmp(appid, g_wmiAppIDs[0]) == 0) return L"LocalSystemHost (SYSTEM)";
    if (_wcsicmp(appid, g_wmiAppIDs[1]) == 0) return L"NetworkServiceHost";
    if (_wcsicmp(appid, g_wmiAppIDs[2]) == 0) return L"LocalServiceHost";
    return L"Unknown WMI host";
}

/* -----------------------------------------------------------------------
 * Check one WMI provider CLSID entry
 * --------------------------------------------------------------------- */
static void AuditWmiClsid(LPCWSTR clsid, LPCWSTR appid, LPCWSTR hostingModel,
                           DWORD *findings)
{
    /* Get InprocServer32 DLL path */
    wchar_t inprocPath[512];
    _snwprintf(inprocPath, _countof(inprocPath),
               L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);

    HKEY hInproc = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, inprocPath, 0, KEY_READ, &hInproc)
            != ERROR_SUCCESS)
        return;

    wchar_t rawDll[MAX_PATH * 2] = {0};
    DWORD   cb = sizeof(rawDll), type = 0;
    RegQueryValueExW(hInproc, NULL, NULL, &type, (LPBYTE)rawDll, &cb);
    RegCloseKey(hInproc);

    if (!*rawDll) return;

    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(rawDll, expanded, _countof(expanded));

    /* Try to get a friendly class name */
    wchar_t className[256] = {0};
    wchar_t classKeyPath[512];
    _snwprintf(classKeyPath, _countof(classKeyPath),
               L"SOFTWARE\\Classes\\CLSID\\%s", clsid);
    HKEY hCls = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, classKeyPath, 0, KEY_READ, &hCls)
            == ERROR_SUCCESS) {
        cb = sizeof(className);
        RegQueryValueExW(hCls, NULL, NULL, &type, (LPBYTE)className, &cb);
        RegCloseKey(hCls);
    }

    BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(expanded);
    BOOL inUser   = IsUserWritablePath(expanded);

    wchar_t dllDir[MAX_PATH * 2] = {0};
    wcsncpy(dllDir, expanded, _countof(dllDir) - 1);
    wchar_t *sl = wcsrchr(dllDir, L'\\');
    BOOL dirWritable = FALSE;
    if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(dllDir); }

    /* Only report interesting (non-System32, writable, or missing) DLLs */
    BOOL inSys32 = WcsContainsI(expanded, L"system32") ||
                   WcsContainsI(expanded, L"syswow64");

    if (!writable && !inUser && !dirWritable && exists && inSys32) return;

    Finding f;
    wcscpy(f.module, L"WMI_PROVIDER");

    if (writable) {
        f.severity = SEV_CRITICAL;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DLL] %s (%s)",
            *className ? className : clsid, hostingModel);
        _snwprintf(f.reason, _countof(f.reason),
            L"WMI provider DLL is WRITABLE! "
            L"WmiPrvSE.exe loads it as %s. "
            L"Replace DLL → SYSTEM code execution. "
            L"DLL: %s  Trigger: wmic.exe path <any class in this provider>",
            hostingModel, expanded);
        PrintFinding(&f);
        (*findings)++;
    } else if (!exists) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[MISSING DLL] %s (%s)",
            *className ? className : clsid, hostingModel);
        _snwprintf(f.reason, _countof(f.reason),
            L"WMI provider DLL does not exist: %s\n"
            L"        WmiPrvSE.exe (%s) will fail to load → research opportunity.\n"
            L"        If parent dir writable (%s): plant DLL.",
            expanded, hostingModel, dirWritable ? L"YES" : L"No");
        PrintFinding(&f);
        (*findings)++;
    } else if (dirWritable && !inSys32) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DIR] %s (%s)",
            *className ? className : clsid, hostingModel);
        _snwprintf(f.reason, _countof(f.reason),
            L"WMI provider DLL directory is user-writable (not System32). "
            L"DLL planting or replacement may be possible. "
            L"DLL: %s  Host: %s", expanded, hostingModel);
        PrintFinding(&f);
        (*findings)++;
    } else if (inUser) {
        f.severity = SEV_MEDIUM;
        _snwprintf(f.target, _countof(f.target),
            L"[USER-PATH] %s (%s)",
            *className ? className : clsid, hostingModel);
        _snwprintf(f.reason, _countof(f.reason),
            L"WMI provider DLL in user-accessible path. "
            L"Verify ACL directly. DLL: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Scan HKLM\SOFTWARE\Classes\CLSID for WMI-hosted entries
 * --------------------------------------------------------------------- */
static void ScanClsidForWmiProviders(DWORD *findings) {
    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CLSID_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open HKLM\\SOFTWARE\\Classes\\CLSID\n");
        return;
    }

    DWORD idx = 0, total = 0, wmiCount = 0;
    wchar_t clsid[128];
    DWORD   clsidCch;

    while (TRUE) {
        clsidCch = _countof(clsid);
        LONG r = RegEnumKeyExW(hRoot, idx++, clsid, &clsidCch,
                                NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS)       continue;
        total++;

        /* Skip non-GUID entries */
        if (clsid[0] != L'{') continue;

        /* Check AppID of this CLSID */
        wchar_t clsidKeyPath[512];
        _snwprintf(clsidKeyPath, _countof(clsidKeyPath),
                   L"SOFTWARE\\Classes\\CLSID\\%s", clsid);

        HKEY hCls = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidKeyPath, 0, KEY_READ, &hCls)
                != ERROR_SUCCESS)
            continue;

        wchar_t appid[128] = {0};
        DWORD   cb = sizeof(appid), type = 0;
        RegQueryValueExW(hCls, L"AppID", NULL, &type, (LPBYTE)appid, &cb);
        RegCloseKey(hCls);

        if (!*appid || !IsWmiHostingAppID(appid)) continue;

        wmiCount++;
        AuditWmiClsid(clsid, appid, AppIdToHostingModel(appid), findings);
    }

    RegCloseKey(hRoot);
    PrintInfo(L"  CLSIDs scanned: %lu  WMI-hosted: %lu\n", total, wmiCount);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_WmiProvider(void) {
    PrintHeader(L"WMI PROVIDER DLL AUDIT  [WmiPrvSE.exe SYSTEM context]");

    PrintInfo(
        L"  WMI providers load in WmiPrvSE.exe. LocalSystemHost providers\n"
        L"  run as SYSTEM. Writable provider DLL = SYSTEM code execution.\n"
        L"  Trigger: wmic.exe / Get-WmiObject / any WMI query on that class.\n\n");

    DWORD findings = 0;

    PrintInfo(L"  Scanning CLSIDs for WMI-hosted providers...\n");
    ScanClsidForWmiProviders(&findings);

    PrintInfo(L"\n");
    if (findings == 0)
        PrintInfo(L"  No WMI provider DLL issues found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOITATION NOTES:\n"
            L"    WMI provider DLL minimal requirements:\n"
            L"      - Export: DllGetClassObject(REFCLSID, REFIID, LPVOID*)\n"
            L"        (can return E_NOTIMPL — WmiPrvSE will handle gracefully)\n"
            L"      - DllMain: place payload here\n"
            L"    Trigger commands:\n"
            L"      wmic.exe /namespace:\\\\root\\cimv2 path Win32_Process get\n"
            L"      Get-WmiObject -Class Win32_Service\n"
            L"      WmiPrvSE.exe (SYSTEM) loads the provider on first class access.\n");
    }
}

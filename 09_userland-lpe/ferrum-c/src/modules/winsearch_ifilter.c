/*
 * winsearch_ifilter.c — Windows Search IFilter & Protocol Handler DLL Hijacking
 *
 * RESEARCH SOURCES:
 *   - Microsoft Windows Search Indexer (SearchIndexer.exe) runs as SYSTEM
 *   - IFilter COM interface: documented in Windows SDK, MSDN IFilter
 *   - Protocol handlers: documented in Windows Search SDK
 *   - Registry layout: HKCR\CLSID\{...} for IFilter, HKLM\SOFTWARE\Microsoft\Windows Search\
 *   - Research: Matthew Graeber (persistence via COM), Andrea Fortuna (Windows Search LPE)
 *   - CVE-2012-0176 (older WS LPE for context), James Forshaw COM research
 *
 * ATTACK SURFACE:
 *   Windows Search Indexer (SearchIndexer.exe):
 *     - Runs as LOCAL SYSTEM with SeBackupPrivilege, SeTakeOwnershipPrivilege
 *     - Loads IFilter DLLs to extract text from files for indexing
 *     - Loads Protocol Handler DLLs to traverse data stores (mapi:// iehistory://)
 *     - File type → IFilter: HKLM\SOFTWARE\Classes\.{ext}\PersistentHandler → CLSID
 *     - CLSID → InprocServer32 DLL → loaded by SearchIndexer.exe (SYSTEM!)
 *     - Protocol → DLL: HKLM\SOFTWARE\Microsoft\Windows Search\ProtocolHandlers\{proto}
 *
 * TRIGGER: Index any file of the targeted extension type, or force re-indexing
 *   wmic service call startservice Name="wsearch"
 *   Control Panel → Indexing Options → Rebuild
 *
 * REFERENCES:
 *   MSDN: IFilter interface, Persistent Handlers
 *   MITRE T1546.015 (COM Object Hijacking)
 *   https://docs.microsoft.com/en-us/windows/win32/search/developing-protocol-handlers
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Enumerate IFilter persistent handlers for writable DLLs
 * --------------------------------------------------------------------- */
static void AuditIFilters(DWORD *findings) {
    PrintInfo(L"  [1] IFilter DLLs loaded by SearchIndexer.exe (SYSTEM):\n");

    /* Common file extensions that have IFilters registered */
    static const wchar_t *IFILTER_EXTS[] = {
        L".docx", L".xlsx", L".pptx", L".doc", L".xls", L".ppt",
        L".pdf", L".odt", L".ods", L".htm", L".html", L".eml",
        L".msg", L".mht", L".xml", L".zip", L".one", L".vsd",
        L".chm", L".msi", L".txt", L".csv", NULL
    };

    DWORD vulnCount = 0;
    for (int i = 0; IFILTER_EXTS[i]; i++) {
        /* Step 1: Extension → PersistentHandler GUID */
        wchar_t extKey[256];
        _snwprintf(extKey, _countof(extKey),
                   L"SOFTWARE\\Classes\\%s\\PersistentHandler", IFILTER_EXTS[i]);

        HKEY hExt = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, extKey, 0, KEY_READ, &hExt) != ERROR_SUCCESS)
            continue;

        wchar_t phGUID[128] = {0};
        DWORD cb = sizeof(phGUID);
        RegQueryValueExW(hExt, NULL, NULL, NULL, (LPBYTE)phGUID, &cb);
        RegCloseKey(hExt);
        if (!*phGUID) continue;

        /* Step 2: PersistentHandler GUID → IFilter CLSID */
        wchar_t phKey[512];
        _snwprintf(phKey, _countof(phKey),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\PersistentAddinsRegistered\\"
                   L"{89BCB740-6119-101A-BCB7-00DD010655AF}", phGUID);

        HKEY hPH = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, phKey, 0, KEY_READ, &hPH) != ERROR_SUCCESS)
            continue;

        wchar_t iFilterCLSID[128] = {0};
        cb = sizeof(iFilterCLSID);
        RegQueryValueExW(hPH, NULL, NULL, NULL, (LPBYTE)iFilterCLSID, &cb);
        RegCloseKey(hPH);
        if (!*iFilterCLSID) continue;

        /* Step 3: IFilter CLSID → InprocServer32 DLL */
        wchar_t clsidKey[512];
        _snwprintf(clsidKey, _countof(clsidKey),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", iFilterCLSID);

        HKEY hCLSID = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidKey, 0, KEY_READ, &hCLSID) != ERROR_SUCCESS)
            continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        cb = sizeof(dllPath);
        RegQueryValueExW(hCLSID, NULL, NULL, NULL, (LPBYTE)dllPath, &cb);
        RegCloseKey(hCLSID);
        if (!*dllPath) continue;

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));

        wchar_t dllExe[MAX_PATH * 2] = {0};
        ExtractExePath(dllPath, dllExe, _countof(dllExe));
        if (!*dllExe) wcsncpy(dllExe, expanded, _countof(dllExe)-1);

        BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(dllExe);

        if (writable || !exists) {
            vulnCount++;
            PrintInfo(L"    [!] %s IFilter CLSID: %s → %s%s\n",
                      IFILTER_EXTS[i], iFilterCLSID, dllExe,
                      writable ? L" [WRITABLE]" : L" [MISSING]");

            Finding f;
            f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
            wcscpy(f.module, L"WINSEARCH");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] IFilter DLL for %s: %s → %s",
                writable ? L"WRITABLE" : L"MISSING",
                IFILTER_EXTS[i], iFilterCLSID, dllExe);
            _snwprintf(f.reason, _countof(f.reason),
                L"IFilter InprocServer32 for %s extension is %s: %s\n"
                L"        CLSID: %s\n"
                L"        SearchIndexer.exe runs as LOCAL SYSTEM and loads this DLL.\n"
                L"        %s the DLL → SYSTEM code exec when indexer processes any %s file.\n"
                L"        Trigger: place a %s file in an indexed folder, wait for indexer\n"
                L"        or restart Windows Search service (net stop wsearch; net start wsearch)",
                IFILTER_EXTS[i],
                writable ? L"WRITABLE" : L"MISSING (plant a DLL here)",
                dllExe, iFilterCLSID,
                writable ? L"Replace" : L"Plant",
                IFILTER_EXTS[i], IFILTER_EXTS[i]);
            PrintFinding(&f);
            (*findings)++;
        }
    }
    if (vulnCount == 0)
        PrintInfo(L"    No vulnerable IFilter DLLs found\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Enumerate Windows Search Protocol Handlers for writable DLLs
 * --------------------------------------------------------------------- */
static void AuditProtocolHandlers(DWORD *findings) {
    PrintInfo(L"  [2] Windows Search protocol handler DLLs:\n");

    HKEY hProto = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows Search\\ProtocolHandlers",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hProto) != ERROR_SUCCESS) {
        PrintInfo(L"    Not found (Windows Search not installed or not configured)\n\n");
        return;
    }

    DWORD idx = 0, vulnCount = 0;
    wchar_t proto[128];
    DWORD   protoCch;

    while (TRUE) {
        protoCch = _countof(proto);
        LONG r = RegEnumKeyExW(hProto, idx++, proto, &protoCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        /* Get CLSID for this protocol handler */
        wchar_t protoKeyPath[512];
        _snwprintf(protoKeyPath, _countof(protoKeyPath),
                   L"SOFTWARE\\Microsoft\\Windows Search\\ProtocolHandlers\\%s", proto);

        HKEY hPH = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, protoKeyPath, 0, KEY_READ, &hPH) != ERROR_SUCCESS)
            continue;

        wchar_t phCLSID[128] = {0};
        DWORD cb = sizeof(phCLSID), type = 0;
        RegQueryValueExW(hPH, NULL, NULL, &type, (LPBYTE)phCLSID, &cb);
        RegCloseKey(hPH);
        if (!*phCLSID) continue;

        /* Resolve CLSID → InprocServer32 DLL */
        wchar_t clsidKey[512];
        _snwprintf(clsidKey, _countof(clsidKey),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", phCLSID);

        HKEY hCLSID = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidKey, 0, KEY_READ, &hCLSID) != ERROR_SUCCESS)
            continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        cb = sizeof(dllPath);
        RegQueryValueExW(hCLSID, NULL, NULL, NULL, (LPBYTE)dllPath, &cb);
        RegCloseKey(hCLSID);
        if (!*dllPath) continue;

        wchar_t dllExe[MAX_PATH * 2] = {0};
        ExtractExePath(dllPath, dllExe, _countof(dllExe));
        if (!*dllExe) wcsncpy(dllExe, dllPath, _countof(dllExe)-1);

        BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(dllExe);

        PrintInfo(L"    %s → %s → %s%s\n",
                  proto, phCLSID, dllExe,
                  writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

        if (writable || !exists) {
            vulnCount++;
            Finding f;
            f.severity = writable ? SEV_CRITICAL : SEV_MEDIUM;
            wcscpy(f.module, L"WINSEARCH");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] Search protocol handler DLL '%s': %s → %s",
                writable ? L"WRITABLE" : L"MISSING",
                proto, phCLSID, dllExe);
            _snwprintf(f.reason, _countof(f.reason),
                L"Windows Search protocol handler '%s' has %s InprocServer32 DLL: %s\n"
                L"        CLSID: %s\n"
                L"        Protocol handlers are loaded by SearchIndexer.exe (LOCAL SYSTEM)\n"
                L"        when indexing %s:// URIs.\n"
                L"        %s → SYSTEM DLL load.",
                proto, writable ? L"WRITABLE" : L"MISSING", dllExe, phCLSID, proto,
                writable ? L"Replace DLL" : L"Plant DLL at path");
            PrintFinding(&f);
            (*findings)++;
        }
    }
    RegCloseKey(hProto);
    if (vulnCount == 0)
        PrintInfo(L"    No vulnerable protocol handler DLLs found\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check Windows Search service account
 * --------------------------------------------------------------------- */
static void AuditSearchServiceAccount(void) {
    PrintInfo(L"  [3] Windows Search service account:\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"WSearch", SERVICE_QUERY_CONFIG);
    if (hSvc) {
        BYTE buf[4096] = {0};
        DWORD needed = 0;
        if (QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)buf,
                                sizeof(buf), &needed)) {
            LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)buf;
            PrintInfo(L"    Service: WSearch  Account: %s\n",
                      cfg->lpServiceStartName ? cfg->lpServiceStartName : L"(null)");
            if (cfg->lpServiceStartName &&
                _wcsicmp(cfg->lpServiceStartName, L"LocalSystem") == 0)
                PrintInfo(L"    [SYSTEM] SearchIndexer runs as LOCAL SYSTEM\n");
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    PrintInfo(L"\n");
}

void Module_WinSearchIFilter(void) {
    PrintHeader(L"WINDOWS SEARCH IFILTER/PROTOCOL  [SearchIndexer.exe=SYSTEM loads IFilter/Protocol DLLs]");

    PrintInfo(
        L"  SearchIndexer.exe (LOCAL SYSTEM) loads IFilter DLLs to extract text from files.\n"
        L"  Protocol handlers traverse data stores (mapi://, csc://, iehistory://).\n"
        L"  Writable IFilter or protocol handler DLL → code exec as SYSTEM on indexing.\n\n");

    DWORD findings = 0;
    AuditSearchServiceAccount();
    AuditIFilters(&findings);
    AuditProtocolHandlers(&findings);

    if (findings == 0)
        PrintInfo(L"  No Windows Search IFilter/protocol handler LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

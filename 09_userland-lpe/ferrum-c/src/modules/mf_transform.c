/*
 * mf_transform.c — Media Foundation Transform (MFT) & DirectShow Filter DLL Hijacking
 *
 * RESEARCH SOURCES:
 *   - Media Foundation Transforms (MFT): HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\
 *     Documented in MSDN: MFTRegister(), MFTEnum()
 *   - DirectShow filters: HKLM\SOFTWARE\Classes\CLSID\{...}\ with Filter key
 *   - MFT loading: mfpat.dll, mf.dll load MFTs in-process for audio/video encode/decode
 *   - DirectShow: quartz.dll (Filter Graph Manager) loads DirectShow filter DLLs
 *   - Service context: Various SYSTEM services use MFT for transcoding:
 *     Windows Media Sharing Service (WMPNetworkSvc = NetworkService)
 *     PC Health Check (system health monitoring)
 *     Microsoft Camera service (FrameServer = LOCAL SYSTEM)
 *     Windows Recall (AI indexing on Copilot+ PCs = SYSTEM context)
 *   - Research:
 *     - Matthew Graeber: DirectShow filter DLL as persistence mechanism
 *     - Hexacorn: "Media Foundation DLL persistence" (blog.hexacorn.com)
 *     - Windows Recall (introduced in Windows 11 24H2):
 *       Uses MFT for screen capture processing — runs as SYSTEM
 *     - MFT writable DLL → loaded by any app doing media:
 *       Edge, Teams, Zoom, Windows Camera, OBS, Zoom
 *
 * ATTACK SURFACE:
 *   1. MFT InprocServer32 DLL writable → code exec in any media-processing process
 *   2. DirectShow filter InprocServer32 DLL writable → code exec in filter graph
 *   3. MFT category: HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\{categoryGUID}\
 *      Contains list of MFT CLSIDs per category (video decode, audio decode, etc.)
 *   4. Windows Camera Frame Server (FrameServer service = LOCAL SYSTEM) uses MFTs
 *   5. Windows Recall (AI screenshot indexer = SYSTEM) uses MFTs for video processing
 *
 * REGISTRATION:
 *   MFTRegister() → HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\{GUID}\InprocServer32
 *   Category entries: HKLM\SOFTWARE\Classes\MediaFoundation\Transforms\Categories\{catGUID}\{mftGUID}
 *
 * REFERENCES:
 *   MSDN: MFTRegister, MFTEnum, Media Foundation Transforms
 *   MSDN: DirectShow SDK (deprecated but DLLs still loaded)
 *   MITRE T1546.015 (COM Object Hijacking)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Enumerate MFT CLSIDs and check InprocServer32 DLL writability
 * --------------------------------------------------------------------- */
static void AuditMFTransforms(DWORD *findings) {
    PrintInfo(L"  [1] Media Foundation Transform (MFT) DLLs:\n");

    static const wchar_t *MFT_ROOTS[] = {
        L"SOFTWARE\\Classes\\MediaFoundation\\Transforms",
        L"SOFTWARE\\WOW6432Node\\Classes\\MediaFoundation\\Transforms",
        NULL
    };

    for (int ri = 0; MFT_ROOTS[ri]; ri++) {
        HKEY hRoot = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MFT_ROOTS[ri],
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS)
            continue;

        PrintInfo(L"    Path: HKLM\\%s\n", MFT_ROOTS[ri]);
        DWORD idx = 0, vulnCount = 0;
        wchar_t clsid[128];
        DWORD   clsidCch;

        while (TRUE) {
            clsidCch = _countof(clsid);
            LONG r = RegEnumKeyExW(hRoot, idx++, clsid, &clsidCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            if (clsid[0] != L'{') continue; /* Skip "Categories" subkey etc. */

            /* Get FriendlyName */
            wchar_t mftKeyPath[512];
            _snwprintf(mftKeyPath, _countof(mftKeyPath), L"%s\\%s", MFT_ROOTS[ri], clsid);

            HKEY hMFT = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, mftKeyPath, 0, KEY_READ, &hMFT) != ERROR_SUCCESS)
                continue;

            wchar_t friendlyName[256] = {0};
            DWORD cb = sizeof(friendlyName);
            RegQueryValueExW(hMFT, NULL, NULL, NULL, (LPBYTE)friendlyName, &cb);
            RegCloseKey(hMFT);

            /* Resolve CLSID → InprocServer32 */
            wchar_t clsidKey[512];
            _snwprintf(clsidKey, _countof(clsidKey),
                       L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);

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
            if (!*dllExe) {
                ExpandEnvironmentStringsW(dllPath, dllExe, _countof(dllExe));
            }

            BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(dllExe);

            if (writable || !exists) {
                vulnCount++;
                PrintInfo(L"      [!] %s [%s] → %s%s\n",
                          *friendlyName ? friendlyName : clsid, clsid, dllExe,
                          writable ? L" [WRITABLE!]" : L" [MISSING]");

                Finding f;
                f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
                wcscpy(f.module, L"MFTRANSFORM");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] MFT DLL '%s' (%s): %s",
                    writable ? L"WRITABLE" : L"MISSING",
                    *friendlyName ? friendlyName : clsid, clsid, dllExe);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Media Foundation Transform '%s' has %s InprocServer32 DLL: %s\n"
                    L"        CLSID: %s\n"
                    L"        MFTs are loaded by any app doing media encode/decode:\n"
                    L"        Edge, Teams, Zoom, Windows Camera, Windows Media Player\n"
                    L"        FrameServer service (Windows Camera) runs as LOCAL SYSTEM.\n"
                    L"        Windows Recall AI indexer (Win11 24H2) runs as SYSTEM.\n"
                    L"        %s → code exec in media-processing process.",
                    *friendlyName ? friendlyName : clsid,
                    writable ? L"WRITABLE" : L"MISSING (plant)",
                    dllExe, clsid,
                    writable ? L"Replace DLL" : L"Plant DLL at path");
                PrintFinding(&f);
                (*findings)++;
            }
        }
        if (vulnCount == 0)
            PrintInfo(L"      No vulnerable MFT DLLs found\n");
        RegCloseKey(hRoot);
        PrintInfo(L"\n");
    }
}

/* -----------------------------------------------------------------------
 * Check Windows Camera Frame Server service (SYSTEM)
 * --------------------------------------------------------------------- */
static void AuditFrameServer(DWORD *findings) {
    PrintInfo(L"  [2] Windows Camera Frame Server (FrameServer = LOCAL SYSTEM):\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return;

    static const wchar_t *FSVC[] = { L"FrameServer", L"FrameServerMonitor", NULL };
    for (int i = 0; FSVC[i]; i++) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, FSVC[i], SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
        if (!hSvc) continue;

        BYTE buf[4096] = {0};
        DWORD needed = 0;
        if (QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)buf, sizeof(buf), &needed)) {
            LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)buf;
            SERVICE_STATUS status = {0};
            QueryServiceStatus(hSvc, &status);
            PrintInfo(L"    %s: account=%s  status=%s\n",
                      FSVC[i],
                      cfg->lpServiceStartName ? cfg->lpServiceStartName : L"unknown",
                      status.dwCurrentState == SERVICE_RUNNING ? L"RUNNING" : L"stopped");
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    PrintInfo(L"\n");
}

void Module_MFTransform(void) {
    PrintHeader(L"MEDIA FOUNDATION TRANSFORMS  [MFT DLL hijacking — FrameServer=SYSTEM, Recall=SYSTEM]");

    PrintInfo(
        L"  MFT DLLs are loaded by any process doing audio/video encode/decode.\n"
        L"  Windows Camera FrameServer (SYSTEM) and Windows Recall AI indexer (SYSTEM) use MFTs.\n"
        L"  Writable MFT InprocServer32 DLL → code exec in media-processing process.\n\n");

    DWORD findings = 0;
    AuditFrameServer(&findings);
    AuditMFTransforms(&findings);

    if (findings == 0)
        PrintInfo(L"  No MFT LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

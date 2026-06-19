/*
 * msdtc_surface.c — MSDTC XA Transaction Manager DLL Hijacking
 *
 * RESEARCH SOURCES:
 *   - MSDTC (Distributed Transaction Coordinator) XA DLL documentation:
 *     HKLM\SOFTWARE\Microsoft\MSDTC\XATM\DLLs
 *   - MSDTC service account: NETWORK SERVICE (has SeImpersonatePrivilege)
 *   - XA transactions: X/Open XA standard, DLL interface for database resource managers
 *     Oracle XA: xa_switch_t interface; IBM MQ XA; Sybase XA
 *   - Research: MSDTC XA DLL loading behavior (Didier Stevens, Hexacorn blog)
 *     https://www.hexacorn.com/blog/2022/ (MSDTC persistence)
 *   - Andrea Fortuna: MSDTC as persistence mechanism
 *   - MSDTC log path: C:\Windows\System32\MsDtc\MSDTC.LOG (writable = log poisoning)
 *   - MSDTC security config: HKLM\SOFTWARE\Microsoft\MSDTC\Security
 *
 * ATTACK SURFACE:
 *   MSDTC loads XA DLLs (specified by database clients for distributed transactions).
 *   Service: msdtc.exe runs as NETWORK SERVICE with SeImpersonatePrivilege.
 *   If NETWORK SERVICE → SeImpersonatePrivilege → PrintSpoofer/RoguePotato → SYSTEM.
 *   Additionally: MSDTC on some configs runs as LOCAL SYSTEM.
 *
 *   XA DLLs: Oracle (xa_d8.dll), IBM MQ (mqxxa.dll), SAP (saptxlq.dll) etc.
 *   These are registered in HKLM\SOFTWARE\Microsoft\MSDTC\XATM\DLLs\{name}\OpenDLL
 *
 * MSDTC SECURITY CONFIG:
 *   HKLM\SOFTWARE\Microsoft\MSDTC\Security\:
 *   NetworkDtcAccess = 0/1 (can be used for network transactions)
 *   XaTransactions = 0/1 (XA transactions enabled)
 *   LuTransactions = 0/1 (LU transactions enabled — mainframe)
 *
 * REFERENCES:
 *   https://docs.microsoft.com/en-us/windows/win32/cossdk/ms-dtc-xa-integration
 *   Hexacorn.com: "MSDTC XA DLL persistence"
 *   MITRE T1574.012 — COR_PROFILER (adjacent pattern)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Audit MSDTC XA transaction DLL paths
 * --------------------------------------------------------------------- */
static void AuditMSDTCXADLLs(DWORD *findings) {
    PrintInfo(L"  [1] MSDTC XA transaction DLL paths:\n");

    static const wchar_t *XA_ROOTS[] = {
        L"SOFTWARE\\Microsoft\\MSDTC\\XATM\\DLLs",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\MSDTC\\XATM\\DLLs",
        NULL
    };

    for (int ri = 0; XA_ROOTS[ri]; ri++) {
        HKEY hRoot = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, XA_ROOTS[ri],
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS)
            continue;

        PrintInfo(L"    %s:\n", XA_ROOTS[ri]);
        DWORD idx = 0;
        wchar_t xaName[256];
        DWORD   xaNameCch;

        while (TRUE) {
            xaNameCch = _countof(xaName);
            LONG r = RegEnumKeyExW(hRoot, idx++, xaName, &xaNameCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;

            wchar_t xaKeyPath[512];
            _snwprintf(xaKeyPath, _countof(xaKeyPath), L"%s\\%s", XA_ROOTS[ri], xaName);

            HKEY hXA = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, xaKeyPath, 0, KEY_READ, &hXA) != ERROR_SUCCESS)
                continue;

            /* Check OpenDLL and CloseDLL values */
            static const wchar_t *DLL_VALS[] = { L"OpenDLL", L"CloseDLL", NULL };
            for (int di = 0; DLL_VALS[di]; di++) {
                wchar_t dllPath[MAX_PATH * 2] = {0};
                DWORD cb = sizeof(dllPath), type = 0;
                if (RegQueryValueExW(hXA, DLL_VALS[di], NULL, &type,
                                     (LPBYTE)dllPath, &cb) != ERROR_SUCCESS) continue;
                if (!*dllPath) continue;

                wchar_t expanded[MAX_PATH * 2] = {0};
                ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));

                BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
                BOOL writable = exists && IsFileWritable(expanded);

                PrintInfo(L"      %s [%s]: %s%s\n", xaName, DLL_VALS[di], expanded,
                          writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

                if (writable || !exists) {
                    Finding f;
                    f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
                    wcscpy(f.module, L"MSDTC");
                    _snwprintf(f.target, _countof(f.target),
                        L"[%s] MSDTC XA DLL '%s' (%s): %s",
                        writable ? L"WRITABLE" : L"MISSING",
                        xaName, DLL_VALS[di], expanded);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"MSDTC XA DLL '%s' (%s) is %s: %s\n"
                        L"        MSDTC runs as NETWORK SERVICE (SeImpersonatePrivilege).\n"
                        L"        XA DLL loaded when any XA transaction begins.\n"
                        L"        %s → NETWORK SERVICE code exec → Potato → SYSTEM.\n"
                        L"        Trigger: any application using XA distributed transactions.",
                        xaName, DLL_VALS[di],
                        writable ? L"WRITABLE" : L"MISSING (plant)", expanded,
                        writable ? L"Replace DLL" : L"Plant DLL");
                    PrintFinding(&f);
                    (*findings)++;
                }
            }
            RegCloseKey(hXA);
        }
        RegCloseKey(hRoot);
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit MSDTC service account and security config
 * --------------------------------------------------------------------- */
static void AuditMSDTCConfig(DWORD *findings) {
    PrintInfo(L"  [2] MSDTC service account and security configuration:\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, L"MSDTC", SERVICE_QUERY_CONFIG);
        if (hSvc) {
            BYTE buf[4096] = {0};
            DWORD needed = 0;
            if (QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)buf, sizeof(buf), &needed)) {
                LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)buf;
                PrintInfo(L"    MSDTC account: %s\n",
                          cfg->lpServiceStartName ? cfg->lpServiceStartName : L"unknown");
                if (cfg->lpServiceStartName &&
                    _wcsicmp(cfg->lpServiceStartName, L"NT AUTHORITY\\NetworkService") == 0) {
                    PrintInfo(L"    [INFO] NetworkService = SeImpersonatePrivilege → Potato chain possible\n");
                }
            }
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }

    /* Check XA enabled */
    HKEY hSec = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\MSDTC\\Security",
                      0, KEY_READ, &hSec) == ERROR_SUCCESS) {
        DWORD xa = 0, cb = sizeof(xa);
        RegQueryValueExW(hSec, L"XaTransactions", NULL, NULL, (LPBYTE)&xa, &cb);
        PrintInfo(L"    XaTransactions enabled: %s\n", xa ? L"YES (XA DLLs can be triggered)" : L"no");
        RegCloseKey(hSec);
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit MSDTC log file writability
 * --------------------------------------------------------------------- */
static void AuditMSDTCLog(DWORD *findings) {
    PrintInfo(L"  [3] MSDTC log file and directory writability:\n");

    static const wchar_t *MSDTC_PATHS[] = {
        L"%SystemRoot%\\System32\\MsDtc",
        L"%SystemRoot%\\System32\\MsDtc\\MSDTC.LOG",
        NULL
    };

    for (int i = 0; MSDTC_PATHS[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(MSDTC_PATHS[i], expanded, _countof(expanded));

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = FALSE;
        if (exists) {
            DWORD attrs = GetFileAttributesW(expanded);
            if (attrs & FILE_ATTRIBUTE_DIRECTORY)
                writable = IsDirWritable(expanded);
            else
                writable = IsFileWritable(expanded);
        }
        PrintInfo(L"    %s: %s%s\n", expanded,
                  !exists ? L"not found" : L"exists",
                  writable ? L" [WRITABLE!]" : L"");
    }
    PrintInfo(L"\n");
}

void Module_MSDTCSurface(void) {
    PrintHeader(L"MSDTC XA SURFACE  [MSDTC XA DLL hijacking — NETWORK SERVICE → Potato → SYSTEM]");

    PrintInfo(
        L"  MSDTC (Distributed Transaction Coordinator) loads XA DLLs for Oracle/IBM/SAP databases.\n"
        L"  MSDTC runs as NETWORK SERVICE with SeImpersonatePrivilege → Potato chain.\n"
        L"  Third-party XA DLLs (Oracle xa_d8.dll, IBM mqxxa.dll) often in writable paths.\n\n");

    DWORD findings = 0;
    AuditMSDTCConfig(&findings);
    AuditMSDTCXADLLs(&findings);
    AuditMSDTCLog(&findings);

    if (findings == 0)
        PrintInfo(L"  No MSDTC XA LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

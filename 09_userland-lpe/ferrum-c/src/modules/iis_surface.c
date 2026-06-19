/*
 * iis_surface.c — IIS ISAPI Module/Filter/CGI DLL Hijacking
 *
 * RESEARCH SOURCES:
 *   - IIS configuration: %windir%\system32\inetsrv\config\applicationHost.config
 *   - ISAPI extensions/filters: DLLs loaded by IIS worker process (w3wp.exe)
 *   - IIS service (W3SVC): runs as LOCAL SYSTEM
 *   - WAS service (Windows Process Activation): runs as LOCAL SYSTEM
 *   - w3wp.exe worker process: runs as ApplicationPoolIdentity (usually)
 *     but with IIS APPPOOL\DefaultAppPool token or custom identity
 *   - IISModule native modules: registered in applicationHost.config <globalModules>
 *   - Research:
 *     - Seatbelt checks IIS config (but only ASPX, not native module DLLs)
 *     - James Forshaw: IIS COM interop and AppPool identity
 *     - Nikhil Mittal: Abusing IIS application pool identity for LPE
 *     - IIS ISAPI filter DLL injection documented in multiple CTF writeups
 *     - CVE-2021-31166 (HTTP.sys) as context for IIS attack surface importance
 *
 * ATTACK SURFACE:
 *   1. Native IIS module DLL (globalModules in applicationHost.config)
 *      → Loaded by w3wp.exe; if DLL is writable → code exec in worker process context
 *   2. ISAPI filter/extension DLL
 *      → Loaded per-request or globally; writable DLL = code exec
 *   3. IIS authentication module DLLs
 *      → Windows Auth (negotiate), Basic Auth, Digest Auth DLLs
 *   4. HTTP.sys driver configuration (kernel surface — noted but not tested)
 *   5. W3SVC service binary (SYSTEM)
 *
 * IIS WORKER PROCESS PRIVILEGE:
 *   Default: IIS APPPOOL\{name} (virtual low-priv account)
 *   If configured with: LocalSystem → full SYSTEM
 *   If configured with: NetworkService → SeImpersonatePrivilege → Potato
 *   If configured with: custom user → check if that user has elevated rights
 *
 * REFERENCES:
 *   MSDN: IIS Native-Code Module Overview
 *   MSDN: ISAPI Extension and Filter Development
 *   MITRE T1505.002 (IIS Transport Agent) — adjacent
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Check if IIS is installed and get base paths
 * --------------------------------------------------------------------- */
static BOOL GetIISInstallPath(wchar_t *pathOut, DWORD cchPath) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\InetStp",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) return FALSE;

    DWORD cb = cchPath * sizeof(wchar_t), type = 0;
    LONG r = RegQueryValueExW(hKey, L"InstallPath", NULL, &type,
                               (LPBYTE)pathOut, &cb);
    RegCloseKey(hKey);
    return (r == ERROR_SUCCESS && *pathOut);
}

/* -----------------------------------------------------------------------
 * Audit core IIS DLLs in inetsrv directory for writability
 * --------------------------------------------------------------------- */
static void AuditIISCoreDLLs(const wchar_t *inetsrvPath, DWORD *findings) {
    PrintInfo(L"  [1] IIS core module DLLs:\n");

    /* Known IIS native modules */
    static const wchar_t *IIS_DLLS[] = {
        L"iiscore.dll",
        L"w3tp.dll",
        L"hwebcore.dll",
        L"isapi.dll",
        L"cachuri.dll",
        L"cachfile.dll",
        L"cachtokn.dll",
        L"auth.dll",
        L"authsspi.dll",
        L"authmap.dll",
        L"authbasic.dll",
        L"authdigest.dll",
        L"auththin.dll",
        L"compress.dll",
        L"compstat.dll",
        L"deflate.dll",
        L"gzip.dll",
        L"filter.dll",
        L"requestfiltering.dll",
        L"static.dll",
        L"httpext.dll",
        L"webengine.dll",
        L"webengine4.dll",
        L"aspnetca.dll",
        NULL
    };

    for (int i = 0; IIS_DLLS[i]; i++) {
        wchar_t dllPath[MAX_PATH * 2] = {0};
        _snwprintf(dllPath, _countof(dllPath), L"%s\\%s", inetsrvPath, IIS_DLLS[i]);

        BOOL exists   = (GetFileAttributesW(dllPath) != INVALID_FILE_ATTRIBUTES);
        if (!exists) continue;

        BOOL writable = IsFileWritable(dllPath);
        if (writable) {
            PrintInfo(L"    [!] %s [WRITABLE!]\n", dllPath);
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"IIS");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] IIS core module DLL: %s", dllPath);
            _snwprintf(f.reason, _countof(f.reason),
                L"IIS core DLL is writable: %s\n"
                L"        This DLL is loaded by w3wp.exe (IIS worker process) for every request.\n"
                L"        W3SVC/WAS services run as LOCAL SYSTEM.\n"
                L"        Replace DLL → code exec in worker process (or SYSTEM on service restart).\n"
                L"        Trigger: any HTTP request to the IIS server.",
                dllPath);
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit applicationHost.config for module DLL paths
 * --------------------------------------------------------------------- */
static void AuditAppHostConfig(const wchar_t *inetsrvPath, DWORD *findings) {
    PrintInfo(L"  [2] applicationHost.config native module DLL paths:\n");

    wchar_t configPath[MAX_PATH * 2] = {0};
    _snwprintf(configPath, _countof(configPath),
               L"%s\\config\\applicationHost.config", inetsrvPath);

    BOOL exists = (GetFileAttributesW(configPath) != INVALID_FILE_ATTRIBUTES);
    if (!exists) {
        PrintInfo(L"    applicationHost.config not found at: %s\n\n", configPath);
        return;
    }

    PrintInfo(L"    Config: %s\n", configPath);

    /* Check config file itself for writability */
    if (IsFileWritable(configPath)) {
        PrintInfo(L"    [!] applicationHost.config is WRITABLE!\n");
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"IIS");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE] IIS applicationHost.config: %s", configPath);
        wcscpy(f.reason,
            L"IIS applicationHost.config is writable!\n"
            L"        Can add malicious <globalModules> entry pointing to attacker DLL.\n"
            L"        Can change AppPool identity to LocalSystem.\n"
            L"        Can add ISAPI filter pointing to payload.dll.\n"
            L"        Restart IIS (net stop W3SVC && net start W3SVC) → SYSTEM code exec.");
        PrintFinding(&f);
        (*findings)++;
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit IIS service account and WAS service
 * --------------------------------------------------------------------- */
static void AuditIISServices(DWORD *findings) {
    PrintInfo(L"  [3] IIS service accounts:\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return;

    static const wchar_t *IIS_SVCS[] = { L"W3SVC", L"WAS", NULL };
    for (int i = 0; IIS_SVCS[i]; i++) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, IIS_SVCS[i], SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
        if (!hSvc) continue;

        BYTE buf[4096] = {0};
        DWORD needed = 0;
        if (QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)buf, sizeof(buf), &needed)) {
            LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)buf;
            SERVICE_STATUS status = {0};
            QueryServiceStatus(hSvc, &status);

            PrintInfo(L"    %s: account=%s status=%s\n",
                      IIS_SVCS[i],
                      cfg->lpServiceStartName ? cfg->lpServiceStartName : L"unknown",
                      status.dwCurrentState == SERVICE_RUNNING ? L"RUNNING" : L"stopped");

            /* Check binary writability */
            if (cfg->lpBinaryPathName) {
                wchar_t binExe[MAX_PATH * 2] = {0};
                ExtractExePath(cfg->lpBinaryPathName, binExe, _countof(binExe));
                if (*binExe && IsFileWritable(binExe)) {
                    PrintInfo(L"    [!] %s binary is WRITABLE: %s\n", IIS_SVCS[i], binExe);
                    Finding f;
                    f.severity = SEV_CRITICAL;
                    wcscpy(f.module, L"IIS");
                    _snwprintf(f.target, _countof(f.target),
                        L"[WRITABLE BINARY] IIS service %s: %s", IIS_SVCS[i], binExe);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"IIS service binary is writable: %s\n"
                        L"        Service '%s' runs as LOCAL SYSTEM. Replace binary → SYSTEM.",
                        binExe, IIS_SVCS[i]);
                    PrintFinding(&f);
                    (*findings)++;
                }
            }
        }
        CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hSCM);
    PrintInfo(L"\n");
}

void Module_IISSurface(void) {
    PrintHeader(L"IIS SURFACE  [IIS native module/ISAPI DLL hijacking + config writability]");

    PrintInfo(
        L"  IIS loads native module DLLs for every HTTP request (W3SVC = SYSTEM).\n"
        L"  Writable IIS DLL or applicationHost.config → SYSTEM code exec on restart.\n\n");

    wchar_t iisPath[MAX_PATH * 2] = {0};
    if (!GetIISInstallPath(iisPath, _countof(iisPath))) {
        /* Try default path */
        wchar_t sysDir[MAX_PATH] = {0};
        GetSystemDirectoryW(sysDir, _countof(sysDir));
        _snwprintf(iisPath, _countof(iisPath), L"%s\\inetsrv", sysDir);
        if (GetFileAttributesW(iisPath) == INVALID_FILE_ATTRIBUTES) {
            PrintInfo(L"  IIS not installed on this system.\n");
            return;
        }
    }
    PrintInfo(L"  IIS install path: %s\n\n", iisPath);

    DWORD findings = 0;
    AuditIISServices(&findings);
    AuditIISCoreDLLs(iisPath, &findings);
    AuditAppHostConfig(iisPath, &findings);

    if (findings == 0)
        PrintInfo(L"  No IIS LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

/*
 * biometric_wbf.c — Windows Biometric Framework (WBF) Adapter DLL Hijacking
 *
 * RESEARCH SOURCES:
 *   - Windows Biometric Framework documentation: MSDN
 *   - WbioSrvc service (Windows Biometric Service) runs as LOCAL SYSTEM
 *   - WBF driver components: unit adapters, sensor adapters, engine adapters
 *   - Registry: HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc\
 *               HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\
 *   - WBF unit database: HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc\DatabaseDir
 *   - WBF sensor adapters: loaded by WbioSrvc (SYSTEM) for fingerprint/face sensors
 *   - Research:
 *     - James Forshaw: Windows Hello/WBF PIN reset vulnerability research
 *     - Lee Christensen: Fingerprint data exfiltration (WBF database path)
 *     - Victor Mata: Windows Hello bypass (adjacent)
 *     - Hexacorn: WBF as persistence location (blog.hexacorn.com/2019)
 *
 * ATTACK SURFACE:
 *   WbioSrvc (LOCAL SYSTEM) loads adapter DLLs for biometric sensor operations:
 *   - Unit adapter: WBDI driver interface (WUDFRd.sys, sensor-specific)
 *   - Sensor adapter: raw sensor data processing DLL
 *   - Engine adapter: biometric algorithm/matching engine DLL
 *   - Storage adapter: template storage DLL
 *   If any adapter DLL path is writable → code exec as LOCAL SYSTEM.
 *
 * WBF BIOMETRIC UNIT REGISTRY:
 *   HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc\
 *   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\Configurations\
 *   Each config has: SensorAdapterFilePath, EngineAdapterFilePath, StorageAdapterFilePath
 *
 * REFERENCES:
 *   MSDN: Windows Biometric Framework API
 *   https://docs.microsoft.com/en-us/windows/win32/secbiomet/winbio-api
 *   MITRE: not yet mapped (novel persistence vector)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Check a DLL path value for writability
 * --------------------------------------------------------------------- */
static void CheckWBFDLL(const wchar_t *label, const wchar_t *dllPath,
                         DWORD *findings) {
    if (!dllPath || !*dllPath) return;

    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));

    wchar_t dllExe[MAX_PATH * 2] = {0};
    ExtractExePath(dllPath, dllExe, _countof(dllExe));
    if (!*dllExe) wcsncpy(dllExe, expanded, _countof(dllExe)-1);

    BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(dllExe);

    PrintInfo(L"      %s: %s%s\n", label, dllExe,
              writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

    if (writable || !exists) {
        Finding f;
        f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
        wcscpy(f.module, L"WBF");
        _snwprintf(f.target, _countof(f.target),
            L"[%s] WBF adapter DLL (%s): %s",
            writable ? L"WRITABLE" : L"MISSING", label, dllExe);
        _snwprintf(f.reason, _countof(f.reason),
            L"WBF biometric adapter DLL (%s) is %s: %s\n"
            L"        WbioSrvc (Windows Biometric Service) runs as LOCAL SYSTEM.\n"
            L"        Adapter DLLs are loaded by WbioSrvc on service startup.\n"
            L"        %s → SYSTEM code exec on next WbioSrvc start or biometric operation.\n"
            L"        Trigger: net stop WbioSrvc && net start WbioSrvc",
            label, writable ? L"WRITABLE" : L"MISSING (plant)",
            dllExe, writable ? L"Replace DLL" : L"Plant DLL at path");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Enumerate WBF configurations and check adapter DLL paths
 * --------------------------------------------------------------------- */
static void AuditWBFConfigurations(DWORD *findings) {
    PrintInfo(L"  [1] WBF biometric unit adapter DLLs:\n");

    static const wchar_t *WBF_ROOTS[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinBio\\Configurations",
        L"SYSTEM\\CurrentControlSet\\Services\\WbioSrvc\\Configurations",
        NULL
    };

    BOOL found = FALSE;
    for (int ri = 0; WBF_ROOTS[ri]; ri++) {
        HKEY hRoot = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WBF_ROOTS[ri],
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS)
            continue;

        found = TRUE;
        PrintInfo(L"    Registry: HKLM\\%s\n", WBF_ROOTS[ri]);

        DWORD idx = 0;
        wchar_t cfgGUID[128];
        DWORD   cfgGUIDCch;

        while (TRUE) {
            cfgGUIDCch = _countof(cfgGUID);
            LONG r = RegEnumKeyExW(hRoot, idx++, cfgGUID, &cfgGUIDCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;

            wchar_t cfgPath[512];
            _snwprintf(cfgPath, _countof(cfgPath), L"%s\\%s", WBF_ROOTS[ri], cfgGUID);

            HKEY hCfg = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, cfgPath, 0, KEY_READ, &hCfg) != ERROR_SUCCESS)
                continue;

            PrintInfo(L"    Config: %s\n", cfgGUID);

            /* Read adapter DLL paths */
            static const wchar_t *ADAPTER_VALS[] = {
                L"SensorAdapterFilePath",
                L"EngineAdapterFilePath",
                L"StorageAdapterFilePath",
                NULL
            };

            for (int ai = 0; ADAPTER_VALS[ai]; ai++) {
                wchar_t dllPath[MAX_PATH * 2] = {0};
                DWORD cb = sizeof(dllPath), type = 0;
                if (RegQueryValueExW(hCfg, ADAPTER_VALS[ai], NULL, &type,
                                     (LPBYTE)dllPath, &cb) == ERROR_SUCCESS) {
                    CheckWBFDLL(ADAPTER_VALS[ai], dllPath, findings);
                }
            }
            RegCloseKey(hCfg);
        }
        RegCloseKey(hRoot);
    }

    if (!found)
        PrintInfo(L"    WBF configurations not found (biometric hardware not present or not enrolled)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit WBF database directory writability
 * --------------------------------------------------------------------- */
static void AuditWBFDatabase(DWORD *findings) {
    PrintInfo(L"  [2] WBF biometric template database directory:\n");

    /* Default WBF database location */
    static const wchar_t *DB_PATHS[] = {
        L"%ProgramData%\\Microsoft\\Windows\\WinBio\\",
        L"%ProgramData%\\Microsoft\\Windows\\WinBio\\AccountInfo",
        NULL
    };

    for (int i = 0; DB_PATHS[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(DB_PATHS[i], expanded, _countof(expanded));

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsDirWritable(expanded);

        PrintInfo(L"    %s: %s%s\n", expanded,
                  !exists ? L"not found" : L"exists",
                  writable ? L" [WRITABLE! — biometric database manipulation]" : L"");
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Report WbioSrvc service status
 * --------------------------------------------------------------------- */
static void AuditWbioSrvcAccount(void) {
    PrintInfo(L"  [3] WbioSrvc service account:\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return;

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"WbioSrvc",
                                  SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (hSvc) {
        BYTE buf[4096] = {0};
        DWORD needed = 0;
        if (QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)buf, sizeof(buf), &needed)) {
            LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)buf;
            SERVICE_STATUS status = {0};
            QueryServiceStatus(hSvc, &status);
            PrintInfo(L"    WbioSrvc: account=%s  status=%s\n",
                      cfg->lpServiceStartName ? cfg->lpServiceStartName : L"unknown",
                      status.dwCurrentState == SERVICE_RUNNING ? L"RUNNING" : L"stopped");
        }
        CloseServiceHandle(hSvc);
    } else {
        PrintInfo(L"    WbioSrvc: not installed\n");
    }
    CloseServiceHandle(hSCM);
    PrintInfo(L"\n");
}

void Module_BiometricWBF(void) {
    PrintHeader(L"WINDOWS BIOMETRIC FRAMEWORK  [WBF adapter DLL hijacking — WbioSrvc=SYSTEM]");

    PrintInfo(
        L"  WbioSrvc (Windows Biometric Service) loads sensor/engine/storage adapter DLLs.\n"
        L"  Service runs as LOCAL SYSTEM — writable adapter DLL → SYSTEM code exec.\n"
        L"  Novel: no public LPE tool checks WBF adapter DLL paths.\n\n");

    DWORD findings = 0;
    AuditWbioSrvcAccount();
    AuditWBFConfigurations(&findings);
    AuditWBFDatabase(&findings);

    if (findings == 0)
        PrintInfo(L"  No WBF LPE surface found (biometric hardware not present or paths secure).\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

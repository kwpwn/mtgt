/*
 * drivers.c — Kernel Driver Enumeration and Risk Check
 *
 * Enumerates all kernel drivers via the SCM (SERVICE_DRIVER type).
 * Flags:
 *   1. Driver binary in a user-writable location
 *   2. Driver binary file itself is writable
 *   3. Boot/System start-type drivers (highest privilege, load early)
 *   4. Driver registry key writable (allows ImagePath modification)
 *   5. Currently running kernel drivers for BYOVD surface awareness
 */

#include "../common.h"

void Module_Drivers(void) {
    PrintHeader(L"KERNEL DRIVER AUDIT");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL,
        SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        PrintInfo(L"  [!] Cannot open SCM (error %lu)\n", GetLastError());
        return;
    }

    /* Enumerate both kernel and file-system drivers */
    DWORD needed = 0, count = 0, resume = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO,
        SERVICE_DRIVER,        /* kernel + filesystem drivers */
        SERVICE_STATE_ALL,
        NULL, 0, &needed, &count, &resume, NULL);

    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(hSCM);
        return;
    }

    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!buf) { CloseServiceHandle(hSCM); return; }

    resume = 0;
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER, SERVICE_STATE_ALL,
            buf, needed, &needed, &count, &resume, NULL)) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseServiceHandle(hSCM);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSW *svcs =
        (ENUM_SERVICE_STATUS_PROCESSW *)buf;
    DWORD findings = 0;

    PrintInfo(L"  Total kernel drivers found: %lu\n\n", count);

    for (DWORD i = 0; i < count; i++) {
        LPCWSTR drvName = svcs[i].lpServiceName;

        SC_HANDLE hSvc = OpenServiceW(hSCM, drvName,
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL);
        if (!hSvc) continue;

        DWORD cfgNeeded = 0;
        QueryServiceConfigW(hSvc, NULL, 0, &cfgNeeded);
        QUERY_SERVICE_CONFIGW *pCfg =
            (QUERY_SERVICE_CONFIGW *)HeapAlloc(GetProcessHeap(), 0, cfgNeeded);
        BOOL gotCfg = pCfg &&
            QueryServiceConfigW(hSvc, pCfg, cfgNeeded, &cfgNeeded);

        if (gotCfg && pCfg->lpBinaryPathName && *pCfg->lpBinaryPathName) {
            wchar_t drvPath[MAX_PATH * 2] = {0};

            /* Driver paths often look like \SystemRoot\System32\drivers\foo.sys
             * or \\?\globalroot\... — expand and normalise.                  */
            wchar_t expanded[MAX_PATH * 2] = {0};
            wcsncpy(expanded, pCfg->lpBinaryPathName, _countof(expanded)-1);
            /* Replace \SystemRoot with actual path */
            if (_wcsnicmp(expanded, L"\\SystemRoot\\", 12) == 0) {
                wchar_t windir[MAX_PATH] = {0};
                GetWindowsDirectoryW(windir, _countof(windir));
                _snwprintf(drvPath, _countof(drvPath), L"%s\\%s",
                           windir, expanded + 12);
            } else {
                wcsncpy(drvPath, expanded, _countof(drvPath)-1);
            }

            Finding f;
            wcscpy(f.module, L"DRIVERS");

            /* ---- Check 1: Binary in user-writable location ---- */
            if (IsUserWritablePath(drvPath)) {
                f.severity = SEV_HIGH;
                wcsncpy(f.target, drvName, _countof(f.target)-1);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Driver binary in user-writable location: %s", drvPath);
                PrintFinding(&f);
                findings++;
            }

            /* ---- Check 2: Binary itself is writable ---- */
            if (GetFileAttributesW(drvPath) != INVALID_FILE_ATTRIBUTES
                && IsFileWritable(drvPath))
            {
                f.severity = SEV_CRITICAL;
                wcsncpy(f.target, drvName, _countof(f.target)-1);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Driver binary is WRITABLE by current user: %s  "
                    L"→ replace with malicious driver", drvPath);
                PrintFinding(&f);
                findings++;
            }

            /* ---- Check 3: Boot / System start-type ---- */
            if (pCfg->dwStartType == SERVICE_BOOT_START ||
                pCfg->dwStartType == SERVICE_SYSTEM_START)
            {
                BOOL running = (svcs[i].ServiceStatusProcess.dwCurrentState
                                == SERVICE_RUNNING);
                /* Only report running boot/system drivers as informational */
                if (running) {
                    f.severity = SEV_INFO;
                    wcsncpy(f.target, drvName, _countof(f.target)-1);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"Early-load %s driver (BYOVD / rootkit surface): %s",
                        pCfg->dwStartType == SERVICE_BOOT_START ? L"BOOT" : L"SYSTEM",
                        drvPath);
                    PrintFinding(&f);
                }
            }
        }

        /* ---- Check 4: Driver registry key writable ---- */
        wchar_t regSub[256];
        _snwprintf(regSub, _countof(regSub),
            L"SYSTEM\\CurrentControlSet\\Services\\%s", drvName);
        if (IsRegKeyWritable(HKEY_LOCAL_MACHINE, regSub)) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"DRIVERS");
            wcsncpy(f.target, drvName, _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Driver registry key WRITABLE → modify ImagePath → "
                L"restart driver → kernel code execution");
            PrintFinding(&f);
            findings++;
        }

        if (pCfg) HeapFree(GetProcessHeap(), 0, pCfg);
        CloseServiceHandle(hSvc);
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseServiceHandle(hSCM);

    if (findings == 0)
        PrintInfo(L"  No driver-level misconfigurations found.\n");
    else
        PrintInfo(L"  Driver findings: %lu\n", findings);

    PrintInfo(L"\n  Tip: For BYOVD research, cross-reference loaded drivers with:\n"
              L"       03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md\n"
              L"       and LOLDrivers (https://www.loldrivers.io/)\n");
}

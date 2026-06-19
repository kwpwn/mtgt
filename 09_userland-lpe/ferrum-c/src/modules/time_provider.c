/*
 * time_provider.c — Windows Time Provider DLL Hijacking (W32Time service)
 *
 * NOVEL SURFACE — No public WinPEAS/PowerUp/Seatbelt check covers this specifically.
 *
 * WHAT W32TIME TIME PROVIDERS ARE:
 *   The Windows Time Service (W32Time) synchronizes system clock with NTP servers.
 *   It supports pluggable time provider DLLs via registry:
 *
 *   HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\{ProviderName}\
 *     DllName = "C:\Windows\system32\w32time.dll"  (default NTP provider)
 *     Enabled = 1
 *     InputProvider = 1/0
 *
 * WHY THIS IS HIGH VALUE:
 *   1. W32Time service (svchost.exe -k LocalService) runs as LOCAL SERVICE
 *      → If DLL is writable: code exec as LOCAL SERVICE
 *      → LOCAL SERVICE has SeImpersonatePrivilege → Potato → SYSTEM
 *
 *   2. W32Time with domain sync may run at higher privilege on domain controllers
 *      → DC: W32Time runs as SYSTEM
 *
 *   3. NtpClient/NtpServer are the default providers — usually system32 DLLs.
 *      But third-party NTP software (Meinberg, NetTime) installs custom providers
 *      in writable paths.
 *
 *   4. If the TimeProviders key itself is writable → register own DLL.
 *      W32Time loads all Enabled providers on service start.
 *
 * TRIGGER:
 *   sc stop w32time && sc start w32time
 *   OR: w32tm /unregister && w32tm /register (admin)
 *   OR: Wait for next time sync cycle
 *   On domain members: runs continuously for domain time sync
 *
 * REAL-WORLD USAGE:
 *   - Stuxnet used a similar service DLL injection technique
 *   - Enterprise NTP appliances (Microsemi, Meinberg) install custom W32Time providers
 *   - Some security products add time provider DLLs for tamper-detection
 *
 * REFERENCES:
 *   https://docs.microsoft.com/en-us/windows-server/networking/windows-time-service/
 *   W32Time provider API: TimeProvOpen, TimeProvCommand, TimeProvClose
 *   MITRE T1543.003 — Windows Service (adjacent technique)
 */

#include "../common.h"

#define W32TIME_PROVIDERS_KEY L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders"
#define W32TIME_SERVICE_KEY   L"SYSTEM\\CurrentControlSet\\Services\\W32Time"

/* -----------------------------------------------------------------------
 * Enumerate time providers and check DLL path writability
 * --------------------------------------------------------------------- */
static void AuditTimeProviders(DWORD *findings) {
    PrintInfo(L"  [1] W32Time Time Provider DLLs:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, W32TIME_PROVIDERS_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (W32Time TimeProviders key not found)\n\n");
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t provName[128];
    DWORD   provNameCch;

    while (TRUE) {
        provNameCch = _countof(provName);
        LONG r = RegEnumKeyExW(hRoot, idx++, provName, &provNameCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        wchar_t provPath[512];
        _snwprintf(provPath, _countof(provPath), L"%s\\%s", W32TIME_PROVIDERS_KEY, provName);
        HKEY hProv = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, provPath, 0, KEY_READ, &hProv) != ERROR_SUCCESS)
            continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(dllPath), type = 0;
        DWORD   enabled = 0, cbE = sizeof(DWORD);
        RegQueryValueExW(hProv, L"DllName", NULL, &type, (LPBYTE)dllPath, &cb);
        RegQueryValueExW(hProv, L"Enabled",  NULL, &type, (LPBYTE)&enabled, &cbE);
        RegCloseKey(hProv);

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));
        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        PrintInfo(L"    Provider: %-25s  Enabled: %lu  DLL: %s%s\n",
                  provName, enabled, expanded,
                  writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

        if ((writable || !exists) && enabled) {
            Finding f;
            f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"TIMEPROV");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] W32Time Provider DLL: %s → %s",
                writable ? L"WRITABLE" : L"MISSING", provName, expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"W32Time Time Provider '%s' DLL is %s: %s\n"
                L"        W32Time service (svchost.exe -k LocalService) loads enabled provider DLLs.\n"
                L"        W32Time runs as LOCAL SERVICE which has SeImpersonatePrivilege.\n"
                L"        %s → code exec as LOCAL SERVICE → Potato → SYSTEM.\n"
                L"        Trigger: sc stop w32time && sc start w32time",
                provName, writable ? L"WRITABLE" : L"MISSING", expanded,
                writable ? L"Replace DLL with payload" : L"Plant DLL at path");
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hRoot);
    if (count == 0) PrintInfo(L"    (no time providers registered)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check if TimeProviders key itself is writable (can register own DLL)
 * --------------------------------------------------------------------- */
static void AuditTimeProviderKeyWritability(DWORD *findings) {
    PrintInfo(L"  [2] TimeProviders key writability (can register new provider DLL):\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, W32TIME_PROVIDERS_KEY,
                      0, KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        PrintInfo(L"    [CRITICAL] W32Time TimeProviders key is WRITABLE!\n\n");

        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"TIMEPROV");
        wcscpy(f.target, L"[WRITABLE] W32Time\\TimeProviders key — can register custom DLL");
        _snwprintf(f.reason, _countof(f.reason),
            L"W32Time TimeProviders registry key is writable.\n"
            L"        Can create new time provider subkey with custom DLL path:\n"
            L"        reg add \"%s\\MalProv\" /v DllName /t REG_SZ /d C:\\tmp\\payload.dll\n"
            L"        reg add \"%s\\MalProv\" /v Enabled /t REG_DWORD /d 1\n"
            L"        sc stop w32time && sc start w32time → DLL loaded as LOCAL SERVICE\n"
            L"        LOCAL SERVICE has SeImpersonatePrivilege → Potato/PrintSpoofer → SYSTEM.",
            W32TIME_PROVIDERS_KEY, W32TIME_PROVIDERS_KEY);
        PrintFinding(&f);
        (*findings)++;
    } else {
        PrintInfo(L"    Key not writable (expected)\n\n");
    }
}

/* -----------------------------------------------------------------------
 * Check W32Time service account (SYSTEM on DC?)
 * --------------------------------------------------------------------- */
static void AuditW32TimeServiceAccount(DWORD *findings) {
    PrintInfo(L"  [3] W32Time service account:\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintInfo(L"    Cannot open SCM\n\n"); return; }

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"W32Time",
                                  SERVICE_QUERY_CONFIG);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        PrintInfo(L"    W32Time service not found\n\n");
        return;
    }

    wchar_t configBuf[4096] = {0};
    DWORD   needed = 0;
    QUERY_SERVICE_CONFIGW *pCfg = (QUERY_SERVICE_CONFIGW *)configBuf;
    QueryServiceConfigW(hSvc, pCfg, sizeof(configBuf), &needed);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    PrintInfo(L"    StartType:    %lu\n", pCfg->dwStartType);
    PrintInfo(L"    ServiceAccount: %s\n\n",
              pCfg->lpServiceStartName ? pCfg->lpServiceStartName : L"(unknown)");

    if (pCfg->lpServiceStartName &&
        _wcsicmp(pCfg->lpServiceStartName, L"LocalSystem") == 0) {
        PrintInfo(L"    [!] W32Time runs as SYSTEM on this machine (likely a DC)\n\n");
        /* On DC, this makes any W32Time provider DLL = SYSTEM */
    }
}

void Module_TimeProvider(void) {
    PrintHeader(L"W32TIME PROVIDER DLLs  [Novel: Time provider DLL hijacking → LOCAL SERVICE/SYSTEM]");

    PrintInfo(
        L"  W32Time (Windows Time Service) loads pluggable time provider DLLs.\n"
        L"  On member workstations: runs as LOCAL SERVICE → SeImpersonate → Potato → SYSTEM.\n"
        L"  On domain controllers: W32Time runs as SYSTEM.\n"
        L"  No public WinPEAS/PowerUp/Seatbelt check covers this surface.\n\n");

    DWORD findings = 0;
    AuditTimeProviders(&findings);
    AuditTimeProviderKeyWritability(&findings);
    AuditW32TimeServiceAccount(&findings);

    if (findings == 0)
        PrintInfo(L"  No W32Time DLL hijacking surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOITATION:\n"
            L"    1. Replace writable provider DLL with payload (exports TimeProvOpen/TimeProvCommand)\n"
            L"    2. sc stop w32time && sc start w32time\n"
            L"    3. DLL loaded as LOCAL SERVICE → SeImpersonatePrivilege available\n"
            L"    4. PrintSpoofer / RoguePotato from LOCAL SERVICE → SYSTEM\n"
            L"  MINIMAL TIME PROVIDER DLL EXPORTS:\n"
            L"    HRESULT WINAPI TimeProvOpen(WCHAR *wszName, PIMEPROV_HELPER_CALLBACKS pHelpCB,\n"
            L"                               PHIMEPROV *phTimeProv);\n"
            L"    DWORD   WINAPI TimeProvCommand(HIMEPROV hTimeProv, TIMEPROVCMD eCmd, PVOID pvArgs);\n"
            L"    void    WINAPI TimeProvClose(HIMEPROV hTimeProv);\n");
    }
}

/*
 * secondary_logon.c — Secondary Logon Service (seclogon) LPE Surface
 *
 * BACKGROUND:
 *   The Secondary Logon Service (seclogon, svchost.exe -k netsvcs) allows
 *   non-admin users to run processes as OTHER users via:
 *     - CreateProcessWithLogonW (Windows login credentials)
 *     - CreateProcessWithTokenW (impersonation token)
 *     - RunAs verb in shell context menu
 *
 *   seclogon runs as SYSTEM. Various vulnerabilities have been found where:
 *   a) The service's process handle table is accessible → DUP_HANDLE
 *   b) The service can be abused to get impersonation tokens
 *   c) Symbolic link attacks on seclogon temporary objects
 *
 * KNOWN TECHNIQUES:
 *
 *   1. SecLogon Thread Hijacking (James Forshaw, Project Zero):
 *      When seclogon starts a new process, it temporarily creates a thread
 *      in the caller's process context with SYSTEM token.
 *      Race condition: duplicate that thread's handle → SYSTEM token access.
 *      (Fixed in specific patches, varies by Windows version)
 *
 *   2. CreateProcessWithLogonW DACL leak:
 *      seclogon creates a process with caller-supplied credentials.
 *      If caller supplies a logon for an admin account + specifies
 *      executable path → seclogon creates that process as admin.
 *      (Legitimate use, but token supply chain can be abused)
 *
 *   3. Runas IFileOperation escalation:
 *      RunAs with certain elevated application contexts can trigger
 *      UAC consent UI bypass on some Windows versions.
 *
 *   4. Handle Inheritance via seclogon:
 *      Processes started via CreateProcessWithLogonW inherit handles.
 *      If caller inherits a SYSTEM handle → handle escapes sandbox.
 *
 * WHAT THIS MODULE CHECKS:
 *   a) Whether seclogon service is running (prerequisite for techniques)
 *   b) seclogon process DACL (can we open it with DUP_HANDLE?)
 *   c) Whether CreateProcessWithLogonW is blocked by policy
 *   d) Whether secondary logon is disabled (hardened systems disable it)
 *   e) SecondaryLogon registry configuration
 *
 * HISTORICAL CVEs:
 *   - CVE-2019-1082: Windows SecLogon EoP (patch: KB4507472)
 *   - CVE-2020-1471: Windows SecLogon EoP
 *   - CVE-2021-36934 (HiveNightmare): touches seclogon service handles
 *   - Multiple Project Zero P0-1564, P0-1782 (Forshaw): seclogon token leaks
 *
 * REFERENCES:
 *   James Forshaw: "Windows Sandbox Attack Surface Analysis" (Project Zero)
 *   "Getting SYSTEM with seclogon" (various blog posts)
 *   MITRE: T1134.002 — Access Token Manipulation: Create Process with Token
 */

#include "../common.h"

#define SECLOGON_SERVICE L"seclogon"
#define SECLOGON_REG \
    L"SYSTEM\\CurrentControlSet\\Services\\seclogon"

/* -----------------------------------------------------------------------
 * Check seclogon service status and configuration
 * --------------------------------------------------------------------- */
static void AuditSecLogonService(DWORD *findings) {
    PrintInfo(L"  [1] Secondary Logon Service status:\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        PrintInfo(L"    Cannot open SCM\n\n");
        return;
    }

    SC_HANDLE hSvc = OpenServiceW(hSCM, SECLOGON_SERVICE,
                                   SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!hSvc) {
        PrintInfo(L"    Secondary Logon service not accessible\n\n");
        CloseServiceHandle(hSCM);
        return;
    }

    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD needed = 0;
    BOOL running = FALSE;

    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                              (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        running = (ssp.dwCurrentState == SERVICE_RUNNING);
        PrintInfo(L"    Status: %s  PID: %lu\n",
                  running ? L"RUNNING" : L"STOPPED",
                  ssp.dwProcessId);

        if (running) {
            PrintInfo(L"    Service is running — secondary logon techniques applicable.\n");

            /* Check service process DACL */
            if (ssp.dwProcessId != 0) {
                HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ssp.dwProcessId);
                if (hProc) {
                    Finding f;
                    f.severity = SEV_HIGH;
                    wcscpy(f.module, L"SECLOGON");
                    _snwprintf(f.target, _countof(f.target),
                        L"[PROCESS_DUP_HANDLE] svchost(seclogon) PID:%lu",
                        ssp.dwProcessId);
                    wcscpy(f.reason,
                        L"Can open seclogon svchost with PROCESS_DUP_HANDLE. "
                        L"Technique: CreateProcessWithLogonW to trigger SYSTEM token creation "
                        L"in seclogon, then DuplicateHandle to steal that token.\n"
                        L"        CVE-2019-1082 / CVE-2020-1471 pattern.\n"
                        L"        PoC reference: James Forshaw, Project Zero #1782.");
                    PrintFinding(&f);
                    (*findings)++;
                    CloseHandle(hProc);
                }
            }
        } else {
            PrintInfo(L"    Service stopped — lower risk but check start permissions.\n");
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check seclogon registry configuration
 * --------------------------------------------------------------------- */
static void AuditSecLogonRegistry(DWORD *findings) {
    PrintInfo(L"  [2] Secondary Logon registry configuration:\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SECLOGON_REG,
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        PrintInfo(L"    seclogon registry key not accessible\n\n");
        return;
    }

    wchar_t start[16] = {0};
    DWORD   cb = sizeof(start), type = 0, startVal = 0;
    if (RegQueryValueExW(hKey, L"Start", NULL, &type,
                         (LPBYTE)&startVal, &cb) == ERROR_SUCCESS) {
        PrintInfo(L"    Start type: %lu (%s)\n", startVal,
                  startVal == 2 ? L"Automatic" :
                  startVal == 3 ? L"Manual (on-demand)" :
                  startVal == 4 ? L"Disabled" : L"Unknown");
    }

    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, SECLOGON_REG);
    PrintInfo(L"    Registry key writable: %s\n\n", keyWritable ? L"YES!" : L"No");

    if (keyWritable) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"SECLOGON");
        wcscpy(f.target, L"[KEY WRITABLE] SYSTEM\\CurrentControlSet\\Services\\seclogon");
        wcscpy(f.reason,
            L"seclogon service registry key is WRITABLE. "
            L"Can modify ImagePath to redirect service to payload EXE. "
            L"Restart service → payload runs as SYSTEM.");
        PrintFinding(&f);
        (*findings)++;
    }

    RegCloseKey(hKey);
}

/* -----------------------------------------------------------------------
 * Check if CreateProcessWithLogonW is testable
 * --------------------------------------------------------------------- */
static void AuditCreateProcessWithLogon(DWORD *findings) {
    PrintInfo(L"  [3] CreateProcessWithLogonW availability:\n");

    /* Test if function exists and is accessible */
    HMODULE hAdvapi = GetModuleHandleW(L"advapi32.dll");
    FARPROC pFunc = NULL;
    if (hAdvapi)
        pFunc = GetProcAddress(hAdvapi, "CreateProcessWithLogonW");

    PrintInfo(L"    CreateProcessWithLogonW: %s\n",
              pFunc ? L"Available" : L"Not found (unexpected)");

    /* Check if secondary logon is blocked by Group Policy */
    HKEY hPol = NULL;
    BOOL blocked = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_READ, &hPol) == ERROR_SUCCESS) {
        DWORD val = 0, vcb = sizeof(val);
        if (RegQueryValueExW(hPol, L"DisableSecondaryLogon", NULL, NULL,
                             (LPBYTE)&val, &vcb) == ERROR_SUCCESS && val != 0) {
            blocked = TRUE;
        }
        RegCloseKey(hPol);
    }

    PrintInfo(L"    DisableSecondaryLogon policy: %s\n\n",
              blocked ? L"BLOCKED (hardened)" : L"Not set (default)");

    if (!blocked && pFunc) {
        Finding f;
        f.severity = SEV_INFO;
        wcscpy(f.module, L"SECLOGON");
        wcscpy(f.target, L"[AVAILABLE] CreateProcessWithLogonW not blocked");
        wcscpy(f.reason,
            L"Secondary logon API available and not disabled by policy. "
            L"Techniques: (1) Token leak via thread hijack during logon "
            L"(requires timing + DUP_HANDLE on seclogon process). "
            L"(2) Trigger logon → intercept SYSTEM token if DUP_HANDLE succeeds. "
            L"Reference: CVE-2019-1082, Forshaw P0#1782.");
        PrintFinding(&f);
    }
}

void Module_SecondaryLogon(void) {
    PrintHeader(L"SECONDARY LOGON SURFACE  [seclogon SYSTEM token leakage surface]");

    PrintInfo(
        L"  seclogon service creates processes under alternate credentials (SYSTEM context).\n"
        L"  Multiple CVEs: token leak during logon, DUP_HANDLE token theft.\n"
        L"  References: CVE-2019-1082, CVE-2020-1471, Forshaw Project Zero.\n\n");

    DWORD findings = 0;
    AuditSecLogonService(&findings);
    AuditSecLogonRegistry(&findings);
    AuditCreateProcessWithLogon(&findings);

    if (findings == 0)
        PrintInfo(L"  No secondary logon LPE surface found (service may be stopped/hardened).\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  ATTACK TECHNIQUE (DUP_HANDLE + seclogon):\n"
            L"    1. Open seclogon svchost with PROCESS_DUP_HANDLE\n"
            L"    2. Call CreateProcessWithLogonW with any valid credentials\n"
            L"    3. While logon is being processed, iterate handle values in seclogon\n"
            L"       DuplicateHandle(seclogon_proc, handle_value, GetCurrentProcess(),\n"
            L"                       &dup, TOKEN_ALL_ACCESS, FALSE, 0)\n"
            L"    4. If dup is a SYSTEM token: ImpersonateLoggedOnUser or CreateProcessWithToken\n"
            L"    Reference implementation: https://github.com/antonioCoco/RunasCs\n"
            L"    Public PoC: SecLogon-LPE (CVE-2019-1082)\n");
    }
}

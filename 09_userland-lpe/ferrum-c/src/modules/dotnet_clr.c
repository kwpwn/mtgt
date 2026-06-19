/*
 * dotnet_clr.c — .NET CLR Profiler / COR_PROFILER LPE Surface
 *
 * WHY .NET CLR PROFILING IS AN LPE SURFACE:
 *   The .NET CLR (Common Language Runtime) supports profiling APIs that
 *   allow external DLLs to hook into .NET process execution. This is
 *   enabled via environment variables:
 *
 *   COR_ENABLE_PROFILING=1
 *   COR_PROFILER={CLSID}    → CLSID of profiler COM object
 *   COR_PROFILER_PATH=<dll> → optional direct DLL path (bypasses registry)
 *
 *   If any SYSTEM/.NET service runs with these variables set, and:
 *   a) The profiler DLL path is user-writable → SYSTEM DLL injection
 *   b) The COM CLSID's InprocServer32 DLL is user-writable → same
 *
 * ATTACK SCENARIOS:
 *
 *   1. SYSTEM SERVICE with COR_ENABLE_PROFILING in environment:
 *      Some hardware vendors / enterprise software (monitoring, APM agents)
 *      install .NET profilers globally by setting environment vars in the
 *      service's registry Environment key.
 *      If profiler DLL is in user-writable path → SYSTEM DLL injection.
 *
 *   2. Machine-level COR_PROFILER in system environment:
 *      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\COR_ENABLE_PROFILING
 *      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\COR_PROFILER
 *      HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\COR_PROFILER_PATH
 *      If set system-wide → ALL .NET processes (including SYSTEM services) load profiler.
 *
 *   3. HKCU COR_PROFILER (already checked by --ENV module partially):
 *      HKCU environment → affects current user's .NET processes only.
 *      If target is High-IL .NET process → cross-IL escalation via profiler DLL.
 *
 *   4. CoreCLR profiling (3.x+ / .NET Core / .NET 5+):
 *      CORECLR_ENABLE_PROFILING, CORECLR_PROFILER, CORECLR_PROFILER_PATH
 *      Same mechanism as legacy .NET but for .NET Core services.
 *
 *   5. .NET Framework configuration files (machine.config):
 *      %windir%\Microsoft.NET\Framework\v4.0.30319\CONFIG\machine.config
 *      If writable → can add assembly redirect → redirect to malicious DLL.
 *
 * RELATED / DIFFERENTIATION FROM --ENV:
 *   --ENV module checks HKCU COR_PROFILER (user-level attacks).
 *   This module focuses on SYSTEM-level:
 *   - HKLM system-wide env variables
 *   - Per-service Environment registry keys
 *   - machine.config writability
 *   - Installed profiler COM DLL paths
 *
 * REAL-WORLD CASES:
 *   - Datadog, NewRelic, Dynatrace, AppDynamics all use .NET profilers
 *   - Some corporate DLP solutions inject via COR_PROFILER
 *   - Research: "Abusing .NET Profiler" (various red team blogs)
 *
 * REFERENCES:
 *   MITRE ATT&CK: T1574.012 — COR_PROFILER
 *   Casey Smith / subTee: original COR_PROFILER research
 *   Microsoft docs: .NET Profiling API
 */

#include "../common.h"

#define SYSENV_KEY \
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
#define SERVICES_KEY \
    L"SYSTEM\\CurrentControlSet\\Services"

/* -----------------------------------------------------------------------
 * Check system-wide COR_PROFILER environment variables
 * --------------------------------------------------------------------- */
static void AuditSystemEnvProfiler(DWORD *findings) {
    PrintInfo(L"  [1] System-wide .NET Profiler environment variables:\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SYSENV_KEY,
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open system env key\n\n");
        return;
    }

    static const wchar_t *profilerVars[] = {
        L"COR_ENABLE_PROFILING",
        L"COR_PROFILER",
        L"COR_PROFILER_PATH",
        L"CORECLR_ENABLE_PROFILING",
        L"CORECLR_PROFILER",
        L"CORECLR_PROFILER_PATH",
        NULL
    };

    BOOL profilerEnabled = FALSE;
    wchar_t profilerPath[MAX_PATH * 2] = {0};
    wchar_t profilerCLSID[64]         = {0};

    for (int i = 0; profilerVars[i]; i++) {
        wchar_t val[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(val), type = 0;
        if (RegQueryValueExW(hKey, profilerVars[i], NULL, &type,
                             (LPBYTE)val, &cb) != ERROR_SUCCESS) continue;

        PrintInfo(L"    %s = %s\n", profilerVars[i], val);

        if (WcsContainsI(profilerVars[i], L"ENABLE_PROFILING") &&
            *val && val[0] == L'1') {
            profilerEnabled = TRUE;
        }
        if (WcsContainsI(profilerVars[i], L"PROFILER_PATH") && *val) {
            wcsncpy(profilerPath, val, _countof(profilerPath) - 1);
        }
        if (WcsContainsI(profilerVars[i], L"PROFILER") &&
            !WcsContainsI(profilerVars[i], L"PATH") &&
            !WcsContainsI(profilerVars[i], L"ENABLE") && *val) {
            wcsncpy(profilerCLSID, val, _countof(profilerCLSID) - 1);
        }
    }

    RegCloseKey(hKey);

    if (!profilerEnabled) {
        PrintInfo(L"    (no system-wide profiler enabled)\n\n");
        return;
    }

    PrintInfo(L"\n    SYSTEM-WIDE .NET PROFILER IS ACTIVE! All .NET processes load this profiler.\n");

    /* Check direct path */
    if (*profilerPath) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(profilerPath, expanded, _countof(expanded));
        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        if (writable || !exists) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"DOTNETCLR");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] COR_PROFILER_PATH: %s",
                writable ? L"WRITABLE" : L"MISSING", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"System-wide .NET Profiler DLL is %s: %s\n"
                L"        COR_ENABLE_PROFILING=1 system-wide → ALL .NET processes load this DLL.\n"
                L"        Including SYSTEM services using .NET (WMI, PowerShell, various services).\n"
                L"        %s → SYSTEM code execution when any .NET service starts.",
                writable ? L"WRITABLE" : L"MISSING", expanded,
                writable ? L"Replace DLL" : L"Plant DLL at path");
            PrintFinding(&f);
            (*findings)++;
        }
    }

    /* Check via CLSID InprocServer32 */
    if (*profilerCLSID) {
        wchar_t inprocPath[MAX_PATH * 2] = {0};
        wchar_t keyPath[512];
        _snwprintf(keyPath, _countof(keyPath),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", profilerCLSID);
        HKEY hCLSID = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hCLSID)
                == ERROR_SUCCESS) {
            DWORD cb = sizeof(inprocPath), type = 0;
            RegQueryValueExW(hCLSID, NULL, NULL, &type, (LPBYTE)inprocPath, &cb);
            RegCloseKey(hCLSID);

            if (*inprocPath) {
                wchar_t expanded[MAX_PATH * 2] = {0};
                ExpandEnvironmentStringsW(inprocPath, expanded, _countof(expanded));
                BOOL writable = IsFileWritable(expanded);
                if (writable) {
                    Finding f;
                    f.severity = SEV_CRITICAL;
                    wcscpy(f.module, L"DOTNETCLR");
                    _snwprintf(f.target, _countof(f.target),
                        L"[WRITABLE CLSID DLL] COR_PROFILER %s: %s",
                        profilerCLSID, expanded);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"System-wide .NET Profiler CLSID DLL is WRITABLE: %s\n"
                        L"        Replace DLL → loaded by ALL .NET processes including SYSTEM services.",
                        expanded);
                    PrintFinding(&f);
                    (*findings)++;
                }
            }
        }
    }

    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check per-service COR_PROFILER in service Environment registry
 * --------------------------------------------------------------------- */
static void AuditServiceProfilers(DWORD *findings) {
    PrintInfo(L"  [2] Per-service .NET Profiler configurations:\n");

    HKEY hServices = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, SERVICES_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hServices)
            != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open services key\n\n");
        return;
    }

    DWORD idx = 0, found = 0;
    wchar_t svcName[256];
    DWORD   svcNameCch;

    while (TRUE) {
        svcNameCch = _countof(svcName);
        LONG r = RegEnumKeyExW(hServices, idx++, svcName, &svcNameCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        /* Check {service}\Environment for COR_ENABLE_PROFILING */
        wchar_t envKeyPath[512];
        _snwprintf(envKeyPath, _countof(envKeyPath),
                   L"%s\\%s\\Environment", SERVICES_KEY, svcName);

        HKEY hEnv = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, envKeyPath,
                          0, KEY_READ, &hEnv) != ERROR_SUCCESS) continue;

        /* Read multi-sz environment block */
        wchar_t envBlock[4096] = {0};
        DWORD   cb = sizeof(envBlock), type = 0;
        RegQueryValueExW(hEnv, NULL, NULL, &type, (LPBYTE)envBlock, &cb);
        RegCloseKey(hEnv);

        /* Search for COR_ENABLE_PROFILING=1 or COR_PROFILER_PATH= */
        BOOL hasProfiling = FALSE;
        wchar_t *profPath = NULL;
        static wchar_t profPathBuf[MAX_PATH * 2];

        for (wchar_t *p = envBlock; *p; p += wcslen(p) + 1) {
            if (WcsContainsI(p, L"COR_ENABLE_PROFILING=1") ||
                WcsContainsI(p, L"CORECLR_ENABLE_PROFILING=1")) {
                hasProfiling = TRUE;
            }
            if (WcsContainsI(p, L"COR_PROFILER_PATH=") ||
                WcsContainsI(p, L"CORECLR_PROFILER_PATH=")) {
                wchar_t *eq = wcschr(p, L'=');
                if (eq) {
                    wcsncpy(profPathBuf, eq + 1, _countof(profPathBuf) - 1);
                    profPath = profPathBuf;
                }
            }
        }

        if (!hasProfiling) continue;
        found++;

        PrintInfo(L"    Service '%s' has .NET profiler: %s\n",
                  svcName, profPath ? profPath : L"(via CLSID)");

        if (profPath) {
            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(profPath, expanded, _countof(expanded));
            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);

            if (writable || !exists) {
                Finding f;
                f.severity = SEV_CRITICAL;
                wcscpy(f.module, L"DOTNETCLR");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] Service '%s' profiler: %s",
                    writable ? L"WRITABLE" : L"MISSING", svcName, expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L".NET Profiler DLL for service '%s' is %s: %s\n"
                    L"        Service runs with COR_ENABLE_PROFILING=1 → loads this DLL.\n"
                    L"        %s → SYSTEM code execution when service restarts.",
                    svcName, writable ? L"WRITABLE" : L"MISSING",
                    expanded,
                    writable ? L"Replace DLL" : L"Plant DLL at path");
                PrintFinding(&f);
                (*findings)++;
            }
        }
    }

    RegCloseKey(hServices);
    PrintInfo(L"    Services with .NET profiler env: %lu\n\n", found);
}

/* -----------------------------------------------------------------------
 * Check machine.config writability
 * --------------------------------------------------------------------- */
static void AuditMachineConfig(DWORD *findings) {
    PrintInfo(L"  [3] .NET machine.config files:\n");

    static const wchar_t *configPaths[] = {
        L"%windir%\\Microsoft.NET\\Framework\\v4.0.30319\\CONFIG\\machine.config",
        L"%windir%\\Microsoft.NET\\Framework64\\v4.0.30319\\CONFIG\\machine.config",
        L"%windir%\\Microsoft.NET\\Framework\\v2.0.50727\\CONFIG\\machine.config",
        NULL
    };

    for (int i = 0; configPaths[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(configPaths[i], expanded, _countof(expanded));

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        PrintInfo(L"    %s: %s\n",
                  expanded, !exists ? L"(not found)" : writable ? L"WRITABLE!" : L"ok");

        if (writable) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"DOTNETCLR");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] machine.config: %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L".NET machine.config is WRITABLE: %s\n"
                L"        Can add assembly binding redirect to redirect any .NET assembly\n"
                L"        to a malicious DLL. Affects all .NET processes on the machine.\n"
                L"        Also: can enable/configure .NET profiling globally.",
                expanded);
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

void Module_DotNetCLR(void) {
    PrintHeader(L"DOTNET CLR SURFACE  [COR_PROFILER DLL injection into .NET SYSTEM services]");

    PrintInfo(
        L"  .NET CLR profiler: DLL injected into all .NET processes if COR_ENABLE_PROFILING=1.\n"
        L"  SYSTEM services using .NET = SYSTEM code exec if profiler DLL is writable.\n"
        L"  MITRE ATT&CK: T1574.012 — COR_PROFILER.\n\n");

    DWORD findings = 0;
    AuditSystemEnvProfiler(&findings);
    AuditServiceProfilers(&findings);
    AuditMachineConfig(&findings);

    if (findings == 0)
        PrintInfo(L"  No .NET CLR profiler LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  QUICK TEST — Is any .NET service running?\n"
            L"    Get-Process | Where-Object {$_.Modules | Where-Object {$_.FileName -like '*clr*'}}\n"
            L"    Or: Task Manager → Details → right-click columns → add 'Platform' → .NET processes show .NET\n\n"
            L"  EXPLOIT PATTERN (if you can set HKLM env vars — unusual but possible):\n"
            L"    [Environment]::SetEnvironmentVariable('COR_ENABLE_PROFILING', '1', 'Machine')\n"
            L"    [Environment]::SetEnvironmentVariable('COR_PROFILER', '{CLSID}', 'Machine')\n"
            L"    [Environment]::SetEnvironmentVariable('COR_PROFILER_PATH', 'C:\\payload.dll', 'Machine')\n"
            L"    // Restart any .NET service → payload.dll loaded as profiler → SYSTEM\n");
    }
}

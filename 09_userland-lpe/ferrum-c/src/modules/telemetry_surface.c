/*
 * telemetry_surface.c — Windows Telemetry / DiagTrack Service LPE Surface
 *
 * WHY DIAGTRACK IS A HIGH-VALUE TARGET:
 *   The Connected User Experiences and Telemetry service (DiagTrack, utcsvc.exe)
 *   runs as NT AUTHORITY\SYSTEM permanently and loads various DLLs and
 *   plugin components at runtime. If any of these are in user-writable locations:
 *   → SYSTEM code execution with no user interaction required.
 *
 * ATTACK SURFACES:
 *
 *   1. DiagTrack Plugin DLLs:
 *      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\*
 *      Various plugin and provider registrations under DiagTrack registry tree.
 *      Third-party software registers plugins here — often in user-writable dirs.
 *
 *   2. ETW Data Collector DLLs:
 *      Performance Counter DLLs registered under:
 *      HKLM\SYSTEM\CurrentControlSet\Services\*\Performance\Library
 *      Loaded by DiagTrack and other SYSTEM services when collecting telemetry.
 *      (Different from --ETW which covers WINEVT providers)
 *
 *   3. Scheduled Task: Microsoft\Windows\Application Experience\
 *      Multiple scheduled tasks related to telemetry run as SYSTEM.
 *      If their action executable path is user-writable → SYSTEM exec on schedule.
 *
 *   4. SQM (Software Quality Monitoring) DLLs:
 *      HKLM\SOFTWARE\Microsoft\SQMClient\*\Plugins\
 *      Older API but still active on many systems.
 *
 *   5. CompatTelRunner / Census:
 *      %windir%\system32\CompatTelRunner.exe runs as SYSTEM via scheduled tasks.
 *      Loads plugins from configurable paths.
 *
 *   6. Microsoft Compatibility Appraiser:
 *      Scheduled task: Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser
 *      Runs CompatTelRunner.exe as SYSTEM — if ExePath is writable → LPE.
 *
 * NOVEL ANGLE:
 *   Performance Counter Library loading is almost never checked by public tools.
 *   Many third-party driver/hardware monitoring installations register perf counter
 *   DLLs in user-writable Program Files locations.
 *
 * REFERENCES:
 *   Microsoft: DiagTrack service documentation
 *   MITRE ATT&CK: T1112 — Modify Registry (for telemetry manipulation)
 *   Performance Counter DLL loading: HKLM\SYSTEM\CurrentControlSet\Services\*\Performance
 *   CompatTelRunner.exe analysis: various security research blogs
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Audit Performance Counter Library DLLs (loaded by SYSTEM for telemetry)
 * --------------------------------------------------------------------- */
static void AuditPerfCounterDLLs(DWORD *findings) {
    PrintInfo(L"  [1] Performance Counter Library DLLs (SYSTEM-loaded for telemetry):\n");

    HKEY hServices = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hServices)
            != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open Services key\n\n");
        return;
    }

    DWORD idx = 0, checked = 0, found = 0;
    wchar_t svcName[256];
    DWORD   svcNameCch;

    while (TRUE) {
        svcNameCch = _countof(svcName);
        LONG r = RegEnumKeyExW(hServices, idx++, svcName, &svcNameCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        /* Check {service}\Performance\Library */
        wchar_t perfKeyPath[512];
        _snwprintf(perfKeyPath, _countof(perfKeyPath),
                   L"SYSTEM\\CurrentControlSet\\Services\\%s\\Performance", svcName);

        HKEY hPerf = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, perfKeyPath,
                          0, KEY_READ, &hPerf) != ERROR_SUCCESS)
            continue;

        wchar_t libPath[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(libPath), type = 0;
        RegQueryValueExW(hPerf, L"Library", NULL, &type, (LPBYTE)libPath, &cb);
        RegCloseKey(hPerf);

        if (!*libPath) continue;
        checked++;

        wchar_t expanded[MAX_PATH * 2] = {0};
        if (wcschr(libPath, L'\\') || wcschr(libPath, L'/')) {
            ExpandEnvironmentStringsW(libPath, expanded, _countof(expanded));
        } else {
            /* Bare DLL name → system32 */
            wchar_t sysDir[MAX_PATH] = {0};
            GetSystemDirectoryW(sysDir, _countof(sysDir));
            _snwprintf(expanded, _countof(expanded), L"%s\\%s", sysDir, libPath);
        }

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        if (writable) {
            PrintInfo(L"    [WRITABLE] %s → %s\n", svcName, expanded);
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"TELEMETRY");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE PERF DLL] Service '%s': %s", svcName, expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Performance Counter Library DLL for service '%s' is WRITABLE: %s\n"
                L"        This DLL is loaded by SYSTEM services (DiagTrack, WMI, PerfHost) "
                L"when collecting telemetry data.\n"
                L"        Replace DLL with payload → SYSTEM code execution on next "
                L"telemetry collection or performance query.",
                svcName, expanded);
            PrintFinding(&f);
            (*findings)++;
            found++;
        } else if (!exists) {
            /* Missing perf DLL = phantom load */
            PrintInfo(L"    [MISSING] %s → %s\n", svcName, expanded);
            wchar_t libDir[MAX_PATH * 2] = {0};
            wcsncpy(libDir, expanded, _countof(libDir) - 1);
            wchar_t *sl = wcsrchr(libDir, L'\\');
            BOOL dirW = FALSE;
            if (sl) { *sl = L'\0'; dirW = IsDirWritable(libDir); }
            if (dirW) {
                Finding f;
                f.severity = SEV_HIGH;
                wcscpy(f.module, L"TELEMETRY");
                _snwprintf(f.target, _countof(f.target),
                    L"[MISSING PERF DLL] Service '%s': %s", svcName, expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Performance Counter DLL missing, directory is writable: %s\n"
                    L"        Service: %s. Plant DLL → SYSTEM loads it on perf query.",
                    expanded, svcName);
                PrintFinding(&f);
                (*findings)++;
                found++;
            }
        }
    }

    RegCloseKey(hServices);
    PrintInfo(L"    Services with Performance DLL: %lu  |  Findings: %lu\n\n",
              checked, found);
}

/* -----------------------------------------------------------------------
 * Audit DiagTrack scheduled task EXE paths
 * --------------------------------------------------------------------- */
static void AuditTelemetryTasks(DWORD *findings) {
    PrintInfo(L"  [2] Telemetry scheduled task executables:\n");

    /* Check common telemetry task action executables */
    static const wchar_t *telemetryExes[] = {
        L"%SystemRoot%\\system32\\CompatTelRunner.exe",
        L"%SystemRoot%\\system32\\DeviceCensus.exe",
        L"%SystemRoot%\\system32\\wsqmcons.exe",
        L"%SystemRoot%\\system32\\DMClient.exe",
        NULL
    };

    for (int i = 0; telemetryExes[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(telemetryExes[i], expanded, _countof(expanded));

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        PrintInfo(L"    %s: %s\n",
                  expanded,
                  !exists ? L"(not found)" : (writable ? L"WRITABLE!" : L"ok"));

        if (writable) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"TELEMETRY");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] Telemetry EXE: %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Telemetry service executable is WRITABLE: %s\n"
                L"        This EXE is run by scheduled tasks as NT AUTHORITY\\SYSTEM.\n"
                L"        Replace EXE → SYSTEM code execution on next task trigger.\n"
                L"        Tasks: Microsoft\\Windows\\Application Experience\\*, "
                L"Microsoft\\Windows\\Customer Experience Improvement Program\\*",
                expanded);
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit DiagTrack ETW data collector DLLs
 * --------------------------------------------------------------------- */
static void AuditDiagTrackRegistry(DWORD *findings) {
    PrintInfo(L"  [3] DiagTrack registry plugin paths:\n");

    static const wchar_t *diagKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\DataExporters",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\TraceManager",
        NULL
    };

    DWORD total = 0;
    for (int ki = 0; diagKeys[ki]; ki++) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, diagKeys[ki], 0, KEY_READ, &hKey)
                != ERROR_SUCCESS) continue;

        /* Check all values that look like DLL paths */
        DWORD vidx = 0;
        wchar_t vName[256];
        wchar_t vData[MAX_PATH * 2];
        DWORD   vNameCch, vDataCb, type;

        while (TRUE) {
            vNameCch = _countof(vName);
            vDataCb  = sizeof(vData);
            LONG r = RegEnumValueW(hKey, vidx++, vName, &vNameCch,
                                   NULL, &type, (LPBYTE)vData, &vDataCb);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(vData, expanded, _countof(expanded));

            /* Check if it looks like a file path */
            if (!wcschr(expanded, L'\\')) continue;
            if (!WcsContainsI(expanded, L".dll") &&
                !WcsContainsI(expanded, L".exe")) continue;

            total++;
            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);

            if (writable) {
                Finding f;
                f.severity = SEV_CRITICAL;
                wcscpy(f.module, L"TELEMETRY");
                _snwprintf(f.target, _countof(f.target),
                    L"[WRITABLE] DiagTrack value '%s': %s", vName, expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"DiagTrack registry value '%s' references writable file: %s\n"
                    L"        DiagTrack service (SYSTEM) uses this path. "
                    L"Replace file → SYSTEM code execution.",
                    vName, expanded);
                PrintFinding(&f);
                (*findings)++;
            }
        }
        RegCloseKey(hKey);
    }

    PrintInfo(L"    DiagTrack file references: %lu\n\n", total);
}

void Module_TelemetrySurface(void) {
    PrintHeader(L"TELEMETRY SURFACE  [DiagTrack SYSTEM service + Performance Counter DLLs]");

    PrintInfo(
        L"  DiagTrack (utcsvc.exe) runs as SYSTEM, loads DLLs from registered paths.\n"
        L"  Performance Counter Library DLLs loaded by SYSTEM for telemetry/WMI.\n"
        L"  Novel: perf counter DLL loading is almost never checked by public tools.\n\n");

    DWORD findings = 0;
    AuditPerfCounterDLLs(&findings);
    AuditTelemetryTasks(&findings);
    AuditDiagTrackRegistry(&findings);

    if (findings == 0)
        PrintInfo(L"  No telemetry LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  TRIGGER METHODS:\n"
            L"    Performance DLL: lodctr /R  (rebuilds perf registry — triggers DLL load)\n"
            L"    Or: start any perf monitoring tool (PerfMon, WMI query, Task Manager)\n"
            L"    DiagTrack tasks: schtasks /run /tn \"Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator\"\n"
            L"    CompatTelRunner: schtasks /run /tn \"Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\"\n");
    }
}

/*
 * vss_writer.c — Volume Shadow Copy Service (VSS) Writer DLL Hijacking
 *
 * NOVEL SURFACE — Not covered by any public LPE enumeration tool.
 *
 * WHAT VSS WRITERS ARE:
 *   Volume Shadow Copy Service (VSS) writers are COM out-of-process servers
 *   that implement the IVssWriter interface. They are invoked by VSS during
 *   snapshot creation to quiesce their data stores (databases, Exchange, SQL Server, etc.)
 *
 *   VSS writers run as separate processes with elevated privileges:
 *   - System writers: run as SYSTEM (SqlWriter, ASR Writer, BITS Writer, etc.)
 *   - Application writers: run as the application's service account
 *
 *   The VSS writer's executable/DLL is registered as a COM out-of-process server:
 *   HKLM\SOFTWARE\Classes\CLSID\{WriterCLSID}\LocalServer32 = "writer.exe"
 *
 * WHY VSS WRITERS ARE AN LPE SURFACE:
 *   1. SYSTEM-LEVEL WRITERS with writable LocalServer32 EXE:
 *      → Replace EXE → triggered by any shadow copy creation → SYSTEM exec
 *      → vssadmin create shadow /for=C: (may need admin, but scheduled backup tasks can trigger)
 *      → Windows Update, System Restore, backup software trigger VSS automatically
 *
 *   2. In-process VSS components (InprocServer32):
 *      Some VSS components load as DLLs into the calling process (SYSTEM).
 *
 *   3. WRITER METADATA DISCOVERY:
 *      Even read-only: enumerating writers reveals what services use VSS,
 *      their paths, and whether they're SYSTEM-context → targets for other attacks.
 *
 * COMMON VSS WRITERS (SYSTEM context):
 *   - BITS Writer: {4969D978-BE47-48B0-B100-1698770CB3E7} — SYSTEM
 *   - ASR Writer: {BE000CEF-10A6-4D9A-ABE5-FEA6C31E1FE0} — SYSTEM
 *   - Registry Writer: {AFBAB4A2-367D-4D15-A586-71DBB18F8485} — SYSTEM
 *   - Task Scheduler Writer: {D61D61C8-D73A-4EEE-8CDD-F6F9786B7124} — SYSTEM
 *   - VSS Metadata Store Writer: — SYSTEM
 *   - Shadow Copy Optimization Writer — SYSTEM
 *   - SQL Server Writer: runs as SQL service account
 *   - Exchange Writer: runs as Exchange service
 *
 * VSS WRITER REGISTRATION:
 *   VssWriter objects register via CreateVssBackupComponents() and Subscribe().
 *   The CLSID is registered in HKLM\SOFTWARE\Classes\CLSID.
 *   Some writers store their path in:
 *   HKLM\SYSTEM\CurrentControlSet\Services\VSS\Diag\
 *
 * REFERENCES:
 *   https://docs.microsoft.com/en-us/windows/win32/vss/overview-of-processing-a-backup-under-vss
 *   VSS SDK: IVssWriter, IVssBackupComponents
 *   MITRE T1490 — Inhibit System Recovery (defense evasion, not LPE — but same mechanism)
 *   James Forshaw: COM+ and VSS writer privilege escalation research
 */

#include "../common.h"

/* Known SYSTEM-context VSS writer CLSIDs and their names */
static const struct {
    const wchar_t *clsid;
    const wchar_t *name;
} SYSTEM_WRITERS[] = {
    { L"{4969D978-BE47-48B0-B100-1698770CB3E7}", L"BITS Writer"                    },
    { L"{BE000CEF-10A6-4D9A-ABE5-FEA6C31E1FE0}", L"ASR Writer"                     },
    { L"{AFBAB4A2-367D-4D15-A586-71DBB18F8485}", L"Registry Writer"                },
    { L"{D61D61C8-D73A-4EEE-8CDD-F6F9786B7124}", L"Task Scheduler Writer"           },
    { L"{59B1F0CF-90EF-465F-9609-6CA8B2938366}", L"IIS Writer"                     },
    { L"{A65FAA63-5EA8-4EBC-9DBD-A0C4DB26912A}", L"WMI Writer"                     },
    { L"{75DFB225-E2E4-4D39-9AC9-FFAFF65DDF06}", L"Shadow Copy Optimization Writer" },
    { L"{542DA469-D3E1-473C-9F4F-7847F01FC64F}", L"COM+ REGDB Writer"              },
    { L"{35E81631-13E1-48DB-97FC-D5BC721BB18A}", L"VSS Metadata Store Writer"       },
    { L"{CD3C27B5-7C63-4B3E-A093-2F7E9C3AE025}", L"Performance Counters Writer"    },
    { L"{E8132975-6F93-4464-A53E-1050253AE220}", L"System Writer"                   },
    { NULL, NULL }
};

/* -----------------------------------------------------------------------
 * Audit a single VSS writer CLSID for LocalServer32 writability
 * --------------------------------------------------------------------- */
static BOOL AuditWriterCLSID(LPCWSTR clsid, LPCWSTR name, DWORD *findings) {
    wchar_t keyPath[512];
    _snwprintf(keyPath, _countof(keyPath),
               L"SOFTWARE\\Classes\\CLSID\\%s\\LocalServer32", clsid);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;

    wchar_t srvPath[MAX_PATH * 2] = {0};
    DWORD   cb = sizeof(srvPath), type = 0;
    RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)srvPath, &cb);
    RegCloseKey(hKey);

    if (!*srvPath) return FALSE;

    wchar_t exePath[MAX_PATH * 2] = {0};
    ExtractExePath(srvPath, exePath, _countof(exePath));
    if (!*exePath) wcsncpy(exePath, srvPath, _countof(exePath)-1);

    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(exePath, expanded, _countof(expanded));
    BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(expanded);

    PrintInfo(L"    [%s] Writer: %-35s → %s%s\n",
              clsid, name, expanded,
              writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

    if (writable || !exists) {
        Finding f;
        f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
        wcscpy(f.module, L"VSSWRITER");
        _snwprintf(f.target, _countof(f.target),
            L"[%s] VSS Writer '%s' EXE: %s",
            writable ? L"WRITABLE" : L"MISSING", name, expanded);
        _snwprintf(f.reason, _countof(f.reason),
            L"VSS Writer '%s' (CLSID: %s) EXE is %s: %s\n"
            L"        System VSS writers run as SYSTEM.\n"
            L"        VSS writers are activated automatically by:\n"
            L"          - Windows Update (shadow copies before updates)\n"
            L"          - System Restore points\n"
            L"          - Backup software (Windows Backup, Veeam, Acronis)\n"
            L"          - vssadmin create shadow /for=C:\n"
            L"        %s → SYSTEM code execution on next shadow copy operation.",
            name, clsid,
            writable ? L"WRITABLE" : L"MISSING", expanded,
            writable ? L"Replace writer EXE with payload" : L"Plant EXE at path");
        PrintFinding(&f);
        (*findings)++;
        return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Enumerate ALL CLSID registrations to find VSS writer patterns
 * --------------------------------------------------------------------- */
static void AuditAllVSSWriters(DWORD *findings) {
    PrintInfo(L"  [1] Known SYSTEM VSS Writer CLSIDs:\n");

    DWORD found = 0;
    for (int i = 0; SYSTEM_WRITERS[i].clsid; i++) {
        if (AuditWriterCLSID(SYSTEM_WRITERS[i].clsid,
                              SYSTEM_WRITERS[i].name, findings)) {
            found++;
        }
    }
    PrintInfo(L"    Known writers checked: %lu\n\n",
              (DWORD)(sizeof(SYSTEM_WRITERS)/sizeof(SYSTEM_WRITERS[0]) - 1));
}

/* -----------------------------------------------------------------------
 * Discover VSS writers from the VSS service registration
 * --------------------------------------------------------------------- */
static void AuditVSSServiceComponents(DWORD *findings) {
    PrintInfo(L"  [2] VSS service component paths:\n");

    /* VSS Diag entries sometimes contain writer DLL paths */
    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services\\VSS\\Diag",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) == ERROR_SUCCESS) {
        DWORD idx = 0, count = 0;
        wchar_t diagName[128];
        DWORD   diagNameCch;
        while (TRUE) {
            diagNameCch = _countof(diagName);
            LONG r = RegEnumKeyExW(hRoot, idx++, diagName, &diagNameCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            count++;
        }
        RegCloseKey(hRoot);
        PrintInfo(L"    VSS\\Diag entries: %lu\n", count);
    }

    /* Check VSS provider DLLs */
    static const wchar_t *VSS_DLLS[] = {
        L"%SystemRoot%\\system32\\vss_ps.dll",
        L"%SystemRoot%\\system32\\vssapi.dll",
        L"%SystemRoot%\\system32\\vsssvc.dll",
        NULL
    };

    for (int i = 0; VSS_DLLS[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(VSS_DLLS[i], expanded, _countof(expanded));
        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);
        PrintInfo(L"    %-50s %s\n",
                  expanded, !exists ? L"[NOT FOUND]" : writable ? L"[WRITABLE!]" : L"ok");
        if (writable) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"VSSWRITER");
            _snwprintf(f.target, _countof(f.target), L"[WRITABLE VSS DLL] %s", expanded);
            wcscpy(f.reason,
                L"Core VSS DLL is writable — loaded by all VSS operations and backup software.\n"
                L"        VSS runs as SYSTEM → universal SYSTEM code injection.");
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check for any SYSTEM services with IVssWriter in their description
 * --------------------------------------------------------------------- */
static void AuditVSSWriterServices(DWORD *findings) {
    PrintInfo(L"  [3] Services related to VSS writers:\n");

    static const wchar_t *WRITER_SERVICES[] = {
        L"SQLWriter",      /* SQL Server VSS Writer — SQL service acct */
        L"MSExchangeIS",   /* Exchange IS writer */
        L"OSearch15",      /* SharePoint search writer */
        L"SPWriterV4",     /* SharePoint writer */
        L"SPSearch",       /* SharePoint search */
        NULL
    };

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintInfo(L"    Cannot open SCM\n\n"); return; }

    for (int i = 0; WRITER_SERVICES[i]; i++) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, WRITER_SERVICES[i], SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        wchar_t cfgBuf[4096] = {0};
        DWORD   needed = 0;
        QUERY_SERVICE_CONFIGW *pCfg = (QUERY_SERVICE_CONFIGW *)cfgBuf;
        if (QueryServiceConfigW(hSvc, pCfg, sizeof(cfgBuf), &needed)) {
            PrintInfo(L"    [FOUND] %s — runs as %s\n",
                      WRITER_SERVICES[i],
                      pCfg->lpServiceStartName ? pCfg->lpServiceStartName : L"?");
            if (pCfg->lpBinaryPathName) {
                wchar_t exePath[MAX_PATH * 2] = {0};
                ExtractExePath(pCfg->lpBinaryPathName, exePath, _countof(exePath));
                BOOL writable = (GetFileAttributesW(exePath) != INVALID_FILE_ATTRIBUTES)
                                && IsFileWritable(exePath);
                if (writable)
                    PrintInfo(L"      Binary WRITABLE: %s\n", exePath);
            }
        }
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);
    PrintInfo(L"\n");
}

void Module_VSSWriter(void) {
    PrintHeader(L"VSS WRITER DLL HIJACKING  [Novel: Volume Shadow Copy writer EXE/DLL — triggered by backup ops]");

    PrintInfo(
        L"  VSS system writers run as SYSTEM — triggered by Windows Update, backup, restore points.\n"
        L"  Writable writer EXE = automatic SYSTEM exec on next shadow copy operation.\n"
        L"  No public LPE tool covers this surface.\n\n");

    DWORD findings = 0;
    AuditAllVSSWriters(&findings);
    AuditVSSServiceComponents(&findings);
    AuditVSSWriterServices(&findings);

    if (findings == 0)
        PrintInfo(L"  No VSS writer hijacking surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  TRIGGER VSS WRITER EXECUTION:\n"
            L"    vssadmin create shadow /for=C:  (requires admin)\n"
            L"    wmic shadowcopy call create Volume=C:\\\\\n"
            L"    Create/delete a System Restore point (triggers VSS automatically)\n"
            L"    Install/update any software using Windows Installer (may trigger VSS)\n"
            L"    Run Windows Backup → triggers all registered writers\n");
    }
}

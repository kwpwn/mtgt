/*
 * perflib.c — Performance Counter DLL Audit
 *
 * UNDEREXPLORED ATTACK SURFACE:
 * Windows Performance Counter providers register DLLs under:
 *   HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Performance\
 *       Library  = "path\to\counter.dll"
 *       Open     = "OpenPerfData"
 *       Collect  = "CollectPerfData"
 *       Close    = "ClosePerfData"
 *
 * These DLLs are loaded by pdh.dll (Performance Data Helper) which is
 * called by:
 *   - Task Manager (elevated in some contexts)
 *   - perfmon.exe (often elevated)
 *   - WMI Performance Counter Provider (SYSTEM)
 *   - Any monitoring agent calling PdhOpenQuery / PdhCollectQueryData
 *
 * If the Library path is user-writable, or the Performance registry
 * subkey is writable → DLL load in elevated/SYSTEM context.
 *
 * This check is absent from WinPEAS, PowerUp, Seatbelt, and Ferrum Go.
 * It is a genuine gap in automated LPE enumeration tools (as of 2026).
 *
 * Attack chain:
 *   1. Find service with writable Performance\Library path
 *   2. Replace DLL with proxy (forward real exports from OpenPerfData etc.)
 *   3. Wait for perfmon / Task Manager / WMI query to collect counters
 *   4. DLL loads in collector's process context (often SYSTEM via WMI)
 *
 * References:
 *   https://docs.microsoft.com/en-us/windows/win32/perfctrs/adding-counter-names-and-descriptions-to-the-registry
 *   SDK: LoadLibrary called from pdh!PdhiOpenCounter
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Required exports a performance counter DLL must provide.
 * Used to craft a working proxy if hijacking.
 * --------------------------------------------------------------------- */
static const wchar_t *g_perfExports[] = {
    L"OpenPerfData",    /* or custom name from Open value   */
    L"CollectPerfData", /* or custom name from Collect value */
    L"ClosePerfData",   /* or custom name from Close value   */
    NULL
};

/* -----------------------------------------------------------------------
 * Check one service's Performance subkey.
 * --------------------------------------------------------------------- */
static void CheckPerfService(LPCWSTR svcName, DWORD *findings) {
    wchar_t subPath[512];
    _snwprintf(subPath, _countof(subPath),
        L"SYSTEM\\CurrentControlSet\\Services\\%s\\Performance", svcName);

    HKEY hPerf = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hPerf)
            != ERROR_SUCCESS)
        return;   /* no Performance subkey — not a perf provider */

    /* Read Library value */
    wchar_t libPath[MAX_PATH * 2] = {0};
    DWORD   cb = sizeof(libPath), type = 0;
    BOOL    hasLib = (RegQueryValueExW(hPerf, L"Library", NULL, &type,
                                       (LPBYTE)libPath, &cb) == ERROR_SUCCESS);
    RegCloseKey(hPerf);

    if (!hasLib || !*libPath) return;

    /* Expand environment variables */
    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(libPath, expanded, _countof(expanded));

    /* ---- Check 1: DLL in user-writable location ---- */
    if (IsUserWritablePath(expanded)) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"PERFLIB");
        _snwprintf(f.target, _countof(f.target),
            L"%s\\Performance\\Library", svcName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Perf counter DLL in user-writable location. "
            L"Loaded by pdh.dll / WMI SYSTEM context. DLL: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    }

    /* ---- Check 2: DLL file itself is writable ---- */
    if (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES
        && IsFileWritable(expanded))
    {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"PERFLIB");
        _snwprintf(f.target, _countof(f.target),
            L"%s\\Performance\\Library", svcName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Perf counter DLL is WRITABLE by current user! "
            L"Replace with proxy DLL → code runs when WMI/perfmon queries this counter. "
            L"DLL: %s  Required exports: OpenPerfData, CollectPerfData, ClosePerfData",
            expanded);
        PrintFinding(&f);
        (*findings)++;
    }

    /* ---- Check 3: DLL missing (phantom load) ---- */
    if (GetFileAttributesW(expanded) == INVALID_FILE_ATTRIBUTES) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"PERFLIB");
        _snwprintf(f.target, _countof(f.target),
            L"%s\\Performance\\Library", svcName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Perf counter DLL NOT FOUND on disk — phantom load candidate. "
            L"If any searched dir is writable, plant DLL there. "
            L"Missing: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    }

    /* ---- Check 4: Performance registry subkey writable ---- */
    if (IsRegKeyWritable(HKEY_LOCAL_MACHINE, subPath)) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"PERFLIB");
        _snwprintf(f.target, _countof(f.target),
            L"HKLM\\...\\%s\\Performance", svcName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Performance registry subkey WRITABLE. "
            L"Modify Library value → point to evil DLL → "
            L"code runs in WMI/pdh context (often SYSTEM). "
            L"Current library: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_PerfLib(void) {
    PrintHeader(L"PERFORMANCE COUNTER DLL AUDIT (UNDEREXPLORED SURFACE)");

    PrintInfo(
        L"  Checking HKLM\\...\\Services\\*\\Performance\\Library\n"
        L"  These DLLs load in pdh.dll/WMI/perfmon context (often SYSTEM).\n"
        L"  Standard LPE tools (WinPEAS, PowerUp, Seatbelt) do NOT check this.\n\n");

    HKEY hServices = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",
        0, KEY_READ | KEY_ENUMERATE_SUB_KEYS,
        &hServices) != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open Services key\n");
        return;
    }

    DWORD idx = 0, total = 0, checked = 0;
    wchar_t svcName[128];
    DWORD   svcCch;

    while (TRUE) {
        svcCch = _countof(svcName);
        LONG ret = RegEnumKeyExW(hServices, idx++, svcName, &svcCch,
                                  NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS)       continue;
        checked++;
        CheckPerfService(svcName, &total);
    }
    RegCloseKey(hServices);

    PrintInfo(L"  Services checked: %lu\n", checked);

    if (total == 0)
        PrintInfo(L"  No performance counter DLL issues found.\n");
    else {
        PrintInfo(L"  Findings: %lu\n\n", total);
        PrintInfo(
            L"  EXPLOITATION NOTE:\n"
            L"  To trigger DLL load:\n"
            L"    1. Open Task Manager (elevated) → Performance tab\n"
            L"    2. Run: typeperf \"\\<ObjectName>\\<CounterName>\" -sc 1\n"
            L"    3. Run: wmic path Win32_PerfRawData_<SvcName>_* get *\n"
            L"    4. Wait for any monitoring agent (Zabbix, PRTG, etc.) to poll\n"
            L"  If WMI provider host (WmiPrvSE.exe) loads the DLL: SYSTEM execution.\n");
    }
}

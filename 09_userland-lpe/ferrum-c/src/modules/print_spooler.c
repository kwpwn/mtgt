/*
 * print_spooler.c — Print Monitor + Print Processor DLL Audit
 *
 * ATTACK SURFACE — CRITICAL:
 *   The Print Spooler service (spoolsv.exe) runs as SYSTEM and loads DLLs
 *   registered under two registry locations:
 *
 *   1. PRINT MONITORS:
 *      HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver
 *      spoolsv.exe calls AddPrintMonitor / LoadLibrary on the Driver value.
 *      Driver value is usually just a filename (e.g., "pjlmon.dll") and
 *      Windows searches System32. But third-party monitors may use full paths
 *      pointing to non-System32 locations.
 *
 *   2. PRINT PROCESSORS:
 *      HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\
 *          Windows x64\Print Processors\<name>\Driver
 *      Same loading mechanism, same attack surface.
 *
 * WHY THIS CLASS IS HIGH-VALUE:
 *   - PrintNightmare (CVE-2021-1675 / CVE-2021-34527) was entirely in the
 *     Print Spooler DLL loading pipeline. Patching closed specific code paths
 *     but did NOT change the fundamental architecture: spoolsv.exe (SYSTEM)
 *     loads arbitrary DLLs from administrator-specified paths.
 *   - Post-patch variants (CVE-2022-21999, etc.) show this class keeps producing.
 *   - Third-party printer software frequently installs monitors/processors to
 *     application-specific directories that may be user-writable.
 *
 * CHECKS PERFORMED:
 *   For each Monitor / Processor Driver value:
 *     a) Expand environment variables in the path
 *     b) If full path: check file writability + directory writability
 *     c) If filename only: search System32 first, then check if the DLL exists
 *        elsewhere in a user-writable location (DLL planting risk)
 *     d) If DLL does not exist: SEV_HIGH (phantom — can be planted if search hits
 *        a user-writable directory before System32, unlikely but possible)
 *
 * NOTE ON EXPLOITATION:
 *   Even if the DLL is in System32 (protected), the loading pipeline can
 *   sometimes be redirected via:
 *     - DLL side-loading from the spoolsv.exe working directory (C:\Windows\System32)
 *     - A weak ACL on the registry key itself (replacing the Driver value)
 *   This module also checks registry key ACL for the Driver value key.
 */

#include "../common.h"

#define MONITORS_KEY \
    L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors"
#define PROCESSORS_KEY \
    L"SYSTEM\\CurrentControlSet\\Control\\Print\\Environments\\Windows x64\\Print Processors"

/* -----------------------------------------------------------------------
 * Resolve a monitor/processor Driver value to an absolute path.
 * If just a filename, look it up in System32.
 * Returns FALSE if not resolvable.
 * --------------------------------------------------------------------- */
static BOOL ResolveDriverPath(LPCWSTR driverVal, LPWSTR out, DWORD outCch) {
    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(driverVal, expanded, _countof(expanded));

    /* If it already has a path separator, it's a full path */
    if (wcschr(expanded, L'\\') || wcschr(expanded, L'/')) {
        wcsncpy(out, expanded, outCch - 1);
        return TRUE;
    }

    /* Filename only: build System32 path */
    wchar_t sys32[MAX_PATH] = {0};
    GetSystemDirectoryW(sys32, _countof(sys32));
    _snwprintf(out, outCch, L"%s\\%s", sys32, expanded);
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Audit one print driver entry (monitor or processor)
 * --------------------------------------------------------------------- */
static void AuditDriverEntry(LPCWSTR entryName, LPCWSTR driverVal,
                              LPCWSTR parentKeyPath, LPCWSTR entryType,
                              DWORD *findings)
{
    wchar_t fullPath[MAX_PATH * 2] = {0};
    if (!ResolveDriverPath(driverVal, fullPath, _countof(fullPath))) return;

    BOOL hasSep   = (wcschr(driverVal, L'\\') != NULL);
    BOOL exists   = (GetFileAttributesW(fullPath) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(fullPath);

    /* Check the directory containing the DLL */
    wchar_t dllDir[MAX_PATH * 2] = {0};
    wcsncpy(dllDir, fullPath, _countof(dllDir) - 1);
    wchar_t *sl = wcsrchr(dllDir, L'\\');
    if (sl) *sl = L'\0';
    BOOL dirWritable = IsDirWritable(dllDir);
    BOOL inUserPath  = IsUserWritablePath(fullPath);

    /* Also check if the registry KEY is writable (can change Driver path) */
    wchar_t subKeyPath[512];
    _snwprintf(subKeyPath, _countof(subKeyPath), L"%s\\%s", parentKeyPath, entryName);
    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, subKeyPath);

    Finding f;
    wcscpy(f.module, L"PRINT_SPOOLER");

    if (writable) {
        f.severity = SEV_CRITICAL;
        _snwprintf(f.target, _countof(f.target),
            L"[%s] %s — WRITABLE DLL", entryType, entryName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Print %s DLL is DIRECTLY WRITABLE by current user! "
            L"spoolsv.exe (SYSTEM) loads this DLL. "
            L"Replace → DllMain runs as NT AUTHORITY\\SYSTEM. "
            L"Trigger: net stop/start Spooler OR send print job. "
            L"DLL: %s", entryType, fullPath);
        PrintFinding(&f);
        (*findings)++;
    } else if (!exists && hasSep) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[%s] %s — DLL MISSING (full path)", entryType, entryName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Print %s DLL does not exist at registered path. "
            L"If parent directory is writable, plant the DLL. "
            L"spoolsv.exe (SYSTEM) will load it on next print operation. "
            L"Dir writable: %s  Path: %s",
            entryType, dirWritable ? L"YES" : L"No", fullPath);
        PrintFinding(&f);
        (*findings)++;
    } else if (dirWritable && hasSep) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[%s] %s — WRITABLE DIRECTORY", entryType, entryName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Print %s DLL directory is user-writable. "
            L"DLL itself may be replaceable or a proxy DLL can be planted alongside. "
            L"Trigger: net stop/start Spooler. DLL: %s",
            entryType, fullPath);
        PrintFinding(&f);
        (*findings)++;
    } else if (inUserPath && hasSep) {
        f.severity = SEV_MEDIUM;
        _snwprintf(f.target, _countof(f.target),
            L"[%s] %s — USER-PATH LOCATION", entryType, entryName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Print %s DLL is in a user-controlled path (%s). "
            L"Verify file ACL directly.", entryType, fullPath);
        PrintFinding(&f);
        (*findings)++;
    }

    if (keyWritable) {
        Finding fk;
        fk.severity = SEV_CRITICAL;
        wcscpy(fk.module, L"PRINT_SPOOLER");
        _snwprintf(fk.target, _countof(fk.target),
            L"[%s KEY] %s — WRITABLE REGISTRY KEY", entryType, entryName);
        _snwprintf(fk.reason, _countof(fk.reason),
            L"Current user can modify the print %s registry key! "
            L"Change the Driver value to any attacker-controlled DLL path. "
            L"spoolsv.exe (SYSTEM) will load it on restart. "
            L"Key: HKLM\\%s", entryType, subKeyPath);
        PrintFinding(&fk);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Enumerate all entries under a Print key
 * --------------------------------------------------------------------- */
static void EnumPrintKey(LPCWSTR keyPath, LPCWSTR entryType, DWORD *findings) {
    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [skip] Cannot open HKLM\\%s\n", keyPath);
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t name[256];
    DWORD   nameCch;

    while (TRUE) {
        nameCch = _countof(name);
        LONG r = RegEnumKeyExW(hRoot, idx++, name, &nameCch,
                                NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS)       continue;
        count++;

        HKEY hEntry = NULL;
        if (RegOpenKeyExW(hRoot, name, 0, KEY_READ, &hEntry) != ERROR_SUCCESS)
            continue;

        wchar_t driverVal[MAX_PATH * 2] = {0};
        DWORD cb = sizeof(driverVal);
        if (RegQueryValueExW(hEntry, L"Driver", NULL, NULL,
                             (LPBYTE)driverVal, &cb) == ERROR_SUCCESS && *driverVal)
            AuditDriverEntry(name, driverVal, keyPath, entryType, findings);

        RegCloseKey(hEntry);
    }

    RegCloseKey(hRoot);
    PrintInfo(L"  %s entries: %lu\n", entryType, count);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_PrintSpooler(void) {
    PrintHeader(L"PRINT SPOOLER DLL AUDIT  [PrintNightmare-class surface]");

    PrintInfo(
        L"  spoolsv.exe (SYSTEM) loads DLLs registered as print monitors\n"
        L"  and print processors. Writable DLL or registry key = SYSTEM exec.\n"
        L"  CVE-2021-1675 / CVE-2021-34527 class (PrintNightmare).\n\n");

    DWORD findings = 0;

    PrintInfo(L"  [1] Print Monitors:\n");
    EnumPrintKey(MONITORS_KEY, L"Monitor", &findings);

    PrintInfo(L"\n  [2] Print Processors (x64):\n");
    EnumPrintKey(PROCESSORS_KEY, L"Processor", &findings);

    PrintInfo(L"\n");
    if (findings == 0)
        PrintInfo(L"  No print spooler DLL issues found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOIT PATH (CRITICAL findings):\n"
            L"    1. Craft minimal DLL (DllMain with payload, no exports needed)\n"
            L"    2. Replace writable DLL or create the missing one\n"
            L"    3. Trigger: sc stop Spooler && sc start Spooler\n"
            L"       OR: Send any print job to any printer\n"
            L"    4. spoolsv.exe (SYSTEM) loads DLL → DllMain → SYSTEM shell\n");
    }
}

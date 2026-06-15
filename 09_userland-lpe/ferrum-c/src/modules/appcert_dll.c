/*
 * appcert_dll.c — AppCert DLL Audit
 *
 * ATTACK SURFACE — HIGH:
 *   AppCert DLLs are loaded into EVERY process that calls one of:
 *     CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW,
 *     CreateProcessWithTokenW, WinExec
 *
 *   Registry key:
 *     HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls\
 *       <ValueName> = REG_SZ full path to DLL
 *
 *   How it works:
 *     When a process calls CreateProcess, the kernel (KernelBase.dll) calls
 *     AppCertpCallDll() for each registered AppCert DLL BEFORE the new process
 *     is created. The DLL is loaded into the CALLING process (not the child).
 *     The DLL's exported function CreateProcessNotify(wchar_t *path) is called.
 *
 *   LPE angle:
 *     If an elevated process (SYSTEM service, Task Scheduler, etc.) calls
 *     CreateProcess, the AppCert DLL runs IN THAT ELEVATED PROCESS.
 *     → If DLL is writable by current user → wait for elevated process to
 *     CreateProcess → code runs at elevated privilege.
 *
 *   Persistence angle (even without immediate LPE):
 *     AppCert DLL runs in EVERY process → ideal keylogger / credential harvester.
 *     Any future elevated CreateProcess → automatic privilege escalation.
 *
 * CHECKS:
 *   1. Are any AppCert DLLs registered?
 *   2. Is the DLL file writable by current user? → CRITICAL
 *   3. Is the directory writable (can plant a replacement)? → HIGH
 *   4. Does the DLL exist? If not → can plant in a writable location? → HIGH
 *   5. Is the registry key itself writable? → Can add new AppCert DLL → HIGH
 *
 * REQUIRED DLL EXPORT:
 *   The AppCert DLL must export:
 *     NTSTATUS NTAPI CreateProcessNotify(LPCWSTR processImagePath);
 *   This function is called synchronously in the caller's context.
 *
 * REFERENCES:
 *   MITRE ATT&CK: T1546.009 (Event Triggered Execution: AppCert DLLs)
 *   Mark Russinovich — Process creation internals
 */

#include "../common.h"

#define APPCERT_KEY \
    L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls"

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_AppCertDLL(void) {
    PrintHeader(L"APPCERT DLL AUDIT  [Loaded into EVERY CreateProcess caller]");

    PrintInfo(
        L"  AppCert DLLs load into any process calling CreateProcess*.\n"
        L"  If an elevated process calls CreateProcess, the DLL runs elevated.\n"
        L"  Key: HKLM\\" APPCERT_KEY L"\n\n");

    DWORD findings = 0;

    /* Check if the key itself is writable */
    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, APPCERT_KEY);
    if (keyWritable) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"APPCERT_DLL");
        wcscpy(f.target, L"[KEY WRITABLE] HKLM\\" APPCERT_KEY);
        wcscpy(f.reason,
            L"User can write to AppCertDlls registry key! "
            L"Add a new value with path to attacker DLL. "
            L"DLL will load into EVERY process calling CreateProcess. "
            L"When an elevated process calls CreateProcess → SYSTEM code exec. "
            L"Required export: CreateProcessNotify(LPCWSTR imagePath)");
        PrintFinding(&f);
        findings++;
    }

    /* Enumerate existing AppCert DLL entries */
    HKEY hKey = NULL;
    LONG ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, APPCERT_KEY,
                              0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS) {
        if (ret == ERROR_FILE_NOT_FOUND)
            PrintInfo(L"  No AppCert DLLs registered (key does not exist).\n");
        else
            PrintInfo(L"  [!] Cannot open AppCertDlls key (err %ld)\n", ret);
        goto done;
    }

    DWORD idx = 0, count = 0;
    wchar_t valName[256], valData[MAX_PATH * 2];
    DWORD   nameCch, dataCb, type;

    while (TRUE) {
        nameCch = _countof(valName);
        dataCb  = sizeof(valData);
        LONG r  = RegEnumValueW(hKey, idx++, valName, &nameCch,
                                NULL, &type, (LPBYTE)valData, &dataCb);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS)       continue;
        count++;

        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        if (!*valData) continue;

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(valData, expanded, _countof(expanded));

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);
        BOOL inUser   = IsUserWritablePath(expanded);

        /* Directory writable */
        wchar_t dllDir[MAX_PATH * 2] = {0};
        wcsncpy(dllDir, expanded, _countof(dllDir) - 1);
        wchar_t *sl = wcsrchr(dllDir, L'\\');
        BOOL dirWritable = FALSE;
        if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(dllDir); }

        Finding f;
        wcscpy(f.module, L"APPCERT_DLL");

        if (writable) {
            f.severity = SEV_CRITICAL;
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] %s", valName);
            _snwprintf(f.reason, _countof(f.reason),
                L"AppCert DLL is DIRECTLY WRITABLE! "
                L"Loads into every CreateProcess caller. "
                L"Elevated process CreateProcess → your code runs elevated. "
                L"DLL: %s  |  Required export: CreateProcessNotify()", expanded);
            PrintFinding(&f);
            findings++;
        } else if (!exists) {
            f.severity = SEV_HIGH;
            _snwprintf(f.target, _countof(f.target),
                L"[MISSING DLL] %s", valName);
            _snwprintf(f.reason, _countof(f.reason),
                L"AppCert DLL does not exist: %s\n"
                L"        If parent directory is writable, plant the DLL.\n"
                L"        Dir writable: %s",
                expanded, dirWritable ? L"YES" : L"No");
            PrintFinding(&f);
            findings++;
        } else if (dirWritable) {
            f.severity = SEV_HIGH;
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE DIR] %s", valName);
            _snwprintf(f.reason, _countof(f.reason),
                L"AppCert DLL directory is user-writable. "
                L"May allow DLL planting or replacement. DLL: %s", expanded);
            PrintFinding(&f);
            findings++;
        } else if (inUser) {
            f.severity = SEV_MEDIUM;
            _snwprintf(f.target, _countof(f.target),
                L"[USER-PATH] %s", valName);
            _snwprintf(f.reason, _countof(f.reason),
                L"AppCert DLL in user-accessible path. Verify ACL. DLL: %s",
                expanded);
            PrintFinding(&f);
            findings++;
        } else {
            /* DLL exists and is protected — just report its existence */
            PrintInfo(L"  [ok] %s → %s\n", valName, expanded);
        }
    }

    RegCloseKey(hKey);
    PrintInfo(L"  AppCert DLLs registered: %lu\n", count);

done:
    PrintInfo(L"\n");
    if (findings == 0)
        PrintInfo(L"  No AppCert DLL issues found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOITATION NOTES:\n"
            L"    Required DLL export:\n"
            L"      NTSTATUS NTAPI CreateProcessNotify(LPCWSTR processImagePath);\n"
            L"    Trigger: ANY elevated process calling CreateProcess.\n"
            L"    Monitor with: ProcMon [Operation=CreateProcess, Integrity=High/System]\n"
            L"    If no elevated CreateProcess soon: trigger via:\n"
            L"      schtasks /run /tn <any system task>\n"
            L"      This causes Task Scheduler (SYSTEM) to CreateProcess.\n");
    }
}

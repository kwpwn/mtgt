/*
 * registry.c — Registry Permission LPE Checks
 *
 * Checks:
 *   1. AlwaysInstallElevated (both HKLM + HKCU must be = 1)
 *   2. Winlogon Userinit / Shell values — writable?
 *   3. AppInit_DLLs — non-empty + LoadAppInit_DLLs = 1?
 *   4. Every service key under HKLM\...\Services for user-writable ACL
 *   5. HKCU\Environment\Path — prepend attack surface
 *   6. IFEO (Image File Execution Options) — Debugger values for
 *      high-value targets (utilman, sethc, osk, etc.)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * 1. AlwaysInstallElevated
 * --------------------------------------------------------------------- */
static void CheckAlwaysInstallElevated(DWORD *total) {
    DWORD hklmVal = 0, hkcuVal = 0;
    DWORD cb = sizeof(DWORD);

    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        RegQueryValueExW(hk, L"AlwaysInstallElevated", NULL, NULL,
                         (LPBYTE)&hklmVal, &cb);
        RegCloseKey(hk);
    }

    cb = sizeof(DWORD);
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hk) == ERROR_SUCCESS) {
        RegQueryValueExW(hk, L"AlwaysInstallElevated", NULL, NULL,
                         (LPBYTE)&hkcuVal, &cb);
        RegCloseKey(hk);
    }

    if (hklmVal == 1 && hkcuVal == 1) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"REGISTRY");
        wcscpy(f.target, L"AlwaysInstallElevated");
        wcscpy(f.reason,
            L"HKLM + HKCU both set to 1. Any MSI installs as SYSTEM. "
            L"Exploit: msiexec /quiet /i evil.msi");
        PrintFinding(&f);
        (*total)++;
    } else {
        PrintInfo(L"  AlwaysInstallElevated: HKLM=%lu HKCU=%lu (not vulnerable)\n",
                  hklmVal, hkcuVal);
    }
}

/* -----------------------------------------------------------------------
 * 2. Winlogon values
 * --------------------------------------------------------------------- */
static void CheckWinlogon(DWORD *total) {
    LPCWSTR regPath = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hk)
            != ERROR_SUCCESS)
        return;

    struct { LPCWSTR value; LPCWSTR desc; } checks[] = {
        { L"Userinit", L"Userinit: add payload to run at logon as logged-in user" },
        { L"Shell",    L"Shell: replace explorer.exe with payload" },
        { NULL, NULL }
    };

    for (int i = 0; checks[i].value; i++) {
        wchar_t data[MAX_PATH * 2] = {0};
        DWORD   cb   = sizeof(data), type = 0;
        RegQueryValueExW(hk, checks[i].value, NULL, &type,
                         (LPBYTE)data, &cb);

        /* Check if the key itself is writable */
        if (IsRegKeyWritable(HKEY_LOCAL_MACHINE, regPath)) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"REGISTRY");
            wcsncpy(f.target, checks[i].value, _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"%s  |  Current value: %s", checks[i].desc, data);
            PrintFinding(&f);
            (*total)++;
        } else {
            PrintInfo(L"  Winlogon\\%s: %s (key not writable)\n",
                      checks[i].value, data);
        }
    }
    RegCloseKey(hk);
}

/* -----------------------------------------------------------------------
 * 3. AppInit_DLLs
 * --------------------------------------------------------------------- */
static void CheckAppInitDLLs(DWORD *total) {
    LPCWSTR regPath =
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hk)
            != ERROR_SUCCESS)
        return;

    DWORD loadEnabled = 0, cb = sizeof(DWORD);
    RegQueryValueExW(hk, L"LoadAppInit_DLLs", NULL, NULL,
                     (LPBYTE)&loadEnabled, &cb);

    wchar_t dllVal[MAX_PATH * 2] = {0};
    cb = sizeof(dllVal);
    RegQueryValueExW(hk, L"AppInit_DLLs", NULL, NULL, (LPBYTE)dllVal, &cb);
    RegCloseKey(hk);

    if (loadEnabled && *dllVal) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"REGISTRY");
        wcscpy(f.target, L"AppInit_DLLs");
        _snwprintf(f.reason, _countof(f.reason),
            L"AppInit_DLLs active (LoadAppInit=1). "
            L"Injected into every user32.dll consumer. DLLs: %s", dllVal);
        PrintFinding(&f);
        (*total)++;
    } else {
        PrintInfo(L"  AppInit_DLLs: LoadEnabled=%lu  Value='%s'\n",
                  loadEnabled, dllVal);
    }
}

/* -----------------------------------------------------------------------
 * 4. Writable service registry keys
 * --------------------------------------------------------------------- */
static void CheckWritableServiceKeys(DWORD *total) {
    HKEY hServices = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",
        0, KEY_READ | KEY_ENUMERATE_SUB_KEYS,
        &hServices) != ERROR_SUCCESS)
        return;

    DWORD idx = 0;
    wchar_t svcName[128];
    DWORD   svcCch;
    DWORD   found = 0;

    while (TRUE) {
        svcCch = _countof(svcName);
        LONG ret = RegEnumKeyExW(hServices, idx++, svcName, &svcCch,
                                  NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS)       continue;

        wchar_t subPath[256];
        _snwprintf(subPath, _countof(subPath),
            L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);

        if (IsRegKeyWritable(HKEY_LOCAL_MACHINE, subPath)) {
            /* Check if service runs as SYSTEM (makes it LPE, not just misconfiguration) */
            HKEY hSvc = NULL;
            wchar_t objName[128] = {0};
            DWORD   cb = sizeof(objName), type = 0;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hSvc)
                    == ERROR_SUCCESS) {
                RegQueryValueExW(hSvc, L"ObjectName", NULL, &type,
                                 (LPBYTE)objName, &cb);
                RegCloseKey(hSvc);
            }

            BOOL isSystem = (*objName == 0) ||
                            _wcsicmp(objName, L"LocalSystem") == 0 ||
                            WcsContainsI(objName, L"SYSTEM");

            Finding f;
            f.severity = isSystem ? SEV_CRITICAL : SEV_HIGH;
            wcscpy(f.module, L"REGISTRY");
            wcsncpy(f.target, svcName, _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Service registry key WRITABLE by current user. "
                L"Account: %s  → modify ImagePath → restart svc → %s",
                *objName ? objName : L"LocalSystem",
                isSystem ? L"SYSTEM execution" : L"service account execution");
            PrintFinding(&f);
            found++;
            (*total)++;
        }
    }
    RegCloseKey(hServices);

    if (found == 0)
        PrintInfo(L"  No writable service registry keys found.\n");
}

/* -----------------------------------------------------------------------
 * 5. IFEO Debugger for high-value targets
 * --------------------------------------------------------------------- */
static void CheckIFEO(DWORD *total) {
    /* These executables are commonly targeted for IFEO debugger hijacking
     * because they can be triggered from the lock screen or elevated context */
    static const wchar_t *targets[] = {
        L"utilman.exe", L"sethc.exe", L"osk.exe", L"magnify.exe",
        L"narrator.exe", L"displayswitch.exe", L"atbroker.exe",
        NULL
    };

    for (int i = 0; targets[i]; i++) {
        wchar_t subPath[256];
        _snwprintf(subPath, _countof(subPath),
            L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
            L"\\Image File Execution Options\\%s", targets[i]);

        HKEY  hk  = NULL;
        wchar_t debugger[MAX_PATH] = {0};
        DWORD   cb = sizeof(debugger);

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hk)
                == ERROR_SUCCESS) {
            RegQueryValueExW(hk, L"Debugger", NULL, NULL,
                             (LPBYTE)debugger, &cb);
            RegCloseKey(hk);

            if (*debugger) {
                /* A debugger is already set — existing or attacker-placed */
                Finding f;
                f.severity = SEV_CRITICAL;
                wcscpy(f.module, L"REGISTRY");
                wcsncpy(f.target, targets[i], _countof(f.target)-1);
                _snwprintf(f.reason, _countof(f.reason),
                    L"IFEO Debugger already set: %s  "
                    L"→ launching %s runs this binary instead",
                    debugger, targets[i]);
                PrintFinding(&f);
                (*total)++;
            }
        }

        /* Is the IFEO key itself writable? */
        if (IsRegKeyWritable(HKEY_LOCAL_MACHINE, subPath)) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"REGISTRY");
            wcsncpy(f.target, targets[i], _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"IFEO key for %s is WRITABLE. "
                L"Set Debugger to payload → runs when %s is launched "
                L"(lock screen → Accessibility button = SYSTEM execution)",
                targets[i], targets[i]);
            PrintFinding(&f);
            (*total)++;
        }
    }
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_Registry(void) {
    PrintHeader(L"REGISTRY PERMISSION AUDIT");

    DWORD total = 0;

    PrintInfo(L"  [1] AlwaysInstallElevated\n");
    CheckAlwaysInstallElevated(&total);

    PrintInfo(L"\n  [2] Winlogon Userinit / Shell\n");
    CheckWinlogon(&total);

    PrintInfo(L"\n  [3] AppInit_DLLs\n");
    CheckAppInitDLLs(&total);

    PrintInfo(L"\n  [4] Writable service registry keys\n");
    CheckWritableServiceKeys(&total);

    PrintInfo(L"\n  [5] IFEO Debugger (Accessibility tool targets)\n");
    CheckIFEO(&total);

    PrintInfo(L"\n  Total registry findings: %lu\n", total);
}

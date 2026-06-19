/*
 * ps_hijack.c — PowerShell Profile & Module Path DLL/Script Hijacking
 *
 * WHAT POWERSHELL LOADS AT STARTUP:
 *   PowerShell has multiple profile scripts that auto-execute on startup,
 *   and PSModulePath directories that are searched for module DLLs.
 *
 *   PROFILE SCRIPTS (in order of execution):
 *   1. $PSHOME\profile.ps1                  — All users, all hosts (System-wide)
 *   2. $PSHOME\Microsoft.PowerShell_profile.ps1  — All users, PS console only
 *   3. $HOME\Documents\PowerShell\profile.ps1    — Current user, all hosts
 *   4. $HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1  — Current user, console
 *
 *   $PSHOME = C:\Windows\System32\WindowsPowerShell\v1.0\  (or pwsh.exe location)
 *
 * ATTACK SURFACES:
 *
 *   1. SYSTEM-WIDE PROFILE ($PSHOME\profile.ps1) WRITABILITY:
 *      If writable → any PowerShell invocation (by ANY user, including SYSTEM services
 *      that call PowerShell) runs the profile script.
 *      SYSTEM services using PowerShell: Windows Defender ATP, Azure AD Connect,
 *      Azure Arc, SCCM/SCOM, many enterprise management tools.
 *
 *   2. PSModulePath DIRECTORY WRITABILITY:
 *      Env variable: PSModulePath = C:\Users\...\Documents\WindowsPowerShell\Modules;
 *                                   C:\Program Files\WindowsPowerShell\Modules;
 *                                   C:\Windows\system32\WindowsPowerShell\v1.0\Modules
 *      If ANY directory in PSModulePath is writable and appears BEFORE system modules:
 *      → Import-Module Pester (or any common module) → loads from writable dir instead
 *      → Common in enterprise: first PSModulePath entry is C:\Program Files\... (sometimes writable)
 *
 *   3. POWERSHELL ISE PROFILE:
 *      $PSHOME\Microsoft.PowerShellISE_profile.ps1 — loaded by PowerShell ISE (admin tool)
 *
 *   4. POWERSHELL v2 AVAILABILITY:
 *      If PowerShell v2 is available (powershell.exe -version 2), bypasses AMSI, CLM,
 *      ScriptBlockLogging (v2 has no AMSI). Check: Get-WindowsOptionalFeature -Online
 *      HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine\PowerShellVersion
 *
 *   5. CONSTRAINED LANGUAGE MODE (CLM) bypass surface:
 *      If CLM enabled but PSModulePath has writable dir →
 *      plant trusted-signed DLL module → loads in FullLanguage mode even under CLM
 *
 * REAL-WORLD USAGE:
 *   - PowerShell profile modification is a classic post-exploitation persistence
 *   - SCCM/ConfigMgr agents invoke PowerShell as SYSTEM → profile-based SYSTEM exec
 *   - Azure AD Connect uses PowerShell → profile hijack = DA credential theft
 *
 * REFERENCES:
 *   MITRE T1546.013 — PowerShell Profile
 *   Will Schroeder (@harmj0y): PowerShell profile persistence
 *   Ryan Watson: "PowerShell Module Path DLL Hijacking"
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Audit PowerShell profile script writability
 * --------------------------------------------------------------------- */
static void AuditPowerShellProfiles(DWORD *findings) {
    PrintInfo(L"  [1] PowerShell profile scripts:\n");

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, _countof(sysDir));

    /* Build PSHOME paths */
    wchar_t psHome[MAX_PATH * 2] = {0};
    _snwprintf(psHome, _countof(psHome),
               L"%s\\WindowsPowerShell\\v1.0", sysDir);

    /* PowerShell 7+ (pwsh) locations */
    static const wchar_t *PS7_PATHS[] = {
        L"%ProgramFiles%\\PowerShell\\7",
        L"%ProgramFiles%\\PowerShell\\6",
        NULL
    };

    static const struct {
        const wchar_t *relPath;
        const wchar_t *description;
        BOOL isAllUsers;
    } PROFILES[] = {
        { L"profile.ps1", L"All users, all hosts", TRUE },
        { L"Microsoft.PowerShell_profile.ps1", L"All users, PS console", TRUE },
        { L"Microsoft.PowerShellISE_profile.ps1", L"All users, PS ISE", TRUE },
        { NULL, NULL, FALSE }
    };

    /* System-wide profiles in PSHOME */
    for (int i = 0; PROFILES[i].relPath; i++) {
        wchar_t profilePath[MAX_PATH * 2] = {0};
        _snwprintf(profilePath, _countof(profilePath), L"%s\\%s", psHome, PROFILES[i].relPath);

        BOOL exists   = (GetFileAttributesW(profilePath) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = FALSE;

        if (exists) {
            writable = IsFileWritable(profilePath);
        } else {
            /* Even if file doesn't exist, check if DIRECTORY is writable (can create profile) */
            writable = IsDirWritable(psHome);
        }

        PrintInfo(L"    %s [%s]: %s  [%s]\n",
                  PROFILES[i].relPath,
                  PROFILES[i].description,
                  exists ? L"exists" : L"not present",
                  writable ? L"WRITABLE!" : L"not writable");

        if (writable) {
            Finding f;
            f.severity = PROFILES[i].isAllUsers ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"PSHIJACK");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] PowerShell %s profile: %s",
                exists ? L"WRITABLE FILE" : L"WRITABLE DIR (can create)",
                PROFILES[i].description, profilePath);
            _snwprintf(f.reason, _countof(f.reason),
                L"PowerShell profile '%s' (%s) is %s.\n"
                L"        This profile script executes for ALL USERS at every PowerShell start.\n"
                L"        SYSTEM services using PowerShell (SCCM, Azure AD Connect, Defender ATP)\n"
                L"        will execute this profile → code exec as SYSTEM.\n"
                L"        %s → PowerShell payload runs on next pwsh invocation by any user.",
                PROFILES[i].relPath, PROFILES[i].description,
                exists ? L"writable" : L"in writable directory (can create)",
                exists ? L"Append payload to profile" : L"Create profile.ps1 with payload");
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit PSModulePath directories
 * --------------------------------------------------------------------- */
static void AuditPSModulePath(DWORD *findings) {
    PrintInfo(L"  [2] PSModulePath directory writability (module DLL hijacking):\n");

    /* Get PSModulePath from system environment */
    wchar_t psModPath[4096] = {0};
    DWORD   cb = sizeof(psModPath);

    HKEY hEnv = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                      0, KEY_READ, &hEnv) == ERROR_SUCCESS) {
        DWORD type = 0;
        RegQueryValueExW(hEnv, L"PSModulePath", NULL, &type,
                         (LPBYTE)psModPath, &cb);
        RegCloseKey(hEnv);
    }

    /* Also get from process environment */
    if (!*psModPath) {
        GetEnvironmentVariableW(L"PSModulePath", psModPath, _countof(psModPath));
    }

    /* Default paths if not set */
    if (!*psModPath) {
        wchar_t sysDir[MAX_PATH] = {0};
        GetSystemDirectoryW(sysDir, _countof(sysDir));
        _snwprintf(psModPath, _countof(psModPath),
                   L"%s\\WindowsPowerShell\\v1.0\\Modules;"
                   L"%%ProgramFiles%%\\WindowsPowerShell\\Modules",
                   sysDir);
    }

    PrintInfo(L"    PSModulePath: %s\n\n", psModPath);

    /* Enumerate semicolon-separated paths */
    wchar_t copy[4096];
    wcsncpy(copy, psModPath, _countof(copy)-1);
    wchar_t expanded[MAX_PATH * 2] = {0};

    wchar_t *ctx = NULL;
    wchar_t *token = wcstok(copy, L";", &ctx);
    int idx = 0;

    while (token) {
        ExpandEnvironmentStringsW(token, expanded, _countof(expanded));
        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsDirWritable(expanded);

        PrintInfo(L"    [%d] %s%s\n",
                  idx++, expanded,
                  !exists ? L" [NOT FOUND]" : writable ? L" [WRITABLE!]" : L"");

        if (writable) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"PSHIJACK");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE PSModulePath] %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"PSModulePath directory is writable: %s\n"
                L"        Plant a fake module here with same name as commonly used modules.\n"
                L"        When any PowerShell session imports the module, your DLL/script loads.\n"
                L"        Common targets: Pester, PSReadLine, PowerSploit, Az, AzureAD\n"
                L"        If a SYSTEM PowerShell session imports such a module → SYSTEM exec.\n"
                L"        Example: mkdir %s\\Pester && place Pester.psm1 + Pester.dll",
                expanded, expanded);
            PrintFinding(&f);
            (*findings)++;
        }
        token = wcstok(NULL, L";", &ctx);
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check PowerShell v2 availability (AMSI bypass)
 * --------------------------------------------------------------------- */
static void AuditPowerShellV2(DWORD *findings) {
    PrintInfo(L"  [3] PowerShell v2 availability (AMSI/CLM bypass surface):\n");

    HKEY hKey = NULL;
    BOOL v2Available = FALSE;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t ver[64] = {0};
        DWORD cb = sizeof(ver), type = 0;
        RegQueryValueExW(hKey, L"PowerShellVersion", NULL, &type, (LPBYTE)ver, &cb);
        RegCloseKey(hKey);
        if (*ver) v2Available = TRUE;
        PrintInfo(L"    PowerShell v2: %s\n\n", v2Available ? L"AVAILABLE [AMSI BYPASS]" : L"not found");
    } else {
        /* Check if powershell.exe exists at all */
        wchar_t sysDir[MAX_PATH] = {0};
        GetSystemDirectoryW(sysDir, _countof(sysDir));
        wchar_t psExe[MAX_PATH * 2] = {0};
        _snwprintf(psExe, _countof(psExe), L"%s\\WindowsPowerShell\\v1.0\\powershell.exe", sysDir);
        v2Available = (GetFileAttributesW(psExe) != INVALID_FILE_ATTRIBUTES);
        PrintInfo(L"    PowerShell v2: %s\n\n", v2Available ? L"present" : L"not found");
    }

    if (v2Available) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"PSHIJACK");
        wcscpy(f.target, L"[AMSI BYPASS] PowerShell v2 available — no AMSI, no CLM enforcement");
        wcscpy(f.reason,
            L"PowerShell v2 is available on this system.\n"
            L"        PowerShell v2 has no AMSI integration and no ScriptBlockLogging.\n"
            L"        Constrained Language Mode is NOT enforced in v2.\n"
            L"        Bypass: powershell.exe -version 2 -command <malicious script>\n"
            L"        Can be used to bypass AppLocker script rules if they don't block v2.\n"
            L"        Disable v2: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root");
        PrintFinding(&f);
        (*findings)++;
    }
}

void Module_PSHijack(void) {
    PrintHeader(L"POWERSHELL HIJACKING  [T1546.013 — Profile scripts + PSModulePath DLL hijacking]");

    PrintInfo(
        L"  System-wide PowerShell profiles run for ALL users including SYSTEM services.\n"
        L"  SCCM, Azure AD Connect, Defender ATP invoke PowerShell as SYSTEM.\n"
        L"  PSModulePath writable dir → module DLL hijacking on Import-Module.\n\n");

    DWORD findings = 0;
    AuditPowerShellProfiles(&findings);
    AuditPSModulePath(&findings);
    AuditPowerShellV2(&findings);

    if (findings == 0)
        PrintInfo(L"  No PowerShell hijacking surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  PROFILE PAYLOAD EXAMPLE:\n"
            L"    echo 'Start-Process cmd.exe -ArgumentList \"/c whoami >> C:\\tmp\\out.txt\"' >> profile.ps1\n"
            L"    [Next PowerShell invocation by ANY user executes this]\n\n"
            L"  MODULE HIJACKING:\n"
            L"    mkdir C:\\path\\writable\\Modules\\Pester\\\n"
            L"    # Create minimal Pester.psm1 + rootModule that loads your DLL\n"
            L"    Import-Module Pester  # executed by SCCM/automation → SYSTEM\n");
    }
}

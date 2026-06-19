/*
 * sysvol_scripts.c — Domain SYSVOL/NETLOGON Script Writability & GPO Script Audit
 *
 * WHAT SYSVOL/NETLOGON ARE:
 *   On Active Directory domain members, two UNC paths are accessible:
 *   \\{domain}\SYSVOL\{domain}\  — Group Policy storage (replicated between DCs)
 *   \\{domain}\NETLOGON\         — Logon scripts location (legacy, still used)
 *
 *   GPO logon scripts (configured via Group Policy) are stored in SYSVOL and
 *   executed at user logon in the user's context. If a domain admin/user logon
 *   script is writable, it executes as the privileged user at their next logon.
 *
 * ATTACK SURFACES:
 *
 *   1. WRITABLE SYSVOL/NETLOGON LOGON SCRIPTS:
 *      If \\{domain}\SYSVOL\...\Scripts\Logon\*.bat/cmd/ps1 is writable:
 *      → Script executes as domain user (or domain admin if their GPO uses it)
 *      → Domain admin logon = domain privilege escalation
 *
 *   2. LOCAL LOGON SCRIPTS IN REGISTRY:
 *      HKCU\Environment\UserInitMprLogonScript
 *      Executes at logon for current user (persistence, not LPE for own account)
 *      But if set in HKLM for another user → LPE
 *
 *   3. GPO SCRIPT REGISTRY:
 *      HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\
 *      HKCU\SOFTWARE\Policies\Microsoft\Windows\System\Scripts\
 *      Startup/Shutdown scripts (HKLM — runs as SYSTEM)
 *      Logon/Logoff scripts (HKCU — runs as user)
 *      If script paths are writable → code exec
 *
 *   4. DOMAIN CONTROLLER ENUMERATION:
 *      If domain member: enumerate DCs, discover domain name, check SYSVOL access.
 *
 *   5. NET LOGON SCRIPT VALUE:
 *      Active Directory user account attribute "scriptPath" specifies a logon script.
 *      If the script path (in NETLOGON share) is writable → exec as that user.
 *
 * REAL-WORLD CASES:
 *   - BloodHound finding: WritableSYSVOL — most common domain privilege escalation
 *   - CVE-2021-42287/42278 (noPac): domain escalation via SYSVOL GPO manipulation
 *   - Red team engagements: SYSVOL writable scripts → immediate DA in many orgs
 *
 * REFERENCES:
 *   harmj0y: "A Red Teamer's Guide to GPOs and OUs"
 *   BloodHound: SYSVOL writability checks
 *   PowerView: Find-DomainGPO, Get-DomainGPOLocalGroup
 *   MITRE T1484.001 — Group Policy Modification
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Get current domain name via USERDNSDOMAIN or netbios
 * --------------------------------------------------------------------- */
static BOOL GetDomainName(wchar_t *domainOut, DWORD cchDomain) {
    /* Try USERDNSDOMAIN environment variable */
    if (GetEnvironmentVariableW(L"USERDNSDOMAIN", domainOut, cchDomain) > 0)
        return TRUE;

    /* Try USERDOMAIN */
    wchar_t netbios[256] = {0};
    if (GetEnvironmentVariableW(L"USERDOMAIN", netbios, _countof(netbios)) > 0) {
        /* Check if it's different from computername (if so, it's a domain) */
        wchar_t computer[256] = {0};
        DWORD cb = _countof(computer);
        GetComputerNameW(computer, &cb);
        if (_wcsicmp(netbios, computer) != 0) {
            wcsncpy(domainOut, netbios, cchDomain-1);
            return TRUE;
        }
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Test writability of a UNC path
 * --------------------------------------------------------------------- */
static BOOL IsUNCPathWritable(LPCWSTR uncPath) {
    /* Try to create a temp file in the UNC path */
    wchar_t testFile[MAX_PATH * 2] = {0};
    _snwprintf(testFile, _countof(testFile), L"%s\\ferrum_test_%lu.tmp",
               uncPath, GetCurrentProcessId());

    HANDLE h = CreateFileW(testFile, GENERIC_WRITE, 0, NULL,
                           CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
                           NULL);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Audit SYSVOL script paths
 * --------------------------------------------------------------------- */
static void AuditSYSVOLScripts(DWORD *findings) {
    PrintInfo(L"  [1] SYSVOL/NETLOGON logon script writability:\n");

    wchar_t domain[256] = {0};
    if (!GetDomainName(domain, _countof(domain))) {
        PrintInfo(L"    Not domain-joined (USERDNSDOMAIN not set)\n\n");
        return;
    }

    PrintInfo(L"    Domain: %s\n", domain);

    static const wchar_t *SCRIPT_SUBPATHS[] = {
        L"Scripts\\Logon",
        L"Scripts\\Logoff",
        L"Scripts\\Startup",
        L"Scripts\\Shutdown",
        NULL
    };

    wchar_t sysvolBase[512];
    wchar_t netlogon[512];
    _snwprintf(sysvolBase, _countof(sysvolBase), L"\\\\%s\\SYSVOL\\%s\\", domain, domain);
    _snwprintf(netlogon, _countof(netlogon), L"\\\\%s\\NETLOGON\\", domain);

    /* Test basic SYSVOL access */
    BOOL sysvolAccessible = (GetFileAttributesW(sysvolBase) != INVALID_FILE_ATTRIBUTES);
    BOOL netlogonAccessible = (GetFileAttributesW(netlogon) != INVALID_FILE_ATTRIBUTES);

    PrintInfo(L"    SYSVOL base:   %s [%s]\n", sysvolBase,
              sysvolAccessible ? L"accessible" : L"not accessible");
    PrintInfo(L"    NETLOGON:      %s [%s]\n", netlogon,
              netlogonAccessible ? L"accessible" : L"not accessible");

    /* Check NETLOGON writability */
    if (netlogonAccessible) {
        BOOL nwrit = IsUNCPathWritable(netlogon);
        PrintInfo(L"    NETLOGON writable: %s\n", nwrit ? L"YES [CRITICAL!]" : L"No");
        if (nwrit) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"SYSVOL");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE NETLOGON] %s", netlogon);
            wcscpy(f.reason,
                L"Domain NETLOGON share is WRITABLE by current user!\n"
                L"        NETLOGON hosts logon scripts for domain user accounts.\n"
                L"        Place malicious script here → executes as ANY user who has this script configured.\n"
                L"        If domain admin has a logon script → DA compromise.\n"
                L"        Enumerate scripts with: net use Z: \\\\domain\\NETLOGON then dir Z:\\\n"
                L"        BloodHound query: MATCH (n:GPO) WHERE n.gpcfilesyspath CONTAINS 'NETLOGON'");
            PrintFinding(&f);
            (*findings)++;
        }
    }

    /* Enumerate GPO directories in SYSVOL */
    if (sysvolAccessible) {
        wchar_t policiesPath[512];
        _snwprintf(policiesPath, _countof(policiesPath), L"%sPolicies", sysvolBase);

        WIN32_FIND_DATAW ffd = {0};
        wchar_t searchPattern[512];
        _snwprintf(searchPattern, _countof(searchPattern), L"%s\\*", policiesPath);

        HANDLE hFind = FindFirstFileW(searchPattern, &ffd);
        if (hFind == INVALID_HANDLE_VALUE) {
            PrintInfo(L"    Cannot enumerate SYSVOL\\Policies\n\n");
            return;
        }

        DWORD gpoCount = 0;
        do {
            if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
                && ffd.cFileName[0] == L'{') {
                gpoCount++;

                /* Check script paths within this GPO */
                for (int si = 0; SCRIPT_SUBPATHS[si]; si++) {
                    wchar_t scriptDir[MAX_PATH * 2];
                    _snwprintf(scriptDir, _countof(scriptDir),
                               L"%s\\%s\\%s", policiesPath, ffd.cFileName, SCRIPT_SUBPATHS[si]);

                    if (GetFileAttributesW(scriptDir) == INVALID_FILE_ATTRIBUTES) continue;

                    BOOL writable = IsUNCPathWritable(scriptDir);
                    if (writable) {
                        PrintInfo(L"    [!] WRITABLE: %s\n", scriptDir);
                        Finding f;
                        f.severity = WcsContainsI(SCRIPT_SUBPATHS[si], L"Startup") ?
                                     SEV_CRITICAL : SEV_HIGH;
                        wcscpy(f.module, L"SYSVOL");
                        _snwprintf(f.target, _countof(f.target),
                            L"[WRITABLE GPO SCRIPTS] %s", scriptDir);
                        _snwprintf(f.reason, _countof(f.reason),
                            L"GPO script directory is writable: %s\n"
                            L"        Scripts here run for all users/machines targeted by this GPO.\n"
                            L"        %s scripts run as: %s\n"
                            L"        Plant script → executes at next logon for all affected accounts.",
                            scriptDir, SCRIPT_SUBPATHS[si],
                            WcsContainsI(SCRIPT_SUBPATHS[si], L"Startup") ? L"SYSTEM" :
                            WcsContainsI(SCRIPT_SUBPATHS[si], L"Logon")   ? L"logged-on user" :
                                                                              L"SYSTEM/user");
                        PrintFinding(&f);
                        (*findings)++;
                    }
                }
            }
        } while (FindNextFileW(hFind, &ffd));
        FindClose(hFind);
        PrintInfo(L"    GPO directories enumerated: %lu\n", gpoCount);
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit local GPO script registry paths
 * --------------------------------------------------------------------- */
static void AuditGPOScriptRegistry(DWORD *findings) {
    PrintInfo(L"  [2] Local GPO script registry paths:\n");

    static const struct {
        HKEY        root;
        const wchar_t *rootName;
        const wchar_t *keyPath;
        const wchar_t *description;
        BOOL         isSystem;
    } GPO_KEYS[] = {
        { HKEY_LOCAL_MACHINE, L"HKLM",
          L"SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Startup",
          L"Machine Startup scripts", TRUE },
        { HKEY_LOCAL_MACHINE, L"HKLM",
          L"SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Shutdown",
          L"Machine Shutdown scripts", TRUE },
        { HKEY_CURRENT_USER, L"HKCU",
          L"SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logon",
          L"User Logon scripts", FALSE },
        { HKEY_CURRENT_USER, L"HKCU",
          L"SOFTWARE\\Policies\\Microsoft\\Windows\\System\\Scripts\\Logoff",
          L"User Logoff scripts", FALSE },
        { 0, NULL, NULL, NULL, FALSE }
    };

    for (int i = 0; GPO_KEYS[i].rootName; i++) {
        HKEY hRoot = NULL;
        if (RegOpenKeyExW(GPO_KEYS[i].root, GPO_KEYS[i].keyPath,
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS)
            continue;

        DWORD idx = 0, count = 0;
        wchar_t scriptIdx[32];
        DWORD   scriptIdxCch;

        while (TRUE) {
            scriptIdxCch = _countof(scriptIdx);
            LONG r = RegEnumKeyExW(hRoot, idx++, scriptIdx, &scriptIdxCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            count++;

            wchar_t scriptKeyPath[512];
            _snwprintf(scriptKeyPath, _countof(scriptKeyPath),
                       L"%s\\%s", GPO_KEYS[i].keyPath, scriptIdx);

            HKEY hScript = NULL;
            if (RegOpenKeyExW(GPO_KEYS[i].root, scriptKeyPath, 0, KEY_READ, &hScript)
                    != ERROR_SUCCESS) continue;

            wchar_t scriptPath[MAX_PATH * 2] = {0};
            DWORD   cb = sizeof(scriptPath), type = 0;
            RegQueryValueExW(hScript, L"Script", NULL, &type, (LPBYTE)scriptPath, &cb);
            RegCloseKey(hScript);

            if (!*scriptPath) continue;
            PrintInfo(L"    [%s] %s #%s: %s\n",
                      GPO_KEYS[i].rootName, GPO_KEYS[i].description,
                      scriptIdx, scriptPath);

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(scriptPath, expanded, _countof(expanded));
            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);

            if (writable || !exists) {
                Finding f;
                f.severity = (GPO_KEYS[i].isSystem && writable) ? SEV_CRITICAL : SEV_HIGH;
                wcscpy(f.module, L"SYSVOL");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] GPO Script [%s]: %s",
                    writable ? L"WRITABLE" : L"MISSING", GPO_KEYS[i].description, expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"GPO script '%s' (%s) is %s: %s\n"
                    L"        This script runs as: %s\n"
                    L"        %s → code exec at next logon/startup.",
                    scriptPath, GPO_KEYS[i].description,
                    writable ? L"WRITABLE" : L"MISSING", expanded,
                    GPO_KEYS[i].isSystem ? L"SYSTEM" : L"current user",
                    writable ? L"Replace script with payload" : L"Plant script at path");
                PrintFinding(&f);
                (*findings)++;
            }
        }
        RegCloseKey(hRoot);
        if (count > 0)
            PrintInfo(L"    %s scripts found: %lu\n", GPO_KEYS[i].description, count);
    }

    /* Check UserInitMprLogonScript */
    PrintInfo(L"\n  [3] UserInitMprLogonScript (legacy per-user logon script):\n");
    HKEY hEnv = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_READ, &hEnv) == ERROR_SUCCESS) {
        wchar_t script[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(script), type = 0;
        RegQueryValueExW(hEnv, L"UserInitMprLogonScript", NULL, &type, (LPBYTE)script, &cb);
        RegCloseKey(hEnv);
        if (*script) {
            PrintInfo(L"    UserInitMprLogonScript = %s\n", script);
            BOOL exists = (GetFileAttributesW(script) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(script);
            if (!writable && !exists)
                PrintInfo(L"    [!] Script path does not exist — plant payload there\n");
        } else {
            PrintInfo(L"    (not set)\n");
        }
    }
    PrintInfo(L"\n");
}

void Module_SYSVOLScripts(void) {
    PrintHeader(L"SYSVOL/GPO SCRIPTS  [T1484.001 — Domain SYSVOL write + GPO logon script hijacking]");

    PrintInfo(
        L"  Domain SYSVOL scripts execute at logon for ALL affected domain accounts.\n"
        L"  Writable NETLOGON/SYSVOL = domain privilege escalation if admin has logon script.\n"
        L"  Machine Startup scripts (HKLM GPO) run as SYSTEM at boot.\n\n");

    DWORD findings = 0;
    AuditSYSVOLScripts(&findings);
    AuditGPOScriptRegistry(&findings);

    if (findings == 0)
        PrintInfo(L"  No SYSVOL/GPO script hijacking surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  ENUMERATION (PowerView):\n"
            L"    Get-DomainGPO | Select-Object displayname,gpcfilesyspath\n"
            L"    Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.ObjectType -eq 'GroupPolicy'}\n"
            L"    dir \\\\domain\\SYSVOL\\domain\\Policies -Recurse | ? {$_.Name -like '*.bat'}\n");
    }
}

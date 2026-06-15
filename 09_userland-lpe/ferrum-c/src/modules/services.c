/*
 * services.c — Windows Service Misconfiguration Detector
 *
 * Checks:
 *   1. Unquoted service image paths containing spaces
 *   2. Service binary in a user-writable directory
 *   3. Service binary file itself is writable by current user
 *   4. Weak service DACL (SERVICE_CHANGE_CONFIG granted to non-admin)
 *   5. ServiceDll (svchost-hosted) in writable location
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Returns TRUE if the path is unquoted AND contains a space.
 * This is the raw ImagePath as stored in the registry.
 * --------------------------------------------------------------------- */
static BOOL IsUnquotedWithSpaces(LPCWSTR path) {
    if (!path || *path == L'\0') return FALSE;
    if (*path == L'"') return FALSE;   /* already quoted */
    return (wcschr(path, L' ') != NULL);
}

/* -----------------------------------------------------------------------
 * Check the service DACL for SERVICE_CHANGE_CONFIG granted to
 * unprivileged SIDs (Authenticated Users, Everyone, BUILTIN\Users).
 * Returns TRUE if such an ACE is found.
 * --------------------------------------------------------------------- */
static BOOL ServiceDACLIsWeak(SC_HANDLE hSvc) {
    DWORD needed = 0;
    QueryServiceObjectSecurity(hSvc, DACL_SECURITY_INFORMATION,
                               NULL, 0, &needed);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return FALSE;

    PSECURITY_DESCRIPTOR pSD =
        (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!pSD) return FALSE;

    BOOL weak = FALSE;
    if (!QueryServiceObjectSecurity(hSvc, DACL_SECURITY_INFORMATION,
                                    pSD, needed, &needed))
        goto done;

    BOOL    hasDacl = FALSE, defaulted = FALSE;
    PACL    pDacl   = NULL;
    if (!GetSecurityDescriptorDacl(pSD, &hasDacl, &pDacl, &defaulted) ||
        !hasDacl || !pDacl)
        goto done;

    /* Well-known SIDs we consider unprivileged */
    PSID sidBU = NULL, sidWD = NULL, sidAU = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth   = SECURITY_NT_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY worldAuth= SECURITY_WORLD_SID_AUTHORITY;

    AllocateAndInitializeSid(&ntAuth,   2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS,
        0,0,0,0,0,0, &sidBU);                    /* BUILTIN\Users       */
    AllocateAndInitializeSid(&worldAuth, 1,
        SECURITY_WORLD_RID, 0,0,0,0,0,0,0, &sidWD); /* Everyone         */
    AllocateAndInitializeSid(&ntAuth,   1,
        SECURITY_AUTHENTICATED_USER_RID, 0,0,0,0,0,0,0, &sidAU); /* Auth Users */

    ACL_SIZE_INFORMATION aclInfo = {0};
    GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation);

    for (DWORD i = 0; i < aclInfo.AceCount && !weak; i++) {
        ACCESS_ALLOWED_ACE *pAce = NULL;
        if (!GetAce(pDacl, i, (LPVOID *)&pAce)) continue;
        if (pAce->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

        PSID aceSid = (PSID)&pAce->SidStart;
        BOOL isUnpriv = (sidBU && EqualSid(aceSid, sidBU)) ||
                        (sidWD && EqualSid(aceSid, sidWD)) ||
                        (sidAU && EqualSid(aceSid, sidAU));
        if (!isUnpriv) continue;

        /* Does this ACE grant SERVICE_CHANGE_CONFIG ? */
        if (pAce->Mask & SERVICE_CHANGE_CONFIG)
            weak = TRUE;
    }

    if (sidBU) FreeSid(sidBU);
    if (sidWD) FreeSid(sidWD);
    if (sidAU) FreeSid(sidAU);

done:
    HeapFree(GetProcessHeap(), 0, pSD);
    return weak;
}

/* -----------------------------------------------------------------------
 * For svchost services: read ServiceDll from Parameters subkey.
 * Returns TRUE and fills dllPath on success.
 * --------------------------------------------------------------------- */
static BOOL GetServiceDll(LPCWSTR svcName, LPWSTR dllPath, DWORD pathCch) {
    wchar_t regPath[512];
    _snwprintf(regPath, _countof(regPath),
        L"SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", svcName);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS)
        return FALSE;

    DWORD type = 0, cb = pathCch * sizeof(wchar_t);
    BOOL ok = (RegQueryValueExW(hKey, L"ServiceDll", NULL, &type,
                                (LPBYTE)dllPath, &cb) == ERROR_SUCCESS);
    RegCloseKey(hKey);

    if (ok) {
        /* expand %SystemRoot% etc. */
        wchar_t expanded[MAX_PATH * 2];
        ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));
        wcsncpy(dllPath, expanded, pathCch - 1);
        dllPath[pathCch - 1] = L'\0';
    }
    return ok;
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_Services(void) {
    PrintHeader(L"SERVICE MISCONFIGURATION");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL,
        SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) {
        PrintInfo(L"  [!] Cannot open SCM (error %lu)\n", GetLastError());
        return;
    }

    DWORD needed = 0, count = 0, resumeHandle = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &needed, &count, &resumeHandle, NULL);

    if (GetLastError() != ERROR_MORE_DATA) {
        CloseServiceHandle(hSCM);
        return;
    }

    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!buf) { CloseServiceHandle(hSCM); return; }

    resumeHandle = 0;
    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL,
            buf, needed, &needed, &count, &resumeHandle, NULL)) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseServiceHandle(hSCM);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSW *svcs =
        (ENUM_SERVICE_STATUS_PROCESSW *)buf;
    DWORD findings = 0;

    for (DWORD i = 0; i < count; i++) {
        LPCWSTR svcName = svcs[i].lpServiceName;

        SC_HANDLE hSvc = OpenServiceW(hSCM, svcName,
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL);
        if (!hSvc) continue;

        /* -- QueryServiceConfig -- */
        DWORD cfgNeeded = 0;
        QueryServiceConfigW(hSvc, NULL, 0, &cfgNeeded);
        QUERY_SERVICE_CONFIGW *pCfg =
            (QUERY_SERVICE_CONFIGW *)HeapAlloc(GetProcessHeap(), 0, cfgNeeded);
        BOOL gotCfg = pCfg &&
            QueryServiceConfigW(hSvc, pCfg, cfgNeeded, &cfgNeeded);

        if (gotCfg && pCfg->lpBinaryPathName) {
            LPCWSTR rawPath = pCfg->lpBinaryPathName;
            wchar_t exePath[MAX_PATH * 2] = {0};
            ExtractExePath(rawPath, exePath, _countof(exePath));

            Finding f;
            wcscpy(f.module, L"SERVICES");

            /* ---- Check 1: Unquoted path ---- */
            /* Check exePath (exe portion only), not rawPath — spaces in
             * arguments like "svchost.exe -k LocalService" are not exploitable. */
            if (*exePath && IsUnquotedWithSpaces(exePath)) {
                f.severity = SEV_HIGH;
                wcsncpy(f.target, svcName, _countof(f.target)-1);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Unquoted service path with spaces: %s", rawPath);
                PrintFinding(&f);
                findings++;
            }

            /* ---- Check 2: Binary in user-writable location ---- */
            if (*exePath && IsUserWritablePath(exePath)) {
                f.severity = SEV_HIGH;
                wcsncpy(f.target, svcName, _countof(f.target)-1);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Service binary in user-writable location: %s", exePath);
                PrintFinding(&f);
                findings++;
            }

            /* ---- Check 3: Binary file itself is writable ---- */
            if (*exePath && GetFileAttributesW(exePath) != INVALID_FILE_ATTRIBUTES
                && IsFileWritable(exePath))
            {
                f.severity = SEV_CRITICAL;
                wcsncpy(f.target, svcName, _countof(f.target)-1);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Service binary is WRITABLE by current user: %s", exePath);
                PrintFinding(&f);
                findings++;
            }
        }

        /* ---- Check 4: Weak service DACL ---- */
        if (ServiceDACLIsWeak(hSvc)) {
            Finding f;
            wcscpy(f.module, L"SERVICES");
            f.severity = SEV_CRITICAL;
            wcsncpy(f.target, svcName, _countof(f.target)-1);
            wcscpy(f.reason,
                L"SERVICE_CHANGE_CONFIG granted to unprivileged SID (BUILTIN\\Users / Everyone)");
            PrintFinding(&f);
            findings++;
        }

        /* ---- Check 5: ServiceDll writable (svchost services) ---- */
        if (gotCfg && pCfg->dwServiceType & SERVICE_WIN32_SHARE_PROCESS) {
            wchar_t dllPath[MAX_PATH * 2] = {0};
            if (GetServiceDll(svcName, dllPath, _countof(dllPath)) && *dllPath) {
                if (IsUserWritablePath(dllPath) || IsFileWritable(dllPath)) {
                    Finding f;
                    wcscpy(f.module, L"SERVICES");
                    f.severity = IsFileWritable(dllPath) ? SEV_CRITICAL : SEV_HIGH;
                    wcsncpy(f.target, svcName, _countof(f.target)-1);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"ServiceDll is writable or in user-writable path: %s", dllPath);
                    PrintFinding(&f);
                    findings++;
                }
            }
        }

        if (pCfg) HeapFree(GetProcessHeap(), 0, pCfg);
        CloseServiceHandle(hSvc);
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseServiceHandle(hSCM);

    if (findings == 0)
        PrintInfo(L"  No service misconfigurations found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

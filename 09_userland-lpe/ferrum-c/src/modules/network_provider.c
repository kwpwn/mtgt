/*
 * network_provider.c — Windows Network Provider DLL Audit
 *
 * ATTACK SURFACE — HIGH:
 *   Windows Multiple Provider Router (MPR / mpr.dll) maintains a list of
 *   network providers. These DLLs are loaded when any process calls:
 *     WNetOpenEnum, WNetEnumResource, WNetGetConnection,
 *     WNetAddConnection2, WNetCancelConnection2, etc.
 *
 *   Registry:
 *     HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order\
 *         ProviderOrder = "RDPNP,LanmanWorkstation,webclient" (comma-separated)
 *
 *     For each provider name:
 *     HKLM\SYSTEM\CurrentControlSet\Services\<ProviderName>\NetworkProvider\
 *         ProviderPath = "C:\Windows\System32\ntlanman.dll"
 *         Name         = "Microsoft Windows Network"
 *
 *   WHO CALLS WNet APIs:
 *     - Explorer.exe (when browsing network shares) — Medium integrity
 *     - System processes doing drive mapping
 *     - Logon scripts (SYSTEM context on domain machines)
 *     - Any process calling WNet* functions
 *     - IMPORTANTLY: winlogon.exe / net.exe (potentially SYSTEM)
 *
 *   NETWORK PROVIDER CREDENTIAL INTERCEPTION:
 *     A malicious network provider DLL can intercept ALL credentials passed
 *     through WNetAddConnection2 / NPLogonNotify:
 *       DWORD WINAPI NPLogonNotify(LPLOGENTRY lpLogEntry,
 *           LPCWSTR lpAuthentInfoType, LPVOID lpAuthentInfo, ...);
 *     This receives plaintext credentials for ALL network authentications!
 *     Used by malware (e.g., Mimikatz network provider module) for cred harvest.
 *
 * LPE ANGLE:
 *   If ProviderPath DLL is writable by current user:
 *     → Replace DLL → any process calling WNet* loads attacker code
 *     → If that process is elevated (winlogon, SYSTEM script) → LPE
 *
 *   If registry key (ProviderPath value) is writable:
 *     → Change ProviderPath to point to attacker DLL
 *     → Less visible than changing DLL file itself
 *
 * MINIMUM DLL EXPORTS:
 *   DWORD WINAPI NPGetCaps(DWORD nIndex);       (required)
 *   DWORD WINAPI NPOpenEnum(...);                (if supporting enumeration)
 *   DWORD WINAPI NPLogonNotify(...);             (for credential capture)
 *
 * REFERENCES:
 *   Mimikatz misc::memssp / net provider module
 *   MITRE ATT&CK: T1556.002 (Modify Authentication Process: Network Provider)
 */

#include "../common.h"

#define NP_ORDER_KEY \
    L"SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order"
#define NP_SERVICES_PREFIX \
    L"SYSTEM\\CurrentControlSet\\Services\\"
#define NP_SUBKEY \
    L"\\NetworkProvider"

/* -----------------------------------------------------------------------
 * Audit one network provider
 * --------------------------------------------------------------------- */
static void AuditProvider(LPCWSTR providerName, DWORD *findings) {
    /* Build the registry path for the provider's NetworkProvider key */
    wchar_t keyPath[512];
    _snwprintf(keyPath, _countof(keyPath), L"%s%s%s",
               NP_SERVICES_PREFIX, providerName, NP_SUBKEY);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [skip] %s — key not found\n", providerName);
        return;
    }

    wchar_t provPath[MAX_PATH * 2] = {0};
    wchar_t provFriendlyName[256]  = {0};
    DWORD   cb, type;

    cb = sizeof(provPath);
    RegQueryValueExW(hKey, L"ProviderPath", NULL, &type, (LPBYTE)provPath, &cb);
    cb = sizeof(provFriendlyName);
    RegQueryValueExW(hKey, L"Name", NULL, &type, (LPBYTE)provFriendlyName, &cb);

    /* Check if ProviderPath key value is writable (can redirect the path) */
    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, keyPath);

    RegCloseKey(hKey);

    wchar_t label[256];
    _snwprintf(label, _countof(label), L"%s (%s)",
               providerName,
               *provFriendlyName ? provFriendlyName : L"no friendly name");

    PrintInfo(L"  Provider: %-30s → %s\n", label, *provPath ? provPath : L"(no path)");

    if (!*provPath) {
        if (keyWritable) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"NET_PROVIDER");
            _snwprintf(f.target, _countof(f.target),
                L"[NO PATH + KEY WRITABLE] %s", label);
            _snwprintf(f.reason, _countof(f.reason),
                L"Network provider has no ProviderPath AND the registry key is writable. "
                L"Set ProviderPath to attacker DLL → loaded by all WNet callers. "
                L"Key: HKLM\\%s", keyPath);
            PrintFinding(&f);
            (*findings)++;
        }
        return;
    }

    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(provPath, expanded, _countof(expanded));

    BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(expanded);
    BOOL inUser   = IsUserWritablePath(expanded);

    wchar_t dllDir[MAX_PATH * 2] = {0};
    wcsncpy(dllDir, expanded, _countof(dllDir) - 1);
    wchar_t *sl = wcsrchr(dllDir, L'\\');
    BOOL dirWritable = FALSE;
    if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(dllDir); }

    Finding f;
    wcscpy(f.module, L"NET_PROVIDER");

    if (writable) {
        f.severity = SEV_CRITICAL;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DLL] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Network provider DLL is WRITABLE! "
            L"Loaded by any process calling WNetOpenEnum/WNetAddConnection2. "
            L"Implement NPLogonNotify() to capture ALL plaintext network credentials. "
            L"If loaded by elevated process → LPE. "
            L"DLL: %s  |  Required export: NPGetCaps(DWORD nIndex)",
            expanded);
        PrintFinding(&f);
        (*findings)++;
    } else if (!exists) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[MISSING DLL] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Network provider DLL does not exist: %s\n"
            L"        Dir writable: %s — plant DLL to intercept network auth.",
            expanded, dirWritable ? L"YES" : L"No");
        PrintFinding(&f);
        (*findings)++;
    } else if (dirWritable && !WcsContainsI(expanded, L"system32")) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DIR] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Network provider DLL directory is user-writable (not System32). "
            L"DLL planting possible. DLL: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    } else if (inUser) {
        f.severity = SEV_MEDIUM;
        _snwprintf(f.target, _countof(f.target),
            L"[USER-PATH] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Network provider DLL in user-accessible path. "
            L"Verify ACL. DLL: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    }

    if (keyWritable) {
        Finding fk;
        fk.severity = SEV_HIGH;
        wcscpy(fk.module, L"NET_PROVIDER");
        _snwprintf(fk.target, _countof(fk.target),
            L"[KEY WRITABLE] %s NetworkProvider registry", label);
        _snwprintf(fk.reason, _countof(fk.reason),
            L"User can write ProviderPath registry value. "
            L"Change to attacker DLL path without touching the file. "
            L"Key: HKLM\\%s", keyPath);
        PrintFinding(&fk);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_NetworkProvider(void) {
    PrintHeader(L"NETWORK PROVIDER DLL AUDIT  [Credential intercept + LPE surface]");

    PrintInfo(
        L"  Network provider DLLs load in ANY process calling WNet* APIs.\n"
        L"  NPLogonNotify() receives PLAINTEXT credentials for all net auth.\n"
        L"  Writable DLL = credential harvest OR LPE if elevated caller.\n\n");

    /* Read provider order */
    wchar_t order[1024] = {0};
    DWORD   cb = sizeof(order), type = 0;
    HKEY    hOrder = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NP_ORDER_KEY, 0, KEY_READ, &hOrder)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open NetworkProvider\\Order key\n");
        return;
    }

    RegQueryValueExW(hOrder, L"ProviderOrder", NULL, &type,
                     (LPBYTE)order, &cb);
    RegCloseKey(hOrder);

    if (!*order) {
        PrintInfo(L"  No provider order found.\n");
        return;
    }

    PrintInfo(L"  Provider order: %s\n\n", order);

    /* Parse comma-separated list and audit each provider */
    DWORD findings = 0;
    wchar_t buf[1024];
    wcsncpy(buf, order, _countof(buf) - 1);
    wchar_t *tok = buf, *comma;

    do {
        comma = wcschr(tok, L',');
        if (comma) *comma = L'\0';

        /* Trim spaces */
        while (*tok == L' ') tok++;
        wchar_t *end = tok + wcslen(tok) - 1;
        while (end > tok && *end == L' ') { *end = L'\0'; end--; }

        if (*tok) AuditProvider(tok, &findings);

        tok = comma ? comma + 1 : NULL;
    } while (tok);

    PrintInfo(L"\n");
    if (findings == 0)
        PrintInfo(L"  No network provider DLL issues found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  CREDENTIAL CAPTURE (even without LPE):\n"
            L"    Implement NPLogonNotify in your provider DLL:\n"
            L"      DWORD WINAPI NPLogonNotify(\n"
            L"        LPLOGENTRY lpLogEntry, LPCWSTR lpAuthentInfoType,\n"
            L"        LPVOID lpAuthentInfo, LPCWSTR lpPreviousAuthentInfoType,\n"
            L"        LPVOID lpPreviousAuthentInfo, LPWSTR lpStationName,\n"
            L"        LPVOID StationHandle, LPWSTR *lpLogonScript) {\n"
            L"        // lpAuthentInfo → MSV1_0_INTERACTIVE_LOGON with user/pass\n"
            L"        return WN_SUCCESS;\n"
            L"      }\n"
            L"    MITRE: T1556.002 / similar to Mimikatz misc::memssp\n");
    }
}

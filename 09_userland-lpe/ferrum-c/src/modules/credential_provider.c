/*
 * credential_provider.c — Windows Credential Provider DLL Audit
 *
 * ATTACK SURFACE — HIGH:
 *   Windows Credential Providers are COM objects that implement the login UI.
 *   They are registered under:
 *     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Authentication\
 *         Credential Providers\{GUID}\
 *           (default) = CLSID of the credential provider COM object
 *
 *   These DLLs are loaded by:
 *     logonui.exe    — runs at WINLOGON integrity, heavily protected
 *     winlogon.exe   — the login manager (SYSTEM)
 *     lsass.exe      — for pre-logon scenario
 *     credui.dll     — when UAC credential prompt appears
 *     explorer.exe   — when unlocking screen (elevated)
 *
 *   LOADING CONTEXT:
 *     The credential provider DLL is loaded in-process by logonui.exe which
 *     runs in session 0 with SYSTEM privileges. This is the highest-value
 *     DLL load target in Windows outside of kernel drivers.
 *
 *   LPE ANGLE:
 *     1. Find a credential provider CLSID whose InprocServer32 DLL is in a
 *        user-writable location.
 *     2. Replace the DLL (or plant if missing).
 *     3. Trigger: Lock the screen (Win+L) → logonui.exe activates providers
 *        → loads your DLL → DllMain runs at SYSTEM/WINLOGON integrity.
 *     4. Alternatively: UAC credential prompt → credui.dll loads providers
 *        in the requesting process's context.
 *
 * REQUIRED DLL EXPORTS:
 *   Must implement ICredentialProvider COM interface. Minimal implementation:
 *     DllMain (payload here)
 *     DllGetClassObject (return E_NOTIMPL — logonui will skip this provider)
 *
 * CHECKS:
 *   1. Enumerate all registered credential provider CLSIDs
 *   2. Look up each CLSID's InprocServer32 DLL path in HKCR (or HKLM\Classes)
 *   3. Check DLL writability, missing DLL, writable parent directory
 *   4. Check if the credential provider registry key itself is writable
 *      (could change CLSID to point to attacker's COM object)
 *
 * THIRD-PARTY RISK:
 *   Biometric vendors (fingerprint, face recognition), smart card vendors,
 *   remote desktop credential providers (RDWeb, Citrix), and VPN clients
 *   frequently register credential providers. These are rarely audited.
 */

#include "../common.h"

#define CRED_PROVIDERS_KEY \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Authentication\\Credential Providers"

/* -----------------------------------------------------------------------
 * Resolve a credential provider CLSID to its InprocServer32 DLL path.
 * Returns TRUE if found, FALSE otherwise.
 * --------------------------------------------------------------------- */
static BOOL ResolveProviderDLL(LPCWSTR clsid, LPWSTR dllOut, DWORD dllCch) {
    /* Try HKLM\SOFTWARE\Classes\CLSID first, then HKCU\Software\Classes\CLSID */
    static const struct { HKEY root; LPCWSTR prefix; } roots[] = {
        { HKEY_LOCAL_MACHINE,  L"SOFTWARE\\Classes\\CLSID\\" },
        { HKEY_CLASSES_ROOT,   L"CLSID\\"                    },
        { HKEY_CURRENT_USER,   L"Software\\Classes\\CLSID\\" },
    };

    for (int i = 0; i < 3; i++) {
        wchar_t path[512];
        _snwprintf(path, _countof(path), L"%s%s\\InprocServer32",
                   roots[i].prefix, clsid);

        HKEY hKey = NULL;
        if (RegOpenKeyExW(roots[i].root, path, 0, KEY_READ, &hKey)
                != ERROR_SUCCESS)
            continue;

        DWORD cb = dllCch * sizeof(wchar_t), type = 0;
        BOOL  got = (RegQueryValueExW(hKey, NULL, NULL, &type,
                                      (LPBYTE)dllOut, &cb) == ERROR_SUCCESS);
        RegCloseKey(hKey);
        if (got && *dllOut) return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Audit a single credential provider entry
 * --------------------------------------------------------------------- */
static void AuditProvider(LPCWSTR providerGuid, HKEY hProvRoot, DWORD *findings) {
    /* Read the (default) value — it should be the CLSID of the COM object */
    HKEY hProv = NULL;
    if (RegOpenKeyExW(hProvRoot, providerGuid, 0, KEY_READ, &hProv)
            != ERROR_SUCCESS)
        return;

    wchar_t clsid[128]     = {0};
    wchar_t provName[256]  = {0};
    DWORD   cb, type;

    /* Friendly name (optional) */
    cb = sizeof(provName);
    RegQueryValueExW(hProv, L"FriendlyName", NULL, &type, (LPBYTE)provName, &cb);

    /* CLSID from default value (often same as providerGuid) */
    cb = sizeof(clsid);
    if (RegQueryValueExW(hProv, NULL, NULL, &type, (LPBYTE)clsid, &cb)
            != ERROR_SUCCESS || !*clsid)
        wcsncpy(clsid, providerGuid, _countof(clsid) - 1);

    RegCloseKey(hProv);

    /* Resolve the DLL path */
    wchar_t rawDLL[MAX_PATH * 2] = {0};
    if (!ResolveProviderDLL(clsid, rawDLL, _countof(rawDLL))) {
        /* CLSID not found in any Classes hive */
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"CRED_PROVIDER");
        _snwprintf(f.target, _countof(f.target),
            L"[UNRESOLVED CLSID] %s  {%s}",
            *provName ? provName : L"(unknown)", clsid);
        _snwprintf(f.reason, _countof(f.reason),
            L"Credential provider CLSID not found in any Classes hive. "
            L"Register attacker COM object with this CLSID in HKCU → "
            L"logonui.exe loads your DLL on next screen lock. "
            L"Trigger: Win+L (lock screen).");
        PrintFinding(&f);
        (*findings)++;
        return;
    }

    /* Expand environment variables */
    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(rawDLL, expanded, _countof(expanded));

    BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(expanded);
    BOOL inUser   = IsUserWritablePath(expanded);

    wchar_t dllDir[MAX_PATH * 2] = {0};
    wcsncpy(dllDir, expanded, _countof(dllDir) - 1);
    wchar_t *sl = wcsrchr(dllDir, L'\\');
    BOOL dirWritable = FALSE;
    if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(dllDir); }

    wchar_t label[256];
    _snwprintf(label, _countof(label), L"%s {%s}",
               *provName ? provName : L"(no name)", clsid);

    Finding f;
    wcscpy(f.module, L"CRED_PROVIDER");

    if (writable) {
        f.severity = SEV_CRITICAL;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DLL] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Credential provider DLL is WRITABLE! "
            L"Loaded by logonui.exe (SYSTEM/WINLOGON) on screen lock. "
            L"Replace DLL → DllMain runs at SYSTEM. Trigger: Win+L. "
            L"DLL: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    } else if (!exists) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[MISSING DLL] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Credential provider DLL does not exist: %s\n"
            L"        Plant DLL in parent directory (writable: %s)\n"
            L"        OR register CLSID in HKCU to redirect load.\n"
            L"        Trigger: Win+L (lock screen) → logonui.exe activation.",
            expanded, dirWritable ? L"YES" : L"No");
        PrintFinding(&f);
        (*findings)++;
    } else if (dirWritable) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DIR] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Credential provider DLL directory user-writable. "
            L"May allow proxy DLL planting. DLL: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    } else if (inUser) {
        f.severity = SEV_MEDIUM;
        _snwprintf(f.target, _countof(f.target),
            L"[USER-PATH] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Credential provider DLL in user-accessible path. "
            L"Verify ACL. DLL: %s", expanded);
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_CredentialProvider(void) {
    PrintHeader(L"CREDENTIAL PROVIDER DLL AUDIT  [Loaded by logonui.exe / SYSTEM]");

    PrintInfo(
        L"  Credential providers load in logonui.exe at WINLOGON integrity\n"
        L"  when screen is locked or UAC credential dialog appears.\n"
        L"  Writable DLL = SYSTEM code execution on Win+L.\n\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CRED_PROVIDERS_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open credential providers key\n");
        return;
    }

    DWORD findings = 0, idx = 0, count = 0;
    wchar_t guid[128];
    DWORD   guidCch;

    while (TRUE) {
        guidCch = _countof(guid);
        LONG r = RegEnumKeyExW(hRoot, idx++, guid, &guidCch,
                                NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS)       continue;
        count++;
        AuditProvider(guid, hRoot, &findings);
    }

    RegCloseKey(hRoot);

    PrintInfo(L"  Credential providers enumerated: %lu\n", count);
    PrintInfo(L"\n");

    if (findings == 0)
        PrintInfo(L"  No credential provider DLL issues found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOIT STEPS:\n"
            L"    Minimal DLL (payload in DllMain, DllGetClassObject returns E_NOTIMPL):\n"
            L"      BOOL WINAPI DllMain(HMODULE h, DWORD r, LPVOID lp) {\n"
            L"        if (r == DLL_PROCESS_ATTACH) <payload>;\n"
            L"        return TRUE;\n"
            L"      }\n"
            L"      HRESULT DllGetClassObject(REFCLSID r,REFIID i,void**o){return 0x80004002;}\n"
            L"    Trigger: Lock workstation (Win+L) OR runas.exe with /user:domain\\user\n"
            L"    logonui.exe runs as SYSTEM and loads all providers via CoCreateInstance.\n");
    }
}

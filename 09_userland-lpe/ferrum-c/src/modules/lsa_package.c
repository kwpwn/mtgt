/*
 * lsa_package.c — LSA Authentication/Security Package DLL Audit
 *
 * ATTACK SURFACE — CRITICAL:
 *   lsass.exe (NT AUTHORITY\SYSTEM, Protected Process Light) loads DLL modules
 *   listed in three registry values at boot:
 *
 *   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\
 *     Authentication Packages  (REG_MULTI_SZ) — auth package DLLs (e.g. msv1_0)
 *     Security Packages        (REG_MULTI_SZ) — security support provider DLLs
 *     OSConfig\Security Packages (REG_MULTI_SZ) — additional SSP packages
 *
 *   These values contain just FILENAMES (no path), and lsass.exe loads them
 *   from System32. However:
 *     a) Third-party security software (AV/EDR/DLP) often registers its own
 *        SSP/Auth package DLL. If that DLL is in a writable location, or
 *        the registry key itself is writable → lsass.exe code injection.
 *     b) If the DLL DOES NOT EXIST in System32, lsass.exe will search for it
 *        via the DLL search order — which may include user-writable directories.
 *     c) If the REG_MULTI_SZ key is user-writable, attacker can ADD a new
 *        package DLL name → lsass.exe loads attacker DLL at next boot.
 *
 * WHY THIS IS HIGH VALUE:
 *   - lsass.exe is the credential store — SYSTEM + ALL credentials in memory
 *   - Running code inside lsass = full credential dump without Mimikatz
 *   - Used by real nation-state malware (Turla, APT29) as persistence
 *   - Post-patch windows: LSAISO (isolated userspace) protects against some
 *     attacks but NOT against DLL loading via LSA packages on non-VBS systems
 *
 * CHECKS:
 *   1. Can current user write to the Authentication Packages / Security Packages
 *      registry key? → Can ADD new DLL name → lsass loads at next boot
 *   2. For each registered DLL name: does it exist in System32?
 *      If not → phantom load, DLL search order applies
 *   3. For third-party DLLs in System32: check if the file is writable
 *      (unlikely on modern Windows but possible with misconfigured ACLs)
 *   4. For DLLs with full paths: standard writability check
 *
 * PRIVILEGE NEEDED TO EXPLOIT:
 *   - Writing the registry key requires admin. BUT:
 *   - If the key ACL is misconfigured (some AV products open up ACLs for
 *     their own management tools), non-admin write is possible.
 *   - On VMs and enterprise deployments, misconfigured Lsa keys occur.
 */

#include "../common.h"

#define LSA_KEY         L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define LSA_OSCONFIG    L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig"

/* -----------------------------------------------------------------------
 * Check a REG_MULTI_SZ value containing DLL names/paths
 * --------------------------------------------------------------------- */
static void AuditMultiSzPackages(LPCWSTR keyPath, LPCWSTR valueName,
                                  LPCWSTR label, DWORD *findings)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [skip] HKLM\\%s not accessible\n", keyPath);
        return;
    }

    /* Check if current user can WRITE the key (add new packages) */
    BOOL keyWritable = IsRegKeyWritable(HKEY_LOCAL_MACHINE, keyPath);

    /* Read the multi-sz value */
    DWORD cb = 0, type = 0;
    RegQueryValueExW(hKey, valueName, NULL, &type, NULL, &cb);
    if (!cb || cb > 0x10000) {
        RegCloseKey(hKey);
        if (keyWritable) {
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"LSA_PACKAGE");
            _snwprintf(f.target, _countof(f.target),
                L"[KEY WRITABLE] HKLM\\%s : %s", keyPath, valueName);
            _snwprintf(f.reason, _countof(f.reason),
                L"Current user can WRITE to %s key. "
                L"Add a new DLL name → lsass.exe loads it at next boot as SYSTEM. "
                L"Payload DLL needs to export SpLsaModeInitialize (for auth packages) "
                L"or InitSecurityInterfaceW (for SSPs).", label);
            PrintFinding(&f);
            (*findings)++;
        }
        return;
    }

    wchar_t *multi = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, cb + 2);
    if (!multi) { RegCloseKey(hKey); return; }

    RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)multi, &cb);
    RegCloseKey(hKey);

    /* Iterate multi-sz (double-null terminated) */
    wchar_t *p = multi;
    wchar_t sys32[MAX_PATH] = {0};
    GetSystemDirectoryW(sys32, _countof(sys32));

    while (p && *p) {
        /* Skip placeholder entries like "" (two literal quote chars, or whitespace-only) */
        wchar_t stripped[MAX_PATH * 2] = {0};
        wcsncpy(stripped, p, _countof(stripped) - 1);
        wchar_t *s = stripped;
        while (*s == L'"' || *s == L' ' || *s == L'\t') s++;
        wchar_t *e = s + wcslen(s) - 1;
        while (e > s && (*e == L'"' || *e == L' ' || *e == L'\t')) e--;
        *(e + 1) = L'\0';
        if (!*s) { p += wcslen(p) + 1; continue; }

        wchar_t fullPath[MAX_PATH * 2] = {0};
        BOOL hasSep = (wcschr(p, L'\\') != NULL);

        if (hasSep) {
            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(p, expanded, _countof(expanded));
            wcsncpy(fullPath, expanded, _countof(fullPath) - 1);
        } else {
            _snwprintf(fullPath, _countof(fullPath), L"%s\\%s", sys32, p);
            /* Check if the name already has .dll; if not, append */
            if (!WcsContainsI(fullPath, L".dll"))
                wcsncat(fullPath, L".dll", _countof(fullPath) - wcslen(fullPath) - 1);
        }

        BOOL exists   = (GetFileAttributesW(fullPath) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(fullPath);
        BOOL inUser   = IsUserWritablePath(fullPath);

        Finding f;
        wcscpy(f.module, L"LSA_PACKAGE");

        if (!exists) {
            /* Phantom DLL — lsass will search DLL path; can we plant it? */
            f.severity = SEV_HIGH;
            _snwprintf(f.target, _countof(f.target),
                L"[PHANTOM] %s : %s", label, p);
            _snwprintf(f.reason, _countof(f.reason),
                L"LSA package DLL not found: %s\n"
                L"        lsass.exe will search for it; if a user-writable directory\n"
                L"        appears in DLL search before System32, plant the DLL there.\n"
                L"        Requires: reboot or lsass restart (difficult, but ATM attack).\n"
                L"        DLL exports needed: SpLsaModeInitialize / InitSecurityInterfaceW",
                fullPath);
            PrintFinding(&f);
            (*findings)++;
        } else if (writable) {
            f.severity = SEV_CRITICAL;
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE DLL] %s : %s", label, p);
            _snwprintf(f.reason, _countof(f.reason),
                L"LSA package DLL is WRITABLE by current user! "
                L"lsass.exe (SYSTEM PPL-light) loads this DLL. "
                L"Replace → code runs inside lsass = full credential access. "
                L"DLL: %s", fullPath);
            PrintFinding(&f);
            (*findings)++;
        } else if (inUser && hasSep) {
            f.severity = SEV_MEDIUM;
            _snwprintf(f.target, _countof(f.target),
                L"[USER-PATH] %s : %s", label, p);
            _snwprintf(f.reason, _countof(f.reason),
                L"LSA package DLL in user-writable location. "
                L"Verify file ACL directly. DLL: %s", fullPath);
            PrintFinding(&f);
            (*findings)++;
        }

        p += wcslen(p) + 1; /* advance to next string in multi-sz */
    }

    HeapFree(GetProcessHeap(), 0, multi);

    if (keyWritable) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"LSA_PACKAGE");
        _snwprintf(f.target, _countof(f.target),
            L"[KEY WRITABLE] HKLM\\%s : %s", keyPath, valueName);
        _snwprintf(f.reason, _countof(f.reason),
            L"User can write to %s registry key! "
            L"Add own DLL name to list → lsass.exe loads it at next boot. "
            L"Payload needs: SpLsaModeInitialize (auth pkg) or "
            L"InitSecurityInterfaceW (SSP). "
            L"Note: requires reboot to activate (persistent LPE).", label);
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_LSAPackage(void) {
    PrintHeader(L"LSA AUTHENTICATION/SECURITY PACKAGE DLL AUDIT");

    PrintInfo(
        L"  Checks DLLs loaded by lsass.exe (SYSTEM) at boot via Lsa registry.\n"
        L"  Code inside lsass = full credential access + SYSTEM privilege.\n"
        L"  Technique used by APT29/Turla for credential persistence.\n\n");

    DWORD findings = 0;

    /* Authentication Packages */
    AuditMultiSzPackages(LSA_KEY, L"Authentication Packages",
                         L"LSA Auth Package", &findings);

    /* Security Packages */
    AuditMultiSzPackages(LSA_KEY, L"Security Packages",
                         L"LSA Security Package (SSP)", &findings);

    /* OSConfig Security Packages (sometimes used by security software) */
    AuditMultiSzPackages(LSA_OSCONFIG, L"Security Packages",
                         L"LSA OSConfig SSP", &findings);

    PrintInfo(L"\n");
    if (findings == 0)
        PrintInfo(L"  No LSA package DLL issues found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  EXPLOITATION NOTES:\n"
            L"    DLL exports required (pick one based on package type):\n"
            L"      Auth Package: SpLsaModeInitialize()\n"
            L"      SSP/AP:       InitSecurityInterfaceW() → SpAcceptCredentials()\n"
            L"    Activation requires lsass restart (usually = reboot) → persistent.\n"
            L"    On non-PPL systems: also exploitable for Mimikatz-style credential dump.\n"
            L"    Reference: https://attack.mitre.org/techniques/T1547/005/\n");
    }
}

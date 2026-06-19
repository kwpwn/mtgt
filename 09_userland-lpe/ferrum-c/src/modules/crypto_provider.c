/*
 * crypto_provider.c — CryptoAPI / CSP DLL Hijacking & Cryptographic Provider Abuse
 *
 * NOVEL SURFACE — No public LPE tool systematically checks this.
 *
 * WHAT CryptoAPI PROVIDERS ARE:
 *   Windows Cryptographic Service Providers (CSPs) are DLLs that implement
 *   cryptographic algorithms (RSA, AES, SHA, etc.) for the CryptoAPI.
 *
 *   Registry paths:
 *     HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider\{ProviderName}
 *       Image Path = "C:\Windows\system32\rsaenh.dll"
 *       Type = 24 (PROV_RSA_AES)
 *
 *     HKLM\SOFTWARE\Microsoft\Cryptography\Defaults\Provider Types\Type XXX
 *       Name = "Microsoft Strong Cryptographic Provider"
 *
 * WHY CSP DLLs ARE HIGH VALUE:
 *   CSP DLLs are loaded by CryptAcquireContext() into ANY process that uses crypto:
 *   - TLS/SSL handshakes (browser, PowerShell, WinRM, WMI, etc.)
 *   - Code signing verification (AppLocker, WDAC, UAC)
 *   - Remote authentication (Kerberos, NTLM)
 *   - Certificate operations
 *
 *   IF the CSP DLL path is writable:
 *   → Replace DLL → loaded by ANY process calling CryptAcquireContext()
 *   → If a SYSTEM process does crypto → code exec as SYSTEM
 *   → If a High-IL process does crypto → code exec at High IL
 *
 * ADDITIONAL SURFACES:
 *   1. CNG (Cryptography Next Generation) providers:
 *      HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\*
 *      More modern but same attack surface.
 *
 *   2. SSL/TLS Cipher Suites (SCHANNEL providers):
 *      HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
 *      SCHANNEL.dll is SYSTEM-loaded — if writable, universal SYSTEM inject.
 *
 *   3. CryptoAPI SIG verification bypass:
 *      If the CSP used for code signature verification is writable →
 *      can bypass Authenticode verification for malicious DLLs.
 *
 * REAL-WORLD CASES:
 *   - Nation-state malware has abused CSP DLL positions on shared systems
 *   - Third-party crypto cards (SafeNet, Gemalto) install custom CSP DLLs
 *     in non-system paths → if installation directory is writable → code exec
 *   - VPN/smartcard software commonly adds CSP DLLs in user-accessible paths
 *
 * REFERENCES:
 *   MSDN: CryptAcquireContext, CryptEnumProviders
 *   CNG: BCryptEnumRegisteredProviders
 *   https://docs.microsoft.com/en-us/windows/win32/seccrypto/
 */

#include "../common.h"

#define CSP_PROV_KEY  L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"
#define CSP_TYPE_KEY  L"SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider Types"
#define CNG_CFG_KEY   L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SHA"
#define SCHANNEL_KEY  L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"

/* -----------------------------------------------------------------------
 * Audit legacy CryptoAPI CSP DLLs
 * --------------------------------------------------------------------- */
static void AuditCSPDLLs(DWORD *findings) {
    PrintInfo(L"  [1] Legacy CryptoAPI CSP DLLs (CryptAcquireContext):\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, CSP_PROV_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open CSP Providers key\n\n");
        return;
    }

    DWORD idx = 0, count = 0, vulnCount = 0;
    wchar_t provName[256];
    DWORD   provNameCch;

    while (TRUE) {
        provNameCch = _countof(provName);
        LONG r = RegEnumKeyExW(hRoot, idx++, provName, &provNameCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        wchar_t provPath[512];
        _snwprintf(provPath, _countof(provPath), L"%s\\%s", CSP_PROV_KEY, provName);

        HKEY hProv = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, provPath, 0, KEY_READ, &hProv) != ERROR_SUCCESS)
            continue;

        wchar_t imagePath[MAX_PATH * 2] = {0};
        DWORD   provType = 0;
        DWORD   cb = sizeof(imagePath), type = 0;
        RegQueryValueExW(hProv, L"Image Path", NULL, &type, (LPBYTE)imagePath, &cb);
        cb = sizeof(DWORD);
        RegQueryValueExW(hProv, L"Type", NULL, &type, (LPBYTE)&provType, &cb);
        RegCloseKey(hProv);

        if (!*imagePath) continue;

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(imagePath, expanded, _countof(expanded));
        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        /* Check for non-System32 CSP DLLs (higher risk) */
        BOOL isNonSystem = (!WcsContainsI(expanded, L"\\Windows\\system32\\")
                         && !WcsContainsI(expanded, L"\\Windows\\SysWOW64\\"));

        if (writable || !exists || isNonSystem) {
            vulnCount++;
            PrintInfo(L"    [%s] CSP: %-45s → %s\n",
                      writable ? L"!" : (!exists ? L"?" : L"*"),
                      provName, expanded);

            Finding f;
            f.severity = (writable && isNonSystem) ? SEV_CRITICAL :
                         writable                  ? SEV_HIGH :
                         !exists                   ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"CRYPTOPROV");
            _snwprintf(f.target, _countof(f.target),
                L"[%s%s] CSP DLL: %s → %s",
                isNonSystem ? L"NON-SYS " : L"",
                writable ? L"WRITABLE" : (!exists ? L"MISSING" : L"SUSPICIOUS"),
                provName, expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"CryptoAPI CSP '%s' DLL is %s: %s\n"
                L"        Provider Type: %lu\n"
                L"        CSP DLLs are loaded by ANY process calling CryptAcquireContext().\n"
                L"        This includes: TLS/SSL, code signing, Kerberos, NTLM, certificate ops.\n"
                L"        If a SYSTEM/High-IL process uses crypto: code exec at that IL.\n"
                L"        %s → code exec in any crypto-using process.",
                provName,
                writable ? L"WRITABLE" : (!exists ? L"MISSING" : L"non-standard path"),
                expanded, provType,
                writable ? L"Replace DLL with payload" : L"Plant DLL at path");
            PrintFinding(&f);
            (*findings)++;
        } else {
            PrintInfo(L"    OK: %-45s  %s\n", provName, expanded);
        }
    }

    RegCloseKey(hRoot);
    PrintInfo(L"    CSPs scanned: %lu | Vulnerable: %lu\n\n", count, vulnCount);
}

/* -----------------------------------------------------------------------
 * Audit SCHANNEL.dll writability (universal TLS DLL)
 * --------------------------------------------------------------------- */
static void AuditSCHANNEL(DWORD *findings) {
    PrintInfo(L"  [2] SCHANNEL.dll (TLS/SSL implementation — loaded by every TLS connection):\n");

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, _countof(sysDir));

    wchar_t schannel[MAX_PATH * 2] = {0};
    _snwprintf(schannel, _countof(schannel), L"%s\\schannel.dll", sysDir);

    BOOL exists   = (GetFileAttributesW(schannel) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(schannel);

    PrintInfo(L"    %s: %s\n\n",
              schannel, !exists ? L"[NOT FOUND]" : writable ? L"[WRITABLE!]" : L"ok");

    if (writable) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"CRYPTOPROV");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE] SCHANNEL.dll: %s", schannel);
        wcscpy(f.reason,
            L"SCHANNEL.dll is WRITABLE! This DLL handles ALL TLS/SSL connections on Windows.\n"
            L"        Loaded by: WinHTTP, WinInet, PowerShell, WMI, RDP, WinRM, and more.\n"
            L"        Replace SCHANNEL.dll → code exec in every process making a TLS connection.\n"
            L"        Includes SYSTEM services → universal SYSTEM code execution.\n"
            L"        This is an ultra-high-value finding.");
        PrintFinding(&f);
        (*findings)++;
    }

    /* Also check cryptsp.dll (CryptoAPI stub DLL) */
    wchar_t cryptsp[MAX_PATH * 2] = {0};
    _snwprintf(cryptsp, _countof(cryptsp), L"%s\\cryptsp.dll", sysDir);
    BOOL cExists = (GetFileAttributesW(cryptsp) != INVALID_FILE_ATTRIBUTES);
    BOOL cWrite  = cExists && IsFileWritable(cryptsp);
    PrintInfo(L"    cryptsp.dll (CryptoAPI stub): %s\n\n",
              !cExists ? L"[NOT FOUND]" : cWrite ? L"[WRITABLE!]" : L"ok");

    if (cWrite) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"CRYPTOPROV");
        _snwprintf(f.target, _countof(f.target), L"[WRITABLE] cryptsp.dll: %s", cryptsp);
        wcscpy(f.reason,
            L"cryptsp.dll (CryptoAPI Service Provider stub) is WRITABLE.\n"
            L"        This DLL is the dispatch layer for ALL CSP calls.\n"
            L"        Every process calling CryptAcquireContext() loads cryptsp.dll.\n"
            L"        Replace it → universal code injection across all crypto-using processes.");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Check for third-party CSPs in non-system paths (smartcard, HSM, VPN)
 * --------------------------------------------------------------------- */
static void AuditThirdPartyCSPs(DWORD *findings) {
    PrintInfo(L"  [3] Third-party CSP DLL directory writability:\n");

    /* Common paths for third-party CSP DLLs */
    static const wchar_t *THIRD_PARTY_PATHS[] = {
        L"%ProgramFiles%\\SafeNet\\Authentication\\SAC",
        L"%ProgramFiles%\\Gemalto\\Classic Client",
        L"%ProgramFiles%\\HID Global\\ActivClient",
        L"%ProgramFiles%\\Oberthur Technologies",
        L"%ProgramFiles%\\OpenSC Project\\OpenSC",
        L"%SystemRoot%\\SysWOW64\\",
        NULL
    };

    /* Check these dirs for any .dll files with writable parent */
    DWORD foundWritable = 0;
    for (int i = 0; THIRD_PARTY_PATHS[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(THIRD_PARTY_PATHS[i], expanded, _countof(expanded));
        if (GetFileAttributesW(expanded) == INVALID_FILE_ATTRIBUTES) continue;

        if (IsDirWritable(expanded)) {
            foundWritable++;
            PrintInfo(L"    [WRITABLE CSP DIR] %s\n", expanded);
        }
    }
    if (foundWritable == 0) PrintInfo(L"    No writable third-party CSP directories found\n");
    PrintInfo(L"\n");
}

void Module_CryptoProvider(void) {
    PrintHeader(L"CRYPTO PROVIDER DLLs  [Novel: CSP/SCHANNEL DLL hijacking → code exec in all crypto ops]");

    PrintInfo(
        L"  CryptoAPI CSP DLLs loaded by ANY process using Windows crypto (TLS, signing, etc.).\n"
        L"  Writable CSP DLL → code exec in SYSTEM services doing crypto operations.\n"
        L"  No public WinPEAS/PowerUp/Seatbelt check systematically covers this surface.\n\n");

    DWORD findings = 0;
    AuditCSPDLLs(&findings);
    AuditSCHANNEL(&findings);
    AuditThirdPartyCSPs(&findings);

    if (findings == 0)
        PrintInfo(L"  No CryptoAPI CSP DLL hijacking surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  TRIGGER ANY CSP DLL LOAD:\n"
            L"    PowerShell: Invoke-WebRequest https://... (TLS → SCHANNEL)\n"
            L"    certutil.exe -decode base64.txt output.bin (CryptoAPI)\n"
            L"    Any HTTPS request from any process loads the registered CSP DLL\n");
    }
}

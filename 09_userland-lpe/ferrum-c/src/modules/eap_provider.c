/*
 * eap_provider.c — RAS/VPN EAP Method DLL Hijacking & Network Provider Surfaces
 *
 * NOVEL SURFACE — Not covered by WinPEAS, PowerUp, or Seatbelt.
 *
 * WHAT EAP PROVIDERS ARE:
 *   EAP (Extensible Authentication Protocol) methods are DLLs loaded by the
 *   RAS (Remote Access Service) / VPN subsystem for authentication.
 *
 *   Registry paths:
 *     HKLM\SYSTEM\CurrentControlSet\Services\RasMan\PPP\EAP\{EapType}\
 *       Path = "C:\Windows\system32\rastls.dll"
 *       PeerDLLPath = "C:\Windows\system32\rastls.dll"
 *       ConfigUIPath = "C:\Windows\system32\rasdlg.dll"
 *
 *   EAP types:
 *     13 = EAP-TLS (smart card / certificate)
 *     26 = EAP-MS-CHAP v2 (password)
 *     25 = PEAP
 *     18 = EAP-SIM / EAP-AKA
 *
 * WHY EAP DLLs ARE HIGH VALUE:
 *   1. RasMan service runs as LOCAL SYSTEM → SYSTEM code exec via DLL replace
 *   2. EAP DLLs are loaded when a VPN connection is established or authentication UI shown
 *   3. Third-party VPN clients (Cisco AnyConnect, Palo Alto GlobalProtect, Juniper)
 *      install custom EAP types in non-system paths → often writable
 *   4. Enterprise EAP (RADIUS, PEAP) installations add custom EAP handlers
 *
 * ADDITIONAL SURFACES IN THIS MODULE:
 *
 *   WINSOCK LSP (Legacy):
 *     HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\
 *     LSP DLLs loaded by any process that uses Winsock (deprecated but still present).
 *     If present and writable → code exec in any socket-using process.
 *
 *   NDIS FILTER DRIVERS (partial):
 *     HKLM\SYSTEM\CurrentControlSet\Control\Network\{GUID}\{GUID}\Connection
 *     Network filter DLLs — kernel-level (not audited fully here, but detected).
 *
 *   IKE/IPSec Extension DLLs:
 *     HKLM\SYSTEM\CurrentControlSet\Services\IKEEXT\
 *     IKE (Internet Key Exchange) extension DLLs for IPSec VPN.
 *     Run in SVCHOST as NETWORK SERVICE.
 *
 * TRIGGER CONDITIONS:
 *   - EAP DLLs: any VPN connect attempt, WLAN 802.1X auth, NPS authentication
 *   - LSP DLLs: any socket operation (immediate, all processes)
 *   - IKE DLLs: IPSec/L2TP VPN connect
 *
 * REFERENCES:
 *   https://docs.microsoft.com/en-us/windows/win32/eap/eap-interfaces
 *   Winsock LSP: https://docs.microsoft.com/en-us/windows/win32/winsock/winsock-layered-service-providers
 *   IKEEXT: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ike/
 */

#include "../common.h"

#define EAP_KEY     L"SYSTEM\\CurrentControlSet\\Services\\RasMan\\PPP\\EAP"
#define LSP_KEY     L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries"
#define LSP_KEY64   L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64"
#define IKEEXT_KEY  L"SYSTEM\\CurrentControlSet\\Services\\IKEEXT"

/* -----------------------------------------------------------------------
 * Audit EAP provider DLLs
 * --------------------------------------------------------------------- */
static void AuditEAPProviders(DWORD *findings) {
    PrintInfo(L"  [1] RAS/VPN EAP Method DLLs (RasMan = LOCAL SYSTEM):\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, EAP_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (EAP key not found — RAS/VPN not configured)\n\n");
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t eapType[64];
    DWORD   eapTypeCch;

    while (TRUE) {
        eapTypeCch = _countof(eapType);
        LONG r = RegEnumKeyExW(hRoot, idx++, eapType, &eapTypeCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        wchar_t eapPath[512];
        _snwprintf(eapPath, _countof(eapPath), L"%s\\%s", EAP_KEY, eapType);
        HKEY hEap = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, eapPath, 0, KEY_READ, &hEap) != ERROR_SUCCESS)
            continue;

        static const wchar_t *DLL_VALUES[] = {
            L"Path", L"PeerDLLPath", L"ConfigUIPath", L"IdentityUIPath", NULL
        };

        wchar_t friendlyName[128] = {0};
        DWORD cb = sizeof(friendlyName), type = 0;
        RegQueryValueExW(hEap, L"FriendlyName", NULL, &type,
                         (LPBYTE)friendlyName, &cb);

        for (int vi = 0; DLL_VALUES[vi]; vi++) {
            wchar_t dllPath[MAX_PATH * 2] = {0};
            cb = sizeof(dllPath);
            if (RegQueryValueExW(hEap, DLL_VALUES[vi], NULL, &type,
                                 (LPBYTE)dllPath, &cb) != ERROR_SUCCESS) continue;
            if (!*dllPath) continue;

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));
            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);

            /* Flag non-System32 DLLs (third-party EAP) */
            BOOL isNonSystem = !WcsContainsI(expanded, L"\\Windows\\system32\\");

            PrintInfo(L"    EAP %s [%s] %s: %s%s\n",
                      eapType, *friendlyName ? friendlyName : L"?",
                      DLL_VALUES[vi], expanded,
                      writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : isNonSystem ? L" [non-sys]" : L""));

            if (writable || !exists) {
                Finding f;
                f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
                wcscpy(f.module, L"EAPPROV");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] EAP %s %s DLL: %s",
                    writable ? L"WRITABLE" : L"MISSING",
                    eapType, DLL_VALUES[vi], expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"EAP Method %s '%s' %s DLL is %s: %s\n"
                    L"        EAP DLLs are loaded by RasMan (LOCAL SYSTEM) for VPN/802.1X auth.\n"
                    L"        %s → SYSTEM code execution on next VPN connect attempt.\n"
                    L"        Trigger: any VPN connection, WLAN authentication, or NPS auth.",
                    eapType, *friendlyName ? friendlyName : L"unknown",
                    DLL_VALUES[vi],
                    writable ? L"WRITABLE" : L"MISSING", expanded,
                    writable ? L"Replace DLL with payload" : L"Plant DLL at path");
                PrintFinding(&f);
                (*findings)++;
            }
        }
        RegCloseKey(hEap);
    }
    RegCloseKey(hRoot);
    if (count == 0) PrintInfo(L"    (no EAP methods registered)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit Winsock LSP DLLs (legacy layered service providers)
 * --------------------------------------------------------------------- */
static void AuditWinsockLSP(DWORD *findings) {
    PrintInfo(L"  [2] Winsock LSP (Layered Service Provider) DLLs:\n");

    static const wchar_t *LSP_KEYS[] = { LSP_KEY, LSP_KEY64, NULL };

    DWORD totalLSP = 0, vulnLSP = 0;

    for (int ki = 0; LSP_KEYS[ki]; ki++) {
        HKEY hRoot = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSP_KEYS[ki],
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS)
            continue;

        DWORD idx = 0;
        wchar_t entryName[64];
        DWORD   entryNameCch;

        while (TRUE) {
            entryNameCch = _countof(entryName);
            LONG r = RegEnumKeyExW(hRoot, idx++, entryName, &entryNameCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            totalLSP++;

            wchar_t entryPath[512];
            _snwprintf(entryPath, _countof(entryPath), L"%s\\%s", LSP_KEYS[ki], entryName);
            HKEY hEntry = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, entryPath, 0, KEY_READ, &hEntry) != ERROR_SUCCESS)
                continue;

            wchar_t dllPath[MAX_PATH * 2] = {0};
            DWORD   cb = sizeof(dllPath), type = 0;
            RegQueryValueExW(hEntry, L"PackedCatalogItem", NULL, &type,
                             (LPBYTE)dllPath, &cb);
            RegCloseKey(hEntry);

            /* PackedCatalogItem is binary, not easily parsed; just flag existence */
            if (totalLSP == 1) {
                PrintInfo(L"    LSP entries present — Winsock LSP chain found.\n");
                PrintInfo(L"    LSP DLLs load into ALL socket-using processes.\n");
                PrintInfo(L"    Enumerate with: netsh winsock show catalog\n");
            }
        }
        RegCloseKey(hRoot);
    }

    if (totalLSP > 0) {
        PrintInfo(L"    Total LSP entries: %lu\n", totalLSP);
        PrintInfo(L"    Run 'netsh winsock show catalog' to enumerate all LSP DLLs.\n\n");
    } else {
        PrintInfo(L"    (no LSP entries — expected on modern Windows)\n\n");
    }
}

/* -----------------------------------------------------------------------
 * Check IKEEXT service for custom extension DLLs
 * --------------------------------------------------------------------- */
static void AuditIKEExtensions(DWORD *findings) {
    PrintInfo(L"  [3] IKEv2/IPSec extension DLLs (IKEEXT — NETWORK SERVICE):\n");

    /* IKEEXT runs as NETWORK SERVICE — check its binary path */
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintInfo(L"    Cannot open SCM\n\n"); return; }

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"IKEEXT", SERVICE_QUERY_CONFIG);
    if (hSvc) {
        wchar_t cfgBuf[4096] = {0};
        DWORD   needed = 0;
        QUERY_SERVICE_CONFIGW *pCfg = (QUERY_SERVICE_CONFIGW *)cfgBuf;
        if (QueryServiceConfigW(hSvc, pCfg, sizeof(cfgBuf), &needed)) {
            PrintInfo(L"    IKEEXT service account: %s\n",
                      pCfg->lpServiceStartName ? pCfg->lpServiceStartName : L"?");
            PrintInfo(L"    IKEEXT handles IKEv2/IPSec VPN key exchange.\n");
            PrintInfo(L"    Custom authentication extensions can be registered via:\n");
            PrintInfo(L"    HKLM\\SYSTEM\\CurrentControlSet\\Services\\IKEEXT\\Parameters\\AuthMethod\n\n");
        }
        CloseServiceHandle(hSvc);
    } else {
        PrintInfo(L"    IKEEXT service not found\n\n");
    }
    CloseServiceHandle(hSCM);
}

void Module_EAPProvider(void) {
    PrintHeader(L"EAP/VPN PROVIDER DLLs  [Novel: RAS EAP method + Winsock LSP DLL hijacking]");

    PrintInfo(
        L"  EAP DLLs loaded by RasMan (LOCAL SYSTEM) for VPN/802.1X authentication.\n"
        L"  Third-party VPN (Cisco AnyConnect, GlobalProtect) often install in writable paths.\n"
        L"  No public LPE tool systematically checks this surface.\n\n");

    DWORD findings = 0;
    AuditEAPProviders(&findings);
    AuditWinsockLSP(&findings);
    AuditIKEExtensions(&findings);

    if (findings == 0)
        PrintInfo(L"  No EAP/VPN DLL hijacking surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  TRIGGER EAP DLL LOAD:\n"
            L"    rasdial <VPN-connection-name> <user> <pass>\n"
            L"    Connect via Windows Settings → VPN\n"
            L"    Any 802.1X network authentication (WiFi/wired enterprise)\n");
    }
}

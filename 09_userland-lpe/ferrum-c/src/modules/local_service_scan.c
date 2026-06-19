/*
 * local_service_scan.c — Localhost Listening Service Enumeration
 *
 * WHY THIS IS A 0-DAY SURFACE:
 *   Many SYSTEM services and privileged applications expose local TCP/UDP
 *   listeners (127.0.0.1 or 0.0.0.0) for internal IPC with their user-mode
 *   counterparts. If these services:
 *     a) Accept unauthenticated connections
 *     b) Trust caller input without validation
 *     c) Execute privileged operations based on that input
 *   → Any local process (even Medium IL) can escalate.
 *
 *   Real-world examples from this research project:
 *     - ASUS ArmourySocketServer (gRPC on localhost) — researched in researchhh/
 *     - ASUS AC node addon (WebSocket on localhost) — ws_probe.cs / ws_ac_probe.cs
 *     - AsusCertService (named pipe + localhost) — asuscert_probe.c
 *
 *   Additional real-world cases:
 *     - Dell SupportAssist: unauthenticated localhost REST API (CVE-2019-12280)
 *     - Razer Synapse: localhost HTTP with command execution
 *     - NVIDIA Container: localhost gRPC without auth
 *     - Various hardware monitoring tools: unauthenticated localhost
 *
 * THIS MODULE:
 *   1. Enumerate all TCP/UDP listeners via GetExtendedTcpTable / GetExtendedUdpTable
 *   2. For each loopback listener: identify the owning process (PID)
 *   3. Get process integrity level and account (SYSTEM? High IL?)
 *   4. Try basic TCP connect → probe: HTTP GET /, gRPC PING, or raw byte
 *   5. Report all privileged listeners as research targets
 *
 * INTERPRETATION:
 *   - Port 135 = RPC Endpoint Mapper (already covered by --RPCSVC)
 *   - Port 445 = SMB (skip)
 *   - Non-standard ports on SYSTEM process = HIGH research value
 *   - WebSocket upgrade response = likely JSON/gRPC API = inspect methods
 *
 * RESEARCH WORKFLOW:
 *   1. Get port list from this module
 *   2. Use grpc_probe / ws_probe (from researchhh/) for gRPC/WebSocket services
 *   3. For HTTP: curl http://127.0.0.1:<port>/ to see API docs or error
 *   4. For raw TCP: netcat / custom probe to identify protocol
 *   5. Look for: command execution endpoints, file upload, path parameters
 *
 * COMPILE NOTES:
 *   Requires: iphlpapi.lib (-liphlpapi)
 *   Headers: iphlpapi.h, tcpmib.h (included via iphlpapi.h)
 */

#include "../common.h"
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* Extended TCP table structures */
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* Well-known ports to skip (not interesting LPE surface) */
static BOOL IsSkipPort(USHORT port) {
    static const USHORT skip[] = {
        135,    /* RPC Endpoint Mapper — covered by --RPCSVC */
        445,    /* SMB */
        139,    /* NetBIOS */
        137, 138, /* NetBIOS */
        0
    };
    for (int i = 0; skip[i]; i++)
        if (skip[i] == port) return TRUE;
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Quick TCP connect probe — returns TRUE if something responds
 * --------------------------------------------------------------------- */
static BOOL TcpProbeConnect(USHORT port) {
    WSADATA wsd = {0};
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) return FALSE;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WSACleanup(); return FALSE; }

    /* Non-blocking with 200ms timeout */
    DWORD timeout = 200;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 */

    BOOL connected = (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    closesocket(s);
    WSACleanup();
    return connected;
}

/* -----------------------------------------------------------------------
 * Probe: send HTTP GET / and read banner (protocol fingerprinting)
 * --------------------------------------------------------------------- */
static void HttpProbe(USHORT port, wchar_t *banner, DWORD bannerCch) {
    banner[0] = L'\0';
    WSADATA wsd = {0};
    if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0) return;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { WSACleanup(); return; }

    DWORD timeout = 500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(s); WSACleanup(); return;
    }

    /* Send minimal HTTP GET */
    const char *req = "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    send(s, req, (int)strlen(req), 0);

    /* Read response banner (first 256 bytes) */
    char buf[512] = {0};
    int  got = recv(s, buf, sizeof(buf) - 1, 0);
    closesocket(s);
    WSACleanup();

    if (got > 0) {
        /* Convert to wide, take first line */
        char firstLine[256] = {0};
        char *nl = strchr(buf, '\n');
        int   copyLen = nl ? (int)(nl - buf) : got;
        if (copyLen > 200) copyLen = 200;
        strncpy(firstLine, buf, copyLen);
        MultiByteToWideChar(CP_ACP, 0, firstLine, -1, banner, bannerCch);
    }
}

/* -----------------------------------------------------------------------
 * Enumerate TCP listeners and report privileged ones
 * --------------------------------------------------------------------- */
void Module_LocalServiceScan(void) {
    PrintHeader(L"LOCALHOST SERVICE SCAN  [Privileged local TCP listeners]");

    PrintInfo(
        L"  Enumerates TCP services listening on 127.0.0.1 (localhost).\n"
        L"  SYSTEM/High-IL services with accessible local ports = research targets.\n"
        L"  This is the automated version of the manual grpc_probe/ws_probe workflow.\n\n");

    /* Get extended TCP table (includes PID ownership) */
    DWORD bufSize = 65536;
    MIB_TCPTABLE_OWNER_PID *table = (MIB_TCPTABLE_OWNER_PID *)
        HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!table) return;

    DWORD ret = GetExtendedTcpTable(table, &bufSize, TRUE,
                                     AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (ret == ERROR_INSUFFICIENT_BUFFER) {
        HeapFree(GetProcessHeap(), 0, table);
        table = (MIB_TCPTABLE_OWNER_PID *)HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (!table) return;
        ret = GetExtendedTcpTable(table, &bufSize, TRUE,
                                   AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
    }

    if (ret != NO_ERROR) {
        PrintInfo(L"  [!] GetExtendedTcpTable failed: %lu\n", ret);
        HeapFree(GetProcessHeap(), 0, table);
        return;
    }

    DWORD findings = 0, totalLocal = 0;

    PrintInfo(L"  %-8s  %-6s  %-10s  %-30s  %s\n",
              L"Port", L"Conn", L"Account", L"Process", L"Banner");
    PrintInfo(L"  %s\n", L"--------------------------------------------------------------------------");

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &table->table[i];

        DWORD localAddr = ntohl(row->dwLocalAddr);
        USHORT localPort = ntohs((USHORT)row->dwLocalPort);

        /* Only loopback (127.0.0.1) or all-interfaces (0.0.0.0) listeners */
        BOOL isLoopback = (localAddr == 0x7F000001); /* 127.0.0.1 */
        BOOL isAny      = (localAddr == 0x00000000); /* 0.0.0.0 */
        if (!isLoopback && !isAny) continue;
        if (IsSkipPort(localPort))  continue;

        totalLocal++;
        DWORD pid = row->dwOwningPid;

        /* Get process info */
        wchar_t exePath[MAX_PATH * 2] = {0};
        wchar_t account[128]          = {0};
        DWORD   il                    = 0;

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProc) {
            DWORD cb = _countof(exePath);
            QueryFullProcessImageNameW(hProc, 0, exePath, &cb);
            il = GetProcessIntegrityRID(hProc);
            CloseHandle(hProc);
        }
        GetProcessUser(pid, account, _countof(account));

        wchar_t *exeName = wcsrchr(exePath, L'\\');
        if (exeName) exeName++; else exeName = exePath;
        if (!*exeName) _snwprintf(exeName = exePath, 1, L"(PID:%lu)", pid);

        /* Try connect + HTTP probe */
        BOOL canConnect = TcpProbeConnect(localPort);
        wchar_t banner[256] = {0};
        if (canConnect)
            HttpProbe(localPort, banner, _countof(banner));

        PrintInfo(L"  %-8u  %-6s  %-10s  %-30s  %s\n",
                  localPort,
                  canConnect ? L"OPEN" : L"closed",
                  account,
                  exeName,
                  *banner ? banner : L"(no HTTP response)");

        /* High/System IL service on accessible port = HIGH finding */
        if (canConnect && il >= 0x2000 &&
            !WcsContainsI(account, L"SYSTEM") == FALSE) {
            /* SYSTEM account or high IL: elevated service */
        }

        if (canConnect) {
            BOOL isPriv = (il >= SECURITY_MANDATORY_HIGH_RID ||
                           WcsContainsI(account, L"SYSTEM") ||
                           WcsContainsI(account, L"NetworkService") ||
                           WcsContainsI(account, L"LocalService"));

            if (isPriv) {
                Finding f;
                f.severity = WcsContainsI(account, L"SYSTEM") ? SEV_HIGH : SEV_MEDIUM;
                wcscpy(f.module, L"LOCAL_SVC");
                _snwprintf(f.target, _countof(f.target),
                    L"[PORT %u] %s (%s)",
                    localPort, exeName, account);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Privileged service listening on localhost TCP port %u. "
                    L"Process: %s  Account: %s  IL: 0x%04lX\n"
                    L"        Connection accepted from Medium IL (port is open).\n"
                    L"        %s\n"
                    L"        RESEARCH: "
                    L"(1) HTTP: curl http://127.0.0.1:%u/ — look for API endpoints. "
                    L"(2) gRPC: grpcurl -plaintext localhost:%u list. "
                    L"(3) WebSocket: wscat -c ws://127.0.0.1:%u/. "
                    L"(4) Raw: nc 127.0.0.1 %u — observe protocol banner. "
                    L"Focus: unauthenticated endpoints that execute privileged ops.",
                    localPort, exePath, account, il,
                    *banner ? banner : L"(no HTTP banner)",
                    localPort, localPort, localPort, localPort);
                PrintFinding(&f);
                findings++;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, table);

    PrintInfo(L"\n  Local TCP listeners found: %lu  |  Privileged+accessible: %lu\n\n",
              totalLocal, findings);

    PrintInfo(
        L"  RESEARCH TOOLS (from researchhh/ in this project):\n"
        L"    grpc_probe.exe   — enumerate gRPC service methods\n"
        L"    ws_probe.exe     — WebSocket connection + message probe\n"
        L"    ws_ac_probe.exe  — ASUS AC WebSocket specific probe\n"
        L"    tcp_probe2.exe   — raw TCP banner grab\n\n"
        L"  GENERAL TOOLING:\n"
        L"    grpcurl:   https://github.com/fullstorydev/grpcurl\n"
        L"    wscat:     npm install -g wscat\n"
        L"    Burp Suite: proxy localhost traffic for full API enumeration\n"
        L"    curl:      curl -v http://127.0.0.1:<port>/ --max-time 2\n");
}

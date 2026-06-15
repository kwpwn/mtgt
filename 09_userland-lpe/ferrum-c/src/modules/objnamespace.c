/*
 * objnamespace.c — NT Object Namespace Directory ACL Audit
 *
 * WHY THIS IS NOVEL:
 *   WinPEAS, PowerUp, Seatbelt, Ferrum-Go: NONE check the NT Object Manager
 *   namespace. This is a genuinely unexplored attack surface in automated tooling.
 *
 * THE NT OBJECT NAMESPACE (separate from filesystem):
 *   \                              root
 *   \BaseNamedObjects\             global named objects (mutex, event, section)
 *   \Sessions\1\BaseNamedObjects\  per-session (apps normally use this)
 *   \KnownDlls\                    KnownDLL section objects (critical for DLL load)
 *   \GLOBAL??\                     Win32 device name symlinks
 *
 * ATTACK SURFACE — Object Squatting:
 *   1. A SYSTEM service creates a named mutex/section: OpenMutex(L"Global\\AppSingleton")
 *   2. If user can CREATE objects in the same directory BEFORE the service starts:
 *      → Create the object first with attacker-controlled parameters
 *      → Service opens the user-created object ("already exists" path)
 *      → Behavior diverges in attacker's favor (access granted, lockout bypassed, etc.)
 *   3. Named section squatting: SYSTEM creates shared memory, user plants the section
 *      first → SYSTEM writes privileged data into user-readable memory.
 *
 * ATTACK SURFACE — Third-party Directory ACL:
 *   Some products create sub-directories in \BaseNamedObjects\ (e.g.,
 *   \BaseNamedObjects\<ProductName>\) with Everyone:CREATE_OBJECT to allow
 *   low-priv apps to signal the service. If that ACL is weaker than intended,
 *   any process can create objects there with attacker-controlled attributes.
 *
 * REFERENCES:
 *   James Forshaw (Project Zero) — Windows Object Namespace Squatting
 *   Alex Ionescu — Windows Internals, Object Manager chapter
 *   CVE-2021-34486 — Event Log TOCTOU via object namespace
 */

#include "../common.h"

/* winternl.h (included via common.h) provides:
 *   UNICODE_STRING, PUNICODE_STRING, OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES,
 *   OBJ_CASE_INSENSITIVE, InitializeObjectAttributes
 * We still need to define types not in winternl.h: */

#define DIRECTORY_QUERY               0x0001
#define DIRECTORY_TRAVERSE            0x0002
#define DIRECTORY_CREATE_OBJECT       0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED | 0x000F)

/* Not in standard SDK headers (kernel-mode only in ntifs.h) */
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

/* NT STATUS codes not in winternl.h */
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES  ((NTSTATUS)0x8000001AL)
#endif

/* NT API function pointer types */
typedef NTSTATUS (NTAPI *PFN_NtOpenDirectoryObject)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);
typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryObject)(
    HANDLE  DirectoryHandle,
    PVOID   Buffer,
    ULONG   BufferLength,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG  Context,
    PULONG  ReturnLength
);
typedef NTSTATUS (NTAPI *PFN_NtQuerySecurityObject)(
    HANDLE              Handle,
    SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    ULONG               Length,
    PULONG              LengthNeeded
);

static PFN_NtOpenDirectoryObject  g_NtOpenDir   = NULL;
static PFN_NtQueryDirectoryObject g_NtQueryDir  = NULL;
static PFN_NtQuerySecurityObject  g_NtQuerySec  = NULL;
static BOOL                       g_nsInit      = FALSE;

static BOOL NsInit(void) {
    if (g_nsInit) return TRUE;
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return FALSE;
    g_NtOpenDir  = (PFN_NtOpenDirectoryObject) GetProcAddress(h, "NtOpenDirectoryObject");
    g_NtQueryDir = (PFN_NtQueryDirectoryObject)GetProcAddress(h, "NtQueryDirectoryObject");
    g_NtQuerySec = (PFN_NtQuerySecurityObject) GetProcAddress(h, "NtQuerySecurityObject");
    g_nsInit     = (g_NtOpenDir && g_NtQueryDir && g_NtQuerySec);
    return g_nsInit;
}

/* -----------------------------------------------------------------------
 * Open an NT object directory by NT path (e.g. L"\\BaseNamedObjects")
 * Returns NULL on failure.
 * --------------------------------------------------------------------- */
static HANDLE NsOpenDir(LPCWSTR ntPath, ACCESS_MASK access) {
    UNICODE_STRING ustr;
    /* Use RtlInitUnicodeString via function pointer (loaded dynamically) */
    ustr.Buffer        = (PWSTR)ntPath;
    ustr.Length        = (USHORT)(wcslen(ntPath) * sizeof(wchar_t));
    ustr.MaximumLength = ustr.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h = NULL;
    g_NtOpenDir(&h, access, &oa);
    return h;
}

/* -----------------------------------------------------------------------
 * Check if current token can perform desiredAccess on directory handle.
 * Uses NtQuerySecurityObject + AccessCheck.
 * --------------------------------------------------------------------- */
static BOOL DirAllowsAccess(HANDLE hDir, ACCESS_MASK desiredAccess) {
    ULONG needed = 0;
    g_NtQuerySec(hDir,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
        NULL, 0, &needed);
    if (!needed || needed > 0x20000) return FALSE;

    PSECURITY_DESCRIPTOR pSD = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!pSD) return FALSE;

    BOOL result = FALSE;
    ULONG returned = 0;
    if (g_NtQuerySec(hDir,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            pSD, needed, &returned) != 0)
        goto done;

    HANDLE hTok = NULL, hDup = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hTok))
        goto done;
    if (!DuplicateToken(hTok, SecurityImpersonation, &hDup))
        goto done;

    GENERIC_MAPPING gm = {
        DIRECTORY_QUERY,
        DIRECTORY_CREATE_OBJECT,
        DIRECTORY_TRAVERSE,
        DIRECTORY_ALL_ACCESS
    };
    MapGenericMask(&desiredAccess, &gm);

    PRIVILEGE_SET ps;
    DWORD         psLen = sizeof(ps);
    ZeroMemory(&ps, psLen);
    DWORD         granted = 0;
    BOOL          ok      = FALSE;
    AccessCheck(pSD, hDup, desiredAccess, &gm, &ps, &psLen, &granted, &ok);
    result = ok;

done:
    if (hDup) CloseHandle(hDup);
    if (hTok) CloseHandle(hTok);
    HeapFree(GetProcessHeap(), 0, pSD);
    return result;
}

/* -----------------------------------------------------------------------
 * Enumerate child entries of type "Directory" using ReturnSingleEntry=TRUE
 * (simpler, avoids complex buffer offset arithmetic).
 * --------------------------------------------------------------------- */
static void AuditSubDirs(HANDLE hParent, LPCWSTR parentNtPath, DWORD *findings) {
    BYTE   buf[2048];
    ULONG  ctx = 0, retLen = 0;
    BOOL   restart = TRUE;

    while (TRUE) {
        NTSTATUS st = g_NtQueryDir(hParent, buf, sizeof(buf),
                                    TRUE /* single entry */,
                                    restart, &ctx, &retLen);
        restart = FALSE;

        if (st == STATUS_NO_MORE_ENTRIES || (st != 0 && st != 0x00000105 /* MORE_ENTRIES */))
            break;

        POBJECT_DIRECTORY_INFORMATION info = (POBJECT_DIRECTORY_INFORMATION)buf;
        if (!info->Name.Buffer || info->Name.Length == 0) break;

        /* Only care about sub-Directory objects — these are product namespaces */
        wchar_t typeName[64] = {0};
        if (info->TypeName.Buffer && info->TypeName.Length > 0) {
            int n = min(info->TypeName.Length / 2, 63);
            wcsncpy(typeName, info->TypeName.Buffer, n);
        }
        if (_wcsicmp(typeName, L"Directory") != 0) continue;

        wchar_t subName[256] = {0};
        {
            int n = min(info->Name.Length / 2, 255);
            wcsncpy(subName, info->Name.Buffer, n);
        }

        /* Build full NT path of the sub-directory */
        wchar_t subPath[512] = {0};
        _snwprintf(subPath, _countof(subPath), L"%s\\%s", parentNtPath, subName);

        HANDLE hSub = NsOpenDir(subPath, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL);
        if (!hSub) continue;

        BOOL canCreate    = DirAllowsAccess(hSub, DIRECTORY_CREATE_OBJECT);
        BOOL canCreateSub = DirAllowsAccess(hSub, DIRECTORY_CREATE_SUBDIRECTORY);
        CloseHandle(hSub);

        if (canCreate || canCreateSub) {
            Finding f;
            f.severity = canCreate ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"OBJ_NAMESPACE");
            wcsncpy(f.target, subPath, _countof(f.target) - 1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Non-admin can %s in NT object dir. "
                L"Object squatting: create mutex/section/event here "
                L"before a privileged service to control the IPC primitive. "
                L"Next: WinObj.exe to enumerate objects; ProcMon to watch "
                L"[Path contains %s] for SYSTEM service accesses.",
                canCreate ? L"CREATE OBJECTS" : L"CREATE SUB-DIRECTORIES",
                subName);
            PrintFinding(&f);
            (*findings)++;
        }
    }
}

/* -----------------------------------------------------------------------
 * Audit a single NT object directory (top-level)
 * --------------------------------------------------------------------- */
static void AuditDir(LPCWSTR ntPath, LPCWSTR desc, DWORD *findings) {
    HANDLE hDir = NsOpenDir(ntPath, DIRECTORY_QUERY | DIRECTORY_TRAVERSE | READ_CONTROL);
    if (!hDir) {
        PrintInfo(L"    [skip] %s — access denied\n", ntPath);
        return;
    }

    BOOL canCreate    = DirAllowsAccess(hDir, DIRECTORY_CREATE_OBJECT);
    BOOL canCreateSub = DirAllowsAccess(hDir, DIRECTORY_CREATE_SUBDIRECTORY);

    PrintInfo(L"    %s  [CREATE:%s, MKDIR:%s]\n",
              ntPath,
              canCreate    ? L"YES" : L"no",
              canCreateSub ? L"YES" : L"no");

    /* Unexpected: normal users should not be able to create in global BNO root */
    if (canCreate) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"OBJ_NAMESPACE");
        wcsncpy(f.target, ntPath, _countof(f.target) - 1);
        _snwprintf(f.reason, _countof(f.reason),
            L"User can CREATE OBJECTS directly in %s (%s). "
            L"Normal for \\Sessions\\x\\BNO (by design), unexpected for global. "
            L"Squatting: create mutex/section before SYSTEM service to race object creation.",
            ntPath, desc);
        PrintFinding(&f);
        (*findings)++;
    }

    /* Enumerate sub-directories (third-party product namespaces) */
    AuditSubDirs(hDir, ntPath, findings);

    CloseHandle(hDir);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_ObjNamespace(void) {
    PrintHeader(L"NT OBJECT NAMESPACE ACL AUDIT  [Novel — no public tool checks this]");

    PrintInfo(
        L"  Enumerates NT Object Manager directories for weak CREATE_OBJECT ACLs.\n"
        L"  A non-admin user able to create objects in a directory used by SYSTEM\n"
        L"  = object squatting → race-condition primitive for LPE research.\n\n");

    if (!NsInit()) {
        PrintInfo(L"  [!] Failed to resolve NtOpenDirectoryObject / NtQueryDirectoryObject\n");
        return;
    }

    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    wchar_t sessionBNO[128];
    _snwprintf(sessionBNO, _countof(sessionBNO),
               L"\\Sessions\\%lu\\BaseNamedObjects", sessionId);

    struct { LPCWSTR path; LPCWSTR desc; } dirs[] = {
        { L"\\BaseNamedObjects",  L"global named objects"              },
        { sessionBNO,             L"per-session named objects"         },
        { L"\\KnownDlls",         L"KnownDLL section objects"          },
        { L"\\GLOBAL??",          L"Win32 device symlinks"             },
    };

    PrintInfo(L"  Directories:\n");
    DWORD findings = 0;
    for (int i = 0; i < (int)(sizeof(dirs)/sizeof(dirs[0])); i++)
        AuditDir(dirs[i].path, dirs[i].desc, &findings);

    PrintInfo(L"\n");
    if (findings == 0) {
        PrintInfo(L"  No unexpected object directory ACLs found.\n");
    } else {
        PrintInfo(L"  Findings: %lu\n\n", findings);
        PrintInfo(
            L"  RESEARCH NEXT STEPS:\n"
            L"    1. Use WinObj.exe (Sysinternals) to browse flagged directories\n"
            L"    2. ProcMon: filter [Path=\\*BaseNamedObjects*\\<name>] + [Process=SYSTEM svc]\n"
            L"    3. PoC: CreateMutexW(NULL,FALSE,L\"<NT path in Win32 form>\") before svc start\n"
            L"    4. Named section: CreateFileMappingW(INVALID_HANDLE_VALUE,NULL,\n"
            L"       PAGE_READWRITE,0,0x1000,L\"Global\\\\<name>\") — check if SYSTEM writes\n"
            L"    Reference: James Forshaw's NT Object Manager squatting research\n");
    }
}

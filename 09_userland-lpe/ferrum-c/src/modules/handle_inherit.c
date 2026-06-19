/*
 * handle_inherit.c — Inheritable Handle Leakage Audit
 *
 * WHY HANDLE INHERITANCE MATTERS FOR LPE:
 *   When Windows spawns a new process, all kernel object handles marked as
 *   "inheritable" (SECURITY_ATTRIBUTES.bInheritHandle=TRUE) in the parent
 *   process are duplicated into the child process's handle table.
 *
 *   If a HIGH-IL or SYSTEM process inherits handles FROM a lower-IL parent,
 *   OR if a SYSTEM process passes inheritable handles down to child processes
 *   that we can influence, an attacker can:
 *
 *   a) RECEIVE a SYSTEM-level handle through inheritance chain
 *   b) ABUSE inheritable handles in processes we can trick into spawning children
 *   c) SCAN spawned child processes for leaked handles we can access
 *
 * VULNERABLE PATTERNS:
 *
 *   1. SYSTEM service spawns child process with inherited handles
 *      → Child inherits SYSTEM token handle
 *      → Child has lower IL / accessible to us
 *      → We enumerate child's handle table via NtQuerySystemInformation(SystemHandleInformation)
 *      → DuplicateHandle the inherited SYSTEM token from the child
 *
 *   2. Process creates inheritable file/directory handles to privileged resources
 *      → When spawning children, those handles are passed down
 *      → Child accessible → leak privileged file access
 *
 *   3. Security software creating processes with inherited kernel object handles
 *      (Event handles, Mutex handles, Token handles) — can be duplicated out
 *
 * THIS MODULE:
 *   a) Enumerate all system handles via NtQuerySystemInformation
 *   b) Find inheritable handles owned by SYSTEM/High-IL processes
 *   c) Check if the handle type suggests privilege (Token, Process, Section)
 *   d) Detect processes that appear to have SYSTEM process handles inherited
 *   e) Report processes with many inheritable handles (handle leak indicators)
 *
 * KEY TECHNIQUE — Handle Inheritance Abuse:
 *   1. Find a SYSTEM-spawnable process that uses CreateProcess with inheritance
 *      (many Windows services call CreateProcess with bInheritHandles=TRUE)
 *   2. Place an inheritable handle to desired resource in the right table position
 *      before the child is spawned
 *   3. The child inherits our handle → we interact with child → resource access
 *
 * REFERENCES:
 *   James Forshaw: "Windows Privilege Escalation via Inherited Handles" (Project Zero)
 *   "Exploring the Handle Table via NtQuerySystemInformation" (various)
 *   NtQuerySystemInformation SystemHandleInformation: 0x10
 *   Token handle value type: 0x5 (depends on Windows version)
 */

#include "../common.h"

/* NtQuerySystemInformation SystemHandleInformation (class 16 = 0x10) */
#define SystemHandleInformationClass  0x10

/* winternl.h already defines SYSTEM_HANDLE_ENTRY / SYSTEM_HANDLE_INFORMATION
 * with fields: OwnerPid, ObjectType, HandleFlags, HandleValue, ObjectPointer, AccessMask
 * and Count / Handle[1] — use those directly.                                         */

typedef NTSTATUS (WINAPI *PNtQuerySystemInformation)(
    DWORD  SystemInformationClass,
    PVOID  SystemInformation,
    DWORD  SystemInformationLength,
    PDWORD ReturnLength
);

/* Handle type numbers (approximate, OS-dependent) */
#define HANDLE_TYPE_PROCESS  7
#define HANDLE_TYPE_TOKEN    5
#define HANDLE_TYPE_THREAD   8
#define HANDLE_TYPE_FILE     28
#define HANDLE_TYPE_EVENT    17

/* OBJ_INHERIT bit in NT handle attributes (HandleFlags field of SYSTEM_HANDLE_ENTRY).
 * NB: different from HANDLE_FLAG_INHERIT (0x1) which is the Win32 SetHandleInformation flag. */
#define NT_HANDLE_FLAG_INHERIT  0x02

/* -----------------------------------------------------------------------
 * Enumerate inheritable handles from SYSTEM processes
 * --------------------------------------------------------------------- */
static void AuditInheritableHandles(DWORD *findings) {
    PrintInfo(L"  [1] Enumerating inheritable handles in SYSTEM processes:\n");

    PNtQuerySystemInformation pNtQSI =
        (PNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQSI) {
        PrintInfo(L"    NtQuerySystemInformation not found\n\n");
        return;
    }

    /* Dynamic buffer for handle information */
    DWORD bufSize = 1 * 1024 * 1024; /* Start with 1MB */
    SYSTEM_HANDLE_INFORMATION *pHI = NULL;
    NTSTATUS status;
    DWORD needed = 0;

    do {
        if (pHI) HeapFree(GetProcessHeap(), 0, pHI);
        pHI = (SYSTEM_HANDLE_INFORMATION *)HeapAlloc(GetProcessHeap(), 0, bufSize);
        if (!pHI) { PrintInfo(L"    Out of memory\n\n"); return; }
        status = pNtQSI(SystemHandleInformationClass, pHI, bufSize, &needed);
        bufSize *= 2;
    } while (status == 0xC0000004L /* STATUS_INFO_LENGTH_MISMATCH */
             && bufSize < 64 * 1024 * 1024);

    if (status != 0) {
        PrintInfo(L"    NtQuerySystemInformation failed: 0x%08lX\n\n", status);
        HeapFree(GetProcessHeap(), 0, pHI);
        return;
    }

    PrintInfo(L"    Total system handles: %lu\n", pHI->Count);

    /* Track per-process inheritable handle counts */
    typedef struct { DWORD pid; DWORD inheritCount; BOOL isSystem; } ProcEntry;
    static ProcEntry procs[4096];
    DWORD procCount = 0;

    DWORD interesting = 0;

    for (DWORD i = 0; i < pHI->Count && i < 65536; i++) {
        SYSTEM_HANDLE_ENTRY *h = &pHI->Handle[i];

        /* Only inheritable handles (OBJ_INHERIT = 0x02 in NT handle attrs) */
        if (!(h->HandleFlags & NT_HANDLE_FLAG_INHERIT)) continue;

        /* Only from SYSTEM/elevated processes */
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, h->OwnerPid);
        if (!hProc) continue;

        DWORD il = GetProcessIntegrityRID(hProc);
        CloseHandle(hProc);

        if (il < SECURITY_MANDATORY_HIGH_RID) continue;

        /* Track inheritable counts per process */
        BOOL found = FALSE;
        for (DWORD pi = 0; pi < procCount; pi++) {
            if (procs[pi].pid == h->OwnerPid) {
                procs[pi].inheritCount++;
                found = TRUE;
                break;
            }
        }
        if (!found && procCount < 4096) {
            procs[procCount].pid          = h->OwnerPid;
            procs[procCount].inheritCount = 1;
            procCount++;
        }

        /* Flag interesting handle types */
        if (h->ObjectType == HANDLE_TYPE_TOKEN ||
            h->ObjectType == HANDLE_TYPE_PROCESS) {
            interesting++;
        }
    }

    HeapFree(GetProcessHeap(), 0, pHI);

    PrintInfo(L"    Privileged processes with inheritable handles:\n");

    for (DWORD pi = 0; pi < procCount && pi < 32; pi++) {
        wchar_t account[128] = {0};
        GetProcessUser(procs[pi].pid, account, _countof(account));

        wchar_t exeName[MAX_PATH] = {0};
        HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procs[pi].pid);
        if (hP) {
            DWORD cb = _countof(exeName);
            QueryFullProcessImageNameW(hP, 0, exeName, &cb);
            CloseHandle(hP);
        }
        wchar_t *name = wcsrchr(exeName, L'\\');
        if (name) name++; else name = exeName;

        PrintInfo(L"      PID:%6lu  %-20s  %-16s  inheritable: %lu\n",
                  procs[pi].pid, name, account, procs[pi].inheritCount);
    }

    if (procCount > 32)
        PrintInfo(L"      ... and %lu more processes\n", procCount - 32);

    PrintInfo(L"\n    Interesting handles (Token/Process, inheritable, from High/SYSTEM): %lu\n",
              interesting);

    if (interesting > 0) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"HANDLES");
        _snwprintf(f.target, _countof(f.target),
            L"[INHERITABLE] %lu token/process handles found in High-IL processes",
            interesting);
        _snwprintf(f.reason, _countof(f.reason),
            L"%lu inheritable Token or Process handles found in High-IL/SYSTEM processes.\n"
            L"        If any of these processes create children (cmd, notepad, etc.) with "
            L"bInheritHandles=TRUE, the child inherits these privileged handles.\n"
            L"        Child process may be accessible (lower IL, PROCESS_DUP_HANDLE) → "
            L"steal the inherited SYSTEM/Token handle.\n"
            L"        Tool: SysInternals Handle.exe, NtQueryProcessInformation(ProcessHandleTable)",
            interesting);
        PrintFinding(&f);
        (*findings)++;
    }

    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check for processes spawned with inheritable handle chains (live check)
 * --------------------------------------------------------------------- */
static void AuditChildProcessHandles(DWORD *findings) {
    PrintInfo(L"  [2] Child processes of SYSTEM services (potential handle leaks):\n");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        PrintInfo(L"    Cannot enumerate processes\n\n");
        return;
    }

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    BOOL more = Process32FirstW(hSnap, &pe);

    DWORD childOfSystem = 0;

    while (more) {
        /* Is parent SYSTEM and child lower IL? */
        DWORD ppid = pe.th32ParentProcessID;
        DWORD cpid = pe.th32ProcessID;

        if (ppid == 0 || cpid == 0) { more = Process32NextW(hSnap, &pe); continue; }

        HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ppid);
        HANDLE hChild  = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, cpid);

        if (hParent && hChild) {
            DWORD pIL = GetProcessIntegrityRID(hParent);
            DWORD cIL = GetProcessIntegrityRID(hChild);

            if (pIL >= SECURITY_MANDATORY_SYSTEM_RID && /* Parent = SYSTEM */
                cIL  <  SECURITY_MANDATORY_SYSTEM_RID && /* Child = non-SYSTEM */
                cIL  >= SECURITY_MANDATORY_MEDIUM_RID) { /* Child = accessible */

                wchar_t parentUser[64] = {0};
                GetProcessUser(ppid, parentUser, _countof(parentUser));

                wchar_t childUser[64] = {0};
                GetProcessUser(cpid, childUser, _countof(childUser));

                if (WcsContainsI(parentUser, L"SYSTEM")) {
                    PrintInfo(L"    SYSTEM→lower: PPID:%lu(%s) → PID:%lu %s (%s)\n",
                              ppid, parentUser, cpid, pe.szExeFile, childUser);
                    childOfSystem++;
                }
            }
        }

        if (hParent) CloseHandle(hParent);
        if (hChild)  CloseHandle(hChild);

        more = Process32NextW(hSnap, &pe);
    }
    CloseHandle(hSnap);

    PrintInfo(L"    SYSTEM→lower-IL child processes: %lu\n\n", childOfSystem);

    if (childOfSystem > 0) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"HANDLES");
        _snwprintf(f.target, _countof(f.target),
            L"[SYSTEM CHILDREN] %lu lower-IL processes spawned by SYSTEM",
            childOfSystem);
        wcscpy(f.reason,
            L"SYSTEM-spawned lower-IL processes exist. "
            L"If spawned with bInheritHandles=TRUE, they may hold inherited SYSTEM handles. "
            L"Check with: NtQuerySystemInformation(SystemHandleInformation) filtered by these PIDs. "
            L"Duplicate any inherited Token/Process handles → privilege escalation.");
        PrintFinding(&f);
        (*findings)++;
    }
}

void Module_HandleInherit(void) {
    PrintHeader(L"HANDLE INHERITANCE AUDIT  [Inheritable handle leakage from SYSTEM processes]");

    PrintInfo(
        L"  Enumerates inheritable handles in SYSTEM/High-IL processes.\n"
        L"  Handle inheritance abuse is a classic Windows privilege escalation technique.\n"
        L"  Used by Forshaw (Project Zero) and multiple public LPE CVE chains.\n\n");

    DWORD findings = 0;
    AuditInheritableHandles(&findings);
    AuditChildProcessHandles(&findings);

    if (findings == 0)
        PrintInfo(L"  No handle inheritance issues found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  HANDLE STEALING TECHNIQUE:\n"
            L"    1. Find child process (lower IL) spawned by SYSTEM with bInheritHandles\n"
            L"    2. Open child with PROCESS_DUP_HANDLE\n"
            L"    3. Enumerate handle table values (4, 8, 12, ... up to 65536)\n"
            L"    4. DuplicateHandle(hChild, candidate, GetCurrentProcess(),\n"
            L"                       &dup, TOKEN_ALL_ACCESS, FALSE, 0)\n"
            L"    5. If dup is a SYSTEM token: SetThreadToken / CreateProcessWithToken\n"
            L"    6. You now have SYSTEM shell\n\n"
            L"  TOOL: SysInternals Process Explorer → show handles → filter by type\n"
            L"  TOOL: NtObjectManager PowerShell module (James Forshaw)\n"
            L"    Get-NtHandle -ProcessId <child_pid> | Where-Object { $_.ObjectType -eq 'Token' }\n");
    }
}

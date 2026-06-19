/*
 * process_dacl.c — Process Security Descriptor (DACL) Audit
 *
 * WHY PROCESS DACLs MATTER FOR LPE:
 *   Every Windows process has a security descriptor that controls who can
 *   perform what operations on it. If a SYSTEM-level process has a weak DACL
 *   that grants non-admin users excessive access rights, an attacker can:
 *
 *   a) PROCESS_DUP_HANDLE:
 *      DuplicateHandle to steal kernel object handles FROM the target.
 *      If SYSTEM process has an open handle to a privileged object (token,
 *      process, file), we can duplicate it into our process → privilege theft.
 *
 *   b) PROCESS_VM_READ + PROCESS_VM_WRITE:
 *      Read/write process memory → inject shellcode → SYSTEM code execution.
 *      Or: read SYSTEM process memory for credential extraction.
 *
 *   c) PROCESS_CREATE_THREAD:
 *      Create remote thread in SYSTEM process → arbitrary code execution.
 *
 *   d) PROCESS_SUSPEND_RESUME:
 *      Suspend/resume process → DoS or synchronization manipulation.
 *
 * HISTORICAL CASES:
 *   - Various EDR/AV processes have had weak DACLs (Trend Micro, McAfee)
 *   - Hardware vendor tools often misconfigure process ACLs for IPC
 *   - Some game anti-cheats create accessible processes for user-mode hooks
 *   - CVE-2021-34527 (PrintNightmare) chain used process handle duplication
 *
 * DETECTION APPROACH:
 *   1. Enumerate all processes
 *   2. For each SYSTEM/High-IL process: read its security descriptor
 *   3. AccessCheck for dangerous rights (VM_READ/WRITE, DUP_HANDLE, CREATE_THREAD)
 *   4. Flag processes granting these rights to Everyone/Authenticated Users/Interactive
 *
 * NOTE:
 *   Some rights (VM_READ) are intentionally granted to authenticated users
 *   for debugging purposes. Context matters — report with severity calibrated
 *   to the process account (SYSTEM process with world-accessible handles = CRITICAL).
 *
 * REFERENCES:
 *   James Forshaw: "Abusing Token Privileges for LPE" (Project Zero)
 *   PROCESS_DUP_HANDLE token stealing: wellknown technique
 *   CVE-2020-16898: Solarwinds process handle vulnerability
 */

#include "../common.h"

/* Access rights to test for */
#define ACCESS_VM_READ      PROCESS_VM_READ
#define ACCESS_VM_WRITE     PROCESS_VM_WRITE
#define ACCESS_DUP_HANDLE   PROCESS_DUP_HANDLE
#define ACCESS_CREATE_THREAD PROCESS_CREATE_THREAD
#define ACCESS_TERMINATE    PROCESS_TERMINATE

typedef struct {
    DWORD mask;
    const wchar_t *name;
    Severity sev;
    const wchar_t *exploitNote;
} DangerousAccess;

static const DangerousAccess g_accessList[] = {
    { PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
      L"VM_WRITE+CREATE_THREAD",
      SEV_CRITICAL,
      L"Can inject shellcode: WriteProcessMemory + CreateRemoteThread → arbitrary code in SYSTEM process"
    },
    { PROCESS_DUP_HANDLE,
      L"DUP_HANDLE",
      SEV_HIGH,
      L"Can duplicate handles from SYSTEM process: steal token/file handles → privilege escalation. "
      L"Technique: DuplicateHandle(hSYSTEM, INVALID_HANDLE_VALUE, hSelf, &hSelfDup, TOKEN_ALL_ACCESS, ...) "
      L"→ get caller's own token duplicated with SYSTEM security context."
    },
    { PROCESS_VM_READ,
      L"VM_READ",
      SEV_MEDIUM,
      L"Can read SYSTEM process memory: scan for credentials, tokens, keys. "
      L"ReadProcessMemory on lsass → equivalent to Mimikatz (if target is lsass)."
    },
    { PROCESS_CREATE_THREAD,
      L"CREATE_THREAD",
      SEV_HIGH,
      L"Can create remote thread in SYSTEM process. "
      L"Combined with ReadProcessMemory to find shellcode location."
    },
    { 0, NULL, 0, NULL }
};

/* -----------------------------------------------------------------------
 * Test if current token has a specific access right to a process
 * --------------------------------------------------------------------- */
static BOOL CanAccessProcess(HANDLE hProc, DWORD desiredAccess) {
    /* Get process security descriptor */
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD ret = GetSecurityInfo(hProc, SE_KERNEL_OBJECT,
                                DACL_SECURITY_INFORMATION |
                                OWNER_SECURITY_INFORMATION |
                                GROUP_SECURITY_INFORMATION,
                                NULL, NULL, NULL, NULL, &pSD);
    if (ret != ERROR_SUCCESS || !pSD) return FALSE;

    /* Duplicate current token as impersonation token */
    HANDLE hTok = NULL, hImpTok = NULL;
    BOOL result = FALSE;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &hTok))
        goto done;
    if (!DuplicateToken(hTok, SecurityImpersonation, &hImpTok))
        goto done;

    GENERIC_MAPPING gm = {
        PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_INFORMATION,
        PROCESS_VM_READ,
        PROCESS_ALL_ACCESS
    };
    MapGenericMask(&desiredAccess, &gm);

    PRIVILEGE_SET privSet;
    DWORD         psLen   = sizeof(privSet);
    DWORD         granted = 0;
    BOOL          ok      = FALSE;

    AccessCheck(pSD, hImpTok, desiredAccess, &gm, &privSet, &psLen, &granted, &ok);
    result = ok;

done:
    if (pSD)     LocalFree(pSD);
    if (hTok)    CloseHandle(hTok);
    if (hImpTok) CloseHandle(hImpTok);
    return result;
}

/* -----------------------------------------------------------------------
 * Audit a single process
 * --------------------------------------------------------------------- */
static void AuditProcess(DWORD pid, LPCWSTR exeName, DWORD *findings) {
    HANDLE hProc = OpenProcess(READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, pid);
    if (!hProc) return;

    DWORD il = GetProcessIntegrityRID(hProc);

    /* Only care about SYSTEM/High IL processes */
    if (il < SECURITY_MANDATORY_HIGH_RID) {
        CloseHandle(hProc);
        return;
    }

    /* Get account */
    wchar_t account[128] = {0};
    GetProcessUser(pid, account, _countof(account));

    /* For each dangerous access right: test if current user can get it */
    for (int i = 0; g_accessList[i].mask; i++) {
        if (CanAccessProcess(hProc, g_accessList[i].mask)) {
            Finding f;
            f.severity = g_accessList[i].sev;

            /* Escalate severity if process is SYSTEM */
            if (WcsContainsI(account, L"SYSTEM") && f.severity < SEV_CRITICAL)
                f.severity = SEV_CRITICAL;

            wcscpy(f.module, L"PROC_DACL");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] PID:%lu %s (%s)",
                g_accessList[i].name, pid, exeName, account);
            _snwprintf(f.reason, _countof(f.reason),
                L"Current user has %s access to %s process (PID %lu, IL=0x%04lX, %s).\n"
                L"        %s",
                g_accessList[i].name, exeName, pid, il, account,
                g_accessList[i].exploitNote);
            PrintFinding(&f);
            (*findings)++;
            break; /* report highest-severity access only per process */
        }
    }

    CloseHandle(hProc);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_ProcessDACL(void) {
    PrintHeader(L"PROCESS DACL AUDIT  [Weak process security descriptors → handle/memory access]");

    PrintInfo(
        L"  Checks if current user can open SYSTEM/High-IL processes with dangerous rights.\n"
        L"  DUP_HANDLE → steal tokens. VM_WRITE+CREATE_THREAD → code injection.\n"
        L"  Historical: EDR/AV products, hardware tools often misconfigure this.\n\n");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        PrintInfo(L"  [!] Cannot enumerate processes\n");
        return;
    }

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    BOOL more = Process32FirstW(hSnap, &pe);
    DWORD findings = 0, scanned = 0;

    while (more) {
        DWORD pid = pe.th32ProcessID;
        if (pid != 0 && pid != 4) {
            AuditProcess(pid, pe.szExeFile, &findings);
            scanned++;
        }
        more = Process32NextW(hSnap, &pe);
    }
    CloseHandle(hSnap);

    PrintInfo(L"  Processes scanned: %lu  |  Findings: %lu\n\n", scanned, findings);

    if (findings == 0) {
        PrintInfo(L"  No process DACL misconfigurations found (expected on hardened systems).\n");
    } else {
        PrintInfo(
            L"  EXPLOITATION (DUP_HANDLE on SYSTEM process):\n"
            L"    HANDLE hSys = OpenProcess(PROCESS_DUP_HANDLE, FALSE, <systemPid>);\n"
            L"    HANDLE hTok = NULL;\n"
            L"    DuplicateHandle(hSys, (HANDLE)0x4,  // try common handle values 4,8,12...\n"
            L"                    GetCurrentProcess(), &hTok, TOKEN_ALL_ACCESS, FALSE, 0);\n"
            L"    // If successful: CreateProcessWithTokenW(hTok, ...) → SYSTEM shell\n\n"
            L"  EXPLOITATION (VM_WRITE + CREATE_THREAD on SYSTEM process):\n"
            L"    HANDLE h = OpenProcess(PROCESS_VM_WRITE|PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION, FALSE, pid);\n"
            L"    VirtualAllocEx(h, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
            L"    WriteProcessMemory(h, baseAddr, shellcode, shellcodeLen, NULL);\n"
            L"    CreateRemoteThread(h, NULL, 0, baseAddr, NULL, 0, NULL);\n"
            L"    // shellcode executes as SYSTEM\n");
    }
}

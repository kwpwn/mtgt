/*
 * impersonate_hunter.c — Dangerous Token Privilege + Account Combination Audit
 *
 * WHY THIS MATTERS FOR 0-DAY LPE:
 *   Windows services inherit certain privileges based on their logon account.
 *   When a *non-admin* process or service-account process holds a dangerous
 *   privilege, the entire OS class of attack built around that privilege
 *   becomes reachable from medium integrity.
 *
 *   This is NOT just a "known exploit" scanner — it maps the RESEARCH SURFACE:
 *   any service with SeImpersonatePrivilege is a potential NEW Potato variant
 *   if the known trigger mechanisms are patched or unavailable.
 *
 * DANGEROUS PRIVILEGE CLASSES:
 *
 *  [CRITICAL]
 *   SeTcbPrivilege          — "Trusted Computer Base". Can call LsaLogonUser,
 *                             NtCreateToken, bypass security checks. Essentially
 *                             SYSTEM. Should NEVER appear outside lsass/winlogon.
 *
 *   SeCreateTokenPrivilege  — Create arbitrary access tokens via NtCreateToken().
 *                             Can manufacture a SYSTEM token from scratch.
 *
 *   SeDebugPrivilege        — OpenProcess(PROCESS_ALL_ACCESS) on any process.
 *                             Inject into lsass → dump credentials. Or inject
 *                             shellcode into a SYSTEM process.
 *
 *  [HIGH]
 *   SeImpersonatePrivilege  — The "Potato" privilege. Can impersonate any
 *                             security context. Combine with: fake named pipe /
 *                             fake COM server → trick SYSTEM to authenticate →
 *                             impersonate → SYSTEM shell.
 *                             GodPotato, PrintSpoofer, RoguePotato, etc.
 *                             HIGH VALUE if process = NetworkService/LocalService.
 *
 *   SeAssignPrimaryToken    — Assign a primary token to a spawned process.
 *                             Combine with SeImpersonate: impersonate SYSTEM →
 *                             get token → CreateProcessAsUser() with SYSTEM token.
 *
 *   SeLoadDriverPrivilege   — NtLoadDriver() with an arbitrary driver path.
 *                             Load custom .sys → kernel read/write → SYSTEM.
 *                             Requires: writable registry path for driver config.
 *                             CVE-2019-1388 class (not BYOVD — load NEW driver).
 *
 *   SeRestorePrivilege      — Write any file regardless of DACL/ownership.
 *                             NtCreateFile with FILE_OPEN_FOR_BACKUP_INTENT.
 *                             Replace DLL in System32, write registry hives (SAM).
 *
 *  [MEDIUM]
 *   SeBackupPrivilege       — Read any file regardless of DACL.
 *                             Read SAM/SECURITY/SYSTEM hives → offline cred crack.
 *
 *   SeTakeOwnershipPrivilege— Take ownership of any object.
 *                             Own a SYSTEM file → change ACL → replace it.
 *
 *   SeRelabelPrivilege      — Change mandatory integrity label (MIC).
 *                             Lower integrity label on High-IL object → bypass UAC.
 *
 *   SeCreateSymbolicLink    — Create kernel-mode symlinks without admin.
 *                             Use for junction/symlink attacks against SYSTEM writes.
 *
 *   SeManageVolumePrivilege — Bypass file system checks for volume-level access.
 *                             Can map/read raw disk sectors.
 *
 * ACCOUNT CONTEXT:
 *   The same privilege means different things in different contexts:
 *
 *   NetworkService + SeImpersonate → Potato (high priority target)
 *   LocalService   + SeImpersonate → Potato (high priority target)
 *   Regular user   + SeDebug       → CRITICAL misconfiguration (immediate LPE)
 *   Regular user   + SeLoadDriver  → Kernel driver load (immediate LPE)
 *   Any            + SeTcb         → CRITICAL (should never appear here)
 *
 * COMPILE: advapi32 only (already in build.bat)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Dangerous privilege table
 * --------------------------------------------------------------------- */
typedef struct {
    LPCWSTR privName;
    LPCWSTR shortLabel;
    Severity sevAlways;      /* severity regardless of account */
    Severity sevInSvcAcct;   /* extra severity if account = NetworkSvc/LocalSvc */
    LPCWSTR exploitNote;
} DangerousPriv;

static const DangerousPriv g_dangerousPrivs[] = {
    {
        L"SeTcbPrivilege", L"SeTcb",
        SEV_CRITICAL, SEV_CRITICAL,
        L"Trusted Computer Base. Can call LsaLogonUser/NtCreateToken. "
        L"NEVER expected outside lsass/winlogon — flag immediately. "
        L"Exploit: NtCreateToken() with SYSTEM SID → arbitrary token."
    },
    {
        L"SeCreateTokenPrivilege", L"SeCreateToken",
        SEV_CRITICAL, SEV_CRITICAL,
        L"Create arbitrary access tokens via NtCreateToken(). "
        L"Build SYSTEM token from scratch. Combine with SeAssignPrimary "
        L"→ spawn SYSTEM process with no prior privilege."
    },
    {
        L"SeDebugPrivilege", L"SeDebug",
        SEV_CRITICAL, SEV_CRITICAL,
        L"OpenProcess(PROCESS_ALL_ACCESS) on ANY process including SYSTEM. "
        L"Write shellcode into lsass / winlogon → SYSTEM code exec. "
        L"Or: DuplicateHandle on SYSTEM token → CreateProcessWithToken."
    },
    {
        L"SeImpersonatePrivilege", L"SeImpersonate",
        SEV_MEDIUM, SEV_HIGH,
        L"Potato attack surface: trick SYSTEM to authenticate to a fake pipe/COM "
        L"server, then ImpersonateNamedPipeClient / DuplicateToken → SYSTEM. "
        L"Trigger: PrintSpoofer (SpoolSample), GodPotato (BITS coerce), "
        L"RoguePotato (OXID resolver), EfsPotato (EFS coerce). "
        L"Research: new coercion paths via undocumented SYSTEM→pipe auth flows."
    },
    {
        L"SeAssignPrimaryTokenPrivilege", L"SeAssignPrimary",
        SEV_HIGH, SEV_HIGH,
        L"Assign primary token to new process via CreateProcessAsUser(). "
        L"Combine with SeImpersonate: impersonate SYSTEM → duplicate token "
        L"→ CreateProcessAsUser(dupToken, ...) → SYSTEM shell."
    },
    {
        L"SeLoadDriverPrivilege", L"SeLoadDriver",
        SEV_HIGH, SEV_HIGH,
        L"Load kernel driver via NtLoadDriver(). "
        L"Write driver config to HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>, "
        L"set ImagePath to attacker .sys → NtLoadDriver → kernel r/w → SYSTEM. "
        L"Note: different from BYOVD — this LOADS a new driver, not uses existing."
    },
    {
        L"SeRestorePrivilege", L"SeRestore",
        SEV_HIGH, SEV_HIGH,
        L"Write any file ignoring DACL via NtCreateFile(FILE_OPEN_FOR_BACKUP_INTENT). "
        L"Replace DLLs in System32, overwrite registry hives (SAM/SECURITY), "
        L"write to files owned by TrustedInstaller. No ACL check applies."
    },
    {
        L"SeBackupPrivilege", L"SeBackup",
        SEV_MEDIUM, SEV_MEDIUM,
        L"Read any file ignoring DACL (backup semantics). "
        L"Read C:\\Windows\\System32\\config\\SAM → offline NTLM crack. "
        L"Read DPAPI master keys, private keys, cached domain credentials."
    },
    {
        L"SeTakeOwnershipPrivilege", L"SeTakeOwnership",
        SEV_MEDIUM, SEV_HIGH,
        L"Take ownership of any securable object via SetSecurityInfo(OWNER_SECURITY_INFORMATION). "
        L"Own a SYSTEM32 DLL → change DACL → replace with payload. "
        L"Own registry key → write new startup entry."
    },
    {
        L"SeRelabelPrivilege", L"SeRelabel",
        SEV_MEDIUM, SEV_HIGH,
        L"Change mandatory integrity level (MIL) of any object. "
        L"Lower MIL of High-integrity object to Medium → bypass UAC for that object. "
        L"Or raise MIL of attacker file → force SYSTEM to trust it."
    },
    {
        L"SeCreateSymbolicLinkPrivilege", L"SeCreateSymlink",
        SEV_MEDIUM, SEV_MEDIUM,
        L"Create NTFS/object-namespace symbolic links without admin privilege. "
        L"Typically admin-only on Win10+. If present on non-admin: "
        L"object symlink + junction attack against SYSTEM file writes (TOCTOU)."
    },
    {
        L"SeManageVolumePrivilege", L"SeManageVolume",
        SEV_MEDIUM, SEV_MEDIUM,
        L"Bypass filesystem security for volume-level access. "
        L"Can map/read/write raw disk sectors via FSCTL_ALLOW_EXTENDED_DASD_IO. "
        L"Logic bug research: NTFS parsing vulnerabilities reachable from userland."
    },
    { NULL, NULL, 0, 0, NULL }
};

/* -----------------------------------------------------------------------
 * Well-known SID helpers
 * --------------------------------------------------------------------- */
static BOOL SidIsWellKnown(PSID sid, WELL_KNOWN_SID_TYPE type) {
    BYTE buf[SECURITY_MAX_SID_SIZE];
    DWORD len = sizeof(buf);
    if (!CreateWellKnownSid(type, NULL, buf, &len)) return FALSE;
    return EqualSid(sid, buf);
}

/* Returns a short string for the process account context */
static const wchar_t *AccountLabel(PSID userSid) {
    if (SidIsWellKnown(userSid, WinLocalSystemSid))         return L"NT AUTHORITY\\SYSTEM";
    if (SidIsWellKnown(userSid, WinNetworkServiceSid))      return L"NT AUTHORITY\\NetworkService";
    if (SidIsWellKnown(userSid, WinLocalServiceSid))        return L"NT AUTHORITY\\LocalService";
    if (SidIsWellKnown(userSid, WinBuiltinAdministratorsSid)) return L"BUILTIN\\Administrators";
    return L"(user account)";
}

/* Returns TRUE if this SID is a service-account (NetworkSvc or LocalSvc) */
static BOOL IsServiceAccount(PSID sid) {
    return SidIsWellKnown(sid, WinNetworkServiceSid) ||
           SidIsWellKnown(sid, WinLocalServiceSid);
}

/* Returns TRUE if this SID is a non-privileged user (not SYSTEM, not Admins) */
static BOOL IsUnprivilegedUser(PSID sid) {
    return !SidIsWellKnown(sid, WinLocalSystemSid) &&
           !SidIsWellKnown(sid, WinBuiltinAdministratorsSid) &&
           !SidIsWellKnown(sid, WinNetworkServiceSid) &&
           !SidIsWellKnown(sid, WinLocalServiceSid);
}

/* -----------------------------------------------------------------------
 * Check if a privilege LUID is enabled OR present (available) in the token.
 * Returns 0 = not present, 1 = present but disabled, 2 = enabled.
 * --------------------------------------------------------------------- */
static int PrivilegeState(HANDLE hToken, LPCWSTR privName) {
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privName, &luid)) return 0;

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &needed);
    if (!needed) return 0;

    PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!pPrivs) return 0;

    int result = 0;
    if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, needed, &needed)) {
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
            if (pPrivs->Privileges[i].Luid.LowPart == luid.LowPart &&
                pPrivs->Privileges[i].Luid.HighPart == luid.HighPart)
            {
                result = (pPrivs->Privileges[i].Attributes &
                          SE_PRIVILEGE_ENABLED) ? 2 : 1;
                break;
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, pPrivs);
    return result;
}

/* -----------------------------------------------------------------------
 * Audit a single process token for dangerous privileges
 * --------------------------------------------------------------------- */
static void AuditProcessPrivileges(DWORD pid, LPCWSTR exeName,
                                   DWORD *findings)
{
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        return;
    }

    /* Get the token user SID */
    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
    PTOKEN_USER pUser = (PTOKEN_USER)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!pUser) { CloseHandle(hToken); CloseHandle(hProc); return; }

    if (!GetTokenInformation(hToken, TokenUser, pUser, needed, &needed)) {
        HeapFree(GetProcessHeap(), 0, pUser);
        CloseHandle(hToken);
        CloseHandle(hProc);
        return;
    }

    PSID userSid = pUser->User.Sid;
    const wchar_t *acctLabel = AccountLabel(userSid);
    BOOL isSvcAcct   = IsServiceAccount(userSid);
    BOOL isUnprivUser = IsUnprivilegedUser(userSid);
    BOOL isSystem    = SidIsWellKnown(userSid, WinLocalSystemSid);

    /* Skip pure SYSTEM processes — we expect them to have dangerous privs */
    if (isSystem) {
        HeapFree(GetProcessHeap(), 0, pUser);
        CloseHandle(hToken);
        CloseHandle(hProc);
        return;
    }

    /* Check each dangerous privilege */
    for (int i = 0; g_dangerousPrivs[i].privName; i++) {
        int state = PrivilegeState(hToken, g_dangerousPrivs[i].privName);
        if (state == 0) continue;  /* not present */

        const DangerousPriv *dp = &g_dangerousPrivs[i];

        /* Compute effective severity */
        Severity sev;
        if (isUnprivUser) {
            /* Regular user with dangerous priv = misconfiguration → always critical/high */
            sev = (dp->sevAlways < SEV_HIGH) ? SEV_HIGH : dp->sevAlways;
        } else if (isSvcAcct) {
            sev = dp->sevInSvcAcct;
        } else {
            sev = dp->sevAlways;
        }

        /* SeImpersonate in a non-service account is lower priority */
        if (_wcsicmp(dp->privName, L"SeImpersonatePrivilege") == 0 && !isSvcAcct)
            sev = SEV_LOW;  /* expected for admin processes, not interesting */

        if (sev == SEV_LOW || sev == SEV_INFO) continue; /* filter noise */

        Finding f;
        f.severity = sev;
        wcscpy(f.module, L"IMPERSONATE");
        _snwprintf(f.target, _countof(f.target),
            L"[%s] PID:%lu %s (%s)",
            dp->shortLabel, pid, exeName, acctLabel);
        _snwprintf(f.reason, _countof(f.reason),
            L"%s [%s]  Account: %s  "
            L"Exploit: %s",
            dp->privName,
            state == 2 ? L"ENABLED" : L"present/adjustable",
            acctLabel,
            dp->exploitNote);
        PrintFinding(&f);
        (*findings)++;
    }

    /* Special combo: SeBackup + SeRestore together = full filesystem access */
    int hasBackup   = PrivilegeState(hToken, L"SeBackupPrivilege");
    int hasRestore  = PrivilegeState(hToken, L"SeRestorePrivilege");
    if (hasBackup && hasRestore && !isSystem) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"IMPERSONATE");
        _snwprintf(f.target, _countof(f.target),
            L"[SeBackup+SeRestore COMBO] PID:%lu %s (%s)",
            pid, exeName, acctLabel);
        _snwprintf(f.reason, _countof(f.reason),
            L"Both SeBackup and SeRestore are present. "
            L"Combination = read ANY file (backup) + write ANY file (restore) "
            L"regardless of DACL/ownership. "
            L"Attack: (1) read SAM/SECURITY hives via backup semantics "
            L"→ offline NTLM hash extraction. "
            L"(2) Use restore to write payload to System32 or replace service binary.");
        PrintFinding(&f);
        (*findings)++;
    }

    HeapFree(GetProcessHeap(), 0, pUser);
    CloseHandle(hToken);
    CloseHandle(hProc);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_ImpersonateHunter(void) {
    PrintHeader(
        L"DANGEROUS TOKEN PRIVILEGE AUDIT  [Logic-bug LPE surface]");

    PrintInfo(
        L"  Enumerates ALL running processes for dangerous token privileges.\n"
        L"  Focus: service accounts (NetworkService/LocalService) with SeImpersonate\n"
        L"  = Potato-class attack surface. Also: any non-SYSTEM process with\n"
        L"  SeDebug / SeLoadDriver / SeCreateToken = immediate LPE path.\n\n");

    PrintInfo(
        L"  ACCOUNT CONTEXT LEGEND:\n"
        L"    NetworkService/LocalService + SeImpersonate → Potato family\n"
        L"    Any user + SeDebug/SeTcb/SeCreateToken → CRITICAL (should not exist)\n"
        L"    Any + SeLoadDriver → load kernel .sys → SYSTEM\n"
        L"    Any + SeRestore → overwrite System32 DLLs\n\n");

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        PrintInfo(L"  [!] Cannot enumerate processes\n");
        return;
    }

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    BOOL more = Process32FirstW(hSnap, &pe);
    DWORD findings = 0;

    while (more) {
        DWORD pid = pe.th32ProcessID;
        if (pid == 0 || pid == 4) { more = Process32NextW(hSnap, &pe); continue; }

        AuditProcessPrivileges(pid, pe.szExeFile, &findings);
        more = Process32NextW(hSnap, &pe);
    }
    CloseHandle(hSnap);

    if (findings == 0)
        PrintInfo(L"  No unexpected dangerous privileges found.\n");
    else
        PrintInfo(L"\n  Total findings: %lu\n", findings);

    PrintInfo(
        L"\n"
        L"  EXPLOITATION NOTES:\n"
        L"  SeImpersonate (Potato variants):\n"
        L"    GodPotato:     coerce SYSTEM via BITS service CLSID call → ALPC → impersonate\n"
        L"    PrintSpoofer:  coerce spoolsv.exe → named pipe auth → ImpersonateNamedPipeClient\n"
        L"    RoguePotato:   OXID resolver redirect → DCOM auth → token steal\n"
        L"    EfsPotato:     EFS RPC → ALPC channel → SYSTEM impersonation\n"
        L"    Research target: ANY new RPC/ALPC path where SYSTEM authenticates to\n"
        L"    a user-controlled endpoint. The trigger mechanism is the 0-day surface.\n\n"
        L"  SeLoadDriverPrivilege path:\n"
        L"    1. Write reg: HKCU\\System\\CurrentControlSet\\Services\\<name>\\ImagePath\n"
        L"       (or HKLM if you have write access)\n"
        L"    2. NtLoadDriver(L\"\\\\Registry\\\\Machine\\\\SYSTEM\\\\...\\\\ <name>\")\n"
        L"    3. Driver loaded in kernel → SYSTEM r/w primitive\n\n"
        L"  SeRestorePrivilege path:\n"
        L"    NtCreateFile(path, GENERIC_WRITE, ..., FILE_OPEN_FOR_BACKUP_INTENT)\n"
        L"    → ignores DACL → write arbitrary SYSTEM files\n");
}

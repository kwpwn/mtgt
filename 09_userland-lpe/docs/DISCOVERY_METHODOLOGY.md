# LPE Discovery Methodology

Systematic approach to finding privilege escalation opportunities: tool chain, manual
enumeration checklist, ProcMon filter recipes, Ferrum integration, and building custom
enumeration for specific environments.

---

## 1. Phases of LPE Discovery

```
Phase 1: Situational Awareness
    Who am I? What's my context? What process/service am I running in?
    
Phase 2: Automated Enumeration
    Run tooling to scan for common misconfigs quickly
    
Phase 3: Manual Investigation
    Deep-dive into promising leads from Phase 2
    
Phase 4: Dynamic Observation
    ProcMon / Sysmon: watch for runtime-only opportunities
    
Phase 5: Validation
    Confirm exploitability before attempting execution
```

---

## 2. Phase 1: Situational Awareness

### Current Identity and Context

```powershell
# Current user and privileges:
whoami /all          → user SID, group memberships, ALL privileges (enabled and disabled)
whoami /priv         → just privileges (check for dangerous ones)
whoami /groups       → current group memberships

# Token integrity level:
whoami /groups | findstr /i "integrity"
# S-1-16-4096 = Low  | S-1-16-8192 = Medium | S-1-16-12288 = High | S-1-16-16384 = System

# Session info:
query session        → RDP / console sessions
query user           → logged in users

# Network context:
ipconfig /all        → IP addresses, DNS, domain
net config workstation → domain membership, logon server
```

### First-Look Privilege Assessment

```
SeImpersonatePrivilege present?
    → Potato family immediately applicable
    → PrintSpoofer if Spooler running
    → GodPotato (works broadly)

SeDebugPrivilege present?
    → Token theft from any SYSTEM process
    → LSASS dump

SeLoadDriverPrivilege present?
    → BYOVD path (see 03_byovd/)
    → Load vulnerable signed driver → kernel exploit

SeBackupPrivilege present?
    → Read SAM hive → hash extraction → pass-the-hash
```

### Environment Survey

```
# OS version (affects technique applicability):
systeminfo | findstr /i "OS Name\|OS Version\|Build Type\|System Type"

# Current directory and PATH:
echo %CD%
echo %PATH%

# Interesting environment variables:
set | findstr /i "path\|tmp\|temp\|profiler\|cor_\|proc"

# What processes are running:
tasklist /V          → process list with user column
tasklist /svc        → processes with services they host
```

---

## 3. Phase 2: Automated Enumeration

### Tool Priority Order

For speed, run in this order (fastest to most comprehensive):

```
1. whoami /all              → 5 seconds → reveals dangerous privileges immediately
2. Ferrum.exe --ALL         → 30-60 seconds → broad surface scan
3. WinPEAS.exe              → 2-5 minutes → comprehensive, noisy
4. PowerUp.ps1 Invoke-AllChecks → 1-2 minutes → service/DLL/registry focused
5. Seatbelt.exe -group=all  → 2-3 minutes → token, COM, environment
```

### Ferrum — What Each Module Adds

```
ferrum.exe --CLSID    → COM hijack candidates (elevated process + missing HKCU CLSIDs)
ferrum.exe --dllsearch → writable %PATH% dirs, KnownDLLs context
ferrum.exe --services  → unquoted paths, weak ACLs, writable dirs
ferrum.exe --tokens    → processes with dangerous privileges (scoring system)
ferrum.exe --pipes     → security-relevant named pipes present
ferrum.exe --registry  → writable service keys, AlwaysInstallElevated, Winlogon values
ferrum.exe --scheduled → writable task files/binaries, task binary in writable dir
ferrum.exe --drivers   → user-writable driver paths, boot/system drivers
ferrum.exe --env       → PATH analysis, COR_PROFILER, user environment vars
ferrum.exe --advanced  → additional heuristics
ferrum.exe --ALL --OUTPUT report.txt  → run everything, save to file
```

### WinPEAS — Key Sections

```
winpeas.exe systeminfo     → OS, hotfixes, environment
winpeas.exe servicesinfo   → service misconfigs
winpeas.exe applicationsinfo → installed software with version info
winpeas.exe networkinfo    → network + firewall
winpeas.exe windowscreds   → credential stores
winpeas.exe processinfo    → running processes
winpeas.exe all            → everything (generates a lot of output)
```

### PowerUp — Focused Service/Privilege Checks

```powershell
Import-Module PowerUp.ps1

# Service checks:
Get-ServiceUnquoted               → unquoted paths
Get-ModifiableServiceFile         → writable service binaries
Get-ModifiableService             → weak service DACLs
Write-ServiceBinary -ServiceName X -UserName backdoor -Password P@ss

# Registry:
Get-RegistryAlwaysInstallElevated → AlwaysInstallElevated check
Get-RegistryAutoRun               → autorun registry entries with writable paths

# DLL:
Find-DLLHijack                    → DLL hijacking opportunities
Find-PathHijack                   → writable directories in %PATH%

# Token:
Get-ProcessTokenPrivilege         → token privileges for all processes
```

### Seatbelt — Token and COM Focused

```
Seatbelt.exe TokenPrivileges     → current token + dangerous privs
Seatbelt.exe ProcessCreationEvents → recent process events
Seatbelt.exe PowerShellEvents    → PowerShell history
Seatbelt.exe COMAutoElevations   → auto-elevation COM CLSIDs
Seatbelt.exe EnvironmentPath     → PATH analysis
Seatbelt.exe ScheduledTasks      → scheduled task enumeration
Seatbelt.exe LocalUsers          → local user accounts
```

---

## 4. Phase 3: Manual Investigation

### Service Manual Audit

```
# 1. List all services with binary paths:
sc.exe query type= all state= all | findstr /i "service name"
foreach service: sc.exe qc <name>  ← check binary path and account

# 2. Unquoted path check (look for spaces without quotes):
wmic service get name,pathname,startmode | findstr /i "auto"
# → Flag: any path with spaces NOT enclosed in quotes

# 3. Service DACL (SDDL) check:
sc.exe sdshow <service>
# Decode SDDL: look for RP (read properties), WP (write properties), CC (change config)
# to non-admin SIDs (BU=Builtin Users, AU=Authenticated Users, WD=World/Everyone)

# 4. Binary ACL check:
icacls "C:\path\to\service.exe"
# Look for: Users:(W) / Everyone:(M) / Authenticated Users:(F)

# 5. Directory ACL check:
icacls "C:\path\to\service_directory"
# Look for write access for non-admins

# Automate with accesschk:
accesschk.exe -ucwqv "Authenticated Users" *    ← service DACL
accesschk.exe -uwq "Authenticated Users" "C:\Program Files"  ← binary dirs
```

### COM Manual Audit

```
# List all CLSIDs in HKLM with InprocServer32:
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" | ForEach-Object {
    $clsid = $_.PSChildName
    $inproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
    if ($inproc) {
        $hkcuPath = "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32"
        if (-not (Test-Path $hkcuPath)) {
            [PSCustomObject]@{
                CLSID = $clsid
                DLL = $inproc.'(default)'
            }
        }
    }
} | Export-Csv "com_candidates.csv"

# Auto-elevation CLSIDs:
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" | ForEach-Object {
    $elevPath = "$($_.PSPath)\Elevation"
    if (Test-Path $elevPath) {
        $enabled = (Get-ItemProperty $elevPath -ErrorAction SilentlyContinue).Enabled
        if ($enabled -eq 1) {
            Write-Host "Auto-elevate CLSID: $($_.PSChildName)"
        }
    }
}
```

### Registry Manual Audit

```
# Service keys writable:
accesschk.exe -kvusq "Authenticated Users" HKLM\SYSTEM\CurrentControlSet\Services

# Autorun paths:
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# AlwaysInstallElevated:
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul

# Winlogon:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# AppInit:
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs
```

### Scheduled Task Manual Audit

```powershell
# All tasks with their actions and principals:
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $info = Get-ScheduledTaskInfo $_.TaskName $_.TaskPath -ErrorAction SilentlyContinue
    $actions = $_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
    $principal = $_.Principal
    [PSCustomObject]@{
        Name = $task.TaskName
        Path = $task.TaskPath
        Principal = $principal.UserId
        RunLevel = $principal.RunLevel
        Actions = $actions -join '; '
        State = $task.State
        LastRun = $info.LastRunTime
    }
} | Where-Object { $_.Principal -match "SYSTEM|S-1-5-18" } | Format-Table

# Check task XML file ACLs:
Get-ChildItem "C:\Windows\System32\Tasks\" -Recurse -File | ForEach-Object {
    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
    if ($acl.Access | Where-Object {
        $_.IdentityReference -match "Users|Everyone" -and
        $_.FileSystemRights -match "Write|Modify|FullControl"
    }) {
        Write-Host "[WRITABLE TASK] $($_.FullName)"
    }
}
```

---

## 5. Phase 4: Dynamic Observation (ProcMon)

ProcMon reveals runtime-only attack surfaces that static enumeration misses.

### Setup ProcMon for LPE Research

```
1. Run ProcMon as Administrator (or from SYSTEM context for full coverage)
2. Clear existing events (Ctrl+X)
3. Set up filters before capturing (reduces noise)
4. Trigger target activity (interact with elevated app, wait for scheduled event)
5. Stop capture
6. Export to CSV for programmatic analysis
```

### Filter Recipe 1: COM Hijack Discovery

```
Operation = RegOpenKey           → Include
Result = NAME NOT FOUND          → Include
Path contains CLSID              → Include
Path contains HKCU               → Include

→ Shows: elevated processes looking up CLSIDs in HKCU that don't exist
→ Each row = COM hijack candidate
```

### Filter Recipe 2: DLL/File Not Found

```
Operation = CreateFile           → Include
Result = NAME NOT FOUND          → Include
Path ends with .dll              → Include
Process Name = <target>          → Include (optional, to focus)

→ Shows: phantom DLL loads (DLL that doesn't exist → plant it)
```

### Filter Recipe 3: Elevated Process Registry Writes (Monitoring for Timing)

```
Operation = RegSetValue          → Include
Process Name ≠ svchost.exe       → Include (exclude noisy service host)
User = SYSTEM                    → Include

→ Shows: what SYSTEM-level processes are writing to registry
→ If writing to user-accessible locations → persistence/hijack opportunity
```

### Filter Recipe 4: File System Access by SYSTEM Processes

```
Operation = WriteFile            → Include
Path contains Users              → Include  ← SYSTEM writing into user dirs (unusual)
OR
Path contains ProgramData        → Include

→ Shows: SYSTEM processes writing to user-accessible paths
→ If writing a DLL or EXE → potential replacement target
```

### Filter Recipe 5: Service Binary Path Audit (Startup)

```
Capture at system startup or service start.
Operation = Process Start        → Include
Parent Process = services.exe    → Include

→ Shows: every process launched by SCM (service start)
→ Verify each path is in System32/Program Files (not user-writable)
→ Anomalies = potential unquoted path or writable binary issues
```

### Analyzing ProcMon Output Programmatically

After saving as CSV:
```python
import pandas as pd

df = pd.read_csv('procmon_log.csv')

# COM hijack candidates:
com_misses = df[
    (df['Operation'] == 'RegOpenKey') &
    (df['Result'] == 'NAME NOT FOUND') &
    (df['Path'].str.contains('HKCU')) &
    (df['Path'].str.contains('CLSID'))
]

# Get unique CLSIDs:
com_misses['CLSID'] = com_misses['Path'].str.extract(r'\{([0-9A-Fa-f-]+)\}')
print(com_misses.groupby(['Process Name', 'CLSID']).size())

# Phantom DLL candidates:
dll_misses = df[
    (df['Operation'] == 'CreateFile') &
    (df['Result'] == 'NAME NOT FOUND') &
    (df['Path'].str.endswith('.dll'))
]
print(dll_misses[['Process Name', 'Path']].drop_duplicates())
```

---

## 6. Validation Checklist

Before attempting exploitation, validate:

### Service Misconfiguration
```
[ ] Service runs as SYSTEM or elevated account (not just any user)
[ ] Attacker can restart the service (SERVICE_STOP + SERVICE_START, or wait for reboot)
[ ] For unquoted path: parent directory actually writable (icacls confirms)
[ ] For DACL: SERVICE_CHANGE_CONFIG confirmed, not just SERVICE_START
[ ] For binary replace: binary file writable confirmed (can actually write, not just icacls says so)
```

### COM Hijacking
```
[ ] Target process runs at SYSTEM or High integrity
[ ] CLSID has InprocServer32 in HKLM (not LocalServer32 → harder)
[ ] HKCU entry doesn't exist (or ours would override)
[ ] Can reliably trigger COM activation (UI interaction, scheduled event, etc.)
[ ] ThreadingModel is Apartment or Both (compatible with target's apartment)
[ ] Test with stub DLL: does process survive DllGetClassObject returning E_NOTIMPL?
```

### DLL Hijacking
```
[ ] Target DLL is NOT in KnownDLLs
[ ] Target binary directory is actually writable (not just appears so in icacls)
[ ] Process we're targeting runs elevated
[ ] Can trigger the load (process restarts, feature activation)
[ ] Proxy DLL needed? (enumerate real DLL exports first)
```

### Token Abuse
```
[ ] SeImpersonatePrivilege: is Print Spooler running? (net start | findstr Spooler)
[ ] SeLoadDriverPrivilege: can we create HKCU\System\CurrentControlSet\Services\X?
[ ] SeDebugPrivilege: is there a SYSTEM process without PPL we can open?
```

### Registry
```
[ ] AlwaysInstallElevated: both HKLM AND HKCU keys must be = 1
[ ] Service key writable: verify with reg add test (use benign value name to test write)
```

---

## 7. Environment-Specific Adjustments

### IIS / Web Application Context

```
Identity: IIS APPPOOL\DefaultAppPool or NETWORK SERVICE
Key checks:
  1. whoami /priv → SeImpersonatePrivilege (almost always present)
  2. Immediately try PrintSpoofer / GodPotato
  3. If AppPool is Custom Identity → check that account's privileges/group membership

Path:
  SeImpersonatePrivilege → PrintSpoofer → SYSTEM shell
  From SYSTEM → add admin user or dump credentials
```

### SQL Server Context

```
Identity: NT SERVICE\MSSQLSERVER or sa (if misconfigured)
Key checks:
  1. SeImpersonatePrivilege (default for MSSQLSERVER account)
  2. xp_cmdshell enabled? → already shell execution (not LPE per se but useful)
  3. Can we enable xp_cmdshell? EXECUTE AS LOGIN with sysadmin role

Path:
  EXEC xp_cmdshell 'PrintSpoofer.exe -c cmd.exe'
  → SYSTEM shell via SQL Server
```

### Windows Service (Custom Business App)

```
Identity: varies — custom local/domain account
Key checks:
  1. What groups is the service account in?
  2. What privileges does it have? (Process Hacker → token → service process)
  3. Is there an interactive session we can inject into?
  4. What's the service binary's directory ACL?
  5. What DLLs does the service load? Any phantom DLLs?

Path depends heavily on what the service account has.
```

### Domain User (Standard)

```
Identity: DOMAIN\user
Key checks:
  1. Local admin? (net localgroup administrators)
  2. Any group with dangerous rights? (Backup Operators, Print Operators)
  3. Local service misconfigs (independent of domain)
  4. Kerberoastable? (separate attack vector)
  5. GPO-pushed software with misconfigs?
```

---

## 8. Documenting Findings

For each finding, document:

```
Technique: [service misconfiguration / COM hijacking / DLL hijacking / token abuse / etc.]
Target: [which service/process/component]
Vulnerable Component: [specific file path / registry key / CLSID]
Prerequisite: [what context is needed]
Trigger: [how to activate the exploit]
Impact: [SYSTEM / High integrity / specific account]
Reliability: [always / intermittent / boot-time only]
Detection risk: [events generated, AV/EDR response expected]
Windows versions affected: [build range]
Mitigation: [what would fix it]
```

---

## 9. Building a Custom Enumerator

For environments where you can't run known tools (EDR blocks them):

### Minimal PowerShell LPE Checker

```powershell
# Runs with no external dependencies, pure PowerShell built-ins

function Check-LPE {
    Write-Host "=== TOKEN PRIVILEGES ==="
    $priv = (whoami /priv 2>$null) -join "`n"
    foreach ($p in @("SeImpersonatePrivilege","SeDebugPrivilege","SeLoadDriverPrivilege",
                      "SeTcbPrivilege","SeBackupPrivilege","SeRestorePrivilege")) {
        if ($priv -match $p) { Write-Host "[DANGEROUS] $p found!" }
    }
    
    Write-Host "`n=== ALWAYSINSTALLELEVATED ==="
    $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($hklm -eq 1 -and $hkcu -eq 1) { Write-Host "[VULN] AlwaysInstallElevated is ON!" }
    
    Write-Host "`n=== UNQUOTED SERVICE PATHS ==="
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' '
    } | ForEach-Object { Write-Host "[UNQUOTED] $($_.Name): $($_.PathName)" }
    
    Write-Host "`n=== WRITABLE SERVICE BINARIES ==="
    Get-WmiObject Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
        $exe = ($_.PathName -replace '"','').Trim() -replace ' .*',''
        if ($exe -and (Test-Path $exe)) {
            try {
                $stream = [System.IO.File]::OpenWrite($exe)
                $stream.Close()
                Write-Host "[WRITABLE] $($_.Name): $exe"
            } catch {}
        }
    }
    
    Write-Host "`n=== WRITABLE PATH DIRECTORIES ==="
    $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) } | ForEach-Object {
        try {
            $testfile = Join-Path $_ "lpe_test_$(Get-Random).tmp"
            [System.IO.File]::WriteAllText($testfile, "test")
            Remove-Item $testfile -ErrorAction SilentlyContinue
            Write-Host "[WRITABLE PATH] $_"
        } catch {}
    }
    
    Write-Host "`n=== SPOOLER STATUS ==="
    $spooler = Get-Service Spooler -ErrorAction SilentlyContinue
    if ($spooler.Status -eq "Running") { Write-Host "[POTATO TARGET] Print Spooler is Running" }
}

Check-LPE
```

---

## 10. Quick Reference: What Tool Finds What

```
Technique                    → Best Tool
─────────────────────────────────────────────────────────────────
SeImpersonatePrivilege       → whoami /priv (instant)
Unquoted service path        → PowerUp: Get-ServiceUnquoted
                               WinPEAS: servicesinfo
                               Ferrum: --services
Weak service DACL            → accesschk -ucwqv "Users" *
                               PowerUp: Get-ModifiableService
Writable service binary      → accesschk -uwq + PowerUp: Get-ModifiableServiceFile
COM hijack candidates        → ProcMon (filter: CLSID + HKCU + NAME NOT FOUND)
                               Ferrum: --CLSID
Auto-elevation COM CLSIDs    → Seatbelt: COMAutoElevations
                               OleViewDotNet
Phantom DLLs                 → ProcMon (filter: .dll + NAME NOT FOUND)
Writable %PATH% dirs         → Ferrum: --dllsearch | --env
                               PowerUp: Find-PathHijack
AlwaysInstallElevated        → reg query (2 keys)
                               PowerUp: Get-RegistryAlwaysInstallElevated
Writable task binaries       → Ferrum: --scheduled
                               Custom PowerShell (section 9)
Named pipe surface           → Ferrum: --pipes | pipelist.exe
                               accesschk -w \Pipe\
Dangerous token privileges   → Ferrum: --tokens (with scores)
                               Seatbelt: TokenPrivileges
Writable service registry    → accesschk -kvusq "Users" HKLM\...\Services
                               Ferrum: --registry
```

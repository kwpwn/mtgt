# Scheduled Task Abuse — Deep Dive

Windows Task Scheduler architecture, task XML format, permission model, and all LPE vectors:
writable task files, binary hijacking via tasks, task registration exploitation, and
environment/DLL hijack via task execution context.

---

## 1. Task Scheduler Architecture

### Components

**Task Scheduler Service** (`svchost.exe -k netsvcs`, service name: `Schedule`):
- Runs as SYSTEM
- Reads task definitions from `C:\Windows\System32\Tasks\` (XML files)
- Monitors trigger conditions (time, event, logon, startup, etc.)
- Launches task processes using the configured user account
- Exposes COM interface (`ITaskService`) and legacy interface for management

**Task definition storage**:
- Modern tasks: `C:\Windows\System32\Tasks\<TaskPath>` (XML files)
- Legacy tasks (Win2000/XP): `C:\Windows\Tasks\<name>.job` (binary format)
- Also stored in registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`

**API layers**:
- Modern API: `ITaskService` → `ITaskFolder` → `ITaskDefinition` (Task Scheduler 2.0, Vista+)
- Legacy API: `ITaskScheduler` (Task Scheduler 1.0)
- Command line: `schtasks.exe`
- PowerShell: `ScheduledTasks` module (`Get-ScheduledTask`, `Register-ScheduledTask`)

### Task Execution Flow

```
Trigger fires (time reached / event occurs / user logon)
    │
    └── Schedule service (SYSTEM) reads task XML
            │
            └── Extract: Principal (who runs it) + Action (what runs)
                    │
                    ├── Principal: LocalSystem → CreateProcess as SYSTEM
                    ├── Principal: NETWORK SERVICE → CreateProcess as NETWORK SERVICE
                    ├── Principal: Specific user → requires that user's logon session
                    └── Principal: "Run only when user is logged on" → user's session
```

For tasks running as SYSTEM: the Schedule service calls `CreateProcessAsUser` with the
SYSTEM token → the task process has full SYSTEM access.

---

## 2. Task XML Structure

A task definition XML (`C:\Windows\System32\Tasks\TaskName`):

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  
  <RegistrationInfo>
    <Date>2024-01-01T00:00:00</Date>
    <Author>DOMAIN\Admin</Author>
    <URI>\TaskName</URI>
  </RegistrationInfo>

  <Triggers>
    <!-- When does this task run? -->
    <CalendarTrigger>
      <StartBoundary>2024-01-01T03:00:00</StartBoundary>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
    <LogonTrigger>
      <!-- Run at every user logon -->
    </LogonTrigger>
    <BootTrigger>
      <!-- Run at system startup -->
    </BootTrigger>
    <EventTrigger>
      <Subscription>
        <!-- Run when specific event log entry appears -->
        <QueryList><Query Id="0" Path="Security">
          <Select Path="Security">*[System[(EventID=4624)]]</Select>
        </Query></QueryList>
      </Subscription>
    </EventTrigger>
  </Triggers>

  <Principals>
    <!-- Who runs this task? -->
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>     <!-- LocalSystem SID -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>

  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Hidden>false</Hidden>                       <!-- hidden tasks don't appear in schtasks list -->
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>

  <Actions Context="Author">
    <!-- What does this task do? -->
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>/c "do something"</Arguments>
      <WorkingDirectory>C:\Windows\System32</WorkingDirectory>
    </Exec>
    <!-- Or COM handler: -->
    <ComHandler>
      <ClassId>{CLSID}</ClassId>
      <Data>optional data passed to handler</Data>
    </ComHandler>
  </Actions>

</Task>
```

### Key Fields for LPE Research

**Principal `<UserId>`**: Controls what account runs the task.
- `S-1-5-18` = LocalSystem (SYSTEM)
- `S-1-5-19` = Local Service
- `S-1-5-20` = Network Service
- A specific user SID → runs as that user
- Empty / `<LogonType>InteractiveToken</LogonType>` → runs as current interactive user

**`<RunLevel>`**: For tasks running as a user:
- `LeastPrivilege`: run with filtered token (standard user)
- `HighestAvailable`: run with elevated token (if user is admin)

**`<Hidden>true`**: Task doesn't appear in `schtasks.exe /query` or Task Scheduler UI.
Still exists in `C:\Windows\System32\Tasks\` filesystem and registry. Used by malware.

---

## 3. Permission Model — Task Filesystem

### Task Definition Files

`C:\Windows\System32\Tasks\` contains the XML task files. Each file maps to a task.
Subdirectories represent task folders (namespacing).

**Default permissions on the Tasks directory**:
```
C:\Windows\System32\Tasks\
  BUILTIN\Administrators: Full Control
  NT AUTHORITY\SYSTEM: Full Control
  CREATOR OWNER: Special permissions (limited)
  BUILTIN\Users: Read & Execute, List Folder Contents
```

Standard users can READ task files (see task configurations) but cannot write.

**However**: Specific task files may have misconfigured permissions:
- Task created by a user → that user may retain write access to the task file
- Tasks created by software with overly permissive ACL setup
- Corporate deployment tools that create tasks with broad permissions

### Checking Task File Permissions

```powershell
# Check all task files for user-writable permissions:
Get-ChildItem "C:\Windows\System32\Tasks\" -Recurse -File | ForEach-Object {
    $acl = Get-Acl $_.FullName
    $writable = $acl.Access | Where-Object {
        ($_.IdentityReference -match "Users|Everyone|Authenticated Users") -and
        ($_.FileSystemRights -match "Write|Modify|FullControl")
    }
    if ($writable) {
        Write-Host "[WRITABLE TASK] $($_.FullName)"
        $writable | Select-Object IdentityReference, FileSystemRights
    }
}
```

### Task Registry Keys

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
    Tasks\{GUID}\
        Path    = "\TaskName"
        Hash    = SHA256 of task XML (integrity check, but partial)
        Actions = binary-encoded action data
        Triggers= binary-encoded trigger data
        ...
```

If registry keys are writable → modify task configuration directly in registry.
(Changes in registry may not match XML file → inconsistency, Task Scheduler resolves from registry.)

---

## 4. Technique 1: Writable Task Binary

### Finding Tasks with Writable Binaries

If a SYSTEM-run task executes a binary in a user-writable location:
```
Task Action: <Command>C:\Program Files\SomeApp\tool.exe</Command>
If C:\Program Files\SomeApp\tool.exe is writable by current user:
→ Replace with payload
→ Wait for task trigger or run manually (if AllowStartOnDemand = true)
→ Payload executes as SYSTEM
```

**Enumeration**:
```powershell
# Get all tasks, extract commands, check file writability:
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $task.Actions | Where-Object { $_.CmdLine -or $_.Execute } | ForEach-Object {
        $exe = if ($_.Execute) { $_.Execute } else { $_.CmdLine -split ' ' | Select-Object -First 1 }
        $exe = $exe -replace '"', ''
        if ($exe -and (Test-Path $exe -PathType Leaf)) {
            $acl = Get-Acl $exe -ErrorAction SilentlyContinue
            $w = $acl.Access | Where-Object {
                $_.IdentityReference -match "Users|Everyone" -and
                $_.FileSystemRights -match "Write|Modify|FullControl"
            }
            if ($w) {
                Write-Host "[VULN] Task: $($task.TaskName) → Binary writable: $exe"
            }
        }
    }
}
```

### Task Trigger for On-Demand Execution

If `AllowStartOnDemand = true` (common), the task can be manually triggered:
```
schtasks.exe /Run /TN "TaskName"
→ Executes immediately (if caller has task START permission)
```

Task START permission is checked against the task's DACL:
```
# Check task DACL:
(Get-ScheduledTask "TaskName").SecurityDescriptor
# or:
schtasks.exe /Query /TN "TaskName" /V /FO LIST
```

By default, a task can be started by:
- The task's creator
- Administrators
- SYSTEM

If current user is the creator → can trigger manually → immediate SYSTEM execution.

---

## 5. Technique 2: Writable Task XML File

If the task XML file itself is writable:

```
1. Identify writable task XML: C:\Windows\System32\Tasks\Microsoft\Windows\Foo\BarTask
2. Read current XML to understand structure
3. Modify <Command> to point to payload:
   <Command>C:\Users\user\payload.exe</Command>
   OR: change <UserId> from current-user SID to S-1-5-18 (if Task Scheduler accepts this)
4. Write modified XML back
5. Trigger task execution
```

**Caveat**: Task Scheduler maintains a hash of the task XML in the registry
(`TaskCache\Tasks\{GUID}\Hash`). If the hash doesn't match, the task may fail to run
(this behavior varies by Windows version and task type).

**Bypassing the hash**:
- Update the registry hash to match the modified XML
- The hash is stored as DWORD/BINARY in the registry key — writable if registry key is writable
- Use SHA256 of the modified XML content (the exact hash algorithm matches Registry TaskCache)

### Task XML Modification for DLL Injection

Instead of changing the binary, modify the task's working directory and environment:
```xml
<Exec>
  <Command>C:\Windows\System32\cmd.exe</Command>  <!-- unchanged, legitimately signed -->
  <WorkingDirectory>C:\Users\user\evil_dir\</WorkingDirectory>
  <!-- If cmd.exe loads a DLL from CWD in this new working dir → DLL hijack -->
</Exec>
```
(Limited applicability for cmd.exe specifically, but relevant for apps that load DLLs from CWD)

---

## 6. Technique 3: Creating Tasks as Non-Admin

### User-Context Task Registration

Standard users can create tasks that run under their own account:
```powershell
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c payload"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "UserTask" -Action $action -Trigger $trigger
# → Task runs as current user at their next logon
```
This is NOT LPE (same user, same privileges). But it IS persistence.

### Abusing High-Privilege Task Registration

If an attacker can call `ITaskService::NewTask` with `Principal.UserId = SYSTEM`:
- Requires admin by default
- But if the Task Scheduler COM interface is accessible from Medium integrity with certain
  exploit/misconfiguration → create SYSTEM task without UAC

**COM interface for task creation** (requires admin normally):
```c
ITaskService *pService;
CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, &pService);
pService->Connect(NULL, NULL, NULL, NULL);  // connect to local scheduler

ITaskFolder *pRoot;
pService->GetFolder(L"\\", &pRoot);

ITaskDefinition *pTask;
pService->NewTask(0, &pTask);

// Set principal to SYSTEM
IPrincipal *pPrincipal;
pTask->get_Principal(&pPrincipal);
pPrincipal->put_UserId(L"S-1-5-18");  // SYSTEM
pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);

// Set action
// ...

pRoot->RegisterTaskDefinition(L"EvilTask", pTask, TASK_CREATE_OR_UPDATE, ...);
```

**UAC bypass via task creation**: Some older UAC bypass techniques involved creating tasks
via the `ITaskService` COM auto-elevation path (Task Scheduler is auto-elevating in some
configurations). These are version-specific and most are patched.

---

## 7. Technique 4: Task Scheduler DLL Hijacking

### Scenario

The Task Scheduler service (`svchost.exe -k netsvcs`) loads `taskschd.dll` and other DLLs
at service startup. But more interesting: tasks themselves may load DLLs.

**COM Handler tasks**: A task with `<ComHandler><ClassId>{GUID}</ClassId>` activates a COM
object when the task fires. If that CLSID is hijackable in HKCU (see doc 01) → task execution
triggers DLL load in the scheduler process (SYSTEM).

**Exec tasks**: If the task binary loads DLLs from a writable location → DLL hijack at
task runtime (same as general DLL hijacking but triggered by task).

**svchost DLL hijack for Schedule service**:
The DLL that implements the Schedule service itself (`taskschd.dll`, `schedsvc.dll`) is
in System32. Not directly hijackable unless a phantom DLL scenario applies for service startup.

---

## 8. Legacy Tasks (.job format)

`C:\Windows\Tasks\` contains `.job` files (Win2000/XP era, still supported).
The Task Scheduler 1.0 API reads these.

**Format**: Binary packed structure (not XML).
**ACL**: `C:\Windows\Tasks\` default allows Authenticated Users to create NEW files
(not write existing), which means:
- Authenticated users can drop new `.job` files
- But .job files run in the context of whoever created them (not SYSTEM)
- Unless the .job file specifies `RunAsInteractiveUser` or has a stored credential

**Edge case**: Some environments misconfigure `C:\Windows\Tasks\` with write access for
Authenticated Users to both existing and new files → overwrite existing SYSTEM tasks.

```powershell
# Check:
icacls "C:\Windows\Tasks\"
# If "Authenticated Users:(W)" or "(M)" → writable
```

---

## 9. Technique 5: Environment Variable Hijack via Task

Tasks run with specific environment variables. Some tasks inherit the SYSTEM environment,
some set their own. If a task runs a script or binary that uses environment variables for
path construction:

```
Task: C:\Windows\System32\wscript.exe "C:\Scripts\backup.vbs"
backup.vbs content:
    Set shell = CreateObject("WScript.Shell")
    shell.Run Environ("TEMP") & "\cleanup.bat"

If %TEMP% is attacker-controlled for SYSTEM user → plant cleanup.bat there
```

However, SYSTEM's %TEMP% is `C:\Windows\TEMP` which is not user-writable by default.

More realistic: tasks that use `%USERNAME%` or `%USERPROFILE%` (user-specific variables) in
paths, where the task actually runs as an interactive user.

---

## 10. Technique 6: Scheduled Task as Persistence (Post-SYSTEM)

After achieving SYSTEM, create a hidden persistence task:
```powershell
# Hidden task (doesn't appear in schtasks /query by normal users):
$action = New-ScheduledTaskAction -Execute "C:\Windows\System32\cmd.exe" -Argument "/c payload.exe"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -Hidden
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Settings $settings -Principal $principal

# Task stored at: C:\Windows\System32\Tasks\WindowsUpdate
# Registry: HKLM\...\Schedule\TaskCache\Tree\WindowsUpdate
```

**Making task harder to detect**:
- Use a name matching a legitimate Microsoft task (namespace + name mimicry)
- Place in `\Microsoft\Windows\` subfolder
- Set Hidden = true in task settings
- Set task description to match legitimate ones

---

## 11. Ferrum's Scheduled Task Module

Ferrum's `scheduled` module enumerates tasks and flags:

1. **Non-system accounts running tasks**: Tasks running as non-system accounts that could
   be targeted for credential access (if account password is accessible).

2. **Writable task binary paths**: Task `Execute` path is in user-accessible directories
   (`\Users\`, `\Temp\`, `\ProgramData\`).

3. **Task XML files in writable locations**: Task definition file ACL allows user modification.

4. **Failed auto-start tasks**: Task with auto-start trigger that's not running (possibly
   available to trigger manually).

---

## 12. Enumeration Commands

```powershell
# List all tasks with details:
schtasks.exe /Query /FO LIST /V | more

# PowerShell detailed view:
Get-ScheduledTask | Select-Object TaskName, TaskPath, State |
    ForEach-Object { 
        $t = Get-ScheduledTaskInfo $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Name = $_.TaskName
            Path = $_.TaskPath
            State = $_.State
            LastRun = $t.LastRunTime
            NextRun = $t.NextRunTime
        }
    }

# Task actions (what binary does each task run):
Get-ScheduledTask | ForEach-Object {
    $_ | Select-Object -ExpandProperty Actions | ForEach-Object {
        [PSCustomObject]@{
            Task = $task.TaskName
            Execute = $_.Execute
            Arguments = $_.Arguments
        }
    }
}

# Find tasks running as SYSTEM:
Get-ScheduledTask | Where-Object {
    ($_ | Select-Object -ExpandProperty Principal).UserId -match "SYSTEM|S-1-5-18"
}

# Check specific task XML file ACL:
icacls "C:\Windows\System32\Tasks\<TaskName>"
```

---

## 13. Detection

### Event 4698 — Scheduled Task Created
```
Event 4698, Log: Security
Subject: User who created the task
Task Name: \TaskName
Task Content: <XML of the task definition>
```
Alert on: tasks created by non-admin users with SYSTEM principal.

### Event 4702 — Scheduled Task Updated
Alert on: modifications to existing tasks, especially system tasks.

### Event 4699 — Scheduled Task Deleted
For tracking task cleanup.

### Event 4700/4701 — Task Enabled/Disabled

### Sysmon Event 1: Process Creation
Alert on: `services.exe` spawning processes from non-standard paths (task execution).
`svchost.exe` → `taskhostw.exe` → `suspicious_binary.exe`.

### File System Audit
Monitor writes to `C:\Windows\System32\Tasks\` by non-SYSTEM accounts.

### Registry Audit
Monitor writes to:
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`
by non-admin processes.

---

## 14. Summary

```
Scheduled Task LPE Attack Vectors:

[Enumeration]
schtasks /Query /V + Get-ScheduledTask + icacls on task files

    │
    ├── Task binary writable?
    │     → Replace binary with payload
    │     → schtasks /Run or wait for trigger → SYSTEM execution
    │
    ├── Task XML file writable?
    │     → Modify <Command> to attacker binary
    │     → Update registry hash if needed
    │     → Trigger task → SYSTEM execution
    │
    ├── Task with COM handler + hijackable CLSID?
    │     → HKCU COM hijack (see doc 01)
    │     → Task fires → COM activation → DLL loads in SYSTEM context
    │
    ├── Task binary in user-writable directory?
    │     → DLL hijacking in that directory
    │     → Task trigger → DLL loaded → SYSTEM code execution
    │
    └── No direct write access?
          → Use persistence path (post-SYSTEM): create hidden task as SYSTEM
```

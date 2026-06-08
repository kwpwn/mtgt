# EDR Block Chain Analysis

## Overview

Modern EDR agents communicate over multiple independent channels to their cloud
backend. Disrupting a single channel is often insufficient — most agents have
fallback logic that attempts alternate transports when primary channels fail.
This document maps every communication channel, assigns each technique to the
layer it blocks, and provides three complete operational chains for the three
most common commercial EDRs.

---

## 1. EDR Communication Architecture

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │                         EDR Agent Process                            │
  │  (MsSense.exe / CSFalconService.exe / SentinelAgent.exe)            │
  │                                                                      │
  │  ┌────────────┐   ┌───────────────┐   ┌──────────────────────────┐  │
  │  │ Telemetry  │   │  ETW Consumer │   │  Policy/Config Updater   │  │
  │  │ Uploader   │   │  (reads ETW   │   │  (downloads detection    │  │
  │  │ (HTTPS/    │   │   sessions)   │   │   rules, signatures)     │  │
  │  │  gRPC)     │   └───────┬───────┘   └──────────┬───────────────┘  │
  │  └─────┬──────┘           │                      │                  │
  └────────┼──────────────────┼──────────────────────┼──────────────────┘
           │                  │ (kernel events)       │
           │         ┌────────▼────────┐              │
           │         │  ETW Subsystem  │              │
           │         │  (NTOSKRNL)     │              │
           │         │  Sessions:      │              │
           │         │  - Sense        │              │
           │         │  - ETW-TI       │              │
           │         │  - Falcon       │              │
           │         └─────────────────┘              │
           │                                          │
           ▼                                          ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     Windows Network Stack                           │
  │                                                                     │
  │  ┌──────────────┐   ┌──────────────┐   ┌───────────────────────┐   │
  │  │  DNS Client  │   │  TCP/IP      │   │  TLS / HTTP.sys       │   │
  │  │  (dnscache)  │   │  (tcpip.sys) │   │  (schannel.dll)       │   │
  │  │              │   │              │   └───────────────────────┘   │
  │  │  1. hosts    │   │  Routing     │                               │
  │  │  2. cache    │   │  table       │                               │
  │  │  3. NRPT  ◄──┼───┼─── OUR      │                               │
  │  │  4. DNS srv  │   │  RULES ──►  │                               │
  │  └──────────────┘   │  /32 routes │                               │
  │                     └──────────────┘                               │
  │                                                                     │
  │  ┌──────────────────────────────────────────────────────────────┐  │
  │  │  QoS / pacer.sys                                             │  │
  │  │  Per-process bandwidth cap (edrchoker — existing BOF)        │  │
  │  └──────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     Physical Network Interface                      │
  │                     (packets exit only if all                       │
  │                      above layers allow them)                       │
  └─────────────────────────────────────────────────────────────────────┘
           │
           ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                     EDR Cloud Backend                               │
  │  MDE:    *.security.microsoft.com  *.wdcp.microsoft.com            │
  │  CS:     *.falcon.crowdstrike.com  *.cloudsink.net                 │
  │  S1:     *.sentinelone.net         *.pax.sentinelone.net           │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer Analysis — Which Technique Blocks Which Layer

```
  CHANNEL                    BLOCKED BY              MECHANISM
  ─────────────────────────────────────────────────────────────────────
  DNS resolution             nrpt_sinkhole           NRPT rule redirects
  (domain -> IP lookup)                              to 127.0.0.2 / SERVFAIL

  TCP connect to             null_route              /32 host route forces
  known IPs (no DNS)                                 traffic to loopback /
                                                     immediate RST

  Network throughput         edrchoker               QoS pacer.sys cap:
  (after connection)                                 8 bps — TLS handshake
                                                     takes ~6000 seconds

  ETW kernel events          etw_tamper              ControlTraceW STOP:
  (behavioral telemetry)                             session torn down,
                                                     consumer gets NOTFOUND

  WFP layer blocking         (separate BOF)          see 01_wfp_block.c
  (deep packet filter)
  ─────────────────────────────────────────────────────────────────────
```

### Why Each Technique Works at the OS Level

#### nrpt_sinkhole — NRPT Registry Injection

The Windows DNS Client (dnscache service, hosted in svchost.exe with
`-k NetworkService`) processes all DNS queries in user-space before
forwarding to the kernel resolver. On each query, it iterates the NRPT
policy list stored at:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\
```

Each subkey is one rule. The dnscache service parses the `Name`
(REG_MULTI_SZ) field as a namespace pattern and compares it against the
query FQDN. If the pattern matches, the `DNSServers` value overrides the
adapter's configured DNS server for that query.

Setting `DNSServers = "127.0.0.2"` causes the DNS query to be sent to
127.0.0.2 UDP/53. No service binds to 127.0.0.2:53, so:
- UDP: no response → query times out → SERVFAIL returned to application
- If the application has a timeout, the connect attempt fails with
  WSAHOST_NOT_FOUND or similar socket error

The EDR agent is not notified that the NRPT table was modified. The policy
change takes effect immediately after a `DnsFlushResolverCache()` call (or
on the next TTL expiry of any cached answer).

**Internal call path:**
```
Application: getaddrinfo("endpoint.microsoft.com", ...)
  -> DnsQuery (dnsapi.dll)
  -> RPC to dnscache service
  -> dnscache: check NRPT table
  -> match found -> redirect to 127.0.0.2:53
  -> UDP query to 127.0.0.2:53 -> ETIMEDOUT
  -> return WSANO_DATA / SERVFAIL to application
```

#### null_route — Routing Table /32 Blackhole

The IPv4 forwarding table (accessible via `route print` or the
`GetIpForwardTable` API) is maintained by `tcpip.sys`. When an outgoing
TCP SYN is routed, the kernel performs a longest-prefix-match (LPM) lookup.
A /32 host route (mask 0xFFFFFFFF) is the most specific possible entry —
it always wins over any other existing route to that IP (/24 subnet,
/0 default gateway).

By setting the next-hop of the /32 to 127.0.0.1 on the loopback interface:
1. Kernel routes SYN packet to the loopback adapter
2. Loopback driver delivers packet to the local TCP stack
3. TCP stack looks for a socket bound to the destination IP (e.g. 52.183.0.1)
4. No socket is bound to that IP on loopback
5. TCP stack sends RST back to the connecting socket
6. `connect()` returns WSAECONNREFUSED immediately
7. Zero packets leave the physical NIC

This is OS-level enforcement — no userspace firewall or WFP rule is
involved. `tcpip.sys` makes the routing decision before the packet is
handed to the NIC driver.

**Why this covers hardcoded IPs:**
Some EDR agents ship with cloud IPs compiled in (or cached to disk from a
previous DNS lookup) and use them directly without DNS. The NRPT sinkhole
has no effect on these connections. The /32 route blocks them regardless
of how the IP was obtained.

#### etw_tamper — ETW Session Teardown

ETW (Event Tracing for Windows) is the primary kernel telemetry channel.
The architecture:

```
  Kernel provider (e.g. Microsoft-Windows-Kernel-Process)
    -> EtwWrite() syscall (NtTraceEvent)
    -> ETW logger thread in ntoskrnl
    -> writes event to session buffer
    -> session buffer flushed to consumer

  Consumer (EDR)
    -> OpenTrace() + ProcessTrace() on named session
    -> reads events in real time
```

When `ControlTraceW(0, sessionName, props, EVENT_TRACE_CONTROL_STOP)` is
called:
1. ETW subsystem marks the session as stopping
2. Remaining buffer contents are flushed to the consumer (last events)
3. The session handle is destroyed
4. The consumer's `ProcessTrace()` call returns with
   `ERROR_WMI_INSTANCE_NOT_FOUND` (0x80071069)
5. The EDR's event processing loop exits or throws an error
6. All future kernel events that would have gone to this session are
   **silently dropped** — no error is raised to the provider

The SYSTEM token requirement arises because ETW sessions created by system
services have their security descriptor set to `NT AUTHORITY\SYSTEM` as
owner. `ControlTrace` on a session you don't own requires matching the
session owner's privilege level. A `SeSecurityPrivilege`-bearing
Administrator token is still refused.

**Winlogon token theft path:**
```
  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
  -> find winlogon.exe (always SYSTEM, always present)
  -> OpenProcess(PROCESS_QUERY_INFORMATION, winlogon_pid)
  -> OpenProcessToken(hProc, TOKEN_DUPLICATE)
  -> DuplicateToken(hToken, SecurityImpersonation)
  -> SetThreadToken(NULL, hDup)   <- current thread is now SYSTEM
  -> ControlTraceW(...)           <- called as SYSTEM
  -> SetThreadToken(NULL, NULL)   <- revert
```

**What the EDR loses:**
- Microsoft-Windows-Threat-Intelligence (ETW-TI) session: no process
  creation events, no network connection events, no memory allocation
  events. This is the primary source of behavioral signals for MDE.
- CrowdStrike-Falcon-Sensor: no process events, no file system events.
  CS kernel sensor telemetry is completely cut off.
- SentinelOne-Sensor: same effect for S1's Deep Visibility telemetry.

#### edrchoker — QoS Bandwidth Starvation (existing BOF)

Even if DNS and routing are not fully blocked (e.g. the EDR reconnects via
a new IP), pacer.sys enforces a per-process bandwidth cap of 8 bps.
At 8 bps, a TLS 1.3 ClientHello (~320 bytes) takes 320 seconds to transmit.
A full telemetry batch (typically 1–100 KB) would take 1,000–100,000 seconds.
Effectively zero throughput for any practical EDR function.

---

## 3. Chain Recipes

### Chain A: Microsoft Defender for Endpoint (MDE)

**EDR process names:** `MsSense.exe`, `MsSenseS.exe`, `SenseNdr.exe`
**Cloud domains:** `*.endpoint.microsoft.com`, `*.wdcp.microsoft.com`,
  `*.ods.opinsights.azure.com`, `*.security.microsoft.com`,
  `*.events.data.microsoft.com`
**ETW sessions:** `Microsoft-Windows-Sense`,
  `Microsoft-Windows-Threat-Intelligence`
**Common cloud IP ranges:** 20.190.x.x, 52.183.x.x, 13.89.x.x (Azure)

**Step-by-step beacon commands:**

```
# Step 1: Stop ETW sessions first (blind behavioral detection immediately)
etw_tamper mde

# Step 2: Sinkhole all MDE DNS domains
nrpt_sinkhole *.endpoint.microsoft.com;*.wdcp.microsoft.com;*.ods.opinsights.azure.com;*.security.microsoft.com;*.events.data.microsoft.com

# Step 3: Blackhole known MDE IP ranges (covers hardcoded IPs)
#   (resolve MsSense.exe's current connections first: netstat -anob | findstr MsSense)
null_route 20.190.128.1;20.190.129.1;52.183.20.1;13.89.176.1

# Step 4: Apply QoS cap as failsafe (covers any IP/domain we missed)
edrchoker MsSense.exe;MsSenseS.exe;SenseNdr.exe
```

**What this achieves:**
- ETW session torn down → MDE cannot receive kernel behavioral events
- DNS sinkholed → domain lookups fail with SERVFAIL
- /32 routes → hardcoded IP connections get immediate RST
- QoS cap → any connection that does succeed is throttled to 8 bps

**Expected MDE behavior after chain:**
MDE process continues running but enters a "disconnected" state. Local
on-disk scanning may still work. Behavioral detection (real-time
protection via ETW-TI) is disabled. Cloud sandbox detonation, cloud
ML inference, and EDR telemetry upload all fail.

---

### Chain B: CrowdStrike Falcon

**EDR process names:** `CSFalconService.exe`, `CSFalconContainer.exe`,
  `falconhost.exe` (older), `CsFalconD.exe` (Linux-style service name)
**Cloud domains:** `*.falcon.crowdstrike.com`, `*.cloudsink.net`,
  `ts01-*.cloudsink.net` (telemetry sinks), `*.crowdstrike.com`
**ETW sessions:** `CrowdStrike-Falcon-Sensor`,
  `CrowdStrike-Falcon-Operational`
**Common cloud IP ranges:** 35.232.x.x, 34.102.x.x (GCP)

**Step-by-step beacon commands:**

```
# Step 1: Stop CrowdStrike ETW sessions
etw_tamper crowdstrike

# Step 2: Sinkhole CrowdStrike DNS domains
nrpt_sinkhole *.falcon.crowdstrike.com;*.cloudsink.net;*.crowdstrike.com

# Step 3: Blackhole CrowdStrike cloud IPs
#   (use: Resolve-DnsName ts01-b.cloudsink.net to get current IPs first)
null_route 35.232.0.1;34.102.200.1;34.102.201.1

# Step 4: QoS throttle as failsafe
edrchoker CSFalconService.exe;CSFalconContainer.exe
```

**Expected CrowdStrike behavior after chain:**
Falcon sensor enters "reduced functionality mode" — local prevention
heuristics continue but real-time telemetry upload fails. The Falcon
console shows the sensor as "offline" within ~5 minutes. New detection
policy pushes from the cloud do not arrive.

---

### Chain C: SentinelOne

**EDR process names:** `SentinelAgent.exe`, `SentinelServiceHost.exe`,
  `SentinelStaticEngine.exe`, `SentinelHelperService.exe`
**Cloud domains:** `*.sentinelone.net`, `*.pax.sentinelone.net`,
  `usea1.pax.sentinelone.net`, `eap-prod-*.sentinelone.net`
**ETW sessions:** `SentinelOne-Sensor`, `SentinelOne-Operational`
**Common cloud IP ranges:** 54.x.x.x, 3.x.x.x (AWS us-east-1)

**Step-by-step beacon commands:**

```
# Step 1: Stop SentinelOne ETW sessions
etw_tamper sentinelone

# Step 2: Sinkhole SentinelOne DNS domains
nrpt_sinkhole *.sentinelone.net;*.pax.sentinelone.net

# Step 3: Blackhole SentinelOne cloud IPs
#   (use: Resolve-DnsName usea1.pax.sentinelone.net to get current IPs)
null_route 54.80.0.1;3.213.0.1;3.214.0.1

# Step 4: QoS throttle as failsafe
edrchoker SentinelAgent.exe;SentinelServiceHost.exe
```

**Expected SentinelOne behavior after chain:**
SentinelOne agent enters "disconnected mode". Local static analysis
(StaticAI) and behavioral AI (BEHAVIOURAL_AI) still execute but upload
no data. Deep Visibility telemetry (the primary forensic feed) stops.
Console shows agent as "Disconnected" and policy sync fails.

---

## 4. Gaps and Residual Risks

### nrpt_sinkhole Gaps

| Risk | Description | Mitigation |
|------|-------------|------------|
| Cached DNS answers | If MDE resolved its domains before sinkhole install, cached answers remain until TTL expires. `DnsFlushResolverCache()` is called automatically by the BOF. | Run `ipconfig /flushdns` manually as backup. |
| Hardcoded IPs | Some EDR agents cache cloud IPs to disk (e.g. a config file or registry value) and bypass DNS. NRPT has no effect. | Use `null_route` in parallel. |
| DoH (DNS over HTTPS) | If the EDR uses its own DoH resolver (common in enterprise agents), NRPT is bypassed entirely. DoH goes directly to HTTPS port 443. | Use `null_route` to block the DoH endpoint IP, or `edrchoker` to throttle the process. |
| IPv6 | NRPT rules apply to IPv4 DNS (A records). AAAA record lookups and IPv6 connectivity are not affected. | Disable IPv6 on the adapter or add IPv6-specific rules. |
| Registry detection | Some EDR agents monitor HKLM policy keys for modification. | Apply ETW tamper first to reduce EDR's monitoring capability. |

### null_route Gaps

| Risk | Description | Mitigation |
|------|-------------|------------|
| IP rotation | Cloud backends use Anycast or rotate IPs frequently. A /32 for today's IP is irrelevant tomorrow. | Use in combination with NRPT so new IPs (from DNS) cannot be obtained. |
| IPv6 routes | `MIB_IPFORWARDROW` is IPv4 only. IPv6 routes require `CreateIpForwardEntry2` with `MIB_IPFORWARD_ROW2`. | Add IPv6 null routes separately, or disable IPv6. |
| Route persistence | Routes added by `CreateIpForwardEntry` are not always persistent across reboots (depends on `dwForwardProto`). NETMGMT routes (proto=3) are typically removed on reboot. | Reinstall routes after reboot, or use persistent route store. |
| Route detection | `route print` shows the /32 entries. A sufficiently paranoid EDR could check its own routes. | ETW tamper reduces monitoring capability before applying routes. |

### etw_tamper Gaps

| Risk | Description | Mitigation |
|------|-------------|------------|
| Session restart | EDR service may detect session loss and restart the ETW session (many agents have a watchdog thread for this). Detection depends on how quickly the EDR responds. | Re-run `etw_tamper` periodically, or use `edrchoker` to slow the EDR's watchdog loop. |
| Alternative telemetry | Some EDR agents (especially MDE) also use `PsSetCreateProcessNotifyRoutine` kernel callbacks, minifilter callbacks, and object callbacks independently of ETW. These are not affected by ETW session teardown. | Combine with edrchoker throttle to make telemetry upload impossible even if local events are still captured. |
| WinLogon access | If Beacon runs with a constrained token (e.g. low-integrity or sandboxed), `OpenProcess(winlogon)` may fail. | Ensure Beacon is running in a high-integrity elevated process. |
| EDR console alert | Many EDR vendors detect ETW-TI session loss server-side (they see telemetry stop) and generate a "sensor disconnected" alert. | This is a tradeoff: local detection is stopped, but the SOC may be alerted. In time-sensitive operations, accept this risk. |
| New session names | Vendor may use undocumented session names that are not in the default list. | Use `logman query` or `etwtrace list` to enumerate running sessions first, then pass custom names to the BOF. |

### edrchoker Gaps (existing BOF, documented for completeness)

| Risk | Description | Mitigation |
|------|-------------|------------|
| QoS bypass | Some processes bypass QoS by using raw sockets or by calling at elevated priority. | Unlikely for standard EDR agents that use WinHTTP / WinSock. |
| WMI watchdog detection | WMI permanent subscriptions are a well-known persistence mechanism and are monitored by many EDRs. | Apply ETW tamper before installing watchdog. |
| Policy scope | `AppPathNameMatchCondition` matches on process name only (not full path). A process renamed to `MsSense.exe` would also be throttled. | Accept this side effect or add path matching if available. |

### Combined Chain Risk Summary

```
  TECHNIQUE          DETECTION RISK     EFFECTIVENESS   REVERSIBILITY
  ──────────────────────────────────────────────────────────────────────
  nrpt_sinkhole      LOW                HIGH            HIGH (delete keys)
                     (registry write,   (blocks DNS)    (remove rules,
                     no process events)                  flush cache)

  null_route         LOW                HIGH            HIGH (delete routes)
                     (routing change,   (blocks IPs)
                     no process events)

  etw_tamper         MEDIUM             HIGH            LOW (session gone,
                     (EDR may see       (no kernel       EDR must restart
                     session stop;      events)          session itself)
                     SOC alert likely)

  edrchoker          MEDIUM             HIGH            HIGH (delete WMI
                     (WMI subscription  (0 throughput)   subscription)
                     is detectable)
  ──────────────────────────────────────────────────────────────────────
```

**Recommended operational order:**
1. `etw_tamper` first — reduce EDR's local monitoring before other changes
2. `nrpt_sinkhole` — block DNS before EDR can make new connections
3. `null_route` — block hardcoded IPs
4. `edrchoker` — failsafe throughput cap on any connections that leak through

This order minimizes the window during which the EDR is partially impaired
but still able to detect and report the impairment activity.

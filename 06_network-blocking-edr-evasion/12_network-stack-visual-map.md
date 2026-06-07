# Visual Map: Where Every Technique Operates in the Windows Network Stack

## The Complete Stack with Attack Points

```
════════════════════════════════════════════════════════════════════════════
LAYER                    COMPONENT              TECHNIQUES OPERATING HERE
════════════════════════════════════════════════════════════════════════════

[USER-MODE APP]
    │  Application calls connect() / send()
    │
    ╔══════════════════════════════╗
    ║  Winsock Layer               ║ ←── G: Winsock LSP intercepts here
    ║  (ws2_32.dll)                ║     All connect()/send()/recv() routed
    ║                              ║     through LSP chain before kernel
    ╚══════════════════════════════╝
    │
    ╔══════════════════════════════╗
    ║  AFD.sys                     ║
    ║  (Ancillary Function Driver) ║
    ╚══════════════════════════════╝
    │
    │  IRP_MJ_WRITE ──────────────────── Q: IRP hook on tcpip.sys dispatch table
    │  (crosses user/kernel boundary)         operates BEFORE WFP
    ▼
────────────────────────── KERNEL BOUNDARY ──────────────────────────────
    │
    ╔══════════════════════════════╗
    ║  tcpip.sys                   ║
    ║  (TCP/IP Stack)              ║
    ║                              ║
    ║  ┌──────────────────────┐   ║
    ║  │   WFP Filter Engine  │   ║ ←── Techniques 02-07 operate HERE
    ║  │                      │   ║     (WFP filter injection, deletion,
    ║  │  [ALE_AUTH_CONNECT]  │   ║     360WFP, WinDivert, custom callout)
    ║  │  [OUTBOUND_TRANSPORT]│   ║
    ║  │  [INBOUND_TRANSPORT] │   ║
    ║  └──────────────────────┘   ║
    ╚══════════════════════════════╝
    │
    │
    │  [TCP packet constructed, ready for network]
    │
    ╔══════════════════════════════╗
    ║  NDIS.sys                    ║
    ║  (Network Driver Interface)  ║
    ║                              ║
    ║  ┌──────────────────────┐   ║ ←── K: NDIS LWF driver operates HERE
    ║  │   NDIS LWF Module    │   ║     Full Ethernet frame access
    ║  └──────────────────────┘   ║     No WFP events generated
    ║                              ║
    ║  ┌──────────────────────┐   ║ ←── EDRChoker(06) / pacer.sys HERE
    ║  │   pacer.sys          │   ║     QoS Packet Scheduler
    ║  │   (QoS Scheduler)    │   ║     Below WFP — no WFP audit
    ║  └──────────────────────┘   ║
    ╚══════════════════════════════╝
    │
    ╔══════════════════════════════╗
    ║  NIC Miniport Driver         ║
    ║  (e.g., e1000.sys, realtek)  ║
    ╚══════════════════════════════╝
    │
    ▼
════════════════════════════════
  Physical NIC Hardware
════════════════════════════════


═══════════════════════════════════════════════════════════════════════════
LAYER                    COMPONENT              TECHNIQUES OPERATING HERE
═══════════════════════════════════════════════════════════════════════════

[BEFORE PACKET IS BUILT — DNS and Routing layer]

    Application resolves hostname
    │
    ╔══════════════════════════════╗
    ║  DNS Client (dnscache)       ║ ←── A: hosts file / hosts.ics
    ║                              ║     B: NRPT (checked FIRST before DNS)
    ║  Resolution order:           ║
    ║    1. DNS cache              ║
    ║    2. NRPT table             ║
    ║    3. hosts file             ║
    ║    4. hosts.ics              ║
    ║    5. DNS server query       ║
    ╚══════════════════════════════╝
    │
    IP address resolved
    │
    ╔══════════════════════════════╗
    ║  IP Routing Table            ║ ←── D: Null route / blackhole
    ║  (checked before any stack)  ║     E: IP sinkholing (secondary IP)
    ║                              ║     Routes packet to void/loopback
    ╚══════════════════════════════╝

[PARALLEL POLICY SYSTEMS]

    ╔══════════════════════════════╗
    ║  IPSec Policy Agent          ║ ←── C: IPSec filter rules
    ║  (PolicyAgent / ipsec.sys)   ║     Separate from WFP — own audit trail
    ╚══════════════════════════════╝

    ╔══════════════════════════════╗
    ║  WinHTTP Proxy Layer         ║ ←── F: WinHTTP proxy poisoning
    ║  (winhttp.dll)               ║     Routes HTTP through dead proxy
    ╚══════════════════════════════╝

    ╔══════════════════════════════╗
    ║  TLS Validation              ║ ←── I: Certificate store attack
    ║  (schannel.dll / ncrypt.dll) ║     Remove trusted CA → TLS fails
    ╚══════════════════════════════╝

[PROCESS-LEVEL ATTACKS]

    ╔══════════════════════════════╗
    ║  EDR Process internals       ║ ←── L: Socket handle theft (NtDuplicateObject)
    ║                              ║     M: CPU starvation (priority/affinity)
    ║  Worker threads              ║     P: Named pipe IPC interception
    ║  Socket handles              ║
    ╚══════════════════════════════╝

[INFRASTRUCTURE ATTACKS]

    ╔══════════════════════════════╗
    ║  Base Filtering Engine (BFE) ║ ←── J: BFE service stop
    ║  (Windows service)           ║     Disables ALL WFP evaluation
    ╚══════════════════════════════╝

    ╔══════════════════════════════╗
    ║  Network Adapter Binding     ║ ←── N: Adapter binding disable
    ║  (NDIS binding registry)     ║     TCP/IP unbound from NIC
    ╚══════════════════════════════╝

    ╔══════════════════════════════╗
    ║  Firewall Profile            ║ ←── O: Profile switching
    ║  (Domain/Private/Public)     ║     Domain→Public changes rule scope
    ╚══════════════════════════════╝

    ╔══════════════════════════════╗
    ║  TCP State Machine           ║ ←── H: RST injection / SetTcpEntry
    ║  (MIB_TCPTABLE2)             ║     Terminate active connections
    ╚══════════════════════════════╝
```

---

## Attack Coverage Matrix

Which EDR capabilities does each technique defeat?

| Technique | Blocks new connections | Kills existing connections | Defeats hardcoded IPs | WFP-hardened EDR bypass |
|---|---|---|---|---|
| 02: WFP filter injection | Yes | No | No | Partial |
| 03: WFP filter deletion | Yes (removes block) | No | No | No |
| 04: 360WFP BYOVD | Yes | No | No | **Yes** |
| 05: WinDivert | Yes | No | No | **Yes** |
| 06: QoS throttling | Partial (timeout) | Partial | No | **Yes** |
| 07: Custom callout | Yes | No | No | **Yes** |
| A: Hosts file | Yes (DNS-based) | No | **No** | **Yes** |
| B: NRPT | Yes (DNS-based) | No | **No** | **Yes** |
| C: IPSec | Yes | No | Yes | **Yes** |
| D: Null routing | Yes | No | Yes | **Yes** |
| E: IP sinkholing | Yes | No | Yes | **Yes** |
| F: WinHTTP proxy | Partial (WinHTTP only) | No | No | **Yes** |
| G: Winsock LSP | Yes | No | No | **Yes** |
| H: RST injection | No | **Yes** | Yes | **Yes** |
| I: Cert store attack | Yes (TLS-based) | No | No | **Yes** |
| J: BFE stop | Yes (nuclear) | Yes | Yes | **Yes** |
| K: NDIS LWF | Yes | Yes | Yes | **Yes** |
| L: Handle theft | No | **Yes** | Yes | **Yes** |
| M: CPU starvation | Partial | Partial | Yes | **Yes** |
| N: Adapter binding | Yes (nuclear) | Yes | Yes | **Yes** |
| Q: IRP hook | Yes | No | Yes | **Yes** |

---

## Technique Pairing Guide

### For maximum stealth (minimize all logging):
```
Primary:   B (NRPT)     — No WFP, no routing event, wildcard DNS
Backup:    E (IP sink)  — Catches hardcoded IPs, no WFP
Teardown:  H (RST)      — Kill existing connections
```

### For maximum coverage (ensure EDR cannot communicate):
```
Phase 1:   B + D        — DNS + routing null route
Phase 2:   C            — IPSec for backup coverage
Phase 3:   06 (QoS)     — TLS timeout even if connection established
Phase 4:   L (handle)   — Kill any existing connections
```

### For environments where EDR is WFP-hardened (max-weight callout):
```
Skip all WFP-based techniques (02, 03)
Use:       B + E + C + 06
           NRPT + IP sinkholing + IPSec + QoS throttling
None of these interact with WFP
```

### For environments where network driver analysis is expected:
```
Skip:      K (LWF), custom callout (07)
Use:       B + E + C + F
           Pure policy/registry-based: very low driver footprint
```

---

## Detection Coverage by Blue Team Capability

What blue team investments detect which techniques?

| Blue Team Investment | Techniques Detected |
|---|---|
| WFP audit (Event 5447) | 02, 03 |
| WFP callout audit (5446) | 07 |
| Sysmon registry monitoring | B (NRPT), E (TCPIP interface), F (proxy), O (profile) |
| File integrity (hosts) | A |
| Driver load monitoring (7045) | 04, 05, K |
| IPSec audit (5460, 5471) | C |
| Process creation (4688) | netsh for A, B, C, D |
| ETW kernel trace | L (NtDuplicateObject), Q (IRP hook) |
| Network baseline comparison | D (route table) |
| HVCI enabled | Custom unsigned kernel drivers (07, K, Q) |
| EDR connectivity watchdog | All (when watchdog fires) |

**Gap analysis:** Techniques that NO standard investment catches without custom work:
- **E: IP sinkholing** — requires monitoring secondary IP assignments specifically
- **hosts.ics** — rarely monitored, no standard SIEM rule
- **QoS registry** — requires custom Sysmon rule for QoS key path
- **WinHTTP proxy** — requires monitoring specific WATP registry key
- **M: CPU starvation** — only visible in performance monitoring, not security logs

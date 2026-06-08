# Network Blocking & EDR Evasion — Research Index

## Scope

Techniques that manipulate Windows network stack, scheduling, and telemetry
components to block, throttle, redirect, or blind EDR/XDR agents — without
triggering WFP audit events (Event 5447).

Coverage spans userland-only approaches through kernel driver chains.

---

## Master Ranking Table

Ranked by **overall offensive value** = stealth × effectiveness × privilege cost.

| Rank | # | Technique | Code | Kernel? | Privilege | Persists? | WFP Event? | Tier |
|------|---|-----------|------|---------|-----------|-----------|------------|------|
| 1  | 04 | QoS throttle (EDRChoker/pacer.sys) | `04_qos_throttle.c` | No | Admin | Yes (reg) | **No** | **S** |
| 2  | 05 | NRPT DNS sinkhole | `05_nrpt_sinkhole.c` | No | Admin | Yes (reg) | **No** | **S** |
| 3  | 08 | IP sinkholing (secondary IP) | `08_ip_sinkhole.c` | No | Admin | Partial | **No** | **S** |
| 4  | 21 | ETW session manipulation | `21_etw_session_tamper.c` | No | Admin+SYSTEM | Partial | **No** | **S** |
| 5  | 13 | Socket handle theft (NtDuplicateObject) | `13_handle_theft.c` | No | Admin (SeDebug) | No | **No** | **A** |
| 6  | 07 | Null routing / blackhole | `07_null_route.c` | No | Admin | Yes | **No** | **A** |
| 7  | 06 | IPSec filter block | `06_ipsec_block.c` | No (ipsec.sys) | Admin | Yes | **No** | **A** |
| 8  | 09 | WinHTTP proxy poisoning | `09_winhttp_proxy.c` | No | Admin | Yes (reg) | **No** | **A** |
| 9  | 10 | TCP RST injection (SetTcpEntry) | `10_tcp_rst.c` | No | Admin | No (loop) | **No** | **A** |
| 10 | 20 | Firewall profile switch | `20_firewall_profile.c` | No | Admin | Yes | Indirect | **A** |
| 11 | 14 | CPU starvation (Job Object cap) | `14_cpu_starve.c` | No | Admin | No | **No** | **A** |
| 12 | 19 | Adapter binding disable | `19_adapter_binding.c` | No | Admin | Yes | **No** | **B** |
| 13 | 11 | Certificate store attack | `11_cert_store.c` | No | Admin | Yes | **No** | **B** |
| 14 | 17 | HOSTS file poisoning | `17_hosts_poison.c` | No | Admin | Yes | **No** | **B** |
| 15 | 12 | BFE service stop | `12_bfe_stop.c` | No | Admin/SYSTEM | No | **No** | **B** |
| 16 | 02 | WFP filter injection (EDRSilencer) | `01_wfp_block.c` | No | Admin | No | **Yes** | **B** |
| 17 | 03 | WFP filter deletion (lift containment) | `02_wfp_delete.c` | No | Admin | No | **Yes** | **B** |
| 18 | 16 | WinDivert packet silencing | `16_windivert_edrprison.c` | Yes (WinDivert) | Admin | No | **No** | **B** |
| 19 | 15 | Named pipe IPC hijack | `15_pipe_hijack.c` | No | Admin | No | **No** | **B** |
| 20 | 18 | Winsock LSP injection | `18_winsock_lsp_install.c` | No | Admin | Yes | **No** | **C** |
| 21 | — | NDIS LWF driver | `kernel/ndis_lwf/` | Yes | Kernel | Yes | **No** | **C** |
| 22 | — | WFP callout driver (custom) | `kernel/wfp_callout/` | Yes | Kernel | Event 5446 | Yes | **C** |
| 23 | — | IRP hook (tcpip.sys/afd.sys) | `kernel/irp_hook/` | Yes | Kernel | **No** | **No** | **C** |
| 24 | 03 | BYOVD — 360 WFP exploit | `03_360wfp_exploit.c` | Yes (BYOVD) | Admin | No | Minimal | **C** |

---

## Tier Definitions

### Tier S — No kernel, no WFP event, persists, high effectiveness
All four are **recommended starting point** for EDR evasion chains.

- **QoS throttle** is the gold standard: enforced by `pacer.sys` (built-in Windows),
  operates below WFP, no driver loading, no ETW audit event. EDR's TCP connections
  timeout before TLS handshake completes.

- **NRPT sinkhole** complements QoS: even if EDR has hardcoded IPs cached, DNS-based
  reconnect is blocked. Wildcard namespace support covers all subdomains.

- **IP sinkholing** is the most creative: EDR cloud IPs claimed as secondary adapter
  IPs so packets never leave the machine. Zero network evidence.

- **ETW session manipulation** is orthogonal to the others: does NOT block network but
  blinds EDR's behavioral detection engine. No events = no alerts for injection,
  credential dump, etc. Combine with any network technique for full blind + deaf.

### Tier A — High effectiveness, userland, minor detection surface
Use when Tier S alone is insufficient or target EDR uses hardcoded IPs.

### Tier B — Effective but leaves artifacts or needs loop/rerun
Use as supplement or when Tier A/S not available.

### Tier C — Kernel driver or deprecated — highest capability, highest risk
Reserve for BYOVD chains or when user-mode approaches are insufficient.

---

## Decision Flowchart

```
Goal: Silence EDR telemetry
│
├─ Block NETWORK (EDR can't phone home)
│   ├─ No WFP events needed?
│   │   ├─ Want persistence?    → QoS throttle (04)  +  NRPT (05)
│   │   ├─ Want zero network evidence? → IP sinkhole (08)
│   │   ├─ Want immediate TCP kill?    → TCP RST loop (10) + null route (07)
│   │   └─ Need HTTP-specific?         → WinHTTP proxy (09)
│   └─ WFP events acceptable?
│       └─ → WFP filter injection (02)
│
├─ Blind BEHAVIORAL DETECTION (EDR can't see what Beacon does)
│   ├─ No kernel?  → ETW session stop (21) + token steal
│   └─ Have BYOVD? → etw_ti_bypass.c (03_byovd/) — provider-level
│
└─ Full chain (recommended)
    → QoS (04) + NRPT (05) + ETW session (21)
    = EDR can't send telemetry AND can't see behavior
```

---

## Combination Chains

### Chain 1 — Minimum footprint (all userland, no kernel)
```
1. QoS throttle (04)     → throttle EDR TCP to 8 bps
2. NRPT sinkhole (05)    → block DNS reconnect
3. ETW session stop (21) → blind behavioral detection
```
Privilege: Admin + SYSTEM token (via SetThreadToken from winlogon)
Detection surface: registry writes only

### Chain 2 — Maximum persistence
```
1. QoS throttle (04)         → immediate network block
2. NRPT sinkhole (05)        → persistent DNS block
3. Autologger disable (21-C) → ETW session won't restart on reboot
4. WinHTTP proxy (09)        → block HTTP fallback
```
Privilege: Admin
Survives: Reboot (all registry-based)

### Chain 3 — Zero network trace (IP sinkhole chain)
```
1. IP sinkhole (08)     → EDR cloud IPs claimed locally, traffic never leaves NIC
2. ETW session stop (21)→ behavioral blind
3. TCP RST (10)         → kill existing established connections immediately
```
Privilege: Admin + SYSTEM
Network evidence: None externally

### Chain 4 — BYOVD full chain
```
1. etw_ti_bypass.c (03_byovd/) → kernel-level ETW-TI provider disable
2. NDIS LWF driver              → below-WFP packet drop
3. NRPT (05)                    → DNS backup block
```
Privilege: Kernel (vulnerable driver)
Visibility: Near-zero

---

## Technique Coverage Matrix

```
Attack Layer        Technique
─────────────────────────────────────────────────────────────
DNS resolution      NRPT (05), HOSTS poison (17)
IP routing          Null route (07), IP sinkhole (08)
TCP transport       TCP RST (10), Socket handle theft (13)
HTTP/TLS layer      WinHTTP proxy (09), Cert store (11)
Bandwidth/QoS       QoS throttle (04)  ← below all of above
ETW telemetry       ETW session (21), ETW-TI BYOVD
Process scheduling  CPU starvation (14)
WFP layer           WFP inject (02), WFP delete (03), BFE stop (12)
Kernel/NDIS         NDIS LWF, IRP hook, WFP callout driver
```

---

## Files in This Module

| File | Content |
|------|---------|
| `00_overview.md` | This file — index, rankings, decision flowchart |
| `01_wfp-architecture.md` | WFP internals: layers, sublayers, filters, callouts |
| `02_wfp-filter-injection.md` | EDRSilencer approach: add WFP block filters |
| `03_wfp-filter-deletion.md` | Lift containment: delete EDR's own WFP filters |
| `04_byovd-360wfp-exploit.md` | BYOVD: abuse 360's signed driver IOCTL |
| `05_byovd-windivert-edrprison.md` | WinDivert signed driver packet silencing |
| `06_qos-throttling-edrchoker.md` | pacer.sys QoS throttling (EDRChoker technique) |
| `07_custom-callout-driver.md` | Write your own WFP callout driver |
| `08_detection-and-defense.md` | Blue team: detection and hardening |
| `09_references.md` | All source links |
| `10_beyond-wfp-alternative-techniques.md` | DNS, NRPT, IPSec, routing, IP sinkhole, proxy, LSP, RST, TLS |
| `11_advanced-creative-techniques.md` | BFE stop, NDIS LWF, handle theft, CPU starvation, ETW session, IRP hook |
| `12_network-stack-visual-map.md` | ASCII visual map across network stack |
| `code/` | All C implementations + kernel driver sources |

---

## Novelty Assessment

| Technique | Public Research? | Notes |
|-----------|-----------------|-------|
| QoS throttle | EDRChoker (2024) | Relatively new, pacer.sys angle novel |
| ETW session manipulation (userland) | **Minimal** | Consumer-side attack, no BYOVD needed |
| Socket handle theft for sockets | **Minimal** | NtDuplicateObject for socket close = novel application |
| Job Object CPU cap for EDR | **None found** | No public writeup targeting EDR specifically |
| IP sinkholing | IPMute (2024) | Published but obscure |
| NRPT abuse | Moderate coverage | Used by some malware families |
| NDIS LWF without BYOVD | Low | Few offensive implementations |

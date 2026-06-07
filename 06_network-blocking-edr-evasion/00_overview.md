# Network Blocking & EDR Evasion Techniques — Research Index

## Scope

This module documents techniques that manipulate Windows network stack components to
block, throttle, or redirect network traffic — specifically in the context of silencing
EDR/XDR telemetry or lifting network containment.

The techniques span multiple layers of the Windows networking stack, from user-mode
APIs down to kernel-mode callout drivers and hardware-adjacent packet schedulers.

---

## Technique Map

### WFP / Driver-Based (files 02-07)

| # | Technique | Layer | Requires Kernel? | Leaves WFP Logs? |
|---|-----------|-------|-----------------|-----------------|
| 02 | WFP Filter Injection (EDRSilencer) | WFP sublayer | No (user-mode API) | Yes |
| 03 | WFP Filter Deletion (Lift Containment) | WFP sublayer | No (user-mode API) | Yes |
| 04 | BYOVD — 360WFP_Exploit | WFP callout (kernel) | Yes (driver) | Minimal |
| 05 | BYOVD — WinDivert / EDRPrison | NDIS packet level | Yes (driver) | Minimal |
| 06 | QoS Throttling — EDRChoker | pacer.sys (below WFP) | No (policy API) | **No** |
| 07 | Custom WFP Callout Driver | WFP callout (kernel) | Yes (driver) | Event 5446 |

### Non-WFP Alternatives (file 10)

| ID | Technique | Layer | WFP Events? | Stealth |
|---|---|---|---|---|
| A | Hosts file / hosts.ics | DNS resolution | **No** | Medium |
| B | NRPT (Name Resolution Policy Table) | DNS resolution | **No** | High |
| C | IPSec filter rules | IPSec policy engine | **No** | High |
| D | Null routing / blackhole | IP routing table | **No** | High |
| E | IP sinkholing (secondary IP) | Network adapter | **No** | **Very High** |
| F | WinHTTP/WinINET proxy poisoning | HTTP layer | **No** | High |
| G | Winsock LSP injection | Winsock API | **No** | Medium |
| H | TCP RST injection | TCP state machine | **No** | High |
| I | Certificate store attack | TLS validation | **No** | High |

### Advanced Creative (file 11)

| ID | Technique | Layer | WFP Events? | Complexity |
|---|---|---|---|---|
| J | BFE service stop | WFP infrastructure | **No** | Low |
| K | NDIS LWF driver | Below WFP | **No** | High |
| L | Socket handle theft (NtDuplicateObject) | Process internals | **No** | Medium |
| M | CPU starvation (affinity/priority) | Process scheduling | **No** | Low |
| N | Network adapter binding disable | NDIS binding | **No** | Medium |
| O | Firewall profile switching | WFP profile scope | No | Low |
| P | Named pipe IPC interception | EDR local IPC | **No** | High |
| Q | IRP hook on tcpip.sys | Below WFP | **No** | Very High |

---

## Files in this Module

- `01_wfp-architecture.md` — WFP internals: layers, sublayers, filters, callouts
- `02_wfp-filter-injection.md` — Technique: add block filters (EDRSilencer approach)
- `03_wfp-filter-deletion.md` — Technique: delete EDR filters to lift containment
- `04_byovd-360wfp-exploit.md` — Technique: abuse 360's signed driver IOCTL
- `05_byovd-windivert-edrprison.md` — Technique: leverage WinDivert signed driver
- `06_qos-throttling-edrchoker.md` — Technique: pacer.sys QoS bandwidth throttling
- `07_custom-callout-driver.md` — Technique: write your own WFP callout driver
- `08_detection-and-defense.md` — Blue team perspective: detection and hardening
- `09_references.md` — All source links
- `10_beyond-wfp-alternative-techniques.md` — Non-WFP: DNS, NRPT, IPSec, routing, IP sinkholing, proxy, LSP, RST, TLS
- `11_advanced-creative-techniques.md` — BFE stop, NDIS LWF, handle theft, CPU starvation, IRP hook, named pipe
- `12_network-stack-visual-map.md` — ASCII visual map of all techniques across the stack + coverage matrix

---

## Prerequisites

To understand this module, you should be familiar with:
- Windows kernel driver basics (IRP, IOCTL, device objects)
- Windows network stack concepts (TCP/IP stack, NDIS)
- Basic C/C++ for kernel development

See `../01_core-handbook/` for foundational concepts.

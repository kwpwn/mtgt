# Topic Index

Backlinks: [README](../../README.md) | [learning path](windows-kernel-pwn-learning-path.md) | [case-study matrix](case-study-matrix.md)

## How to Use This Index

Start from a concept, read the deep-dive hub, then choose one or two case studies. For each case study, answer: what is the primitive, why is it powerful, what breaks under modern mitigations, and what telemetry would a defender see?

## Core Topics

| Topic | Primary docs | Source notes |
|---|---|---|
| Windows internals | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md), existing `docs/windows-internals/` | WRMSR, eneio64, HVCI sources |
| Driver model and IOCTL | [IOCTL reversing workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md) | Lenovo, eneio64, AsIO3, Julian Pena |
| Buffer methods | [IOCTL reversing workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md) | WRMSR, BYOVD driver notes |
| Kernel memory and paging | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md) | eneio64, Datafarm, BusterCall, VT-rp |
| Primitive reasoning | [primitive framework](../kernel-research/primitive-reasoning-framework.md) | All source notes |
| HVCI/VBS/KDP/VT-rp/HLAT | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) | Connor, XPN, Datafarm, malk, BusterCall, Tandasat |
| BYOVD | [Windows 11 threat model](../byovd/byovd-modern-windows-11-threat-model.md) | Lenovo, eneio64, AsIO3, BlackSnufkin, GhostWolfLab |
| BYOVD detection | [detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) | G3tSyst3m, GhostWolfLab, BlackSnufkin |
| Version and mitigation matrix | [mitigation/version matrix](mitigation-version-matrix.md) | NCC, Connor, XPN, Tandasat, Synacktiv |
| MSR/WRMSR | [MSR research notes](../kernel-research/msr-wrmsr-research-notes.md) | Idafchev, eneio64, Synacktiv shadow stack |
| Kernel pool | [pool study map](../windows-heap/kernel-pool-exploitation-study-map.md) | Theori, vp777 |
| Win32k | [win32k attack surface](../kernel-research/win32k-and-gui-kernel-attack-surface.md) | Unit42, SecWiki |
| Information disclosure | [primitive framework](../kernel-research/primitive-reasoning-framework.md) | WindowsForum CVE-2026-21222 |
| Shadow stack/CET | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) | Synacktiv SSTIC 2025 |
| Component filtering | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) | big5-sec component filter |

## Vulnerability Classes

| Class | What to learn | Good starting docs |
|---|---|---|
| Arbitrary read/write | Capability, address discovery, version-specific offsets, detection | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Physical memory R/W | Page-table walking, PFN translation, VBS/KDP caveats | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md) |
| MSR write | LSTAR/syscall path, CPU scope, crash risk, modern mitigations | [MSR notes](../kernel-research/msr-wrmsr-research-notes.md) |
| Wild copy | Double fetch, fault-bounded copy, pool target selection | [pool map](../windows-heap/kernel-pool-exploitation-study-map.md) |
| PreviousMode | Data-only transition from weak primitive to kernel R/W | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Handle/object abuse | Object references, Ob callbacks, process/thread handle policy | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Callback tamper concepts | Why callbacks are high-value, how defenders monitor them | [BYOVD detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) |
| DSE/g_CiOptions concepts | Code integrity policy, VBS/HVCI limits, PatchGuard risk | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |

## Version/Mitigation Map

| Environment | Study focus |
|---|---|
| Windows 7 / Server 2008 R2 | Legacy lack of modern mitigations; registry/stack/pool case studies are mostly historical. |
| Windows 10 pre-1809 | KASLR, SMEP, pool hardening, but less default VBS/HVCI. |
| Windows 10 1809-21H2 | More ETW and kernel sensor coverage; KCFG/CET adoption begins. |
| Windows 11 22H2 | HVCI commonly relevant; PreviousMode tricks begin to fail across builds. |
| Windows 11 23H2/24H2/25H2 | Fewer kernel leaks, stronger HVCI/VBS posture, vulnerable driver blocklist matters more. |
| Server SKUs | Treat as version-specific; role, Secure Boot, VBS, and driver inventory decide risk. |

## Lab-Safe Study Rule

Every page should be read with this chain:

`bug class -> primitive -> constraints -> version -> mitigation -> detection -> safe lab model`

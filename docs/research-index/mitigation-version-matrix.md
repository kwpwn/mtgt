# Mitigation and Version Matrix

Backlinks: [README](../../README.md) | [topic index](topic-index.md) | [learning path](windows-kernel-pwn-learning-path.md) | [primitive framework](../kernel-research/primitive-reasoning-framework.md)

## Purpose

This matrix summarizes how Windows version and mitigation posture changes kernel primitive reasoning. Use it as the hub that BYOVD and mitigation docs link back to.

## Version Matrix

| Windows posture | Kernel exploit research meaning | BYOVD meaning | Detection focus |
|---|---|---|---|
| Windows 7 / Server 2008 R2 | Historical environment with many modern mitigations absent. | Legacy drivers often load more easily. | Unsupported OS, legacy exploit artifacts, crashes. |
| Windows 10, HVCI off | KASLR, SMEP, PatchGuard, KCFG state vary by build. | Signed vulnerable drivers still matter. | Driver load, service creation, device access. |
| Windows 10/11, VBS on, HVCI off | Some trust decisions move to VTL1, but kernel code integrity posture differs from full HVCI. | DSE/g_CiOptions assumptions need VBS-specific validation. | CI policy state, secure-kernel events. |
| Windows 11 22H2, HVCI on | Unsigned kernel code assumptions largely fail; data-only and existing-code reasoning matter. | Vulnerable signed drivers remain a key entry point if allowed. | Blocklist, rare signer, IOCTL behavior, crashes. |
| Windows 11 23H2/24H2+ | More leak and PreviousMode hardening; exact build matters. | Driver version and policy state dominate risk. | WDAC/HVCI posture, blocked driver events, object tamper. |
| Server SKUs | Defaults vary by role and enterprise policy. | Inventory and allowlisting are mandatory. | Baseline deviations and maintenance windows. |

## Mitigation Matrix

| Mitigation | Blocks or weakens | Does not fully block |
|---|---|---|
| KASLR | Blind kernel address targeting | Leaks, symbols, logic bugs. |
| SMEP | Kernel executing user pages | Kernel data-only corruption. |
| SMAP | Kernel accessing user pages | Kernel memory corruption. |
| NX / NonPagedPoolNx | Direct code in data/pool pages | Data-only attacks and existing-code reuse. |
| KCFG/XFG | Invalid indirect control flow | Direct data corruption, allowed target abuse. |
| CET / Shadow Stack | Return-address corruption/ROP | Data-only attacks and non-return control flow. |
| HVCI | Unsigned kernel code and simple executable-page tricks | Vulnerable signed drivers, selected data-only attacks. |
| VBS | VTL0 control over selected sensitive decisions | Bugs in allowed VTL0 code and unprotected data. |
| KDP | Writes to selected protected data | Unprotected kernel data and logic bugs. |
| VT-rp/HLAT | Selected remapping attacks | Unsupported hardware/configurations and unprotected ranges. |
| PatchGuard | Persistent tamper of protected structures | Immediate impact before delayed bugcheck, unprotected data. |
| Secure Boot | Boot-chain and CI policy weakening | Signed vulnerable drivers unless blocked by policy. |
| Vulnerable driver blocklist | Known-bad driver identities | Unknown/new variants and stale policies. |
| WDAC | Non-allowlisted code/drivers | Misconfigured allowlists and already-trusted vulnerable drivers. |

## Primitive Impact Matrix

| Primitive | HVCI off | HVCI on | VBS/KDP/HLAT caveat |
|---|---|---|---|
| Arbitrary read | Leak enables KASLR bypass. | Still useful for reconnaissance. | VTL1 secrets remain isolated. |
| Arbitrary write | May target code/data depending on mitigations. | Mostly data-only/existing-code reasoning. | KDP may block chosen data. |
| Physical R/W | Can become virtual R/W after page walking. | Cannot simply create trusted executable code. | HLAT/VT-rp may defeat remapping assumptions. |
| MSR write | Dangerous but crash-prone. | Unsigned-code end state constrained. | Secure-kernel and KVA shadow assumptions matter. |
| Pool overflow/UAF | Target object corruption. | Data-only impact remains possible. | Object hardening and KDP matter. |
| BYOVD | Driver primitive may be direct. | Driver load policy and post-primitive constraints dominate. | Blocklist/WDAC are earliest control points. |

## Related Repo Docs

- [HVCI/VBS/KDP/VT-rp/HLAT deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md)
- [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md)
- [BYOVD detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md)
- [Primitive reasoning framework](../kernel-research/primitive-reasoning-framework.md)

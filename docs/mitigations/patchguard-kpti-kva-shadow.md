# PatchGuard, KPTI, and KVA Shadow

## Purpose

This document explains how PatchGuard and KPTI/KVA Shadow changed Windows kernel research, driver expectations, and exploit assumptions. It treats them as layered integrity and isolation measures rather than as one-size-fits-all answers to kernel memory safety.

## Background

### Why kernel integrity matters

The Windows kernel is a shared privileged execution environment. If arbitrary code or silent structural corruption can persist there, the blast radius extends across process boundaries, security policy, and system trust. Mitigations therefore aim to make certain classes of kernel tampering harder, less stable, or more detectable.

### PatchGuard / Kernel Patch Protection

PatchGuard is Microsoft’s long-running effort to detect certain forms of unauthorized tampering in 64-bit kernel environments. It matters because many older rootkit-era assumptions involved persistent patching of core tables, code regions, and critical control structures.

### KPTI / KVA Shadow

KPTI, often discussed in Windows as KVA Shadow, separates user-mode and kernel-mode address views more aggressively. The mitigation exists in response to speculative-execution side-channel pressure, especially the Meltdown class, and it changed how analysts think about kernel address visibility and context switching.

### Why old exploit assumptions break

Older mental models often assumed:

- large kernel address visibility from user context,
- stable syscall/trap code shape,
- weaker separation between user and kernel address views,
- persistence-oriented patching as a workable end state.

Modern Windows invalidates many of these assumptions partially or completely.

## PatchGuard Deep Dive

### What PatchGuard aims to protect

PatchGuard is best understood as an integrity monitor over categories of high-value kernel state. It does not document every implementation detail publicly, and behavior drifts across versions, but the goal is consistent: make unsupported kernel patching unstable and expensive.

### Protected categories at a conceptual level

Commonly discussed categories include:

- SSDT-related control surfaces,
- IDT and GDT-related state,
- certain MSRs,
- kernel code regions,
- sensitive callback or dispatch surfaces where relevant,
- critical kernel structures tied to core integrity assumptions.

The exact set, cadence, and implementation are intentionally not treated here as a reverse-engineering bypass target.

### Delayed crash behavior

PatchGuard is important partly because it is not a simple inline access check. A system can appear to continue running after unsupported tampering, then bugcheck later when an integrity check discovers the inconsistency. That delayed failure complicates both offense and defense:

- researchers may misattribute the eventual crash,
- defenders may see instability after the triggering action is long gone,
- root-cause work requires careful time correlation.

### Why PatchGuard is not a general memory-safety solution

PatchGuard does not promise:

- no vulnerable signed drivers,
- no data-only corruption,
- no unsafe IOCTL semantics,
- no object lifetime bugs,
- no race conditions,
- no pool corruption outside the specific integrity categories it watches.

Its mission is narrower: protect core integrity assumptions against unsupported tampering.

### Why data-only corruption may still be dangerous

A system can maintain intact kernel code and still suffer severe security consequences if mutable security-relevant data is corrupted. This is why docs elsewhere in the repo emphasize semantic corruption, object state, and unsafe driver behavior rather than only code-patching routes.

### Version drift and undocumented behavior

PatchGuard is version-sensitive and intentionally under-documented at implementation level. That means:

- reverse-engineering notes age quickly,
- broad claims require build context,
- defenders should reason from the mitigation’s purpose, not from one historical watch-list snapshot.

## KPTI / KVA Shadow Deep Dive

### User/kernel address space separation

KVA Shadow gives user mode a more restricted kernel mapping view. At a conceptual level:

```text
user execution context
  -> minimal kernel mapping exposure needed for transitions

kernel execution context
  -> full kernel address-space view
```

This reduces what speculative side-channel behavior can infer about privileged mappings.

### CR3 switching concept

The mitigation relies on switching between address-space roots appropriate to user and kernel execution phases. The critical research lesson is not to memorize low-level mechanics, but to understand that:

- context changes now carry more translation significance,
- kernel address visibility assumptions are less portable across contexts,
- old "user can still see enough kernel mapping structure" shortcuts became less reliable.

### Syscall and interrupt transition impact

System call, interrupt, and exception transitions become part of the mitigation story because the OS must move between the restricted and privileged mapping views safely and efficiently.

### TLB / PCID notes at a conceptual level

Translation lookaside buffer behavior and features such as PCID matter because KVA Shadow adds translation-management cost. The mitigation is therefore not only a security boundary change but also a performance and complexity tradeoff.

### Impact on kernel address visibility

KVA Shadow changed practical assumptions about:

- what user mode can meaningfully infer from kernel mappings,
- how stable page-table observations are across contexts,
- how easily older research techniques generalize to modern systems.

### Impact on debugging and assumptions

Researchers must be more deliberate about:

- which process context they inspect,
- whether the current address-space view is user or kernel oriented,
- whether build-specific trap or syscall code changed because of mitigation work.

## Mitigation Interaction Matrix

| Mitigation | Blocks/hardens | Does not block | Research impact | Defender note |
|---|---|---|---|---|
| PatchGuard | Unsupported tampering of certain core kernel integrity categories | All mutable-data corruption, unsafe signed-driver logic, many lifetime bugs | Persistence-oriented patching is less stable | Delayed bugchecks can signal prior tampering |
| KASLR | Predictable fixed addresses | Arbitrary reads, semantic abuse once addresses are known | Address discovery remains a prerequisite in weaker models | Inventory and crash context still matter |
| SMEP | Kernel execution from user pages | Data-only corruption, many signed-driver abuse paths | Ret2usr-style assumptions weakened | Helps, but does not sanitize IOCTL semantics |
| SMAP | Some direct supervisor access to user pages | All logic bugs and all supported copy paths | Matters most when code directly touches user memory | Useful but context-dependent in driver review |
| KPTI / KVA Shadow | Broad user visibility into kernel mappings, Meltdown-related leakage assumptions | Memory-safety bugs, unsafe drivers, mutable-data corruption | Context and translation assumptions changed | Strong mitigation, not a substitute for driver review |
| HVCI / VBS | Unsigned or untrusted kernel code execution paths | Vulnerable signed drivers with dangerous semantics | Pushes research toward data-only and existing-code reasoning | Strongly beneficial but not magic |
| Driver Signature Enforcement | Unsigned kernel driver load in normal policy paths | Signed but unsafe driver behavior | BYOVD remains relevant | Trust policy must be paired with blocklists and inventory |
| Kernel CFG | Some indirect control-flow abuse | Data-only object corruption, many semantic-abuse paths | Forward-edge control-flow abuse becomes narrower | Valuable when combined with other layers |
| Pool hardening | Some classic allocator exploitation assumptions | All logic errors and all object corruption | Old pool code-exec thinking ages badly | Still requires good driver hygiene and verifier use |

## Common Mistakes

- Assuming PatchGuard protects all important kernel data.
- Assuming KPTI prevents all kernel exploitation.
- Assuming KASLR matters after a strong arbitrary read exists.
- Assuming HVCI fully protects systems from vulnerable signed drivers.
- Assuming Driver Signature Enforcement says anything about runtime IOCTL safety.

## Research Notes

- PatchGuard and KVA Shadow are easiest to understand when treated as answers to specific classes of kernel risk, not as generalized anti-exploit magic.
- Modern Windows defense is layered. The strategic shift is not "kernel exploitation is impossible", but "fragile and unsupported approaches fail earlier, while semantic and trust-boundary issues remain highly relevant."
- Compatibility pressure matters. KVA Shadow in particular had to preserve documented driver behavior where possible, which is why supported I/O and probing patterns remain important to understand.

## Debugging / Inspection Notes

Safe inspection topics:

- check Windows build and patch level first,
- verify symbol correctness before interpreting trap paths or structure layouts,
- inspect VBS/HVCI state conceptually alongside crash context,
- interpret bugchecks with time correlation in mind when PatchGuard-style delayed failure is possible.

High-level crash interpretation notes:

- delayed integrity bugchecks can point to earlier tampering rather than the immediate active stack alone,
- translation and context matter when debugging address-visibility assumptions on KVA Shadow systems,
- symbol drift can make mitigation analysis look wrong when the real problem is mismatched type or code interpretation.

## Defensive Angle

PatchGuard, KPTI, HVCI, blocklists, and driver signing are layered because no single mechanism addresses every kernel risk:

- PatchGuard constrains some unsupported tampering.
- KVA Shadow constrains address-space exposure assumptions.
- HVCI constrains code integrity.
- blocklists constrain known-bad signed drivers.
- inventory and telemetry constrain operational blind spots.

This is why driver inventory and vulnerable-driver policy still matter even on modern hardened Windows installs.

## Lab-Safe Exercises

1. On a test system, record the exact Windows build and note which mitigation assumptions in your research notes depend on that build.
2. Compare a legacy kernel writeup and a modern Windows 11 writeup, and classify which assumptions were weakened by PatchGuard, KVA Shadow, or HVCI.
3. In a crash dump, practice separating "what crashed" from "what might have happened earlier" when integrity monitoring is involved.

## References / Further Reading

- MSRC Blog, `KVA Shadow: Mitigating Meltdown on Windows`:
  https://www.microsoft.com/en-us/msrc/blog/2018/03/kva-shadow-mitigating-meltdown-on-windows/
- Microsoft Learn, `Enable memory integrity`:
  https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft Learn, `Virtual Address Spaces`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
- Microsoft Learn, `Driver security checklist`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist
- Existing repo note, `02_mitigations-vbs-hvci-vtrp/MITIGATION_MATRIX.md`
- Existing repo note, `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`
- Existing repo note, `02_mitigations-vbs-hvci-vtrp/VT_RP_HLAT_DEEP_DIVE.md`

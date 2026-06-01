# MSR and WRMSR Research Notes

Backlinks: [README](../../README.md) | [topic index](../research-index/topic-index.md) | [learning path](../research-index/windows-kernel-pwn-learning-path.md) | [primitive framework](primitive-reasoning-framework.md)

## Purpose

Explain Model Specific Register research in a lab-safe way, centered on why arbitrary WRMSR is dangerous and how mitigations change the analysis.

## What You Will Learn

- What MSRs are and why drivers legitimately use them.
- What `RDMSR` and `WRMSR` do.
- Why LSTAR/syscall path control is dangerous.
- Why SMEP, SMAP, KVA shadow, PatchGuard, HVCI, and CPU affinity matter.

## Core Concepts

| Term | Meaning |
|---|---|
| MSR | CPU control register scoped by architecture, core, thread, or package. |
| `RDMSR` | Ring 0 instruction that reads an MSR selected by `ECX`. |
| `WRMSR` | Ring 0 instruction that writes an MSR selected by `ECX` with `EDX:EAX`. |
| LSTAR | MSR that points to the long-mode syscall entry target. |
| CPU affinity | Some MSRs are per-core/thread; exploitability and crashes can depend on where code runs. |

## Why Arbitrary MSR Write Is Dangerous

If a driver lets an untrusted caller choose both MSR index and value, the caller can attempt to change CPU behavior. LSTAR is a common teaching example because syscall transition uses it. The lab-safe lesson is: a control register write can move the kernel entry path, but modern syscall entry has stack, CR3, SMEP/SMAP, KVA shadow, and PatchGuard constraints.

## Mitigation Notes

| Mitigation | Effect |
|---|---|
| SMEP | Kernel cannot execute user pages; redirecting to user memory crashes. |
| SMAP | Kernel access to user pages can fault depending on state and platform behavior. |
| NX | Writable data is not executable by default. |
| KVA shadow | Syscall entry begins in a constrained transition mapping. |
| PatchGuard | Persistent control-structure tamper can bugcheck later. |
| HVCI | Blocks unsigned kernel code assumptions and changes viable end states. |
| Secure Boot/blocklist | May prevent loading the vulnerable driver in the first place. |

## Detection Notes

- Hardware-monitoring or overclocking driver loaded unexpectedly.
- Device object with broad user access.
- IOCTLs that accept MSR index/value structures.
- Sudden bugcheck after syscall path activity.
- Rare calls to MSR helper paths from vendor drivers outside expected software.

## Common Misconceptions

- LSTAR write is not a one-step stable exploit.
- WRMSR scope can be per logical processor; one CPU state may differ from another.
- Restoring state is not optional in real systems, but this repo does not provide restoration code.
- HVCI does not make the bug disappear; it changes what an attacker can do after control.

## Questions to Ask Yourself

1. Which MSR index is reachable and why?
2. Does the driver validate caller identity and device ACL?
3. Is the MSR core/thread scoped?
4. Which mitigation causes the first crash?
5. What would a defender see before the crash or state change?

## Related Repo Docs

- [Primitive reasoning framework](primitive-reasoning-framework.md)
- [Page-table deep dive](../windows-internals/page-table-and-address-translation-deep-dive.md)
- [HVCI/VBS deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md)

## References

- Idafchev WRMSR: https://idafchev.github.io/blog/wrmsr/
- xacone eneio64: https://xacone.github.io/eneio-driver.html
- Synacktiv shadow stack PDF for CET-related MSRs: https://www.synacktiv.com/sites/default/files/2025-06/sstic_windows_kernel_shadow_stack_mitigation.pdf

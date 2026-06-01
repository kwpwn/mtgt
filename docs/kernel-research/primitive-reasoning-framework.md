# Primitive Reasoning Framework

Backlinks: [README](../../README.md) | [topic index](../research-index/topic-index.md) | [learning path](../research-index/windows-kernel-pwn-learning-path.md)

## Purpose

This framework teaches how to evaluate a Windows kernel vulnerability primitive without turning it into an operational exploit recipe.

## What You Will Learn

- How to describe a primitive by power, constraints, preconditions, and side effects.
- Why mitigations change the end goal from code execution to data-only or existing-code reasoning.
- How to connect primitive behavior to defensive telemetry.

## Prerequisites

Read [page-table deep dive](../windows-internals/page-table-and-address-translation-deep-dive.md) and [IOCTL reversing workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md).

## Primitive Scorecard

For any source, fill this first:

| Question | Why it matters |
|---|---|
| What address space does it touch? | User VA, kernel VA, physical, MSR, MMIO, port I/O all differ. |
| Is the target controlled? | Arbitrary, constrained, relative, fixed, one-shot, repeated. |
| Is the value controlled? | Full value, partial value, increment/decrement, copy, zero, stale value. |
| What width? | Byte/word/dword/qword/range changes usefulness. |
| Is it repeatable? | One-shot primitives are much harder to compose. |
| What address knowledge is needed? | KASLR, object leak, symbol offsets, build-specific fields. |
| What cleanup is required? | PatchGuard and object consistency may punish lingering corruption. |
| What mitigation blocks the intended goal? | HVCI, KCFG, CET, KDP, blocklist, Secure Boot. |

## Primitive Matrix

| Primitive | Power | Constraints | Mitigations | Detection | Safe mental model |
|---|---|---|---|---|---|
| Arbitrary read | Leak kernel memory, defeat KASLR, inspect objects | Need address, width, stable context | KASLR reduced by leak; VBS can isolate secrets | Unusual IOCTLs, info-leak crash patterns | A read is reconnaissance, not immediate control. |
| Arbitrary write | Modify object fields or pointers | Need target address, value, consistency | HVCI blocks unsigned code path; KCFG/CET constrain control flow; KDP may protect data | Kernel crashes, object tamper, CI/PatchGuard events | A write is only useful if the object tolerates the change. |
| Physical R/W | Access RAM via PFN/mapping | Need translation, page size, CR3 context | VBS/KDP/HLAT can break remapping assumptions | Driver load, PhysicalMemory mapping, IOCTL burst | Physical is below virtual; translation is the hard part. |
| MSR write | Change CPU control registers such as syscall target | CPU scope, affinity, immediate crash risk | SMEP/SMAP, KVA shadow, PatchGuard, HVCI | BSOD after syscall, suspicious driver IOCTL | MSRs control CPU behavior; bad writes crash fast. |
| MMIO/port I/O | Device/hardware control | Hardware-specific, unstable, often privileged | IOMMU, driver policy, access checks | Hardware driver IOCTLs, device instability | Treat as device attack surface, not generic memory. |
| Wild copy | Large uncontrolled/partially controlled copy | Need stop condition and target object adjacency | Pool hardening, KASLR, NX, HVCI | Crashes in copy path, pool corruption | Useful only when bounded into a meaningful overwrite. |
| PreviousMode | Turn user probes into kernel-trusted access | Offset/build-specific, must restore | Windows 11 23H2+ checks and bugchecks affect tricks | KTHREAD anomalies, privileged memory syscalls | A tiny field can shift trust semantics. |
| Handle/object abuse | Abuse references, access masks, callbacks | Need object lifecycle knowledge | PPL, Ob callbacks, access checks, silo/appcontainer | Handle opens, callback telemetry | Security is often in object metadata. |
| Callback tamper concept | Blind or alter security monitoring paths | Protected by PatchGuard/KCFG/HVCI/KDP | PatchGuard, VBS, CI, EDR self-defense | Callback list changes, driver loads, security service anomalies | Study for defense; do not build tamper tooling. |
| DSE/g_CiOptions concept | Affect driver signature enforcement | Highly protected, version-specific | VBS/HVCI/KDP/PatchGuard/Secure Boot | Code Integrity events, driver load anomalies | CI is a policy boundary, not a stable target. |

## Why Primitive Power Changes by Version

| Version posture | Practical meaning |
|---|---|
| Windows 7 | Many historical code-execution chains lack modern mitigations; mostly useful for learning old assumptions. |
| Windows 10 | SMEP, KASLR, pool hardening, PatchGuard, and increasing telemetry raise the bar. |
| Windows 11 22H2 | HVCI/VBS are commonly relevant; data-only and existing-code concepts matter more. |
| Windows 11 23H2/24H2+ | More leaks removed, PreviousMode tricks constrained, blocklist and HVCI assumptions must be verified. |

## Detection Notes

Defensive mapping should start before the final primitive effect:

| Stage | Telemetry |
|---|---|
| Driver arrival | File creation, service key, Code Integrity, image load, certificate metadata. |
| Device access | Device object name, handle open, caller integrity, repeated IOCTLs. |
| Primitive probing | Crashes, invalid parameter storms, unusual physical/MSR access. |
| Object effect | Token/protection/callback/list anomalies, system service behavior changes. |
| Cleanup | Rapid restore patterns, service deletion, file deletion, logs around reboot/bugcheck. |

## Common Misconceptions

- “Arbitrary write” without address knowledge is not enough.
- “HVCI bypass” is not a universal property; it depends on CPU, hypervisor, build, and exact primitive.
- Data-only attacks can be as serious as code execution, but they are also version fragile.
- PoC offsets are teaching artifacts, not reusable facts.

## Questions to Ask Yourself

1. Why is this primitive sufficient or insufficient?
2. Which mitigation directly breaks the desired end state?
3. What version assumption is hidden in the write-up?
4. What observable action must happen before the primitive is used?
5. What cleanup or restoration would a crash dump reveal?

## Related Repo Docs

- [MSR notes](msr-wrmsr-research-notes.md)
- [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md)
- [HVCI/VBS deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md)
- [BYOVD detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md)

## References

- HN Security pointer dereference to R/W: https://hnsecurity.it/blog/from-arbitrary-pointer-dereference-to-arbitrary-read-write-in-latest-windows-11/
- IoRing primitive repo: https://github.com/yardenshafir/IoRingReadWritePrimitive
- Idafchev WRMSR: https://idafchev.github.io/blog/wrmsr/
- Theori CVE-2023-28218: https://theori.io/blog/exploiting-windows-kernel-wild-copy-with-user-fault-handling-cve-2023-28218
- ExploitPack Shadow SSDT: https://www.exploitpack.com/blogs/news/shadow-ssdt-hijacking-to-achieve-kernel-code-execution-via-rw-primitives

# Windows Kernel Pwn Learning Path

Backlinks: [README](../../README.md) | [topic index](topic-index.md) | [question bank](windows-kernel-pwn-question-bank.md) | [case-study matrix](case-study-matrix.md)

## Purpose

This roadmap turns the repository into a deep-learning notebook for legal Windows kernel security research. The goal is not to memorize exploit chains; the goal is to reason from internals to primitive power, mitigation pressure, version differences, and defensive telemetry.

## Level 0: C/C++, Windows Basics, PE, Calling Convention, WinDbg

| Item | Notes |
|---|---|
| Learning goals | Read C/C++ driver code, understand PE sections/imports, Windows x64 calling convention, IRQL basics, WinDbg symbols. |
| Why | Most kernel bugs are boring until you can explain which pointer, length, object, or access check became wrong. |
| Repo docs | `docs/debugging/`, `MEMORY.md`, existing core handbook files. |
| Outside sources | Microsoft Learn driver docs, Windows Internals, public symbol server docs. |
| Check questions | What does `rcx/rdx/r8/r9` mean at a call site? Why does a bad symbol path ruin kernel debugging? Why does PE section permission matter? |
| Lab-safe exercise | Load a benign Microsoft symbol in WinDbg and identify a function prologue, arguments, and module base. |
| Pitfalls | Treating decompiler output as source code; ignoring IRQL and pageable code. |

## Level 1: Kernel Architecture, Processes, Threads, Handles, Objects

| Item | Notes |
|---|---|
| Learning goals | Understand object manager, handles, reference counts, `EPROCESS`, `ETHREAD/KTHREAD`, tokens, callbacks. |
| Why | Many primitives become meaningful only because they target objects with security semantics. |
| Repo docs | [primitive framework](../kernel-research/primitive-reasoning-framework.md), [glossary](glossary.md). |
| Outside sources | Windows Internals, Microsoft object manager docs, Unit42 Win32k background. |
| Check questions | Why is a kernel pointer leak valuable? Why can a handle table leak become a primitive enabler? |
| Lab-safe exercise | Use WinDbg in a local VM to inspect object type names and handle counts without modifying memory. |
| Pitfalls | Assuming offsets are stable; confusing object address with handle value. |

## Level 2: Driver Model, IRP, IOCTL, Device Object, Symbolic Link, SDDL

| Item | Notes |
|---|---|
| Learning goals | Follow `DriverEntry`, device creation, symbolic links, dispatch tables, IOCTL control flow, SDDL/ACL. |
| Why | BYOVD and driver bugs usually start at a device object callable from user mode. |
| Repo docs | [IOCTL reversing workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md), [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md). |
| Outside sources | Microsoft WDK docs, Idafchev WRMSR, xacone eneio64, Julian Pena driver posts. |
| Check questions | Why does `IoCreateDeviceSecure` matter? What is encoded in `CTL_CODE`? When is `METHOD_NEITHER` risky? |
| Lab-safe exercise | Reverse a benign sample driver dispatch table and list IOCTLs without calling them. |
| Pitfalls | Focusing on IOCTL values before validating access control and buffer method. |

## Level 3: Kernel Memory, Pool, Paging, PTE, CR3, KVA Shadow

| Item | Notes |
|---|---|
| Learning goals | Explain virtual-to-physical translation, page-table levels, PFN, NX/U/S/RW bits, pool allocation classes. |
| Why | Modern primitives often require address translation or object adjacency reasoning. |
| Repo docs | [page-table deep dive](../windows-internals/page-table-and-address-translation-deep-dive.md), [pool map](../windows-heap/kernel-pool-exploitation-study-map.md). |
| Outside sources | xacone eneio64, Datafarm HVCI, vp777 pool overflow, Theori wild copy. |
| Check questions | Why is physical R/W not automatically virtual R/W? How does KVA shadow change syscall entry reasoning? |
| Lab-safe exercise | Walk a virtual address by hand from a documented diagram, not by modifying live PTEs. |
| Pitfalls | Assuming one process CR3 view exposes every kernel mapping in the same way. |

## Level 4: Vulnerability Classes

| Item | Notes |
|---|---|
| Learning goals | Classify arbitrary R/W, physical R/W, MSR write, MMIO/port I/O, wild copy, pointer dereference, UAF, overflow, race/TOCTOU, PreviousMode, handle abuse. |
| Why | Classification predicts constraints, crash modes, mitigation impact, and detection. |
| Repo docs | [primitive framework](../kernel-research/primitive-reasoning-framework.md), [MSR notes](../kernel-research/msr-wrmsr-research-notes.md). |
| Outside sources | Idafchev WRMSR, Theori CVE-2023-28218, HN Security pointer deref, jeffaf AsIO3. |
| Check questions | Why is an arbitrary decrement weaker than arbitrary write but still dangerous? |
| Lab-safe exercise | For three source notes, write the primitive, constraints, and blocked mitigations. |
| Pitfalls | Calling every bug “arbitrary write” before proving write target, width, timing, and repeatability. |

## Level 5: Exploit Primitive Reasoning

| Item | Notes |
|---|---|
| Learning goals | Turn a bug class into a capability model: target control, width, repeatability, address knowledge, side effects. |
| Why | Exploitability is a reasoning problem, not just a code problem. |
| Repo docs | [primitive framework](../kernel-research/primitive-reasoning-framework.md), [question bank](windows-kernel-pwn-question-bank.md). |
| Outside sources | IoRing primitive, HN Security, vp777. |
| Check questions | What extra condition turns physical R/W into object field manipulation? What telemetry appears before privilege change? |
| Lab-safe exercise | Build a non-executable primitive scorecard for a source note. |
| Pitfalls | Ignoring cleanup/restoration and PatchGuard-triggered delayed crashes. |

## Level 6: Mitigation-Aware Exploitation Concepts

| Item | Notes |
|---|---|
| Learning goals | Understand SMEP, SMAP, NX, KASLR, KCFG, XFG, CET, HVCI, VBS, KDP, VT-rp, HLAT, PatchGuard. |
| Why | Modern Windows changes the allowed end state: data-only/existing-code concepts often replace unsigned shellcode. |
| Repo docs | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md). |
| Outside sources | Connor McGarr HVCI, XPN, Tandasat, Synacktiv shadow stack, NCC Group mitigation list. |
| Check questions | Why does HVCI block writable-executable kernel memory? What does KCFG break in old ROP thinking? |
| Lab-safe exercise | Make a matrix: primitive vs HVCI on/off vs likely detection. |
| Pitfalls | Treating “HVCI bypass” claims as universal without CPU, build, Secure Boot, and blocklist context. |

## Level 7: BYOVD Research Methodology

| Item | Notes |
|---|---|
| Learning goals | Build a defensive taxonomy of signed vulnerable drivers, driver loading policy, blocklist behavior, and device ACL risk. |
| Why | BYOVD is a trust-boundary failure: a signed driver can expose kernel capability to an untrusted caller. |
| Repo docs | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md), [detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md). |
| Outside sources | Quarkslab Lenovo, xacone eneio64, BlackSnufkin, GhostWolfLab. |
| Check questions | Why does a valid signature not prove safe behavior? What changes when vulnerable driver blocklist is enabled? |
| Lab-safe exercise | Inventory drivers in a lab VM and classify by vendor, signature, load path, and device ACL. |
| Pitfalls | Downloading/running PoCs instead of extracting defensive indicators and design lessons. |

## Level 8: Detection Engineering and Telemetry

| Item | Notes |
|---|---|
| Learning goals | Map driver load, Code Integrity, ETW, Sysmon, MDE, vulnerable driver indicators, crash telemetry, and object tamper symptoms. |
| Why | Research without telemetry produces fragile knowledge. |
| Repo docs | [BYOVD detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md). |
| Outside sources | Unit42, G3tSyst3m as unsafe example, GhostWolfLab, Microsoft docs. |
| Check questions | What events appear before a driver is usable? How would blocklist failure appear? |
| Lab-safe exercise | Collect benign driver load events in a VM and document fields, not bypasses. |
| Pitfalls | Overfitting to hash-only detections; ignoring certificates, paths, service keys, and device names. |

## Level 9: Case Study Reading Methodology

| Item | Notes |
|---|---|
| Learning goals | Read a public write-up without copying exploit code: extract assumptions, primitive, version, mitigation, detection, uncertainty. |
| Why | Public write-ups often mix timeless concepts with build-specific details. |
| Repo docs | [case-study matrix](case-study-matrix.md), source notebook. |
| Outside sources | All curated sources. |
| Check questions | Which claim is general? Which claim is only true on a specific build? Which claim needs independent verification? |
| Lab-safe exercise | Summarize one source in the 15-question template. |
| Pitfalls | Treating GitHub PoC README claims as vendor-confirmed facts. |

## Level 10: Capstone Lab Design, Defensive and Lab-Safe

| Item | Notes |
|---|---|
| Learning goals | Design a controlled VM lab for reversing, crash triage, telemetry, and mitigation comparison without weaponized payloads. |
| Why | A good lab teaches causality while preventing accidental misuse. |
| Repo docs | [remaining work](remaining-work.md), [source coverage report](source-coverage-report.md). |
| Outside sources | Microsoft Learn, vendor guidance, safe reversing references. |
| Check questions | What is the explicit research question? What is out of scope? What evidence proves the conclusion? |
| Lab-safe exercise | Build a capstone plan: one benign driver, one IOCTL map, one mitigation matrix, one detection report. |
| Pitfalls | Mixing production credentials, internet-exposed systems, or live vulnerable drivers into a research lab. |

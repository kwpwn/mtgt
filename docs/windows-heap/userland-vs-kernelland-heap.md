# Userland Heap vs Kernelland Pool

## Purpose

This document compares user-mode heap behavior and kernel pool behavior for Windows memory-corruption research, debugging, and defensive triage.

## Background

User-mode heap bugs and kernel pool bugs are often described with the same words:

- use-after-free,
- overflow,
- double free,
- type confusion,
- race.

But the operational meaning changes sharply once the bug moves from a process-private allocator into the kernel's shared privileged memory environment.

## Core Concepts

The most useful mental model is not "heap vs pool" as a naming difference. It is:

```text
private allocator inside one process
vs
privileged allocator shared across kernel subsystems and drivers
```

That difference changes lifetime assumptions, crash impact, verification strategy, and telemetry.

## Technical Deep Dive

### Allocation control and isolation

| Property | User-mode heap | Kernel pool |
|---|---|---|
| Isolation boundary | Usually one process | Shared privileged kernel environment |
| Caller privilege | Restricted by user mode | Kernel mode |
| Recovery after fault | Process crash often contains damage | System-wide crash or subsystem instability |
| External noise | Process-local and app-specific | Cross-driver, cross-subsystem timing noise |

### Object lifetime

User-mode objects are often easier to reason about because the address space, thread model, and object graph are narrower. Kernel objects may:

- outlive the creating thread,
- move through IRP queues, worker items, or callbacks,
- be touched at different IRQLs,
- be shared across security, I/O, networking, and memory-management components.

### Metadata exposure

User-mode heap metadata is still important, but the kernel pool environment adds stronger blast radius because corruption can affect:

- executive objects,
- driver-owned state,
- security-relevant object fields,
- completion routines or callback-linked data structures.

### Reliability and crash impact

| Bug shape | User-mode impact | Kernel impact |
|---|---|---|
| UAF | Often process-scoped logic or control-flow corruption | Shared object reuse, broad instability, possible system bugcheck |
| Overflow | Neighboring user object or heap metadata | Neighboring kernel object, pool metadata, or system instability |
| Type confusion | App-logic or browser-style primitive | High-value object misuse if object class is privileged |
| Race | Process-local inconsistency | Cross-thread or cross-core kernel lifetime fault |

### Telemetry

User-mode:

- richer process telemetry,
- easier crash capture,
- verifier and page heap at process granularity.

Kernel:

- stronger need for crash dump triage,
- Driver Verifier and Special Pool,
- more limited semantic telemetry around private driver internals,
- higher value in pool tags, driver load, and object-level debugging.

### Mitigation differences

| Topic | User-mode heap | Kernel pool |
|---|---|---|
| Code execution assumptions | CFG/CET increasingly relevant | HVCI, CET, kCFG, NX, PatchGuard pressure payload routes |
| Allocator hardening | LFH, segment heap, cookies, page heap | Pool cookies, verifier, NonPagedPoolNx, newer allocation APIs |
| Containment | Often process kill | Often bugcheck or broader system effect |

### Comparison table by bug family

| Bug family | Userland interpretation | Kernelland interpretation | Defensive priority shift |
|---|---|---|---|
| Userland UAF | Recycled app object or metadata | Recycled privileged object or pool neighbor | Higher because object semantics can be security-critical |
| Kernel pool UAF | N/A | Shared-lifetime fault with system-wide effect | Very high |
| Userland overflow | Object or heap-metadata corruption inside one process | N/A | Medium-high depending on target |
| Kernel pool overflow | N/A | Adjacent kernel object or allocator state corruption | Very high |
| Type confusion | Logic/object-layout mismatch | Wrong privileged object interpretation | Very high when object class is sensitive |
| Race condition | Often app-specific | IRQL, callback, work-item, or refcount-sensitive | High and often underdiagnosed |

### Research notes

A stable user-mode primitive does not imply a stable kernel-mode analogue. Kernel work usually has:

- higher privilege,
- worse failure cost,
- more mitigation pressure,
- more shared allocator state,
- better value from semantic corruption and worse value from naive payload thinking.

## Windows Version Notes

- User-mode heap analysis must now account for both NT heap and segment heap behavior.
- Kernel pool analysis on modern Windows must account for NonPagedPoolNx, verifier-assisted diagnosis, and stronger control-flow mitigations that reduce the value of classic executable-pool ideas.

## Common Mistakes

- Reusing user-mode exploitation intuition directly in kernel pool analysis.
- Underestimating the effect of shared subsystem activity on kernel allocation reproducibility.
- Treating crash frequency as the only measure of importance.
- Ignoring object semantics in favor of allocator trivia.

## Debugging / Inspection Notes

User-mode:

- `!heap`
- page heap
- Application Verifier

Kernel-mode:

- `!pool`
- `!poolfind`
- `!poolused`
- `!verifier`

Comparison checklist:

- Which allocator is active?
- Who owns the object lifetime?
- Is the corruption local or shared?
- What verification tool surfaces it earlier?
- Does the crash contain the fault or only report it late?

## Defensive Angle

This comparison matters because it changes prioritization. A user-mode bug may be easier to trigger, but a kernel pool bug can have much broader consequences even when it is less reliable. Defensive review should therefore weigh:

- object sensitivity,
- privilege boundary crossed,
- ability to verify and reproduce,
- availability of telemetry and crash artifacts,
- likelihood of containment versus system-wide failure.

## Lab-Safe Exercises

1. Compare one user-mode UAF crash and one kernel pool UAF crash and record how lifetime ownership differs.
2. Build a table of which debugging tools help most in user mode versus kernel mode.
3. Review an existing repo doc and tag each bug discussion as "allocator-centric", "object-centric", or "mixed".

## References / Further Reading

- Microsoft Learn, `!heap`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-heap
- Microsoft Learn, `Low-fragmentation Heap`:
  https://learn.microsoft.com/en-us/windows/win32/memory/low-fragmentation-heap
- Microsoft Learn, `ExAllocatePool2`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2
- Microsoft Learn, `Driver Verifier`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier
- Existing repo note, `04_connor-mcgarr-study/04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`

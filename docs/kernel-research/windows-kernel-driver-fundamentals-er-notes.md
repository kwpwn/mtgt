# Windows Kernel Driver Fundamentals From ER Article 01

Updated: 2026-05-28

## Purpose

This note distills the useful driver-research lessons from Alexandre Borges's
`Exploiting Reversing (ER) series: Article 01 - Windows kernel drivers part 01`.

Source PDF:

- `E:\Dowloads\exploit_reversing_01-1.pdf`

This is not a translation mirror. It is a repo-native study note that turns the
article into reusable research checkpoints:

```text
driver basics
  -> object model
  -> device exposure
  -> IRP path
  -> IRQL / ISR / DPC
  -> memory residency
  -> RE implications
```

Use it with:

- `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
- `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md`
- `docs/userland-to-kernel/ioctl-reverse-engineering.md`
- `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md`
- `docs/kernel-research/race-and-toctou-in-drivers.md`
- `docs/debugging/crash-dump-driver-triage.md`

## Why This Article Matters

A lot of exploit and BYOVD material starts too late. It begins at:

```text
here is an IOCTL
here is an arbitrary write
here is the impact
```

That is not enough. Before a driver can be exploited or abused, it first has to
exist as a Windows I/O object with:

- a `DriverEntry`,
- one or more device objects,
- a namespace or interface reachable from user mode or another driver,
- dispatch routines,
- synchronization and IRQL constraints,
- memory allocation rules,
- teardown rules.

This article is valuable because it reminds you that driver research begins with
the I/O model, not with the bug.

## The Core Mental Model

The safe high-level model is:

```text
DriverEntry
  -> create/register device state
  -> expose namespace or interface
  -> assign dispatch path
  -> receive IRPs
  -> touch memory / objects / hardware
  -> complete request
  -> unload safely
```

Every later exploitability question is attached to one of those stages.

## Driver Object Versus Device Object

The article spends time on a distinction many newcomers blur together:

- `DRIVER_OBJECT` describes the driver as an executable kernel component.
- `DEVICE_OBJECT` describes an I/O endpoint owned by that driver.

Why the distinction matters:

```text
driver binary loaded
  !=
user mode can talk to it
```

The interesting attack surface usually appears at the device layer, not merely at
the image layer.

Research questions:

- How many device objects does the driver create?
- Are they named?
- Are they control devices, functional devices, filter devices, or internal-only?
- Which dispatch routines are attached to them?
- Is there a symbolic link or device interface that makes them reachable?

This is why `IoCreateDevice`, `IoCreateDeviceSecure`, `IoCreateSymbolicLink`, and
interface registration calls are such strong anchors during static RE.

## Why Device Naming Is A Security Question

The article's basic `IoCreateDevice` / symbolic-link discussion becomes a
reachability problem in modern research.

If a device is:

- named in the NT namespace,
- linked into DOS namespace,
- or exposed through a device interface,

then the next question is not "interesting implementation?" but:

```text
who can open it?
```

That leads directly to ACL/SDDL reasoning:

- broad DACL means low-friction reachability,
- admin-only or service-only ACL changes attacker preconditions,
- unnamed internal devices may still be reachable indirectly through another
  stack component or helper service.

This is where fundamentals become exploitation triage.

## IRPs Are The Real User/Kernel Contract

The article is introductory, but the deepest lesson is that the driver is not
just "called". It participates in the Windows I/O request model.

That means:

- major function tables matter,
- stack locations matter,
- buffered/direct/neither methods matter,
- completion and lifetime matter.

The practical RE translation is:

```text
MajorFunction[IRP_MJ_DEVICE_CONTROL]
  -> current stack location
  -> IOCTL code
  -> buffer interpretation
  -> privileged sink
```

If you skip directly to the sink and do not understand the IRP contract, you will
misread:

- where the input came from,
- whether the pointer is trusted,
- when the memory is valid,
- whether the driver copied or referenced the user buffer,
- whether the request can outlive the caller context.

## `IoCreateDevice` Is Not Just Boilerplate

For a beginner, `IoCreateDevice` looks like setup code. For a researcher, it
answers several high-value questions at once:

- device type,
- flags,
- exclusivity,
- object existence,
- later symbolic-link or interface exposure.

Why this matters:

```text
the creation site often explains what assumptions the rest of the driver makes
about callers, buffering, and intended usage
```

Examples of downstream consequences:

- control-device patterns often imply private IOCTLs,
- stack-attached functional/filter devices imply different IRP expectations,
- secure-open and access-control choices affect who can trigger the code path.

## Type Libraries In IDA Are Not Cosmetic

The article's note about loading `ntddk` type information into IDA is worth
keeping as a permanent repo reminder.

Why:

```text
correct structure and prototype recovery
  -> fewer false assumptions
  -> better field naming
  -> better call-site reasoning
```

Without types, beginners often reverse:

- raw offsets without ownership,
- callback signatures without context,
- object pointers without field meaning,
- dispatch paths without recognizing standard I/O-manager idioms.

This becomes especially damaging when the code touches:

- `DEVICE_OBJECT`,
- IRP stack locations,
- MDLs,
- process/thread objects,
- callback registration structures.

Type recovery does not solve private-layout drift, but it drastically improves the
first pass.

## IRQL Is A Design Constraint, Not Trivia

One of the strongest parts of the article is the interrupt/IRQL/ISR/DPC section.

New researchers often learn IRQL as vocabulary:

- `PASSIVE_LEVEL`,
- `APC_LEVEL`,
- `DISPATCH_LEVEL`,
- interrupt DIRQLs.

That is too shallow. The right question is:

```text
what operations are legal at the current execution level?
```

Why it matters:

- pageable memory access can fault,
- waiting/blocking may be illegal,
- certain DDIs are illegal,
- callback or completion paths can run in contexts very different from the
  original caller,
- a request path that looks fine at `PASSIVE_LEVEL` can crash in DPC context.

This is why so many bugchecks reduce to:

```text
wrong pointer, wrong IRQL, wrong lifetime
```

## ISR And DPC: Why The Split Exists

The article explains that an ISR should stay short and that heavier work is moved
into DPC context.

That split is not just implementation taste. It encodes a kernel invariant:

```text
interrupt path must stop/acknowledge the interrupt fast
  -> defer heavier processing
  -> continue at a lower synchronization cost
```

For researchers, this creates several implications:

- work may be split across contexts,
- the original triggering actor may no longer be current,
- pointers captured during one phase may be used in another,
- lock rules and pageable-data rules can change mid-flow.

That is why DPC-heavy drivers deserve extra scrutiny for:

- stale context,
- race conditions,
- user-buffer lifetime misuse,
- IRQL-unsafe helper calls,
- object cleanup during in-flight deferred work.

## Memory Residency: Paged Versus Nonpaged Is Operational

The article emphasizes kernel memory pools because driver code runs under rules
user-mode developers do not normally think about.

The important research lesson is:

```text
allocation type is part of program correctness
```

Why:

- nonpaged memory is required for high-IRQL access,
- paged memory is cheaper but unsafe in many asynchronous or elevated contexts,
- misuse may not fail immediately; it can fail only under specific timing or load.

This creates common bug classes:

- pageable code or data touched at `DISPATCH_LEVEL`,
- freed nonpaged context still referenced by DPC/work item/callback,
- pool-type mismatch with actual call path,
- assumptions that a user buffer can stand in for stable kernel storage.

## Why Driver Unload Matters To Exploitability

Introductory material often underplays unload paths. That is a mistake.

Unload code tells you:

- which objects the author thinks they own,
- whether callbacks are unregistered,
- whether symbolic links are removed,
- whether queued work is drained,
- whether references are balanced.

If unload/cleanup is weak, the driver may carry:

- dangling callback state,
- stale device references,
- object lifetime bugs,
- race opportunities around stop/remove/unload.

Even when the target bug is not in unload, the unload path tells you how mature
the driver's lifecycle discipline really is.

## What A Beginner Should Actually Recover First

From a new driver sample, recover these in order:

1. `DriverEntry` and unload routine.
2. Device creation sites and device names.
3. Symbolic links or interfaces.
4. Major-function assignments or KMDF callback registration.
5. `IRP_MJ_DEVICE_CONTROL` or equivalent queue handler.
6. Buffer model and request lifetime.
7. Privileged sinks.
8. IRQL transitions, deferred work, callbacks, timers.

This sequence is more important than memorizing every kernel structure name.

## Bridge To Modern BYOVD And Exploit Research

This article is introductory, but it still matters for BYOVD because every
vulnerable or abusable driver eventually has to answer:

- How is it opened?
- Which IOCTL or IRP path is reachable?
- What object or hardware state can it touch?
- Does it run in WDM or KMDF shape?
- Does it misuse IRQL, MDLs, or raw pointers?
- Does cleanup suggest broader engineering weakness?

The bug may be modern, but the surface still begins with classic driver
fundamentals.

## Common Mistakes When Reading Driver Intro Material

- Treating device exposure as mere plumbing instead of attack-surface definition.
- Thinking `DriverEntry` is enough without mapping the request path.
- Memorizing IRQL names without connecting them to legal memory and API usage.
- Ignoring unload/cleanup because "the bug is somewhere else."
- Looking for shellcode opportunities before understanding object/lifetime
  constraints.
- Assuming a loaded driver always implies an exposed user-mode attack path.

## How To Use This Note In The Repo

Use this note when:

- onboarding someone into driver RE,
- reviewing a public PoC that starts too deep in the chain,
- explaining why `IoCreateDevice` and IRQL still matter in 2026,
- bridging from Windows Internals reading into practical triage.

Recommended follow-up path:

1. `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
2. `docs/userland-to-kernel/ioctl-reverse-engineering.md`
3. `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md`
4. `docs/userland-to-kernel/method-neither-research-notes.md`
5. `docs/kernel-research/race-and-toctou-in-drivers.md`
6. `docs/debugging/crash-dump-driver-triage.md`

## Study Questions

1. Why is a `DEVICE_OBJECT` often more important than the driver image itself for
   attack-surface mapping?
2. Why does IRQL turn memory-allocation choices into correctness constraints?
3. Why is DPC usage a research signal for lifetime and race bugs?
4. What can you infer from `IoCreateDeviceSecure` that you cannot infer from a raw
   sink alone?
5. Why does the unload path reveal more than just cleanup quality?
6. When reading a PoC, which missing driver-fundamentals questions most often hide
   the real preconditions?

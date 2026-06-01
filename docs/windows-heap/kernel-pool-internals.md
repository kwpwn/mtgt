# Kernel Pool Internals

## Purpose

This document expands kernel pool coverage beyond the repo's existing conceptual overview. It focuses on allocation lifecycle, pool categories, hardening, debugging, and crash triage relevant to Windows kernel research.

## Background

Kernel pool is where drivers and kernel subsystems request dynamic memory for objects, buffers, IRPs, lookaside-style state, and many transient internal structures. Modern pool research is less about "put shellcode in pool" and more about:

```text
which object is allocated,
where it sits,
how long it lives,
what metadata protects it,
and what the kernel will do if that object is corrupted.
```

## Core Concepts

### Paged pool vs nonpaged pool

- Paged pool can be paged out and is unsuitable for code paths that require memory at elevated IRQL.
- Nonpaged pool stays resident and is therefore important for high-IRQL paths, dispatcher objects, and many driver-critical structures.

This distinction affects both reliability and debugging because residency and IRQL constraints decide which code paths can safely touch which allocations.

### Pool tags

Pool tags are four-byte identifiers associated with many allocations. They are one of the most useful defensive and debugging hooks because they help correlate memory usage and corruption patterns with specific subsystems or drivers.

### Big pool allocations

Large allocations may be tracked differently from ordinary small-pool behavior. Analysts should not force every crash into a small-object mental model when the allocation path suggests a larger or differently managed region.

### Pool allocation lifecycle

At a conceptual level:

```text
allocate
  -> initialize
  -> publish pointer or embed object into subsystem state
  -> use / reference / queue / link
  -> free or recycle
```

Corruption is most dangerous when the object remains reachable after a stale assumption about lifetime, type, or adjacency.

### `ExAllocatePool2` and `ExAllocatePool3`

Modern Windows deprecates older pool allocation patterns in favor of newer APIs such as `ExAllocatePool2` and `ExAllocatePool3`. This matters for research because allocator APIs often carry:

- pool type and flags,
- quota or policy behavior,
- initialization expectations,
- improved security posture compared with older routines.

## Technical Deep Dive

### Pool header concept

Analysts often speak loosely about the "pool header". What matters is not memorizing every layout detail across builds, but understanding that allocator-managed metadata exists near or around the allocation and can influence:

- size interpretation,
- state tracking,
- verification,
- free-path behavior,
- tag association.

Corruptions can therefore have three broad effects:

- object-only corruption,
- allocator-metadata corruption,
- combined corruption that first alters object behavior and later crashes during free or reuse.

### Kernel pool grooming concept

At a lab-safe level, grooming means:

```text
shape the timing and size profile of allocations
so a target object lands in a studyable neighborhood
```

In kernel work, this is harder than in user mode because:

- allocator state is shared across broader subsystem activity,
- timing noise is higher,
- crashes are more disruptive,
- IRQL and work-queue behavior change lifetimes.

### Kernel memory bug classes

| Bug class | Typical kernel effect | Why it matters |
|---|---|---|
| UAF | Stale pointer hits reused object | Can become logic corruption or direct crash |
| Overflow | Adjacent object or allocator metadata corruption | Severity depends on target object class |
| Type confusion | Wrong object interpretation with valid pointer | Often highly stable if object lifetimes align |
| Double free | Allocator state inconsistency | Often caught by verifier or hardening |
| Race condition | Lifetime mismatch or double completion | Often difficult to reproduce without instrumentation |

### Pool hardening

Modern Windows pool hardening changes the research landscape:

| Hardening feature | Defensive effect | Research implication |
|---|---|---|
| Pool cookies / integrity checks | Detect some metadata damage | Delayed crashes may indicate earlier corruption |
| NonPagedPoolNx | Reduces classic executable-pool assumptions | Pushes focus toward data-only and object corruption |
| Improved allocation APIs | Safer initialization and policy expression | Older vulnerable code patterns stand out more |
| Driver Verifier / Special Pool | Converts latent corruption into earlier failures | Essential for root-cause work |

### Defensive crash triage

A productive triage posture:

- identify the allocation type and likely tag,
- determine whether the crash occurred on access, free, or verifier check,
- separate object misuse from allocator-metadata damage,
- ask whether the failure depends on load, timing, or concurrency,
- determine whether the issue is driver-local or shared across a broader subsystem.

### Inspection matrix

| Observation | Likely interpretation |
|---|---|
| Crash at free with verifier | Earlier overwrite or UAF likely |
| Crash only under Special Pool | Boundary overrun/underrun or freed-memory use |
| Corruption tied to one tag | Strong candidate for driver ownership |
| Inconsistent object type at stable address | Reuse pattern or type confusion |

## Windows Version Notes

- NonPagedPoolNx changed the strategic value of classic pool code-execution ideas.
- Newer allocation routines (`ExAllocatePool2`, `ExAllocatePool3`) are part of the modernization path and matter in code review.
- Pool internals remain build-sensitive, so analysts should not overfit old layout assumptions to current Windows 10/11 systems.

## Common Mistakes

- Treating all kernel pool bugs as equivalent to old Windows 7 exploitation patterns.
- Ignoring IRQL and residency requirements when reasoning about object lifetime.
- Focusing only on overflows and missing logic-oriented type confusion or UAF patterns.
- Assuming the first crash location is the original corruption site.
- Forgetting that verifier can drastically improve signal quality.

## Debugging / Inspection Notes

Useful WinDbg commands:

- `!pool`
- `!poolfind`
- `!poolused`
- `!verifier`
- `!analyze -v`

Useful validation tools:

- Driver Verifier
- Special Pool

Lab-safe debugging flow:

```text
collect bugcheck and stack
  -> inspect suspect tag / allocation class
  -> determine access-vs-free failure
  -> compare verifier and non-verifier behavior
  -> correlate to driver code path
```

## Defensive Angle

Kernel pool research supports better driver review and crash response because it teaches reviewers to ask:

- what object class is exposed to corruption,
- what allocator assumptions the driver relies on,
- which verification features would surface the bug earlier,
- whether the resulting corruption is likely to be local, systemic, or cross-subsystem.

This is more useful operationally than memorizing historical pool exploitation tricks.

## Lab-Safe Exercises

1. On a kernel dump, use `!pool` and `!poolfind` to inspect a known tag and record what you can confirm versus what remains build-specific.
2. Run Driver Verifier on a test driver in a lab and compare the bugcheck behavior with verifier disabled.
3. Build a matrix for three historical kernel bug classes and note whether each is more about lifetime, adjacency, or metadata.

## References / Further Reading

- Microsoft Learn, `ExAllocatePool2`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2
- Microsoft Learn, `Allocating System-Space Memory`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/allocating-system-space-memory
- Microsoft Learn, `Special Pool memory corruption detection in Driver Verifier`:
  https://learn.microsoft.com/hr-hr/windows-hardware/drivers/devtest/special-pool
- Microsoft Learn, `How to Use Driver Verifier for Driver Testing`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier
- Microsoft Learn, `!verifier`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-verifier
- 04_connor-mcgarr-study existing repo note, `04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`
- Anquanke, `HEVD chi yi chu fen xi`:
  https://www.anquanke.com/post/id/170446

# User Mode Heap Internals

## Purpose

This document introduces the Windows user-mode heap from the perspective of bug triage, debugging, and exploit-primitive theory. It focuses on allocator concepts, metadata, bug classes, and defensive debugging tools rather than exploitation steps.

## Background

User-mode memory corruption research often starts with a deceptively simple idea:

```text
Corrupt an allocation,
then make the allocator or a neighboring object do something useful.
```

But allocator behavior decides whether corruption is local, detectable, recoverable, or immediately fatal. Modern Windows uses multiple allocator paths, and the analyst needs enough internal model to interpret crash artifacts and reason about heap-sensitive code.

## Core Concepts

### NT heap overview

The classic Windows user-mode heap is the long-standing general-purpose allocator used by many processes and APIs. It is not a single list of chunks; it is a set of policies and metadata structures that manage:

- segment-backed storage,
- free and busy blocks,
- lookaside or front-end optimizations,
- commit and decommit behavior,
- corruption checks and encoding.

### LFH

The low-fragmentation heap (LFH) is a policy layer that changes how certain allocation sizes are serviced. The key idea is to reduce fragmentation and improve performance by grouping same-sized allocations into predictable size classes. For debugging, this means:

- adjacent-block assumptions become less reliable,
- classic freelist corruption thinking becomes less directly applicable,
- crash interpretation needs heap-type awareness.

### Segment heap

Modern Windows also uses the segment heap in many user-mode scenarios. It changes the implementation details and invalidates many allocator assumptions inherited from older exploit literature. Analysts should treat "heap" as a family of allocator behaviors, not a single universal internal shape.

### Front-end vs back-end allocator

The front-end allocator is optimized for common small allocations and speed. The back-end allocator manages larger segments and slower paths. Research-wise, this distinction matters because bugs often manifest in one layer but are explained by transitions between the two.

### Allocation metadata

Metadata is the allocator's memory about memory. It may include:

- size information,
- state flags,
- links or indexes,
- encoded values,
- segment ownership context,
- debugging or verification state.

Corruption becomes dangerous when attacker-controlled writes affect metadata that later influences allocation, free, coalescing, or object lookup decisions.

## Technical Deep Dive

### Why heap grooming exists conceptually

Heap grooming is not a magic exploitation recipe. At a research level it means:

```text
shape allocator state so that the vulnerable allocation
lands near objects or metadata whose corruption is meaningful
and reproducible enough to study.
```

For defensive work, this idea matters because reproducibility often depends less on the original bug than on allocator state before the bug fires.

### Common bug classes

| Bug class | Typical allocator effect | Defensive interest |
|---|---|---|
| Use-after-free | Stale pointer reaches recycled object | Strong crash and logic-corruption signal |
| Double free | Heap state inconsistency or immediate detection | Often easier to detect with verifier tools |
| Overflow | Adjacent object or metadata corruption | Context-dependent severity |
| Underflow | Header or neighboring allocation corruption | Often caught later than the write itself |
| Type confusion | Wrong object layout used under valid lifetime | Often logic-oriented rather than allocator-oriented |

### Mitigations

User-mode heap hardening is layered. The analyst should think in terms of friction, not absolute prevention:

| Mitigation | What it tries to do | Analyst takeaway |
|---|---|---|
| Heap cookies / integrity checks | Detect corrupted management state | Corruption may be detected at free time, not write time |
| Safe unlinking / safer list handling | Reduce classic freelist abuse | Old unlinking writeups age badly |
| Encoded pointers | Make metadata corruption less direct | Pointer-looking fields may need decoding logic |
| LFH randomization / bucketing | Reduce predictability and fragmentation | Layout control assumptions weaken |
| CFG / CET interaction | Harden control-flow sinks after corruption | Memory corruption may still exist without immediate control-flow payoff |

### Debugging posture

The most productive user-mode heap mindset is:

```text
allocator diagnosis first,
payload fantasy later.
```

Questions to ask:

- Which heap implementation is active?
- Is the corruption detected immediately or only on free?
- Was the overwritten data user object state, allocator metadata, or both?
- Does page heap or Application Verifier change the timing?
- Are there reproducible size classes or allocation lifetimes involved?

### Inspection matrix

| Symptom | Likely first question |
|---|---|
| Crash on free | Was metadata or tail padding corrupted earlier? |
| Crash only under verifier | Is normal execution hiding the original fault site? |
| UAF with inconsistent target object | Is the freed slot being recycled by a size-stable bucket? |
| Overflow with no immediate crash | Did it hit object data instead of checked metadata? |

## Windows Version Notes

- LFH became broadly important starting with Vista-era systems and remains relevant.
- Segment heap materially changes many assumptions taken from older NT-heap-focused exploitation guides.
- Windows 10 and Windows 11 often require analysts to verify whether a target process uses NT heap, segment heap, or a mixture depending on subsystem and allocation path.

## Common Mistakes

- Assuming all processes use the same heap implementation.
- Treating LFH as a separate heap rather than a policy layer.
- Reading old heap exploitation writeups as if their adjacency assumptions still hold unchanged.
- Ignoring verifier-only crashes because they do not reproduce in default runtime.
- Confusing object-logic corruption with allocator-metadata corruption.

## Debugging / Inspection Notes

Useful user-mode debugging tools:

- `gflags` and page heap to catch overruns and underruns earlier.
- Application Verifier for heap-sensitive stops and diagnostics.
- WinDbg:
  - `!heap`
  - `!heap -s`
  - `!heap -triage`
  - `!heap -p`

Inspection flow:

```text
determine heap type
  -> identify failing allocation or free
  -> compare verifier vs non-verifier behavior
  -> decide whether corruption hit metadata, object data, or both
```

## Defensive Angle

For defenders and developers, the heap is a debugging problem long before it is an exploitation problem. The strongest outcomes often come from:

- enabling verification early in testing,
- correlating crashes with allocation size classes and call stacks,
- understanding whether a crash reflects immediate detection or delayed manifestation,
- documenting which process components allocate from which heap implementation.

## Lab-Safe Exercises

1. Use `!heap` on a user-mode dump and identify whether the target process shows NT heap, segment heap, or both.
2. Enable page heap on a non-production test binary and compare crash timing with and without page heap.
3. Build a table of three crash signatures and note whether they look more like UAF, overflow, double free, or type confusion.

## References / Further Reading

- Microsoft Learn, `!heap`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-heap
- Microsoft Learn, `GFlags and PageHeap`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/gflags-and-pageheap
- Microsoft Learn, `Application Verifier - Testing Applications`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier-testing-applications
- Microsoft Learn, `Application Verifier - Debugging Application Verifier Stops`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/application-verifier-debugging-application-verifier-stops
- Microsoft Learn, `Low-fragmentation Heap`:
  https://learn.microsoft.com/en-us/windows/win32/memory/low-fragmentation-heap
- Anquanke, `Windows nei he ti quan lou dong CVE-2018-8120 fen xi - shang`:
  https://www.anquanke.com/post/id/241057

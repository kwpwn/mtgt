# WinDbg Kernel Research Workflow

## Purpose

This document provides a safe, practical workflow for kernel debugging, dump analysis, and driver triage with WinDbg. It is designed for Windows kernel research, crash investigation, and defensive review rather than for exploit development.

## Setup Concepts

### Live kernel debugging vs crash dump

Crash dumps give stable postmortem state with lower operational risk. Live kernel debugging gives richer interactivity but changes timing and can alter behavior. Researchers should prefer dumps when the question is:

- what crashed,
- which driver was involved,
- what object or pool state existed at failure time.

Live debugging is more useful when the question is:

- how a request flows before crash,
- what a driver object or device stack looks like in motion,
- how verifier changes runtime behavior.

### Local kernel debugging

Local kernel debugging is convenient for inspection and learning, but it is not a substitute for clean VM-based workflows when studying unstable third-party drivers.

### VM kernel debugging

A VM is usually the best research environment because it provides:

- snapshots,
- rollback,
- deterministic repro workflows,
- safer crash handling,
- easier verifier experimentation.

### Symbols

WinDbg quality depends heavily on symbols. Without correct symbols:

- structure fields become misleading,
- stack traces degrade,
- mitigation and object analysis become unreliable,
- build drift is easy to misread as "weird kernel behavior".

### Source indexing and public vs private symbols

Public symbols are often enough for object and crash orientation, but not always enough for every field or source-level relationship. This is why symbol provenance must be part of every research note.

### Symbol cache hygiene

Symbol cache hygiene matters because stale or mixed caches can quietly poison interpretation. A reproducible workflow records:

- symbol path,
- cache path,
- build version,
- whether public or private symbols were used.

## Core Workflow

1. Identify Windows build.
2. Configure symbols.
3. Load the dump or attach the debugger.
4. Verify `nt` symbols before trusting any structure interpretation.
5. Inspect loaded modules and drivers.
6. Inspect relevant processes and threads.
7. Inspect device objects and driver objects.
8. Inspect pool allocations if memory corruption is suspected.
9. Inspect PTE or virtual-to-physical translation only when the question requires it.
10. Analyze the bugcheck and correlate it with subsystem context.
11. Write notes with build, symbols, driver version, hashes, and observations preserved.

## Command Map

| Goal | Commands | Notes |
|---|---|---|
| Confirm target version | `vertarget` | Establish exact OS and build context first |
| List modules | `lm`, `lmv` | Use verbose module view when checking image details |
| Diagnose symbol loading | `!sym noisy`, `.symfix`, `.reload` | Turn on noisy symbols before reloading when symbol issues appear |
| Run automatic crash analysis | `!analyze -v` | Good starting point, not final truth |
| Inspect processes | `!process` | Useful for `EPROCESS`, object table, and context |
| Inspect threads | `!thread` | Useful for wait state, owner process, and stack |
| Show stack | `k`, `kv` | `kv` gives richer symbol detail when available |
| Inspect driver object | `!drvobj` | Good for dispatch table and object relationships |
| Inspect device object | `!devobj` | Good for device stack and queue context |
| Inspect object namespace | `!object` | Good for named-object discovery and counts |
| Inspect handles | `!handle` | Good for granted access and object type mapping |
| Inspect pool blocks | `!pool`, `!poolfind`, `!poolused` | Use when allocator corruption or tag analysis matters |
| Inspect page translation | `!pte`, `!vtop` | Use for paging and translation questions, not by default |
| Raw memory view | `dq`, `dd`, `db` | Useful only when symbols or typed output are insufficient |
| Check verifier state | `!verifier` | Important for verifier-induced crashes or validation context |

## Research Workflows

### Inspecting an IOCTL crash

Safe workflow:

```text
identify failing driver and stack
  -> confirm device-control dispatch path
  -> inspect current process and thread
  -> inspect relevant device and driver objects
  -> compare buffer/IRP interpretation with expected IOCTL method
  -> document trust-boundary failure hypothesis
```

### Inspecting pool corruption

```text
start from bugcheck and faulting address
  -> determine whether crash is on access or free path
  -> inspect nearby pool/tag state
  -> check verifier status
  -> correlate suspect tag or driver ownership
```

### Inspecting invalid user pointer crashes

```text
inspect thread and previous stack context
  -> identify device-control or system-service boundary
  -> determine whether request came from user mode
  -> inspect IRP and relevant stack location fields conceptually
  -> ask whether raw user memory was touched at the wrong time or IRQL
```

### Inspecting driver object and device object exposure

```text
enumerate driver object
  -> inspect device objects
  -> inspect namespace path
  -> map user-visible symbolic link to kernel device object
```

### Inspecting page-table translation

Only do this when the question truly needs translation context:

```text
establish process context
  -> inspect VA with !pte
  -> use !vtop if appropriate
  -> record whether translation interpretation depends on build or mitigation state
```

### Validating PDB symbol correctness

```text
confirm build
  -> inspect module load and symbol state
  -> reload if needed
  -> verify trusted type output before using field offsets
```

### Documenting vulnerable behavior without weaponizing it

A safe note should answer:

- what object or buffer crossed the boundary,
- what validation appears missing,
- what crash or corruption class is implied,
- what telemetry and mitigations matter,
- what remains unverified.

It should avoid turning those observations into a runnable chain.

## Crash Triage Matrix

| Symptom | Possible root cause | What to inspect | Notes |
|---|---|---|---|
| Access violation in driver | Bad pointer, stale object, wrong buffer interpretation | `!analyze -v`, stack, driver dispatch path | Start with pointer provenance |
| Bugcheck from invalid address | User-pointer misuse, freed object, wrong IRQL access | thread context, IRP path, memory region | Determine whether address was user, kernel, or freed pool |
| Pool corruption | Overflow, UAF, double free, delayed metadata detection | `!pool`, `!poolfind`, `!poolused`, `!verifier` | First crash site may be late |
| Use-after-free suspicion | Lifetime mismatch or reuse | stack history, object ownership, verifier clues | Look for stale references and async work |
| `IRQL_NOT_LESS_OR_EQUAL` | Wrong IRQL memory access, pageable access, pointer misuse | current IRQL context, thread, stack | Raw user pointers at high IRQL are a common theme |
| `PAGE_FAULT_IN_NONPAGED_AREA` | Invalid or stale address, wrong nonpaged assumption | faulting address, object lifetime, pool state | Separate "nonpaged" expectation from actual access path |
| `DRIVER_VERIFIER_DETECTED_VIOLATION` | Contract violation surfaced by verifier | `!verifier`, stack, driver options | Often higher-signal than non-verifier crash |
| `SYSTEM_SERVICE_EXCEPTION` | Bad transition-path behavior or invalid access in service-related flow | service boundary, thread, stack, symbols | Verify symbols before interpreting nt path details |

## Common Mistakes

- Trusting `!analyze -v` as the entire answer.
- Reading typed fields before confirming symbol correctness.
- Ignoring driver version, hash, and signer provenance in the notes.
- Overusing paging commands when the bug is clearly an object-lifetime problem.
- Mixing dump-derived facts with assumptions from a different build.

## Research Notes

- Good kernel debugging is mostly disciplined context management: build, symbols, object ownership, and subsystem boundaries.
- WinDbg is strongest when the analyst keeps a clear question in mind. Random command spraying produces noise faster than insight.
- Crash triage becomes much better when notes explicitly distinguish facts, hypotheses, and build-sensitive interpretation.

## Defensive Angle

Crash dumps support detection and incident response because they preserve:

- involved driver modules,
- stack traces,
- process and thread context,
- verifier state,
- object and pool clues,
- bugcheck parameters,
- and sometimes evidence of repeated malformed interaction.

Repeated crashes in the same driver path can indicate:

- faulty software quality,
- aggressive fuzzing,
- exploit development attempts,
- or a production compatibility problem.

Preserve:

- driver version and hash,
- signer and path,
- bugcheck code and parameters,
- dump timestamp,
- whether verifier was enabled,
- whether the system had VBS/HVCI or related hardening enabled.

## Lab-Safe Exercises

1. Open a kernel dump and run the core workflow from `vertarget` through `!analyze -v`, noting where symbol confidence changes your interpretation.
2. For one test driver, use `!drvobj`, `!devobj`, and `!object` to map namespace exposure and dispatch ownership.
3. Compare a verifier-induced crash dump and a non-verifier crash dump from the same bug and document what signal improved.

## References / Further Reading

- Microsoft Learn, `Analyze a kernel-mode dump file by using WinDbg`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/analyzing-a-kernel-mode-dump-file-with-windbg
- Microsoft Learn, `Configure Symbol Path`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path
- Microsoft Learn, `Verifying Symbols`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/verifying-symbols
- Microsoft Learn, `!sym`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-sym
- Microsoft Learn, `!analyze`:
  https://learn.microsoft.com/ga-ie/windows-hardware/drivers/debuggercmds/-analyze
- Microsoft Learn, `!process`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-process
- Microsoft Learn, `!thread`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-thread
- Microsoft Learn, `!drvobj`:
  https://learn.microsoft.com/ja-jp/windows-hardware/drivers/debuggercmds/-drvobj
- Microsoft Learn, `!devobj`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-devobj
- Microsoft Learn, `!object`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-object
- Microsoft Learn, `!handle`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-handle
- Microsoft Learn, `!verifier`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-verifier
- Existing repo note, [runtime-pdb-symbol-resolution.md](E:\Windows-kernel-exploit-research-resource\docs\kernel-research\runtime-pdb-symbol-resolution.md)

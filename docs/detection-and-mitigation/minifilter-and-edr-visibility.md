# Minifilter Drivers and EDR Visibility

## Purpose

This document explains how file-system minifilters contribute to security visibility, where they sit in the I/O path, what they can and cannot observe, and why altitude, callback design, and supporting telemetry determine how useful they really are for detection.

## Background

### File System Filter Manager

Windows Filter Manager (`FltMgr`) provides the common infrastructure for minifilter drivers. Instead of each security product building a legacy filter stack from scratch, a minifilter registers with `FltMgr`, which manages:

- attachment ordering,
- callback dispatch,
- instance management,
- communication paths between user mode and kernel mode.

### Minifilter drivers

A minifilter driver chooses which file-system operations it wants to observe and optionally influence. It can register:

- pre-operation callbacks,
- post-operation callbacks,
- and additional support callbacks depending on feature set.

### Altitudes

Altitude is not just a label. It controls relative order in the minifilter stack. Higher or lower position changes what the filter sees first, what it sees after transformation by others, and how much context is still available.

### Pre-operation and post-operation callbacks

Pre-operation callbacks run before the request is passed further down the stack. Post-operation callbacks run on the way back up after completion. This ordering is critical for:

- decision timing,
- file identity reasoning,
- correlation between intent and result,
- and avoiding wrong assumptions about object lifetime.

### File I/O visibility and security-product usage

EDRs, AVs, DLP tools, and compliance products use minifilters because file operations remain one of the richest and most operationally useful telemetry surfaces in Windows.

## Core Concepts

### Filter Manager

Filter Manager is the execution framework that dispatches I/O callbacks across minifilter instances in altitude order. It provides the abstraction that makes the minifilter model consistent and interoperable.

### Instance attachment and volumes

Minifilters do not exist only as one global object. They attach as instances to relevant volumes or file-system stacks. Visibility is therefore:

- per-instance,
- per-volume,
- and shaped by where the instance is attached.

### Altitude ordering

At a high level:

```text
pre-operation:
  higher altitude -> lower altitude

post-operation:
  lower altitude -> higher altitude
```

This means a filter's observations depend on both the original operation and the transformations or blocking decisions of earlier participants.

### Operation callbacks

Minifilters can observe:

- IRP-based I/O,
- Fast I/O,
- file-system filter callback operations,
- and related communication-port activity.

### Communication ports conceptually

Minifilters often cooperate with user-mode services through Filter Manager communication ports. That relationship matters because:

- policy may be decided in user mode,
- kernel code may send events up,
- responsiveness and teardown correctness become part of sensor quality.

### User-mode service relationship

Many security products depend on a kernel minifilter plus a user-mode service. The minifilter provides privileged visibility; the service provides policy, logging, cloud enrichment, or response orchestration.

## Technical Deep Dive

### Where minifilters sit in the I/O stack

Conceptually:

```text
user process
  -> file API / native I/O
  -> I/O Manager
  -> Filter Manager
  -> minifilter instances by altitude
  -> file system
  -> storage stack
```

This placement makes minifilters powerful, but still scoped to file-system semantics.

### Why altitude order matters

Altitude changes what you mean by "visibility". A filter higher in the stack may observe earlier intent. A filter lower in the stack may observe a request after another filter changed or annotated it. This affects:

- file names seen,
- normalized identity,
- access intent,
- whether the request even survives to lower layers.

### What minifilters can observe

They are strong at:

- create/open requests,
- reads and writes,
- renames and deletes,
- volume and stream-oriented file activity,
- operation sequencing around file-system semantics.

### What minifilters cannot magically observe

They do not automatically give full visibility into:

- memory-only behavior with no file-system event,
- every image or section mapping nuance unless correlated with image-load telemetry,
- all storage activity once semantics drop below the file-system layer,
- every user-mode intent before it becomes a file-system operation.

### Performance and deadlock risks

Minifilters are easy to misuse because they sit on hot I/O paths. Problems include:

- expensive callbacks,
- reentrancy into file operations,
- waiting in unsafe contexts,
- calling into user-mode coordination too aggressively,
- lock-order mistakes when the filter already runs inside a layered stack.

### Reentrancy risks

A minifilter may trigger more file activity while observing file activity. That means callback code must be written with explicit awareness of:

- recursion,
- reissued operations,
- helper-generated I/O,
- self-observation loops.

### File identity complexity

File identity is not trivial:

- names may change,
- path normalization differs by layer and timing,
- streams, reparse points, and volume context complicate interpretation,
- a single operation may involve more than one meaningful path representation.

### Rename/delete/transaction edge cases

High-level visibility can become ambiguous around:

- rename before later access,
- delete-on-close semantics,
- transactional or staged operations,
- operations whose final semantic outcome is known only in post-operation context.

### Visibility gaps and false assumptions

The biggest false assumption is:

```text
I have a minifilter, therefore I see everything important.
```

In reality, defenders need to combine minifilter data with:

- image-load telemetry,
- process ancestry,
- handle activity,
- ETW,
- Code Integrity,
- driver load,
- crash data.

## Visibility Matrix

| Activity | Minifilter visibility | Caveats | Other telemetry to combine |
|---|---|---|---|
| File create/open | Strong | Name and object identity can still be nuanced | Process ancestry, handle telemetry |
| Read/write | Strong | Semantics may differ by cached/Fast I/O path and filter ordering | Process context, ETW, content policy decisions |
| Rename | Medium-strong | Pre/post timing and name normalization matter | Process lineage, post-op result, file identity logic |
| Delete | Medium-strong | Delete intent and delete-on-close semantics differ | Handle lifetime, cleanup/close, post-op state |
| Section mapping | Partial | File-to-memory transition needs image/load or memory correlation | Image-load telemetry, process creation |
| Process image load relationship | Partial alone | File event does not equal successful execution context | Image-load callbacks, ETW, process notify |
| Memory-only activity | Weak | No file operation may occur at all | ETW, callbacks, memory telemetry |
| Raw disk/volume activity | Limited at high level | Some lower-layer semantics can reduce file-level meaning | Storage, volume, and lower-layer telemetry as appropriate |

## Debugging / Inspection Notes

### `fltmc` concepts

`fltmc` is useful for:

- listing loaded minifilters,
- seeing altitudes,
- confirming whether a filter is attached.

The point is inventory and ordering, not runtime tampering.

### WinDbg filter inspection concepts

Safe debugging goals:

- confirm filter load and module identity,
- inspect callback registration logic and unload path,
- correlate crash stacks with pre-operation or post-operation execution,
- understand which instances and altitudes are involved.

### How to document filter altitude and callbacks

Useful note format:

```text
Filter name:
Altitude:
Registered pre-op callbacks:
Registered post-op callbacks:
User-mode service dependency:
Unload/teardown notes:
Known visibility gaps:
```

### How to reason about file operation flow

Always ask:

- is this pre-op or post-op,
- what altitude is this filter at,
- what file identity is stable at this point,
- did another filter or the file system already transform the request.

## Defensive Angle

EDRs use minifilters because file activity remains essential, but mature visibility should combine:

- minifilter telemetry,
- ETW and image-load signals,
- process and thread context,
- handle activity,
- driver load telemetry,
- crash and verifier evidence.

Failure modes matter:

- callback bugs can remove coverage,
- performance issues can force product tuning that reduces visibility,
- crashes in minifilter paths may indicate either poor product quality or hostile stress against the sensor.

## Common Mistakes

- Assuming altitude does not materially change what the filter sees.
- Using file path alone as stable identity.
- Overestimating minifilter coverage for memory-only or below-file-system behavior.
- Ignoring user-mode service dependencies and communication-port design.

## Research Notes

- Minifilters are one of the most important defensive callback surfaces precisely because they are useful but incomplete.
- Research value often comes from understanding the mismatch between what a minifilter can see and what security marketing language implies it can see.
- Teardown and communication-port design deserve as much scrutiny as pre-op logic.

## Lab-Safe Exercises

1. Use `fltmc` in a lab to inventory loaded minifilters and record altitude ordering.
2. Pick a documented minifilter and map its registered pre-operation and post-operation callbacks conceptually from source or RE.
3. Build a one-page visibility matrix for a test environment showing which telemetry comes from the minifilter and which must come from elsewhere.

## References / Further Reading

- Microsoft Learn, `Filter Manager Concepts`:
  https://learn.microsoft.com/windows-hardware/drivers/ifs/filter-manager-concepts
- Microsoft Learn, `Filtering I/O Operations in a Minifilter Driver`:
  https://learn.microsoft.com/en-za/windows-hardware/drivers/ifs/filtering-i-o-operations-in-a-minifilter-driver
- Microsoft Learn, `Registering Preoperation and Postoperation Callback Routines`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/registering-preoperation-and-postoperation-callback-routines
- Microsoft Learn, `Communication between User-mode and Minifilters`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/communication-between-user-mode-and-kernel-mode
- Microsoft Learn, `Loading and Unloading a Minifilter`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/loading-and-unloading
- Existing repo note, [callback-surfaces.md](E:\Windows-kernel-exploit-research-resource\docs\kernel-research\callback-surfaces.md)

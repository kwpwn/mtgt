# HKOM / DKOM Hide Research Notes

## Purpose

This document explains hide-oriented kernel object manipulation patterns at a research level. The user shorthand `hkom_hide` is treated here as hide-oriented kernel object manipulation. The more common public term is `DKOM`: Direct Kernel Object Manipulation.

The goal is to understand object relationships, detection inconsistencies, and why these techniques are fragile. This is not a rootkit implementation guide.

For deeper single-technique notes, see:

- `docs/kernel-research/hkom-process-hide-crossview.md`
- `docs/kernel-research/hkom-driver-module-hide-crossview.md`

## Core Idea

Traditional kernel hooks change code or control flow. DKOM-style hiding changes data:

```text
normal system object graph
  -> selected object metadata is modified
  -> one enumeration path no longer sees the object
  -> other references may still exist
  -> cross-view detection can find the inconsistency
```

The key lesson:

```text
hide does not mean gone
```

It usually means one view of the system was desynchronized from another.

## Terminology

| Term | Meaning |
|---|---|
| DKOM | Direct Kernel Object Manipulation; modifying kernel object state directly |
| HKOM | User shorthand here for hide-oriented kernel object manipulation |
| Cross-view detection | Comparing multiple enumeration sources to find objects hidden from one view |
| Object graph | Relationships among object headers, object bodies, handles, lists, references, and subsystem indexes |
| Semantic hide | A state change that makes normal APIs report different reality without removing the object |

## Common Hide Targets

| Target family | Typical object/view involved | Why hiding is fragile |
|---|---|---|
| Process hide | Process list, handle tables, threads, scheduler state | A process has many references beyond one list |
| Driver/module hide | Loaded module list, driver object namespace, memory mappings | Code pages, device objects, services, and callbacks can remain visible |
| Device hide | Object namespace and symbolic links | Existing handles, driver objects, and dispatch paths may still reveal it |
| Callback hide | Callback registration arrays/lists | Side effects and registration artifacts may remain |
| Token/security state hide | Process token and protection fields | Access behavior changes can be inconsistent with process lineage |
| File/minifilter hide | File system namespace, filter stack, cache state | Alternate views can expose mismatches |

This repository should focus on the object-model and detection side of these families, not write mutation recipes.

## Process Hide Concept

A naive process hide idea targets an enumeration structure such as the active process list. The researcher sees:

```text
API enumeration view
  -> walks or depends on one process list
  -> object is no longer returned
```

But the process may still be referenced by:

- threads,
- handles in other processes,
- scheduler structures,
- job/session relationships,
- token references,
- memory-management structures,
- ETW or EDR history,
- crash dump artifacts.

Therefore a good detection question is:

```text
Can I find evidence of a process through a source that does not depend on the hidden view?
```

## Driver / Module Hide Concept

A driver can be visible through more than one relationship:

```text
loaded module metadata
  driver object
  device object
  symbolic link
  service registry key
  image file on disk
  code pages in kernel VA
  callback registrations
  active handles
```

Hiding from one list does not erase all of these. For example, removing a module from a loader-oriented view may still leave:

- executable kernel memory,
- a `DRIVER_OBJECT`,
- one or more `DEVICE_OBJECT`s,
- dispatch routines pointing into the image,
- service-control evidence,
- Code Integrity and driver-load telemetry,
- pool allocations and tags.

## Object Graph View

Think in graphs, not lists:

```text
process
  -> EPROCESS
  -> threads
  -> token
  -> handle table
  -> address space
  -> job/session
  -> ETW/process history

driver
  -> DRIVER_OBJECT
  -> DEVICE_OBJECT list
  -> dispatch table
  -> loaded image memory
  -> service registry key
  -> object namespace links
  -> callbacks / filters / timers / work items
```

A hide technique usually damages one edge in the graph. Cross-view detection looks for the remaining edges.

## Cross-View Detection Matrix

| Hidden thing | Primary view may miss | Alternate views to compare |
|---|---|---|
| Process | Active process enumeration | thread ownership, handle tables, memory regions, ETW history, process creation telemetry |
| Driver module | module list | driver objects, device objects, executable kernel memory, service keys, driver-load events |
| Device object | DOS-device links | `\Device` namespace, `DRIVER_OBJECT` device list, active handles |
| Callback | callback inventory | behavioral side effects, target object access, module owning callback code |
| Token/security state | normal process metadata | access behavior, privilege set, parent lineage, integrity level, audit trail |

## Why Hide Techniques Break

Hide-oriented DKOM is unstable because the kernel maintains many invariants:

- doubly-linked list consistency,
- object reference counts,
- handle counts,
- pointer counts,
- lock ownership,
- lifetime and rundown protection,
- subsystem-specific indexes,
- telemetry history outside the mutated structure.

If one structure is changed without updating every related invariant, the result may be:

- immediate crash,
- later crash during cleanup,
- memory leak,
- orphaned object,
- suspicious inconsistency,
- security product alert.

## Relationship to HVCI and PatchGuard

DKOM-style hiding often avoids new executable code. That means HVCI does not automatically stop every data-only object mutation.

But modern Windows still applies pressure:

- PatchGuard may detect some protected structure tampering.
- KDP can protect selected kernel data.
- HVCI raises the cost of code patching fallback paths.
- EDR products can correlate behavior before and after the hide.
- Build-specific layout drift makes hardcoded field assumptions brittle.

The practical lesson:

```text
data-only does not mean safe, stable, or invisible
```

## Debugging and Forensics Learning Flow

A safe learning workflow:

```text
1. Pick one object family, such as process or driver.
2. Enumerate it through normal APIs.
3. Enumerate related object-manager or debugger views.
4. Draw the object graph.
5. Identify which views depend on which lists or references.
6. Write down cross-view consistency checks.
```

For process research, compare:

- process list,
- thread ownership,
- handle tables,
- token references,
- ETW/process creation history,
- memory-management evidence.

For driver research, compare:

- loaded module view,
- `DRIVER_OBJECT`,
- `DEVICE_OBJECT`,
- dispatch routine addresses,
- service registry state,
- Code Integrity and driver-load telemetry,
- executable kernel memory ranges.

## WinDbg-Oriented Checks

Useful concepts to inspect in a lab:

```text
!process
!thread
!handle
!object
!drvobj
!devobj
lm
```

The learning goal is to answer:

```text
Which views agree?
Which views disagree?
Which object references still exist?
Which module owns the code pointers?
```

Avoid turning these commands into a hide/unhide checklist. Use them to understand object consistency.

## Detection Ideas

Detection should look for disagreement:

- thread exists but owning process is missing from ordinary process enumeration,
- handle table references an object that is missing from the expected namespace view,
- device object exists without expected service or module-list relationship,
- dispatch routine points into executable memory not present in the normal loaded-module view,
- driver-load telemetry exists but later module inventory disagrees,
- Code Integrity event exists but no corresponding normal module state remains,
- process behavior continues after apparent disappearance from one API view.

## Common Mistakes

- Thinking unlinking one list fully hides an object.
- Ignoring references held by handles, threads, callbacks, timers, or work items.
- Assuming HVCI stops all DKOM-style hiding.
- Ignoring PatchGuard and KDP pressure.
- Treating one debugger command as ground truth.
- Hardcoding field offsets without build and symbol provenance.

## Lab-Safe Exercises

1. Draw the graph for one normal process: process object, threads, token, handle table, and memory evidence.
2. Draw the graph for one normal driver: module, driver object, device object, symbolic link, and service entry.
3. Build a cross-view checklist for detecting a hidden process without changing kernel memory.
4. Build a cross-view checklist for detecting a hidden driver without changing kernel memory.

## Relationship to Existing Repo Topics

- `docs/windows-internals/eprocess-token-object-model.md` explains process and token object relationships.
- `docs/windows-internals/object-manager-and-handle-tables.md` explains handles, object headers, namespaces, and device exposure.
- `docs/kernel-research/kernel-object-layout-drift.md` explains why offsets and private layouts drift.
- `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md` explains telemetry around driver loading.
- `03_byovd/01_physical-memory-rw/ASTRA64_DIRECT_DKOM_DEEP_DIVE.md` covers direct DKOM as a BYOVD research case. Treat it as lab-only context.

## Summary

HKOM/DKOM hide research is really object-consistency research:

```text
objects live in graphs
hide usually breaks one view
other references remain
cross-view comparison exposes the mismatch
```

The best way to learn it is not to write a rootkit. It is to understand all the ways Windows can still know an object exists.

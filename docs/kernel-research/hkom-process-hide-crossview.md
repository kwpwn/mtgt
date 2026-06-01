# HKOM / DKOM Process Hide: Cross-View Reasoning

## Technique Summary

Process hiding by kernel object manipulation is the idea of making one process-enumeration view stop reporting a process while the process still exists.

Conceptual model:

```text
process object graph
  -> one enumeration edge is damaged or desynchronized
  -> normal process listing may miss the process
  -> threads, handles, memory, token, or telemetry can still reveal it
```

This document teaches the reasoning model and detection logic. It does not describe how to mutate kernel memory to hide a process.

## Required Assumptions

To reason about process hide, assume:

- Windows has an executive process object model.
- A process is represented by more than one structure and more than one reference path.
- Process enumeration tools do not all use identical data sources.
- Kernel layouts are build-specific.
- A hidden process must still execute through scheduler, memory, handle, and thread state.

The critical assumption behind the hide idea:

```text
some user-visible process enumeration depends on a view that can become inconsistent
```

The critical assumption behind detection:

```text
other views still depend on surviving references
```

## Why This Works

Ask first:

```text
Why can a process be hidden from one view but still be alive?
```

Because a process is not one thing. It is a graph:

```text
EPROCESS
  -> active process relationship
  -> thread list / scheduler relationships
  -> address space
  -> handle table
  -> token reference
  -> job/session relationships
  -> object header and reference counts
  -> telemetry history
```

If one enumeration relationship is damaged, a tool that trusts only that relationship may miss the process. But the kernel still needs enough of the object graph intact to schedule threads, manage memory, process handles, and enforce security.

That creates the core inconsistency:

```text
process is absent from view A
process evidence remains in views B, C, D
```

## Step-by-Step Reasoning

### Step 1: Identify the claimed hidden object

Question:

```text
What object is supposedly hidden?
```

For process hide, the target is not "a PID" alone. The target is the process object and its related graph.

Reasoning:

- PID is an identity label.
- `EPROCESS` is the kernel executive object.
- Threads prove execution.
- Handles prove object interaction.
- Address space proves memory-management state.

### Step 2: Identify the view that misses it

Question:

```text
Which enumeration source fails to show the process?
```

Examples of view families:

- normal user-mode process APIs,
- debugger process list,
- EDR process inventory,
- memory forensics plugin,
- ETW-derived history.

Reasoning:

If only one view misses the process, the technique may be view-specific rather than a complete hide.

### Step 3: Identify alternate references

Question:

```text
Which references must remain if the process is still alive?
```

Look for conceptual evidence:

- threads with an owning process,
- handles opened by or to the process,
- token reference,
- VAD/address-space evidence,
- job/session membership,
- process creation telemetry,
- image section or file object evidence.

Reasoning:

A live process cannot erase every relationship without ceasing to function.

### Step 4: Compare views

Question:

```text
Do independent views agree?
```

Cross-view model:

```text
normal process list says: absent
thread ownership says: present
handle table says: present
memory manager says: present
telemetry says: previously created and not exited
```

Reasoning:

The contradiction is the detection signal.

## Why Not Just Trust the Process List?

Because a list is an implementation detail, not the full truth.

If a defender asks:

```text
Is the process in one list?
```

the answer can be manipulated by damaging that list relationship.

A stronger question is:

```text
Does the whole object graph consistently say this process exists or does not exist?
```

That is harder to fake.

## Detection Matrix

| Evidence source | What it can reveal | Why it survives simple hide |
|---|---|---|
| Thread ownership | Threads still need scheduling context | Process execution depends on threads |
| Handle tables | Handles reference objects and granted access | Object use leaves mediated references |
| Token reference | Security context remains needed | Access checks require a token relationship |
| Address space / VADs | Memory mappings still exist | Process execution needs virtual memory |
| ETW / EDR history | Creation and behavior timeline | Historical telemetry is outside the mutated list |
| Image/file objects | Backing executable or mapped sections | Loader and memory manager state may remain |
| Crash dump | Offline object graph | Runtime API hiding may not affect dump analysis |

## Failure Modes

Process hide breaks when:

- list integrity checks fail,
- reference counts become inconsistent,
- cleanup later touches corrupted linkage,
- a tool uses a different enumeration path,
- EDR uses historical telemetry,
- PatchGuard or related checks notice protected structure tamper,
- the technique assumes wrong field offsets for the build.

Important reasoning:

```text
If a hide technique modifies only one edge,
then every unmodified edge becomes a possible detection path.
```

## Defensive Angle

Detection should focus on disagreement:

- thread exists but owning process is missing from normal enumeration,
- process has memory activity but no process-list entry,
- handles refer to a process object that ordinary tools do not show,
- process creation event exists without an exit event but inventory says absent,
- security context or token use continues after apparent disappearance.

This is cross-view detection.

## Study Questions

- Why is a process better modeled as a graph than as a PID?
- Which process relationships are needed for execution to continue?
- Which views are historical rather than live?
- Why can one list be wrong while the object still exists?
- What would prove that the process is actually gone rather than hidden?
- Which checks become build-sensitive?

## Summary

Process hide via HKOM/DKOM is not magic invisibility. It is usually a targeted inconsistency:

```text
one enumeration path is damaged
other object relationships remain
cross-view comparison exposes the mismatch
```

The correct learning target is object consistency, not mutation.

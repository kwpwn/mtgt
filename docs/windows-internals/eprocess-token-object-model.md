# EPROCESS Token and Object Model

## Purpose

This document consolidates process object, token, handle-table, and Object Manager concepts that are currently scattered across the repo. It is meant as a stable internals reference for Windows kernel research and defensive review.

## Background

A large amount of Windows local privilege escalation research circles around process and token state, but the underlying object model is broader than any one field. To reason safely about process security state, the analyst needs to understand:

- what an `EPROCESS` represents,
- how a token is attached,
- how handles relate to object pointers,
- where Object Manager fits,
- why corrupting these relationships is dangerous.

## Core Concepts

### `EPROCESS`

`EPROCESS` is the executive process object used by the kernel to represent a process as a kernel-managed object. It carries scheduling-adjacent relationships, process identity, token linkage, protection state, handle-table linkage, and other process-wide metadata.

### `KPROCESS`

`KPROCESS` is the lower-level scheduler-oriented process representation embedded within the executive process object. A useful conceptual distinction is:

- `KPROCESS`: processor and scheduling view,
- `EPROCESS`: executive and security-aware process view.

### `UniqueProcessId`

This field provides a stable conceptual identity anchor inside process-object reasoning. Many internal walks and debugger inspections use it to confirm that a candidate process object represents the intended process.

### `ActiveProcessLinks`

This is the linkage that places a process inside the active process list. Analysts care because list linkage often underpins enumeration, object recovery, and consistency checks during debugging.

### `Token` field

The process token field ties the process to its primary security token. Conceptually, this is where process identity meets access control policy. Changing the effective token relationship changes how the system evaluates many future access decisions.

### `_EX_FAST_REF`

Some kernel object references are stored through compact fast-reference forms that combine a pointer with small reference-tracking bits. The important lesson is conceptual:

- a field that looks pointer-like may also encode auxiliary state,
- copying or interpreting it naively is dangerous,
- pointer identity and reference semantics can be intertwined.

### `HANDLE_TABLE`

Handles are not raw object pointers. They are indexes or entries into per-process handle tables managed by the kernel. A handle table mediates:

- which objects a process can reference,
- what access rights were granted,
- how those rights are looked up later.

### `OBJECT_HEADER`

Kernel objects are managed through Object Manager metadata that conceptually includes:

- object type identity,
- reference-related accounting,
- optional name/security/quota data,
- object body layout behind the header.

This is one reason a pointer to an object body is not the same thing as understanding the whole object.

### Object Manager

The Object Manager is the naming, lifetime, and handle-management layer for many kernel object types. It sits at the center of:

- named object namespaces,
- handle creation,
- type enforcement,
- reference counting,
- access checks.

### Access token model

An access token represents the security context used for access decisions. At a conceptual level it carries:

- user and group identity,
- privileges,
- integrity level,
- restrictions and policy context.

## Technical Deep Dive

### Why token corruption is dangerous

Token corruption matters because many access-control decisions ultimately reduce to:

```text
Which effective token is being consulted,
and what rights, groups, privileges, and integrity claims does it carry?
```

If that relationship is corrupted, subsequent operations may be evaluated under the wrong security context. This is a semantic security break, not merely a memory-management oddity.

### Handle tables and trust boundaries

A caller-supplied handle is not proof that the caller should be trusted with the underlying object in every context. Secure code still needs to reason about:

- object type,
- granted access,
- whether the handle came from user mode,
- whether `AccessMode` is being interpreted correctly,
- whether the object lifetime is still valid.

This is why handle conversion routines and `ObReferenceObjectByHandle` are security-sensitive.

### Object model relationship diagram

```text
process
  -> EPROCESS
      -> embedded KPROCESS
      -> Token field
      -> HANDLE_TABLE linkage
      -> ActiveProcessLinks

token object
  -> Object Manager object
  -> privileges, groups, integrity state

user handle
  -> per-process HANDLE_TABLE entry
  -> object pointer + granted access semantics
```

### Integrity level and privileges

Privileges and integrity level are distinct concepts:

- privileges are discrete capabilities granted to the token,
- integrity level is a broader trust label affecting what the subject may modify.

A good process-security review should not collapse these into one idea of "is admin or not".

### Forensic and detection value

Process and token internals matter defensively because anomalies can show up as:

- privilege combinations that do not fit normal parent/child lineage,
- processes acting outside their expected integrity level,
- handle-table patterns inconsistent with the process role,
- object-reference anomalies in kernel debugging or memory forensics.

## Windows Version Notes

- The conceptual model remains stable across supported Windows versions.
- Field offsets and some internal layouts drift by build and servicing level.
- Any documentation that records offsets should bind them to build provenance and symbol source.

## Common Mistakes

- Treating a handle as if it were a raw object pointer.
- Ignoring `_EX_FAST_REF` style encoded semantics.
- Talking about "the token" without distinguishing primary token, object reference, and handle-mediated access.
- Assuming object names, handles, and pointers are interchangeable representations.

## Debugging / Inspection Notes

Useful inspection points:

- WinDbg:
  - `!process`
  - `!handle`
  - `!object`
  - `dt` for process and token-related types
- Object namespace review:
  - WinObj
  - debugger object commands

Inspection checklist:

- Is the candidate process object identity confirmed?
- Does the token linkage make conceptual sense?
- Are the handles being discussed user handles or kernel handles?
- Is the object type confirmed before acting on the handle?

## Defensive Angle

Defenders should think of process security state as a graph, not one field:

- process object,
- token object,
- handle table,
- Object Manager metadata,
- access rights and integrity context.

This graph-oriented view helps explain why anomalies can appear as privilege drift, impossible handle use, or object-reference inconsistencies rather than as one obvious "token theft" signal.

## Lab-Safe Exercises

1. In WinDbg, inspect one normal process and record the conceptual links you can observe: identity, active process list, token linkage, and handle activity.
2. Build a table distinguishing object body, object header, handle, and handle-table entry.
3. Compare one high-integrity process and one ordinary user process from a defensive perspective: expected privileges, expected handle behavior, and expected device-access profile.

## References / Further Reading

- Microsoft Learn, `Windows kernel-mode Object Manager`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-object-manager
- Microsoft Learn, `Managing Kernel Objects`:
  https://learn.microsoft.com/en-gb/windows-hardware/drivers/kernel/managing-kernel-objects
- Microsoft Learn, `Object Handles`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles
- Microsoft Learn, `Object Names`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-names
- Microsoft Learn, `ObReferenceObjectByHandle`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle
- Microsoft Learn, `!object`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-object
- Existing repo note, `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md`
- Existing repo note, `03_byovd/04_limited-primitives/ASIO3_PREVIOUSMODE_DEEP_DIVE.md`

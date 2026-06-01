# PreviousMode and RequestorMode Research Notes

## Purpose

This document explains `PreviousMode` and `RequestorMode` as trust-boundary signals in the Windows kernel. The goal is to clarify how Windows distinguishes user-originated and kernel-originated requests, and why incorrect assumptions about that distinction create dangerous review findings even without classic memory corruption.

## Background

### UserMode vs KernelMode request origin

Windows needs to know whether a buffer, handle, or request came from user mode or from trusted kernel code because:

- user pointers require validation and careful access semantics,
- user handles require access checks and type validation,
- kernel callers are allowed to bypass some user-mode probing conventions when it is safe and intended.

This distinction is not merely bookkeeping; it is part of the system's security model.

### `KTHREAD.PreviousMode` concept

At a conceptual level, `PreviousMode` records whether the thread entered a kernel service path from user mode or kernel mode. That state influences whether the kernel treats parameters as:

- needing user-buffer probing,
- needing user-handle access validation,
- or already trusted kernel-side data.

### `IRP.RequestorMode` concept

For driver I/O paths, `RequestorMode` is the analogous signal attached to a request. It tells the driver whether the I/O originated from user mode or kernel mode. That decision affects whether it is appropriate to trust raw addresses, handles, and structure contents.

### `Nt` vs `Zw` conceptual difference

The `Nt`/`Zw` distinction matters because it reflects different expectations about the caller context and parameter treatment. A useful research framing is:

- `Nt*` is associated with the ordinary system-call contract from user mode.
- `Zw*` is associated with kernel-mode callers that may already be trusted differently.

The danger comes when driver code moves data from an untrusted source into a path that the kernel now interprets as if it came from a trusted caller.

### Why the kernel sometimes probes user buffers and sometimes trusts kernel callers

Kernel code must balance security and performance. Probing every kernel-supplied pointer as if it were user memory would be wrong and expensive. Trusting every caller because execution is in ring 0 would also be wrong. The system therefore carries origin state through multiple layers.

## Core Concepts

### `ProbeForRead` / `ProbeForWrite`

These routines are the visible expression of the user-origin contract. They exist because a caller-originated buffer may be:

- unmapped,
- misaligned,
- accessible for read but not write,
- or changed after validation.

### System service argument validation

Native services and many driver paths do not merely check whether a pointer "looks valid". They interpret access based on who supplied it. That means validation is partly:

- structural,
- access-based,
- and origin-based.

### Kernel callers versus user callers

A kernel caller can still carry untrusted data. This is the core insight behind many confused-trust findings. "Kernel caller" is not the same thing as "safe buffer semantics".

### How trust decisions can become dangerous

If code sees:

```text
current path is kernel-mode
```

and silently upgrades a user-owned pointer or handle to "safe", then the trust boundary has already been lost before any overt corruption occurs.

### Difference between "pointer is valid" and "pointer is safe to trust"

These are not equivalent:

- valid pointer:
  points to mapped memory right now.
- safe to trust:
  belongs to the correct security context, is interpreted with the correct access rules, and will remain safe for the required duration and usage pattern.

## Technical Deep Dive

### How `PreviousMode` affects parameter validation conceptually

Many native-service paths branch behavior conceptually like this:

```text
if caller originated from user mode
  -> probe or validate user parameters
  -> treat handles as user handles
else
  -> trust kernel-style parameter contract
```

This is why `PreviousMode` matters even when the bug is not in the memory manager or syscall layer itself. The trust decision cascades.

### How `RequestorMode` affects driver buffer handling

In a driver, `RequestorMode` helps determine whether:

- a pointer must be treated as user-owned,
- a handle requires defensive validation,
- a nested structure contains user-controlled meaning,
- a copy or probe is required before use.

Ignoring `RequestorMode` or misreading it can collapse buffered, direct, and neither-I/O safety assumptions alike.

### Why incorrect mode assumptions create vulnerabilities

Common failure pattern:

```text
request arrives from an untrusted path
  -> intermediate layer makes it look kernel-originated
  -> downstream code skips validation it would have performed for user mode
```

That is a classic confused-deputy pattern. The deputy is trusted kernel code; the input is not.

### How confused-deputy style bugs can appear

Confused-deputy patterns appear when a driver or subsystem:

- accepts user-owned pointers through a kernel-originated wrapper,
- accepts handles without matching them to the correct `AccessMode`,
- trusts a structure because an intermediate layer already "sanitized" it,
- mixes user and kernel semantics within the same request object.

### Why changing trust-boundary assumptions is dangerous

The kernel's validation strategy depends on the assumption that origin state is meaningful. If code tampers with the interpretation of that state or bypasses it in design, then:

- buffer safety changes,
- handle validation changes,
- nested pointer expectations change,
- and any auditing logic built around normal origin semantics becomes less useful.

### Relationship to `METHOD_NEITHER`

`METHOD_NEITHER` is where `RequestorMode` becomes especially visible because the driver may receive raw user addresses. If the driver believes the request is effectively kernel-owned, it may skip the very checks that made `METHOD_NEITHER` survivable in the first place.

### Relationship to IOCTL dispatch

IOCTL handlers often sit at the last explicit boundary before the driver dereferences or forwards caller-supplied data. This is why `RequestorMode` reasoning belongs in IOCTL reviews, not only in native syscall discussions.

### Relationship to object handle access validation

Handle validation is also mode-sensitive. A caller-supplied handle interpreted under the wrong trust mode can become a cross-boundary logic flaw even if the underlying object manager APIs themselves are functioning correctly.

This is why Microsoft explicitly documents handle-validation guidance around routines such as `ObReferenceObjectByHandle`.

## Bug Class Matrix

| Bug pattern | Trust-boundary mistake | Impact | Detection idea | Safer design |
|---|---|---|---|---|
| Assuming kernel caller means safe buffer | Execution level is mistaken for trust ownership | Raw user data reaches trusted sink | RE for skipped probing on kernel-path wrappers | Preserve origin semantics and validate at final sink |
| Trusting user-controlled kernel path | Intermediary kernel component is treated as sanitizing authority | Confused-deputy behavior | Trace who actually owns the memory and handle state | Re-validate at use site |
| Skipping probe because `RequestorMode` appears `KernelMode` | Driver equates mode flag with semantic safety | Pointer misuse or stale trust assumption | Compare request construction path with final mode interpretation | Use explicit buffer ownership contracts |
| Passing user pointer into `Zw`-style path incorrectly | Data origin and API trust contract diverge | Validation mismatch | RE around `Zw*` invocations sourced from external buffers | Copy or validate before crossing trust-style API boundary |
| Nested pointer validation mistakes | Outer structure origin is validated, inner pointer trust is not | Secondary arbitrary access path or crash | Look for pointer fields inside already-approved buffers | Validate nested buffers independently |
| Inconsistent validation between `Nt` and `Zw` style paths | Similar operation handled under different assumptions | Fragile behavior and security gaps | Compare code paths for same logical operation | Normalize access checks and ownership rules |

## Debugging / Inspection Notes

### How to inspect call path

Focus on:

- where the request originated,
- which layer changes or preserves the mode assumption,
- where the final dereference or handle conversion occurs,
- whether the same logical operation is reached by both user-origin and kernel-origin paths.

### How to identify `Nt`/`Zw` usage in driver RE

In IDA or Ghidra:

- locate imported or resolved `Zw*` routines,
- trace the data flowing into those calls,
- identify whether the inputs originated from IOCTL buffers, callbacks, worker items, or internal kernel-owned state.

### How to inspect `IRP.RequestorMode` conceptually

In WinDbg or typed structure review:

- inspect `IRP` and surrounding stack context,
- correlate the request path with the driver's trust assumptions,
- record whether the code behaves differently for user versus kernel origin.

### How to document trust-boundary assumptions

A useful note format is:

```text
Input owner:
Mode assumption:
Validation site:
Use site:
Nested pointer or handle risk:
Unverified points:
```

## Defensive Angle

### Source review heuristics

- Any path that skips probe or handle validation because it assumes kernel origin should be questioned.
- Any wrapper that forwards user-owned data into `Zw*`-style code deserves close review.
- Any IOCTL path that treats "internal caller" as equivalent to "trusted data" should be documented carefully.

### Binary RE heuristics

- Compare driver code paths that call `Zw*` routines with data from external buffers.
- Look for mode checks that are present but semantically weak.
- Look for asymmetric handling between user-origin and kernel-origin paths.

### Crash patterns

Common outcomes include:

- invalid-address crashes when a skipped validation assumption meets real user memory,
- inconsistent behavior between direct internal use and externally reachable use,
- verifier or access-check failures when handles are interpreted under the wrong mode assumptions.

### Why this matters for driver security review

Because these bugs often look like "logic around validation" rather than flashy memory corruption, they are easy to under-prioritize. In reality, they cut directly across the boundary Windows depends on to keep user-supplied intent from becoming trusted kernel action.

## Common Mistakes

- Treating `KernelMode` as a synonym for "safe input".
- Ignoring nested buffers and handles because the outer call path is internal.
- Forgetting that request origin and buffer ownership can diverge.
- Discussing `PreviousMode` only as an exploit buzzword instead of as a real trust contract.

## Research Notes

- `PreviousMode` and `RequestorMode` are best studied as design invariants, not as magic fields.
- Many review findings here are "boring" in presentation but critical in consequence because they reshape how the kernel interprets caller authority.
- This topic cross-links naturally with `METHOD_NEITHER`, Object Manager handle validation, and IOCTL trust-boundary work.

## Lab-Safe Exercises

1. Trace a driver IOCTL path and document where user-owned data becomes trusted, copied, or revalidated.
2. Compare two code paths in the same driver: one internal helper path and one externally reachable path, and note whether they assume different validation contracts.
3. Write a one-page review note for a `Zw*` call site that receives data from a device-control request, without attempting to operationalize the finding.

## References / Further Reading

- Microsoft Learn, `PreviousMode`:
  https://learn.microsoft.com/nb-no/windows-hardware/drivers/kernel/previousmode
- Microsoft Learn, `IRP_MJ_DEVICE_CONTROL`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control
- Microsoft Learn, `ProbeForRead`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread
- Microsoft Learn, `Failure to Validate Object Handles`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/failure-to-validate-object-handles
- Existing repo note, [method-neither-research-notes.md](E:\Windows-kernel-exploit-research-resource\docs\userland-to-kernel\method-neither-research-notes.md)
- Existing repo note, [object-manager-and-handle-tables.md](E:\Windows-kernel-exploit-research-resource\docs\windows-internals\object-manager-and-handle-tables.md)
- Existing repo note, `03_byovd/04_limited-primitives/ASIO3_PREVIOUSMODE_DEEP_DIVE.md`

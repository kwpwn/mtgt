# MDL Misuse and Direct I/O Research Notes

## Purpose

This document explains memory descriptor lists (MDLs) and Direct I/O as a Windows kernel memory-management topic, with emphasis on ownership, locking, mapping lifetime, cleanup, and how misuse leads to high-risk driver failures.

## Background

### What an MDL is conceptually

An MDL is the kernel's description of a buffer in terms of physical page backing and access intent. It is not merely a pointer wrapper. It exists so the kernel and drivers can reason about:

- which pages back a buffer,
- whether those pages are resident and locked,
- how they may be mapped into system address space,
- and how long the mapping contract remains valid.

### Why Direct I/O exists

Direct I/O exists to reduce copying overhead and support efficient transfer of larger buffers by letting the I/O path work against locked page descriptions rather than always creating a separate system copy.

### `METHOD_IN_DIRECT` and `METHOD_OUT_DIRECT` recap

For device controls, Direct I/O usually means:

- one side of the transfer uses a system buffer,
- the other side is described through an MDL,
- and the driver must understand which direction and which access rights are intended.

### Locked pages

Locking pages does not mean the original user virtual address becomes permanently trustworthy. It means the underlying physical pages are made resident and described safely for the intended operation.

### Mapping user buffers into system address space

Direct I/O often requires mapping the locked pages into system address space so kernel-mode code can access them through a stable system-space virtual address. That mapping has its own lifetime and cleanup rules.

### Difference between virtual address, physical page, and MDL description

These are distinct:

- virtual address:
  an address in a particular process or kernel mapping context.
- physical page:
  the backing memory page frame.
- MDL:
  a description of the page-backed buffer and the access contract around it.

## Core Concepts

### `MmProbeAndLockPages`

Conceptually, this routine:

- validates access rights for the requested operation,
- makes the pages resident,
- locks them,
- and updates the MDL to describe the backing pages.

It is therefore both a validation point and a lifetime boundary.

### `MmGetSystemAddressForMdlSafe`

This routine conceptually maps the MDL-described pages into system address space and returns a kernel-usable virtual address. That address is only meaningful while the underlying mapping contract is still valid.

### `IoAllocateMdl` / `IoFreeMdl`

These routines define ownership around the MDL object itself. Confusing MDL allocation lifetime with page-lock lifetime is a common source of subtle cleanup bugs.

### Page locking and access rights

Direct I/O safety depends on matching intended operation and access semantics:

- read access,
- write access,
- modify access,
- correct handling of zero-length or unusual-length cases.

### IRQL constraints

MDL operations and mapping-related routines carry IRQL requirements. Even when page-backed access is made safer by locking, not every stage is legal at every IRQL.

### Mapping lifetime and cleanup requirements

Every MDL workflow should answer:

- who allocated the MDL,
- who locked the pages,
- who mapped system address space,
- who unlocks,
- who unmaps if needed,
- who frees the MDL,
- and when those operations become legal.

## Technical Deep Dive

### Forgetting to unlock pages

If the pages remain locked, the driver leaks memory pressure and corrupts long-term system behavior. This is not always immediately obvious in testing, which makes it especially dangerous.

### Using MDL after unlock or free

Once pages are unlocked or the MDL is freed or invalidated, previously derived assumptions about:

- PFN array,
- system address mapping,
- or buffer validity

become stale. Continuing to use them is a classic lifetime error.

### Wrong access direction

A driver that probes or locks for one access pattern but later uses the buffer in the opposite direction violates the contract and can:

- fault,
- corrupt data,
- or silently undermine validation assumptions.

### Mapping failure not handled

`MmGetSystemAddressForMdlSafe` can fail. Code that assumes mapping always succeeds often turns low-resource or corner cases into null dereferences or stale-pointer use.

### Stale system address

The system-space address returned from an MDL mapping is not a timeless property. It is tied to the mapping lifetime. Reusing it after cleanup is conceptually the same kind of error as reusing a freed heap pointer.

### Double unlock

Unlocking twice signals confused ownership or repeated teardown. In kernel code, this often means:

- cleanup was split across multiple paths without a single owner,
- error unwinding is inconsistent,
- verifier is likely to surface the bug earlier than production testing.

### Leaking locked pages

This is both a correctness and operational problem. Persistent locked pages can distort:

- memory pressure,
- performance,
- test reproducibility,
- and system stability under load.

### Trusting length from user

Direct I/O improves buffer residence guarantees, not semantic length trust. If the driver trusts:

- a caller-supplied length,
- an internally derived multiplication,
- or an embedded structure count,

without safe arithmetic and consistency checks, the MDL path inherits those logic bugs.

### Integer overflow in MDL length calculation

Overflow in buffer-size logic can create undersized validation and oversized later use. This is one of the clearest examples of how a correct memory-management primitive still depends on correct arithmetic discipline.

### Asynchronous operation lifetime bug

If the request becomes asynchronous, the driver must explicitly maintain ownership of:

- the MDL,
- mapped system address,
- associated IRP state,
- and any driver-private buffers derived from them.

Asynchronous completion is where many MDL bugs stop being obvious and become race-like.

### Mixing `METHOD_NEITHER` assumptions with Direct I/O assumptions

This is an especially subtle failure mode:

- Direct I/O code assumes pages are safely locked and described through `Irp->MdlAddress`.
- `METHOD_NEITHER` code assumes raw user addresses are still the live source of truth.

Mixing these models can cause the driver to:

- probe when it should map,
- map when it should copy,
- trust a raw address after moving to an MDL-based contract,
- or carry stale user-pointer assumptions into a direct-I/O path.

## MDL Misuse Matrix

| Mistake | Root cause | Symptom | Crash risk | Security impact | Defensive/debugging note |
|---|---|---|---|---|---|
| Forgetting to unlock pages | Cleanup ownership unclear | Memory pressure, latent stability issues | Medium | Persistent resource misuse | Track lock/unlock pairing explicitly |
| Using MDL after unlock/free | Stale lifetime assumption | Invalid access or later corruption | High | Memory misuse with unpredictable scope | Document final valid-use point |
| Wrong access direction | Validation contract mismatch | Access violation or corrupted output | High | Boundary failure | Compare `LOCK_OPERATION` with actual use |
| Mapping failure not handled | Null or error path ignored | Null dereference or incomplete cleanup | Medium-high | Reliability weakness | Check mapping return and unwind cleanly |
| Stale system address reuse | Cached mapped address outlives MDL contract | Intermittent faults | High | Hard-to-reproduce corruption | Treat mapped VA as owned resource |
| Double unlock | Confused teardown path | Verifier stop or corruption | High | Cleanup instability | Single-owner cleanup model helps |
| Leaking locked pages | Missing unlock/unmap path | Long-term memory distortion | Medium | Reliability degradation | Stress and verifier can expose it |
| Trusting length from user | Semantic validation omitted | Overrun, underrun, wrong mapping assumptions | High | Memory-safety issue | Separate size validation from MDL mechanics |
| Integer overflow in length calculation | Unsafe arithmetic | Under-validation followed by overuse | High | Potential memory corruption | Safe arithmetic before MDL build |
| Async lifetime bug | Completion path outlives resources | Race-like crash or stale access | High | Broad instability | Document completion ownership clearly |
| Mixing `METHOD_NEITHER` and Direct I/O assumptions | Wrong buffer model carried across paths | Faults, stale-pointer use, wrong cleanup | High | Trust-boundary confusion | Write explicit buffer-model notes per IOCTL |

## Debugging / Inspection Notes

### Safe WinDbg concepts for inspecting crash stacks

Good questions:

- Is the crash in an MDL lifecycle routine, mapping routine, or a later consumer?
- Was the failure in setup, steady-state use, or cleanup?
- Does the stack suggest an async completion or worker-thread path?
- Was Driver Verifier active?

### How to identify MDL-related calls in IDA or Ghidra

Look for:

- `IoAllocateMdl`
- `IoFreeMdl`
- `MmProbeAndLockPages`
- `MmUnlockPages`
- `MmGetSystemAddressForMdlSafe`
- `IoBuildPartialMdl`

The important review step is to connect each call to:

- ownership,
- error handling,
- and cleanup on every path.

### How to document ownership and cleanup

Useful format:

```text
Who allocates MDL:
Who locks pages:
Who maps system VA:
Who unlocks:
Who frees MDL:
Async completion owner:
Error unwind owner:
```

### Driver Verifier relevance

Driver Verifier is particularly valuable for MDL work because lifetime and cleanup errors often become visible only when the environment becomes stricter or more stressed.

## Defensive Angle

MDL bugs are high risk because they combine:

- memory-management complexity,
- lifetime sensitivity,
- privileged access to mapped buffers,
- and cleanup paths that often span multiple functions or threads.

Crash dumps frequently retain strong hints:

- mapping or cleanup stack traces,
- verifier involvement,
- repeated failures on direct-I/O requests,
- signs of resource leakage or stale completion state.

For QA and telemetry, MDL misuse often shows up as:

- nondeterministic driver crashes,
- verifier-only failures,
- stress-induced stability loss,
- bugchecks that cluster around I/O-heavy operations rather than one fixed code path.

## Common Mistakes

- Treating a mapped system address as valid forever.
- Assuming Direct I/O solves all pointer-validation problems.
- Forgetting that zero-length and partial-buffer cases change the MDL picture.
- Splitting cleanup across too many unlabeled owners.

## Research Notes

- MDL correctness is fundamentally an ownership discipline problem.
- Direct I/O is safer than ad hoc raw pointer access only if the driver actually honors the MDL lifecycle contract.
- Many MDL findings are more about cleanup and concurrency than about the initial setup call.

## Lab-Safe Exercises

1. Inspect a toy or sample driver's direct-I/O path and map the MDL lifecycle from creation to cleanup.
2. Compare a buffered-I/O path and a direct-I/O path for the same logical operation and list which ownership responsibilities moved into the driver.
3. In a dump or static RE note, classify an MDL bug as setup, use, or cleanup failure.

## References / Further Reading

- Microsoft Learn, `Using MDLs`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls
- Microsoft Learn, `MmProbeAndLockPages`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages
- Microsoft Learn, `MmGetSystemAddressForMdlSafe`:
  https://learn.microsoft.com/nl-nl/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemaddressformdlsafe
- Microsoft Learn, `Errors in Direct I/O`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/errors-in-direct-i-o
- Microsoft Learn, `DispatchReadWrite Using Direct I/O`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/dispatchreadwrite-using-direct-i-o
- Existing repo note, [method-neither-research-notes.md](E:\Windows-kernel-exploit-research-resource\docs\userland-to-kernel\method-neither-research-notes.md)

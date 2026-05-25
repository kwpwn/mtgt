# METHOD_NEITHER Research Notes

## Purpose

`METHOD_NEITHER` appears frequently in vulnerable-driver research because it pushes more trust-boundary work into driver code and less into the I/O Manager. This document explains why that matters, how the model differs from buffered and direct I/O, and what failure patterns make `METHOD_NEITHER` disproportionately risky in real driver reviews.

## Background

### IOCTL buffering models recap

Windows device control requests carry a transfer method in the IOCTL value. At a high level:

- `METHOD_BUFFERED` gives the driver a kernel-managed system buffer.
- `METHOD_IN_DIRECT` and `METHOD_OUT_DIRECT` involve an MDL-backed transfer for one direction and a system buffer for the other.
- `METHOD_NEITHER` leaves the driver closer to the original user virtual addresses.

That last point is the core reason `METHOD_NEITHER` keeps appearing in bug writeups. The I/O path still goes through the I/O Manager, but the driver often ends up touching addresses that remain fundamentally owned by the requesting process.

### Why `METHOD_NEITHER` passes user pointers more directly

For `IRP_MJ_DEVICE_CONTROL` requests using `METHOD_NEITHER`, Microsoft documents two key conceptual locations:

- `Type3InputBuffer` in the current stack location for input.
- `Irp->UserBuffer` for output.

This differs sharply from `METHOD_BUFFERED`, where the driver usually works against `Irp->AssociatedIrp.SystemBuffer`, and from direct I/O, where the driver typically reasons about an MDL-backed mapping for one transfer direction.

### User pointer, kernel pointer, system buffer, MDL-backed buffer

These are not interchangeable ideas:

| Buffer form | Ownership model | Typical safety property | Main risk |
|---|---|---|---|
| User pointer | Originates in caller VA space | Flexible | Faults, races, remapping, wrong access assumptions |
| Kernel pointer | Resides in kernel-owned address space | Stable while lifetime is valid | Can still be stale or freed |
| System buffer | I/O Manager-managed kernel copy | Easier validation and lifetime | Driver can still trust wrong lengths or nested pointers |
| MDL-backed buffer | Locked and described physical pages | Better stability for larger transfers | Driver still must interpret contents correctly |

### `RequestorMode` / `PreviousMode`

`METHOD_NEITHER` safety depends heavily on whether the request originated in user mode or kernel mode. Two concepts matter:

- `Irp->RequestorMode` describes where the I/O request came from.
- `PreviousMode` influences how native service code interprets caller-supplied buffers and handles.

If a driver assumes the request is trusted because the call path reached kernel mode, it collapses the exact distinction Windows tries to preserve.

### `ProbeForRead` / `ProbeForWrite`

Probe routines are the first boundary check for raw user addresses. They help validate:

- user-range addressing,
- alignment,
- requested length,
- access intent.

They do **not** provide permanent safety. They validate a point-in-time assumption about an address range, not an immutable guarantee about later dereferences.

### `try/except` usage and its limits

Exception-aware access is often required because probing or dereferencing a user pointer can still fault. However:

- `try/except` can catch a fault,
- it cannot repair bad trust assumptions,
- it cannot prevent TOCTOU,
- it cannot retroactively fix IRQL misuse,
- it cannot make an embedded user pointer sane just because the outer structure probed cleanly.

### TOCTOU risk after probing

Time-of-check/time-of-use is central to `METHOD_NEITHER` risk:

```text
driver probes user range
  -> concludes pointer and length are acceptable
  -> caller changes mapping, content, or backing state
  -> driver reuses the stale assumption later
```

The more time, indirection, or asynchronous work separates validation from use, the worse this gets.

## Core Concepts

### User pointer validation

User pointer validation is not one check. It is a contract that must be upheld across:

- address-range correctness,
- access type,
- alignment,
- full length,
- object lifetime,
- execution context,
- later re-use.

### Pointer lifetime

A pointer can be valid when first observed and invalid when later consumed. Lifetime problems become more likely when the driver:

- stores the pointer,
- queues work,
- completes asynchronously,
- or dereferences nested pointers long after the outer structure was checked.

### User/kernel address boundary

The user/kernel boundary is not only about privilege level. It is also about who owns the mapping and who can mutate it. A user mapping remains user-controlled even after a driver briefly inspects it.

### IRQL constraints

Raw user memory access is incompatible with many high-IRQL assumptions. A user page can fault, require paging activity, or simply be inaccessible at the current execution level. This makes `METHOD_NEITHER` especially dangerous when a driver carries a user pointer into:

- DPC context,
- completion routines,
- spin-lock-protected regions,
- or any path that cannot tolerate pageable access.

### Page faults while accessing user memory

Page faults are part of the normal virtual-memory model. The danger comes when a driver behaves as if a user pointer were equivalent to always-resident kernel memory. If the code path cannot tolerate a fault, `METHOD_NEITHER` becomes a structural mismatch.

### Buffer length trust

Length mistakes are common because the driver may validate:

- the minimum structure size,
- but not a nested trailing region,
- or a field-derived byte count,
- or a multiplication that overflowed before probing.

### Structure nesting and embedded pointers

A probed outer structure does not make every field in it safe. A common research pattern is:

```text
outer request structure probes cleanly
  -> structure contains pointer or pointer-like field
  -> driver trusts nested address as if the outer structure vouched for it
```

This is one of the reasons `METHOD_NEITHER` issues can hide inside code that appears to "do the right thing" at first glance.

### 32-bit vs 64-bit pointer issues

Mixed-width assumptions still matter. Drivers that consume user-controlled structures may mis-handle:

- truncation of pointer-sized fields,
- alignment assumptions,
- WOW64 caller differences,
- sign-extension or zero-extension mistakes,
- structure packing mismatch between user and kernel expectations.

## Technical Deep Dive

### `DeviceIoControl` to IRP flow for `METHOD_NEITHER`

Conceptual path:

```text
user process
  -> CreateFile on device path
  -> DeviceIoControl
  -> NtDeviceIoControlFile
  -> I/O Manager builds IRP
  -> current IO_STACK_LOCATION carries IOCTL and lengths
  -> transfer method decodes to METHOD_NEITHER
  -> input pointer conceptually lives in Type3InputBuffer
  -> output pointer conceptually lives in Irp->UserBuffer
  -> driver dispatch routine decides how to validate and use them
```

The key point is that the transfer method determines where the driver must look and what validation burden it inherits.

### Where `Type3InputBuffer` appears conceptually

In `METHOD_NEITHER`, the input side is not magically rewritten into a system buffer. The driver commonly reads the input address from the current stack location. During reverse engineering, this is one of the strongest indicators that the handler is operating under `METHOD_NEITHER` semantics.

### Where `UserBuffer` appears conceptually

The output side is similarly dangerous because the driver may write to a caller-originated address. That means every output write is also a trust-boundary event:

- is the length correct,
- is the range writable from the caller's perspective,
- is the current context still appropriate,
- is the pointer still the same logical target that was validated earlier.

### Why blindly dereferencing user-supplied pointers is unsafe

A raw pointer from user mode tells the kernel almost nothing by itself. It does not prove:

- the address belongs to the caller,
- the pages are present,
- the access type is correct,
- the range is fully mapped,
- the range stays stable,
- the structure nested underneath is consistent.

That is why direct dereference is one of the highest-signal patterns in driver review.

### Why probing once is not enough

One probe is not a lifetime guarantee. Even a correctly sized and aligned user range can become stale if:

- the caller unmaps it,
- the caller remaps it,
- the caller changes contents after validation,
- the driver stores it for later work,
- the driver validates only the outer shell and not an embedded pointer tree.

### Why copying into a kernel-owned buffer is safer

The safer pattern is usually:

```text
validate user input
  -> copy into kernel-owned buffer
  -> operate on the kernel copy
  -> separately validate output path
```

This does not remove every bug class, but it collapses a large amount of pointer-lifetime and TOCTOU complexity. The kernel copy becomes the stable object of later interpretation.

### Read-only input, output, and in/out differences

Research reviews should distinguish:

- input-only user buffer:
  driver reads attacker-controlled data.
- output-only user buffer:
  driver writes kernel-derived data into caller-owned memory.
- in/out buffer:
  driver both trusts and mutates the same user-controlled region.

These have different bug surfaces. Input-only paths are often about trust and parsing. Output paths are often about target validation and write safety. In/out paths combine both.

### Safe design principles

Useful defensive design principles:

- prefer buffered or direct I/O unless `METHOD_NEITHER` is truly needed,
- minimize raw user pointer exposure windows,
- validate lengths before field access,
- validate nested pointer fields independently,
- copy complex input to kernel-owned memory,
- avoid dereferencing user buffers at elevated IRQL,
- avoid retaining raw user pointers across asynchronous work,
- treat output pointers as separately dangerous from input pointers.

## Bug Class Matrix

| Bug pattern | Root cause | Crash risk | Security impact | Detection idea | Safer design |
|---|---|---|---|---|---|
| Unchecked user pointer dereference | Driver treats raw user address as trusted | High | Arbitrary read/write or crash depending on sink | Static RE for direct deref after `METHOD_NEITHER` decode | Use buffered/direct I/O or copy into kernel buffer |
| Incorrect `ProbeForRead` / `ProbeForWrite` usage | Wrong access type or missing exception discipline | High | Boundary bypass, wrong trust assumptions | Review probe site versus later use site | Match probe to intended access and contain later use |
| Probing wrong length | Size arithmetic or structure-length mismatch | Medium-high | Partial validation leading to overrun or stale tail fields | Compare `InputBufferLength` checks with dereferenced offsets | Validate exact consumed region and nested lengths |
| Trusting embedded pointer | Outer structure validated, inner pointer not | High | Secondary arbitrary access path | RE for pointer-like fields passed to copy/map/object APIs | Independently validate or rewrite as offsets/handles |
| Integer overflow in length calculation | Multiplication/addition wraps before check | High | Undersized probe or oversized copy | Look for unchecked arithmetic before validation | Use safe arithmetic and cap lengths early |
| Accessing pageable memory at high IRQL | Driver carries user pointer into wrong execution context | High | Bugcheck and instability | Crash triage around IRQL and faulting address | Copy at PASSIVE_LEVEL and operate on stable kernel buffer |
| Stale pointer after asynchronous operation | Validation/use split by queueing or delayed work | Medium-high | TOCTOU and UAF-like behavior on mappings | RE for stored user pointers in device extensions or work items | Snapshot input into kernel memory before queueing |
| Kernel writing to attacker-controlled pointer | Output target is insufficiently validated | High | Corruption of caller-selected memory or crash | Review writes via `Irp->UserBuffer` and nested outputs | Validate output region and prefer controlled copy paths |

## Debugging / Inspection Notes

### Finding the IOCTL method from `CTL_CODE`

The transfer type is in the low bits of the IOCTL. During static review:

- decode the control code,
- confirm that the method field is `METHOD_NEITHER`,
- then confirm the handler actually uses the corresponding IRP fields.

### Identifying `Type3InputBuffer`-style usage

In IDA or Ghidra, look for reads from the current stack location's device-control parameters that feed:

- structure parsing,
- pointer dereference,
- copy routines,
- map routines,
- object or memory-management helpers.

That pattern is usually more important than naming the field perfectly in decompiler output.

### Identifying `UserBuffer`-style usage

Look for output writes sourced from:

- `Irp->UserBuffer`,
- helper wrappers around it,
- or delayed writes into a stored user address.

### Inspecting IRP fields conceptually

Safe debugger inspection points:

- `dt _IRP`
- `dt _IO_STACK_LOCATION`
- `!irp`

The goal is to confirm:

- method,
- lengths,
- requestor mode,
- and how the handler interprets the request.

### Crash signatures to look for

Patterns worth correlating:

- `IRQL_NOT_LESS_OR_EQUAL`
- `PAGE_FAULT_IN_NONPAGED_AREA`
- access violations inside a vendor driver's device-control routine,
- verifier complaints around I/O validation or pool misuse after malformed requests.

## Defensive Angle

### Static detection heuristics

- `METHOD_NEITHER` IOCTL plus direct pointer dereference.
- Probe routine present, but later access occurs through a different derived pointer.
- Nested pointer fields passed directly to memory or object APIs.
- Output writes performed through caller-owned addresses with weak size checks.

### Source review checklist

- Does the IOCTL really need `METHOD_NEITHER`?
- Is the full consumed length validated?
- Are embedded pointers treated as independent trust boundaries?
- Is all user memory access kept at an IRQL that can tolerate it?
- Are raw user pointers retained beyond immediate request handling?

### Binary reverse engineering checklist

- Decode the IOCTL method.
- Identify where the handler gets input and output addresses.
- Trace all derived pointers.
- Compare probe sites with actual dereference sites.
- Note queueing, work items, DPC handoff, or completion callbacks.

### Runtime telemetry ideas

- Repeated crashes in a device-control path after malformed user requests.
- Driver Verifier-triggered failures when unusual software communicates with the driver.
- Short-lived processes opening the device and issuing bursts of private IOCTLs.

### Driver Verifier relevance

Verifier is valuable because it shortens feedback loops for bad I/O and memory assumptions. It will not tell you "this is a `METHOD_NEITHER` design bug" in those words, but it often turns latent misuse into earlier, clearer failures.

### Special Pool relevance

Special Pool is secondary here compared with verifier and I/O validation, but it becomes useful if pointer misuse drives later pool corruption rather than an immediate fault.

## Common Mistakes

- Equating a successful probe with permanent validity.
- Validating only the top-level structure size.
- Forgetting that output pointers are as dangerous as input pointers.
- Moving user-pointer use into DPC or queued work without redesigning the interface.
- Assuming `try/except` makes an unsafe trust model safe.

## Research Notes

- `METHOD_NEITHER` remains attractive to driver developers because it is flexible and avoids some copy overhead.
- It remains attractive to researchers for the same reason: flexibility often means the driver is acting on richer caller intent with less mediation.
- The most important distinction in review is not "does the driver use `METHOD_NEITHER`?" but "how much user ownership remains after the driver begins processing the request?"

## Lab-Safe Exercises

1. Decode a known test driver's private IOCTL and confirm whether its transfer method is `METHOD_NEITHER`.
2. In IDA or Ghidra, trace one `METHOD_NEITHER` handler and record every point where a user-originated pointer is derived or re-used.
3. In an isolated VM, compare a toy driver's validation logic for `METHOD_BUFFERED` and `METHOD_NEITHER` and write down where the burden shifts.
4. If needed for debugging practice, trigger a controlled invalid-buffer crash in a disposable lab VM and focus only on crash interpretation, not on turning the crash into a capability.

## References / Further Reading

- Microsoft Learn, `Using Neither Buffered Nor Direct I/O`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-neither-buffered-nor-direct-i-o
- Microsoft Learn, `Buffer Descriptions for I/O Control Codes`:
  https://learn.microsoft.com/ja-jp/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes
- Microsoft Learn, `PreviousMode`:
  https://learn.microsoft.com/nb-no/windows-hardware/drivers/kernel/previousmode
- Microsoft Learn, `ProbeForRead`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread
- Microsoft Learn, `IRP_MJ_DEVICE_CONTROL`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control
- Existing repo note, [userland-to-kernel-boundary.md](E:\Windows-kernel-exploit-research-resource\docs\userland-to-kernel\userland-to-kernel-boundary.md)
- Existing repo note, [ioctl-reverse-engineering.md](E:\Windows-kernel-exploit-research-resource\docs\userland-to-kernel\ioctl-reverse-engineering.md)
- Anquanke, `Windows qu dong cheng xu jing tai ni xiang gong cheng de fang fa lun`:
  https://www.anquanke.com/post/id/203237

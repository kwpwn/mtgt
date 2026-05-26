# IOCTL Bug-Class Playbook for Driver Exploit Research

Updated: 2026-05-27

## Purpose

This playbook helps classify dangerous Windows driver IOCTL paths during reverse engineering. It is not a fuzzing harness and does not provide exploit payloads. The goal is to turn a raw IOCTL handler into a clear bug-class note.

Core workflow:

```text
find device control dispatch
  -> identify IOCTL methods and access bits
  -> trace trust boundaries
  -> classify bug class
  -> classify primitive
  -> write detection and mitigation notes
```

## Safety Boundary

Do not record:

- exact weaponized input buffers,
- exploit-ready control code recipes,
- shellcode,
- offset-dependent live-target instructions.

Record:

- transfer method,
- authorization model,
- data ownership,
- dangerous API family,
- primitive class,
- failure modes,
- defensive telemetry.

## IOCTL Review Checklist

| Question | Why it matters |
|---|---|
| Who can open the device? | Determines reachability |
| What is the IOCTL method? | Determines buffer ownership |
| What are the access bits? | Determines I/O Manager enforcement |
| Does the driver revalidate access? | Stronger per-request authorization |
| Which buffer is trusted? | Finds user/kernel boundary bugs |
| Are lengths nested or user-controlled? | Finds overflow and OOB bugs |
| Is work asynchronous? | Finds lifetime/race bugs |
| Are physical/MSR/port APIs reachable? | Finds BYOVD hardware primitives |
| Is the target object referenced safely? | Finds handle/object bugs |

## Bug Class 1: Weak Device ACL

### Pattern

```text
driver creates device object
  -> symbolic link exposed
  -> broad users can open handle
  -> privileged IOCTLs become reachable
```

### Why It Matters

Even a perfectly memory-safe IOCTL can be a vulnerability if it performs privileged action for the wrong caller.

### What To Document

- device path,
- symbolic link,
- expected caller,
- actual caller class,
- whether `IoCreateDeviceSecure` or INF security is used,
- whether per-IOCTL authorization exists.

## Bug Class 2: Weak IOCTL Access Bits

### Pattern

```text
dangerous IOCTL
  -> defined with weak required access
  -> handle with minimal rights can call it
```

### Why It Matters

Device ACL and IOCTL access bits work together. Granular IOCTL access does not replace device security, but it reduces accidental exposure.

### What To Document

- whether IOCTL requires read/write access,
- whether dangerous IOCTL is `FILE_ANY_ACCESS`,
- whether `IoValidateDeviceIoControlAccess` appears,
- whether caller identity is checked in the handler.

Source:

- Microsoft Security Issues for I/O Control Codes:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/security-issues-for-i-o-control-codes

## Bug Class 3: METHOD_BUFFERED Size Confusion

### Pattern

```text
SystemBuffer
  -> input and output share same kernel buffer
  -> driver trusts wrong size or layout
```

### Why It Matters

The driver may validate input size but write output as if a larger structure exists, or parse nested lengths without checking the actual buffer.

### What It Can Become

- pool overread,
- pool overwrite,
- info leak,
- crash.

### What To Document

- minimum header size,
- nested lengths,
- output size assumptions,
- whether same buffer is reused for in/out.

## Bug Class 4: Direct I/O / MDL Contract Mistake

### Pattern

```text
MDL-backed buffer
  -> mapped to system VA
  -> driver caches or reuses mapping incorrectly
```

### Why It Matters

MDLs make page backing explicit. They do not remove lifetime problems.

### What It Can Become

- stale mapping,
- wrong buffer access,
- late completion crash,
- data leak,
- corruption under async I/O.

### What To Document

- MDL owner,
- map/unmap point,
- unlock/free point,
- whether completion path still uses mapping,
- IRQL assumptions.

Local doc:

- `docs/kernel-research/mdl-misuse-and-direct-io.md`

## Bug Class 5: METHOD_NEITHER Raw Pointer Trust

### Pattern

```text
raw user pointer
  -> no capture/probe/locking
  -> dereferenced later or in wrong context
```

### Why It Matters

The user can change memory, unmap it, race it, or point to unexpected addresses.

### What It Can Become

- crash,
- read/write primitive,
- TOCTOU,
- double-fetch,
- stale pointer.

### What To Document

- pointer source,
- probe/capture strategy,
- try/except presence,
- whether pointer is stored,
- whether worker thread uses it later.

Local doc:

- `docs/userland-to-kernel/method-neither-research-notes.md`

## Bug Class 6: Kernel Address Parameter

### Pattern

```text
IOCTL contains address field
  -> driver treats it as trusted kernel address
  -> read/write/copy uses it
```

### Why It Matters

Address parameters are the shortest route to arbitrary kernel R/W if not constrained.

### What It Can Become

- virtual kernel read,
- virtual kernel write,
- memcpy primitive,
- callback/security-state tamper,
- data-only object manipulation.

### What To Document

- virtual vs physical,
- source vs destination,
- readback available,
- width and alignment,
- page crossing behavior,
- exception handling.

## Bug Class 7: Physical Address Parameter

### Pattern

```text
IOCTL contains physical address
  -> driver maps/copies range
  -> caller controls RAM/MMIO target
```

### Why It Matters

This creates a physical memory or device MMIO primitive.

### What It Can Become

- physical RAM read/write,
- device MMIO access,
- firmware/hardware impact,
- kernel object mutation after VA-to-PA bridge.

### What To Document

- range restrictions,
- mapping destination,
- user-mode mapping or kernel copy,
- read/write permissions,
- RAM vs MMIO distinction.

## Bug Class 8: MSR / Port / PCI Operation

### Pattern

```text
caller supplies MSR index, port, PCI BDF, or MMIO range
  -> driver performs privileged hardware operation
```

### Why It Matters

This crosses CPU or hardware privilege boundaries.

### What It Can Become

- KASLR anchor,
- hardware state tamper,
- platform-specific impact,
- denial of service,
- firmware-adjacent access.

### What To Document

- operation type,
- whether writes are allowed,
- range validation,
- platform dependency,
- expected vendor app behavior.

## Bug Class 9: Handle/Object Validation Failure

### Pattern

```text
caller supplies handle
  -> driver references object incorrectly
  -> type/access/mode not validated
```

### Why It Matters

Handles are mediated references, not raw authority. Drivers must validate type, granted access, and origin mode.

### What It Can Become

- confused-deputy object access,
- access check bypass,
- stale object pointer,
- wrong object type use.

### What To Document

- target object type,
- expected access mask,
- `AccessMode`,
- whether `ObReferenceObjectByHandle` is used correctly,
- dereference path.

## Bug Class 10: Async Completion and Cancel Race

### Pattern

```text
IRP queued
  -> cancel/completion/unload paths race
  -> object or buffer lifetime changes
```

### Why It Matters

Many driver bugs appear only when requests overlap or cancellation happens mid-flight.

### What It Can Become

- double completion,
- UAF,
- stale MDL mapping,
- stale callback context,
- crash on unload.

### What To Document

- queue ownership,
- cancel routine,
- completion routine,
- reference counting,
- teardown ordering.

## Primitive Classification Table

| Observation | Primitive |
|---|---|
| caller controls kernel VA source | virtual read |
| caller controls kernel VA destination | virtual write |
| caller controls both copy endpoints | memcpy-like R/W |
| caller controls physical address | physical memory / MMIO |
| caller controls MSR index | MSR primitive |
| caller controls port | port I/O primitive |
| caller controls handle without access validation | object access primitive |
| caller controls nested length | memory corruption / info leak |
| caller controls async lifetime | race / UAF primitive |

## Writeup Template

```text
Driver:
Device object:
Symbolic link:
Expected caller:
Actual reachable caller:

IOCTL family:
Transfer method:
Required access:
Authorization:

Bug class:
Primitive:
Why it works:
What it can do:
What bridge is needed:
Failure modes:
Defensive signals:
References:
```

## References

- IRP_MJ_DEVICE_CONTROL:
  https://learn.microsoft.com/windows-hardware/drivers/kernel/irp-mj-device-control
- Security Issues for I/O Control Codes:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/security-issues-for-i-o-control-codes
- Driver security checklist:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist
- Driver Verifier:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier

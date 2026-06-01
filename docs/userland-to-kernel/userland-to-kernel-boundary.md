# Userland to Kernel Boundary

## Purpose

This document explains the trust boundary between user mode and kernel mode in Windows, with emphasis on system calls, `DeviceIoControl`, I/O request packets (IRPs), requestor context, and the validation duties that sit between an untrusted caller and privileged driver code. The goal is to support reverse engineering, bug class recognition, and defensive review without turning the material into an exploit guide.

## Background

Many Windows local privilege escalation paths are not "kernel exploits" in the classic sense of controlling instruction pointer in ring 0. A large fraction of real-world issues come from software that already runs in kernel mode but accepts dangerous input from user mode through:

- native system calls,
- object handles,
- named device objects,
- I/O control codes (IOCTLs),
- shared memory or mapped sections,
- callback registration or notification channels.

The core defensive question is simple:

```text
Which assumptions from user mode survive the boundary crossing,
and which assumptions must be rebuilt by the kernel component?
```

If a driver crosses that boundary without re-validating the request, the driver becomes a broker for privileged operations.

## Core Concepts

### User mode vs kernel mode

User mode code executes with restricted privilege and must go through kernel-managed interfaces for memory management, object access, file I/O, device access, process creation, and security state changes. Kernel mode code executes with broad access to system memory, devices, and executive objects. This does not mean kernel code is automatically trusted in a security design sense; it means its mistakes have broader blast radius.

### Syscall boundary

The classic boundary for Windows native services is:

```text
user process
  -> kernel32 / other Win32 API
  -> ntdll native wrapper
  -> system call transition
  -> ntoskrnl service routine
  -> executive / manager component
```

The Win32 layer offers stable developer-facing APIs. The native layer exposes the lower-level `Nt*` surface. Both eventually rely on kernel-side parameter interpretation, object access checks, and probing of user-controlled buffers when the caller originated in user mode.

### Nt/Zw distinction at a conceptual level

The `Nt*` and `Zw*` naming split matters because parameter interpretation can differ depending on caller context and previous mode. A user-mode caller reaches native services through `Nt*` entry points exposed by `ntdll`. Kernel-mode components often call `Zw*` routines. The important research takeaway is not "memorize every difference", but:

- access mode influences probing and handle interpretation,
- the kernel needs to know whether the original caller was user mode or kernel mode,
- incorrect assumptions about previous mode can convert a legitimate API into an unsafe primitive.

### `DeviceIoControl` flow

For driver research, the most important userland-to-kernel path is usually the device control path:

```text
user process
  -> CreateFile on \\.\DeviceName or DOS symbolic link
  -> DeviceIoControl
  -> kernel32 thunk
  -> ntdll native wrapper
  -> NtDeviceIoControlFile
  -> I/O Manager
  -> IRP creation
  -> target DRIVER_OBJECT MajorFunction[IRP_MJ_DEVICE_CONTROL]
  -> vendor dispatch routine
```

This path is attractive because it is explicit, structured, repeatable, and often poorly constrained by third-party drivers.

### IRP and `IRP_MJ_DEVICE_CONTROL`

An IRP is the kernel's packet for describing an I/O request. For reverse engineering, the important parts are:

- the major function code,
- the current I/O stack location,
- requestor mode,
- the IOCTL value,
- input and output lengths,
- the buffering method implied by the IOCTL,
- where the buffers actually live.

For device controls, `Parameters.DeviceIoControl.IoControlCode` in the current stack location is the selector that tells the driver which operation the caller wants.

### IOCTL buffering models

IOCTL transfer semantics are part of the trust boundary. The transfer method is encoded in the low bits of the control code.

| Method | Kernel-side view | Main safety property | Main failure mode |
|---|---|---|---|
| `METHOD_BUFFERED` | I/O manager uses `SystemBuffer` for both directions | Simplifies validation and lifetime | Driver trusts contents or size too much |
| `METHOD_IN_DIRECT` | Input usually via `SystemBuffer`, output via MDL-backed buffer | Better for larger transfers | Driver misreads which buffer carries what |
| `METHOD_OUT_DIRECT` | Similar direct-I/O model with MDL-backed transfer | Useful for large output | Driver misuses MDL-backed buffer or length |
| `METHOD_NEITHER` | Raw user virtual addresses are handed through | Flexible but dangerous | Missing probe, wrong process context, TOCTOU, invalid pointer use |

`METHOD_NEITHER` is not automatically a vulnerability, but it sharply raises the burden on the driver.

### `RequestorMode` and `PreviousMode`

Windows tracks where the request originated. Two related concepts appear often:

- `Irp->RequestorMode`: request origin for that I/O request.
- `PreviousMode`: thread-origin state used by native services for parameter treatment and handle validation.

These concepts matter because parameter probing and handle interpretation differ between user-originated and kernel-originated requests. When a driver or system service treats a user-originated request as if it came from kernel mode, the boundary weakens dramatically.

### `ProbeForRead` and `ProbeForWrite`

When the kernel must access user-controlled addresses directly, it cannot assume:

- the pointer is canonical,
- the page is mapped,
- the range is writable,
- the caller will not race the mapping after validation.

`ProbeForRead` and `ProbeForWrite` are conceptually the "is this even a valid user buffer?" check. They are not enough on their own; subsequent dereferences still need exception-aware handling because mappings can change after the probe.

### Access masks and object handles

Crossing the boundary safely also depends on object security:

- what handle did the caller open,
- against which object type,
- with which requested rights,
- under which security context,
- and whether the kernel component re-validates the handle before acting on it.

Unsafe drivers often fail by treating a caller-supplied handle or pointer as authoritative instead of as a claim that still needs type, access, and lifetime validation.

## Technical Deep Dive

### Why the boundary is easy to misunderstand

A user-mode process that successfully opens a driver handle has not earned the right to ask the driver to do arbitrary privileged work. It has only passed one gate:

```text
Can I send a request to this device object?
```

The driver still must answer:

```text
Should this caller be allowed to request this operation,
with this buffer shape,
on this object,
for this length,
in this execution context?
```

The most common validation mistakes cluster into a few families:

| Validation mistake | Why it happens | Defensive impact |
|---|---|---|
| Device object too broadly open | Weak SDDL or insecure creation defaults | Any local process can reach privileged paths |
| IOCTL uses `FILE_ANY_ACCESS` carelessly | Convenience during development | Access checks rely only on handle open success |
| Length check only validates minimum size | Driver expects trailing fields implicitly | Structure confusion and stale field use |
| User pointer trusted after probe | Developer treats probe as permanent guarantee | Race and fault risk remains |
| Wrong buffering model assumptions | Reverse direction or actual kernel buffer misunderstood | Data copied from/to the wrong place |
| Requestor origin ignored | Code assumes trusted caller | User-supplied buffers or handles bypass intended checks |
| Handle type not revalidated | Driver assumes caller passed correct object class | Arbitrary object reference or confused-deputy risk |

### Conceptual flow of a device control request

```text
CreateFile("\\\\.\\VendorDevice")
  -> file object for device is created
  -> security descriptor on the device object decides who may open it

DeviceIoControl(...)
  -> user buffer pointers and lengths are packaged
  -> native service enters the kernel
  -> I/O Manager builds an IRP
  -> current stack location receives IOCTL code and lengths
  -> driver dispatch routine decodes operation
  -> driver validates request
  -> driver performs action or forwards the IRP
```

Each stage is a filtering opportunity. Weak security often means too many of those stages are treated as bookkeeping instead of validation points.

### `METHOD_NEITHER` and direct trust hazards

`METHOD_NEITHER` is conceptually the sharpest edge because the I/O manager does less mediation. The driver often receives original user virtual addresses rather than a kernel-owned copy or an I/O-manager-built MDL. That means the driver must reason about:

- caller context,
- probe semantics,
- exception handling,
- alignment,
- page accessibility,
- race windows,
- asynchronous reuse of the IRP after the original thread context is gone.

This is why many driver security reviews start by asking:

```text
Which IOCTLs are METHOD_NEITHER,
and what does the driver do after it receives those pointers?
```

### `PreviousMode` and confused trust

`PreviousMode` is a particularly important conceptual bridge between native services and exploit primitive theory. If a code path incorrectly causes native routines to treat user-originated parameters as kernel-originated parameters, then APIs that are normally safe because they probe user buffers can become unsafe. Even when a repo already has a case study around `PreviousMode`, the general lesson is broader:

- trust origin is data,
- that data influences parameter interpretation,
- modifying or misreading that data can weaken access checks and probing logic.

### Defensive visibility

Visibility into the boundary is uneven. Defenders usually see:

- handle opens to named devices,
- service creation and driver load activity,
- process ancestry around the caller,
- crash artifacts when validation fails catastrophically,
- some ETW or Sysmon coverage for driver load and image load.

Defenders usually do **not** see, by default:

- exact private IOCTL semantics,
- internal driver authorization logic,
- whether a specific `METHOD_NEITHER` request used unsafe pointer handling,
- whether a legitimate signed driver exposed a privileged operation that should never have been reachable from arbitrary user mode.

That asymmetry is why defensive documentation must emphasize boundary review and driver design, not only runtime detection.

## Windows Version Notes

- The high-level syscall and IRP model is stable across supported Windows versions.
- The exact system call stubs, structure layouts, and internal helper behavior change by build.
- The practical importance of userland-to-kernel boundary flaws increased as code-execution-focused chains became harder under modern mitigations such as HVCI, CET, and stronger code-signing policy.
- Windows 10 and Windows 11 era defenses make "unsafe signed driver semantics" a more operationally relevant problem than classic ret2usr-style mental models.

## Common Mistakes

Checklist for reviewing a userland-to-kernel boundary:

- Is the device object reachable by low-privilege users?
- Does the IOCTL use `FILE_ANY_ACCESS` without a compensating authorization check?
- Does the driver decode lengths before dereferencing any field?
- Does the driver understand the actual buffering model?
- Does it probe user pointers when needed?
- Does it continue to guard later accesses inside exception-aware logic?
- Does it validate handle type and granted access?
- Does it rely on caller context remaining stable across asynchronous work?
- Does it incorrectly assume signed code equals trusted input?

## Debugging / Inspection Notes

Useful inspection points for lab-safe debugging:

- WinObj or DeviceTree to inspect named device objects and symbolic links.
- WinDbg:
  - `!drvobj` to inspect a driver object,
  - `!devobj` to inspect device objects,
  - `!irp` on captured requests,
  - `dt _IRP` and `dt _IO_STACK_LOCATION` for field layout,
  - `!object` for Object Manager namespace inspection.
- Static RE:
  - find `DriverEntry`,
  - identify `IoCreateDevice` or `IoCreateDeviceSecure`,
  - locate `IoCreateSymbolicLink`,
  - inspect `MajorFunction` initialization,
  - trace the `IRP_MJ_DEVICE_CONTROL` handler.

## Defensive Angle

A safe design for this boundary usually looks like:

- restrictive device object ACLs,
- minimal attack surface in exported IOCTLs,
- strongly typed input contracts,
- narrow privilege checks beyond mere handle open success,
- avoidance of `METHOD_NEITHER` unless there is a compelling reason,
- explicit type and access validation for all caller-supplied handles,
- defensive testing under Driver Verifier and fault injection.

Reviewers should treat a driver as a privileged RPC server. The question is not merely whether it "works", but whether it authorizes and validates each request as if the caller is malicious.

## Lab-Safe Exercises

1. Pick a known-safe or test driver and trace its `DeviceIoControl` path from user mode API down to the `IRP_MJ_DEVICE_CONTROL` handler in a debugger.
2. For one IOCTL, identify the transfer method, access bits, input length checks, and whether the device object appears broadly reachable.
3. In WinDbg, inspect `IRP` and `IO_STACK_LOCATION` layouts on the target build and record where IOCTL code, lengths, and requestor mode live.
4. Compare a driver that uses buffered I/O with one that uses direct or neither I/O, and note where the validation burden shifts.

## References / Further Reading

- Microsoft Learn, `IRP_MJ_DEVICE_CONTROL`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control
- Microsoft Learn, `ZwDeviceIoControlFile`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwdeviceiocontrolfile
- Microsoft Learn, `PreviousMode`:
  https://learn.microsoft.com/nb-no/windows-hardware/drivers/kernel/previousmode
- Microsoft Learn, `ProbeForRead`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforread
- Microsoft Learn, `Using Neither Buffered Nor Direct I/O`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-neither-buffered-nor-direct-i-o
- Microsoft Learn, `Determining the Buffering Method for an I/O Operation`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/determining-the-buffering-method-for-an-i-o-operation
- Microsoft Learn, `Object Handles`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles
- Anquanke, `Windows nei he qu dong cheng xu jing tai ni xiang gong cheng de fang fa lun`:
  https://www.anquanke.com/post/id/203237
- Anquanke, `Li yong Windows I/O shi xian ben di ti quan`:
  https://www.anquanke.com/post/id/173626

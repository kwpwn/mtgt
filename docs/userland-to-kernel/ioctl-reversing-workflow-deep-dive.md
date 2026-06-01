# IOCTL Reversing Workflow Deep Dive

Backlinks: [README](../../README.md) | [topic index](../research-index/topic-index.md) | [learning path](../research-index/windows-kernel-pwn-learning-path.md)

## Purpose

Teach a repeatable, lab-safe workflow for understanding driver IOCTL attack surface without building exploit tooling.

## What You Will Learn

- How to find device names, symbolic links, and IOCTL dispatchers.
- How to decode `CTL_CODE`, method, function, device type, and access bits.
- How buffer methods influence vulnerability classes.
- How to document vulnerable patterns safely.

## Prerequisites

Know basic Windows driver structure: `DriverEntry`, `DRIVER_OBJECT`, `DEVICE_OBJECT`, IRPs, and dispatch routines.

## Core Concepts

| Concept | Why it matters |
|---|---|
| `IoCreateDevice` | Creates the kernel device object. |
| `IoCreateDeviceSecure` | Allows explicit SDDL; safer for user-reachable devices. |
| Symbolic link | Exposes `\\.\Name` to user mode. |
| Dispatch table | `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` is the common IOCTL path. |
| `CTL_CODE` | Encodes device type, function, method, and access. |
| SDDL/ACL | Decides who can open the device. |

## CTL_CODE Layout

```text
CTL_CODE(DeviceType, Function, Method, Access)
```

| Field | Question |
|---|---|
| DeviceType | Is this a standard or vendor/custom device type? |
| Function | Which switch case or handler consumes it? |
| Method | How are buffers transferred? |
| Access | Did the driver require read/write access or `FILE_ANY_ACCESS`? |

## Buffer Methods

| Method | Kernel view | Common risk |
|---|---|---|
| `METHOD_BUFFERED` | Input/output share `SystemBuffer`. | Length confusion, stale output, insufficient validation. |
| `METHOD_IN_DIRECT` | Input in `SystemBuffer`, output via MDL for device input semantics. | MDL misuse, access direction confusion. |
| `METHOD_OUT_DIRECT` | Input in `SystemBuffer`, output via MDL for device output semantics. | Trusting user-controlled output mapping. |
| `METHOD_NEITHER` | Raw user pointers in IRP stack. | Missing `ProbeForRead/Write`, TOCTOU, arbitrary pointer deref. |

## Workflow

1. Identify the driver binary, version, signer, and load path.
2. Find `DriverEntry`.
3. Locate device creation and symbolic link creation.
4. Extract SDDL or security descriptor behavior.
5. Find `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, and `IRP_MJ_DEVICE_CONTROL`.
6. Decode IOCTL switch cases.
7. For each IOCTL, map method, expected input/output sizes, access bits, and caller checks.
8. Identify external trust boundary: admin-only service, low-privileged user, or vendor app.
9. Document risky patterns with pseudo-code only.
10. Map primitive, mitigation, detection, and version assumptions.

## Vulnerable Patterns

| Pattern | Why it fails |
|---|---|
| No device ACL or permissive SDDL | Untrusted callers can reach kernel capability. |
| Substring/path-based caller authentication | TOCTOU and hardlink-style races can invalidate the check. |
| Direct user pointer deref | User memory can fault, change, or point to hostile locations. |
| Missing length checks | Kernel buffer overflow or info leak. |
| Double fetch | First validation and later use observe different user data. |
| Exposing `MmMapIoSpace`, MSR, or port I/O directly | Hardware/admin capability becomes user-controlled. |
| Returning uninitialized kernel data | KASLR and object layout leaks. |

## Safe Pseudo-Code Pattern

```text
on_ioctl(code, input, input_len, output, output_len):
    identify buffer method
    validate caller authorization
    validate structure size and version
    validate pointer provenance
    validate address range / object type
    perform bounded operation
    return explicit status and output length
```

## IDA/Ghidra/WinDbg Workflow

| Tool | Use |
|---|---|
| IDA/Ghidra | Rename dispatch routines, recover switch cases, identify calls to dangerous APIs. |
| WinDbg | Verify object names, security descriptors, symbols, and crash triage. |
| Sigcheck/WinVerifyTrust | Validate signer metadata. |
| Static strings | Locate `\Device\`, `\DosDevices\`, debug prints, IOCTL names. |

## Detection Notes

- Driver load followed by unusual user process opening a device.
- Repeated IOCTL fuzz-like failures.
- Kernel crashes inside `IRP_MJ_DEVICE_CONTROL`.
- Device object ACL allowing `Everyone` or low-integrity callers.
- Driver using physical memory, MSR, or process-control APIs.

## Common Misconceptions

- A driver is not safe because it was intended for a vendor service.
- `FILE_ANY_ACCESS` is not a harmless default.
- `METHOD_BUFFERED` is safer than `METHOD_NEITHER`, but still vulnerable if size and semantics are wrong.
- IOCTL value alone is not enough; method and ACL matter.

## Questions to Ask Yourself

1. Who can open the device?
2. Which IOCTLs expose privileged capability?
3. What does the driver trust from user mode?
4. Can input change between validation and use?
5. What telemetry proves a caller exercised this path?

## Related Repo Docs

- [Primitive reasoning framework](../kernel-research/primitive-reasoning-framework.md)
- [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md)
- [Case-study matrix](../research-index/case-study-matrix.md)

## References

- Idafchev WRMSR: https://idafchev.github.io/blog/wrmsr/
- xacone eneio64: https://xacone.github.io/eneio-driver.html
- Julian Pena driver exploitation: https://julian-pena.com/2025-09-29-exploiting-drivers-1/
- Quarkslab Lenovo: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html

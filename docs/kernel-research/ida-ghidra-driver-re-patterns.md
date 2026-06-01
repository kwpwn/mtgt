# IDA/Ghidra Driver RE Pattern Notebook

Updated: 2026-05-27

## Purpose

This notebook lists safe static-reversing patterns for Windows kernel drivers. It is designed for driver research notes, BYOVD triage, and defensive review.

The goal is not to produce an exploit. The goal is:

```text
binary
  -> device exposure
  -> dispatch surface
  -> buffer model
  -> privileged sink
  -> primitive class
  -> failure modes
  -> detection and hardening
```

## Fast Triage Pass

Start with these questions:

- Is it WDM, KMDF/WDF, NDIS, minifilter, filesystem, storage, display, or hardware utility?
- Does it expose a user-mode control device?
- Does it use private IOCTLs?
- Does it touch physical memory, MSRs, port I/O, PCI config, MMIO, process objects, callbacks, or security state?
- Does it create a broad device ACL?
- Is the driver known in LOLDrivers, Microsoft block rules, vendor advisories, or EDR signatures?

## Pattern 1: WDM Driver Skeleton

Look for:

```text
DriverEntry
  -> IoCreateDevice / IoCreateDeviceSecure
  -> IoCreateSymbolicLink
  -> DriverObject->MajorFunction[x] assignments
  -> DriverObject->DriverUnload
```

Why:

```text
WDM dispatch table gives the first attack-surface map
```

Important major functions:

- `IRP_MJ_CREATE`,
- `IRP_MJ_CLOSE`,
- `IRP_MJ_DEVICE_CONTROL`,
- `IRP_MJ_INTERNAL_DEVICE_CONTROL`,
- `IRP_MJ_READ`,
- `IRP_MJ_WRITE`.

Pitfall:

```text
some drivers use common dispatch for many major functions;
the IOCTL path may be selected inside the common routine
```

## Pattern 2: KMDF/WDF Driver Skeleton

Look for:

```text
DriverEntry
  -> WdfDriverCreate
  -> EvtDriverDeviceAdd
  -> WdfDeviceCreate
  -> WdfIoQueueCreate
  -> EvtIoDeviceControl
```

Why:

```text
the real IOCTL handler is often registered as a queue callback,
not assigned into MajorFunction directly
```

What to recover:

- device name,
- symbolic link or device interface,
- queue dispatch mode,
- request handlers,
- object context layout,
- cleanup/destroy callbacks.

## Pattern 3: IOCTL Switch

Classic shape:

```text
IoGetCurrentIrpStackLocation
  -> Parameters.DeviceIoControl.IoControlCode
  -> switch / if-chain
  -> per-command helper
```

Recovery method:

1. Decode the IOCTL fields.
2. Map input/output lengths.
3. Identify which IRP buffer fields are used.
4. Trace user-controlled values into privileged sinks.
5. Classify the primitive.

Do not stop at the code value. The dangerous part is the semantic operation behind the value.

## Pattern 4: Buffer Model Confusion

High-risk signs:

- `METHOD_NEITHER`,
- raw pointer from user buffer,
- pointer field inside a buffered structure,
- no length check before fixed-offset loads,
- same buffer used as both input and output,
- size value used for allocation or copy without bounds,
- 32-bit truncation of pointer or size,
- user pointer stored for later use.

Reasoning:

```text
buffer bugs usually break one of three invariants:
address validity,
length validity,
lifetime/context validity
```

## Pattern 5: Dangerous Sink Import Map

Memory and mapping:

- `MmMapIoSpace`,
- `MmCopyMemory`,
- `MmMapLockedPagesSpecifyCache`,
- `MmProbeAndLockPages`,
- `IoAllocateMdl`,
- `ZwMapViewOfSection`,
- `MmGetPhysicalAddress`.

Object and process:

- `PsLookupProcessByProcessId`,
- `ObReferenceObjectByHandle`,
- `ZwOpenProcess`,
- `ZwTerminateProcess`,
- `ZwQuerySystemInformation`.

Hardware:

- `__readmsr`,
- `__writemsr`,
- `READ_PORT_*`,
- `WRITE_PORT_*`,
- PCI config helpers,
- vendor HAL/device-specific MMIO helpers.

Callback/security:

- `PsSetCreateProcessNotifyRoutine*`,
- `PsSetLoadImageNotifyRoutine`,
- `ObRegisterCallbacks`,
- `CmRegisterCallbackEx`,
- minifilter registration APIs.

Why:

```text
sink class tells you what the driver can affect;
source-to-sink control tells you whether user input chooses the effect
```

## Pattern 6: Physical Memory Path

Static signs:

```text
user-controlled address or offset
  -> physical address interpretation
  -> MmMapIoSpace / copy from mapped range
  -> unmap
```

Questions:

- Does input choose physical address?
- Does input choose length?
- Is the range constrained to device BARs?
- Is cache type fixed or user-controlled?
- Is readback available?
- Is cross-page behavior handled?

Primitive classification:

| Observation | Primitive |
|---|---|
| arbitrary physical map and copy | physical R/W |
| fixed hardware BAR only | hardware-specific MMIO |
| read-only mapping | info leak / physical read |
| write-only mapping | physical write without readback |

## Pattern 7: Virtual Kernel R/W Path

Static signs:

```text
user buffer contains kernel-looking address
  -> driver copies from/to that address
  -> no object/type/range validation
```

Questions:

- Is the address virtual or physical?
- Is copy direction attacker-controlled?
- Is length attacker-controlled?
- Is kernel address range checked?
- Does the driver use structured exception handling?
- Does it expose both read and write?

Why:

```text
virtual R/W often removes the VA-to-PA bridge,
but still needs object discovery and build-aware layout reasoning
```

## Pattern 8: MSR / Port / MMIO Path

Static signs:

```text
input register/index/port
  -> rdmsr/wrmsr or port I/O helper
  -> return value or write side effect
```

Questions:

- Which register namespace is affected?
- Are indices restricted?
- Is the operation CPU-local or system-wide?
- Does it require particular hardware?
- Is the driver using this as intended diagnostics or exposing raw access?

Why:

```text
hardware primitives can be powerful but fragile;
they often create crash and detection risk before stable impact
```

## Pattern 9: Callback And Security-State Path

Static signs:

```text
driver registers callback
  -> stores registration handle
  -> later IOCTL modifies callback state or related policy state
```

or:

```text
driver exposes write primitive
  -> public write-up discusses callback/PPL/CI/minifilter state tamper
```

Research boundary:

- document invariant and detection,
- avoid publishing patch locations,
- avoid exact disable/unlink steps,
- prefer cross-view verification.

Why:

```text
security-state tamper is often more fragile than object data-only modification
because PatchGuard, product self-defense, and telemetry contradictions remain
```

## Pattern 10: Auth Gate And Broker Service

Look for:

- process-name checks,
- image path checks,
- signature checks,
- magic values,
- service session tokens,
- cached trusted handle state,
- IOCTL subcommands hidden behind one public function.

Questions:

- Is the check before or after parsing?
- Is it tied to token identity or just process metadata?
- Can a trusted service be coerced into sending the IOCTL?
- Can a handle be duplicated?
- Does the gate protect every dangerous command?

Why:

```text
many vendor checks are product integrity checks,
not adversarial authorization boundaries
```

## Pattern 11: Build-Sensitive Object Offsets

If the write-up path requires `_EPROCESS`, `_TOKEN`, callback structures, object headers, or kernel globals:

- record Windows build,
- prefer symbols over hard-coded offsets,
- document fallback strategy,
- record failure mode when layout changes,
- separate primitive capability from chosen target field.

Why:

```text
primitive may be stable while the bridge to impact is build-sensitive
```

## Pattern 12: Crash-To-Pattern Feedback

When static analysis is uncertain, crash evidence helps classify the bug:

| Crash sign | Static pattern to revisit |
|---|---|
| user-range pointer in kernel stack | raw pointer trust / METHOD_NEITHER |
| wrong IRQL | pageable access or invalid API at elevated IRQL |
| pool corruption | length or lifetime bug |
| fault near mapped address | physical/virtual confusion |
| crash after unload | callback/timer/work-item cleanup |
| verifier stop | framework or DDI contract violation |

## Documentation Template

```text
Driver:
Vendor:
Type:
Driver model:
Device object:
Symbolic link/interface:
ACL/SDDL:
Dispatch root:
IOCTL map:
Buffer methods:
Dangerous sinks:
Primitive:
Why it works:
Bridge needed:
Failure modes:
Mitigations:
Detection ideas:
Open questions:
```

## Common Mistakes

- Calling everything "arbitrary R/W" without direction, address space, length, and readback.
- Ignoring device ACL and IOCTL access bits.
- Confusing physical and virtual addresses.
- Import-scanning sinks without checking whether user input controls arguments.
- Treating process termination as equivalent to memory primitives.
- Treating a PoC target offset as universal across builds.
- Ignoring cleanup/unload bugs because they are not in the main IOCTL path.

## Study Questions

1. What pattern tells you a driver is KMDF rather than classic WDM?
2. Why does a dangerous sink import not prove exploitability?
3. How do IOCTL method bits change the validation burden?
4. Why is device ACL analysis part of exploitability, not just hardening?
5. What makes a primitive "physical" rather than "virtual"?

## References

- Microsoft Learn, `Defining I/O Control Codes`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
- Microsoft Learn, `IRP_MJ_DEVICE_CONTROL`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control
- Microsoft Learn, `Buffer Descriptions for I/O Control Codes`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes
- Microsoft Learn, `Request Handlers`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/request-handlers
- Existing repo note:
  `docs/userland-to-kernel/ioctl-reverse-engineering.md`


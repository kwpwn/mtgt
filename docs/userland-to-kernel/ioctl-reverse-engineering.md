# IOCTL Reverse Engineering

## Purpose

This document provides a repeatable, lab-safe method for reversing Windows driver IOCTL interfaces. It focuses on identifying device exposure, dispatch handlers, buffering methods, structure hypotheses, and primitive classes without producing exploit code.

## Background

Many vulnerable drivers are not opaque because of complex cryptography or anti-analysis; they are opaque because the analyst has not yet mapped:

- how the device is created,
- how the symbolic link is exposed,
- which major function handles controls,
- how the IOCTL code is decoded,
- what buffer layout the handler expects,
- and what privileged operation the handler ultimately performs.

IOCTL reverse engineering sits between static reverse engineering and bug-class classification. It is where a generic driver binary becomes a concrete attack-surface map.

## Core Concepts

### Device object and symbolic link discovery

Most user-reachable software drivers follow a recognizable pattern in `DriverEntry`:

```text
DriverEntry
  -> IoCreateDevice or IoCreateDeviceSecure
  -> optional security descriptor setup
  -> IoCreateSymbolicLink
  -> MajorFunction dispatch table assignments
```

The symbolic link often becomes the `\\.\Name` string used from user mode.

### Major function table

`DRIVER_OBJECT->MajorFunction[]` is the top-level dispatch table. For IOCTL work, the key slots are:

- `IRP_MJ_CREATE`
- `IRP_MJ_CLOSE`
- `IRP_MJ_DEVICE_CONTROL`
- sometimes `IRP_MJ_INTERNAL_DEVICE_CONTROL`

If `IRP_MJ_DEVICE_CONTROL` points to a dispatcher that switches on `Parameters.DeviceIoControl.IoControlCode`, the analyst has the primary command router.

### `CTL_CODE`

Windows private IOCTLs commonly use:

```text
CTL_CODE(DeviceType, Function, Method, Access)
```

Reverse engineering should decode four fields:

- device type,
- function number,
- transfer method,
- access bits.

That alone does not reveal the vulnerability, but it narrows the expected trust model and buffer semantics.

### Structure recovery

Recovering the input and output structures is usually a hypothesis-building exercise:

- what lengths are checked,
- what offsets are dereferenced,
- whether fields are copied into locals,
- whether a pointer-sized field is treated as an address,
- whether a handle-like field is passed to Object Manager APIs,
- whether a physical address or kernel virtual address interpretation appears.

## Technical Deep Dive

### Step 1: Find the user-visible name

Analysts should first ask:

```text
How does user mode find this driver?
```

Sources of truth:

- `IoCreateSymbolicLink`,
- device interface registration,
- hard-coded `\Device\Name`,
- DOS-device style aliases exposed in logs or strings.

Practical reverse engineering note: drivers that do not create an obvious DOS symbolic link may still be reachable through device interfaces, preexisting names, or by a cooperating service.

### Step 2: Find `DriverEntry`

From `DriverEntry`, record:

- device creation routine,
- device name,
- symbolic link name,
- unload routine,
- dispatch assignments,
- whether the device uses `DO_BUFFERED_IO` or `DO_DIRECT_IO` for read/write paths.

For IOCTL work, note that the transfer method for `IRP_MJ_DEVICE_CONTROL` comes from the IOCTL itself, not from the `DEVICE_OBJECT` read/write flags.

### Step 3: Find the `IRP_MJ_DEVICE_CONTROL` handler

Common pattern:

```text
dispatch_device_control(DeviceObject, Irp)
  -> IoGetCurrentIrpStackLocation(Irp)
  -> code = stack->Parameters.DeviceIoControl.IoControlCode
  -> switch(code) or nested if-chain
```

If the driver uses helper functions, follow:

- code-specific helper dispatch,
- access checks,
- structure copies,
- kernel API sinks such as memory mapping, process/thread/object functions, MSR instructions, or device access helpers.

### Step 4: Decode the control code

A small matrix is useful during triage:

| Field | Why it matters |
|---|---|
| DeviceType | Helps group vendor-specific commands and spot unusual values |
| Function | Distinguishes command families |
| Method | Predicts where buffers come from and what must be validated |
| Access | Indicates whether the IOCTL expects read/write access on the handle |

An IOCTL with `FILE_ANY_ACCESS` and `METHOD_NEITHER` is not automatically vulnerable, but it is a strong review priority because reachability and validation pressure are both high.

### Step 5: Recover input and output contracts

Indicators for structure shape:

- comparisons against `InputBufferLength` and `OutputBufferLength`,
- field-sized loads at fixed offsets,
- pointer arithmetic off a base buffer,
- memcpy-like operations,
- MDL creation or mapping,
- conditional logic based on a "command" field inside the user buffer.

A good analyst does not rush to give the structure a definitive name. Instead, record:

- what fields seem required,
- which fields are sizes, addresses, flags, handles, offsets, or identifiers,
- what remains unknown.

### Step 6: Identify buffering model correctly

This matters because many bad reverse engineering notes mix up:

- `AssociatedIrp.SystemBuffer`,
- `MdlAddress`,
- `UserBuffer`,
- `Type3InputBuffer`.

The transfer method predicts which fields are meaningful. Misreading this stage creates false bug reports and wrong primitive classification.

### Step 7: Recognize primitive class safely

A reverse engineer should classify the **capability**, not jump to a payload:

| Primitive class | Typical sink examples | Review priority |
|---|---|---|
| Kernel virtual read/write | memcpy wrapper, `MmCopyMemory`, direct pointer dereference | High |
| Physical memory map/read/write | `MmMapIoSpace` or device-specific physical access | High |
| MSR read/write | `rdmsr` / `wrmsr` helpers | High |
| Port I/O | `READ_PORT_*`, `WRITE_PORT_*` | Medium-high |
| Process/thread/object manipulation | process kill, object reference, handle conversion | High |
| Driver service action | load/unload/configure helper behavior | Medium |

Classification should stay at the primitive level for documentation. That keeps the write-up useful and safe.

### IOCTL documentation template

Use one row or one subsection per IOCTL:

| Field | Notes |
|---|---|
| IOCTL code | Exact value if verified |
| Method | `BUFFERED`, `IN_DIRECT`, `OUT_DIRECT`, `NEITHER` |
| Access | `FILE_ANY_ACCESS`, `FILE_READ_DATA`, `FILE_WRITE_DATA`, both, or unknown |
| Input struct hypothesis | Confirmed fields and unknown fields |
| Output struct hypothesis | Returned status/data and unknown fields |
| Trust boundary | What part is attacker-controlled |
| Bug class | Missing access check, raw pointer trust, arbitrary map, handle confusion, etc. |
| Crash risk | Low, medium, high, unknown |
| Defensive note | What telemetry or preventive control would matter |

### IDA, Ghidra, and WinDbg notes

Static tools:

- IDA:
  good for cross-references, switch recovery, and quick device-name/IOCTL hunting.
- Ghidra:
  useful for decompilation and data-flow review when types are weak or stripped.

Dynamic tools:

- WinDbg:
  useful for confirming dispatch paths, IRP fields, request lengths, and object names.
- ProcMon / WinObj / DeviceTree:
  useful for observing user-to-driver interaction points without needing to understand the full binary first.

## Windows Version Notes

- IOCTL encoding and major function dispatch patterns are stable across Windows versions.
- Structure offsets inside executive objects or kernel types are build-sensitive, but IOCTL handler logic in third-party drivers is typically vendor-version-sensitive rather than OS-version-sensitive.
- Newer Windows versions increase the defensive relevance of driver reachability, blocklists, HVCI, and signed-driver semantics, but do not change the basic reverse engineering workflow.

## Common Mistakes

Checklist for IOCTL reversing:

- Do not assume the visible `\\.\Name` is the only reachable path.
- Do not infer method semantics from `DO_BUFFERED_IO` or `DO_DIRECT_IO` on the device object for IOCTLs.
- Do not label a field as "kernel address" unless the sink confirms that interpretation.
- Do not treat every pointer-looking field as a vulnerability.
- Do not ignore access bits in the IOCTL.
- Do not confuse "can crash" with "is a useful primitive".
- Do not import exploit assumptions from a different vendor driver with a superficially similar interface.

## Debugging / Inspection Notes

Suggested inspection workflow:

```text
strings / import scan
  -> DriverEntry
  -> device and symbolic link creation
  -> MajorFunction table
  -> IRP_MJ_DEVICE_CONTROL dispatcher
  -> per-IOCTL switch arms
  -> sink APIs and primitive classification
```

Useful debugger commands:

- `!drvobj`
- `!devobj`
- `!object`
- `!irp`
- `dt _IRP`
- `dt _IO_STACK_LOCATION`

Lab-safe review matrix:

| Question | Why it matters |
|---|---|
| Can a low-privilege user open the device? | Reachability |
| Which IOCTLs are `METHOD_NEITHER`? | Validation burden |
| Which IOCTLs accept addresses, sizes, or handles? | Primitive discovery |
| Which IOCTLs call memory-management or object APIs? | Capability inference |
| Which IOCTLs appear to map memory or convert handles? | High-risk trust boundary |

## Defensive Angle

A defensive reviewer should document drivers as privileged RPC endpoints. The most important outputs are:

- which callers can reach which IOCTLs,
- which IOCTLs cross into memory, object, or hardware domains,
- whether the driver relies on caller trust instead of explicit authorization,
- which telemetry points exist before the operation reaches kernel state mutation.

This approach scales better than hunting for one exploit pattern at a time.

## Lab-Safe Exercises

1. Choose a test driver and identify the device object name, symbolic link, and dispatch table.
2. Decode three private IOCTL values and classify their transfer methods and access bits.
3. Build an IOCTL documentation table with "unknown" where structure fields are still unverified.
4. Compare one `METHOD_BUFFERED` path and one `METHOD_NEITHER` path and record where validation responsibility changes.

## References / Further Reading

- Microsoft Learn, `Introduction to I/O Control Codes`:
  https://learn.microsoft.com/nb-no/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes
- Microsoft Learn, `IRP_MJ_DEVICE_CONTROL`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control
- Microsoft Learn, `Buffer Descriptions for I/O Control Codes`:
  https://learn.microsoft.com/ja-jp/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes
- Microsoft Learn, `Defining I/O Control Codes`:
  https://learn.microsoft.com/ja-jp/windows-hardware/drivers/kernel/defining-i-o-control-codes
- Microsoft Learn, `Using Neither Buffered Nor Direct I/O`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-neither-buffered-nor-direct-i-o
- Quarkslab, `BYOVD to the next level (part 1) - exploiting a vulnerable driver (CVE-2025-8061)`:
  https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- Anquanke, `Windows nei he qu dong cheng xu jing tai ni xiang gong cheng de fang fa lun`:
  https://www.anquanke.com/post/id/203237
- Anquanke, `Ji yu IOCTLBF kuang jia bian xie de qu dong lou dong wa jue gong ju KDRIVER FUZZER`:
  https://www.anquanke.com/post/id/97245

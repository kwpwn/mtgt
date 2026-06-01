# WDF/KMDF Reverse Engineering Notes

Updated: 2026-05-27

## Purpose

Many modern Windows drivers do not look like classic WDM drivers. Instead of a clear `DriverEntry -> IoCreateDevice -> MajorFunction[IRP_MJ_DEVICE_CONTROL]` flow, they use KMDF/WDF framework objects, queues, callbacks, request objects, and object contexts.

This note teaches how to reverse those drivers without getting lost in the framework layer.

Safety boundary:

- no exploit code,
- no trigger buffers,
- no runnable IOCTL recipes,
- focus on structure, trust boundaries, bug-class reasoning, and defensive triage.

## Why WDF Changes The Reverse Engineering Shape

Classic WDM often exposes a direct dispatch table:

```text
DRIVER_OBJECT
  -> MajorFunction[IRP_MJ_DEVICE_CONTROL]
  -> switch IoControlCode
```

KMDF moves much of that plumbing into framework objects:

```text
DriverEntry
  -> WdfDriverCreate
  -> EvtDriverDeviceAdd
  -> WdfDeviceCreate
  -> WdfIoQueueCreate
  -> EvtIoDeviceControl / EvtIoRead / EvtIoWrite
```

Why this matters:

```text
the dangerous IOCTL logic may not be reachable from MajorFunction assignments;
it may be registered as a callback inside a queue configuration structure
```

If you only search for `IRP_MJ_DEVICE_CONTROL`, you can miss the real command handler.

## Core KMDF Objects

| Object | Meaning for reverse engineering |
|---|---|
| `WDFDRIVER` | Framework driver object created from the original WDM `DRIVER_OBJECT` |
| `WDFDEVICE` | Framework device object, usually created in `EvtDriverDeviceAdd` |
| `WDFQUEUE` | I/O request queue; request handlers are registered here |
| `WDFREQUEST` | Framework wrapper around an I/O request |
| object context | Driver-owned per-object state attached to WDF objects |
| cleanup/destroy callbacks | Lifetime boundaries for WDF objects |

Do not treat WDF handles as raw pointers. In source they are typed handles. In stripped binaries they may look pointer-like, but the semantic owner is the framework.

## Entry Flow

### Step 1: Recognize `WdfDriverCreate`

`WdfDriverCreate` creates the framework driver object and must be called by KMDF drivers from `DriverEntry` before other framework routines. The call usually receives a `WDF_DRIVER_CONFIG` structure.

Reverse engineering target:

```text
find WDF_DRIVER_CONFIG initialization
  -> find EvtDriverDeviceAdd
  -> pivot into device creation
```

Why:

```text
EvtDriverDeviceAdd is often the real root of device and queue setup
```

### Step 2: Find Device Creation

Look for:

- `WdfDeviceCreate`,
- `WdfDeviceInitAssignName`,
- `WdfDeviceCreateSymbolicLink`,
- `WdfDeviceInitAssignSDDLString`,
- `WdfDeviceInitSetDeviceClass`.

Reverse engineering questions:

- Is there a named device?
- Is a DOS symbolic link exposed?
- Is an SDDL string assigned?
- Is access inherited through device class policy?
- Is this a PnP device or a software/control device?

Why:

```text
primitive strength does not matter if the device cannot be opened by the relevant caller
```

### Step 3: Find Queue Creation

`WdfIoQueueCreate` creates and configures request queues. The key is the queue config structure.

Look for fields that receive callbacks:

- `EvtIoDeviceControl`,
- `EvtIoInternalDeviceControl`,
- `EvtIoRead`,
- `EvtIoWrite`,
- `EvtIoDefault`,
- `EvtIoStop`,
- `EvtIoResume`.

Mental model:

```text
WDF_IO_QUEUE_CONFIG
  -> dispatch mode
  -> callback pointers
  -> queue object
```

Why:

```text
the IOCTL dispatcher may be assigned into a local stack structure,
then passed into WdfIoQueueCreate,
with no obvious global dispatch table
```

### Step 4: Recover `EvtIoDeviceControl`

In a KMDF `EvtIoDeviceControl`, the callback commonly receives:

```text
Queue
Request
OutputBufferLength
InputBufferLength
IoControlCode
```

The handler then uses WDF request helpers to retrieve buffers or memory objects. In stripped decompiler output, the parameter order and helper calls are more reliable than guessed variable names.

Important sinks:

- `WdfRequestRetrieveInputBuffer`,
- `WdfRequestRetrieveOutputBuffer`,
- `WdfRequestRetrieveInputMemory`,
- `WdfRequestRetrieveOutputMemory`,
- `WdfRequestRetrieveUnsafeUserInputBuffer`,
- `WdfRequestRetrieveUnsafeUserOutputBuffer`,
- `WdfRequestProbeAndLockUserBufferForRead`,
- `WdfRequestProbeAndLockUserBufferForWrite`,
- `WdfRequestComplete`,
- `WdfRequestCompleteWithInformation`.

Why:

```text
buffer retrieval helper choice tells you who validates addressability,
length, mapping, and lifetime
```

## WDF Dispatch Modes

| Dispatch mode | Reverse engineering impact |
|---|---|
| sequential | Easier ordering; one request at a time per queue |
| parallel | Race and shared-state analysis matter more |
| manual | Requests may be stored and completed later |

Why this matters:

```text
a safe-looking length check in dispatch may not protect a buffer used later by a worker,
timer, or completion path
```

## Object Context Pattern

WDF drivers often attach custom context to a device, queue, file object, interrupt, or request.

Look for:

- `WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE`,
- context getter wrappers,
- repeated fixed offsets from a returned context pointer,
- cleanup callbacks touching the same fields.

Common context contents:

- device extension state,
- hardware register mappings,
- symbolic state flags,
- queue references,
- DMA/MDL state,
- cached process or file handles,
- callback registration handles,
- locks and work items.

Why:

```text
WDF context replaces many WDM device-extension patterns;
if you miss context layout, you miss the state machine
```

## Dangerous KMDF Research Patterns

### Pattern 1: Unsafe User Buffer Retrieval

Reasoning:

```text
unsafe retrieval means the driver is taking responsibility for validation and lifetime
```

Review questions:

- Does the driver probe and lock the buffer?
- Does it use SEH around user memory?
- Is the buffer used only in caller context?
- Is the pointer stored for later use?
- Can the caller change the pointed data after validation?

Failure mode:

```text
stale user pointer
  -> later worker/callback use
  -> crash, info leak, or corruption depending on sink
```

### Pattern 2: Manual Queue Stores Requests

Reasoning:

```text
request lifetime becomes a driver state-machine problem
```

Review questions:

- Who owns the request after it is forwarded?
- Can it be canceled while a worker uses its context?
- Is completion synchronized with cleanup/unload?
- Are references taken on framework objects?

Failure mode:

```text
cancel/unload race
  -> use-after-free of request context or device state
```

### Pattern 3: WDF Wrapper Around Raw Hardware Access

Reasoning:

```text
WDF makes I/O plumbing safer, but it does not make raw MSR, MMIO, port I/O,
or physical mapping semantics safe
```

Review questions:

- Which callback reaches `MmMapIoSpace`, MSR helpers, port I/O, or PCI config helpers?
- Does the driver validate ranges against real hardware BARs?
- Does it allow arbitrary physical addresses?
- Does a user buffer choose size, offset, or operation type?

Failure mode:

```text
framework-safe request delivery
  -> unsafe privileged hardware operation
```

### Pattern 4: File Object Context As Authorization

Some drivers set state at create/open time and later trust it in IOCTL handlers.

Questions:

- Is `EvtDeviceFileCreate` used?
- Is caller identity checked once and cached?
- Can handles be duplicated into another process?
- Does the driver bind authorization to the original caller, token, or just the file object?
- Are cleanup paths correct?

Why:

```text
auth-at-open may fail if the security property being checked can change,
or if a trusted process becomes a handle broker
```

## WDF Versus WDM Bug-Class Translation

| WDM concept | WDF equivalent |
|---|---|
| `DriverEntry` initializes dispatch table | `DriverEntry` calls `WdfDriverCreate` |
| `AddDevice` creates device object | `EvtDriverDeviceAdd` creates `WDFDEVICE` |
| `IRP_MJ_DEVICE_CONTROL` dispatch | `EvtIoDeviceControl` callback |
| device extension | WDF object context |
| manual IRP completion | `WdfRequestComplete*` |
| cancel routine | queue/request cancellation callbacks |
| unload cleanup | object cleanup/destroy callbacks |

Do not force WDF back into WDM mentally. Map the semantic role, not the exact structure.

## Reverse Engineering Checklist

Collect:

```text
driver type:
WDF version:
DriverEntry:
EvtDriverDeviceAdd:
device name:
symbolic link:
SDDL/device class:
queues:
queue dispatch mode:
EvtIoDeviceControl:
buffer retrieval helpers:
request forwarding:
object contexts:
cleanup callbacks:
dangerous sinks:
primitive class:
reachability:
failure modes:
```

## Common Mistakes

- Searching only for `MajorFunction`.
- Treating `WdfIoQueueCreate` as uninteresting framework noise.
- Ignoring `EvtDeviceFileCreate` because it is not the IOCTL handler.
- Missing manual queues and async request ownership.
- Trusting decompiler names for WDF handles and context pointers.
- Assuming WDF means memory-safe.
- Ignoring SDDL and device-class policy.

## Defensive Angle

For defensive review, WDF drivers should still be documented as privileged RPC endpoints:

```text
caller
  -> file object/device access
  -> queue callback
  -> buffer helper
  -> privileged sink
  -> completion/status
```

Detection and hardening ideas:

- inventory WDF drivers with user-visible device links,
- flag WDF drivers exposing hardware primitives to broad users,
- baseline expected controller processes,
- correlate driver load with new device object access,
- use Driver Verifier and KMDF Verifier in test labs,
- review WDF object cleanup paths after crashes.

## Study Questions

1. Why can a KMDF driver's IOCTL handler be invisible if you only inspect `DRIVER_OBJECT->MajorFunction`?
2. What does the queue dispatch mode tell you about race analysis?
3. Why is `WdfRequestRetrieveUnsafeUserInputBuffer` a review priority?
4. How can file-object context accidentally become a weak authorization cache?
5. Why does WDF reduce framework misuse but not eliminate dangerous privileged operations?

## References

- Microsoft Learn, `WdfDriverCreate`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfdriver/nf-wdfdriver-wdfdrivercreate
- Microsoft Learn, `WdfDeviceCreate`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfdevice/nf-wdfdevice-wdfdevicecreate
- Microsoft Learn, `WdfIoQueueCreate`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdfio/nf-wdfio-wdfioqueuecreate
- Microsoft Learn, `Request Handlers`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/request-handlers
- Microsoft Learn, `Using KMDF Verifier`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-kmdf-verifier


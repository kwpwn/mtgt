# Crash Dump Driver Triage

Updated: 2026-05-27

## Purpose

This document maps common driver research crashes to likely bug classes. It is for debugging, exploitability triage, and defensive analysis. It does not contain exploit steps.

Core question:

```text
What invariant failed before the bugcheck?
```

## Triage Flow

Use this flow:

```text
bugcheck code
  -> faulting module
  -> faulting instruction family
  -> IRQL/context
  -> object/buffer lifetime
  -> recent driver load or IOCTL
  -> likely bug class
```

## First Questions

Ask:

- Which driver is on the stack?
- Is the faulting address canonical?
- Is it user, kernel, freed pool, or invalid?
- What IRQL was active?
- Was Driver Verifier enabled?
- Did the crash happen during dispatch, completion, cancel, callback, unload, or worker execution?
- Was a vulnerable driver loaded shortly before crash?

## Bugcheck Map

| Bugcheck | Common driver research meaning |
|---|---|
| `0xD1 DRIVER_IRQL_NOT_LESS_OR_EQUAL` | invalid memory access at elevated IRQL, stale pointer, pageable access too high |
| `0xA IRQL_NOT_LESS_OR_EQUAL` | similar IRQL/pointer problem, often bad dereference |
| `0x50 PAGE_FAULT_IN_NONPAGED_AREA` | invalid kernel pointer, freed memory, wrong address |
| `0x3B SYSTEM_SERVICE_EXCEPTION` | exception in system service path, bad pointer or user/kernel boundary issue |
| `0x7E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED` | worker/thread crash, async path bug |
| `0xC4 DRIVER_VERIFIER_DETECTED_VIOLATION` | verifier caught contract violation |
| `0xC1 SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION` | overrun/underrun near pool boundary |
| `0xC2 BAD_POOL_CALLER` | bad pool allocation/free contract |
| `0xCE DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS` | unload with active work/IRPs/timers/callbacks |

## Crash Context Patterns

### Dispatch Path Crash

```text
DeviceIoControl path
  -> dispatch routine
  -> buffer parse
  -> crash
```

Likely classes:

- malformed buffer handling,
- wrong IOCTL method assumption,
- length confusion,
- direct raw pointer trust,
- invalid address parameter.

What to inspect:

- transfer method,
- input/output sizes,
- branch taken in IOCTL switch,
- access bits,
- caller mode.

### Completion / Cancel Crash

```text
IRP queued
  -> completion or cancel
  -> crash
```

Likely classes:

- double completion,
- stale context,
- wrong owner cleanup,
- MDL lifetime bug,
- cancel routine race.

What to inspect:

- pending IRP ownership,
- cancel spin lock use,
- completion routine,
- queued work item state,
- reference counts.

### Worker Thread Crash

```text
dispatch stores context
  -> worker uses later
  -> crash
```

Likely classes:

- stale user pointer,
- METHOD_NEITHER misuse,
- freed request context,
- unloaded driver code,
- pageable memory at wrong IRQL.

### Callback Crash

```text
kernel event
  -> registered callback
  -> crash
```

Likely classes:

- callback context freed,
- unregister race,
- callback pointer/state corruption,
- product unload mismatch,
- tamper attempt.

### Unload Crash

```text
driver unload
  -> pending work remains
  -> later call into freed code/data
```

Likely classes:

- active timer,
- active work item,
- callback not unregistered,
- device object still referenced,
- IRPs not drained.

## Faulting Address Reasoning

| Address shape | Meaning |
|---|---|
| near zero | null dereference / small offset |
| user-range address in kernel stack | raw user pointer trust |
| noncanonical address | corrupted pointer or arithmetic |
| pool-looking address | stale/freed object or bad offset |
| executable module address | callback/function pointer path |
| physical-looking value used as VA | physical/virtual confusion |

## Driver Verifier Signal

Driver Verifier turns latent bugs into clearer failures:

- pool overrun,
- IRQL misuse,
- I/O verification failure,
- deadlock risk,
- DMA/MDL misuse,
- unload with pending operations.

Why it matters:

```text
ordinary crash may say "bad pointer";
verifier often says which contract was violated
```

Reference:

- Microsoft Driver Verifier:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier

## BYOVD-Specific Crash Questions

If a BYOVD driver is involved, ask:

- Did a physical write target the wrong PFN?
- Did a virtual write target the wrong build offset?
- Did MSR write corrupt CPU state?
- Did callback/security-state tamper trigger PatchGuard or product self-defense?
- Was HVCI/WDAC/blocklist state changed before crash?
- Did a user-mode controller crash or exit before cleanup?

## Triage Note Template

```text
Crash dump:
Windows build:
HVCI state:
Driver:
Driver hash:
Bugcheck:
Faulting instruction:
Faulting address:
IRQL:
Thread/process:
Recent driver load:
Recent device open:
Likely bug class:
Primitive suspected:
Why:
What would confirm:
Defensive signal:
```

## Study Questions

- Did the crash happen at use, cleanup, callback, or unload?
- Is the pointer bad because the address is wrong or because lifetime ended?
- Does the crash point to IOCTL parsing or async ownership?
- Would Driver Verifier make the contract violation clearer?
- Is this a reliability bug, an exploitable primitive, or both?

## Summary

Crash triage is invariant triage:

```text
pointer validity
buffer ownership
IRQL legality
object lifetime
cleanup ordering
```

Find which invariant broke before deciding whether the crash is exploitable.

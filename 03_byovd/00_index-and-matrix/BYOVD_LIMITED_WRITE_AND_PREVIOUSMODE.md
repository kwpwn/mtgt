# BYOVD Limited Write and `PreviousMode`-Style Primitives

Updated: 2026-05-27

## Technique Summary

Not every useful BYOVD primitive is full arbitrary read/write. Some drivers expose only a narrow mutation:

```text
decrement one byte
OR/AND/XOR a field
write fixed-size value
write only to constrained address class
copy only under strict conditions
```

These can still matter if the target is a semantic kernel field.

```text
small write
  -> changes field interpretation
  -> legitimate kernel code makes different security decision
```

## Representative Drivers / Families

| Driver / family | Primitive idea |
|---|---|
| `AsIO3.sys` style research | constrained decrement / limited write used in `PreviousMode` reasoning |
| `wfshbr64.sys` style LOLDrivers entry | process protection and signature field mutation through bitwise operation |
| arbitrary write drivers with constraints | fixed-width or address-constrained writes |

Local docs:

- `03_byovd/04_limited-primitives/ASIO3_PREVIOUSMODE_DEEP_DIVE.md`
- `docs/kernel-research/previousmode-research-notes.md`

## Required Assumptions

Limited primitive exploitation needs:

- precise knowledge of what the primitive can change,
- a semantic field matching that change,
- build-correct offset,
- target object address,
- a call path that consumes the modified field,
- a way to avoid or recover from wrong-target writes.

The hard part is not size. The hard part is meaning.

## Why This Works

Windows has many small fields that carry policy meaning:

- mode bytes,
- protection levels,
- signature levels,
- flags,
- granted-access bits,
- reference bits,
- packed pointer tags,
- object state values.

A one-byte or one-bit change can alter future behavior:

```text
field before: user-originating request
field after: kernel-trusted request
```

or:

```text
field before: protected process
field after: less protected process
```

That is why limited writes are sometimes more useful than they look.

## The `PreviousMode` Idea

`PreviousMode` / requestor-mode state influences whether some kernel paths treat a request as user mode or kernel mode.

Conceptually:

```text
UserMode
  -> probe user buffers
  -> enforce user pointer restrictions
  -> validate handle/user access more strictly

KernelMode
  -> trust caller more
  -> skip selected probes or restrictions
```

If a thread/request is misclassified, later native API behavior can change.

## Why `PreviousMode` Is Attractive

Because it can transform a tiny primitive into an API-mediated primitive:

```text
limited write changes mode-like field
  -> legitimate Nt/Zw path treats caller differently
  -> API performs read/write/copy/access on caller's behalf
```

This can be cleaner than trying to build a full kernel arbitrary write directly.

## Why It Is Fragile

It depends on:

- exact `_KTHREAD` or request structure layout,
- exact Windows build,
- exact API behavior,
- timing,
- whether the target thread is the one making the next call,
- restore correctness,
- whether modern checks ignore or revalidate the field.

Question:

```text
Which future kernel routine consumes the modified state?
```

If you cannot answer that, the primitive is not understood.

## Limited Primitive Reasoning Flow

### Step 1: Define the primitive exactly

Bad:

```text
driver has arbitrary write
```

Good:

```text
driver can decrement one byte at a caller-influenced kernel address
```

or:

```text
driver can OR a caller-chosen bitmask into a process protection field
```

### Step 2: Match primitive shape to field shape

Questions:

- Is the target field byte-sized, bitfield, pointer, or integer?
- Does the primitive move the field in the useful direction?
- Is the field packed with adjacent state?
- Is there a legal value transition?

### Step 3: Prove semantic impact

Question:

```text
What future decision changes because this field changed?
```

Examples:

- native API probing decision,
- process protection decision,
- signature policy check,
- object access decision,
- callback dispatch decision.

### Step 4: Plan validation and restore

Even in lab reasoning, ask:

- What was the original value?
- Can it be read back?
- Can it be restored?
- What if the thread exits?
- What if the object is freed?

## What It Can Do

Depending on field:

- enable API-mediated kernel memory access,
- downgrade protection semantics,
- change signature/protection levels,
- alter access checks,
- create temporary object inconsistency,
- crash the machine if wrong.

## What It Cannot Do Automatically

A limited primitive does not automatically give:

- arbitrary kernel R/W,
- stable code execution,
- cross-build reliability,
- safe restore,
- stealth.

The value comes from matching the primitive to the field.

## Detection Angle

Detection is difficult because the write may be small, but correlation helps:

- vulnerable driver load,
- unusual IOCTL burst,
- native API behavior inconsistent with caller mode,
- process protection state changes,
- sudden privilege/protection changes after hardware driver load,
- crash dumps with small-field corruption,
- EDR alert about vulnerable driver followed by suspicious object access.

## Failure Modes

- wrong field offset,
- wrong thread,
- field no longer consumed by target API,
- adjacent packed field corrupted,
- value transition invalid,
- object freed,
- restore missed,
- PatchGuard/KDP protects target data,
- telemetry catches impossible state.

## Study Questions

- What exactly can the primitive modify?
- Is the target field the same size and semantic type?
- Which kernel code path reads the field later?
- Why does changing the field affect security?
- How build-sensitive is the field?
- What is the smallest observation that proves the effect?
- What would prove the technique failed?

## Summary

Limited write primitives are about semantic leverage:

```text
small mutation
  -> important field
  -> future kernel decision changes
```

The question is never just "can I write?" It is:

```text
does this tiny write change something Windows will later trust?
```

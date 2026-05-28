# BYOVD Primitive Bridge Reasoning

Updated: 2026-05-27

## Purpose

This note explains how to reason from a BYOVD primitive to a realistic research objective.

It is written for offensive research reading, especially when a public blog says:

```text
this driver gives arbitrary R/W
```

The missing question is:

```text
what bridge turns that primitive into the objective?
```

No runnable exploit chains or trigger buffers are included.

For code-shaped toy models of the same ideas, read:

- `docs/kernel-research/primitive-pseudocode-sketchbook.md`

## Primitive Versus Bridge

Primitive:

```text
what the driver lets you do
```

Bridge:

```text
the extra reasoning needed to make that useful
```

Objective:

```text
the research outcome being demonstrated
```

Example shape:

```text
primitive: physical memory write
bridge: translate target kernel virtual address to physical frame
objective: modify trusted kernel data
```

## Bridge Matrix

| Primitive | Common bridge | Main risk |
|---|---|---|
| physical read | VA-to-PA translation, scan validation | wrong frame or false positive |
| physical write | page-table walk, target object validation | corrupting wrong PFN |
| virtual read | target address discovery | info leak without useful target |
| virtual write | object/field discovery | wrong offset or stale object |
| virtual R/W | data-only target selection | mitigation/lifetime mismatch |
| memcpy primitive | direction and range reasoning | bad direction or length crash |
| MSR write | register-specific semantic model | CPU/virtualization fragility |
| port I/O | device-specific semantic model | hardware dependency |
| MMIO write | BAR/range validation | device corruption or no effect |
| limited write | semantic field selection | cannot shape target value |
| PreviousMode-like primitive | thread-context reasoning | wrong thread or timing |
| callback state tamper | list/handle/integrity reasoning | crash or delayed integrity failure |

## Physical Memory Bridge

Primitive gives:

```text
read/write at physical address or mapped physical range
```

Objective usually needs:

```text
write to a kernel virtual object or kernel image/global data
```

Bridge:

```text
kernel virtual target
  -> address-space context
  -> page table translation
  -> physical page and offset
  -> primitive operation
```

Vì sao bridge is needed:

```text
Windows code and objects are normally reasoned about as virtual addresses;
the driver primitive may only understand physical addresses
```

Failure questions:

- Is the target address valid in the chosen address space?
- Is the page present?
- Is it a large page?
- Is the target in session/process-specific address space?
- Does the primitive handle a write that crosses page boundary?
- Is readback available?

Good write-up sentence:

```text
The physical primitive is powerful, but it is not self-orienting; the exploitability depends on a reliable translation and verification path.
```

## Virtual Kernel R/W Bridge

Primitive gives:

```text
read/write at kernel virtual addresses
```

Objective usually needs:

```text
locate and modify a semantically meaningful object or state field
```

Bridge:

```text
kernel base / object pointer / symbol
  -> target field
  -> validation read
  -> minimal write
  -> state consumer observes change
```

Vì sao bridge is needed:

```text
virtual R/W gives access, not meaning;
meaning comes from object layout and kernel behavior
```

Failure questions:

- Is the target object the current one or a stale one?
- Is the field offset valid on this build?
- Is the field protected, mirrored, or recomputed?
- Does the consumer read the field after the write?
- Is cleanup needed?

Good write-up sentence:

```text
The primitive removes the memory access problem, but not the object-model problem.
```

## Kernel Copy Primitive Bridge

Primitive gives:

```text
driver performs a privileged copy operation
```

Questions:

- Can user input choose source?
- Can user input choose destination?
- Can user input choose length?
- Is direction fixed or selectable?
- Are source and destination both kernel-capable?
- Can copy faults be caught?

Bridge:

```text
copy capability
  -> read/write abstraction
  -> object discovery
  -> semantic state change
```

Failure questions:

- Does direction allow only leak, only write, or both?
- Does the driver clamp length?
- Is copy size too small for target field?
- Does invalid address crash the system?

Good write-up sentence:

```text
A memcpy primitive becomes arbitrary R/W only if direction, address, and length are sufficiently caller-controlled.
```

## MSR Bridge

Primitive gives:

```text
read/write model-specific registers
```

Objective needs:

```text
register with useful OS-visible semantics
```

Bridge:

```text
MSR index
  -> CPU generation meaning
  -> per-core behavior
  -> Windows consumer behavior
  -> safe restore model
```

Vì sao fragile:

```text
MSR effects are highly specific to CPU, virtualization, core context, and Windows expectations
```

Failure questions:

- Is the target MSR valid on this CPU?
- Is it intercepted by hypervisor/VBS?
- Is the value per-core?
- Does a context switch change relevance?
- Does wrong value cause immediate crash?

Good write-up sentence:

```text
MSR access is a primitive; the exploitability comes from knowing the register semantics and execution context.
```

## Port I/O, PCI, And MMIO Bridge

Primitive gives:

```text
raw hardware or device register access
```

Objective needs:

```text
device-specific side effect with OS security relevance
```

Bridge:

```text
port/BAR/config range
  -> device model
  -> valid register
  -> side effect
  -> OS-visible consequence
```

Failure questions:

- Is the hardware present?
- Is the range really device-owned?
- Is the register write destructive?
- Is the effect visible to Windows?
- Is the operation blocked/intercepted under virtualization?

Good write-up sentence:

```text
Raw hardware access is broad capability, but useful impact is usually device-specific.
```

## Limited Write Bridge

Primitive gives:

```text
partial or constrained mutation
```

Objective needs:

```text
target field whose useful state can be reached under that constraint
```

Bridge:

```text
constraint
  -> candidate semantic field
  -> value domain
  -> timing/context
  -> verification
```

Good target properties:

- small field,
- boolean-like meaning,
- bitmask,
- refcount/counter,
- mode/trust enum,
- access mask,
- status flag.

Failure questions:

- Can the primitive set the needed value exactly?
- Can it hit the field alignment?
- Is the field read after modification?
- Is the field restored or recomputed?
- Does changing it break another invariant?

Good write-up sentence:

```text
Limited writes are useful only when the target field's semantics match the write constraint.
```

## PreviousMode-Style Bridge

Primitive gives:

```text
ability to affect caller-mode trust semantics in a narrow context
```

Objective needs:

```text
kernel path that changes validation behavior based on that mode
```

Bridge:

```text
current thread context
  -> mode/trust field
  -> system service behavior
  -> controlled follow-up operation
```

Failure questions:

- Is the correct thread affected?
- Is timing correct?
- Is the field restored?
- Does the follow-up path consult the field?
- Does the system call path differ by Windows build?

Good write-up sentence:

```text
The primitive is not a general write; it is a context-sensitive trust-state change.
```

## Callback/Security-State Bridge

Primitive gives:

```text
ability to modify security-observer or policy-adjacent state
```

Objective needs:

```text
change visibility or policy behavior without breaking integrity assumptions
```

Bridge:

```text
state location
  -> registration/list/cache semantics
  -> product or kernel consumer
  -> consistency model
  -> restore or tolerate drift
```

Failure questions:

- Is there a list entry plus registration handle?
- Is there a count/cache/index that must stay consistent?
- Does PatchGuard monitor the structure?
- Does product self-defense recreate state?
- Does the operation affect all sensors or only one view?

Good write-up sentence:

```text
Security-state tamper is not invisibility; it is pressure against one visibility layer with consistency risk.
```

## Choosing The Best Bridge

Use this decision order:

```text
1. Is there readback?
2. Can targets be discovered symbolically?
3. Is the chosen target stable across builds?
4. Is the field consumed after the write?
5. Is cleanup possible?
6. Does mitigation monitor that state?
7. Is there a lower-risk objective with the same primitive?
```

Do not force every primitive into the same objective. The best bridge is the one that matches the primitive's constraints.

## Study Questions

1. What does the primitive directly give?
2. What does the objective require that the primitive does not give?
3. Which bridge supplies the missing part?
4. Which part is most version-sensitive?
5. Which part is most likely to crash?
6. Which part can silently fail?
7. What would prove the bridge worked?

## Related Docs

- `BYOVD_NON_TERMINATE_PRIMITIVES_TAXONOMY.md`
- `BYOVD_PHYSICAL_MEMORY_PRIMITIVES_DEEP_DIVE.md`
- `BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`
- `BYOVD_MSR_PORT_MMIO_HARDWARE_PRIMITIVES.md`
- `BYOVD_LIMITED_WRITE_AND_PREVIOUSMODE.md`
- `docs/kernel-research/offensive-driver-exploitability-map.md`
- `docs/kernel-research/public-poc-reading-and-annotation-template.md`

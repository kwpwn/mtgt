# BYOVD Process-Creation Callback Tamper: S12Deff Case Study

Updated: 2026-05-28

## Category

This belongs under:

```text
BYOVD
  -> virtual kernel read/write or physical-to-virtual write bridge
  -> callback/security-state tamper
  -> process creation telemetry degradation
```

It is not a separate privilege-escalation class by itself. It is a post-primitive
technique: the operator already has a kernel write primitive, then uses that
primitive to change the callback state that security drivers rely on.

Related local docs:

- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`
- `docs/kernel-research/callback-surfaces.md`
- `docs/kernel-research/runtime-pdb-symbol-resolution.md`
- `docs/kernel-research/kernel-object-layout-drift.md`
- `docs/detection-and-mitigation/driver-evasion-pressure-map.md`

Public source context:

- S12Deff, [Overwriting Process Creation Kernel Callbacks](https://medium.com/@s12deff/overwriting-process-creation-kernel-callbacks-8c9f73980eb7)
- Microsoft, [PsSetCreateProcessNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine)
- Microsoft, [PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- Microsoft, [PsSetCreateThreadNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine)
- Microsoft, [PsSetLoadImageNotifyRoutine](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine)

This note intentionally does not reproduce offsets, runnable code, driver trigger
buffers, callback replacement values, or pointer transformation recipes. The goal
is to preserve the learning model: primitive, invariant, bridge, failure mode.

## One-Sentence Model

Process callback tamper is:

```text
kernel write primitive
  -> mutate process-notification registration state
  -> selected observer is no longer invoked as expected
  -> process creation visibility becomes inconsistent
```

The important word is "inconsistent." This technique does not make the event
impossible to observe. It removes or distorts one observer path.

## What Windows Provides

Windows exposes process-notification callbacks so kernel drivers can be told when
processes are created or exit. Security drivers use this for telemetry and policy.
The public APIs are registration interfaces. They let a driver say:

```text
I own this callback routine.
Call me when a process is created or exits.
I will unregister before unload.
```

That gives Windows a contract:

- registered callback routines are stored in kernel-owned state,
- the OS invokes those routines when the event occurs,
- removal should happen through the official unregister path,
- in-flight callbacks and unload paths need careful synchronization.

The S12Deff process-callback article focuses on violating that contract from the
outside using a vulnerable-driver read/write primitive.

## Why Security Products Care

EDR and AV drivers often need early process visibility because process creation is
where many later decisions start:

- parent/child relationship,
- image path,
- command-line collection,
- token and protection-level context,
- process lineage,
- remote thread and injection correlation,
- first chance to attach user-mode or kernel-side tracking state.

If the process callback path is weakened, downstream analytics may still see the
process later, but they can lose the clean "birth event." That matters because many
correlations are easiest at creation time.

Example reasoning:

```text
process starts
  -> process callback records baseline
  -> thread/image/network/file events are later attached to that baseline
```

If the baseline is missing, later events become harder to explain:

```text
thread exists
  -> image loaded
  -> file touched
  -> network opened
  -> but no trusted process-birth record exists
```

That is why process callback tamper is attractive as a telemetry-evasion idea.

## What Primitive Is Required

The technique requires at least:

- kernel read to identify the relevant registration state and owners,
- kernel write to alter callback-related state,
- module inventory knowledge to classify callback owner ranges,
- build-aware structure knowledge,
- timing control so the state is not left corrupted long enough to crash or be
  repaired.

A pure process-termination primitive is not enough. A file-delete primitive is not
enough. A service-control primitive is not enough. The essential capability is
write access to kernel-resident callback state or to an object that will influence
how the callback dispatch path behaves.

## Why The Primitive Alone Is Not The Impact

A BYOVD write primitive only answers:

```text
Can I write bytes into kernel-addressable memory?
```

It does not answer:

```text
Which bytes are semantically meaningful?
Which version am I on?
Who owns this callback?
Will the dispatcher accept the modified state?
Will the product notice?
Will PatchGuard or another integrity mechanism notice later?
What independent telemetry still exists?
```

This is the core lesson. Exploit literacy is not "I can write." Exploit literacy is
knowing which invariant the write breaks and what other invariants keep the system
alive.

## The Broken Invariant

The invariant is:

```text
security driver is loaded and healthy
  -> its registered process callback remains registered
  -> callback target remains inside the expected driver image
  -> process creation dispatch invokes it
```

Callback tamper breaks one or more of those assumptions.

Common broken-invariant forms:

| Form | Meaning | Result |
|---|---|---|
| Missing observer | Registration state no longer reaches product callback | Product misses process birth path |
| Redirected observer | Registration state points somewhere else | Dispatch does not execute original callback |
| Corrupt observer | Registration metadata is malformed | Crash, bugcheck, or silent callback failure |
| Desynchronized observer | Product thinks it is registered, kernel state disagrees | Health/telemetry contradiction |

The interesting part is not the byte write. The interesting part is the
contradiction between product state and kernel dispatch state.

## Technique Path At A Safe Level

At a conceptual level:

```text
1. Establish kernel read/write primitive.
2. Build a view of loaded kernel images.
3. Build a view of process-notification callback ownership.
4. Choose which observer state is being studied.
5. Modify the registration state in a reversible lab-controlled way.
6. Generate a process creation event.
7. Compare callback-driven telemetry against independent views.
8. Restore and validate consistency.
```

This is intentionally not an implementation recipe. It is a reasoning checklist.

The dangerous jump is between step 3 and step 5. That jump requires build-specific
knowledge about private kernel state. Hardcoding that knowledge is fragile because
Windows internal layouts move, symbol availability changes, and security products
add their own integrity checks.

## Why "Enumerate" And "Overwrite" Are Different

S12Deff's article chain separates two mental models:

```text
enumeration
  -> read callback state
  -> map callback target to owning module
  -> answer "who watches process creation?"
```

versus:

```text
overwrite
  -> write callback-related state
  -> alter dispatch behavior
  -> answer "can I stop or distort this observer?"
```

Enumeration is an observation technique. It can still be sensitive, but it is
conceptually a read-side inventory. Overwrite is state mutation. That crosses into
rootkit-style reliability problems:

- wrong target corrupts kernel state,
- wrong owner classification affects system drivers, not only security drivers,
- wrong timing can collide with callback execution,
- wrong restoration can make the system less stable than leaving it modified.

## Why A "Harmless Replacement" Is Still Not Safe

Some public writeups describe replacing a callback target with a function that
appears harmless. The reasoning is usually:

```text
if the dispatcher calls something valid,
then the system may not crash immediately
```

That is incomplete. A callback has a signature, calling convention, expected side
effects, and context assumptions. A random valid kernel routine is not equivalent
to a valid callback routine.

Why this can fail:

- parameter mismatch can corrupt registers or stack assumptions,
- return value semantics can be wrong,
- routine may not tolerate the callback context,
- product state is not updated even if the kernel call returns,
- another callback may depend on earlier callback side effects,
- a future Windows build may change validation around the call site.

So the real model is:

```text
valid address != valid callback
valid return != semantically correct event handling
no immediate crash != stable technique
```

## Why Restore Logic Is Not A Magic PatchGuard Bypass

Public demonstrations often include "save and restore" logic. That idea tries to
reduce the lifetime of tampered kernel state.

The logic is understandable:

```text
save original state
  -> modify briefly
  -> perform study action
  -> restore original state
```

But the reliability story is much harder:

- an integrity scan can happen while state is modified,
- a callback can execute during the modified window,
- product health checks can run during the modified window,
- restoration can race with legitimate unregister/re-register,
- the saved state can be stale if the owner unloads or updates,
- a crash dump can preserve the tampered interval.

The question is not "did I restore?" The question is:

```text
Who could have observed the interval before restoration?
```

## Relationship To PatchGuard

PatchGuard is one of the pressures around persistent kernel tamper. It is not the
only pressure. Product self-protection, KCFG, HVCI, kernel CFG expectations, and
plain memory corruption can all matter.

Reason about PatchGuard like this:

```text
global kernel control or registration state
  -> long-lived modification
  -> higher delayed bugcheck risk
```

Short-lived modification lowers one risk but raises timing complexity. It also
does not solve product-specific self-checking.

## Relationship To HVCI And KCFG

HVCI and KCFG change which evasion paths are attractive:

- injecting or executing unsigned kernel code becomes harder,
- arbitrary data writes may still exist if a signed vulnerable driver exposes them,
- direct function-pointer patching becomes more fragile,
- data-structure unlinking or state desynchronization becomes more attractive.

That is why modern BYOVD research often moves from "run my kernel payload" toward
"make a small semantic state change."

The process-callback tamper case is a state-change idea. It does not require adding
new executable kernel code. It requires carefully mutating existing registration
state.

## Comparison With Neighbor Techniques

| Technique | Surface | Primitive needed | What changes | Main failure mode |
|---|---|---|---|---|
| Process callback enumeration | Process notify storage | Kernel read | Visibility inventory | Wrong owner or stale layout |
| Process callback overwrite | Process notify storage | Kernel write | Process-birth observer path | Crash or integrity contradiction |
| Thread callback tamper | Thread notify storage | Kernel write | Remote-thread visibility | Still visible through ETW TI or user-mode traces |
| Image-load callback tamper | Image notify storage | Kernel write | DLL/EXE load visibility | Loader still leaves other evidence |
| Object callback tamper | Object Manager callback lists | Kernel write | Handle access mediation | Access still denied elsewhere |
| Minifilter unlinking | Filter Manager state | Kernel write | File I/O observer path | Filter stack inconsistency |
| WFP callout tamper | WFP callout state | Kernel write | Network observer path | Classify path crash or fallback telemetry |
| ETW TI tamper | Kernel ETW provider state | Kernel write | Kernel-native behavior events | Version drift and system-wide anomaly |

The shared idea is:

```text
security visibility is a graph, not one callback
```

Removing one edge changes the graph. It does not erase the graph.

## What This Can Do In A Lab

Studied safely, this technique can teach:

- how process callback registration becomes security telemetry,
- why driver load state and callback state should agree,
- why build-specific private offsets are fragile,
- why "arbitrary write" needs an object model,
- how one telemetry family can be missing while others remain alive,
- why kernel evasion often becomes state consistency research.

## What It Does Not Prove

It does not prove:

- that all process telemetry is gone,
- that all EDRs are blind,
- that the technique works across Windows builds,
- that product self-protection is bypassed,
- that PatchGuard cannot detect the change,
- that replacement with a valid kernel address is semantically correct,
- that process creation will be invisible to ETW, audit policy, user-mode sensors,
  handle tracing, file/network telemetry, or memory scanners.

The strongest conclusion is narrower:

```text
given kernel write and correct private-state knowledge,
one callback dispatch path may be weakened.
```

## Failure Modes

### Wrong Build

Private kernel state is not a stable public ABI. A hardcoded layout or offset can
work on one build and corrupt a different build.

Why:

```text
Windows exports the registration API,
not the private storage layout.
```

### Wrong Owner

The callback owner may be misclassified. A system driver callback can be altered
instead of a third-party security callback.

Why:

```text
address range ownership is an inference,
not a proof of callback semantics.
```

### Wrong Context

A replacement function can be callable but not callback-compatible.

Why:

```text
function address validity does not imply callback-contract validity.
```

### Race With Dispatch

The callback can be modified while process creation is in flight.

Why:

```text
callbacks are live concurrency surfaces,
not passive configuration values.
```

### Product Repair

The security product may periodically validate and re-register state.

Why:

```text
product health state can have its own watchdog logic.
```

### Partial Blindness

Only one sensor path changes.

Why:

```text
process creation can also influence ETW, audit, handles, image loads, memory,
file I/O, network I/O, and product-private state.
```

## How To Read The S12Deff Article Productively

Read it as a sequence of questions, not as code to copy.

### Question 1: What is the input primitive?

Answer:

```text
kernel read/write supplied by a vulnerable signed driver
```

If that primitive is absent, the callback idea is not reachable.

### Question 2: What is the target object?

Answer:

```text
kernel-maintained process-notification registration state
```

This is private implementation state, not the public registration API contract.

### Question 3: What invariant is broken?

Answer:

```text
registered security callback remains the callback invoked by process dispatch
```

### Question 4: What is the bridge?

Answer:

```text
read-side ownership map
  -> write-side state mutation
  -> process creation event used as observable effect
```

### Question 5: What can still see the action?

Answer:

```text
other callback families,
ETW providers,
file and image telemetry,
handle telemetry,
network telemetry,
product-private health checks,
crash and tamper logs
```

### Question 6: What is the strongest version of the technique?

Answer:

Not "write whatever." The stronger version is:

```text
minimal reversible state change
  -> correct build
  -> correct owner
  -> short lifetime
  -> independent verification
  -> clean recovery
```

Even then, it remains fragile.

## Study Questions

1. Why does a process creation callback give better context than a later module
   enumeration?
2. Why is a valid kernel function pointer not automatically a valid callback
   replacement?
3. What data would you need to distinguish a security vendor callback from a
   system callback without relying on a name string alone?
4. Which Windows build assumptions are hidden inside a callback-tamper PoC?
5. How can callback state be inconsistent with service/process health state?
6. Why can HVCI make data-only tamper more attractive while still making the whole
   chain less reliable?
7. What independent telemetry families can still contradict the missing callback
   event?
8. How would you describe the primitive without mentioning a specific driver,
   address, or trigger buffer?

## Short Summary

Process-creation callback tamper is a BYOVD-enabled state manipulation technique.
The useful mental model is:

```text
do not think "overwrite callback"
think "break the invariant that loaded security driver state matches kernel
process-notification dispatch state"
```

That is the part worth learning. The rest is build-specific, fragile, and easy to
turn into a crash instead of a controlled lab result.

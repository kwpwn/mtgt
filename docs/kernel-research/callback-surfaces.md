# Windows Kernel Callback Surfaces

## Purpose

This document explains Windows kernel callback mechanisms as a research topic and as a defensive visibility surface. It focuses on how callbacks are registered, invoked, synchronized, torn down, and monitored, with emphasis on the engineering risks that arise when drivers treat callbacks as "just notifications" instead of as concurrency- and lifetime-sensitive execution paths.

## Background

### Why callbacks exist in the kernel

The kernel uses callback mechanisms because many subsystems need event-driven extensibility without hard-coding every consumer into the core path. A callback gives the OS or a subsystem a way to say:

```text
When this class of event happens,
invoke registered code with the relevant context.
```

This pattern appears in:

- process and thread lifecycle notifications,
- image-load notifications,
- registry activity filtering,
- object access filtering,
- file-system minifilter operations,
- generic callback objects,
- driver-internal observer patterns built on lists, function pointers, or work items.

### Security product usage of callbacks

Security products rely heavily on callbacks because they need timely visibility into:

- process creation,
- image mapping,
- handle operations,
- registry modifications,
- file opens, writes, renames, and deletes.

Callbacks are therefore not only a kernel-programming convenience; they are a strategic observability layer.

### Stability and compatibility tradeoffs

Callbacks offer flexibility, but they also create a contract surface between:

- the subsystem issuing the notification,
- the driver consuming the event,
- other concurrently executing callbacks,
- and the teardown logic that unregisters everything later.

Because the consumer runs on someone else's execution path, poor callback behavior can damage performance, stability, and telemetry quality at once.

### Why callback surfaces matter for defenders and researchers

Researchers care because callback code often sits on high-value trust boundaries and may contain:

- race windows,
- stale context assumptions,
- invalid object-lifetime expectations,
- deadlock hazards,
- callback-ordering assumptions,
- excessive trust in parameters supplied by the OS or by other actors through the OS.

Defenders care because callback failures can silently reduce visibility or destabilize the very components meant to protect the system.

## Core Callback Families

### Process creation notify routines

These callbacks observe process creation and exit events. They are often used to:

- tag or classify processes,
- capture ancestry and command line context,
- coordinate user-mode policy components.

### Thread creation notify routines

Thread notifications matter for:

- activity correlation,
- thread-injection visibility,
- per-process thread-state accounting,
- concurrency-heavy policy decisions.

### Image load notify routines

Image-load callbacks help track:

- executable and DLL mapping,
- driver image loads,
- image path and section context,
- process/image relationships that minifilters alone cannot explain.

### Registry callbacks

Registry callbacks are a filtering and visibility path around key and value operations. They matter because:

- the registry is both configuration state and execution policy surface,
- callback contracts are nuanced,
- driver authors often underestimate how complex lifetime and parameter semantics can become.

### Object callbacks

Object callbacks mediate handle operations for selected object types such as processes and threads. Their security value comes from visibility and access shaping, but they also create subtle interactions with:

- handle tables,
- granted access decisions,
- object types,
- teardown sequencing.

### File-system and minifilter callbacks

Minifilters and file-system callbacks provide pre- and post-operation visibility around file I/O. They form a major part of EDR telemetry, yet they are not a universal sensor and carry their own ordering and reentrancy complexities.

### Driver-specific internal callback patterns

Not all callbacks are registered with public OS-wide surfaces. Drivers often maintain internal:

- callback lists,
- event subscribers,
- DPC completion callbacks,
- worker-item continuations,
- function-pointer tables.

These internal surfaces can inherit the same lifecycle and synchronization bugs as the documented global callback APIs.

## Technical Deep Dive

### Callback registration lifecycle

The lifecycle is more than "register in `DriverEntry`, unregister in unload":

```text
allocate or prepare context
  -> register callback
  -> callback begins receiving events
  -> callback may run concurrently on multiple events
  -> driver state evolves over time
  -> unload or reconfiguration begins
  -> unregister request occurs
  -> in-flight callbacks must drain safely
  -> context and referenced objects can finally be released
```

This is a classic lifetime-management problem disguised as a notification problem.

### Callback invocation context

A callback executes on the context chosen by the subsystem, not the context preferred by the consumer. That means the callback author must reason about:

- current thread and process context,
- APC state,
- IRQL,
- lock hierarchy,
- whether pageable memory access is legal,
- whether it is safe to block,
- whether user-mode cooperation is even possible at that point.

### IRQL considerations

IRQL constraints are a recurring source of callback fragility. Some callback families are documented at `PASSIVE_LEVEL`, while others appear in stack positions where blocking, paging, or calling back into certain subsystems becomes dangerous. The researcher should always ask:

```text
At what IRQL does this callback run,
and what assumptions does the callback body make that only hold at PASSIVE_LEVEL?
```

### Reentrancy risk

Callbacks are often reentrant by design or by environment. Reentrancy can come from:

- multiple concurrent events,
- nested I/O activity triggered by the callback itself,
- callback code touching subsystems that re-trigger related observation,
- teardown racing with in-flight invocation.

Code that assumes "this callback runs one-at-a-time" is often brittle.

### Locking risk

Callback code is especially prone to deadlock because it often runs in an externally owned call path. Unsafe patterns include:

- acquiring broad global locks inside notification paths,
- invoking code that may re-enter the same subsystem,
- waiting while holding locks across callback-controlled operations,
- calling back into user-mode coordination mechanisms without clearly bounded execution.

### Object lifetime and reference safety

Many callback payloads rely on:

- process objects,
- thread objects,
- image path buffers,
- registry key information,
- file objects,
- driver-defined context structures.

The callback must know which references are borrowed, which are stable only for the duration of the call, and which must be safely referenced if stored past return.

### Unregistering callbacks safely

Unregistering safely is harder than freeing a function pointer. The driver must know:

- whether unregister waits for in-flight callbacks,
- whether queued work derived from callbacks still exists,
- whether callback context contains references to already-tearing-down objects,
- whether the callback itself might try to unregister recursively or from the wrong context.

### Common bug classes

- use-after-free during unregister:
  unregister returns or teardown continues while callback-derived state still executes.
- stale context pointer:
  callback stores driver-defined context that later outlives its owner.
- race between callback execution and teardown:
  unload path and active callbacks disagree on whether the world is still valid.
- invalid assumptions about caller context:
  callback code assumes the initiating actor, process, or thread class is always the same.
- deadlocks caused by callbacks acquiring unsafe locks:
  lock hierarchy fails because callback runs on a path already holding subsystem locks.
- callback ordering issues:
  code assumes it runs before or after another observer and breaks when the order changes.
- excessive trust in callback parameters:
  subsystem-provided context is treated as stable beyond its lifetime or as semantically richer than documented.

## Callback Surface Matrix

| Callback family | Main purpose | Typical consumer | Research relevance | Defensive visibility | Common mistake |
|---|---|---|---|---|---|
| Process notify | Process lifecycle visibility | EDR, policy drivers | Trust boundary and teardown sequencing | Strong for process ancestry and lifecycle | Assuming create-time context persists unchanged |
| Thread notify | Thread lifecycle visibility | EDR, profiling, control drivers | High concurrency and lifetime pressure | Useful but noisier than process callbacks | Global state updates without synchronization |
| Image load notify | Track mapped images | EDR, allow/deny policy, visibility tools | Rich metadata but tricky timing | Strong for image correlation | Blocking or expensive work on hot path |
| Registry callback | Observe/filter registry ops | Security, auditing, hardening drivers | Complex contracts and parameter semantics | Good for config-state visibility | Misreading callback info lifetime or meaning |
| Object callback | Observe/filter handle operations | Process-protection and monitoring tools | Access mediation and handle semantics | High for suspicious opens/duplicates | Confusing handle filtering with object ownership |
| Minifilter callback | Observe/filter file I/O | AV/EDR, DLP, auditing | Reentrancy, altitude, performance tradeoffs | Strong for file activity | Assuming full-system visibility from file I/O alone |
| Driver-defined callback | Internal event chaining | Any complex driver | Hidden lifetime and teardown bugs | Low external visibility | Unclear ownership of callback context |

## Debugging / Inspection Notes

### Identifying callback registration calls in IDA or Ghidra

Look for:

- `PsSetCreateProcessNotifyRoutineEx`
- `PsSetCreateThreadNotifyRoutine`
- `PsSetLoadImageNotifyRoutine`
- `CmRegisterCallbackEx`
- `ObRegisterCallbacks`
- `FltRegisterFilter`
- `ExRegisterCallback`

Registration calls often appear in:

- `DriverEntry`,
- initialization helpers,
- feature-enable code paths,
- service-configuration transitions.

### What to look for in callback context structures

Useful questions:

- Is the context embedded in a device extension?
- Does it contain raw object pointers?
- Does it carry locks, reference counts, queues, or state flags?
- Is it shared across callbacks and worker threads?
- Is teardown ownership explicit?

### How to reason about unregister paths

The unregister path should answer:

- what prevents new callback entry,
- what waits for in-flight callbacks,
- what drains derived work items,
- when the final dereference or free is allowed,
- what happens if unregister races with driver unload or service stop.

### WinDbg inspection ideas

Safe inspection ideas:

- inspect driver object unload path and symbolized callback registration sites,
- examine stack traces from callback-path crashes,
- inspect related objects and global state around teardown,
- use module and thread context inspection to correlate which subsystem invoked the callback.

No bypass or exploit steps are needed to learn from these failures.

## Defensive Angle

Callbacks provide visibility, but visibility is only as good as callback quality. If callback code is:

- racing teardown,
- deadlocking hot paths,
- leaking references,
- or crashing under load,

then the defensive surface degrades exactly when it is most needed.

Callback inventory matters because defenders should know:

- which products registered which callback families,
- which drivers depend on callback visibility for enforcement,
- whether multiple products compete in the same surface,
- whether crash clusters point to callback instability rather than one-off bugs.

Repeated crashes in callback-heavy paths can signal:

- poor driver quality,
- incompatibility between multiple security products,
- stress/fuzz conditions,
- or attacker activity that is exercising poorly handled edge cases.

## Common Mistakes

- Treating callback context as immortal state.
- Assuming unregister means "nothing can still be running."
- Acquiring broad locks in notification paths without a documented hierarchy.
- Believing callback order is stable across all product combinations.
- Performing expensive or blocking work directly inside time-sensitive callbacks.

## Research Notes

- Callback safety is mostly a concurrency and ownership problem, not a syntax problem.
- Security tooling often depends more on teardown correctness than on registration correctness.
- Callback surfaces are fertile research areas because they connect trust boundaries, high event volume, and subsystem-specific lifetime rules.

## Lab-Safe Exercises

1. Inspect a sample driver or Microsoft sample that registers one callback family and map registration to callback function and teardown.
2. Draw the lifetime of the callback context structure and mark where references are borrowed, owned, and released.
3. Review a callback path and write down which locks, IRQL assumptions, and teardown assumptions would need verification before you trust the design.

## References / Further Reading

- Microsoft Learn, `PsSetCreateProcessNotifyRoutineEx`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex
- Microsoft Learn, `Registering for Notifications`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/registering-for-notifications
- Microsoft Learn, `OB_CALLBACK_REGISTRATION`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_callback_registration
- Microsoft Learn, `ObCallback Callback Registration Driver` sample:
  https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/obcallback-callback-registration-driver/
- Microsoft Learn, `Filter Manager Concepts`:
  https://learn.microsoft.com/windows-hardware/drivers/ifs/filter-manager-concepts
- Project Zero, `The Windows Registry Adventure #6: Kernel-mode objects`:
  https://projectzero.google/2025/04/the-windows-registry-adventure-6-kernel.html
- Project Zero, `The Windows Registry Adventure #7: Attack surface analysis`:
  https://projectzero.google/2025/05/the-windows-registry-adventure-7-attack-surface.html
- Anquanke, `Windows nei he hui tiao shi xian yuan li yu ni xiang tiao shi fen xi`:
  https://www.anquanke.com/post/id/230073

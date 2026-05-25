# Race Conditions and TOCTOU in Windows Drivers

## Purpose

This document explains race conditions and time-of-check/time-of-use bugs in Windows drivers, with focus on concurrency, asynchronous I/O, shared state, reference counting, and why these bugs often produce unstable but high-value research signals.

## Background

### Why kernel drivers are concurrent

Drivers are rarely single-threaded in practice. They operate in an environment with:

- multiple user processes,
- multiple issuing threads,
- system worker threads,
- DPCs,
- cancel paths,
- callbacks,
- unload and teardown activity,
- parallel device I/O.

This means "the code was correct when I looked at it" is not enough. The question is whether it stays correct under interleaving.

### User/kernel concurrency

The kernel is concurrent not only internally but also relative to untrusted user behavior. A user process can:

- issue overlapping IOCTLs,
- mutate buffers after validation,
- close handles during async operations,
- terminate while requests are still in flight.

### IOCTL concurrency and asynchronous IRPs

Device control traffic is a common race surface because:

- requests may arrive from many threads,
- state is often stored in device extensions,
- completion may occur later or elsewhere,
- cleanup and cancellation can overlap active processing.

### Worker threads and cancel routines

Once a request leaves the initiating thread, the lifetime story becomes more complex. Worker items, system threads, and cancel routines all create opportunities for:

- double-completion,
- use-after-free,
- stale pointer reuse,
- lock-order inversions,
- teardown conflicts.

### Shared device extension state

Device extensions are often the home of:

- request queues,
- callback registrations,
- current-client state,
- buffer ownership flags,
- reference counts,
- synchronization primitives.

That makes them a frequent hotspot for race review.

### Reference counting and object lifetime

Races often appear when the code has no clear answer to:

```text
Who currently owns this object,
who can still reach it,
and what prevents concurrent teardown?
```

## Core Concepts

### TOCTOU

Time-of-check/time-of-use means the driver validates one state, then later operates on a state that may no longer be the same. The classic cases are:

- buffer content changed after validation,
- pointer mapping changed after validation,
- referenced object freed after being deemed valid,
- access rights changed between observation and use.

### Locking

Locks are one tool for serializing access, but not all races are solved by one lock. The reviewer must reason about:

- what state the lock actually protects,
- whether the lock spans the full lifetime-sensitive window,
- whether the lock is legal at the current IRQL,
- and whether other paths touch the same state without it.

### Reference counts

Reference counts are lifetime guards, but only if:

- increments happen before publication,
- decrements happen once and only once,
- failure paths do not leak or double-drop,
- object use is conditioned on valid ownership.

### IRQL

IRQL shapes what synchronization and waiting patterns are legal. A race that seems fixable with "just wait" may be impossible to solve that way at the current IRQL.

### APCs at a high level

APC-related context matters because asynchronous completion, alertable waits, and thread-context assumptions can change when and where cleanup or execution resumes.

### Lifetime ownership

Every race review should produce an ownership map:

- who allocates,
- who references,
- who queues,
- who completes,
- who cancels,
- who unloads,
- who performs final free.

### User buffer mutation after validation

This is the user/kernel version of TOCTOU. It becomes especially relevant when:

- raw user buffers are used directly,
- nested pointers exist,
- copied metadata and live data diverge,
- async work reuses earlier trust decisions.

### Multi-threaded `DeviceIoControl` access

A single user process can intentionally or accidentally produce reordering and overlap that the driver author never modeled. This is why race-prone drivers may behave "fine" under ordinary single-threaded tests and fail under stress.

### Race amplification in labs

Researchers can increase signal safely through:

- higher request concurrency,
- verifier,
- stress loops,
- logging and trace correlation,
- VM snapshots and replay.

The goal is diagnosis, not weaponization.

## Technical Deep Dive

### Validate pointer then use later

This is a fundamental TOCTOU pattern:

```text
driver checks pointer and size
  -> stores or queues request
  -> uses pointer later under changed conditions
```

The later use may occur:

- after the buffer changed,
- after the mapping changed,
- in another thread,
- under another lock or IRQL.

### Validate length then user changes nested data

Outer-structure validation often misses that:

- embedded lengths,
- embedded pointers,
- or count fields

can still be modified before deeper use occurs.

### Free object while another thread uses it

This is the classic race-lifetime failure. It is especially common with:

- request context objects,
- callback registration contexts,
- worker-item private state,
- device-extension subobjects.

### Cancel routine race

Cancellation is a structurally tricky path because:

- the request may already be completing,
- the request may already be dequeued,
- ownership may already have moved,
- completion and cancellation may both believe they are final owner.

### Reference count underflow/overflow conceptually

Reference counting bugs are race multipliers because one bad increment/decrement ordering decision can manifest as:

- leaked objects,
- early frees,
- stale references surviving too long,
- or teardown paths that appear safe only under low concurrency.

### Shared global state without lock

Some drivers keep:

- global client pointers,
- global current request state,
- global callback contexts,
- or shared configuration flags

without a disciplined lock or publication rule. These are often easy to spot in static RE and hard to trust in dynamic use.

### Unload race

Unload races happen when the driver teardown path assumes all meaningful work has stopped, but:

- worker items still exist,
- callbacks are still registered,
- references are still outstanding,
- requests are still completing.

### Callback unregister race

Callback teardown is its own race family because unregister and in-flight callback execution may overlap. This is especially dangerous when callback context points into driver-private state being freed.

### Async IRP completion race

Completion paths are high-risk because they often run in a different execution context than the original dispatch and may not share the same assumptions about buffer lifetime, lock ownership, or final cleanup ownership.

## Race Bug Matrix

| Pattern | Shared state | Missing guarantee | Crash symptom | Defensive review idea |
|---|---|---|---|---|
| Validate pointer then use later | User buffer / request context | Buffer remains stable until use | Intermittent invalid access | Ask where ownership transfers and whether data is copied |
| Validate length then nested data changes | Composite input structure | Nested fields remain semantically stable | Inconsistent parse or late fault | Validate deep structure or snapshot to kernel-owned copy |
| Free object while another thread uses it | Request context, callback context, queue entry | No live references remain before free | UAF-like crash, random stale pointer | Trace refcount/queue ownership across threads |
| Cancel routine race | IRP and queue state | Single final owner of completion and cleanup | Double completion or stale completion path | Review cancel/install/remove ordering |
| Shared global state without lock | Device/global extension fields | Serialized read/write and teardown | Nondeterministic logic or corruption | Inventory every writer and lock coverage |
| Unload race | Driver-wide state | No in-flight work after unload begins | Crash after stop/unload | Check callback unregister, worker drain, refcounts |
| Callback unregister race | Callback list and context | In-flight callbacks drained before free | Tear-down crash or stale context | Verify unregister semantics and post-unregister cleanup |
| Async IRP completion race | IRP, MDL, buffers, context | Completion path owns valid resources | Late completion crash | Map completion ownership explicitly |

## Debugging / Inspection Notes

### How to identify shared state in RE

Look for:

- device extension fields used in many dispatch paths,
- global variables updated by multiple callbacks or threads,
- queues, lists, reference counters, or flags touched outside one lock,
- worker-item or thread-context pointers that outlive dispatch.

### How to inspect locks conceptually

Questions to ask:

- What lock protects this field?
- Is that lock always held on writes?
- Is it held on reads that require coherence?
- Is it legal to hold this lock while calling out or waiting?
- Does teardown use the same lock discipline?

### How to recognize race-looking crashes

Indicators:

- non-deterministic repro,
- inconsistent faulting addresses,
- crash clusters during stress or parallel use,
- verifier exposing bugs that ordinary runs hide,
- failures near completion, cancel, unload, or callback teardown.

### Driver Verifier, Special Pool, and stress testing

Driver Verifier helps surface ownership and contract mistakes earlier. Special Pool can help when races eventually manifest as pool misuse. Stress testing adds concurrency signal, but the documentation here stays at the diagnostic level, not at exploit amplification.

## Defensive Angle

Races create unstable signals, which makes them tempting to dismiss as "flaky drivers." That is exactly why they matter:

- they can become security-relevant without a clean deterministic path,
- they may degrade visibility tooling,
- they may surface only under load or adversarial timing,
- and they often indicate weak ownership design that affects more than one code path.

QA and telemetry can help by correlating:

- repeated nondeterministic crashes,
- verifier-only failures,
- service stop/unload instability,
- spikes in concurrent I/O before crashes.

## Common Mistakes

- Believing one lock equals one solved race.
- Documenting who allocates an object but not who owns final free.
- Ignoring unload, cancel, and completion as first-class concurrency surfaces.
- Treating nondeterministic crashes as low-value.

## Research Notes

- Race review becomes far more effective when every object has an ownership timeline.
- Many "weird" driver crashes reduce to one of three stories: stale buffer, stale object, or stale teardown assumption.
- Callback, MDL, and `METHOD_NEITHER` work all intersect here through lifetime and delayed-use patterns.

## Lab-Safe Exercises

1. Inspect a toy driver with a queue or worker item and map which thread can touch which state.
2. Review a completion or cancel path and write down where double-owner ambiguity could appear.
3. Use verifier and logging in a lab VM to compare single-threaded versus multi-threaded stress behavior without attempting to build an exploit.

## References / Further Reading

- Microsoft Learn, `Driver Verifier`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier
- Microsoft Learn, `Special Pool`:
  https://learn.microsoft.com/hr-hr/windows-hardware/drivers/devtest/special-pool
- Microsoft Learn, `PsCreateSystemThread`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pscreatesystemthread
- Existing repo note, [method-neither-research-notes.md](E:\Windows-kernel-exploit-research-resource\docs\userland-to-kernel\method-neither-research-notes.md)
- Existing repo note, [callback-surfaces.md](E:\Windows-kernel-exploit-research-resource\docs\kernel-research\callback-surfaces.md)

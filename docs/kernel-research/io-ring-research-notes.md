# Windows I/O Ring Research Notes

## Purpose

This document summarizes Windows I/O rings as a modern kernel research surface. It focuses on data structures, trust boundaries, version sensitivity, exploit-primitives literacy, and defensive review. It does not provide a working exploit recipe.

## What I/O Rings Are

Windows I/O rings expose a submission/completion queue model for asynchronous I/O. User mode creates an I/O ring handle, submits operations, and receives completions through a structured API surface.

At a high level:

```text
user process
  -> I/O ring API
  -> kernel-managed ring object and queues
  -> registered files / buffers / operations
  -> completion results
```

Research interest comes from the fact that the API bridges user-controlled requests with kernel-managed state, registered buffers, object references, and asynchronous lifetimes.

## Why Kernel Researchers Care

I/O rings became important in public Windows LPE research because certain builds exposed useful kernel-managed metadata around registered buffers and files. A limited write or increment-style primitive could sometimes be turned into a stronger read/write pattern by corrupting ring-associated metadata.

The important lesson is not "I/O ring is always exploitable." The durable research lesson is:

```text
modern Windows exploitation often upgrades weak primitives by targeting
kernel-owned metadata that already participates in legitimate copy paths
```

## Core Concepts

| Concept | Research relevance |
|---|---|
| Ring handle | User-visible object used to submit and manage operations |
| Submission queue | User-originating operation descriptions |
| Completion queue | Kernel-returned operation results |
| Registered buffers | Memory ranges associated with ring operations |
| Registered files | File handles associated with ring operations |
| Asynchronous lifetime | Objects may remain referenced across submit/complete/cancel paths |
| Build-specific layout | Internal structures and validation changed across Windows 11 builds |

## API Surface at a High Level

The documented user-mode surface is intentionally abstract. It exposes a handle-like `HIORING` value and operations around:

- creating a ring,
- querying supported capabilities,
- registering or unregistering buffers,
- registering or unregistering file handles,
- building operations,
- submitting queued operations,
- reading completions.

Conceptual flow:

```text
CreateIoRing
  -> optional registration of buffers/files
  -> build operation into submission queue
  -> submit
  -> kernel performs asynchronous work
  -> completion entry becomes visible
```

The research point is that this API creates long-lived relationships among a process, object references, registered memory ranges, queued operation state, and completion state.

## Internal State Model

Do not memorize private structure layouts as universal facts. Instead, reason in layers:

```text
user-visible ring handle
  -> kernel object backing the ring
      -> submission queue state
      -> completion queue state
      -> registered buffer table
      -> registered file table
      -> in-flight operation state
```

For exploit-literacy and crash triage, the useful question is:

```text
Which kernel-owned metadata decides where a legitimate copy/read/write operation goes?
```

That metadata family is what made I/O ring interesting in public primitive-upgrade research.

## Trust Boundaries

Key trust-boundary questions:

- Which state is user controlled at creation time?
- Which state is copied into kernel-managed memory?
- Which fields are validated once versus revalidated later?
- Which object references are held across asynchronous completion?
- Which buffer descriptors are trusted during copy operations?
- Which fields are protected by handle checks, access checks, or per-build validation?
- What happens when operations are canceled, completed out of order, or fail mid-path?

## Lifetime Questions

I/O rings are asynchronous, so lifetime is central:

- Does a registered file remain referenced after the user closes the original handle?
- Does a registered buffer description remain valid if user memory mappings change?
- What happens if operation submission succeeds but later execution fails?
- What state is cleaned up on cancel?
- What state is cleaned up only when the ring is closed?
- Are in-flight operations protected against concurrent unregister or close paths?

These are the same families of questions that matter in drivers: ownership, reference counts, cancellation, cleanup, and cross-thread state changes.

## Research-Safe Primitive Model

I/O ring abuse has appeared in primitive-upgrade discussions:

```text
limited write or increment
  -> corrupt selected kernel-owned metadata
  -> influence a legitimate kernel copy path
  -> stronger read/write capability in vulnerable builds
```

Keep analysis at this level unless you are working in an isolated lab with authorization. Do not publish field offsets, trigger buffers, or build-specific mutation sequences as reusable instructions.

## Version Sensitivity

I/O ring research is highly build-sensitive:

- Windows 11 introduced the public API surface.
- Internal structure layouts changed over time.
- Validation and object-reference behavior changed after public exploitation research.
- Public symbols may expose some type names but not every private field needed for precise reasoning.
- Mitigations may change both the target structure and the viability of a primitive-upgrade path.

Every I/O ring note should record:

- Windows build number.
- Symbol source and timestamp.
- Whether HVCI was enabled.
- Whether the research is based on public writeup, crash dump, or local debugging.
- Which claims are conceptual versus build-confirmed.

## Defensive Review Checklist

For a vulnerability or incident involving I/O rings, ask:

- Was the process using documented I/O ring APIs?
- Was I/O ring usage expected for that application role?
- Did suspicious activity involve file, buffer, or handle registration?
- Did the process interact with a vulnerable driver before I/O ring activity?
- Was there a crash near asynchronous I/O operations?
- Are there kernel dumps showing corrupted ring-associated objects?
- Is the Windows build in a range known to be relevant to public I/O ring research?

## Relationship to Drivers and BYOVD

I/O rings are not a driver vulnerability class by themselves, but they matter to driver research because a vulnerable driver can provide the weak primitive that a later stage tries to upgrade.

Example reasoning model:

```text
driver exposes limited kernel write
  -> direct token or code patch path is blocked or unstable
  -> researcher looks for kernel-owned metadata targets
  -> I/O ring, WNF, object headers, or other structures become candidate pivots
```

Defensive implication:

- Do not only classify a driver by the primitive it directly exposes.
- Also ask whether the primitive can corrupt a modern metadata target.
- Record whether current builds still expose the target behavior.

## What "OK" Means for an I/O Ring Note

For this repository, an I/O ring writeup is good enough when it records:

| Requirement | Why |
|---|---|
| Windows build | Internal layout and validation are build-sensitive |
| Primitive source | I/O ring is usually a pivot, not the original bug |
| Target metadata family | Clarifies whether the topic is buffers, files, queues, or completion state |
| Validation changes | Prevents repeating stale public exploit assumptions |
| Telemetry context | Connects I/O ring behavior to driver load, crash, ETW, and EDR context |
| Safety boundary | Avoids turning primitive-upgrade literacy into a reusable chain |

## Detection Notes

Commodity telemetry usually does not explain private I/O ring internals. Detection is correlation-heavy:

- unusual process ancestry,
- suspicious driver load or device-handle activity before I/O ring use,
- rare process using advanced asynchronous I/O APIs,
- crash or verifier evidence after I/O ring operations,
- exploit-chain context from EDR, ETW, Sysmon, and Code Integrity telemetry.

I/O ring events alone are unlikely to be a high-confidence alert without surrounding context.

## Common Mistakes

- Treating public I/O ring exploitation notes as current for every Windows 11 build.
- Ignoring the weak primitive that precedes the I/O ring pivot.
- Publishing offsets without build and symbol context.
- Assuming a crash in asynchronous I/O is enough to prove exploitability.
- Repeating old primitive-upgrade details without checking current validation behavior.

## Lab-Safe Exercises

1. Read the documented I/O ring API surface and diagram the user/kernel boundary without using private offsets.
2. Build a version table for public I/O ring research claims: affected build, primitive type, target metadata family, and patch status if known.
3. Review a crash dump from benign asynchronous I/O testing and practice separating normal object references from suspicious corruption indicators.

## References

- Microsoft Learn, `CreateIoRing`:
  https://learn.microsoft.com/en-us/windows/win32/api/ioringapi/nf-ioringapi-createioring
- Microsoft Learn, I/O ring API family:
  https://learn.microsoft.com/en-us/windows/win32/api/ioringapi/
- Windows Internals Blog, `One I/O Ring to Rule Them All`:
  https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
- Existing repo note, `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md`
- Existing repo note, `docs/kernel-research/kernel-object-layout-drift.md`

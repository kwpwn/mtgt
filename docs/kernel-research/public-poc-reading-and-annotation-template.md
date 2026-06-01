# Public PoC Reading And Annotation Template

Updated: 2026-05-27

## Purpose

This document gives a repeatable way to read public exploit PoCs and convert them into strong research notes.

It is designed for cases where a blog or GitHub repository already published code, but the repo needs a teaching document that explains:

- what the code is proving,
- what primitive exists,
- what assumptions make it work,
- why the technique fails on other systems,
- what the general lesson is.

Do not paste runnable exploit code into notes. Annotate the idea and keep the implementation details in the upstream reference.

## Why Not Just Copy The PoC?

Copying a PoC teaches less than explaining it.

A PoC often mixes four layers:

```text
transport glue
  + vulnerable-driver protocol
  + primitive construction
  + objective-specific payload
```

For learning, separate them.

| Layer | What to write |
|---|---|
| transport glue | how user mode reaches the driver at a high level |
| protocol | what semantic request the driver expects |
| primitive | read/write/map/MSR/port/object action |
| objective | what state the PoC tries to influence |

The valuable part is not the bytes. The valuable part is the invariant that the bytes violate.

## Annotation Workflow

### Step 1: Identify the Claim

Write:

```text
The PoC claims that driver X version Y exposes primitive Z under condition C.
```

Then separate:

- verified by author,
- verified locally,
- inferred from code,
- not yet verified.

Why:

```text
public PoC quality varies;
some prove crash only, some prove primitive, some prove objective
```

### Step 2: Extract Preconditions

Record:

- Windows build,
- architecture,
- driver version/hash,
- signing and blocklist state,
- HVCI/VBS state,
- required privilege,
- hardware requirement,
- vendor service requirement,
- policy or boot configuration dependency.

Question:

```text
what must be true before the first driver call matters?
```

### Step 3: Map Reachability

Record:

- device object,
- symbolic link or interface,
- device ACL,
- service/broker requirement,
- IOCTL access bits,
- custom auth or magic gate.

Reason:

```text
the PoC may assume admin or vendor-service context;
that changes the security impact
```

### Step 4: Classify Primitive

Use precise words:

- physical read,
- physical write,
- virtual read,
- virtual write,
- virtual R/W,
- kernel copy,
- MSR read/write,
- port I/O,
- PCI/MMIO access,
- constrained semantic write,
- object operation,
- process termination,
- crash only.

Then record dimensions:

```text
address space:
direction:
size control:
alignment:
page-crossing:
readback:
sync/async:
caller context:
```

### Step 5: Find The Sink

The sink is the privileged operation the driver performs.

Examples:

- memory copy,
- physical mapping,
- MSR write,
- port write,
- object lookup,
- process operation,
- callback registration or mutation,
- device/firmware operation.

Question:

```text
which user-controlled fields reach the sink?
```

Do not document exact trigger structures as a runnable recipe. Document semantic field roles:

```text
source address field
destination address field
length field
operation selector
result/status field
```

### Step 6: Separate Primitive From Objective

Example:

```text
primitive: virtual kernel write
objective: change a trusted kernel object field
```

These are not the same.

Ask:

- What objective does the PoC choose?
- Is another objective possible with the same primitive?
- Does the objective require symbols or hard-coded offsets?
- Is the objective stable across builds?
- Is cleanup included?

### Step 7: Identify The Bridge

Common bridges:

- kernel base discovery,
- current process discovery,
- token/object discovery,
- VA-to-PA translation,
- page table walk,
- runtime PDB symbol resolution,
- handle table reasoning,
- callback list reasoning,
- policy-state reasoning.

Write the bridge as:

```text
primitive gives X,
but objective needs Y,
so bridge Z connects them
```

### Step 8: Explain "Why It Works"

For every technique, answer:

```text
why does the primitive exist?
why does the driver trust user input?
why is the bridge valid?
why does the target field have semantic impact?
why does the mitigation not block this layer?
why does the technique fail on a different build?
```

This is the section that turns PoC reading into real skill.

### Step 9: Failure Mode Table

Every PoC note should include:

| Failure | Likely reason |
|---|---|
| device open fails | ACL, service missing, symbolic link different |
| driver load fails | blocklist, signature, HVCI, WDAC, Secure Boot |
| IOCTL returns error | wrong version, wrong auth gate, wrong buffer contract |
| crash during call | invalid pointer/size, wrong method, wrong IRQL/context |
| primitive works but objective fails | bad offset, wrong object, mitigation, stale state |
| delayed crash | PatchGuard, cleanup failure, corrupted linked state |
| no visible effect | changed unused field, cache not refreshed, wrong process context |

### Step 10: What The PoC Does Not Prove

Write explicitly:

- Does not prove every driver version is vulnerable.
- Does not prove the primitive is reachable by low-privilege users.
- Does not prove reliability across Windows builds.
- Does not prove compatibility with HVCI/WDAC.
- Does not prove stealth.
- Does not prove the same target field is stable.

## PoC Annotation Template

```text
Title:
Source:
Driver:
Vendor:
CVE/advisory:
PoC author claim:

Environment:
  Windows build:
  Architecture:
  HVCI/VBS:
  Secure Boot:
  WDAC/blocklist:
  Driver hash:
  Driver version:

Reachability:
  Load model:
  Required privilege:
  Device exposure:
  ACL:
  Broker/service:
  Hardware gate:

Primitive:
  Type:
  Read/write:
  Address space:
  Size control:
  Readback:
  Stability:

Sink:
  Privileged operation:
  User-controlled inputs:
  Validation missing:
  Why it works:

Bridge:
  What primitive gives:
  What objective needs:
  Bridge method:
  Build-specific assumptions:

Objective:
  Category:
  Target object/state:
  Verification:
  Cleanup:

Failure modes:
  Immediate:
  Silent:
  Delayed:

Learning:
  General rule:
  Similar driver families:
  Open questions:
```

## How To Rewrite Code As Explanation

Instead of pasting code:

```text
PoC builds an input structure with fields for source, destination, size, and direction.
The driver treats those fields as trusted kernel operation parameters.
This creates a caller-controlled copy primitive.
```

Instead of writing offsets:

```text
The PoC targets a build-sensitive field inside a process-related kernel object.
The field has semantic impact because normal kernel logic consults it later.
```

Instead of writing a bypass sequence:

```text
The PoC changes security-relevant state that is normally controlled by kernel policy.
This is fragile because mirrored state, PatchGuard, and product-specific checks can invalidate it.
```

## Red-Team Reading Questions

When reading any blog:

1. Is the bug in reachability, validation, object lifetime, or privileged API exposure?
2. Does the driver expose a primitive or only one semantic action?
3. Is the PoC proving crash, primitive, or full objective?
4. What part is driver-specific?
5. What part is Windows-build-specific?
6. What part is mitigation-state-specific?
7. What part is just PoC glue?
8. What would you remove to teach the core idea?

## Example Note Skeleton

```text
# DriverName Primitive Study

## Source

Blog/repository/advisory links.

## Claim

One paragraph.

## Primitive

Precise classification.

## Why It Works

Trust boundary and invariant.

## Bridge

What must be discovered or translated.

## Objective

Objective category, not runnable payload.

## Failure Modes

Version, policy, layout, crash, silent fail.

## What I Learned

Reusable lesson for future driver reviews.
```

## Common Mistakes

- Copying code without understanding the primitive.
- Treating a hard-coded offset as a technique.
- Treating a PoC helper function as the vulnerability.
- Confusing IOCTL transport with exploit logic.
- Ignoring reachability because the PoC runs as admin.
- Assuming the blog's Windows build matches your lab.
- Calling a one-shot semantic action "arbitrary R/W."

## Related Repo Notes

- `docs/kernel-research/offensive-driver-exploitability-map.md`
- `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md`
- `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md`
- `docs/userland-to-kernel/ioctl-reverse-engineering.md`
- `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
- `docs/kernel-research/kernel-object-layout-drift.md`


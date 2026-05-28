# Huorong Self-Protection Case Study

Updated: 2026-05-27

## Classification

Huorong Internet Security research in this repo is classified as:

```text
AV self-protection logic research
  -> HIPS daemon/tray/driver split
  -> process-vs-thread protection gap
  -> GUI prompt trust gap
  -> user-mode to driver IPC trust gap
  -> UI availability dependency
```

It should not be filed as BYOVD unless a separate vulnerable-driver primitive is
identified. The public Huorong material studied here is about product self-defense
logic and trust boundaries, not arbitrary kernel read/write.

Primary public source:

- https://github.com/SweetIceLolly/Huorong_Vulnerabilities

Official product source:

- https://www.huorong.cn/document/info/productions/106

## Product Shape

The public writeups describe a product architecture with:

```text
kernel protection / HIPS driver
  <-> user-mode daemon
  <-> tray / GUI prompt process
  <-> user decision
```

That shape is common in AV/HIPS products. The driver observes or blocks sensitive
operations, but the user-mode side may show prompts, collect decisions, and
communicate the result back to the driver.

The security problem is not "there is user mode." User mode is necessary for
UI and policy management. The problem appears when the driver trusts a fragile
user-mode signal without strongly binding it to:

- the real product process,
- the real prompt instance,
- the real user decision,
- the specific blocked operation,
- and a protected communication channel.

## Case 1: Process Protected, Thread Path Not Equally Protected

Public source:

- https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/KillHipsDaemon
- https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/KillTray1

### What The Public Writeups Describe

The public Huorong notes describe a gap where product processes are protected
from direct termination, but thread-level termination paths were not covered in
the same way. The result is a mismatch:

```text
process object appears protected
  != all execution units inside that process are protected
```

### Broken Invariant

Expected invariant:

```text
if a self-protection daemon cannot be terminated,
its threads should not be trivially removed either
```

Why:

```text
process liveness depends on thread liveness
```

Protecting only the process handle path leaves a different object path that can
produce the same practical result: the product component stops doing work.

### Why This Class Exists

Windows has separate object and access-control concepts for:

- processes,
- threads,
- handles,
- windows,
- services,
- jobs,
- files,
- registry keys.

If a product hardens only one path, another path can remain semantically
equivalent from the attacker's perspective.

In research language:

```text
protected object coverage is incomplete
```

### What Can Fail

This technique family depends on:

- product version,
- privilege level,
- thread protection coverage,
- watchdog restart behavior,
- whether the daemon has a protected-process model,
- whether the kernel driver mediates thread access as well as process access.

It is not a universal Windows bypass. It is a product-specific self-protection
coverage bug.

## Case 2: GUI Prompt Decision Spoofing

Public source:

- https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/PromptBypass1

### What The Public Writeup Describes

The public note describes manipulating the product's prompt UI so the prompt
behaves as if the user selected an allow decision.

The core issue is:

```text
the product treats GUI interaction as trustworthy consent
```

but the UI event path is not equivalent to a secure desktop or an authenticated
policy decision.

### Broken Invariant

Expected invariant:

```text
allow/deny prompt result must represent a real user decision
```

Observed research pressure:

```text
window/message path can be influenced by another local process
```

This is the same class of design issue that makes high-integrity prompts
different from normal UI windows. A security prompt should not be just another
window with a clickable button in the same desktop trust domain.

### Why It Matters

The driver may be correct about detecting a sensitive operation, but the final
decision is delegated to user mode:

```text
driver blocks operation
  -> user-mode tray asks user
  -> tray reports "allow"
  -> driver permits operation
```

If the "allow" is not genuinely tied to the user and to the specific prompt, the
driver can enforce the wrong decision.

## Case 3: User-Mode To Driver IPC Response Spoofing

Public source:

- https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/PromptBypass2

### What The Public Writeup Describes

The public note describes the user-mode tray process communicating a prompt
decision back to the protection driver. The key issue is that a third-party
process could reach the same communication surface and synthesize a response.

This is more serious than simple GUI click spoofing because it attacks the
decision channel itself:

```text
driver asks trusted user-mode companion for decision
  -> another process can impersonate the companion's answer
```

### Broken Invariant

Expected invariant:

```text
only the real product companion process can answer a driver security prompt
```

Stronger expected invariant:

```text
the answer is bound to the exact blocked operation,
the exact prompt instance,
the caller identity,
and a freshness token
```

If the driver only parses a message and not the identity and freshness of the
message, the driver is trusting syntax rather than authority.

### Why It Works Conceptually

Security decisions are often split:

```text
kernel driver: sees operation and can block
user-mode UI: asks user and returns decision
```

That split requires authentication. Otherwise the driver cannot know whether it
heard from:

- the real tray process,
- a stale prompt,
- a different prompt,
- a malicious local process,
- or a replayed/guessed response.

The research lesson:

```text
driver IPC is an authorization surface, not just a data pipe
```

## Case 4: Tray/UI Availability As Protection Dependency

Public source:

- https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/KillTray2

### What The Public Writeup Describes

The public note describes crashing the tray UI through high-volume window
message pressure. The daemon case is different because that process does not
expose the same UI surface.

The key invariant:

```text
security decision availability should not depend on a fragile UI message loop
```

If the product needs a prompt response but the tray is unavailable, the product
must fail closed or use a hardened fallback.

### Why It Matters

In HIPS products, prompts are often policy decision points:

```text
sensitive action
  -> prompt user
  -> user allows or denies
```

If the prompt process can be crashed, starved, or spoofed, the product must have
a clear answer to:

```text
what happens when no trustworthy user decision exists?
```

Fail-open behavior is a protection failure. Fail-closed behavior may be noisy
but safer.

## Huorong Technique Matrix

| Case | Primitive class | Broken invariant | Research lesson |
|---|---|---|---|
| Daemon/tray thread path | object coverage gap | protected process should imply protected execution units | protect process, thread, handle, service, and restart paths together |
| Prompt GUI manipulation | UI trust gap | prompt result should mean real user consent | normal desktop UI is not a strong security boundary |
| Driver IPC response spoof | IPC authorization gap | only trusted product companion should answer driver prompts | authenticate caller, freshness, and operation binding |
| Tray message crash | availability gap | prompt broker should remain reliable or fail closed | UI loops are attack surface |

## Why This Is Useful For Research

Huorong is a good study target because it shows that self-protection is not only
about kernel code. A driver can exist and still rely on weak user-mode decisions.

The important mental model:

```text
driver enforcement is only as strong as the decision path it trusts
```

If the decision path is GUI-based, message-based, or unauthenticated, a strong
kernel block can become a weak product policy.

## What To Verify In A Lab

For any Huorong version, verify these properties without assuming old PoCs still
work:

- Are product processes protected as processes and as thread collections?
- Does the driver mediate thread access to product processes?
- Can only the real product companion open the decision channel?
- Is each prompt response bound to a nonce or operation identity?
- Does the UI prompt run in a stronger desktop/integrity context?
- What is the fail-safe behavior if the tray is unavailable?
- Does the daemon restart the tray?
- Does the driver default deny when no valid user decision arrives?
- Are policy decisions logged and auditable?

## Study Questions

1. Why is protecting a process object not enough if thread objects remain
   reachable?
2. What makes a normal GUI prompt weaker than a protected consent UI?
3. What should a driver verify before accepting a user-mode policy response?
4. Why is a replayed or guessed decision message dangerous?
5. What should the driver do if the UI process crashes?
6. Which part is enforcement and which part is policy decision?

## References

- SweetIceLolly, Huorong vulnerabilities:
  https://github.com/SweetIceLolly/Huorong_Vulnerabilities
- KillHipsDaemon public note:
  https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/KillHipsDaemon
- KillTray1 public note:
  https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/KillTray1
- KillTray2 public note:
  https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/KillTray2
- PromptBypass1 public note:
  https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/PromptBypass1
- PromptBypass2 public note:
  https://github.com/SweetIceLolly/Huorong_Vulnerabilities/tree/master/PromptBypass2
- Huorong official product page:
  https://www.huorong.cn/document/info/productions/106

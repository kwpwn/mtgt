# COM and RPC Research Notes

## Purpose

This document is a working note for studying Windows brokered privilege boundaries built on RPC and COM.

The point is not to admire COM architecture. The point is to understand why these surfaces keep producing interesting research:

- privileged services expose structured methods,
- activation and launch policy may differ from invocation policy,
- marshaling hides real object flow,
- security context transitions are easy to misunderstand,
- legacy enterprise compatibility keeps risky surfaces alive for a long time.

If you want to become a strong Windows researcher, you need to be able to read a COM or RPC writeup and answer:

```text
What was the trust boundary?
What authority did the caller gain?
Which invariant actually broke?
```

## Start with the simplest model

### RPC

```text
client
  -> bind to interface endpoint
  -> invoke method
  -> runtime unmarshals
  -> service method executes
```

### COM

```text
client
  -> request activation of class/interface
  -> COM / SCM chooses server
  -> proxy/stub or local server path is established
  -> method invocation crosses process or privilege boundary
```

These look clean. Real systems are not.

What matters is not the pretty abstraction. What matters is:

- who launches the server,
- under which token the server runs,
- how the object is activated,
- who can invoke which methods,
- whether the server impersonates,
- what object or resource the method acts on.

## RPC as a research surface

### Why RPC matters

RPC is where many service interfaces become concrete:

- management methods,
- configuration updates,
- helper operations,
- diagnostic commands,
- broker requests from lower privilege callers.

The runtime handles transport details. That often causes analysts to over-trust the surface.

But the runtime does not prove:

- the method should exist,
- the caller should be allowed to invoke it,
- the method should accept the object named by the caller,
- the service should act on behalf of the caller in that context.

That is application logic, not transport logic.

### The main RPC question

For each interface method, ask:

```text
What privileged semantic action does this method expose,
and what attacker-controlled inputs influence that action?
```

If you only document parameter types and UUIDs, your note is incomplete.

## COM as a research surface

### Why COM matters

COM wraps a lot of Windows privilege boundaries in higher-level abstractions:

- CLSIDs,
- AppIDs,
- activation policy,
- local servers,
- service-hosted COM classes,
- proxy/stub marshaling,
- apartment and threading models.

This makes the surface powerful and confusing at the same time.

A lot of beginners ask:

```text
Which CLSID is interesting?
```

That is not the right first question.

The right first question is:

```text
Which privileged server process or service does this activation path land in,
and what authority does the interface expose after activation?
```

### Why activation is not the whole story

A COM class can be:

- activatable,
- launch-restricted,
- locally accessible,
- or brokered through a service,

and still the real vulnerability may live in:

- one specific method,
- one specific object naming path,
- one impersonation mistake,
- one helper call into another subsystem.

So split your reasoning:

1. activation surface,
2. interface surface,
3. object/operation semantics behind the interface.

## The activation graph

When researching COM, write this graph explicitly:

```text
CLSID / moniker / API entry
  -> activation policy
  -> server executable or service
  -> interface obtained
  -> method invoked
  -> sensitive object / operation
```

Until that graph is written, COM analysis is usually too fuzzy.

## RPC and COM meet at identity

### Why identity is the core issue

A privileged service may:

- accept a call from a low-privilege client,
- inspect parameters,
- impersonate temporarily,
- stop impersonating,
- call into file system, SCM, registry, token APIs, or another broker,
- then return success.

The exact moment identity changes matters.

If the service opens a resource under its own token when it should be using the client token, you get authority expansion.

If it uses the client token where the server should have validated and normalized first, you can get different classes of confusion or unsafe object access.

### Why COM makes this harder

Because COM adds:

- activation-time permissions,
- call permissions,
- interface proxying,
- server-local object wrappers,
- class factories and helper abstractions.

Each abstraction hides where identity is actually being applied.

That is why COM research should always reduce the system back to:

- who is calling,
- who is running,
- who is impersonating,
- who is touching the object,
- who is authorizing the action.

## Marshaling is not just serialization

Marshaling is security-relevant because it controls how object references and parameters cross boundaries.

Why researchers care:

- the receiving side may reconstruct richer meaning than the sender appears to supply,
- interface pointers and object references can carry hidden authority assumptions,
- custom marshaling or legacy formats can create parser and logic complexity,
- "already marshaled" does not mean "already authorized".

The most important mindset:

```text
Correct transport of data is not the same as correct trust of data.
```

## What to recover during research

### For RPC

You want:

- interface UUID or logical identity,
- endpoint exposure model,
- server image or service,
- method list,
- parameter categories,
- authorization path,
- impersonation behavior,
- object types touched by each method.

### For COM

You want:

- CLSID / AppID / server mapping,
- in-proc vs local server vs service-hosted role,
- activation permissions,
- launch permissions,
- interface IID set,
- method families,
- downstream RPC or broker usage,
- object ownership assumptions.

If your notes only contain registry mappings and GUIDs, you have not reached the interesting part.

## The main bug classes

### Weak method authorization

The caller can invoke a method that performs more privileged work than intended.

Why it happens:

- service trusts local caller category too broadly,
- old admin-only assumptions survived into modern lower-privilege contexts,
- one method is overlooked while others are hardened.

### Confused deputy on object targets

The service method is allowed, but it acts on an attacker-chosen target object.

Examples of object meaning:

- file path,
- registry path,
- service name,
- process handle,
- token-like object,
- COM moniker or activation target,
- broker-side object identifier.

This is one of the most common and most educational bug patterns.

### Impersonation mistakes

The service acts under the wrong token at the wrong time.

Why it happens:

- impersonation wrapped only part of the operation,
- helper functions assume caller context but run after revert,
- second-hop calls occur under server identity,
- object creation and object use happen under different identities.

### Multi-hop trust loss

The first layer validates input, but the second layer receives a weaker representation and assumes stronger guarantees.

Pattern:

```text
COM/RPC method
  -> helper object
  -> ALPC or filesystem or SCM action
  -> privileged effect
```

This is where many "it looked safe in the entry point" cases become interesting.

### Stateful logic bugs

The caller creates or reuses context that changes what later methods are allowed to do.

Why it matters:

- authorization may happen only once,
- context handles may outlive intended scope,
- session objects may preserve unsafe state.

## A practical research workflow

### 1. Find the privileged server, not just the interface

The interface name matters less than:

- what process hosts it,
- what token that process runs under,
- what capabilities that process has,
- what subsystems it can already touch.

### 2. Group methods by semantic power

Instead of documenting 30 methods uniformly, classify them:

- pure query,
- configuration write,
- object creation,
- object open/attach,
- execution trigger,
- cleanup or delete,
- broker/forward action.

This immediately tells you where to look harder.

### 3. Mark all caller-controlled object references

These include:

- paths,
- names,
- handles,
- IDs,
- interface pointers,
- activation strings,
- binding contexts.

Object reference control is where logic bugs usually become privilege bugs.

### 4. Trace impersonation and helper calls

Do not stop at the method body.

Trace:

- does it impersonate?
- when does it revert?
- does it call helper APIs afterward?
- does the helper reopen or reinterpret the target object?

### 5. Reduce the bug candidate to one broken invariant

Good examples:

- server should only touch objects it created itself,
- low-privilege callers should never choose the final privileged target,
- activation should not let caller influence privileged server-side path selection,
- authorization should bind to every operation, not only to session creation.

If you cannot phrase the invariant, you probably do not understand the bug yet.

## Why COM/RPC work belongs in a kernel research repo

Because strong Windows research is not just memory corruption.

In practice, you will often need to connect:

- service logic,
- broker trust,
- token behavior,
- object manager semantics,
- kernel object or driver interactions.

Many good LPE case studies sit exactly at that intersection.

If you ignore COM/RPC because they "look user-mode", you stay weaker than the platform requires.

## Relationship to ALPC

COM and RPC are often front doors. ALPC may be one of the internal corridors.

A realistic research chain can look like:

```text
client
  -> COM activation
  -> interface method
  -> service helper
  -> ALPC request to privileged broker
  -> file / token / process / registry / driver effect
```

That is why these notes should be read together, not separately.

## What a strong note should contain

For each studied service or interface family, record:

1. server process and security context,
2. endpoint or activation path,
3. interface list,
4. method families,
5. object references controlled by caller,
6. impersonation and revert points,
7. second-hop components,
8. privileged operations,
9. likely invariant breaks,
10. open research questions.

That gives you a reusable research artifact instead of random observations.

## Study questions

1. Why is "method is reachable" only the beginning of RPC analysis?
2. Why should COM activation rights and interface method rights be analyzed separately?
3. Why does a caller-controlled object reference often matter more than a large parameter blob?
4. Why are second-hop helper calls a recurring place where trust is lost?
5. Why can a fully legitimate local service interface still become an LPE boundary?


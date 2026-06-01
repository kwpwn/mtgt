# ALPC Research Notes

## Purpose

This note turns ALPC from a vague "Windows internal IPC thing" into a usable research surface.

The goal is not to memorize structures for their own sake. The goal is to understand why ALPC keeps appearing in Windows boundary research:

- privileged brokers use it,
- message semantics are richer than simple request/response,
- handle and section passing create object-sharing complexity,
- identity and impersonation mistakes can become privilege bugs.

## The right mental model

Do not start with undocumented fields.

Start with this:

```text
client-controlled intent
  -> ALPC message contract
  -> broker interpretation
  -> privileged action on an object or subsystem
```

If a bug exists, it is usually because the broker interpreted something incorrectly:

- who the client is,
- what object the message refers to,
- when the object should be considered valid,
- whether the broker is allowed to act on it,
- or whether the broker is still acting under the correct security context.

## Why ALPC exists

Windows uses ALPC because some local services need more than a trivial pipe:

- efficient local messaging,
- scalable broker designs,
- handle passing,
- section-backed data exchange,
- synchronization between many clients and services.

Those same features make it a good research surface.

Every additional feature adds another place for assumptions to break.

## Core concepts

### Connection ports and communication ports

At a high level:

- a server exposes a connection point,
- a client requests connection,
- the system establishes a communication relationship,
- later messages flow through that relationship.

Why this matters:

- the security decision at connect time may differ from the decision at message time,
- server code may trust connection-established context too broadly,
- state created at connect can later be reused in unsafe ways.

Research question:

```text
What security properties are checked only once during connection,
but then assumed forever?
```

### Message-based contracts

ALPC is not dangerous because messages exist. It is dangerous because messages have meaning.

A message can represent:

- "open this object",
- "duplicate this handle",
- "map this section",
- "perform this brokered task",
- "notify me when this happens",
- "use this server-side state established earlier".

Why this matters:

The protocol parser can be structurally correct and still insecure if the semantic contract is weak.

### Handle passing

This is one of the most important reasons to study ALPC.

Passing or receiving handles changes the research problem from pure parsing to object authority.

Questions you should ask:

- who created the handle?
- what access mask does it carry?
- is the broker validating object type?
- is it validating provenance or only presence?
- does the broker assume the handle refers to an object of its own choosing?
- can duplicated handles outlive the context in which they were meant to be safe?

Why handles are powerful:

They are already capability-like objects.

A string path still needs resolution. A handle may already point at a resolved object with real access rights.

### Section-backed transfer and shared views

Some ALPC flows use shared memory or section-backed patterns for efficiency.

This introduces another class of questions:

- who owns the section?
- who may write after validation?
- does the broker validate metadata but consume payload later?
- is there time for the client to change data between check and use?
- does the service copy or trust in-place contents?

This is where race and TOCTOU thinking becomes relevant even without classical kernel races.

### Completion and stateful multi-message designs

Many interesting bugs do not live in one malformed message. They live in protocol state.

Examples of the kind of reasoning you need:

- message B is only safe if message A created a trusted context,
- cancel/reconnect paths may free or reset some state but not all,
- a server may bind authorization to session state that becomes stale,
- disconnect timing may create use-after-free style reasoning pressure even before real memory corruption is proven.

## Why ALPC bugs are often confused-deputy bugs

ALPC is commonly used where a less-privileged client asks a more-privileged broker to perform some action.

That is exactly the environment where confused deputy problems thrive.

The broker becomes dangerous when it answers:

```text
"I understand what the client meant,
and I am allowed to perform it."
```

without validating the assumptions behind that statement.

Typical examples of assumptions that fail:

- the target object belongs to the caller,
- the caller is authorized for this server-side action,
- the passed handle came from a safe source,
- a path or object ID still refers to the same thing checked earlier,
- the broker is impersonating the caller at the right time.

## Identity and impersonation

### Why identity is tricky in ALPC

Because the server may have:

- connection-time identity,
- message-time identity,
- thread impersonation state,
- duplicated handles not obviously tied to present caller state,
- cached session or context objects.

A well-designed protocol binds privileged action to a stable identity model.

A weak design often checks identity at one stage and performs the sensitive action at another stage under different assumptions.

### The wrong question

Do not ask only:

```text
Can the low-privilege client talk to the broker?
```

Ask:

```text
Under which identity is the broker touching the sensitive object,
and what attacker-controlled state influenced that action?
```

That is the question that finds real bugs.

## Lifetime and ownership reasoning

ALPC research is full of "who owns this now?" questions.

Examples:

- client allocates or names something; broker later consumes it,
- broker caches a handle or pointer-like context,
- disconnect occurs while async work is still pending,
- section contents change after validation,
- per-client state is reused across reconnect or across logical operations.

Why this matters:

Many serious bugs come from authority outliving its intended scope.

That scope may be:

- connection lifetime,
- request lifetime,
- impersonation lifetime,
- object lifetime,
- session lifetime.

The exact primitive varies, but the reasoning pattern repeats.

## Reverse-engineering workflow for ALPC-heavy targets

### 1. Identify the server role

Is it:

- a broker,
- a policy decision point,
- a resource manager,
- an activation helper,
- a telemetry or event fan-out service,
- or a thin wrapper around another subsystem?

You need the server's job before you can judge message semantics.

### 2. Recover the protocol shape

You want to learn:

- major message types,
- state transitions,
- whether messages are single-shot or multi-stage,
- whether there is handle or section passing,
- whether server-side objects are created and cached.

Do not obsess over every field immediately.

First recover the semantic categories.

### 3. Mark sensitive operations

For each message family, ask:

- does it open, create, map, duplicate, start, stop, or reconfigure something?
- does it bridge to file system, registry, process, token, driver, or service operations?
- does it trigger a second-hop request to another privileged component?

### 4. Mark validation and identity checks

You are looking for:

- security descriptor checks,
- SID/session checks,
- message schema validation,
- object type checks,
- impersonation transitions,
- state prerequisites.

### 5. Find mismatches

Interesting mismatches include:

- validated at connect, used at message time,
- validated before mapping, writable after mapping,
- validated for one object type, used as another,
- checked under impersonation, consumed outside impersonation,
- tied to client session, reused globally.

That is where the best ALPC research questions usually emerge.

## What to capture in notes

When you study an ALPC component, write down:

1. server image / service name,
2. port names or conceptual port roles,
3. client classes expected to connect,
4. message families,
5. passed object types: handle, section, path, identifier, state token,
6. privileged operations reachable,
7. identity checks,
8. impersonation transitions,
9. async or multi-stage state,
10. likely bug classes.

If your note does not include those ten items, it is probably too vague to reuse later.

## Common failure classes

### Confused deputy

The broker performs privileged work on attacker-influenced targets.

Why it happens:

- target ownership is assumed,
- path or handle provenance is not verified,
- policy is attached to request shape instead of object meaning.

### Handle misuse

The broker accepts or returns handles in ways that create more authority than intended.

Why it happens:

- access masks are too broad,
- object type is not constrained,
- duplicated handle lifetime outlives trust context,
- "server-only" assumptions leak into client influence.

### Section / shared memory TOCTOU

Validation occurs on data that can later change before use.

Why it happens:

- zero-copy or shared mapping design,
- split validation and execution phases,
- async worker consumption after initial checks.

### Stateful protocol abuse

One message makes later messages trusted or differently authorized.

Why it happens:

- stale session state,
- reconnect confusion,
- incomplete cleanup,
- protocol states considered impossible but still reachable.

## Bridge to COM and RPC

ALPC often does not live alone.

A service may expose:

- COM activation,
- RPC interface methods,
- and internally use ALPC to talk to another brokered component.

That means one bug chain can span multiple layers:

```text
COM/RPC caller
  -> privileged service method
  -> ALPC broker request
  -> sensitive local action
```

If you only study one layer, you may miss the real invariant break.

## What makes ALPC hard for beginners

Three things:

1. visibility is worse than for named pipes or device objects,
2. protocol meaning matters more than raw API familiarity,
3. there are many state and identity transitions that are easy to hand-wave.

The fix is not to memorize undocumented internals first.

The fix is to force yourself to write:

- the actor graph,
- the object graph,
- the identity graph,
- and the state transitions.

Once those are explicit, reversing becomes much easier.

## Study questions

1. Why is a handle-passing ALPC design often more dangerous than a pure value-copy message design?
2. Why can a correct connection-time authorization check still lead to an insecure protocol later?
3. Why is section-backed transport a research signal for TOCTOU-style reasoning?
4. Why do stale session objects create authority bugs even without memory corruption?
5. Why should an ALPC note include both identity flow and object ownership flow?


# Windows IPC Boundary Atlas

## Purpose

This document is the top-level map for Windows IPC-oriented research in this repository.

If you want to become strong at Windows vulnerability research, you need a clean mental model for one recurring question:

```text
Where does untrusted caller-controlled state cross into more privileged code,
and what exactly is trusted at that boundary?
```

That is the real reason to study IPC.

Kernel bugs matter. Driver bugs matter. But a large amount of practical Windows research also lives in brokered boundaries:

- device IOCTL interfaces,
- ALPC ports,
- RPC endpoints,
- COM activation and interface calls,
- named pipes,
- minifilter communication ports,
- service control and helper-process channels.

This atlas is not a single exploit technique note. It is a reasoning map.

## Why IPC matters for Windows research

A lot of Windows privilege transitions do not happen through "direct code execution in kernel" first. They happen because:

1. a low-privilege process can reach a privileged endpoint,
2. the privileged endpoint accepts a request with hidden assumptions,
3. the endpoint acts on objects, paths, handles, tokens, or state it should not trust,
4. the result becomes privilege escalation, persistence, policy bypass, or stealth.

That means IPC research is really boundary research.

The protocol itself is usually not the final problem. The real problem is typically one of these:

- incorrect authorization,
- confused deputy behavior,
- wrong impersonation model,
- unsafe object reuse,
- parser ambiguity,
- state or lifetime drift,
- identity lost between one layer and another,
- service assumptions that were valid years ago but are now unsafe.

## The main IPC families

### 1. Device IOCTL interfaces

This is the bridge most kernel researchers learn first.

```text
user mode
  -> CreateFile on device object
  -> DeviceIoControl
  -> driver dispatch routine
  -> privileged action
```

Why it matters:

- the endpoint may be kernel-mode,
- the authorization surface is often just device ACL plus dispatch logic,
- data is often caller-controlled buffers,
- the primitive can become memory corruption, arbitrary R/W, physical memory access, callback tamper, and similar effects.

Why it is not enough by itself:

- it teaches the user/kernel boundary well,
- but it does not teach broker logic, identity relays, marshaling, or multi-hop trust.

### 2. ALPC

ALPC is the local broker fabric behind many privileged Windows components.

```text
client
  -> connection port
  -> communication port
  -> message / section / handle passing
  -> broker or service
```

Why it matters:

- many privileged services are not exposed as easy "call function X" surfaces,
- they are brokered through ports and message contracts,
- handle passing and section views add object-sharing complexity,
- identity and impersonation become central.

ALPC teaches you to think in terms of:

- which side owns the object,
- which side names the object,
- whether the broker validates semantic meaning or only structure,
- whether caller identity is still preserved when the action happens.

### 3. RPC

RPC is the interface boundary used by a large amount of Windows service code.

```text
caller
  -> bind to endpoint
  -> invoke method
  -> RPC runtime unmarshals
  -> service implementation runs
```

Why it matters:

- it looks structured and "official", which can create false trust,
- the runtime handles transport and marshaling, but not business authorization,
- interface methods often encode powerful management semantics,
- services may expose local-only assumptions that still create LPE risk.

RPC teaches you to separate:

- transport safety,
- interface exposure,
- method semantics,
- impersonation behavior,
- object access decisions.

### 4. COM / DCOM

COM is not just a developer framework. For researchers, it is a privilege and activation graph.

```text
client
  -> CLSID / moniker / activation request
  -> SCM / activation policy
  -> server process or service
  -> proxy/stub marshaling
  -> interface method
```

Why it matters:

- activation can launch privileged code,
- COM security settings can differ from intuitive expectations,
- interfaces often sit on top of RPC but hide that fact,
- apartments, proxies, and marshaling obscure where the real trust boundary is,
- legacy compatibility can preserve dangerous assumptions.

COM teaches you to think about:

- activation rights versus method rights,
- launch identity versus call identity,
- marshaled object references,
- who actually touches the sensitive object,
- which policy is checked at activation time and which at invocation time.

### 5. Named pipes

Named pipes are simpler, but they show up everywhere in Windows user-mode privilege design.

Why they matter:

- services often expose private helper protocols through pipes,
- the security descriptor may be weaker than intended,
- protocol framing may be custom and error-prone,
- impersonation and file-system style naming can create surprising behavior.

Named pipes are often a good training surface because:

- the topology is easier to observe than ALPC or COM,
- the trust mistakes are conceptually similar.

### 6. Minifilter communication ports

Minifilters often use communication ports to bridge user-mode security software and kernel decision points.

Why they matter:

- they are security product control channels,
- the user/kernel and broker/controller assumptions can drift,
- identity, message policy, and event ownership matter,
- they often sit close to telemetry, blocking, or self-protection logic.

### 7. Service helper channels and ad hoc local protocols

Not every important IPC surface is a formal ALPC/RPC/COM design.

Many real bugs live in:

- custom shared-memory protocols,
- helper executables launched by services,
- localhost sockets,
- file-drop directories used as message queues,
- registry-as-IPC patterns,
- event or section object coordination.

The lesson is simple:

```text
IPC is not defined by a specific API.
IPC is any path where one security context influences another through shared semantics.
```

## Boundary comparison matrix

| Surface | Typical privilege role | Main trust problem | Main researcher question | Common failure shape |
|---|---|---|---|---|
| Device IOCTL | kernel driver or privileged service-helper | caller buffer and object interpretation | What primitive does the handler expose? | R/W, state tamper, parser bug, authorization bug |
| ALPC | broker or service | message semantics plus handle/section ownership | Who validates identity, object meaning, and lifetime? | confused deputy, handle misuse, impersonation mistake |
| RPC | service interface | method authorization and object access | Which methods are reachable and under what identity? | logic bug, weak ACL, unsafe impersonation |
| COM | activation plus interface invocation | split between activation policy and interface semantics | Which server actually runs, under what identity, and what does the interface let me ask for? | activation abuse, interface overreach, marshaling confusion |
| Named pipe | local service helper | custom protocol plus impersonation assumptions | Does the server authenticate the client correctly and bind requests to the right object? | spoofing, weak ACL, protocol confusion |
| Minifilter port | security kernel/user bridge | telemetry and enforcement ownership | Which side is authoritative for allow/deny and what is trusted from user mode? | policy desync, spoofing, weak trust channel |
| Shared memory / ad hoc IPC | custom | ownership, lifetime, synchronization | Who owns the state and what protects it from races or spoofing? | TOCTOU, stale pointers, desync |

## What to enumerate first

When you study a Windows component, do not start by asking "can I exploit it?"

Start with:

1. What is the endpoint family?
2. Who can connect?
3. What identity does the server see?
4. Does the server impersonate?
5. What objects can the client name, pass, or influence?
6. Which side owns lifetime of those objects?
7. Is the server making policy decisions on client-provided identifiers?
8. Is there a second hop from broker to another privileged component?
9. What state is sticky across messages, handles, or sessions?
10. What is the highest-privilege action reachable through this channel?

If you cannot answer these, you do not understand the surface yet.

## The most useful "why" questions

### Why do broker bugs keep appearing?

Because the broker is forced to translate low-privilege intent into high-privilege action.

That translation layer is where assumptions accumulate:

- "this handle came from the client, so it must refer to what they say it does",
- "this path was already validated by an earlier layer",
- "this object reference is still valid by the time we use it",
- "this callback is still acting under the right client identity",
- "this interface method only does benign management work".

Research gets interesting exactly where those assumptions stop being true.

### Why is impersonation so central?

Because many Windows services must sometimes act:

- as themselves,
- as the caller,
- or partially on behalf of the caller.

If the service uses the wrong identity at the wrong moment, it can:

- open a protected object,
- write a path it should not,
- duplicate or create handles with too much power,
- ask another subsystem to do privileged work detached from caller identity.

Impersonation mistakes are rarely about one magic API call. They are about when the security context changes relative to the operation.

### Why do object names matter so much?

Because a large amount of Windows authorization is not just "can caller invoke method X?".

It is:

```text
can this caller cause a privileged component
to act on this specific object?
```

That object may be:

- a file path,
- registry path,
- section object,
- token handle,
- job object,
- COM moniker,
- RPC binding context,
- kernel object handle,
- or another process.

If the service validates only the method but not the target object meaning, you often get confused-deputy behavior.

### Why do multi-hop designs create more bugs?

Because the first layer may validate one thing, then pass a reduced or transformed representation to a second layer that assumes stronger validation happened.

Classic pattern:

```text
client -> broker -> helper -> kernel/service action
```

Each handoff can lose:

- caller identity,
- original provenance,
- synchronization guarantees,
- object lifetime ownership,
- intended policy context.

Researchers should actively look for these translation losses.

## A practical research workflow

### Stage 1: classify the boundary

Decide whether you are looking at:

- direct kernel surface,
- brokered local IPC,
- service control interface,
- activation-and-method interface,
- or hybrid design.

### Stage 2: map the graph

Write the graph in plain text:

```text
caller
  -> endpoint
  -> broker / runtime
  -> service / server process
  -> helper component
  -> sensitive object or operation
```

Until this graph is explicit, reasoning stays fuzzy.

### Stage 3: identify identity transitions

For each hop, write:

- caller token or SID expectations,
- impersonation state,
- whether handle duplication changes ownership,
- whether a server-side object is created before or after policy checks.

### Stage 4: identify semantic inputs

List what the attacker really controls:

- method selector,
- path,
- object name,
- handle,
- buffer contents,
- message ordering,
- race timing,
- activation target,
- binding context,
- shared memory contents.

### Stage 5: ask invariant questions

Examples:

- should the service ever touch an object not created by itself?
- should a client-supplied handle be accepted at all?
- should message A be legal before message B?
- should the broker retain state across reconnect?
- should a low-privilege caller be able to select the target server class or object instance?

### Stage 6: read implementation and logs

At this point, debugger work and reversing become much more useful because you know what you are trying to confirm.

## How this helps driver research specifically

A lot of driver researchers get strong at memory primitives and weaker at service/broker logic.

That becomes a ceiling.

Modern Windows research often needs you to bridge:

- user mode to broker,
- broker to service,
- service to kernel,
- or driver primitive to security product control path.

That is why this atlas belongs in a kernel-research repo.

It broadens you from:

```text
"what can I overwrite?"
```

to:

```text
"which trust boundary can I influence, and what privileged semantic action sits behind it?"
```

That is a better researcher question.

## Recommended reading order in this repo

1. `docs/userland-to-kernel/userland-to-kernel-boundary.md`
2. `docs/windows-internals/object-manager-and-handle-tables.md`
3. `docs/kernel-research/alpc-research-notes.md`
4. `docs/kernel-research/com-and-rpc-research-notes.md`
5. `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md`
6. `docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md`
7. `docs/kernel-research/win32k-research-notes.md`

## Study questions

1. Why is `who can connect?` a weaker question than `what semantic action can the caller cause after connect?`
2. Why can a correctly marshaled request still be insecure?
3. Why is a client-provided handle often more dangerous than a client-provided string?
4. Why do multi-hop broker designs tend to hide identity loss?
5. Why can a local-only endpoint still be an important privilege boundary?


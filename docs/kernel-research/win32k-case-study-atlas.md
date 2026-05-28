# Win32k Case Study Atlas

Updated: 2026-05-27

## Purpose

This atlas complements `docs/kernel-research/win32k-research-notes.md`.

The base note explains the Win32k mental model. This file studies public
Win32k cases as reusable patterns:

```text
case
  -> object family
  -> broken invariant
  -> primitive
  -> bridge
  -> why the bridge worked
  -> why it fails on other builds
```

This is not a PoC collection. It does not preserve trigger recipes, offsets,
syscall numbers, payload code, exploit buffers, or copy-paste chains. The goal
is to learn how to reason from public writeups without mistaking version-specific
exploit plumbing for the technique itself.

## Reading Map

Read in this order:

1. `docs/kernel-research/win32k-research-notes.md`
2. this file
3. `docs/kernel-research/primitive-pseudocode-sketchbook.md`
4. `docs/kernel-research/public-poc-reading-and-annotation-template.md`
5. `docs/kernel-research/kernel-object-layout-drift.md`
6. `docs/kernel-research/offensive-driver-exploitability-map.md`

Why:

```text
Win32k internals first
  -> case studies second
  -> PoC annotation third
  -> layout and exploitability reasoning last
```

If you reverse that order, public exploit details can look like universal truth.
They are not.

## Case Matrix

| Case | Surface | Bug class | Main object idea | Primitive lesson | Bridge lesson |
|---|---|---|---|---|---|
| CVE-2021-1732 | USER / window creation | callback state desync / type confusion | `tagWND` extra bytes and callback boundary | change object interpretation after validation | data-only R/W through window/menu object state |
| CVE-2022-21882 | USER / window callback variant | patch-bypass-style variant of same family | window type/flag change around callback | partial patch can leave equivalent state transition | exploit flow can survive if invariant is not killed |
| CVE-2021-40449 | GDI / DC reset path | use-after-free | GDI device context / reset state | stale object after complex graphics state transition | leak plus object control matters more than code exec |
| CVE-2020-1054 | GDI / icon drawing path | object/memory handling flaw | icon/bitmap/surface-style metadata | graphics metadata can become memory primitive | old GDI mental models still explain modern cases |
| CVE-2019-1458 | USER/GDI historical modern bridge | UAF / write-what-where style | window/menu/desktop object reasoning | data-only impact is practical under mitigations | exact object layout is build-sensitive |
| Smash the Ref class | USER object references | reference count invariant break | objects not held strongly enough across paths | refcount bugs are lifetime bugs with a different face | bug class, not one CVE |
| Historical bitmap/palette | GDI object metadata | primitive construction | manager/worker-style object pairing | normal GDI APIs can become read/write gadgets | mostly historical on current builds |
| CVE-2023-29336 | Win32k EoP metadata | public high-level active exploitation case | window property/object state | Microsoft metadata may be sparse; classify conservatively | do not trust PoC blogs without patch diff |

The important thing is the "why":

```text
exploit detail changes
  -> object invariant pattern repeats
```

## Shared Vocabulary

### Object Family

Win32k case studies become clear only after naming the object family:

```text
USER: window, menu, hook, cursor, input queue, desktop
GDI: bitmap, palette, surface, region, device context, font
```

If a writeup says "Win32k vulnerability" but never names the object family,
your first task is to find it.

### Invariant

An invariant is what kernel code believed was true:

```text
this object is alive
this handle still has this type
this flag still means the same representation
this pointer is kernel-only
this object is locked or referenced until use
this user-mode callback cannot change this state
```

The vulnerability is usually the moment that belief becomes false.

### Primitive

The primitive is the reusable capability:

```text
information leak
bounded write
out-of-bounds read/write
stale object access
type confusion
arbitrary read/write
data-only object modification
```

Do not confuse:

```text
primitive != payload
primitive != final objective
primitive != one exact PoC implementation
```

### Bridge

The bridge is the missing part that turns a primitive into an objective:

```text
leak object address
shape object reuse
convert bounded write into larger object access
find a stable data-only target
avoid control-flow mitigation
restore corrupted object state
```

Most Win32k cases are hard because the bridge is harder than the root bug.

## Case 1: CVE-2021-1732

Sources:

- Google Project Zero,
  [CVE-2021-1732 RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-1732.html)
- Unit42,
  [Inside Win32k Exploitation Part 1](https://unit42.paloaltonetworks.com/win32k-analysis-part-1/)
- Unit42,
  [Inside Win32k Exploitation Part 2](https://unit42.paloaltonetworks.com/win32k-analysis-part-2/)
- iamelli0t,
  [CVE-2021-1732 win32kfull callback out-of-bounds](https://iamelli0t.github.io/2021/03/25/CVE-2021-1732.html)

### What To Learn

CVE-2021-1732 is a good learning case because it contains nearly every
important Win32k theme:

- USER object state,
- window creation,
- user-mode callback,
- kernel/user representation mismatch,
- object flag interpretation,
- data-only primitive construction,
- build-sensitive object layout,
- patch quality and variant risk.

At the conceptual level:

```text
window creation path
  -> kernel reaches a callback boundary
  -> user mode can affect window-related state
  -> kernel resumes with stale interpretation
  -> object field meaning changes
  -> out-of-bounds access becomes possible
```

### Object Family

Primary object family:

```text
USER window object
```

The public analyses often discuss `tagWND`-style reasoning. Treat that as an
object-family label, not as a stable field layout.

Why window objects matter:

- they are created from user mode,
- they carry extra bytes and class/window state,
- they interact with callbacks,
- they are linked to desktop/session state,
- they can connect to menu/window relationships used in bridge construction.

### Broken Invariant

The core invariant:

```text
after window creation validates and prepares extra window/class state, the
object's representation must still mean the same thing after user-mode callback
returns
```

The bug family breaks this:

```text
representation before callback
  != representation after callback
```

The critical "vi sao":

```text
kernel code validated one interpretation of the object
  -> callback allowed user-influenced state transition
  -> kernel later used fields under another interpretation
```

That is why this is not merely a "bad write". It is a state-machine bug.

### Primitive

The primitive reported by public analyses is in the family of out-of-bounds
access that can be upgraded into read/write through neighboring object state.

Teach it as:

```text
state confusion
  -> controlled object metadata effect
  -> bounded or expanded access relative to window object state
  -> bridge to read/write
```

Do not teach it as:

```text
call these APIs in this order
```

That would preserve the exploit recipe and miss the durable lesson.

### Bridge

The bridge in public writeups uses Win32k object relationships to convert a
limited object-state corruption into practical data-only memory access.

Conceptual path:

```text
corrupt window-related state
  -> influence adjacent/related GUI object metadata
  -> use normal USER API behavior as a memory access gadget
  -> read enough kernel state
  -> write a semantic target
```

The durable idea:

```text
normal GUI APIs can become gadgets when their object metadata is corrupted
```

This is the same broad lesson as historical bitmap/palette exploitation, but
with USER object state rather than only GDI object metadata.

### Why It Works

It works when all of these are true:

- the process can call Win32k,
- GUI state is initialized,
- the callback boundary is reachable,
- object state can be changed at the dangerous moment,
- the kernel does not revalidate the key flag/representation after callback,
- object layout and relationships match the writeup assumptions,
- the bridge can turn the limited corruption into a stable read/write path.

Each item is a separate dependency. A patch can break any one of them.

### Why It Fails

Common failure modes:

- Win32k lockdown blocks the process.
- The callback path no longer permits the state transition.
- The kernel revalidates the object after callback.
- The object is strongly referenced or locked across the transition.
- The object layout changed.
- The neighboring object relationship differs on the build.
- The read/write bridge assumes a stale safe-copy or handle-table behavior.
- The final data-only target offset is wrong.

### Research Question

Ask:

```text
What is the smallest invariant Microsoft could enforce to kill the whole bug
family, not just this one call path?
```

If the answer only covers one function, variant risk remains.

## Case 2: CVE-2022-21882

Sources:

- Google Project Zero,
  [CVE-2022-21882 RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-21882.html)
- Unit42,
  [Inside Win32k Exploitation Part 2](https://unit42.paloaltonetworks.com/win32k-analysis-part-2/)
- Microsoft MSRC,
  [CVE-2022-21882](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21882)

### Why This Case Is Important

CVE-2022-21882 is valuable because it is closely related to CVE-2021-1732. It
shows why patch analysis must reason about the invariant, not only the specific
function that was patched.

Conceptual timeline:

```text
CVE-2021-1732
  -> patch addresses known path
  -> related object state transition remains reachable elsewhere
  -> CVE-2022-21882 appears as similar exploitation pattern
```

The lesson:

```text
patching one edge in a state machine is not the same as protecting the state
machine invariant
```

### Object Family

Primary object family:

```text
USER window object plus related menu/window state
```

The source material emphasizes window object type/flag confusion and the same
general bridge family as CVE-2021-1732.

### Broken Invariant

The invariant:

```text
the kernel must not continue using a window object as if its type/representation
is unchanged after a user-mode callback can affect that representation
```

P0 describes this as a window object type confusion family. Unit42 emphasizes
the relation to the earlier bug and the fact that the earlier patch did not
fully kill the equivalent state transition.

### Primitive

Teach the primitive as:

```text
callback-mediated type/representation confusion
  -> out-of-bounds object access
  -> read/write bridge through GUI object metadata
```

The important detail is not the exact object field. The important detail is:

```text
one flag changes how a field is interpreted
```

Why:

```text
if the same bytes are interpreted as different kinds of address/offset/state,
then a safe value under representation A can become dangerous under
representation B
```

### Bridge

The bridge is similar to CVE-2021-1732:

```text
limited corruption
  -> manipulate related window/menu state
  -> create read primitive
  -> create write primitive
  -> perform data-only semantic modification
```

Do not memorize the public exploit steps. Extract the bridge class:

```text
GUI object metadata as read/write adapter
```

### Why The Patch Lesson Matters

Bad patch reasoning:

```text
the old PoC no longer works, therefore the bug class is gone
```

Good patch reasoning:

```text
which invariant did the patch enforce?
can another callback path violate the same invariant?
does the check happen before or after reentrancy?
does the check cover all object representations?
```

This is one of the best Win32k examples of "variant analysis".

### Failure Modes

- object flag is checked after callback,
- type transition is blocked for all relevant paths,
- the object is locked or reference-protected,
- the bridge object no longer gives a memory access primitive,
- the final data-only target is protected or layout-shifted,
- process mitigation blocks Win32k syscalls.

### Study Questions

1. What did CVE-2022-21882 reuse conceptually from CVE-2021-1732?
2. Which invariant should have been enforced after CVE-2021-1732?
3. How do you distinguish "same exploit code" from "same bug class"?
4. Why are callback paths excellent places for patch-bypass variants?

## Case 3: CVE-2021-40449

Sources:

- Kaspersky,
  [MysterySnail and CVE-2021-40449](https://www.kaspersky.com/blog/mysterysnail-cve-2021-40449/42448/)
- Microsoft MSRC,
  [CVE-2021-40449](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40449)

### What To Learn

CVE-2021-40449 is useful because it shifts attention from USER window object
callback patterns to GDI state and object lifetime.

Public reporting describes it as a use-after-free in `NtGdiResetDC`.

Teach the case as:

```text
GDI object/state transition
  -> stale object lifetime
  -> leak/control bridge
  -> local privilege escalation
```

### Object Family

Primary object family:

```text
GDI device context and related graphics state
```

A device context is not just a simple handle. It carries rendering state and
selected objects. Resetting or changing it can touch many connected state
objects.

Why that matters:

```text
complex graphics state transition
  -> many references must remain valid
  -> one stale reference can become UAF
```

### Broken Invariant

The likely invariant:

```text
objects referenced during a GDI reset path must remain valid for every later use
in that path
```

The bug class says this invariant failed:

```text
object was freed
  -> path still used it
```

The "vi sao":

```text
GDI reset operations change object relationships; if a pointer/ref is cached
before the change and used after destruction, kernel code acts on stale state
```

### Primitive

Public reporting mentions leakage of kernel module addresses and privilege
escalation. At the safe reasoning level:

```text
UAF
  -> possible stale read/write or information leak
  -> bridge to locate kernel state
  -> further object/data modification
```

Do not assume every UAF gives write control. A UAF may be:

- crash-only,
- leak-only,
- read-only,
- write-limited,
- type-confusion-capable,
- exploitable only with reliable reclaim.

### Bridge

The bridge questions:

```text
Can the stale object be reclaimed?
Can the stale path read useful kernel data?
Can the stale path write through a controllable field?
Is an additional leak needed?
Does the graphics state allow repeatable attempts?
```

For a real exploit chain, the UAF is only the beginning. The bridge decides
whether it becomes SYSTEM-level impact or just a crash.

### Failure Modes

- reset path now takes stronger references,
- object destruction is deferred,
- stale pointer is nulled,
- reclaim is unreliable,
- leak gives only module base but not object address,
- pool hardening makes fake object shaping fail,
- final target modification is blocked by layout drift or mitigation.

### Study Questions

1. How does a GDI UAF differ from a USER callback UAF?
2. Why is a device context dangerous as a state hub?
3. What proof do you need before saying "this UAF gives arbitrary R/W"?
4. If a UAF gives only an info leak, what bridge is still missing?

## Case 4: CVE-2020-1054

Sources:

- 0xeb-bp,
  [CVE-2020-1054 Analysis](https://0xeb-bp.com/blog/2020/06/15/cve-2020-1054-analysis.html)
- Microsoft MSRC,
  [CVE-2020-1054](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1054)
- SentinelLabs,
  [Purple Fox EK using CVE-2020-1054 and CVE-2019-0808](https://www.sentinelone.com/labs/purple-fox-ek-new-cves-steganography-and-virtualization-added-to-attack-flow/)

### What To Learn

CVE-2020-1054 is useful for understanding why GDI exploitation is about
metadata, not just "graphics".

Public analysis discusses the Win32k `DrawIconEx`-related path and familiar
GDI bitmap/surface concepts. The safe lesson is:

```text
graphics object metadata describes memory operations
  -> if metadata is wrong, drawing can become memory corruption
```

### Object Family

Primary object family:

```text
GDI icon/bitmap/surface-style metadata
```

Important mental model:

```text
drawing operation
  -> dimensions
  -> format
  -> surface backing memory
  -> copy/blend/write path
```

If any metadata piece disagrees with the real allocation, the graphics path can
read or write beyond what it should.

### Broken Invariant

The invariant:

```text
the metadata used by drawing code must accurately describe the allocated
graphics memory and the operation size
```

The bug class breaks that invariant:

```text
operation thinks it can touch N bytes/pixels
  -> backing object only safely supports M
```

### Primitive

Potential primitive class:

```text
bounded graphics memory corruption
  -> object metadata corruption
  -> leak or write bridge
```

The durable lesson:

```text
GDI paths can convert malformed visual state into kernel memory side effects
```

This is why historical bitmap/palette study still matters: even if the exact
old primitive is dead, the idea of object metadata becoming a memory access
adapter remains valuable.

### Bridge

Bridge questions:

```text
Can the corruption target adjacent object metadata?
Can the target object be chosen or groomed?
Can the effect be repeated?
Can corrupted metadata be observed through a normal API?
Can it be turned into a read before a write is attempted?
```

Why read matters:

```text
data-only impact usually needs object addresses and layout knowledge
```

Without a leak, a write primitive may be blind and unreliable.

### Failure Modes

- drawing path now validates size consistently,
- object metadata is separated from attacker-influenced state,
- allocation layout no longer makes useful adjacency likely,
- GDI object hardening prevents old manager/worker assumptions,
- no information leak is available,
- crash occurs before the primitive can be stabilized.

### Study Questions

1. Which metadata values decide how a drawing operation touches memory?
2. What makes a graphics bug crash-only versus primitive-bearing?
3. Why is a repeatable bounded write often more useful than one uncontrolled
   overwrite?
4. Which old bitmap/palette lessons still apply conceptually?

## Case 5: CVE-2019-1458

Sources:

- ByteRaptors,
  [The WizardOpium LPE: Exploiting CVE-2019-1458](https://byteraptors.github.io/windows/exploitation/2020/06/03/exploitingcve2019-1458.html)
- Microsoft MSRC,
  [CVE-2019-1458](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1458)

### What To Learn

CVE-2019-1458 is useful because it sits between older Win32k exploitation
education and modern data-only exploitation.

Treat it as a bridge-era case:

```text
Win32k object bug
  -> write-what-where or UAF-style primitive
  -> data-only modification
  -> privilege impact without kernel shellcode
```

### Object Family

Public writeups discuss Win32k object manipulation and data-only impact. The
exact object plumbing is less important here than the pattern:

```text
object lifetime/corruption
  -> memory primitive
  -> semantic kernel object change
```

### Broken Invariant

The invariant:

```text
kernel GUI object state must not allow user-influenced mutation to become a
write into arbitrary or security-sensitive kernel data
```

The exploitability lesson:

```text
if an object bug gives a write primitive, modern attackers often prefer data
modification over code execution
```

Why:

- SMEP/SMAP/NX punish direct code execution assumptions.
- kCFG/CET punish indirect control-flow hijack.
- HVCI/Code Integrity punish executable-memory and unsigned-code assumptions.
- Token or process-protection state can sometimes be changed as data.

### Primitive

Teach the primitive as:

```text
write-capable object corruption
```

Do not teach the case as one magic field or one static offset.

### Bridge

The bridge is:

```text
write primitive
  -> locate semantic target
  -> write minimal data
  -> preserve system stability
```

The "minimal data" phrase matters. Good modern chains try to change as little
as possible because broad corruption increases crash and detection risk.

### Failure Modes

- object layout drift,
- write target no longer has same semantic meaning,
- object discovery fails,
- mitigation blocks the bridge,
- patch changes the object lifetime,
- exploit assumes an older Windows build.

### Study Questions

1. Why did data-only impact become more attractive over time?
2. What makes a write primitive stable enough for semantic modification?
3. Why is "kernel code execution" a less precise objective than "specific data
   invariant changed"?
4. What would you need to retarget the same case to another build?

## Case 6: Smash The Ref

Sources:

- Rapid7,
  [Exploitability Analysis: Smash the Ref Bug Class](https://www.rapid7.com/blog/post/2020/09/30/exploitability-analysis-smash-the-ref-bug-class/)
- Gil Dabah,
  [Win32k Smash the Ref: New Bug Class and Exploitation Techniques](https://www.ragestorm.net/blogs/)

### What To Learn

"Smash the Ref" is a bug class, not just one vulnerability. It is about
reference-count and lifetime assumptions in Win32k object paths.

The conceptual pattern:

```text
object is looked up
  -> code assumes reference/lifetime is safe
  -> nested behavior changes the reference situation
  -> object can be destroyed or reused
  -> later code uses stale state
```

### Why Refcount Bugs Are Subtle

Bad lifetime thinking:

```text
I looked it up, so it must still exist
```

Correct lifetime thinking:

```text
lookup proves existence only for the protected lookup window
```

If later code uses the object after locks/references are dropped, the original
lookup is not enough.

### Broken Invariant

The invariant:

```text
every object use must be covered by a reference/lock/lifetime guarantee strong
enough for that use
```

When the guarantee covers lookup but not use, refcount bugs become UAF bugs.

### Primitive

Possible primitive classes:

- stale read,
- stale write,
- type confusion after reuse,
- object relationship corruption,
- callback-controlled lifetime split.

### Bridge

The bridge is usually reclaim:

```text
free target object
  -> reclaim memory with controllable or useful object
  -> trigger stale use
```

But modern reclaim is difficult because:

- pool allocation behavior changed,
- object sizes vary by build,
- hardening adds checks,
- timing and thread context matter,
- callback path may now hold stronger references.

### Failure Modes

- reference held across the dangerous region,
- destruction deferred,
- object marked invalid and checked before use,
- pool reclaim cannot be shaped,
- stale use reads harmless data,
- control-flow mitigations block vtable/callback abuse.

### Study Questions

1. What is the difference between lookup validity and use validity?
2. How do callbacks make reference bugs easier to exploit?
3. Why does a refcount bug often need object spraying or reclaim?
4. What patch pattern kills the class instead of one instance?

## Case 7: Historical Bitmap/Palette Primitive

Sources:

- Blue Frost Security,
  [Abusing GDI for Ring0 Exploit Primitives: Evolution](https://labs.bluefrostsecurity.de/publications/2017/10/02/abusing-gdi-for-ring0-exploit-primitives-evolution/)
- Unit42,
  [Inside Win32k Exploitation Part 1](https://unit42.paloaltonetworks.com/win32k-analysis-part-1/)
- Morten Schenk,
  [Taking Windows 10 Kernel Exploitation to the Next Level](https://www.blackhat.com/us-17/briefings/schedule/#taking-windows--kernel-exploitation-to-the-next-level--leveraging-write-what-where-vulnerabilities-in-creators-update-6293)

### What To Learn

Bitmap/palette exploitation is the classic Windows kernel primitive-construction
course. You study it because it teaches how corrupted object metadata can make
normal APIs act like memory read/write gadgets.

Do not study it because you expect old code to work unchanged.

### Core Idea

Conceptual model:

```text
object A controls metadata
object B performs normal API operation
metadata points operation at chosen memory
normal API becomes read/write adapter
```

This is sometimes called a manager/worker style mental model in old writeups.

### Broken Invariant

The invariant:

```text
GDI object metadata must describe only memory owned by that object
```

When metadata can be corrupted:

```text
normal graphics API
  -> trusts corrupted metadata
  -> reads/writes memory outside intended object
```

### Why It Was Powerful

- It turned one corruption bug into repeatable read/write.
- It used normal Windows APIs, making the bridge ergonomic.
- It supported data-only objectives.
- It avoided immediate need for kernel shellcode.

### Why It Is Mostly Historical

Modern Windows weakened this route:

- kernel pointers are less exposed,
- user-mode safe copies were hardened,
- GDI object internals changed,
- object isolation improved,
- old assumptions around bitmap/palette fields drifted,
- mitigations punish control-flow follow-on payloads.

### Still Useful Lesson

The durable lesson is:

```text
an object API can become a memory primitive if object metadata is corrupted
```

This pattern appears outside GDI too:

- USER menu/window metadata,
- I/O ring object metadata,
- kernel queues,
- MDL mappings,
- driver copy primitives.

### Study Questions

1. What makes an API a good read/write adapter?
2. Which metadata fields must be corrupted for an API to touch chosen memory?
3. Why do information leaks matter before metadata corruption?
4. Which modern mitigations specifically hurt old bitmap/palette assumptions?

## Case 8: CVE-2023-29336

Sources:

- Microsoft MSRC,
  [CVE-2023-29336](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29336)
- NVD,
  [CVE-2023-29336](https://nvd.nist.gov/vuln/detail/CVE-2023-29336)
- Numen Cyber,
  [Analysis of CVE-2023-29336](https://www.numencyber.com/cve-2023-29336-win32k-analysis/)

### Why This Case Is Different

This case is included as a cautionary example. Some public posts and PoC
repositories discuss it, but public quality varies. Microsoft's advisory is
high-level. Treat every exploit blog as untrusted until you verify it through
patch diffing, crash behavior, and symbols.

The safe learning goal:

```text
how to classify a sparse public Win32k EoP case without overclaiming
```

### Conservative Classification

Minimum safe classification:

```text
Win32k elevation of privilege
  -> local attacker
  -> GUI/kernel boundary
  -> object-state or memory-safety issue
  -> data-only or memory-corruption bridge likely
```

Do not write:

```text
exact API X causes exact object Y to become arbitrary R/W
```

unless you have independently verified it.

### What To Verify

If you study this case in a lab, verify:

```text
1. Which module changed in the patch?
2. Which function family changed?
3. Is the changed path USER or GDI?
4. Does the crash require GUI thread state?
5. Is there a callback boundary?
6. Is the bug a UAF, OOB, type confusion, or logic/state mismatch?
7. What primitive is proven by crash/debugging?
8. What bridge is assumed by the public PoC?
```

### Why This Matters

Public exploit posts often collapse many steps:

```text
bug -> SYSTEM
```

Good research expands it:

```text
bug
  -> reachability
  -> primitive
  -> leak
  -> bridge
  -> semantic target
  -> reliability
```

If a post skips the middle, it may still be useful, but it is not yet a strong
research note.

## Pattern Atlas

### Pattern A: Callback State Desync

Seen in:

- CVE-2021-1732,
- CVE-2022-21882,
- many older Win32k callback bugs.

Pattern:

```text
validate state
  -> user-mode callback
  -> user mode changes state
  -> kernel resumes with old assumption
```

Invariant:

```text
state after callback must still satisfy every assumption made before callback
```

Patch class:

```text
revalidate after callback or hold state so it cannot change
```

Failure mode for exploit:

```text
patch validates the exact flag/type after callback
```

### Pattern B: Object Representation Flip

Seen in:

- CVE-2021-1732,
- CVE-2022-21882,
- other type/flag confusion cases.

Pattern:

```text
same field means one thing under flag A
same field means another thing under flag B
attacker changes flag between check and use
```

Invariant:

```text
representation tag and represented data must change atomically and safely
```

Why powerful:

```text
safe offset can become pointer-like state, or user pointer can become
kernel-interpreted offset, depending on object design
```

### Pattern C: GDI Metadata Mismatch

Seen in:

- CVE-2020-1054,
- historical bitmap/palette research,
- surface/bitmap style bugs.

Pattern:

```text
metadata says operation length/format/backing memory is valid
actual allocation says it is not
```

Invariant:

```text
metadata and memory backing must agree
```

Bridge:

```text
use normal drawing API as memory access operation after metadata corruption
```

### Pattern D: Reference Lifetime Gap

Seen in:

- Smash the Ref,
- callback UAFs,
- many USER object lifetime cases.

Pattern:

```text
object lookup succeeds
reference protection does not cover later use
object dies or changes
later use reads/writes stale state
```

Invariant:

```text
every use must have its own lifetime guarantee
```

### Pattern E: Sparse Advisory Overclaim

Seen in:

- many modern CVE writeups where MSRC gives little detail,
- recycled PoC posts,
- SEO vulnerability pages.

Pattern:

```text
public title says Win32k EoP
blog claims exact exploitability
no patch diff or crash proof is shown
```

Research response:

```text
classify conservatively until verified
```

This pattern matters because bad public notes pollute your mental model.

## How To Compare Two Win32k Cases

Use this table:

| Question | Case A | Case B |
|---|---|---|
| USER or GDI? |  |  |
| Object family? |  |  |
| Callback boundary? |  |  |
| Broken invariant? |  |  |
| Primitive? |  |  |
| Leak needed? |  |  |
| Read bridge? |  |  |
| Write bridge? |  |  |
| Data-only target? |  |  |
| Build-specific assumption? |  |  |
| Mitigation pressure? |  |  |
| Patch class? |  |  |

When two cases share the same invariant, they are variants even if the APIs
look different.

When two cases share only the final objective, they may be unrelated.

## Patch-Diff Questions

For every Win32k patch diff:

```text
1. Did Microsoft add a check, refcount, lock, cleanup, size clamp, or state reset?
2. Is the new check before or after callback?
3. Does the new check protect all call paths or only one?
4. Does the patch kill the representation transition or only block one trigger?
5. Did the patch alter object layout?
6. Did the patch remove a leak or only stop corruption?
7. Did the patch move code between win32kbase and win32kfull?
8. Does the fix imply the root cause was lifetime, type, size, or logic?
```

Why:

```text
the patch often explains the invariant more honestly than exploit code does
```

## PoC Reading Rules For Win32k

When you read a public Win32k PoC:

1. Ignore exact offsets first.
2. Identify object family.
3. Mark every user-mode callback boundary.
4. Mark every point where object state changes.
5. Separate leak, primitive, and bridge.
6. Replace function names with invariant statements.
7. Record every build assumption.
8. Record why Win32k lockdown would break reachability.
9. Record why GUI/session context matters.
10. Only then read implementation details.

Bad note:

```text
PoC calls function X, then function Y, then gets SYSTEM.
```

Good note:

```text
PoC changes object representation during a callback, creating OOB access over
window state, then converts that into a data-only read/write bridge through
related GUI object metadata.
```

## Study Questions

1. Why are CVE-2021-1732 and CVE-2022-21882 better studied together?
2. What does "patch bypass" mean at the invariant level?
3. Why are user-mode callbacks uniquely dangerous in Win32k?
4. What does a representation flip mean?
5. Why is a flag check after callback stronger than one before callback?
6. Why are GDI metadata bugs still relevant even after bitmap/palette hardening?
7. What makes a UAF exploit-worthy instead of crash-only?
8. Why is an information leak often the real bridge?
9. Why can two exploits share a bridge but not a bug class?
10. Why can two bugs share a bug class but need different bridges?
11. Why should sparse advisory pages be classified conservatively?
12. What proof would convince you a public PoC's claimed arbitrary R/W is real?
13. Which assumptions are likely to break across Windows 10 to Windows 11?
14. Why does Win32k lockdown change exploitability before memory corruption
    even matters?
15. What part of a Win32k case should be reusable five years later?

## Source Map

Primary and high-value sources:

- Google Project Zero,
  [CVE-2021-1732 RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2021/CVE-2021-1732.html)
- Google Project Zero,
  [CVE-2022-21882 RCA](https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-21882.html)
- Unit42,
  [Inside Win32k Exploitation Part 1](https://unit42.paloaltonetworks.com/win32k-analysis-part-1/)
- Unit42,
  [Inside Win32k Exploitation Part 2](https://unit42.paloaltonetworks.com/win32k-analysis-part-2/)
- Kaspersky,
  [MysterySnail and CVE-2021-40449](https://www.kaspersky.com/blog/mysterysnail-cve-2021-40449/42448/)
- 0xeb-bp,
  [CVE-2020-1054 Analysis](https://0xeb-bp.com/blog/2020/06/15/cve-2020-1054-analysis.html)
- ByteRaptors,
  [The WizardOpium LPE: Exploiting CVE-2019-1458](https://byteraptors.github.io/windows/exploitation/2020/06/03/exploitingcve2019-1458.html)
- Rapid7,
  [Exploitability Analysis: Smash the Ref Bug Class](https://www.rapid7.com/blog/post/2020/09/30/exploitability-analysis-smash-the-ref-bug-class/)
- Blue Frost Security,
  [Abusing GDI for Ring0 Exploit Primitives: Evolution](https://labs.bluefrostsecurity.de/publications/2017/10/02/abusing-gdi-for-ring0-exploit-primitives-evolution/)
- Morten Schenk,
  [Taking Windows 10 Kernel Exploitation to the Next Level](https://www.blackhat.com/us-17/briefings/schedule/#taking-windows--kernel-exploitation-to-the-next-level--leveraging-write-what-where-vulnerabilities-in-creators-update-6293)
- Microsoft MSRC,
  [CVE-2021-1732](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1732),
  [CVE-2022-21882](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21882),
  [CVE-2021-40449](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40449),
  [CVE-2020-1054](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1054),
  [CVE-2019-1458](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-1458),
  [CVE-2023-29336](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29336)

Local repository links:

- `docs/kernel-research/win32k-research-notes.md`
- `docs/kernel-research/public-poc-reading-and-annotation-template.md`
- `docs/kernel-research/offensive-driver-exploitability-map.md`
- `docs/kernel-research/kernel-object-layout-drift.md`
- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
- `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`

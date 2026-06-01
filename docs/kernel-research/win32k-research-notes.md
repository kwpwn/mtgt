# Win32k Research Notes

Updated: 2026-05-27

## Purpose

`win32k` is not one small technique. It is the Windows kernel-mode GUI
subsystem and a large historical exploit surface around `USER`, `GDI`,
desktop/session state, GUI syscalls, user-mode callbacks, and graphics object
lifetime.

This note is written as a study document:

```text
subsystem
  -> trust boundary
  -> object model
  -> bug class
  -> primitive
  -> bridge
  -> failure mode
  -> mitigation pressure
```

It intentionally does not include runnable exploit code, trigger buffers,
syscall-number tables, offsets, or copy-paste chains. The goal is to understand
the world around Win32k exploitation well enough to read public writeups, debug
crashes, classify primitives, and reason about why older techniques work or
fail on modern builds.

## The Short Version

When people say "Win32k technique", they may mean one of several different
ideas:

| Meaning | What it really means |
|---|---|
| Win32k syscall attack surface | User-mode code reaches kernel GUI services through `NtUser*` and `NtGdi*` entries exported by `win32u.dll`. |
| USER object exploitation | Bugs around windows, menus, hooks, cursors, input queues, desktops, and window stations. |
| GDI object exploitation | Bugs around bitmaps, palettes, surfaces, regions, device contexts, fonts, and drawing paths. |
| Callback/reentrancy exploitation | Kernel GUI code calls back into user mode, user mode mutates or frees state, and kernel resumes with stale assumptions. |
| Shared heap or handle-table leak | User-mode-visible metadata historically revealed object and kernel-address information. |
| Bitmap/palette primitive | Older GDI object tricks converted controlled object fields into kernel read/write. Modern Windows hardened this heavily. |
| Win32k lockdown bypass target | Sandboxes reduce attack surface by disabling Win32k syscalls; a bypass tries to regain that surface. |
| BYOVD bridge through Win32k | A vulnerable driver primitive can temporarily redirect or abuse a Win32k-related dispatch path. This is fragile and version-sensitive. |

So the first question is always:

```text
Which Win32k idea are we talking about?
```

If the answer is just "Win32k exploit", the note is incomplete.

## Where Win32k Sits

Modern Windows split the historical GUI kernel code across related modules:

| Component | Research meaning |
|---|---|
| `user32.dll` | User-mode API layer for windows, messages, menus, hooks, clipboard, and related `USER` behavior. |
| `gdi32.dll` | User-mode API layer for drawing and graphics device interface behavior. |
| `win32u.dll` | Thin user-mode syscall export layer for many `NtUser*` and `NtGdi*` calls. |
| `win32k.sys` | Historical/loader-facing Win32k kernel component. |
| `win32kbase.sys` | Lower/base Win32k kernel functionality on modern builds. |
| `win32kfull.sys` | Larger implementation body for many USER/GDI kernel services. |
| `ntoskrnl.exe` | Core executive/kernel, memory manager, object manager, scheduler, and general syscall machinery. |

The practical path is:

```text
application
  -> user32.dll / gdi32.dll
  -> win32u.dll
  -> kernel syscall transition
  -> win32kbase.sys / win32kfull.sys
  -> USER/GDI/session/desktop state
```

Why this matters:

- Normal drivers usually expose device objects and IOCTLs.
- Win32k exposes a huge GUI syscall surface to GUI-capable processes.
- Normal kernel objects use executive object manager semantics.
- Many USER/GDI objects use their own handle tables, lifetimes, locks, and
  session-specific assumptions.
- Many Win32k paths were built around complex user interaction, window
  messaging, callbacks, legacy graphics behavior, and compatibility.

That combination creates many opportunities for mismatched assumptions.

## Why Win32k Has Been So Exploitable

Win32k is risky because it sits at an awkward boundary:

```text
untrusted user process
  <-> GUI API compatibility layer
  <-> kernel-mode windowing and graphics subsystem
  <-> shared session objects
  <-> callbacks back into user mode
```

The key problem is not simply "kernel code has bugs". The key problem is that
Win32k needs to maintain rich, mutable, user-influenced object graphs while
also running in kernel mode.

### Reason 1. GUI State Is Highly Mutable

Windows, menus, hooks, cursors, input queues, desktops, and drawing objects are
not static buffers. They are live objects that change while messages are sent,
callbacks run, windows are destroyed, and threads enter or leave GUI state.

Why that matters:

```text
kernel validates object
  -> kernel calls user-mode callback
  -> user-mode code changes object graph
  -> kernel resumes and trusts earlier validation
```

If the resumed code does not revalidate the right invariant, a safe state can
become unsafe.

### Reason 2. Compatibility Pressure Is Extreme

Win32 GUI behavior must preserve old application compatibility. That creates
large amounts of edge-case logic: message routing, window procedures, hooks,
clipboard formats, device contexts, font behavior, printing paths, legacy GDI
operations, and desktop/window-station rules.

Why that matters:

```text
more compatibility state
  -> more uncommon state transitions
  -> more places where object lifetime and type assumptions drift
```

### Reason 3. The Kernel Calls Back Into User Mode

In most kernel driver research, user mode calls kernel mode. Win32k often has a
second direction: kernel GUI code can call back into user mode for window
procedures, hooks, message handling, and client-side GUI behavior.

This creates a dangerous pattern:

```text
kernel is in the middle of an operation
  -> kernel temporarily hands control to user mode
  -> user mode runs arbitrary application logic
  -> kernel resumes the original operation
```

The question becomes:

```text
Did kernel mode preserve every lifetime, lock, type, and state invariant across
the callback?
```

Historically, the answer was often no.

### Reason 4. USER/GDI Handles Are Not Normal Kernel Handles

Many Win32k objects are referenced through USER/GDI handle mechanisms rather
than ordinary `HANDLE` references managed entirely by the object manager.

Why that matters:

- The handle table is subsystem-specific.
- Object type checks are subsystem-specific.
- Some metadata has historically been visible or inferable from user mode.
- Handle reuse can create stale-object reasoning problems.
- The object manager mental model is useful, but not sufficient.

A researcher who only understands `ObReferenceObjectByHandle` style flows will
miss important Win32k-specific lifetime rules.

### Reason 5. Session and Desktop Context Matter

Win32k objects are tied to sessions, window stations, desktops, GUI threads,
and per-session state. A primitive that looks valid from a memory-corruption
perspective may fail because the process is in the wrong session, has no GUI
thread, cannot access the target desktop, or is under a mitigation policy that
blocks Win32k syscalls.

That is why Win32k exploitability is not just:

```text
bug exists -> exploit works
```

It is closer to:

```text
bug exists
  -> reachable from a GUI-capable process
  -> reachable in the right session/desktop
  -> reachable with the right object state
  -> gives a useful primitive
  -> primitive can be bridged under current mitigations
```

## Core Object Families

### USER Objects

`USER` is the window-management side of Win32k. Important research concepts
include:

| Object family | What to study |
|---|---|
| Window objects | Window lifetime, parent/owner relationships, window procedures, message routing, destruction paths. |
| Menus | Nested state, item arrays, callbacks, mutation while being walked. |
| Hooks | Cross-thread or desktop-related callback behavior, callback lifetime, access checks. |
| Cursors/icons | Shared GUI resources, image metadata, user/kernel copy boundaries. |
| Input queues | Thread input attachment, focus/activation state, message queues. |
| Desktops | Isolation boundary for windows, hooks, input, and GUI objects. |
| Window stations | Higher-level grouping around desktops and interactive access. |
| Clipboard | Cross-process GUI data movement and format/state transitions. |

The repeated invariant is:

```text
object identity + object type + object lifetime + access context
```

If a code path validates only one or two of those, it may become exploitable
when the others change during a callback or reentrant operation.

### GDI Objects

`GDI` is the drawing/graphics side. Important research concepts include:

| Object family | What to study |
|---|---|
| Bitmap | Historical object-field manipulation, pixel buffers, surfaces, and kernel/user storage transitions. |
| Palette | Historical companion object for read/write primitive construction. |
| Surface | Graphics memory representation; important in many drawing paths. |
| Device context | Rendering state and object selection state. |
| Region | Complex shape/state parsing and memory management. |
| Font | Historically important parsing and rendering surface, though modern isolation changed some risk. |
| Brush/pen | Smaller state objects that still interact with selection and drawing paths. |

The repeated invariant is:

```text
metadata describes drawing memory correctly
```

If metadata such as size, pointer, owner, selected object state, or backing
storage lifetime becomes inconsistent with real memory, a drawing operation can
become an information leak, out-of-bounds access, stale pointer use, or bounded
write.

## USER/GDI Handle Tables and `gSharedInfo`

Older Win32k exploitation frequently involved USER/GDI handle-table metadata
and the global shared information block commonly discussed as `gSharedInfo`.

The high-level idea:

```text
user mode creates GUI object
  -> Win32k stores object metadata in subsystem tables
  -> some metadata is mirrored or inferable from user mode
  -> researcher correlates handle value with object table entry
  -> object address/type/lifetime information becomes easier to reason about
```

Why this mattered historically:

- It reduced the need for a separate kernel information leak.
- It helped map a user-visible handle to internal kernel object metadata.
- It made object spraying and object replacement easier to debug.
- It helped convert a UAF from "crash" into "controlled stale object".

Why it is less universal now:

- Pointer exposure has been hardened across Windows versions.
- Layouts changed.
- Some user-mode-visible metadata no longer gives direct kernel pointers.
- Modern builds add more isolation and validation around GDI/USER state.

Research lesson:

```text
Do not treat old gSharedInfo or handle-table writeups as universal recipes.
Treat them as historical examples of how an information boundary was weakened.
```

The invariant being attacked was:

```text
user mode should not know enough kernel object location/state to reliably
construct a kernel memory primitive
```

When shared metadata leaked too much, that invariant broke.

## Desktop Heap and Safe Copies

Desktop heap is a key concept in older Win32k notes. It stores per-desktop GUI
state and has historically included user-mode mappings or user-mode-accessible
views of selected GUI metadata.

The important research question is not "what is the exact offset". The useful
question is:

```text
Which copy is authoritative?
```

For many GUI objects, researchers historically had to distinguish:

- the kernel object,
- a user-mode safe copy,
- a handle-table entry,
- a cached or derived field,
- a pointer that used to be exposed but is now hidden or encoded.

Why this matters:

```text
if exploit logic edits or trusts a non-authoritative copy
  -> kernel behavior may not change

if exploit logic trusts a stale copy
  -> build-specific crash or no-op

if exploit logic assumes a pointer is still exposed
  -> modern build breaks the bridge
```

This is also why many old writeups are still valuable but cannot be copied
blindly.

## User-Mode Callbacks

User-mode callback research is one of the most important Win32k study tracks.
Tarjei Mandt's work is a classic starting point because it explains the core
pattern: kernel GUI code enters user mode and then resumes kernel execution
after user-controlled code has had a chance to mutate the world.

The conceptual flow:

```text
kernel begins USER/GDI operation
  -> validates an object or state relationship
  -> calls back into user mode
  -> user-mode callback performs nested GUI operation
  -> nested operation frees/replaces/changes related state
  -> callback returns
  -> kernel resumes with stale assumptions
```

The "why" is critical:

```text
validation before callback is not automatically valid after callback
```

The bug class is often not a simple missing bounds check. It is a time split:

```text
check object
  -> arbitrary user-mode execution
  -> use object
```

That is a GUI-specific version of TOCTOU plus reentrancy.

### What Can Break Across a Callback

| Invariant | How it can break conceptually |
|---|---|
| Object lifetime | Object was valid before callback but destroyed during callback. |
| Object type | Handle is reused for a different object type after callback. |
| Parent/child relationship | Window tree changes while being walked. |
| Menu/item array | Item count or backing allocation changes while code still uses old state. |
| Hook state | Hook is removed or replaced during nested dispatch. |
| Selection state | GDI object selected into a DC changes unexpectedly. |
| Lock/refcount state | Code assumes a reference or lock protects more than it really does. |

### Why Callback Bugs Can Be Powerful

Callback bugs can be powerful because user mode controls timing and state
mutation. A normal race may need unlucky scheduling. A callback bug often gives
the attacker a synchronous window:

```text
kernel asks user mode to run code now
  -> user mode changes state at exactly the dangerous point
```

That does not make exploitation automatic, but it makes the bug class worth
serious attention.

## Common Win32k Bug Classes

### 1. Use-After-Free After Callback

Pattern:

```text
kernel gets object pointer
  -> callback occurs
  -> object is freed or replaced
  -> kernel uses old pointer
```

Why it works:

```text
the object lifetime invariant was checked before user-mode reentrancy, but not
reconfirmed after reentrancy
```

Primitive possibilities:

- stale read,
- stale write,
- type confusion if memory is reused by a different object,
- control of object fields if reclaim can be shaped.

Modern pressure:

- pool hardening,
- object encoding,
- CFG/kCFG/CET pressure on control-flow corruption,
- fewer direct kernel pointers visible to user mode,
- changed object layouts.

Failure modes:

- the object is now strongly referenced across callback,
- the vulnerable state is revalidated after callback,
- reclaim is unreliable,
- layout changed,
- a mitigation turns control-flow impact into a crash.

### 2. Type Confusion in USER/GDI Handles

Pattern:

```text
handle or object entry is interpreted as type A
  -> state changes
  -> same reference is used as type B or with type-A assumptions
```

Why it works:

```text
handle identity was treated as equivalent to object type, but handle identity
alone does not prove type stability across mutation
```

Primitive possibilities:

- object field confusion,
- bounded write through wrong structure layout,
- information leak through wrong metadata interpretation.

Failure modes:

- strict type check is added at every use,
- handle reuse behavior changes,
- vulnerable path requires rare desktop/session state,
- object manager-like references are introduced around the critical section.

### 3. Safe-Copy Mismatch

Pattern:

```text
user-visible copy says one thing
  -> kernel authoritative object says another
  -> code trusts the wrong one or fails to resynchronize
```

Why it works:

```text
two representations of one logical GUI object drift apart
```

Primitive possibilities:

- stale metadata leak,
- wrong size,
- wrong object pointer assumption,
- corrupted GUI state leading to controlled crash or bounded memory effect.

Failure modes:

- user-visible copies no longer expose sensitive fields,
- kernel ignores user copy for security decisions,
- synchronization logic changed.

### 4. Reference Count and Locking Bugs

Pattern:

```text
code assumes object is protected
  -> actual protection only covers lookup, not later use
```

Why it works:

```text
lookup lifetime and operation lifetime are not the same thing
```

Primitive possibilities:

- UAF,
- stale tree traversal,
- stale selected-object state,
- use of partially destroyed object.

Failure modes:

- stronger references,
- object lock is held across the risky section,
- callback is moved outside the dangerous lifetime window,
- destruction is deferred safely.

### 5. Integer and Size Bugs in GDI Paths

Pattern:

```text
complex drawing or region operation computes size
  -> integer overflow/truncation/sign issue
  -> allocation and copy/draw length disagree
```

Why it works:

```text
metadata math no longer describes the memory operation
```

Primitive possibilities:

- out-of-bounds read,
- out-of-bounds write,
- pool corruption,
- information leak.

Failure modes:

- checked arithmetic,
- maximum object limits,
- allocation size and operation size are derived from one validated value,
- vulnerable code path moved to user-mode or sandboxed parser.

### 6. GDI Surface / Bitmap / Palette Primitive Construction

Historical pattern:

```text
corrupt or control GDI object metadata
  -> make one object describe memory chosen through another object
  -> use normal GDI API as read/write gadget
```

Why it works:

```text
graphics APIs perform reads/writes through object metadata, so corrupt metadata
can redirect those normal operations
```

Why it is historically important:

- It converted memory corruption into a stable read/write primitive.
- It allowed data-only kernel changes without immediate control-flow hijack.
- It avoided needing direct shellcode execution in many old chains.

Why it is not a modern default:

- Microsoft hardened GDI object internals and pointer exposure.
- Object layouts changed across releases.
- Control-flow mitigations make old payload assumptions weaker.
- Reliable object discovery is harder without leaks.

Research lesson:

```text
learn bitmap/palette as a primitive-construction pattern, not as a universal
modern exploit recipe
```

### 7. Win32k Dispatch or Syscall Machinery Abuse

Some BYOVD research samples use vulnerable driver read/write primitives to
temporarily modify kernel dispatch-related state. Win32k-related dispatch paths
appear in some public lab chains because GUI syscalls can provide a convenient
kernel execution context.

At the concept level:

```text
driver primitive
  -> modify sensitive dispatch-related kernel state
  -> invoke a reachable syscall path
  -> use the transition as a bridge
  -> restore state
```

Why it is fragile:

- dispatch internals are build-specific,
- PatchGuard and integrity checks may notice persistent changes,
- HVCI/Code Integrity changes what can execute,
- kCFG/CET changes control-flow assumptions,
- wrong restoration can crash the system,
- GUI syscall availability depends on process mitigation state.

In this repository, prefer reading this as:

```text
how a primitive can be bridged into an effect
```

not as:

```text
a stable cross-version technique
```

## Primitive Matrix

| Primitive | Win32k route | Bridge needed | Why it is useful | Why it fails |
|---|---|---|---|---|
| Information leak | Shared metadata, stale object fields, uninitialized graphics data | Map leaked value to object/kernel layout | Breaks KASLR or object-location uncertainty | Pointers hidden/encoded, layout changed, leak is only user pointer |
| UAF read/write | Callback or lifetime bug | Reclaim stale object with useful shape | Turns object lifetime bug into memory primitive | Reclaim unreliable, stronger refs, pool hardening |
| Type confusion | USER/GDI handle or object state mismatch | Force confused object state into useful field access | Can become bounded write or leak | Strict type checks and object validation |
| Bounded write | GDI size/metadata issue | Choose targetable field and repeat safely | Data-only changes may be possible | Bounds, alignment, and object discovery fail |
| Bitmap/palette R/W | Historical GDI metadata corruption | Pair objects so normal API reads/writes chosen memory | Converts bug into stable read/write | Modern GDI hardening and pointer hiding |
| Callback-controlled timing | User-mode callback reentrancy | Mutate state at exact unsafe point | Synchronous race-like control | Callback moved, state revalidated, object locked |
| Dispatch bridge | BYOVD write into dispatch-related state | Invoke reachable Win32k/syscall path and restore | Can convert write primitive into execution-like effect | PatchGuard, HVCI, kCFG/CET, version drift |

The important habit:

```text
Do not stop at "arbitrary R/W".
Name the route, bridge, invariant, and failure mode.
```

## Win32k Versus Normal Driver IOCTL Exploitation

| Area | Driver IOCTL research | Win32k research |
|---|---|---|
| Entry point | Device object and `IRP_MJ_DEVICE_CONTROL` | `NtUser*` / `NtGdi*` syscalls through `win32u.dll` |
| Reachability | Device ACL, service load, signer policy | Process mitigation, GUI thread, desktop/session access |
| Object model | Driver-owned structs, WDF objects, executive objects | USER/GDI handles, desktop heap, session objects |
| Common bug | Bad buffer validation, METHOD_NEITHER, arbitrary R/W | Callback reentrancy, object lifetime, GDI metadata |
| Timing | Often direct request/response | Message loops, callbacks, nested GUI operations |
| Exploit bridge | Kernel R/W to token/CI/object field | Object primitive to leak/RW/data-only change |
| Reliability issue | Build offsets, HVCI, blocklist | Layouts, session state, callback reachability, lockdown |

This comparison helps avoid a common mistake: treating Win32k as just another
driver. It is kernel code, but the mental model is different.

## Win32k Lockdown

Windows exposes a process mitigation that can disable Win32k system calls for a
process. The documented policy field is `DisallowWin32kSystemCalls` in
`PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY`.

Conceptually:

```text
process mitigation says no Win32k syscalls
  -> process cannot use the normal USER/GDI kernel syscall surface
  -> many historical sandbox escape routes disappear from that process
```

Why this matters:

- Browser sandboxes and hardened processes often try to reduce Win32k exposure.
- A bug in Win32k may be irrelevant if the attacking process cannot call Win32k.
- Exploit chains may need a non-Win32k bug first, or a brokered path, or a
  different attack surface.

The research question becomes:

```text
Is the vulnerable Win32k path reachable from the threat model's process?
```

Not:

```text
Does the vulnerable code exist somewhere in the OS image?
```

Failure mode:

```text
public PoC assumes normal desktop process
  -> target process has Win32k lockdown
  -> syscall route is blocked
  -> exploit path is not reachable
```

That is why every Win32k note should record process context.

## GUI Thread Requirement

Some Win32k paths require a thread to be converted into or initialized as a GUI
thread. A simple console process and a GUI-heavy process do not always have the
same Win32k state.

Conceptually:

```text
first GUI operation
  -> thread/process gains GUI-related kernel state
  -> subsequent USER/GDI calls have more state available
```

Why this matters:

- A crash may happen only after GUI initialization.
- A path may fail because required per-thread GUI state does not exist.
- A service context may not behave like an interactive desktop process.
- A sandboxed process may intentionally avoid creating GUI state.

Research habit:

```text
record the process type, session, desktop, and whether GUI state is initialized
```

## Session, Window Station, and Desktop

Win32k state is deeply connected to interactive sessions.

| Concept | Why it matters |
|---|---|
| Session | Win32k objects and GUI state are often per-session. Session 0 services differ from interactive sessions. |
| Window station | Groups desktops and controls access to interactive GUI resources. |
| Desktop | Contains windows, hooks, menus, and input routing for a GUI context. |
| Thread input | Threads can have input queues and relationships that affect message routing. |

Exploitability question:

```text
Can the process reach the object graph where the vulnerable state lives?
```

A primitive may be technically valid but practically unreachable from the
wrong session or desktop.

## Reading Public Win32k Writeups

Use this template when reading a public Win32k post:

```text
1. What build is the post about?
2. Which module is involved: win32k.sys, win32kbase.sys, win32kfull.sys?
3. Is the entry USER, GDI, or both?
4. Is the object family window, menu, hook, bitmap, palette, surface, region, DC, or font?
5. Is there a callback/reentrancy boundary?
6. Which invariant is broken?
7. What primitive is obtained?
8. Is there an information leak, or does the post assume one?
9. What bridge turns the primitive into impact?
10. Which mitigations does the bridge rely on being absent or bypassed?
11. What changed in later Windows builds?
12. What part is technique, and what part is version-specific detail?
```

If a public post contains code, read it as evidence for those answers, not as a
universal recipe.

## Deep Reasoning: Why Each Part Exists

### Why `win32u.dll` Matters

Modern user-mode GUI syscalls are exported through `win32u.dll`. From a
research perspective, this tells you where user-mode transitions into kernel
GUI services.

Why:

```text
user32/gdi32 are high-level API layers
  -> win32u exposes lower syscall stubs
  -> kernel side enters win32kbase/win32kfull
```

Do not confuse export names with exploitability. An exported syscall stub only
means there is an entry path. It does not mean the path is reachable under the
target mitigation policy or useful for a primitive.

### Why USER Objects Are Dangerous

USER objects are connected by relationships:

```text
window -> parent/owner -> thread/input queue -> desktop -> window station
```

Why:

```text
relationship-heavy objects create many partial validation bugs
```

Example reasoning:

```text
code validates a child window belongs to a parent
  -> callback changes parent/child state
  -> code resumes with old relationship assumption
```

The precise object may differ, but the reasoning pattern is stable.

### Why GDI Objects Are Dangerous

GDI objects describe memory and drawing operations:

```text
metadata
  -> dimensions
  -> format
  -> backing storage
  -> selected object state
  -> operation length
```

Why:

```text
if metadata becomes inconsistent, normal drawing APIs can touch memory in
unexpected ways
```

That is why bitmap/palette and surface research was historically important:
the exploit did not always need to execute code immediately. It could bend
legitimate graphics operations into a memory primitive.

### Why Callback Reentrancy Is Special

A normal syscall often has this shape:

```text
validate input
  -> perform operation
  -> return
```

A Win32k callback path may have this shape:

```text
validate state
  -> call user mode
  -> user mode changes state
  -> perform operation using old assumption
  -> return
```

The extra user-mode execution window is the exploitability multiplier.

### Why `gSharedInfo` Was So Important

Kernel exploits need knowledge:

```text
where is the object?
what type is it?
when was it reused?
what field changed?
```

Historically, shared Win32k metadata answered too many of those questions from
user mode. That reduced uncertainty and made object-based exploitation much
more reliable.

Modern hardening tries to restore the invariant:

```text
user mode can refer to GUI objects, but should not learn sensitive kernel
locations or mutable kernel-only metadata
```

### Why Bitmap/Palette Is Mostly Historical

The bitmap/palette pattern is still worth learning because it teaches primitive
construction:

```text
corrupt object A
  -> use API on object B
  -> normal kernel code reads/writes target memory
```

But it is mostly historical as a default path because modern Windows changed
the assumptions that made it easy:

- pointer visibility,
- object layout,
- GDI object manager behavior,
- pool behavior,
- control-flow mitigation,
- memory integrity settings.

Research takeaway:

```text
understand the primitive idea, then ask what modern invariant blocks it
```

### Why Win32k Lockdown Works as Attack Surface Reduction

Win32k lockdown is not a memory-corruption mitigation inside Win32k. It is an
attack-surface mitigation.

Why:

```text
if process cannot call Win32k
  -> Win32k bugs are not directly reachable from that process
```

This is powerful for sandboxing because it removes a historically rich kernel
surface from renderer-like processes.

The limitation:

```text
another process may still have Win32k access
```

So the threat model must include process boundary, broker behavior, and whether
the attacker can influence a GUI-capable process.

### Why Hardcoded Offsets Fail

Win32k internals are highly build-sensitive:

- object layouts change,
- fields move,
- private symbols may be incomplete,
- handle-table entry formats change,
- mitigations alter object metadata,
- session-space behavior evolves,
- compiler and CFG instrumentation changes code shape.

Why:

```text
private kernel GUI implementation details are not stable ABI
```

Therefore a good research note should say:

```text
this build had this layout assumption
```

not:

```text
Win32k always has this offset
```

### Why Session Context Can Break a PoC

Win32k is not just memory. It is also interactive state.

A PoC can fail because:

- it runs as a service in Session 0,
- it has no interactive desktop,
- the desktop denies access,
- the thread is not GUI-initialized,
- the process has Win32k syscalls disabled,
- object creation succeeds but the target callback never fires,
- the target path exists only with certain window/message state.

This is why Win32k research needs environment notes, not just offsets.

## Win32k and BYOVD Bridges

Win32k appears in some BYOVD chains not because the vulnerable driver is a GUI
driver, but because Win32k/syscall machinery can become a bridge once a driver
gives kernel memory read/write.

Conceptual bridge:

```text
BYOVD primitive
  -> discover kernel base and relevant module state
  -> modify sensitive kernel data for a short window
  -> invoke a reachable transition path
  -> restore modified state
```

Why a researcher might study this:

- It shows how a primitive is upgraded.
- It demonstrates why arbitrary write is not the same as impact.
- It exposes the role of dispatch machinery, kernel-base discovery, and
  restoration discipline.

Why this repo treats it carefully:

- dispatch modification is fragile,
- persistent tamper can collide with PatchGuard,
- HVCI and Code Integrity change execution assumptions,
- kCFG/CET create control-flow constraints,
- exact syscall/offset details become weaponized quickly and age poorly.

For the Astra64 material in this repository, read the Win32k-related path as a
case study in bridge reasoning:

```text
physical memory primitive
  -> kernel object/module discovery
  -> bridge choice
  -> compare direct data-only object modification vs fragile dispatch path
```

Related local notes:

- `03_byovd/01_physical-memory-rw/ASTRA64_RW_CODE_WALKTHROUGH.md`
- `03_byovd/01_physical-memory-rw/ASTRA64_DIRECT_DKOM_DEEP_DIVE.md`
- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
- `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`

## Win32k Research Workflow

Use this workflow for a public CVE writeup, crash, or suspected Win32k bug.

### Step 1. Name the Surface

Write:

```text
Surface: USER / GDI / mixed
Module: win32kbase / win32kfull / win32k
Entry: NtUser-family / NtGdi-family / callback path / internal worker
Object: window / menu / hook / bitmap / palette / surface / region / DC / font
```

Why:

```text
without object family, primitive reasoning becomes vague
```

### Step 2. Identify Reachability

Write:

```text
Process context:
  - interactive desktop or not
  - GUI thread initialized or not
  - Win32k syscalls disabled or allowed
  - AppContainer/sandbox or normal process
  - session and desktop assumptions
```

Why:

```text
Win32k bugs are often present but not reachable from the process that matters
```

### Step 3. Find the Invariant

Ask:

```text
What did kernel mode believe was true?
```

Examples:

- object is still alive,
- handle still references same type,
- parent/child relationship is stable,
- menu item array did not change,
- backing surface has enough memory,
- selected GDI object is valid,
- user-mode safe copy matches kernel state,
- callback cannot alter the state being used.

Why:

```text
the invariant is the real vulnerability explanation
```

### Step 4. Locate the Time Split

Ask:

```text
Is there a callback, message dispatch, nested syscall, or reentrant operation
between validation and use?
```

Why:

```text
Win32k bugs often live in the gap between validation and resumed kernel use
```

### Step 5. Classify the Primitive

Do not write only "kernel exploit". Write one of:

- info leak,
- stale read,
- stale write,
- bounded write,
- type confusion,
- UAF,
- object metadata corruption,
- GDI API-as-read/write,
- dispatch bridge,
- crash-only.

Why:

```text
the primitive decides the bridge; the bug name does not
```

### Step 6. Identify the Bridge

Ask:

```text
What additional capability turns the primitive into impact?
```

Examples:

- information leak to object address,
- heap shaping to reclaim stale object,
- symbol/layout knowledge,
- writable data-only target,
- repeatable operation,
- stable restoration,
- access to GUI syscall path.

Why:

```text
many Win32k bugs are only useful after a separate bridge is solved
```

### Step 7. Record Failure Modes

Write the reasons it fails:

- wrong build,
- wrong process mitigation,
- wrong session,
- no GUI thread,
- object layout drift,
- callback no longer reachable,
- object held by stronger reference,
- pool behavior changed,
- pointer not leaked,
- kCFG/CET blocks control-flow path,
- HVCI blocks executable-memory assumption,
- PatchGuard notices persistent global tamper.

Why:

```text
failure modes are what make the note reusable on future builds
```

## Practical Debugging Questions

When a Win32k PoC or crash behaves unexpectedly, ask:

```text
Did the process actually enter GUI state?
```

```text
Is Win32k syscall disable policy enabled for this process?
```

```text
Is this running in the same session/desktop assumed by the writeup?
```

```text
Did the object type or handle-table layout change on this build?
```

```text
Is the crash before or after the user-mode callback?
```

```text
Was the object freed, or only detached from the visible relationship?
```

```text
Is the field being observed authoritative kernel state or a user-mode safe copy?
```

```text
Does the primitive require an information leak that the writeup glosses over?
```

```text
Does the bridge assume old GDI bitmap/palette behavior?
```

```text
Is the exploit trying to convert a data primitive into control flow on a system
where control-flow mitigations make that bridge unrealistic?
```

## Failure Mode Catalog

### Build Drift

Symptom:

```text
the same conceptual bug path exists, but the proof-of-concept crashes in a
different place or does nothing
```

Likely reasons:

- object layout changed,
- field moved,
- callback sequence changed,
- compiler emitted different checks,
- object type validation was added,
- pool allocation behavior changed.

Study response:

```text
extract the invariant and primitive; discard stale layout assumptions
```

### Lockdown Blocks Reachability

Symptom:

```text
syscall path is unavailable from the target process
```

Likely reasons:

- process has `DisallowWin32kSystemCalls`,
- sandbox policy blocks GUI syscalls,
- target process intentionally avoids GUI state.

Study response:

```text
record the mitigation as a reachability failure, not as an exploit failure
```

### No Stable Leak

Symptom:

```text
bug can corrupt or stale-read data, but cannot locate a useful target
```

Likely reasons:

- old shared metadata no longer leaks pointers,
- handle table hides sensitive fields,
- KASLR/object randomization is not solved,
- writeup assumed symbols or debug build.

Study response:

```text
separate primitive from address-discovery bridge
```

### Callback No Longer Reentrant Enough

Symptom:

```text
the callback happens, but mutation no longer breaks the resumed kernel path
```

Likely reasons:

- reference held across callback,
- state is revalidated after callback,
- destruction is deferred,
- object is locked across the critical region,
- nested operation is blocked.

Study response:

```text
compare pre-callback and post-callback invariants
```

### Historical GDI Primitive No Longer Works

Symptom:

```text
bitmap/palette-style object manipulation does not produce kernel R/W
```

Likely reasons:

- object fields no longer map the same way,
- pointer fields are protected or hidden,
- GDI manager behavior changed,
- selected-object constraints changed,
- modern mitigations prevent the assumed bridge.

Study response:

```text
learn the primitive-construction idea, then identify the modern block
```

## Safe Lab Documentation Template

Use this for your own Win32k notes:

```text
Title:
Build:
Source writeup:
Surface: USER / GDI / mixed
Module:
Entry family:
Object family:
Process context:
Session/desktop assumption:
Win32k lockdown state:

Invariant:
Why it breaks:
Callback/reentrancy boundary:
Primitive:
Bridge:
Mitigation pressure:
Failure modes:

What changed in newer builds:
What I can verify in WinDbg:
What remains unknown:
Study questions:
```

This keeps the note useful without preserving weaponized trigger details.

## Study Questions

1. Why is validation before a user-mode callback not enough?
2. What is the difference between object lookup lifetime and operation
   lifetime?
3. Why are USER/GDI handles different from ordinary object manager handles?
4. Why did `gSharedInfo` matter historically for exploit reliability?
5. Why does Win32k lockdown reduce attack surface instead of fixing a specific
   memory corruption bug?
6. What makes bitmap/palette primitives useful as a historical learning model?
7. Why does a Win32k bug often require a separate information leak?
8. Why can a public Win32k PoC fail in Session 0 but work in an interactive
   desktop?
9. Why is a GDI metadata bug sometimes more useful than a direct control-flow
   bug under modern mitigations?
10. Why is a dispatch bridge through Win32k fragile in BYOVD chains?
11. How would you separate "bug", "primitive", "bridge", and "objective" in a
   Win32k writeup?
12. Which assumptions in an old Win32k exploit are likely to be build-specific?
13. If a callback bug is patched, what kind of invariant did Microsoft likely
   strengthen?
14. If a post says "arbitrary read/write", what proof would you need before
   trusting that claim?
15. Which exact process and desktop context did the writeup assume?

## Source Map

Primary and high-value references:

- Microsoft Learn,
  [`PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy)
  - documents `DisallowWin32kSystemCalls`.
- Microsoft Learn,
  [`UpdateProcThreadAttribute`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
  - useful for process-creation mitigation context.
- Tarjei Mandt,
  [Kernel Attacks through User-Mode Callbacks](https://media.blackhat.com/bh-us-11/Mandt/BH_US_11_Mandt_win32k_WP.pdf)
  - classic callback/reentrancy study.
- Palo Alto Unit42,
  [Win32k Analysis Part 1](https://unit42.paloaltonetworks.com/win32k-analysis-part-1/)
  and
  [Win32k Analysis Part 2](https://unit42.paloaltonetworks.com/win32k-analysis-part-2/)
  - public Win32k vulnerability analysis examples.
- Blue Frost Security,
  [Abusing GDI for Ring0 Exploit Primitives: Evolution](https://labs.bluefrostsecurity.de/publications/2017/10/02/abusing-gdi-for-ring0-exploit-primitives-evolution/)
  - historical GDI primitive evolution.
- Google Project Zero,
  [Project Zero blog](https://googleprojectzero.blogspot.com/)
  - multiple Windows kernel and Win32k case studies; use posts as examples of
    vulnerability analysis rather than version-independent recipes.
- Microsoft Learn,
  [Microsoft vulnerable driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
  - relevant when Win32k is used as a BYOVD bridge rather than the root bug.

Local repository links:

- `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md`
- `docs/kernel-research/primitive-pseudocode-sketchbook.md`
- `docs/kernel-research/win32k-case-study-atlas.md`
- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
- `docs/kernel-research/io-ring-research-notes.md`
- `docs/kernel-research/hkom-dkom-hide-research-notes.md`
- `docs/kernel-research/public-poc-reading-and-annotation-template.md`
- `docs/kernel-research/offensive-driver-exploitability-map.md`
- `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
- `03_byovd/01_physical-memory-rw/ASTRA64_RW_CODE_WALKTHROUGH.md`
- `03_byovd/01_physical-memory-rw/ASTRA64_DIRECT_DKOM_DEEP_DIVE.md`

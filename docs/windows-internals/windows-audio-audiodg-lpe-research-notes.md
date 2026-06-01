# Windows Audio / audiodg.exe LPE Research Notes

Updated: 2026-05-28

## Classification

This note explains S1lky's article "Abusing Windows Audio for Local Privilege
Escalation" as a Windows internals case study.

Source:

- https://medium.com/@S.1.l.k.y/abusing-windows-audio-for-local-privilege-escalation-1d59440116cb

Local reference copy:

- `90_sources/_temp_audiodg_lpe/`

Classification:

```text
Windows user-mode LPE chain
  -> writable System PATH / arbitrary file-write precondition
  -> audiodg.exe DLL search-order hijack via vendor APO dependency
  -> low-privileged audio endpoint restart primitive
  -> code execution as NT AUTHORITY\LOCAL SERVICE
  -> service-restricted token escape via Task Scheduler privilege restoration
  -> optional SYSTEM bridge through impersonation-style technique
```

It is not:

- BYOVD,
- kernel R/W,
- win32k exploitation,
- DSE bypass,
- PatchGuard bypass,
- a universal Windows vulnerability without preconditions.

The article is interesting because it composes several weak assumptions across
subsystems. No single part is enough by itself.

## One-Screen Mental Model

```text
writable directory is already in System PATH
  -> audiodg.exe inherits AudioSrv environment
  -> vendor APO or dependency is loaded without a fully qualified path
  -> DLL search order reaches writable System PATH directory
  -> audiodg.exe loads attacker-controlled DLL
  -> code runs as LOCAL SERVICE inside audiodg.exe
  -> service token is restricted, so direct impersonation path may fail
  -> Task Scheduler can create a new LOCAL SERVICE process with requested privileges
  -> impersonation-style SYSTEM bridge becomes viable from that less-restricted context
```

The "why" is:

```text
Windows audio is designed to restart audiodg.exe on demand,
and audiodg.exe is a privileged-enough, vendor-extensible process.
```

## Main Preconditions

The chain depends on preconditions. This is the first thing to understand.

| Precondition | Why It Matters |
|---|---|
| A writable directory is in the machine-wide System PATH, or another bug can place a DLL into such a directory | DLL search order becomes attacker-influenced for processes that inherit that PATH |
| The audio stack has a vendor APO or dependency that performs a non-fully-qualified DLL load | The hijack target must actually be searched by name |
| `AudioSrv` / `audiodg.exe` has inherited the relevant environment block | Services do not constantly refresh System PATH from registry |
| Audio endpoint state can be changed by a normal user | This gives a non-admin restart primitive for `audiodg.exe` |
| `audiodg.exe` starts under `LOCAL SERVICE` and loads the relevant APO | The first privilege jump is user -> service account context |
| Task Scheduler can launch a `LOCAL SERVICE` task with explicitly requested privileges | This can produce a less-restricted service-account token than the original service child |
| A SYSTEM bridge is possible from the restored service-account context | The final jump is not from audio itself; it depends on impersonation mechanics |

Without the writable path or file-write precondition, the chain has no payload
placement point. Without a vulnerable audio dependency, the placement point is
not consumed. Without the endpoint restart primitive, the classic path needs a
reboot or privileged service restart.

## Actors And Components

### `AudioSrv`

`AudioSrv` is the Windows Audio service hosted in `svchost.exe`.

Role:

```text
session and policy coordinator
  -> manages audio sessions
  -> launches/supervises audiodg.exe
  -> does not perform the heavy audio processing itself
```

Why it matters:

```text
audiodg.exe is started by AudioSrv
  -> child process inherits the service account and environment block
```

If `AudioSrv` inherited a System PATH that includes a writable directory, then
child processes such as `audiodg.exe` may inherit the same environment.

Important nuance:

```text
updating System PATH in the registry does not automatically update already
running service environment blocks
```

This is why writable System PATH entries that already existed before service
startup are more useful than entries added later.

### `audiodg.exe`

`audiodg.exe` is Windows Audio Device Graph Isolation.

Role:

```text
audio graph processing
  -> mixes streams
  -> hosts effects and enhancements
  -> isolates third-party audio processing from AudioSrv
```

Microsoft's audio architecture intentionally isolates audio graph processing so
that failures in effects or vendor processing do not crash the core service.
This isolation improves stability but also creates a service-owned process that
loads extensibility code.

Why it matters for the article:

```text
audiodg.exe can load vendor APO-related DLLs
  -> those DLLs may load dependencies
  -> dependency search can hit System PATH
```

This is not an `audiodg.exe` memory corruption bug. It is a DLL search-order
and environment-trust problem.

### Audio Processing Objects

Audio Processing Objects, or APOs, are user-mode COM-style audio effect
components. Microsoft documents APOs as DLL-based in-process objects used for
stream, mode, and endpoint effects.

Why they matter:

```text
vendor audio enhancement code runs inside the audio graph process
```

The article's example uses Realtek-related APO behavior. The exact DLL name and
dependency chain are hardware and driver dependent, so do not treat the specific
file names in the article as universal.

The invariant:

```text
vendor APO dependency loads should not be controllable by low-privileged users
```

If a vendor APO loads a dependency by name rather than by a trusted fully
qualified path, the Windows DLL search order can become part of the trust
boundary.

### APO Load Shape

The useful mental model is:

```text
audio endpoint
  -> endpoint effects / vendor enhancement configuration
  -> APO COM object
  -> APO DLL loaded into audiodg.exe
  -> APO DLL resolves its own dependencies
```

The vulnerable behavior is usually not that the APO itself is malicious. The
fragile part is dependency resolution:

```text
trusted APO DLL
  -> asks loader for dependency by name
  -> loader searches process search path
  -> writable PATH directory can win
```

Why this distinction matters:

- the APO may be signed and legitimate;
- the dependency name may be optional or vendor-specific;
- the unsafe load can be inside vendor code rather than Microsoft code;
- different audio drivers produce different dependency graphs.

So the right research wording is:

```text
audiodg.exe hosts a vendor extensibility graph whose dependency search may be
attacker-influenced on some systems
```

not:

```text
audiodg.exe always loads attacker DLLs
```

### `AudioEndpointBuilder`

`AudioEndpointBuilder` handles endpoint enumeration and lifecycle.

Why it matters:

```text
endpoint availability affects whether audiodg.exe needs to stay alive
```

If no usable render endpoint exists, the audio graph can become unnecessary.
That gives the researcher a way to make `audiodg.exe` exit naturally without
killing the service directly.

### MMDevice API

The documented MMDevice API lets applications enumerate audio endpoint devices
and query their state. Microsoft documents `IMMDeviceEnumerator` as the starting
interface for discovering endpoint devices.

Why it matters:

```text
MMDevice gives read/discovery visibility into audio endpoints
```

By itself, this is not the write primitive used by the article. It is mainly the
enumeration side of the story.

### `IPolicyConfig`

`IPolicyConfig` is an undocumented COM interface used by Windows audio policy
components. The article uses it as the write side for endpoint policy.

Conceptually:

```text
MMDevice API
  -> enumerate/query endpoint state

IPolicyConfig
  -> change endpoint policy such as visibility/enabled state
```

The interesting property is that endpoint visibility changes can be performed
without administrative rights on the tested builds. This is legitimate product
functionality used by Windows settings/control-panel style flows.

The broken assumption is not "users can change their audio devices." That is
expected. The problem is the composition:

```text
normal user can change endpoint visibility
  -> endpoint state affects audiodg.exe lifetime
  -> audiodg.exe restart triggers DLL load
```

## The DLL Search-Order Primitive

The first technical primitive is a classic one:

```text
process loads a DLL by name
  -> search order includes PATH directories
  -> one PATH directory is writable by the attacker
  -> attacker controls the DLL that gets loaded
```

For this case, the sensitive process is not a random desktop app. It is
`audiodg.exe`, running under a service account.

Why this is powerful:

```text
low-privileged user controls file contents
  -> service-context process loads that file
  -> user gains code execution in service account context
```

This is not magic privilege escalation. It is a trust mismatch:

```text
the service trusts its environment and dependency search path
but the environment includes a user-writable location
```

### Loader Invariant

The Windows loader has a deterministic search algorithm, but deterministic does
not mean safe. It is safe only if every searched location is trusted for the
security context of the loading process.

The invariant should be:

```text
service-context process search path
  -> contains only service-context-trusted directories
```

If a normal user can write into a directory that a service-context process uses
for DLL search, the trust boundary has already been weakened.

The dependency name is just the trigger. The root bug is:

```text
writable path is in a privileged process's DLL search graph
```

## Why System PATH Matters

There are two different PATH ideas:

```text
user PATH
machine/System PATH
```

The article is about machine-wide System PATH because services inherit the
machine environment. A writable user PATH is usually not enough for a service
process that does not inherit the interactive user's environment.

Important nuance:

```text
services inherit an environment block when they start
```

If a new System PATH entry is added after `AudioSrv` is already running,
`audiodg.exe` may still inherit the old environment from `AudioSrv`. That is why
the article distinguishes between:

- a writable System PATH that already existed before service startup;
- changing System PATH later and needing a service restart or reboot;
- using another arbitrary file-write/copy primitive to place a DLL into an
  already-relevant directory.

### Path Timing

The timing model is:

```text
machine environment in registry
  -> service control manager / service host receives environment
  -> AudioSrv runs with that environment
  -> AudioSrv starts audiodg.exe
  -> audiodg.exe inherits from AudioSrv
```

That means there are two separate questions:

1. Is the machine PATH unsafe in the registry?
2. Did the relevant service process actually inherit that unsafe value?

This is a common source of confusion in service-context DLL hijacking. A path
that appears in the registry may not be live in the already-running service's
environment block.

## The audiodg.exe Restart Primitive

The article's key contribution is the restart primitive.

Classic DLL hijack exploitation often needs:

```text
plant DLL
  -> wait for reboot or restart privileged service
  -> target process loads DLL
```

That is slow and often requires privileges. The audio trick makes the restart
more controllable:

```text
disable active render endpoints
  -> audio graph becomes unnecessary
  -> audiodg.exe exits after a timeout
  -> re-enable endpoint and play/use audio
  -> AudioSrv starts audiodg.exe again
  -> audiodg.exe initializes APOs and dependency loads
```

Why this works:

```text
audiodg.exe is demand-started based on audio graph need
```

Why endpoint visibility matters:

```text
if no active render endpoint exists,
there may be no graph to process
```

This is not process termination by privilege. It is lifecycle steering through a
legitimate audio policy surface.

## Why The Endpoint Trick Is Not The Vulnerability By Itself

Low-privileged users changing audio endpoints is normal Windows behavior. The
restart primitive becomes security-relevant only when combined with the DLL
search-order issue.

In isolation:

```text
user toggles audio endpoint
  -> audio breaks or restarts
  -> nuisance / normal setting change
```

In the chain:

```text
user toggles endpoint
  -> audiodg.exe restarts
  -> service-context process loads attacker-controlled dependency
```

The exploitability comes from composition.

## First Privilege Transition: User To LOCAL SERVICE

After the dependency is loaded, code runs inside `audiodg.exe`.

Security context:

```text
NT AUTHORITY\LOCAL SERVICE
```

That is already a privilege change from a normal user:

```text
interactive user
  -> service account context
```

But it is not yet SYSTEM.

Why LOCAL SERVICE is interesting:

- it is a built-in service account;
- it can have service-account privileges not available to a normal user;
- some historical LPE patterns use service accounts plus impersonation;
- but modern service hardening can heavily restrict what the token can do.

## Service-Restricted Token Problem

The article reports that a direct impersonation-style escalation did not work
from the original `audiodg.exe` context even though the privilege list looked
promising.

This is the crucial lesson:

```text
seeing a privilege name in a token is not the same as having an unrestricted,
usable security context for every object and RPC/named-pipe path
```

`AudioSrv` is hosted under a hardened LocalService service group. Its child
`audiodg.exe` inherits service-hardening restrictions.

Service hardening can involve:

- service SID restrictions;
- write-restricted tokens;
- reduced object namespace access;
- networking restrictions;
- privilege filtering;
- process token DACL differences.

So the failed bridge is not surprising:

```text
LOCAL SERVICE inside service-restricted audiodg.exe
  -> not equivalent to a clean LOCAL SERVICE logon token
```

The article's "why did GodPotato fail?" answer is basically:

```text
the token context is too restricted for the expected impersonation mechanics
```

## Task Scheduler Privilege Restoration

The next bridge is Task Scheduler.

Microsoft documents Task Security Hardening. The relevant idea is that Task
Scheduler can launch tasks under built-in service accounts and can shape the
task process token using required privileges and token SID type.

The article uses this to create a new process as `LOCAL SERVICE` with a less
restricted privilege set than the inherited `audiodg.exe` child token.

Conceptual chain:

```text
code in restricted LOCAL SERVICE process
  -> asks Task Scheduler to run a LOCAL SERVICE task
  -> task definition requests specific required privileges
  -> Task Scheduler creates a fresh task process token
  -> new process has privileges needed for impersonation-style bridge
```

Why this matters:

```text
the escape is not "audiodg.exe becomes SYSTEM"
```

More accurate:

```text
audiodg.exe gives code execution as restricted LOCAL SERVICE
Task Scheduler creates a different LOCAL SERVICE process
that process has the right token shape for the next bridge
```

This distinction matters because it tells you where each invariant breaks.

### Token Shape Comparison

| Token context | Why it appears | Security meaning |
|---|---|---|
| Original interactive user | Starting point | No service-account privileges |
| `audiodg.exe` as `LOCAL SERVICE` | DLL loaded inside audio graph process | Service account, but inherited service hardening can block later bridges |
| Scheduled task as `LOCAL SERVICE` | Task Scheduler creates a new task process | Same built-in account, but a different token construction path |
| SYSTEM after impersonation bridge | Separate impersonation primitive | Not provided directly by Windows Audio |

The key lesson:

```text
account name
  != token shape
```

Two processes can both say `LOCAL SERVICE` and still have different usable
privileges, groups, restrictions, and object access.

## Final SYSTEM Bridge

The final SYSTEM step in the article relies on an impersonation-style technique
from a service-account context after the Task Scheduler token shaping.

At a high level:

```text
service-account process with usable impersonation privileges
  -> coerces or receives authentication from SYSTEM-owned component
  -> impersonates duplicated SYSTEM token
  -> launches chosen child operation as SYSTEM
```

The important research point:

```text
Windows Audio is not directly granting SYSTEM
```

Windows Audio provides:

```text
restartable service-account DLL loading context
```

Task Scheduler provides:

```text
less-restricted LOCAL SERVICE token
```

The impersonation bridge provides:

```text
SYSTEM token transition
```

Treat these as three separate primitives.

## PoC Repository Static Reading Notes

Local copy:

- `90_sources/_temp_audiodg_lpe/`

The repo has four relevant artifacts:

| File | Role | Research classification |
|---|---|---|
| `README.md` | Describes the upstream workflow | Operational overview; do not treat as defensive documentation |
| `audio_disable_debug.cpp` | Endpoint controller source | Restart primitive implementation |
| `audio_disable_debug_x64.exe` | Prebuilt controller binary | Do not trust or run in analysis notes |
| `Hijack.cpp` | Example DLL payload | Operational payload stub; useful only to identify intended bridge |
| `windows_audio_device_control.pdf` | Additional upstream notes | Supporting reference |

### `audio_disable_debug.cpp`

This file is the cleanest part of the repo to study because it implements the
audio endpoint lifecycle primitive without needing kernel code.

Main blocks:

| Code area | Purpose | Why it exists |
|---|---|---|
| property-key definitions | names for endpoint friendly-name fields | MinGW compatibility and readable debug output |
| `PrintHResult` | explains COM/API failures | makes unsupported interface and access-denied conditions obvious |
| `PrintDeviceState` | decodes endpoint state flags | separates active/disabled/not-present/unplugged endpoint states |
| `IPolicyConfig` definition | local declaration of undocumented audio policy interface | lets the tool call endpoint visibility control |
| `DeviceInfo` | local endpoint record | keeps ID, friendly name, description, and state together |
| `StateFile` | stores endpoint IDs in temp state | remembers exactly which active devices were changed |
| `AudioDeviceController` | COM and endpoint orchestration | owns MMDevice enumeration and policy changes |
| `wmain` | command dispatcher | maps high-level modes to controller actions |

#### Property Keys

The file manually defines property keys for friendly names and device
descriptions. This is not part of the exploit primitive. It is usability code:

```text
endpoint ID is opaque
friendly name makes debug output understandable
```

Why it matters:

The endpoint ID is what the policy interface needs, but the human researcher
needs a way to know which endpoint is being changed.

#### `IPolicyConfig`

The file declares an undocumented interface locally because the SDK does not
provide a stable public header for the write-side policy interface used here.

Conceptual role:

```text
documented MMDevice API
  -> tells you what endpoints exist

undocumented policy interface
  -> changes endpoint visibility
```

Why the fallback interface exists:

The code tries a newer interface first, then a Vista-era interface shape. That is
version-tolerance engineering. It does not make the primitive universal; it only
helps the tool survive interface differences across builds.

#### `StateFile`

`StateFile` writes the IDs of endpoints that were active before the disable
operation. This is important for reliability:

```text
disable only active endpoints
save their IDs
restore the same IDs later
```

Why this is better than blindly enabling everything:

- some endpoints were already disabled by the user;
- some endpoints are unplugged or not present;
- a reliable test should restore only what it changed;
- rollback state reduces accidental lab disruption.

This is also a useful research pattern: if a PoC changes host state, track the
original state.

#### `AudioDeviceController`

This class does the real endpoint work.

Constructor flow:

```text
initialize COM apartment
  -> create MMDevice enumerator
  -> create PolicyConfig client
  -> mark controller initialized
```

Why COM apartment initialization matters:

MMDevice and PolicyConfig are COM surfaces. Without COM initialization, object
creation and interface calls fail before the audio logic begins.

Enumeration flow:

```text
enumerate render endpoints
  -> collect ID
  -> collect state
  -> collect readable properties
```

The tool enumerates all render endpoint states, not only active endpoints, so it
can produce a complete debug picture. It only changes active endpoints during
the disable operation.

Disable flow:

```text
filter active render endpoints
  -> save active endpoint IDs
  -> set endpoint visibility false for each saved endpoint
```

Enable flow:

```text
load saved endpoint IDs
  -> set endpoint visibility true
  -> delete state file if restore succeeds
```

The security role of this file is narrow:

```text
it creates a low-privileged lifecycle trigger for audiodg.exe
```

It does not place a DLL, exploit a memory bug, or perform the SYSTEM bridge.

### `Hijack.cpp`

This file is an example payload stub. It demonstrates what the upstream author
wanted to happen after the DLL is loaded inside `audiodg.exe`: use the service
account context to reach Task Scheduler and launch the next stage.

Do not treat it as a clean engineering pattern.

Why:

- it performs heavy work from DLL process-attach context;
- DLL process attach runs under loader-lock-sensitive conditions;
- spawning interpreters or calling complex APIs from `DllMain` is brittle;
- the file is operational payload glue, not a robust loader design.

The conceptual value is only:

```text
DLL load in audiodg.exe
  -> service-account code execution
  -> Task Scheduler token-shaping bridge
```

The implementation details are intentionally not repeated here.

### Prebuilt Binary

The repo includes a prebuilt endpoint-controller executable. For research notes,
prefer source review over running prebuilt binaries.

Reason:

```text
prebuilt binary
  -> opaque behavior and lab side effects

source review
  -> auditable primitive model
```

## Source-Level Dataflow

The endpoint controller's dataflow is:

```text
COM init
  -> create endpoint enumerator
  -> enumerate render endpoints
  -> record endpoint IDs and states
  -> select active endpoints
  -> persist selected IDs
  -> change endpoint visibility
  -> later restore persisted IDs
```

The exploit-chain dataflow is broader:

```text
unsafe DLL search graph
  + endpoint restart primitive
  + service-account token bridge
  -> LPE chain
```

Keep those separate. The endpoint controller is only one part of the full chain.

## Why The Code Saves Only Active Devices

The code does not disable every endpoint it can see. It filters for active render
devices.

Why:

```text
active render endpoint
  -> likely contributes to audiodg.exe being needed

disabled / unplugged / not-present endpoint
  -> not useful for forcing the active graph away
```

This is both cleaner and more reliable. It minimizes unrelated state changes and
focuses on the condition needed for the restart primitive.

## Why The Tool Uses Endpoint Visibility

The policy interface does not "kill `audiodg.exe`." It changes endpoint
visibility. The process exit is an indirect consequence:

```text
endpoint hidden or unavailable
  -> no active render graph remains
  -> audio graph process becomes idle / unnecessary
  -> process exits after normal lifecycle handling
```

That is why this technique is subtle: it uses normal product lifecycle behavior
as a trigger.

## Why The Payload Uses Task Scheduler

The payload side uses Task Scheduler because raw code execution in
`audiodg.exe` is not enough for the final objective. The inherited service token
is too constrained for some common impersonation bridges.

Conceptually:

```text
audiodg.exe token
  -> proves service-account code execution
  -> may be too restricted for final bridge

scheduled task token
  -> same account family
  -> constructed through another OS broker
  -> can carry requested privileges differently
```

The lesson for exploit analysis:

```text
LPE chains often need token normalization before final elevation
```

The first elevated context is not always the final useful context.

## End-To-End Primitive Map

| Stage | Primitive | Broken Invariant |
|---|---|---|
| Placement | writable machine PATH or arbitrary file-write into searched location | service search paths should not include attacker-writable directories |
| Load | unqualified APO dependency load | service-context dependency resolution should be deterministic and trusted |
| Trigger | endpoint visibility changes restart `audiodg.exe` | benign lifecycle control composes with unsafe dependency loading |
| First context | DLL code runs inside `audiodg.exe` | user-controlled code should not run in service audio graph |
| Token issue | original token is service-restricted | visible privilege names do not guarantee useful impersonation |
| Token restoration | scheduled task as service account with required privileges | task engine can mint a different token shape for the same service account |
| SYSTEM bridge | impersonation-style technique | service-account impersonation privileges can become SYSTEM transition |

## Why This Is Not "Just DLL Hijacking"

The DLL hijack is old. The article's value is the trigger and bridge:

```text
classic DLL hijack
  -> often requires reboot or privileged service restart

audio endpoint lifecycle
  -> gives low-privileged on-demand restart of audiodg.exe
```

And:

```text
LOCAL SERVICE code execution
  -> often blocked by service restrictions

Task Scheduler hardening behavior
  -> can create a cleaner service-account token if configured that way
```

So the research contribution is composition, not a new memory corruption bug.

## Why The Specific APO/DLL Is Not Universal

The article observed one Realtek-related dependency on the tested host. That is
not guaranteed elsewhere.

This depends on:

- audio hardware,
- OEM driver package,
- APO registration,
- endpoint effect configuration,
- installed enhancement software,
- Windows build and driver version.

The general research question is:

```text
which DLL dependencies does audiodg.exe attempt to resolve from PATH on this
specific host?
```

The answer is host-specific.

## Failure Modes

Common reasons the chain fails:

- no writable machine-wide System PATH directory;
- the writable directory was added after service startup and is not in the
  inherited service environment;
- no vulnerable vendor APO/dependency exists;
- DLL search path behavior is hardened by the vendor package;
- audiodg.exe does not restart because an endpoint remains active;
- endpoint visibility changes are blocked or unavailable;
- the loaded DLL crashes and the APO is disabled after repeated failures;
- service-restricted token blocks direct impersonation;
- Task Scheduler policy, hardening, or monitoring blocks the token-restoration
  bridge;
- the impersonation-style SYSTEM bridge is patched, blocked, or cannot find a
  suitable SYSTEM authentication path.

## Defensive Reasoning

High-signal observations:

```text
audiodg.exe loads a DLL from outside Windows/OEM trusted directories
```

```text
non-audio user process repeatedly toggles endpoint visibility
```

```text
audiodg.exe exits and restarts shortly before unusual service-account activity
```

```text
LOCAL SERVICE creates or starts a scheduled task with unusual required privileges
```

```text
service-account process attempts impersonation-style behavior after audiodg.exe
dependency load
```

Hardening questions:

- Are all machine-wide PATH directories non-writable by standard users?
- Do vendor APO DLLs load dependencies by fully qualified trusted paths?
- Are unexpected DLL loads from `audiodg.exe` blocked or logged?
- Are audio endpoint state changes from unusual callers monitored?
- Are scheduled tasks by built-in service accounts baselineable?
- Are service-account tasks with explicit privilege arrays rare enough to alert?

## Study Questions

1. Why is a writable System PATH entry more dangerous than a writable user PATH
   entry for service-context hijacking?
2. Why does `audiodg.exe` inherit the environment from `AudioSrv`?
3. Why does changing endpoint visibility restart `audiodg.exe` without directly
   killing the service?
4. Why does code execution as `LOCAL SERVICE` not automatically mean SYSTEM?
5. Why can a scheduled task create a different token shape than the original
   service child process?
6. Why is the Realtek dependency in the article a host-specific example rather
   than a universal exploit target?
7. Which invariant is most important: trusted PATH, fully qualified DLL loads,
   endpoint lifecycle control, or token hardening?

## References

- S1lky, "Abusing Windows Audio for Local Privilege Escalation":
  https://medium.com/@S.1.l.k.y/abusing-windows-audio-for-local-privilege-escalation-1d59440116cb
- S1lky PoC repository:
  https://github.com/S1lkys/AudioDG.exe-DLL-Hijacking-for-LPE
- Microsoft, Implementing Audio Processing Objects:
  https://learn.microsoft.com/windows-hardware/drivers/audio/implementing-audio-processing-objects
- Microsoft, About MMDevice API:
  https://learn.microsoft.com/windows/win32/coreaudio/mmdevice-api
- Microsoft, DEVICE_STATE_XXX constants:
  https://learn.microsoft.com/windows/win32/coreaudio/device-state-xxx-constants
- Microsoft, Dynamic-link library search order:
  https://learn.microsoft.com/windows/win32/dlls/dynamic-link-library-search-order
- Microsoft, Task Security Hardening:
  https://learn.microsoft.com/windows/win32/taskschd/task-security-hardening
- Microsoft, RequiredPrivileges element:
  https://learn.microsoft.com/windows/win32/taskschd/taskschedulerschema-requiredprivileges-requiredprivilegestype-element
- itm4n, "Give Me Back My Privileges! Please?":
  https://itm4n.github.io/localservice-privileges/

# S12Deff Medium Source Map

Updated: 2026-05-28

## Purpose

This document maps public S12Deff Medium material into this repository's research
taxonomy. It is not a code mirror and it does not copy exploit programs. The goal
is to turn public writeups into:

- primitive classification,
- violated invariant,
- bridge from primitive to impact,
- failure mode,
- local reading path.

Medium direct page fetching was inconsistent during review. The newest posts were
visible through RSS/profile snippets, and older posts were found through public
search indexes. Treat this as a public-indexed source map, not a guarantee that
every S12Deff post ever published is present.

Primary profile/source:

- [S12 - 0x12Dark Development on Medium](https://medium.com/@s12deff)
- [S12Deff Medium RSS feed](https://medium.com/feed/@s12deff)

## How To Use This Map

For each article, read in this order:

```text
article title
  -> what primitive is being shown?
  -> what Windows subsystem owns the invariant?
  -> what bridge turns primitive into effect?
  -> what assumptions are build-specific?
  -> what local doc explains the internals?
```

Do not read these articles as copy-paste code sources. Several posts include
runnable code, hardcoded values, or direct tamper logic. In this repo, extract the
conceptual model and keep implementation details in a separate private lab notebook
if you are authorized to test them.

## Category Map

### 1. Kernel Callback And Telemetry Tamper

This group sits closest to:

- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`
- `03_byovd/00_index-and-matrix/BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`
- `docs/kernel-research/callback-surfaces.md`
- `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
- `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`

#### Overwriting Process Creation Kernel Callbacks

Source:

- [Overwriting Process Creation Kernel Callbacks](https://medium.com/@s12deff/overwriting-process-creation-kernel-callbacks-8c9f73980eb7)

Classification:

```text
BYOVD kernel write
  -> process-notification callback state
  -> EDR/AV process-birth visibility tamper
```

Why it matters:

Process creation is one of the earliest points where a security product can build
lineage. If that callback path is weakened, later telemetry may still exist, but
the clean birth event can be missing or desynchronized.

Local deep dive:

- `03_byovd/00_index-and-matrix/BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`

#### Enumerating Process Creation Kernel Callbacks

Source status:

- Referenced by the overwrite article as the preceding article.
- Public search/profile snippets show the same article chain, but direct discovery
  of a stable standalone URL was inconsistent during this pass.

Classification:

```text
kernel read
  -> callback inventory
  -> owner attribution
```

Why it matters:

Enumeration is the read-side version of the callback problem. It teaches how to
reason about "who is watching" before any mutation is considered.

Local reading:

- `docs/kernel-research/callback-surfaces.md`
- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`

#### Kernel Event Monitor

Source:

- [Kernel Event Monitor](https://medium.com/@s12deff/kernel-event-monitor-0348cd88fcae)

Classification:

```text
driver learning
  -> process/thread/image callback registration
  -> event monitor
```

Why it matters:

This is the clean-side version of the same callback families. Before studying
tamper, understand how legitimate drivers register, run, and unregister callbacks.

Local reading:

- `docs/kernel-research/callback-surfaces.md`

#### Kernel Process Event Monitor

Source:

- [Kernel Process Event Monitor](https://medium.com/@s12deff/kernel-process-event-monitor-eb3776bba590)

Classification:

```text
driver learning
  -> process callback registration
  -> lifecycle observer
```

Why it matters:

This is a minimal process-callback example. It is useful because it isolates the
lifetime contract: register, receive event, unregister before unload.

Local reading:

- `docs/kernel-research/callback-surfaces.md`

#### Detecting Remote Thread Creation With Windows Driver

Source:

- [Detecting Remote Thread Creation with Windows Driver](https://medium.com/@s12deff/detecting-remote-thread-creation-with-windows-driver-9901fdbaf7b1)

Classification:

```text
thread callback
  -> creator context versus target process
  -> remote-thread visibility
```

Why it matters:

The core invariant is that thread creation includes both the target process and
the creator execution context. If those disagree, the event can represent
cross-process thread creation.

Local reading:

- `docs/kernel-research/callback-surfaces.md`
- `docs/windows-internals/eprocess-token-object-model.md`

#### Building A Windows File System Minifilter Driver

Source:

- [Building a Windows File System Minifilter Driver: Intercepting File Access](https://medium.com/@s12deff/building-a-windows-file-system-minifilter-driver-intercepting-file-access-55b933ccd6a4)

Classification:

```text
Filter Manager learning
  -> minifilter registration
  -> file I/O pre/post operation callbacks
```

Why it matters:

This is the clean-side companion for file-telemetry tamper. You need the normal
Filter Manager model before unlinking or patching discussions make sense.

Local reading:

- `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
- `docs/kernel-research/callback-surfaces.md`

#### Silencing EDR File Telemetry: MiniFilter Callback Unlinking

Source:

- [Silencing EDR File Telemetry: MiniFilter Callback Unlinking](https://medium.com/@s12deff/silencing-edr-file-telemetry-minifilter-callback-unlinking-fe215b009d72)

Classification:

```text
BYOVD kernel write
  -> Filter Manager callback/list state
  -> file I/O observer path tamper
```

Why it matters:

This is not "file invisibility." It is a study of what happens when one filter
path no longer receives expected operations.

Local reading:

- `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`

#### Building A Windows Network Filter Driver

Source:

- [Building a Windows Network Filter Driver: Intercepting Outbound Connections](https://medium.com/@s12deff/building-a-windows-network-filter-driver-intercepting-outbound-connections-b604c366008c)

Classification:

```text
WFP learning
  -> callout registration
  -> outbound network event observation
```

Why it matters:

This is the clean-side model for WFP. It explains why callout registration and
classify paths are valuable telemetry points.

Local reading:

- `docs/detection-and-mitigation/driver-evasion-pressure-map.md`

#### Silencing EDR Network Telemetry: WFP Callout Patching Via BYOVD

Source:

- [Silencing EDR Network Telemetry: WFP Callout Patching via BYOVD](https://medium.com/@s12deff/silencing-edr-network-telemetry-wfp-callout-patching-via-byovd-1f9ee7ed0e67)

Classification:

```text
BYOVD kernel write
  -> WFP callout/classify state
  -> network telemetry path tamper
```

Why it matters:

The violated invariant is that a registered network callout still points to the
callout logic that the owning driver expects.

Local reading:

- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`
- `docs/detection-and-mitigation/driver-evasion-pressure-map.md`

#### Silencing ETW Threat Intelligence Via BYOVD

Source:

- [Silencing ETW Threat Intelligence via BYOVD](https://medium.com/@s12deff/silencing-etw-threat-intelligence-via-byovd-c2ba9e3bb072)

Classification:

```text
BYOVD kernel write
  -> ETW Threat Intelligence provider state
  -> kernel-native behavior event degradation
```

Why it matters:

ETW Threat Intelligence is not merely a third-party callback. It is kernel-native
behavior telemetry. Tamper here is closer to OS telemetry state mutation than
product callback removal.

Local reading:

- `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`
- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`

### 2. BYOVD Primitive Chain And Kernel State Modification

This group sits closest to:

- `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
- `03_byovd/00_index-and-matrix/BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`
- `03_byovd/00_index-and-matrix/BYOVD_CASE_GDRV.md`
- `docs/kernel-research/runtime-pdb-symbol-resolution.md`
- `docs/mitigations/dse-code-integrity-research-notes.md`

#### Exploiting A Kernel Read/Write Primitive Using BYOVD

Source:

- [Exploiting a Kernel Read/Write Primitive using BYOVD](https://medium.com/@s12deff/exploiting-a-kernel-read-write-primitive-using-byovd-977d7b7dfc01)

Classification:

```text
signed vulnerable driver
  -> arbitrary kernel read/write primitive
  -> bridge candidate for later object/state tamper
```

Why it matters:

This is the base layer for many later articles. It explains the difference between
"driver loaded" and "primitive obtained."

Local reading:

- `03_byovd/00_index-and-matrix/BYOVD_CASE_GDRV.md`
- `03_byovd/00_index-and-matrix/BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`

#### Abusing A Vulnerable Driver To Gain Arbitrary Kernel R/W And Bypass PPL

Source:

- [Abusing a vulnerable driver BYOVD to gain arbitrary kernel R/W and bypass PPL protection](https://medium.com/@s12deff/abusing-a-vulnerable-driver-byovd-to-gain-arbitrary-kernel-r-w-and-bypass-ppl-protection-571552c7efc8)

Classification:

```text
kernel R/W
  -> protected-process metadata
  -> PPL state manipulation
```

Why it matters:

This shows a classic data-only bridge: no kernel shellcode is needed if the target
object already contains a security decision field.

Local reading:

- `docs/windows-internals/eprocess-token-object-model.md`
- `03_byovd/00_index-and-matrix/BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`

#### Demonstrating Windows Defender Evasion Via PPL Manipulation

Source:

- [Demonstrating Windows Defender Evasion via PPL Manipulation](https://medium.com/@s12deff/demonstrating-windows-defender-evasion-via-ppl-manipulation-8767f1ee7ad9)

Classification:

```text
kernel object metadata change
  -> process protection-level inconsistency
  -> remediation pressure change
```

Why it matters:

This is another example of semantic object modification: the field is small, but
the policy effect is large because the kernel consults that state during access
decisions.

Local reading:

- `docs/windows-internals/eprocess-token-object-model.md`
- `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md`

#### Windows PPL Protected Processes Light

Source:

- [Windows PPL (Protected Processes Light)](https://medium.com/@s12deff/windows-ppl-protected-processes-light-e158332aedca)

Classification:

```text
Windows internals primer
  -> process protection hierarchy
  -> signer/type/audit policy reasoning
```

Why it matters:

This is the foundation article for the PPL series. The key learning point is that
PPL is enforced from kernel process metadata and access checks, so user-mode
privilege alone does not explain which handles or operations are allowed.

Local reading:

- `docs/windows-internals/eprocess-token-object-model.md`
- `docs/windows-internals/object-manager-and-handle-tables.md`

#### Discovering PPL Protection In Windows Processes

Source:

- [Discovering PPL Protection in Windows Processes](https://medium.com/@s12deff/discovering-ppl-protection-in-windows-processes-2328ba4608e5)

Classification:

```text
kernel read
  -> process protection metadata
  -> PPL inventory
```

Why it matters:

This is read-side object inspection. It does not change protection state; it maps
which process object metadata explains observed access behavior.

Local reading:

- `docs/kernel-research/runtime-pdb-symbol-resolution.md`
- `docs/kernel-research/kernel-object-layout-drift.md`
- `docs/windows-internals/eprocess-token-object-model.md`

#### Disabling PPL Protection On Windows Processes

Source:

- [Disabling PPL Protection on Windows Processes](https://medium.com/@s12deff/disabling-ppl-protection-on-windows-processes-0cb77a065939)

Classification:

```text
kernel write
  -> process protection metadata
  -> access-control behavior change
```

Why it matters:

This is the write-side counterpart to PPL inventory. The important academic lesson
is data-only policy mutation: a small metadata change can alter many later access
decisions because the kernel consults that metadata.

Local reading:

- `docs/windows-internals/eprocess-token-object-model.md`
- `03_byovd/00_index-and-matrix/BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`
- `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`

#### PPL Reaper

Source:

- [PPL Reaper](https://medium.com/@s12deff/ppl-reaper-66b380f0662f)

Classification:

```text
PPL tooling article
  -> inspect/manipulate protection metadata
  -> process policy-state workflow
```

Why it matters:

Treat this as a tooling wrapper around the PPL object-metadata idea, not a new
primitive. The underlying invariant is still process protection state inside the
kernel object model.

Local reading:

- `docs/windows-internals/eprocess-token-object-model.md`
- `docs/research-index/technique-writing-standard.md`

#### Weaponizing PPL For Process Immortality

Source status:

- Public Medium list/search snippets reference this article in S12Deff's
  "Windows PPL Evasion" list, but a stable article URL was not confirmed during
  this pass.

Classification:

```text
process protection metadata
  -> remediation resistance
  -> process lifetime pressure
```

Why it matters:

This appears to be the "raise protection instead of lowering protection" side of
the PPL series. The same object field can be studied as either a weakening or
hardening mutation depending on direction.

Local reading:

- `docs/windows-internals/eprocess-token-object-model.md`
- `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md`

#### Bypassing Code Integrity Using BYOVD For Kernel R/W Primitives

Source:

- [Bypassing Code Integrity Using BYOVD for Kernel R/W Primitives](https://medium.com/@s12deff/bypassing-code-integrity-using-byovd-for-kernel-r-w-primitives-8135087e1c1e)

Classification:

```text
kernel R/W
  -> Code Integrity state
  -> policy-state tamper
```

Why it matters:

Code Integrity is a policy engine. The interesting research point is not "disable
CI"; it is how a global policy state can be treated as mutable data when a kernel
write primitive exists.

Local reading:

- `docs/mitigations/dse-code-integrity-research-notes.md`
- `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`

#### Discover Code Integrity Protection Status

Source:

- [Discover Code Integrity Protection Status](https://medium.com/@s12deff/discover-code-integrity-protection-status-d5119fa96bd5)

Classification:

```text
user-mode system query
  -> Code Integrity status interpretation
  -> precondition check
```

Why it matters:

Before changing a policy, a researcher needs to know whether the policy is active.
This is a precondition and environment-discovery article.

Local reading:

- `docs/mitigations/dse-code-integrity-research-notes.md`

#### Reversing Windows Defender Vulnerable Driver: KslD.sys

Source:

- [Reversing Windows Defender Vulnerable Driver: KslD.sys](https://medium.com/@s12deff/reversing-windows-defender-vulnerable-driver-ksld-sys-d64a485ee8e8)

Classification:

```text
driver reverse engineering
  -> kernel memory read capability
  -> default-install reachability question
```

Why it matters:

The valuable research question is reachability: vulnerable driver present on disk
does not automatically mean exploitable primitive is reachable under modern
policy, versioning, and access controls.

Local reading:

- `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md`
- `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
- `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`

#### Kernel Dynamic Offset Resolution Using PDB Symbols

Source:

- [Kernel Dynamic Offset Resolution using PDB Symbols](https://medium.com/@s12deff/kernel-dynamic-offset-resolution-using-pdb-symbols-b0aaa499ac25)

Classification:

```text
symbol-aware research tooling
  -> build-specific offset discovery
  -> reduced hardcoding
```

Why it matters:

Many BYOVD bridges fail because offsets drift. Symbol-driven offset resolution is
a way to replace static constants with build-aware lookup, though it introduces
network, cache, trust, and parsing assumptions.

Local reading:

- `docs/kernel-research/runtime-pdb-symbol-resolution.md`
- `docs/kernel-research/kernel-object-layout-drift.md`

### 3. User-Mode Primitive And Evasion-Adjacent Posts

This group is not kernel-driver research by itself, but it connects to driver
research because user-mode actions often become the "objective" after the kernel
primitive weakens one protection layer.

#### Remote PEB Walking: Enumerating Loaded Modules

Source:

- [Remote PEB Walking: Enumerating Loaded Modules](https://medium.com/@s12deff/remote-peb-walking-enumerating-loaded-modules-bbb84e64f322)

Classification:

```text
remote process memory read
  -> PEB loader list
  -> module inventory without high-level module APIs
```

Why it matters:

This teaches the difference between API-level enumeration and structure-level
enumeration. The same mental model appears in kernel research: API contract versus
internal state.

Local reading:

- `docs/windows-internals/object-manager-and-handle-tables.md`

#### Detecting EDR Inline Hooks In ntdll.dll

Source:

- [Detecting EDR Inline Hooks in ntdll.dll](https://medium.com/@s12deff/detecting-edr-inline-hooks-in-ntdll-dll-18df079d76d4)

Classification:

```text
user-mode sensor analysis
  -> ntdll code integrity comparison
  -> hook detection
```

Why it matters:

This is user-mode counterpart to kernel callback inspection: identify where the
observer has inserted itself, then reason about what that observer can see.

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### Remote Process Write Primitive Via APC Routines

Source:

- [Remote Process Write Primitive via APC Routines](https://medium.com/@s12deff/remote-process-write-primitive-via-apc-routines-82c2598c6419)

Classification:

```text
user-mode remote write primitive
  -> APC delivery and argument semantics
  -> process injection building block
```

Why it matters:

The useful lesson is primitive substitution: an operation normally performed by a
watched API can sometimes be represented by another mechanism with different
telemetry.

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### Remote Process Read Primitive Via NtCreateThreadEx Exit Code

Source:

- [Remote Process Read Primitive via NtCreateThreadEx Exit Code](https://medium.com/@s12deff/remote-process-read-primitive-via-ntcreatethreadex-exit-code-8370c54ed648)

Classification:

```text
user-mode remote read primitive
  -> remote thread return-value channel
  -> small-chunk memory extraction
```

Why it matters:

This is another primitive-substitution example. The study question is how a
function's return semantics can accidentally become a data channel.

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### Primitive Process Injection: APC Tandem

Source:

- [Primitive Process Injection: APC Tandem](https://medium.com/@s12deff/primitive-process-injection-apc-tandem-1dcec8515c86)

Classification:

```text
user-mode injection composition
  -> chained primitives
  -> process execution objective
```

Why it matters:

This belongs in the "objective after visibility reduction" bucket. It is not a
driver exploit primitive, but callback/ETW/WFP tamper often tries to create room
for later user-mode activity.

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### UAC Bypass Via ComputerDefaults.exe

Source:

- [UAC Bypass via ComputerDefaults.exe](https://medium.com/@s12deff/uac-bypass-via-computerdefaults-exe-16b3e65f2805)

Classification:

```text
user-mode elevation boundary
  -> auto-elevated binary behavior
  -> local privilege workflow
```

Why it matters:

This is not kernel research, but it can appear in a complete local chain. Keep it
separate from BYOVD primitives so the taxonomy stays clean.

Local reading:

- `docs/research-index/technique-writing-standard.md`

#### Essential Windows Evasion Techniques

Source:

- [Essential Windows Evasion Techniques](https://medium.com/@s12deff/essential-windows-evasion-techniques-c8721656674f)

Classification:

```text
user-mode evasion survey
  -> syscall/API-shape changes
  -> import hiding
  -> sandbox/debugger checks
  -> memory-only and hook-aware execution
```

Why it matters:

This is a survey article, not a driver primitive. Map it as vocabulary for
user-mode objectives that may follow kernel-side visibility reduction.

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### Ghostly Hollowing

Source:

- [Ghostly Hollowing](https://medium.com/@s12deff/ghostly-hollowing-3de4831c7a83)

Classification:

```text
user-mode process injection
  -> deleted-file / mapped-image semantics
  -> disk-artifact reduction
```

Why it matters:

This belongs in the user-mode objective bucket. It is useful for comparing how
file, image-load, process, and memory telemetry see different stages of a hollowing
or ghosting-style flow.

Local reading:

- `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### Testing Antivirus Detection Levels On Ghostly Hollowing Crypter

Source:

- [Testing Antivirus Detection Levels on Ghostly Hollowing Crypter](https://medium.com/@s12deff/testing-antivirus-detection-levels-on-ghostly-hollowing-crypter-087cdc2d9025)

Classification:

```text
AV testing / payload packaging
  -> static and dynamic detection comparison
  -> crypter evaluation
```

Why it matters:

This is measurement-oriented material. Keep it separate from kernel primitives so
the repo does not confuse "payload packaging changed a scan result" with "kernel
telemetry surface changed."

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### Payload Obfuscation Family

Sources:

- [AV Evasion with XOR Encryption](https://medium.com/@s12deff/av-evasion-with-xor-encryption-89468ef123f4)
- [RC4 Shellcode Encryption](https://medium.com/@s12deff/rc4-shellcode-encryption-0c7adc22fff5)
- [RC6 Shellcode Encryption](https://medium.com/@s12deff/rc6-shellcode-encryption-fc38ada8c55e)
- [Heap Encryption](https://medium.com/@s12deff/heap-encryption-9f98be61f99c)
- [Adding NOPs to shellcode to evade rule-based detection](https://medium.com/@s12deff/adding-nops-to-shellcode-to-evade-rule-based-detection-0cef27c679fa)

Classification:

```text
payload representation change
  -> static signature pressure
  -> runtime decoding or memory-layout change
```

Why it matters:

These are not driver exploit posts. They are payload-shape posts. The useful
research distinction is:

```text
payload representation changed
  !=
kernel policy state changed
  !=
kernel callback visibility changed
```

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

### 4. Driver Loading, Artifact Minimization, And Policy-State Chains

This group connects user-mode orchestration with kernel-driver research. The
articles should be classified by precondition and artifact model, not copied as
loader recipes.

#### Temporary Driver Injection

Source:

- [Temporary Driver Injection](https://medium.com/@s12deff/temporary-driver-injection-34add0cda42e)

Classification:

```text
driver-load orchestration
  -> short-lived driver file/service state
  -> reduced persistence artifacts
```

Why it matters:

This is not a new kernel primitive. It changes how a driver is staged and removed.
The kernel still has to accept a driver load, and driver-load telemetry remains a
central event.

Local reading:

- `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
- `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`

#### Loading Kernel Drivers In-Memory

Source:

- [Loading Kernel Drivers In-Memory](https://medium.com/@s12deff/loading-kernel-drivers-in-memory-fc5d71c576e2)

Classification:

```text
driver-load staging model
  -> embedded driver bytes
  -> temporary materialization/load flow
```

Why it matters:

Treat this as a staging/artifact question. The important research question is
which artifacts move from persistent disk to transient disk, registry, memory, or
driver-load telemetry.

Local reading:

- `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`

#### Ghost Driver Injection

Source:

- [Ghost Driver Injection](https://medium.com/@s12deff/ghost-driver-injection-a21917010584)

Classification:

```text
driver-load artifact minimization
  -> temporary path and cleanup model
  -> loaded-module visibility remains
```

Why it matters:

The study point is the artifact tradeoff: reducing one disk trace does not remove
driver object state, loaded image state, Code Integrity state, or ETW load events.

Local reading:

- `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`

#### Windows Defender Killer: Registry Edits Plus BYOVD

Source:

- [Windows Defender Killer: Combining Registry Edits with BYOVD for Permanent Disable](https://medium.com/@s12deff/windows-defender-killer-combining-registry-edits-with-byovd-for-permanent-disable-d0faea53ece2)

Classification:

```text
policy/configuration tamper chain
  -> security product configuration state
  -> BYOVD-assisted persistence pressure
```

Why it matters:

This should be handled as a product-health consistency case, not as a primitive
deep dive. The useful taxonomy question is which state is OS policy, which state is
product configuration, and which state is enabled by kernel write access.

Local reading:

- `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md`
- `docs/detection-and-mitigation/av-self-protection-research-index.md`

#### EDR Process Whitelist Enumeration

Source:

- [EDR Process Whitelist Enumeration](https://medium.com/@s12deff/edr-process-whitelist-enumeration-7c7eb8b1c480)

Classification:

```text
user-mode product visibility mapping
  -> injected-module presence/absence
  -> trusted process hypothesis
```

Why it matters:

The invariant is that some products use injected components in monitored
processes. Absence of those components can suggest a trust or compatibility
exception, but it is not proof that the process is unmonitored.

Local reading:

- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

#### Hide Processes In Task Manager

Source:

- [Hide Processes in Task Manager](https://medium.com/@s12deff/hide-processes-in-task-manager-64043c7c2c4b)

Classification:

```text
user-mode API tamper
  -> process-list filtering
  -> view-specific hiding
```

Why it matters:

This is a good contrast with DKOM. User-mode filtering hides from consumers of a
specific API path. It does not change kernel process ownership.

Local reading:

- `docs/kernel-research/hkom-process-hide-crossview.md`
- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

### 5. HKOM / DKOM / Object-State Posts

#### Direct Kernel Object Manipulation To Hide Processes

Source:

- [Direct Kernel Object Manipulation to Hide Processes](https://medium.com/@s12deff/direct-kernel-object-manipulation-to-hide-processes-6fe9b45bd81c)

Classification:

```text
kernel object state manipulation
  -> process list view tamper
  -> cross-view inconsistency
```

Why it matters:

DKOM teaches the same core lesson as callback tamper: changing one authoritative
list can fool one view while leaving references elsewhere.

Local reading:

- `docs/kernel-research/hkom-dkom-hide-research-notes.md`
- `docs/kernel-research/hkom-process-hide-crossview.md`

### 6. Lab Environment, Tooling, And Meta Posts

#### Useful Sandboxes For Windows Malware Developers

Source:

- [Useful Sandboxes for Windows Malware Developers](https://medium.com/@s12deff/useful-sandboxes-for-windows-malware-developers-9e5fe8586d86)

Classification:

```text
lab/testing environment
  -> static and dynamic analysis services/tools
  -> behavior and detection feedback
```

Why it matters:

This is not an exploit technique. It belongs in lab workflow and validation. Keep
it out of primitive taxonomy unless a specific sandbox behavior becomes the topic.

Local reading:

- `docs/research-index/technique-writing-standard.md`

## Cross-Article Technique Graph

```text
clean sensor examples
  -> process/thread/image callbacks
  -> minifilter callbacks
  -> WFP callouts

BYOVD primitive examples
  -> kernel read/write
  -> PPL state
  -> Code Integrity state
  -> callback/filter/provider state

offset tooling
  -> PDB symbol resolution
  -> layout drift handling

user-mode objectives
  -> module enumeration
  -> hook inspection
  -> remote read/write primitives
  -> injection
  -> UAC workflow

driver loading and staging
  -> temporary driver materialization
  -> embedded driver bytes
  -> loaded-module and CI visibility

payload-shape posts
  -> encryption/obfuscation surveys
  -> detection-level testing
  -> not kernel primitives
```

The sequence to study is:

```text
1. Learn the legitimate sensor.
2. Learn the kernel read/write primitive.
3. Learn build-specific object discovery.
4. Learn the violated invariant.
5. Learn why the mutation is fragile.
6. Compare against independent telemetry.
```

## Local Reading Paths

### Path A: Callback And Sensor Foundations

1. `docs/kernel-research/callback-surfaces.md`
2. `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
3. `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`
4. `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`
5. `03_byovd/00_index-and-matrix/BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`

### Path B: BYOVD Primitive To State Change

1. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
2. `03_byovd/00_index-and-matrix/BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`
3. `03_byovd/00_index-and-matrix/BYOVD_CASE_GDRV.md`
4. `docs/kernel-research/runtime-pdb-symbol-resolution.md`
5. `docs/kernel-research/kernel-object-layout-drift.md`

### Path C: PPL, CI, And Policy-State Mutation

1. `docs/windows-internals/eprocess-token-object-model.md`
2. `docs/mitigations/dse-code-integrity-research-notes.md`
3. `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
4. `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`

### Path D: User-Mode Objective Context

1. `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`
2. `docs/kernel-research/hkom-process-hide-crossview.md`
3. `docs/research-index/technique-writing-standard.md`

### Path E: Driver Loading And Artifact Model

1. `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
2. `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`
3. `docs/mitigations/dse-code-integrity-research-notes.md`
4. `docs/detection-and-mitigation/av-self-protection-research-index.md`

## Research Questions

1. Which S12Deff articles are clean sensor-building articles, and which are
   tamper articles?
2. Which posts require kernel R/W, and which only require user-mode process
   access?
3. Which articles depend on private Windows layouts?
4. Which articles depend on documented public registration APIs?
5. Which techniques mutate global state, and which only read or infer state?
6. Which techniques are one-sensor blind spots rather than whole-system
   invisibility?
7. Which local docs should be expanded when a new S12Deff article appears?
8. Which posts are payload-shape changes rather than OS/kernel state changes?
9. Which driver-loading posts change artifact lifetime without changing the fact
   that the kernel loaded a driver?

## Coverage Gaps To Revisit

- Confirm whether a standalone "Enumerating Process Creation Kernel Callbacks" URL
  exists outside the overwrite article's recap.
- Add separate local notes if S12Deff publishes follow-up posts on object
  callbacks, registry callbacks, or callback enumeration via symbols.
- Keep S12Deff source mapping separate from DriverShield and LOLDrivers mapping so
  source discovery does not get confused with driver capability verification.

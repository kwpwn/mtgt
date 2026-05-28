# BYOVD DriverShield Blog Technique Atlas

Updated: 2026-05-27

## Purpose

This document uses DriverShield's BYOVD index as a source-discovery page, then
filters the results down to technique-bearing writeups and research notes.

DriverShield page:

- https://drivershield.io/byovd/

DriverShield data endpoint observed from the page:

- https://drivershield.io/?r=api/byovd

At the time of review, the DriverShield BYOVD endpoint returned 95 public
repositories. Many entries are tools, loaders, process killers, scanners, or
malware projects. This atlas does not use those as primary teaching material.
It extracts only the reusable technical patterns that appear in writeups,
research READMEs, and blog-style notes linked through the index.

Important rule:

```text
Do not study a BYOVD source as "how to run the tool".
Study it as "what primitive, invariant, bridge, and failure mode does this
source demonstrate?"
```

This file intentionally avoids runnable PoC code, driver-specific IOCTL values,
trigger buffers, patch bytes, offset tables, commands, and exploit chains.

## Source Filter

### Included As Technique Sources

These DriverShield BYOVD entries contain enough technical explanation to extract
technique patterns:

| DriverShield entry | Technique value |
|---|---|
| `BlackSnufkin/BYOVD` | vulnerable-driver reverse engineering workflow, process-kill family, physical R/W case, driver-specific PoC organization |
| `0xJs/BYOVD_read_write_primitive` | RTCore64-style R/W primitive used for PPL state, token state, callback state, CI state |
| `RainbowDynamix/GhostKatz` | LSASS access through physical memory read primitives and VA-to-PA bridge |
| `Muz1K1zuM/kslkatz_bof` | KslD-style physical memory credential access idea, no OpenProcess dependency |
| `ColeHouston/theHandler-BOF` | handle object tamper to access protected process memory |
| `FuzzySecurity/BHUSA-2023` | rootkit/post-exploitation technique taxonomy: DKOM, NDIS, kernel-state collection |
| `Dor00tkit/BamExtensionTableHook` | process notification callback arrays versus extension table mechanism |
| `xM0kht4r/CVE-2025-7771` | ThrottleStop physical memory R/W and virtual-to-physical bridge |
| `athenasec16/CVE-2026-29923` | PowerStrip/pstrip64 physical-memory mapping bug class |
| `moiz-2x/CVE-2025-24990_POC` | METHOD_NEITHER trust bug, limited writes, pointer dereference, I/O ring bridge |
| `vxcall/kur` | vulnerable-driver mediated kernel read/write and kernel-created handles |
| `4l3x777/dse_pg_bypass` | Code Integrity callback/state reasoning and PatchGuard pressure |
| `redteamfortress/PPLShade` | PPL metadata manipulation via multi-driver memory primitives |
| `FreeXR/eureka_panther-adreno-gpu-exploit-1` | GPU driver memory corruption to kernel R/W and privilege escalation |
| `KeServiceDescriptorTable/vulnerable-drivers` | vulnerable-driver sample corpus as source candidates |

### Excluded From This Pass

Excluded categories:

- process-termination-only projects,
- loader-only projects,
- ransomware or malware projects,
- scanner/framework/tooling-only projects,
- generic pentest lists,
- repositories with no useful technical explanation,
- pure collection repos without per-driver analysis.

Reason:

```text
tool output is not a technique explanation
```

The goal is to build academic research notes, not a list of runnable utilities.

## Technique Map

| Technique family | Source examples from DriverShield index | Local learning value |
|---|---|---|
| physical memory R/W | GhostKatz, CVE-2025-7771, pstrip64, LnvMSRIO-style notes | raw physical primitive, VA-to-PA bridge, object discovery |
| virtual kernel R/W | RTCore64/GDRV-style writeups | direct kernel object modification |
| limited write upgrade | CVE-2025-24990-style write/decrement/null primitives | weak primitive to semantic field or I/O ring bridge |
| `PreviousMode` / trust-bit bridge | CVE-2025-24990, prior public Windows research | convert pointer-probing trust decision |
| I/O ring metadata bridge | CVE-2025-24990, Windows I/O ring writeups | object metadata adapter |
| PPL metadata tamper | PPLShade, RTCore64 primitive demos | process access-check metadata |
| handle object tamper | theHandler | protected process memory via handle metadata |
| callback and extension table | BamExtensionTableHook, callback remover writeups | process/image/registry/Object Manager/extension callbacks |
| DSE / Code Integrity state | dse_pg_bypass, CI callback research | policy callback/state tamper under PG/HVCI pressure |
| DKOM / rootkit state | BHUSA-2023, Sunder-style notes | object graph visibility changes |
| WFP/network semantic action | 360WFP-style research | driver semantic operation, not generic memory corruption |
| GPU/third-party kernel memory corruption | Adreno GPU exploit | non-IOCTL kernel driver memory corruption path |
| driver discovery workflow | BlackSnufkin/BYOVD, HEVD, vulnerable-driver corpora | review methodology and bug-class vocabulary |

## Technique 01: Physical Memory R/W

Source examples:

- `RainbowDynamix/GhostKatz`
- `Muz1K1zuM/kslkatz_bof`
- `xM0kht4r/CVE-2025-7771`
- `athenasec16/CVE-2026-29923`
- `BlackSnufkin/BYOVD` physical R/W cases

### Core Idea

Physical memory R/W means the vulnerable driver exposes some way to read or
write machine physical memory. That is not automatically the same as "kernel
object control".

The bridge is:

```text
physical address capability
  -> identify the kernel virtual object
  -> translate or locate physical backing
  -> validate object identity
  -> perform minimal semantic read/write
```

### Why It Works

The operating system normally mediates access through virtual memory,
privileges, object manager, memory manager, and page protections. A driver that
maps or copies arbitrary physical memory bypasses those layers because it
operates below normal virtual address semantics.

The broken invariant:

```text
unprivileged user mode should not be able to ask a signed driver to map or copy
arbitrary physical pages
```

### What It Can Do

Physical R/W can support:

- kernel base discovery,
- page table walking,
- reading process objects,
- modifying process token/protection metadata,
- reading LSASS memory indirectly,
- locating and modifying callback or list metadata,
- creating an arbitrary kernel virtual read/write bridge when combined with
  VA-to-PA translation.

### What It Cannot Do Alone

Physical R/W does not automatically provide:

- target object address,
- correct Windows build offsets,
- process identity,
- stable writes,
- safe MMIO avoidance,
- protection against PatchGuard,
- automatic virtual address translation.

### Pseudo-Flow

```text
primitive = physical_memory_read_write

target_va = discover_kernel_object()
target_pa = translate_or_locate_physical_backing(target_va)

if not validate_target_identity(target_pa):
    stop("wrong page or wrong build")

original = read_physical(target_pa)
write_physical(target_pa, desired_semantic_value)
verify_readback(target_pa)
restore_when_needed(original)
```

### Failure Modes

- physical scan hits MMIO,
- page translation is wrong,
- target object moved or exited,
- build offsets are stale,
- large page handling is missing,
- HVCI or hypervisor layer prevents the expected write effect,
- write succeeds but semantic target is wrong.

### Study Questions

1. What proves the physical page really backs the target object?
2. Does the technique need virtual-to-physical translation, pool scanning, or a
   kernel information leak?
3. What distinguishes LSASS physical memory reading from `OpenProcess`-based
   dumping?
4. Which part is driver-specific and which part is a general physical R/W
   bridge?

## Technique 02: Virtual Kernel R/W

Source examples:

- `0xJs/BYOVD_read_write_primitive`
- `zer0condition/GDRVLib`
- RTCore64/GDRV-style entries in the DriverShield index

### Core Idea

Virtual kernel R/W is more direct than physical memory R/W. Instead of forcing
the researcher to translate virtual targets into physical addresses, the driver
or primitive can read or write a kernel virtual address directly.

The bridge is:

```text
kernel virtual address R/W
  -> object/global discovery
  -> semantic field choice
  -> write discipline
```

### Why It Works

Many vendor drivers include privileged memory helpers for diagnostics,
overclocking, hardware management, firmware support, or device control. If a
helper accepts caller-controlled kernel addresses without proper authorization,
the driver becomes a kernel memory copy oracle.

Broken invariant:

```text
only trusted kernel code should decide which kernel virtual addresses can be
read or written
```

### What It Can Do

Virtual kernel R/W can support:

- token relationship changes,
- PPL protection metadata edits,
- callback pointer/list edits,
- Code Integrity state edits,
- object metadata adapter attacks,
- process/thread object field changes.

### Why It Is Still Hard

Even when the primitive is strong, the researcher still needs:

- kernel base,
- symbols or layout validation,
- target object discovery,
- correct lifetime assumptions,
- restore discipline,
- mitigation awareness.

### Pseudo-Flow

```text
primitive = kernel_virtual_read_write

kernel_base = discover_kernel_base()
target = discover_object_or_global(kernel_base)

if not target_semantics_are_understood(target):
    stop("do not write unknown kernel state")

original = kread(target.field)
kwrite(target.field, desired_value)
verify_effect()
restore_if_state_is_temporary(original)
```

### Failure Modes

- address is valid but not the intended field,
- field meaning changed across builds,
- PatchGuard or another integrity mechanism checks the state,
- write corrupts neighbor fields,
- target object lifetime is not stable,
- the desired objective is blocked by another policy layer.

## Technique 03: Limited Write Upgrade

Source examples:

- `moiz-2x/CVE-2025-24990_POC`
- limited write/decrement/null-byte patterns in public Windows driver writeups

### Core Idea

Some driver bugs do not give full arbitrary write. They give weaker effects:

```text
write a fixed value
write one byte
write zero
decrement a value
write to a pointer after a forced dereference
```

These are still valuable when they can hit a semantic field or object metadata
that amplifies the effect.

Broken invariant:

```text
small or fixed writes should not reach kernel-controlled trust state
```

### Upgrade Paths

| Weak primitive | Possible bridge |
|---|---|
| null byte write | clear an enable bit, terminate a string, change small state |
| fixed DWORD write | alter a known state field, redirect a controlled object path |
| decrement | steer a counter, reduce a byte from known value, shape object state |
| pointer dereference | turn controlled address into kernel object side effect |
| bounded write | target compact metadata or object adapter state |

### Pseudo-Flow

```text
primitive = limited_write

targets = enumerate_semantic_small_fields()

for target in targets:
    if primitive_can_reach(target):
        if field_value_after_write_is_useful(target):
            if target_can_be_restored_or_is_short_lived(target):
                consider_bridge(target)
```

### Failure Modes

- weak write reaches only useless fields,
- value cannot be shaped enough,
- neighbor field corruption causes crash,
- semantic state is cached elsewhere,
- target requires exact value not achievable by the primitive,
- repeated writes trigger instability.

### Study Questions

1. Is the primitive weak because of size, value, alignment, or address limits?
2. Which kernel fields are small but security-critical?
3. Can the weak primitive be combined with I/O ring or another metadata adapter?

## Technique 04: METHOD_NEITHER Trust Bugs

Source examples:

- `moiz-2x/CVE-2025-24990_POC`
- general driver bug-class notes from DriverShield-indexed sources

### Core Idea

`METHOD_NEITHER` IOCTLs often pass user pointers to a driver without automatic
buffer capture. If the driver trusts the pointer or fails to probe and validate
it, user mode can influence where the driver reads or writes.

Broken invariant:

```text
kernel driver must not trust caller-supplied pointers without checking address
space, size, lifetime, and access mode
```

### Why It Matters

`METHOD_NEITHER` bugs can create:

- arbitrary read,
- arbitrary write,
- write-what-where,
- pointer dereference,
- info leak,
- UAF/race if the user buffer changes during use.

### Pseudo-Flow

```text
request.user_pointer = attacker_controlled_address

driver:
    if not validates_user_pointer_correctly:
        write_to(request.user_pointer)

researcher:
    classify whether target can be user VA, kernel VA, stale VA, or object VA
```

### Failure Modes

- the driver probes correctly,
- SMEP/SMAP/KVA policies alter assumptions,
- only user-mode addresses are accepted,
- write value is fixed or useless,
- modern builds require additional privileges for kernel address disclosure.

## Technique 05: I/O Ring Metadata Bridge

Source examples:

- `moiz-2x/CVE-2025-24990_POC`
- I/O ring public Windows internals writeups
- local repo note: `docs/kernel-research/io-ring-research-notes.md`

### Core Idea

I/O ring object metadata can act as a bridge from a limited write into a more
useful read/write primitive if a controlled write can alter registered-buffer
metadata.

The bridge is:

```text
limited write
  -> corrupt I/O ring registered-buffer metadata
  -> invoke normal I/O ring operation
  -> kernel copies from/to attacker-chosen address
```

Broken invariant:

```text
registered buffer metadata should describe the buffer that was actually
registered and pinned
```

### Why It Works

The I/O ring subsystem is trusted kernel code. If its object metadata is
corrupted, normal subsystem operations can become memory access adapters.

### Pseudo-Flow

```text
ring = create_controlled_ring()
entry = locate_registered_buffer_metadata(ring)

limited_write(entry.pointer_field, target_kernel_address)
limited_write(entry.length_field, safe_length)

normal_ring_operation()
read_result_from_controlled_output()

restore_metadata(entry)
```

### Failure Modes

- I/O ring API absent or patched,
- object layout changed,
- metadata field not reachable by the weak write,
- size mismatch causes crash,
- kernel validates metadata before use,
- no leak exists to locate the ring object.

## Technique 06: `PreviousMode` And Caller Trust

Source examples:

- `moiz-2x/CVE-2025-24990_POC` references this class
- public Windows research on arbitrary pointer dereference to read/write

### Core Idea

`PreviousMode` is a thread-local trust marker. Some kernel services decide
whether to probe caller pointers based on whether the caller is considered
user-mode or kernel-mode.

Broken invariant:

```text
only the syscall dispatcher should determine previous caller mode
```

### Why It Works

If a write primitive changes a thread's caller-mode state, later system calls
may treat user-provided kernel pointers as trusted kernel pointers.

### Pseudo-Flow

```text
thread = locate_current_thread()
original = read_thread_caller_mode(thread)

write_thread_caller_mode(thread, kernel_mode)

try:
    call_service_that_uses_caller_mode_for_probe_decision()
finally:
    restore_thread_caller_mode(thread, original)
```

### Failure Modes

- wrong thread,
- thread migrates or is preempted,
- service has additional checks,
- field layout changed,
- restore happens too late,
- target build patched the known bridge.

## Technique 07: PPL Metadata Tamper

Source examples:

- `redteamfortress/PPLShade`
- `0xJs/BYOVD_read_write_primitive`
- `xM0kht4r/CVE-2025-7771`
- local Lenovo notes

### Core Idea

Protected Process Light decisions depend partly on process protection metadata.
A kernel write primitive can lower or raise this metadata, changing later handle
access decisions.

Broken invariant:

```text
protected-process identity should be created by trusted signing and process
creation policy, not post-creation memory writes
```

### Two Directions

| Direction | Meaning |
|---|---|
| lower target protection | make a protected target easier to open |
| raise self protection | make current process harder for lower-trust callers to open |

These are not the same objective even if they touch similar metadata.

### Pseudo-Flow

```text
target = find_process_object()
original = read_protection_metadata(target)

if goal == "access target":
    write_protection_metadata(target, lower_state)

if goal == "protect self":
    write_protection_metadata(target, higher_state)

perform_one_access_check_dependent_action()
restore_metadata_if_temporary(original)
```

### Failure Modes

- PatchGuard or integrity monitor observes inconsistent protection,
- signer/protection relationship is impossible,
- another access-control layer still denies access,
- target process exits,
- field layout changed,
- caller has equal or higher protection.

## Technique 08: Handle Object Tamper

Source examples:

- `ColeHouston/theHandler-BOF`

### Core Idea

Instead of opening a privileged handle normally, a researcher can use kernel
R/W to modify handle-table or handle-object metadata after a handle exists.

The bridge is:

```text
open allowed or decoy handle
  -> locate kernel handle metadata
  -> alter target/access relationship
  -> use normal handle-based operation
```

Broken invariant:

```text
handle access masks and object references should be created only by Object
Manager access checks
```

### Why It Works

Windows user-mode APIs operate through handles. If the kernel metadata behind a
handle changes, the caller may appear to possess different access or a different
object relationship.

### Pseudo-Flow

```text
handle = create_low_privilege_or_decoy_handle()
handle_entry = locate_kernel_handle_entry(current_process, handle)

original = snapshot_handle_entry(handle_entry)

write_handle_entry(handle_entry, desired_target_or_access)

normal_api_uses_handle(handle)

restore_handle_entry(original)
```

### Failure Modes

- handle table layout changed,
- wrong process handle table,
- object pointer/reference count mismatch,
- access mask is not enough because another policy blocks the operation,
- kernel object lifetime changes,
- restore fails.

## Technique 09: Callback State Tamper

Source examples:

- `0xJs/BYOVD_read_write_primitive`
- `Dor00tkit/BamExtensionTableHook`
- BlackSnufkin callback-related references
- public "Removing Kernel Callbacks Using Signed Drivers" style writeups

### Core Idea

Security products rely on several kernel callback families:

- process creation,
- thread creation,
- image load,
- registry operations,
- Object Manager handle operations,
- minifilter file operations.

With kernel R/W, callback state can be removed, disabled, unlinked, or bypassed.

Broken invariant:

```text
registered callbacks should remain registered until removed by official kernel
APIs
```

### Important Nuance: Standard Callbacks Are Not The Whole Story

The BamExtensionTableHook research highlights that process notification
visibility can also exist outside the standard callback array through extension
table mechanisms.

Lesson:

```text
clearing the obvious callback array is not equivalent to clearing every process
notification path
```

### Pseudo-Flow

```text
callback_surface = choose_surface(process | image | registry | object | file)
entries = enumerate_callback_storage(callback_surface)

for entry in entries:
    owner = classify_owner(entry)
    if owner_matches_research_target:
        save_entry(entry)
        disable_or_unlink(entry)

perform_one_event()
restore_entries()
```

### Failure Modes

- wrong callback family,
- extension table or secondary path still active,
- owner classification wrong,
- system callback removed accidentally,
- callback list corruption,
- product re-registers callback,
- another telemetry source observes the event.

## Technique 10: Code Integrity / DSE State

Source examples:

- `4l3x777/dse_pg_bypass`
- `ZwCreateFile/FuckDse`
- `0xJs/BYOVD_read_write_primitive`

### Core Idea

Driver Signature Enforcement and Code Integrity rely on policy state and
validation callback paths. A kernel write primitive can attempt to change the
state or callback relationship consumed during image validation.

Broken invariant:

```text
kernel image validation policy should be controlled only by Code Integrity and
trusted kernel initialization paths
```

### Two Technique Shapes

| Shape | Meaning |
|---|---|
| policy-state tamper | change data consumed by CI decision |
| callback-pointer/path tamper | alter validation callback path or function pointer relationship |

Both are fragile because they interact with PatchGuard, HVCI, and kernel code
integrity assumptions.

### Pseudo-Flow

```text
ci_target = locate_ci_state_or_validation_callback()
original = read_ci_target(ci_target)

if platform_integrity_protects(ci_target):
    stop("bridge probably fails")

write_ci_target(short_window_value)
perform_one_validation_dependent_action()
restore_ci_target(original)
```

### Failure Modes

- HVCI protects or virtualizes the state,
- PatchGuard notices persistent change,
- target callback changed between builds,
- validation has multiple layers,
- driver blocklist or WDAC still blocks load,
- write lands on wrong module/state.

## Technique 11: DKOM And Rootkit State

Source examples:

- `FuzzySecurity/BHUSA-2023`
- `ColeHouston/Sunder`
- local HKOM/DKOM notes

### Core Idea

DKOM modifies kernel object graphs directly. It does not necessarily remove an
object; it changes which views can see it.

Broken invariant:

```text
all kernel views of the same object graph should remain consistent
```

### Examples Of DKOM-Like State

- process list relationships,
- driver module list relationships,
- callback lists,
- object handle tables,
- filter manager lists,
- network driver or NDIS relationships,
- keyboard/input state collection paths.

### Pseudo-Flow

```text
object = locate_kernel_object()
view_link = choose_view_specific_link(object)

original = save_link_state(view_link)
unlink_or_modify(view_link)

compare_views()

restore_link_state(original)
```

### Failure Modes

- object exits while hidden,
- list restored incorrectly,
- cross-view check exposes contradiction,
- PatchGuard checks the object class,
- another subsystem still references the object,
- the objective depends on a view that was not modified.

## Technique 12: WFP / Network Semantic Primitive

Source examples:

- `kyxiaxiang/360WFP_Exploit`

### Core Idea

Not every BYOVD primitive is memory read/write. Some vulnerable drivers expose
a powerful semantic operation. A WFP/network-oriented driver can be abused to
change network filtering behavior.

Broken invariant:

```text
only authorized security/network management components should be able to create
or modify filtering behavior that affects other products' network connectivity
```

### Why It Matters

This is a semantic primitive:

```text
driver already knows how to perform a privileged action
attacker reaches that action with unauthorized parameters
```

That differs from arbitrary memory corruption.

### Pseudo-Flow

```text
driver_semantic_action = "modify network filtering behavior"

if caller_can_reach_action_without_authorization:
    choose_targeted_policy_change()
    invoke_semantic_action_once()
    verify_effect_scope()
```

### Failure Modes

- action requires SYSTEM/admin,
- target product uses another channel,
- network stack or WFP policy blocks change,
- driver version changed,
- effect is noisy or temporary,
- semantic action is process-specific rather than global.

## Technique 13: GPU / Third-Party Kernel Memory Corruption

Source examples:

- `FreeXR/eureka_panther-adreno-gpu-exploit-1`

### Core Idea

BYOVD is often associated with Windows `.sys` management drivers, but the
broader lesson applies to any trusted kernel driver. A GPU or device driver
memory corruption bug can produce arbitrary kernel memory access or privilege
escalation if the driver exposes a reachable attack surface.

Broken invariant:

```text
device driver command streams and buffers should not allow user-controlled
state to corrupt kernel memory
```

### Why It Matters

This expands the mental model:

```text
not only IOCTL helper drivers
  -> device command processors
  -> GPU/firmware/display stacks
  -> complex parser/state-machine bugs
```

### Pseudo-Flow

```text
submit_device_command(controlled_state)
driver_processes_command()

if command_state_corrupts_kernel_object:
    derive_read_write_or_privilege_primitive()
```

### Failure Modes

- bug only affects one hardware/firmware version,
- memory corruption is not controllable,
- sandbox/IOMMU/driver isolation changes reachability,
- exploit relies on device-specific timing,
- primitive cannot be bridged to a stable object target.

## Technique 14: Driver Discovery And IOCTL Triage

Source examples:

- `BlackSnufkin/BYOVD`
- `hacksysteam/HackSysExtremeVulnerableDriver`
- vulnerable-driver collections in DriverShield index

### Core Idea

Before exploiting anything, a researcher must classify the driver surface:

```text
who can open the device?
which dispatch routine handles control requests?
which transfer method is used?
which dangerous APIs are reachable?
what primitive can be proven?
```

### Why HEVD Still Matters

HEVD is not a real BYOVD target in the same sense as an OEM vulnerable driver.
It is useful because it teaches bug-class vocabulary:

- stack overflow,
- pool overflow,
- use-after-free,
- integer overflow,
- arbitrary write,
- null pointer dereference,
- uninitialized memory,
- double fetch,
- info leak.

### Pseudo-Flow

```text
driver = load_into_reversing_tool()

device = find_device_creation()
acl = classify_device_access(device)
dispatch = find_device_control_dispatch()

for request in dispatch.cases:
    transfer = classify_transfer_method(request)
    trust = trace_user_controlled_fields(request)
    api = identify_dangerous_kernel_api(request)
    primitive = classify_effect(request, trust, api)

write_research_note(request, primitive, reachability, failure_modes)
```

### Failure Modes

- device is not reachable by the assumed user,
- hardware dependency missing,
- IOCTL is privileged or gated,
- dangerous API exists but is not reachable,
- input size constraints prevent impact,
- crash is not a useful primitive.

## Technique 15: LSASS Without Normal Process Access

Source examples:

- `RainbowDynamix/GhostKatz`
- `Muz1K1zuM/kslkatz_bof`
- `ColeHouston/theHandler-BOF`

### Core Idea

Several DriverShield-indexed sources focus on LSASS or protected process memory
without relying on the normal user-mode handle path.

Three broad routes:

| Route | Bridge |
|---|---|
| physical memory read | locate process memory through physical/virtual mapping |
| handle object tamper | alter kernel handle metadata after a handle exists |
| PPL metadata tamper | change process protection metadata before access check |

### Broken Invariant

```text
protected process memory should be accessible only through authorized handle and
protection-policy paths
```

### Pseudo-Flow

```text
if route == physical_memory:
    locate_process_address_space()
    map_or_read_relevant_pages()

if route == handle_tamper:
    create_or_reuse_handle()
    alter_handle_metadata()

if route == protection_metadata:
    temporarily alter access-check state()

perform_one_memory_collection_action()
restore_any_modified_state()
```

### Failure Modes

- wrong process address space,
- PPL/signature policy still blocks access,
- physical pages not located,
- handle table layout changed,
- memory collection format invalid,
- credential material protected by another layer.

## Blog-To-Document Conversion Template

When turning one DriverShield-indexed writeup into a local note, use this:

```text
Source:
Driver:
CVE:
Primitive:
Reachability:
Trust boundary:
Broken invariant:
Bridge:
Object/global target:
Why it works:
What can be done:
What fails:
Mitigation/build assumptions:
What not to copy:
Study questions:
```

The most important fields:

```text
primitive
bridge
broken invariant
failure mode
```

If those are missing, the note is not educational enough.

## DriverShield-Derived Backlog

High-value candidates to convert into separate local notes:

| Candidate | Technique family | Target local doc |
|---|---|---|
| `moiz-2x/CVE-2025-24990_POC` | METHOD_NEITHER, limited write, I/O ring bridge | `BYOVD_CASE_LTMDM64_LIMITED_WRITE_IORING.md` |
| `athenasec16/CVE-2026-29923` | pstrip64 physical memory mapping | `BYOVD_CASE_PSTRIP64_CVE_2026_29923.md` |
| `xM0kht4r/CVE-2025-7771` | ThrottleStop physical R/W, Superfetch VA-to-PA | extend physical memory family doc |
| `ColeHouston/theHandler-BOF` | handle object tamper | `docs/kernel-research/handle-object-tamper-research-notes.md` |
| `Dor00tkit/BamExtensionTableHook` | extension table callback visibility | `docs/kernel-research/kernel-extension-table-callbacks.md` |
| `4l3x777/dse_pg_bypass` | CI callback/state and PG pressure | extend DSE/CI notes |
| `RainbowDynamix/GhostKatz` | physical memory LSASS access | extend physical memory / protected process notes |
| `FreeXR/eureka_panther-adreno-gpu-exploit-1` | GPU driver memory corruption | `docs/kernel-research/gpu-driver-kernel-memory-corruption.md` |
| `kyxiaxiang/360WFP_Exploit` | WFP/network semantic primitive | `docs/kernel-research/wfp-driver-semantic-primitives.md` |

## Study Questions

1. Which DriverShield-indexed sources demonstrate physical memory R/W?
2. Which sources demonstrate virtual kernel R/W?
3. Which sources show weak primitive upgrade instead of full arbitrary write?
4. Which sources rely on object metadata adapters?
5. Which sources target access-check metadata rather than code execution?
6. Which sources target visibility surfaces such as callbacks or minifilters?
7. Which sources are pure process-termination and should stay out of this
   technique atlas?
8. Which techniques require kernel base discovery first?
9. Which techniques require object address discovery first?
10. Which techniques depend most heavily on Windows build offsets?
11. Which techniques fail under HVCI or PatchGuard pressure?
12. Which techniques are semantic driver abuse rather than memory corruption?
13. Which technique would you convert into a standalone case study first?
14. What should be removed from a public PoC before converting it into a safe
   academic note?
15. What is the shortest explanation of primitive versus bridge for each
   technique?

## References

DriverShield:

- DriverShield BYOVD index: https://drivershield.io/byovd/
- DriverShield BYOVD API endpoint: https://drivershield.io/?r=api/byovd

Selected DriverShield-indexed technique sources:

- BlackSnufkin BYOVD: https://github.com/BlackSnufkin/BYOVD
- 0xJs BYOVD read/write primitive: https://github.com/0xJs/BYOVD_read_write_primitive
- RainbowDynamix GhostKatz: https://github.com/RainbowDynamix/GhostKatz
- Muz1K1zuM kslkatz_bof: https://github.com/Muz1K1zuM/kslkatz_bof
- ColeHouston theHandler-BOF: https://github.com/ColeHouston/theHandler-BOF
- FuzzySecurity BHUSA-2023: https://github.com/FuzzySecurity/BHUSA-2023
- Dor00tkit BamExtensionTableHook:
  https://github.com/Dor00tkit/BamExtensionTableHook
- xM0kht4r CVE-2025-7771: https://github.com/xM0kht4r/CVE-2025-7771
- athenasec16 CVE-2026-29923:
  https://github.com/athenasec16/CVE-2026-29923
- moiz-2x CVE-2025-24990_POC:
  https://github.com/moiz-2x/CVE-2025-24990_POC
- vxcall kur: https://github.com/vxcall/kur
- 4l3x777 dse_pg_bypass: https://github.com/4l3x777/dse_pg_bypass
- redteamfortress PPLShade: https://github.com/redteamfortress/PPLShade
- FreeXR Adreno GPU exploit:
  https://github.com/FreeXR/eureka_panther-adreno-gpu-exploit-1
- KeServiceDescriptorTable vulnerable drivers:
  https://github.com/KeServiceDescriptorTable/vulnerable-drivers

External technique references linked by those sources:

- Outflank, Mapping Virtual to Physical Addresses Using Superfetch:
  https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/
- Physical Graffiti LSASS:
  https://adepts.of0x.cc/physical-graffiti-lsass/
- Yarden Shafir, Kernel Extension Mechanism:
  https://medium.com/yarden-shafir/yes-more-callbacks-the-kernel-extension-mechanism-c7300119a37a
- Alex Ionescu, DKOM 3.0:
  http://publications.alex-ionescu.com/Infiltrate/Infiltrate%202019%20-%20DKOM%2030%20-%20Hiding%20and%20Hooking%20with%20Windows%20Extension%20Hosts.pdf
- Windows Internals, One I/O Ring To Rule Them All:
  https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
- HN Security, arbitrary pointer dereference to arbitrary R/W:
  https://hnsecurity.it/blog/from-arbitrary-pointer-dereference-to-arbitrary-read-write-in-latest-windows-11/

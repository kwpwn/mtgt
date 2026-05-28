# BYOVD Case Study: `LnvMSRIO.sys` Technique-Chain Atlas

Updated: 2026-05-27

## Purpose

This note reviews the external Lenovo LPE draft set at:

```text
E:\driver_research\lenovo_lpe\docs
```

Those drafts are useful because they separate one vulnerable-driver primitive
into many technique outcomes: kernel base discovery, data-only object changes,
PPL state, `PreviousMode`, Code Integrity state, DKOM, I/O ring object metadata,
ETW/notification/callback pressure, and Filter Manager state.

This repo version intentionally normalizes them into a safer research atlas:

```text
external hands-on draft
  -> primitive
  -> invariant
  -> bridge
  -> failure mode
  -> study question
```

It does not copy IOCTL layouts, trigger buffers, hardcoded offsets, byte patch
values, code snippets, or step-by-step bypass recipes.

For code-shaped mental models that make these primitives easier to visualize,
read:

- `docs/kernel-research/primitive-pseudocode-sketchbook.md`

## External Draft Inventory

Reviewed local files:

| Draft | Topic | Research class |
|---|---|---|
| `01_kaslr_defeat.md` | MSR/LSTAR and physical scan | kernel base discovery |
| `02_token_steal.md` | token object data change | data-only privilege state |
| `03_ppl_bypass.md` | target PPL protection change | object access-check state |
| `04_previousmode.md` | thread `PreviousMode` change | semantic field bridge to kernel VA access |
| `05_dse_bypass.md` | Code Integrity state tamper | policy state tamper |
| `06_dkom_hide.md` | `ActiveProcessLinks` unlink | DKOM/hide/cross-view |
| `07_ioring.md` | I/O ring object metadata | object metadata read bridge |
| `08_etw_patch.md` | ETW-TI code patching | telemetry code-path tamper |
| `09_callback_kill.md` | Ps notify callback state | callback visibility tamper |
| `10_ob_callback.md` | Object Manager callbacks | handle/access visibility tamper |
| `11_cm_callback.md` | registry callbacks | registry visibility tamper |
| `12_minifilter_blind.md` | Filter Manager callback lists | filesystem visibility tamper |
| `13_ppl_elevate.md` | self PPL state elevation | self-protection state tamper |

The set is coherent. It demonstrates one central lesson:

```text
physical/MSR primitive
  -> target discovery
  -> semantic kernel data edit
  -> narrow objective
```

The part to improve is not "add more tricks". The important improvement is
making every trick explain:

```text
why this state matters
why this field/list/callback is trusted
why the primitive reaches it
what breaks on another build
what must be restored
```

## Core Primitive Model

The external notes all reuse a small primitive set:

| Primitive | What it gives | What it does not give by itself |
|---|---|---|
| physical memory read | raw bytes from physical address space | object identity, virtual target address, safe write target |
| physical memory write | data modification at physical address | semantic correctness, stability, restore safety |
| MSR read | privileged CPU state such as syscall-entry anchors | a writable target or object bridge |
| MSR write | CPU control-state mutation | reliability, mitigation safety, PatchGuard safety |
| VA-to-PA translation | bridge from kernel VA target to physical write | proof that the target is the right object/field |
| module/base discovery | locate kernel image context | final exploit impact |

This distinction matters because many writeups collapse:

```text
physical write -> SYSTEM
```

The real chain is:

```text
physical write
  -> target discovery
  -> build-specific layout validation
  -> semantic field/list/code target
  -> minimal modification
  -> verification
  -> restoration or controlled lifetime
```

## Pseudo-PoC Companion For The Lenovo Drafts

This section gives each external draft a code-shaped mental model. These are
not Windows APIs and not exploit snippets. They are small state-machine sketches
for learning how the bridge is supposed to feel.

### Draft 01: Kernel Base Discovery

Toy flow:

```text
anchor = primitive.read_cpu_syscall_anchor()

for page in physical_memory.walk_aligned_candidates():
    header = primitive.read_physical(page, "header-sized-window")

    if not looks_like_kernel_image(header):
        continue

    candidate = infer_image_candidate(page)

    if anchor_inside_candidate(anchor, candidate):
        if candidate_has_expected_sections(candidate):
            return candidate.base

return "no trusted base"
```

What to imagine:

```text
one privileged CPU/kernel anchor
  -> many physical candidates
  -> one image relationship that explains the anchor
```

The key academic point is validation. A base address is trusted only after the
anchor, image headers, image range, and section expectations agree.

### Draft 02: Token Relationship Edit

Toy flow:

```text
system_proc = object_finder.process_by_identity("trusted-system")
self_proc   = object_finder.process_by_identity("current")

system_token = object_reader.field(system_proc, "token-reference")
self_token   = object_reader.field(self_proc, "token-reference")

if not semantic_check.token_reference(system_token):
    stop("the source token does not look valid")

state_change.save(self_proc, "token-reference", self_token)
state_change.write(self_proc, "token-reference", system_token)

if not behavior_check.new_child_has_expected_identity():
    state_change.restore(self_proc, "token-reference")
```

What to imagine:

```text
not code execution
not shellcode
just object identity changed underneath normal access-check logic
```

The bridge is object discovery plus semantic validation of the token reference.

### Draft 03: Target PPL Lowering

Toy flow:

```text
target = object_finder.process_by_role("protected-target")

original = object_reader.field(target, "protection-metadata")

if not semantic_check.protection_state(original):
    stop("target is not in expected protection state")

state_change.save(target, "protection-metadata", original)
state_change.write(target, "protection-metadata", "less-protected")

if access_test.required_handle_now_opens():
    perform_one_lab_action()

state_change.restore(target, "protection-metadata")
```

What to imagine:

```text
handle access decision reads process protection metadata
  -> metadata changed
  -> later handle decision changes
```

The bridge is not "kill PPL". The bridge is "make a later access-check consume
altered process protection state".

### Draft 04: `PreviousMode` Trust-Bit Flip

Toy flow:

```text
thread = thread_finder.current_execution_thread()
original = object_reader.field(thread, "caller-mode")

if original != "user":
    stop("unexpected caller-mode state")

execution_guard.pin_current_context()

state_change.write(thread, "caller-mode", "kernel")

try:
    result = trusted_service.read_kernel_address_for_lab()
finally:
    state_change.write(thread, "caller-mode", original)
    execution_guard.unpin_current_context()

verify.field_equals(thread, "caller-mode", "user")
```

What to imagine:

```text
one thread-local trust bit
  -> many later kernel services change pointer-probing behavior
```

The failure mode is also visible: if the wrong thread runs a syscall while the
trust bit is wrong, the system can consume a dangerous pointer.

### Draft 05: Code Integrity State Window

Toy flow:

```text
ci_state = policy_finder.code_integrity_state()
original = object_reader.field(ci_state, "driver-load-policy")

if platform.memory_integrity_protects(ci_state):
    stop("policy state is not expected to be writable")

state_change.save(ci_state, "driver-load-policy", original)
state_change.write(ci_state, "driver-load-policy", "permissive-lab-window")

load_result = lab_loader.try_one_driver_load()

state_change.restore(ci_state, "driver-load-policy")
verify.field_equals(ci_state, "driver-load-policy", original)
```

What to imagine:

```text
one policy decision happens inside a short corrupted-state window
```

The bridge is timing: the driver-load decision must happen while the altered
policy state is in effect, and restoration must happen before integrity checks
or later code depend on the impossible state.

### Draft 06: DKOM Process List Unlink

Toy flow:

```text
target = object_finder.process_by_identity("lab-target")
links  = object_reader.field(target, "enumeration-links")

if not list_check.bidirectional_links_are_consistent(links):
    stop("do not unlink from a corrupt list")

state_change.save(target, "enumeration-links", links)

list_ops.unlink(target, "enumeration-links")

normal_view  = process_view.enumeration_api()
object_view  = process_view.handle_or_thread_backing_state()

record_cross_view(normal_view, object_view)

list_ops.relink(target, state_change.saved_links(target))
verify.list_consistent_again()
```

What to imagine:

```text
one view loses the process
other kernel references still prove it exists
```

The academic point is cross-view inconsistency, not true object deletion.

### Draft 07: I/O Ring Metadata Adapter

Toy flow:

```text
ring = subsystem.create_ring()
subsystem.register_user_buffer(ring, "known-buffer")

ring_object = object_finder.kernel_object_for_handle(ring.handle)
entry = object_scanner.find_registered_buffer_entry(ring_object, "known-buffer")

original_mapping = object_reader.field(entry, "kernel-buffer-pointer")

state_change.write(entry, "kernel-buffer-pointer", "target-kernel-address")

subsystem.normal_write_operation(ring, entry)
captured = lab_output.read_result()

state_change.write(entry, "kernel-buffer-pointer", original_mapping)
verify.object_metadata_restored(entry)
```

What to imagine:

```text
corrupt object metadata
  -> normal subsystem API becomes a read adapter
```

This is the same mental model as many old GDI primitive constructions, but the
object family is different.

### Draft 08: ETW-TI Code-Path Tamper

Toy flow:

```text
log_path = telemetry_finder.event_log_path("sensitive-event-class")

if platform.code_pages_are_integrity_protected(log_path):
    stop("do not expect code mutation to work")

original = code_reader.bytes(log_path)

state_change.write_code(log_path, "return-without-logging")

perform_one_lab_operation()

state_change.restore_code(log_path, original)
verify.code_bytes_equal(log_path, original)
```

What to imagine:

```text
operation still happens
one telemetry path returns early
```

This is intentionally riskier than data-only edits because it touches executable
code expectations and therefore collides with Code Integrity, PatchGuard and
HVCI-style protections.

### Draft 09: Ps Notification Callback Storage

Toy flow:

```text
storage = callback_finder.notification_storage("process-thread-image")
entries = callback_reader.enumerate(storage)

for entry in entries:
    owner = callback_classifier.owner(entry)

    if owner == "third-party-security":
        state_change.save(entry, "callback-state", entry.snapshot())
        callback_ops.disable(entry)

event_result = lab_event.trigger_one_process_event()

callback_ops.restore_saved_entries()
verify.callback_storage_consistent(storage)
```

What to imagine:

```text
future events stop reaching selected observers
```

This does not mean the event is invisible everywhere. It means one callback
surface was altered.

### Draft 10: Object Manager Callback List

Toy flow:

```text
object_type = object_manager.type_by_name("process")
list_head = object_reader.field(object_type, "callback-list")

for node in list_walk.safe_nodes(list_head):
    if callback_classifier.owner(node) == "third-party-security":
        state_change.save(node, "list-links", node.links())
        list_ops.unlink(node)

handle_result = access_test.open_lab_target_with_requested_access()

list_ops.restore_saved_nodes()
verify.list_consistent_again()
```

What to imagine:

```text
one access-filtering layer is absent from later handle opens
```

But token checks, object ACLs, PPL and other policies may still deny access.

### Draft 11: Registry Callback Vector

Toy flow:

```text
vector = callback_finder.registry_callback_vector()

for slot in vector.slots:
    cb = callback_reader.decode(slot)

    if cb.owner == "third-party-security":
        state_change.save(slot, "registry-callback", cb)
        callback_ops.disable(slot)

registry_lab.perform_one_controlled_write()

callback_ops.restore_saved_slots()
verify.vector_shape(vector)
```

What to imagine:

```text
registry visibility is scoped to registry operations only
```

It does not blind file, network, process, Code Integrity or hypervisor
telemetry.

### Draft 12: Minifilter Operation Lists

Toy flow:

```text
for volume in filter_manager.volumes():
    for operation in interesting_file_operations:
        list_head = volume.operation_list(operation)

        for node in list_walk.safe_nodes(list_head):
            owner = filter_classifier.owner(node)

            if owner == "third-party-security-filter":
                state_change.save(node, "filter-list-links", node.links())
                list_ops.unlink(node)

file_lab.perform_one_operation_on_target_volume()

list_ops.restore_saved_nodes_reverse_order()
verify.filter_graph_consistent()
```

What to imagine:

```text
visibility depends on volume + operation class + filter instance
```

If a note does not name those three, "minifilter blind" is too vague.

### Draft 13: Self PPL Elevation

Toy flow:

```text
self = object_finder.process_by_identity("current")
original = object_reader.field(self, "protection-metadata")

state_change.save(self, "protection-metadata", original)
state_change.write(self, "protection-metadata", "higher-lab-trust")

if lower_trust_caller_cannot_open_self():
    record("access decision consumed modified target metadata")

state_change.restore(self, "protection-metadata")
verify.field_equals(self, "protection-metadata", original)
```

What to imagine:

```text
the process appears more protected to later access checks
```

It does not mean the image became legitimately signed at that protection level.

## Technique 01: Kernel Base From MSR And Physical Scan

External draft:

```text
01_kaslr_defeat.md
```

### What It Teaches

Kernel base discovery is the first bridge. A raw physical primitive is
uncomfortable until you can correlate:

```text
kernel virtual address
  <-> kernel image
  <-> physical page
```

An MSR read can expose a pointer into the kernel's syscall-entry path. A
physical scan can then look for the backing kernel image page and reconstruct
the base relationship.

### Invariant

The invariant being used:

```text
the CPU syscall-entry anchor points into ntoskrnl, and ntoskrnl remains loaded
at a stable base after boot
```

This is not a vulnerability by itself. It is a bridge from privileged hardware
state to kernel layout knowledge.

### Why It Works

It works because:

- the driver exposes MSR read,
- the syscall-entry MSR contains a kernel pointer,
- the kernel image can be recognized from PE structure and expected alignment,
- the physical read primitive can inspect candidate pages.

### Failure Modes

- physical scan touches unsafe MMIO ranges,
- kernel image layout assumption changes,
- large-page assumption is wrong for the target build/config,
- the scan finds a false PE header,
- read primitive is limited or filtered,
- the lab uses virtualization settings that alter physical layout.

### Upgrade Needed In Draft

Add a clear "trust check" after base discovery:

```text
candidate base
  -> PE headers valid
  -> export/symbol relationship valid
  -> syscall-entry VA falls inside image range
  -> physical bytes match expected virtual image region
```

This prevents teaching "first PE-looking page wins".

## Technique 02: Token Data-Only Modification

External draft:

```text
02_token_steal.md
```

### What It Teaches

Token manipulation is the classic data-only privilege lesson:

```text
process object
  -> token reference
  -> access-check identity
```

The point is not "copy this field". The point is:

```text
Windows privilege checks trust token object identity and token attributes
```

Changing the process-token relationship changes the security identity seen by
future operations.

### Invariant

The invariant being violated:

```text
only the kernel's normal process/token management paths should decide which
token a process uses
```

Physical write breaks that invariant by editing object state directly.

### Why It Works

It works when:

- the target process object is correctly identified,
- the privileged token reference remains valid,
- reference/counting semantics are not broken badly enough to crash,
- the process performs a new action after the token state changes,
- the layout assumptions match the current build.

### Failure Modes

- `EPROCESS` layout drift,
- confusing physical and virtual object addresses,
- copying a token reference without understanding fast-reference bits,
- target process exits during modification,
- process token state is cached or checked earlier than expected,
- telemetry/callbacks observe the resulting privilege anomaly.

### Upgrade Needed In Draft

Avoid saying an offset is "stable" unless the note shows symbol validation.
Better format:

```text
Observed on build:
Validated via:
Fallback if symbol unavailable:
Failure if field mismatch:
```

## Technique 03: PPL State Lowering On A Target Process

External draft:

```text
03_ppl_bypass.md
```

### What It Teaches

Protected Process Light is enforced through process protection metadata that
affects access checks. A narrow data write can change how the kernel answers:

```text
may caller open this protected process with this access mask?
```

The teaching value is:

```text
access-control state is data
```

### Invariant

The invariant:

```text
process protection level should be set only by trusted image/signing and
process-creation policy, not by post-creation arbitrary memory writes
```

### Why It Works

It works because Object Manager and process access logic consult process
protection metadata during handle creation and access checks.

If the metadata changes, later access checks can make different decisions.

### Failure Modes

- protection metadata is checked by PatchGuard on the build,
- modifying a critical process causes instability indirectly,
- write is not restored before integrity validation,
- target process is not the one expected,
- build layout differs,
- access was denied for another reason unrelated to PPL.

### Upgrade Needed In Draft

Separate two different ideas:

```text
lowering protection of a target process
raising protection of the current process
```

They use similar metadata but have different objectives and different risk.

## Technique 04: `PreviousMode` As A Semantic Bridge

External draft:

```text
04_previousmode.md
```

### What It Teaches

`PreviousMode` is powerful because it changes how kernel services interpret
caller trust:

```text
UserMode caller
  -> probe user pointers

KernelMode caller
  -> trust kernel pointers
```

The interesting part is not the byte write. The interesting part is that a
small thread-local semantic field can change the behavior of many later kernel
APIs.

### Invariant

The invariant:

```text
syscall dispatcher should be the authority for whether a request originated
from user mode or kernel mode
```

Direct memory write breaks that invariant.

### Why It Works

It works if:

- the current thread object is correctly located,
- the write targets the active thread, not a stale or wrong thread,
- the thread does not migrate or execute unrelated syscalls during the window,
- the field is restored before further user-controlled syscalls,
- the target kernel APIs still rely on `PreviousMode` as expected.

### Failure Modes

- CPU/thread affinity assumptions fail,
- scheduler preempts the thread at a bad time,
- field offset differs,
- a later syscall trusts a bad pointer and crashes the system,
- the read/write API path has additional hardening beyond `PreviousMode`.

### Upgrade Needed In Draft

Add a "thread ownership" checklist:

```text
current CPU
current thread
affinity state
preemption window
restore point
post-restore verification
```

That is the core safety property of this technique.

## Technique 05: Code Integrity State Tamper

External draft:

```text
05_dse_bypass.md
```

### What It Teaches

Driver Signature Enforcement is an enforcement result of Code Integrity state.
If a kernel write can alter CI policy state, a driver-load decision can change.

Teach it as:

```text
policy state tamper
```

not as:

```text
universal DSE bypass recipe
```

### Invariant

The invariant:

```text
Code Integrity policy state should be writable only by trusted CI initialization
and policy-management paths
```

### Why It Works

It works only if:

- the CI state target is correctly located,
- the write reaches the actual backing memory,
- HVCI or hypervisor protections do not discard or block the write,
- the driver-load action happens while the altered policy state is effective,
- the original state is restored before integrity checks notice.

### Failure Modes

- HVCI protects CI-related pages,
- physical write readback shows no semantic change,
- PatchGuard detects persistent tamper,
- wrong CI state variable is found,
- driver loading races the restore window,
- target OS build moved or changed the policy logic.

### Upgrade Needed In Draft

Make every "CI state" claim build-gated. The draft should include:

```text
Windows build
CI module version
HVCI state
Secure Boot state
WDAC policy state
vulnerable driver blocklist state
```

Without those, readers may overgeneralize.

## Technique 06: DKOM Process Hide

External draft:

```text
06_dkom_hide.md
```

### What It Teaches

Process hiding by list unlinking is a cross-view lesson:

```text
one kernel enumeration path no longer sees the object
other references still exist
```

This is not true deletion. It is view manipulation.

### Invariant

The invariant:

```text
the process list should represent every live process object consistently
```

DKOM breaks one representation while leaving the object alive.

### Why It Works

It works because many enumeration APIs historically walk or derive from a
linked process list. If a process object is unlinked, that view can become
blind while handles, threads, callbacks, scheduler state, and object references
still know the process exists.

### Failure Modes

- process exits while unlinked,
- list links are restored incorrectly,
- another view exposes the hidden process,
- endpoint tooling performs cross-view checks,
- build changes list relationship or validation,
- integrity tooling flags broken list consistency.

### Upgrade Needed In Draft

Add a cross-view table:

```text
view hidden from:
view still visible from:
what contradiction remains:
what restores consistency:
```

That makes DKOM understandable instead of magical.

## Technique 07: I/O Ring Object Metadata Bridge

External draft:

```text
07_ioring.md
```

### What It Teaches

I/O ring research is valuable because it shows how a small object metadata
change can make a legitimate subsystem perform memory access on the attacker's
behalf.

Conceptual model:

```text
registered user buffer
  -> kernel object stores mapping metadata
  -> metadata is corrupted
  -> normal I/O ring operation reads from unintended kernel VA
```

### Invariant

The invariant:

```text
I/O ring registered-buffer metadata must describe the buffer that was actually
registered and pinned
```

### Why It Works

It works when:

- the target build supports the relevant I/O ring behavior,
- the ring object is discoverable,
- registered-buffer metadata can be located without hardcoding,
- the corruption preserves object consistency enough for the subsystem to run,
- the operation length and mapping assumptions stay valid.

### Failure Modes

- API not present on the build,
- object layout changed,
- handle/object enumeration does not expose what the draft assumes,
- metadata scan finds the wrong field,
- operation length does not match mapped buffer state,
- the subsystem validates the mapping before use.

### Upgrade Needed In Draft

Describe this as a "metadata adapter" pattern:

```text
write primitive
  -> corrupt object metadata
  -> normal subsystem operation becomes read/write adapter
```

Then compare it to historical GDI bitmap/palette and Win32k USER object
bridges.

## Technique 08: ETW-TI Code-Path Tamper

External draft:

```text
08_etw_patch.md
```

### What It Teaches

This draft demonstrates direct code-path tamper against telemetry routines.
It is the riskiest class in the set because it modifies executable kernel code
or code-adjacent behavior.

Teach it as:

```text
telemetry code-path integrity violation
```

not as:

```text
recommended evasion method
```

### Invariant

The invariant:

```text
kernel telemetry provider code should remain immutable after load
```

### Why It Works

It works only if:

- the correct telemetry functions are resolved,
- the code page is writable through the primitive,
- no hypervisor/CI protection blocks the write,
- no integrity check observes the modification,
- the code is restored before destabilizing effects accumulate.

### Failure Modes

- HVCI blocks or discards writes to protected code pages,
- PatchGuard detects code modification,
- function layout changes,
- patch target is inlined or no longer exported/resolvable,
- wrong byte range corrupts nearby instructions,
- telemetry is produced by another provider/path.

### Upgrade Needed In Draft

Add a warning that code patching has different risk than data-only tamper:

```text
data-only object edit
  -> semantic corruption risk

kernel .text patch
  -> code-integrity and control-flow risk
```

This distinction is essential.

## Technique 09: Process/Thread/Image Notification Callback Tamper

External draft:

```text
09_callback_kill.md
```

### What It Teaches

Kernel notification callbacks are a visibility surface. Security tools often
register callbacks for process, thread, and image-load events. If callback
storage is modified, observers may miss later events.

### Invariant

The invariant:

```text
registered kernel callbacks should remain registered until removed through the
official unregister path
```

Direct memory write bypasses the official lifecycle.

### Why It Works

It works when:

- callback storage is located correctly,
- non-system callback entries can be distinguished from system entries,
- the write preserves enough structure for the kernel to keep running,
- the tool does not immediately re-register or self-heal,
- later security-relevant activity depends on that callback path.

### Failure Modes

- callback layout changes,
- entry encoding/refcounting is misunderstood,
- system callback is removed accidentally,
- EDR watchdog restores callback,
- another telemetry source still observes the event,
- the operation creates a cross-view contradiction.

### Upgrade Needed In Draft

Replace "PatchGuard does not check this" with:

```text
PatchGuard behavior is build- and target-dependent; verify in the exact lab.
```

Absolute claims age badly.

## Technique 10: Object Manager Callback List Tamper

External draft:

```text
10_ob_callback.md
```

### What It Teaches

Object Manager callbacks influence handle creation and duplication decisions.
Security products use them to reduce access to protected processes or threads.

The research lesson:

```text
handle-access policy can be externalized into callback chains
```

If those chains are altered, access-check behavior can change.

### Invariant

The invariant:

```text
object type callback lists should be modified only by trusted registration and
unregistration paths
```

### Why It Works

It works when:

- the object type is located correctly,
- its callback list is walked safely,
- third-party callbacks are distinguished from kernel/system callbacks,
- list integrity is preserved,
- the target access attempt actually flows through that callback list.

### Failure Modes

- wrong object type,
- wrong callback list offset,
- list corruption,
- system callback removed,
- EDR self-heals,
- target access blocked by PPL, token, job, silo, or other policy even without
  the callback.

### Upgrade Needed In Draft

Add this question:

```text
If the callback is gone, what other access-control layer can still deny access?
```

That prevents overclaiming.

## Technique 11: Registry Callback Tamper

External draft:

```text
11_cm_callback.md
```

### What It Teaches

Registry callbacks are a visibility and policy surface. Security tooling uses
them to observe persistence, service creation, security policy changes, and
other registry-sensitive behavior.

### Invariant

The invariant:

```text
registry callback registration state should match the set of active callbacks
that the Configuration Manager invokes
```

### Why It Works

It works if:

- callback storage is found,
- callback entries are decoded correctly,
- the modified callback state is still structurally valid,
- the monitored registry activity depends on those callbacks,
- no secondary telemetry catches the same behavior.

### Failure Modes

- callback-vector discovery fails,
- callback entry layout changed,
- removing the wrong entry breaks legitimate kernel behavior,
- EDR re-registers,
- ETW/Sysmon/auditing still captures the registry operation,
- access-denial policy lives somewhere else.

### Upgrade Needed In Draft

Add "visibility scope":

```text
registry callbacks cover registry operations
they do not blind file, process, network, or CI telemetry
```

## Technique 12: Filter Manager / Minifilter Callback Blind

External draft:

```text
12_minifilter_blind.md
```

### What It Teaches

Minifilters are a major file-system visibility and control layer. EDR and AV
products commonly use minifilter callbacks to inspect file activity.

The technique class is:

```text
Filter Manager object-graph manipulation
```

### Invariant

The invariant:

```text
Filter Manager callback lists should accurately describe which filters receive
which file-system operation callbacks
```

### Why It Works

It works when:

- Filter Manager global/object state is located,
- frames, volumes, and callback nodes are walked correctly,
- third-party filter callbacks are distinguished from framework/internal nodes,
- list unlinking preserves structure,
- the target activity depends on those minifilter callbacks.

### Failure Modes

- layout drift in Filter Manager objects,
- corrupted list link causes crash,
- internal node is removed,
- filter reattaches,
- another volume/frame still has callbacks,
- file-system events are captured by another layer,
- cross-view checks detect registered filter versus missing operation callback.

### Upgrade Needed In Draft

Add volume/frame scope:

```text
which volume was affected?
which IRP major classes were affected?
which filter instance remained attached?
which callback path was still active?
```

Without that, "minifilter blind" is too broad.

## Technique 13: Self PPL State Elevation

External draft:

```text
13_ppl_elevate.md
```

### What It Teaches

This is the mirror image of target PPL lowering. Instead of reducing another
process's protection, it raises protection metadata on the current process.

Teach it as:

```text
self-protection state tamper
```

not as:

```text
legitimate Protected Process identity
```

### Invariant

The invariant:

```text
protected-process state should come from trusted signing and process creation,
not post-hoc object memory writes
```

### Why It Works

It works because handle access checks compare caller/target trust and process
protection metadata. If current process protection metadata changes, other
processes may receive different access results when trying to open it.

### Failure Modes

- PatchGuard or integrity validation notices inconsistent protection,
- caller has equal or higher protection level,
- target action does not depend on process handle access,
- build layout differs,
- security tooling observes impossible signer/protection relationship,
- protection state is restored too late or not at all.

### Upgrade Needed In Draft

Add this distinction:

```text
protection metadata changed
  != image is actually Microsoft-signed at that trust level
```

This helps explain why protection-state tamper can be detectable as an
impossible identity.

## Cross-Technique Reasoning

### Why The Chain Is Strong

The external draft set is strong because it demonstrates multiple bridges from
the same primitive:

```text
physical/MSR primitive
  -> kernel base
  -> EPROCESS data-only changes
  -> thread semantic field changes
  -> object metadata adapters
  -> callback/list visibility tamper
```

That teaches a core BYOVD truth:

```text
the vulnerable driver is only the entry primitive; the objective is chosen by
which kernel invariant you decide to violate
```

### Why The Chain Is Fragile

The chain is fragile because most outcomes depend on private implementation
details:

- object offsets,
- callback storage layout,
- module code shape,
- compiler output,
- PatchGuard target set,
- HVCI policy,
- vulnerable driver blocklist state,
- vendor fixed version,
- Windows build.

Strong docs should make fragility visible, not hide it.

### Why Restoration Keeps Appearing

Many drafts include restore logic. That is not cosmetic.

Restoration matters because:

```text
kernel object graph expects consistency
integrity monitors expect stable policy state
callbacks expect registered lifecycle
linked lists expect bidirectional coherence
threads expect caller-mode state to match reality
```

The general pattern:

```text
save original state
  -> apply narrow mutation
  -> perform one objective
  -> verify effect
  -> restore original state
  -> verify restoration
```

If a technique cannot restore, the note should explain why the resulting
inconsistency is safe for the lab objective.

### Why HVCI Matters Differently Per Technique

HVCI is not a universal yes/no answer.

| Technique class | HVCI pressure |
|---|---|
| code patching | high pressure; protected executable pages may reject writes |
| Code Integrity state | high pressure; CI-related state may be protected or virtualized |
| EPROCESS data-only fields | often less direct HVCI pressure, but still build/policy sensitive |
| linked-list DKOM | usually data-oriented, but integrity/cross-view risk remains |
| I/O ring metadata | depends on object validation and build behavior |
| callback storage | data-oriented, but layout and self-healing matter |

The correct question:

```text
which page/object/state is protected, and by which layer?
```

not:

```text
is HVCI on?
```

### Why PatchGuard Claims Need Care

Avoid absolute statements like:

```text
PatchGuard does not check X
```

Prefer:

```text
This lab did not observe PatchGuard failure for X on build Y during time window Z.
```

Why:

- PatchGuard target sets have changed across builds.
- Timers are intentionally non-deterministic.
- Some checks depend on system state.
- VBS/Secure Kernel behavior changes integrity assumptions.
- A short successful demo is not proof of long-term safety.

### Why Offsets Are Not Knowledge

Offsets are observations. The knowledge is the object relationship.

Bad:

```text
field is at this offset
```

Good:

```text
field represents this semantic invariant; on build X it was observed at offset
Y using symbol method Z
```

That is the difference between a brittle PoC note and a real research note.

## Draft Quality Review

### Strong Parts

- Clear separation into one technique per file.
- Good habit of explaining "why" after many code blocks.
- Good emphasis on restore for risky state changes.
- Good coverage of both data-only and code-path tamper.
- Good inclusion of HVCI/PatchGuard stability sections.
- Good progression from base discovery to higher-level object targets.

### Main Issues To Fix

1. The docs include too many direct operational artifacts for a public research
   notebook: IOCTL layouts, hardcoded offsets, byte patch values, and runnable
   flows.
2. Some stability claims are too absolute, especially around PatchGuard,
   callback storage, and offset stability.
3. Several notes should split "primitive", "bridge", and "objective" more
   explicitly.
4. Some techniques need process/build preconditions at the top.
5. HVCI needs per-target explanation instead of general statements.
6. Detection/visibility scope should be described even in offensive study notes
   because it explains what the technique actually blinds and what it does not.
7. The docs should record symbol validation method for every private field.
8. The encoding should be normalized to UTF-8 if the drafts are meant to be
   viewed from PowerShell or copied between repos.

### Recommended Per-File Template

Use this structure for every draft:

```text
Title
Lab build and driver version
Primitive used
Objective
Preconditions
Invariant being violated
Bridge from primitive to target
Why the target matters
Failure modes
Mitigation interaction
Restore/rollback logic
Verification method
Open questions
References
```

This template preserves the educational value while preventing the note from
becoming only a recipe.

## Read Order For Learning

Recommended order:

1. `01_kaslr_defeat.md`
2. `04_previousmode.md`
3. `02_token_steal.md`
4. `03_ppl_bypass.md`
5. `13_ppl_elevate.md`
6. `07_ioring.md`
7. `06_dkom_hide.md`
8. `09_callback_kill.md`
9. `10_ob_callback.md`
10. `11_cm_callback.md`
11. `12_minifilter_blind.md`
12. `05_dse_bypass.md`
13. `08_etw_patch.md`

Why this order:

```text
layout discovery
  -> semantic data field
  -> object identity
  -> object metadata bridge
  -> visibility surfaces
  -> policy/code integrity tamper last
```

Code and CI patching are last because they are the most fragile and easiest to
overgeneralize.

## Study Questions

1. What primitive does `LnvMSRIO.sys` provide before any bridge is added?
2. Why is kernel base discovery a bridge, not an objective?
3. Why does physical write need VA-to-PA translation for most object targets?
4. Why is token modification a data-only attack?
5. What is the semantic difference between target PPL lowering and self PPL
   elevation?
6. Why does `PreviousMode` affect later syscall behavior?
7. Why are I/O ring object edits similar in spirit to historical GDI object
   metadata primitives?
8. Why is code patching riskier than data-only state tamper?
9. Why do callback-removal techniques blind only specific visibility surfaces?
10. What contradiction remains after process DKOM unlinking?
11. Why can HVCI block one technique while not directly blocking another?
12. Why is "PatchGuard did not fire" not proof that a technique is safe?
13. How would you validate a private offset without hardcoding it?
14. What must be restored for each technique?
15. Which technique is most build-sensitive, and why?

## Local And External References

Local drafts reviewed:

- `E:\driver_research\lenovo_lpe\docs\01_kaslr_defeat.md`
- `E:\driver_research\lenovo_lpe\docs\02_token_steal.md`
- `E:\driver_research\lenovo_lpe\docs\03_ppl_bypass.md`
- `E:\driver_research\lenovo_lpe\docs\04_previousmode.md`
- `E:\driver_research\lenovo_lpe\docs\05_dse_bypass.md`
- `E:\driver_research\lenovo_lpe\docs\06_dkom_hide.md`
- `E:\driver_research\lenovo_lpe\docs\07_ioring.md`
- `E:\driver_research\lenovo_lpe\docs\08_etw_patch.md`
- `E:\driver_research\lenovo_lpe\docs\09_callback_kill.md`
- `E:\driver_research\lenovo_lpe\docs\10_ob_callback.md`
- `E:\driver_research\lenovo_lpe\docs\11_cm_callback.md`
- `E:\driver_research\lenovo_lpe\docs\12_minifilter_blind.md`
- `E:\driver_research\lenovo_lpe\docs\13_ppl_elevate.md`

External references:

- Quarkslab,
  [Exploiting Lenovo driver CVE-2025-8061](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html)
- Quarkslab,
  [Exploiting Lenovo driver CVE-2025-8061 - part 2](https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html)
- NVD,
  [CVE-2025-8061](https://nvd.nist.gov/vuln/detail/CVE-2025-8061)
- Microsoft,
  [Microsoft vulnerable driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)

Related repo notes:

- `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO.md`
- `03_byovd/00_index-and-matrix/BYOVD_MSR_PORT_MMIO_HARDWARE_PRIMITIVES.md`
- `03_byovd/00_index-and-matrix/BYOVD_PHYSICAL_MEMORY_PRIMITIVES_DEEP_DIVE.md`
- `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
- `docs/kernel-research/previousmode-research-notes.md`
- `docs/kernel-research/io-ring-research-notes.md`
- `docs/kernel-research/hkom-dkom-hide-research-notes.md`
- `docs/detection-and-mitigation/driver-evasion-pressure-map.md`

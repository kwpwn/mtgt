# Kernel Primitive Pseudocode Sketchbook

Updated: 2026-05-27

## Purpose

This file exists because pure taxonomy is hard to visualize. A serious Windows
kernel research note needs something more concrete than:

```text
arbitrary write -> impact
```

But copying real exploit code, IOCTL layouts, offsets, patch bytes, and bypass
recipes turns a learning note into an operational runbook. This sketchbook uses
pseudo-PoCs instead:

```text
toy object
  -> toy primitive
  -> toy invariant violation
  -> toy bridge
  -> real research lesson
```

The snippets below are intentionally not valid Windows exploit code. They have
no real device names, IOCTLs, offsets, syscall numbers, byte patches, or
structure layouts. The goal is to make the mechanics imaginable while keeping
the durable academic lesson: what invariant breaks, why a primitive matters,
and what bridge is required.

## How To Read These Snippets

Every mini-PoC has five parts:

| Part | Meaning |
|---|---|
| Toy model | Small fake structures that represent the real concept. |
| Primitive | The capability obtained from a bug or vulnerable driver. |
| Invariant | What the kernel/subsystem assumes should remain true. |
| Bridge | How the primitive becomes useful. |
| Failure mode | Why the same idea fails on a real modern build. |

If you can explain all five, you understand the technique better than someone
who only memorizes a PoC.

## Sketch 01: Primitive Interface

Most BYOVD chains can be abstracted into a small interface:

```text
primitive.read_physical(address, length) -> bytes
primitive.write_physical(address, bytes) -> ok/fail
primitive.read_msr(name) -> value
primitive.read_kernel_va(address, length) -> bytes
primitive.write_kernel_va(address, bytes) -> ok/fail
```

This is not an implementation. It is a research vocabulary.

### Why This Helps

Different vulnerable drivers expose different concrete operations:

```text
driver A -> physical map
driver B -> kernel memcpy
driver C -> MSR read/write
driver D -> limited write
driver E -> callback unregister helper
```

But after abstraction, you can ask the same questions:

```text
Can I read?
Can I write?
Is the address physical or virtual?
Is length controlled?
Is alignment constrained?
Does the primitive fault safely?
Can I verify the write?
Can I restore original state?
```

### Toy Example

```text
primitive = {
    kind: "physical-read-write",
    max_read: "one page",
    max_write: "small aligned write",
    address_space: "physical",
    fault_behavior: "may crash on MMIO",
    verification: "readback required"
}
```

The learning point:

```text
the primitive is not the exploit; the primitive is the tool the exploit must
bridge into a target object or policy state
```

## Sketch 02: Kernel Base Discovery From A Trusted Anchor

### Toy Model

```text
cpu.syscall_entry_anchor = kernel_va_inside_kernel_image

kernel_image = {
    base_va: unknown,
    size: unknown,
    headers: "PE-like",
    code: "... syscall entry lives here ..."
}
```

### Pseudo-PoC

```text
anchor_va = primitive.read_cpu_anchor("syscall-entry")

for candidate_pa in aligned_physical_candidates:
    page = primitive.read_physical(candidate_pa, one_page)

    if looks_like_kernel_image_header(page):
        candidate_base_va = infer_virtual_base(candidate_pa)

        if anchor_va_is_inside(candidate_base_va, image_size):
            if bytes_near_anchor_match_expected_image_region():
                return candidate_base_va

return not_found
```

### Invariant

```text
the CPU needs a stable syscall-entry target, and that target lives inside the
loaded kernel image
```

### Why It Works

The anchor gives you one point inside the kernel image. A scan finds the image
base. The bridge is:

```text
one pointer inside image
  -> image base
  -> symbol-relative reasoning
```

### Why It Fails

```text
false PE-looking page
wrong physical/virtual relationship
unsafe MMIO read
image not mapped as expected
anchor belongs to a trampoline or different module
symbol offset assumed from wrong build
```

### Real Lesson

Kernel base discovery is not impact. It is a layout bridge.

## Sketch 03: Virtual Target From Physical Primitive

### Toy Model

```text
virtual_address = 0xKERNEL_OBJECT_FIELD
physical_address = page_table_translate(virtual_address)
```

### Pseudo-PoC

```text
function safe_write_kernel_field(kernel_va, new_value):
    pa = translate_kernel_va_to_pa(kernel_va)

    if pa is invalid:
        return fail("no physical backing")

    original = primitive.read_physical(pa, size(new_value))

    if original does not look semantically valid:
        return fail("wrong field or wrong build")

    primitive.write_physical(pa, new_value)

    verify = primitive.read_physical(pa, size(new_value))
    if verify != new_value:
        primitive.write_physical(pa, original)
        return fail("write did not stick")

    return restore_token(original)
```

### Invariant

```text
kernel virtual object state should not be editable through raw physical memory
without memory manager/object manager participation
```

### Why It Works

The bridge converts:

```text
physical primitive
  -> virtual object target
  -> semantic field edit
```

### Why It Fails

```text
wrong CR3/page table root
large-page handling missing
page not present
target is in device/MMIO memory
target field is not at assumed layout
write is blocked/virtualized
semantic validation was too weak
```

### Real Lesson

Physical write is powerful only after address translation and object
validation. Without those, it is mostly a crash generator.

## Sketch 04: Data-Only Token Relationship

### Toy Model

```text
Process {
    pid
    name
    token_ref
}

Token {
    user_sid
    groups
    privileges
}
```

### Pseudo-PoC

```text
system_process = find_process_by_name("trusted-system-process")
self_process   = find_process_by_pid(current_pid)

system_token = read_field(system_process, "token_ref")
self_token   = read_field(self_process, "token_ref")

if not token_ref_looks_valid(system_token):
    stop("bad token reference")

write_field(self_process, "token_ref", system_token)

if child_process_inherits_expected_identity():
    objective_complete()
else:
    write_field(self_process, "token_ref", self_token)
```

### Invariant

```text
process token identity should change only through trusted kernel token-management
paths
```

### Why It Works

Access checks consult the process token. If the process object now points at a
different trusted token object, later operations can be evaluated with a
different identity.

### Why It Fails

```text
wrong process object
wrong token field
bad fast-reference handling
token object lifetime issue
child process created before token change
access denied by PPL or another policy layer
layout drift
```

### Real Lesson

This is a semantic data attack. No kernel shellcode is required because the
kernel itself continues doing normal access checks against corrupted state.

## Sketch 05: Protection Metadata Lowering

### Toy Model

```text
Process {
    token_ref
    protection_level
}

function can_open_process(caller, target, desired_access):
    if target.protection_level > caller.protection_level:
        return denied
    return normal_access_check(caller.token, target, desired_access)
```

### Pseudo-PoC

```text
target = find_process("protected-target")

original_protection = read_field(target, "protection_level")

if not protection_level_looks_expected(original_protection):
    stop("target is not in expected protection state")

write_field(target, "protection_level", lower_level)

if access_check_now_allows_required_handle():
    perform_one_lab_action()

write_field(target, "protection_level", original_protection)
verify_restored(target, original_protection)
```

### Invariant

```text
protected-process state should be decided by trusted signing/process-creation
policy, not direct object memory writes
```

### Why It Works

Handle access checks read process protection metadata. If metadata is lowered,
the same handle request may receive a different decision.

### Why It Fails

```text
wrong process
wrong protection field
PatchGuard/integrity check observes inconsistent state
access denied by token/ACL even after protection change
target exits or crashes
restore missed
```

### Real Lesson

Changing one byte of semantic state can be more powerful than controlling
instruction pointer, but it is also easy to overclaim because many other access
checks still exist.

## Sketch 06: Self-Protection Metadata Raising

### Toy Model

```text
self.protection_level = normal

security_agent tries:
    open(self, terminate | write_memory)
```

### Pseudo-PoC

```text
self = find_process_by_pid(current_pid)
original = read_field(self, "protection_level")

write_field(self, "protection_level", high_trust_label)

if lower_trust_process_cannot_open_self():
    record("protection metadata affected access result")

write_field(self, "protection_level", original)
verify_restored(self, original)
```

### Invariant

```text
a process should not be able to become a protected-process identity by editing
its own kernel object metadata
```

### Why It Works

Other processes' handle requests compare against the target's protection
metadata. If your process appears more protected, lower-trust callers may be
denied.

### Why It Fails

```text
caller is equal/higher trust
other policy still grants/denies independently
protection/signing relationship looks impossible
integrity check notices
build layout differs
restore fails
```

### Real Lesson

Protection metadata is a policy input. It is not the same as actually being a
legitimately signed protected process.

## Sketch 07: `PreviousMode` As A Trust Bit

### Toy Model

```text
Thread {
    previous_mode: UserMode | KernelMode
}

function kernel_service(thread, pointer):
    if thread.previous_mode == UserMode:
        probe_user_pointer(pointer)
    else:
        trust_kernel_pointer(pointer)

    read_or_write(pointer)
```

### Pseudo-PoC

```text
thread = locate_current_thread()
original_mode = read_field(thread, "previous_mode")

if original_mode != UserMode:
    stop("unexpected thread state")

write_field(thread, "previous_mode", KernelMode)

try:
    result = call_kernel_service_with_kernel_pointer()
finally:
    write_field(thread, "previous_mode", original_mode)

verify_field(thread, "previous_mode", UserMode)
```

### Invariant

```text
only the syscall entry/dispatcher should decide whether the caller came from
user mode or kernel mode
```

### Why It Works

Some kernel service paths decide whether to probe pointers based on
`PreviousMode`. If that trust bit is changed, later calls may treat a pointer
as kernel-trusted.

### Why It Fails

```text
wrong thread
thread migrates/preempts during the window
field offset drift
service path has extra validation
restore happens too late
unrelated syscall runs while mode is wrong
```

### Real Lesson

This is a semantic bridge. A tiny data edit changes how later kernel code
interprets caller trust.

## Sketch 08: Code Integrity Policy State

### Toy Model

```text
CodeIntegrity {
    driver_signing_policy
    memory_integrity_state
}

function load_driver(image):
    if CodeIntegrity.driver_signing_policy rejects image:
        return denied
    return load(image)
```

### Pseudo-PoC

```text
ci_state = locate_code_integrity_policy_state()
original = read_field(ci_state, "driver_signing_policy")

if memory_integrity_protects(ci_state):
    stop("write may not affect real policy state")

write_field(ci_state, "driver_signing_policy", permissive_test_state)

attempt_one_lab_load()

write_field(ci_state, "driver_signing_policy", original)
verify_restored(ci_state, original)
```

### Invariant

```text
driver-load policy should be controlled by Code Integrity and platform policy,
not arbitrary kernel memory writes
```

### Why It Works

The loader consults policy state. If state is corrupted during the load
decision, the decision may change.

### Why It Fails

```text
HVCI protects or virtualizes the relevant state
wrong state variable
policy has multiple enforcement layers
PatchGuard observes persistent tamper
restore races the load
WDAC/blocklist still denies load
```

### Real Lesson

Policy-state tamper is not the same as disabling every enforcement layer.
Always ask which policy check actually consumed the corrupted state.

## Sketch 09: DKOM Process Hiding

### Toy Model

```text
ProcessList: A <-> B <-> C <-> D

hide C:
    B.next = D
    D.prev = B
    C.prev = C
    C.next = C
```

### Pseudo-PoC

```text
target = find_process_by_pid(pid)

links = read_field(target, "process_list_links")
save_original_links(target, links)

if not list_links_are_consistent(links):
    stop("bad list state")

unlink_from_list(target)

if normal_process_enumeration_misses(target):
    record("one view is blind")

if scheduler_or_handle_table_still_references(target):
    record("object still exists")

restore_links(target)
verify_list_consistency()
```

### Invariant

```text
the process enumeration list should be a consistent view of live process
objects
```

### Why It Works

Some enumeration paths trust a list. Removing an object from that list blinds
that view, but other kernel references remain.

### Why It Fails

```text
process exits while unlinked
links restored incorrectly
another view sees the process
cross-view check detects contradiction
layout drift
list integrity checks fail
```

### Real Lesson

DKOM hiding is not deletion. It is inconsistent object visibility.

## Sketch 10: I/O Ring Metadata Adapter

### Toy Model

```text
IoRingObject {
    registered_buffers[0].user_va
    registered_buffers[0].system_va
    registered_buffers[0].length
}

function ring_write_to_file(ring, index):
    src = ring.registered_buffers[index].system_va
    len = ring.registered_buffers[index].length
    file.write(copy_from_kernel(src, len))
```

### Pseudo-PoC

```text
ring = create_toy_ring()
register_buffer(ring, normal_user_buffer)

object = locate_ring_object_for_current_process()
entry  = locate_registered_buffer_entry(object)

original_system_va = read_field(entry, "system_va")

write_field(entry, "system_va", target_kernel_va)

ring_write_to_file(ring, buffer_index)
captured = read_file_output()

write_field(entry, "system_va", original_system_va)
verify_restored(entry)
```

### Invariant

```text
registered-buffer metadata should continue to describe the buffer that was
actually registered and pinned
```

### Why It Works

The normal subsystem operation trusts object metadata. If metadata is changed,
the subsystem may copy from or to a different address than intended.

### Why It Fails

```text
object layout changed
registered buffer entry not found
length mismatch
subsystem validates mapping before use
API not available on build
metadata corruption crashes cleanup path
```

### Real Lesson

This is the same family as many object-metadata primitives:

```text
corrupt metadata
  -> let normal kernel code perform the access
```

## Sketch 11: Generic Callback Array Blinding

### Toy Model

```text
CallbackArray = [
    system_callback,
    security_vendor_callback,
    audit_callback
]

function notify_event(event):
    for cb in CallbackArray:
        if cb.enabled:
            cb.function(event)
```

### Pseudo-PoC

```text
array = locate_callback_storage("process-or-image-events")
entries = enumerate_callbacks(array)

for entry in entries:
    owner = classify_callback_owner(entry)

    if owner == "third-party-security-tool":
        saved.append(save_entry(entry))
        disable_entry(entry)

trigger_one_lab_event()
observe_which_callbacks_receive_it()

for saved_entry in saved:
    restore_entry(saved_entry)

verify_callback_storage_consistency(array)
```

### Invariant

```text
registered callbacks should remain active until removed through official
registration lifecycle
```

### Why It Works

Notification code trusts callback storage. If callback entries are disabled or
removed, later events may not reach the observer.

### Why It Fails

```text
callback storage layout changed
entry owner misclassified
system callback disabled
security tool self-heals
other telemetry path still observes the event
cross-view check detects missing callback
```

### Real Lesson

Callback tamper is scoped. It blinds a specific visibility surface, not the
entire system.

## Sketch 12: Object Manager Callback Chain

### Toy Model

```text
ObjectType("Process") {
    callback_list = [
        security_pre_open_callback,
        audit_post_open_callback
    ]
}

function open_object(caller, target, access):
    for cb in target.type.callback_list:
        access = cb.pre_operation(caller, target, access)

    return access_check(caller, target, access)
```

### Pseudo-PoC

```text
process_type = locate_object_type("Process")
callbacks = walk_callback_list(process_type)

for cb in callbacks:
    if callback_owner_is_security_vendor(cb):
        saved.append(save_callback_node(cb))
        unlink_or_disable_callback(cb)

result = attempt_one_handle_open()

restore_callback_nodes(saved)
verify_callback_list(process_type)
```

### Invariant

```text
object type callback lists should be changed only by official Object Manager
registration and unregistration paths
```

### Why It Works

Object Manager consults callback chains during handle operations. If a security
callback is missing, the requested access may not be reduced or denied by that
callback.

### Why It Fails

```text
PPL still denies access
token/ACL still denies access
wrong object type
callback list corruption
security tool re-registers
another callback still blocks the access
```

### Real Lesson

Removing a callback removes one policy layer. It does not automatically grant
access if another layer denies it.

## Sketch 13: Registry Callback Chain

### Toy Model

```text
RegistryCallbacks = [
    monitor_persistence_keys,
    monitor_services_keys,
    audit_security_keys
]

function registry_write(key, value):
    for cb in RegistryCallbacks:
        cb.pre_set_value(key, value)
    perform_write(key, value)
```

### Pseudo-PoC

```text
callbacks = locate_registry_callback_vector()
saved = []

for cb in callbacks:
    if callback_owner_is_third_party(cb):
        saved.append(save_callback(cb))
        disable_callback(cb)

perform_one_lab_registry_operation()

restore_callbacks(saved)
verify_registry_callback_vector()
```

### Invariant

```text
Configuration Manager callback state should match the registered registry
observers
```

### Why It Works

Registry operations invoke registered callbacks. If callback storage is altered,
some observers may miss registry operations.

### Why It Fails

```text
wrong vector
wrong callback entry layout
callback owner misclassified
EDR re-registers
Sysmon/ETW/auditing sees the event anyway
the target action does not use registry callbacks
```

### Real Lesson

A visibility primitive must be tied to the exact event class it affects.

## Sketch 14: Minifilter Operation List Unlink

### Toy Model

```text
Volume {
    operation_lists[READ]  = [filterA, filterB, filterC]
    operation_lists[WRITE] = [filterA, filterB, filterC]
}

function dispatch_file_operation(volume, op, request):
    for filter in volume.operation_lists[op]:
        filter.pre_operation(request)
    file_system.perform(request)
```

### Pseudo-PoC

```text
for volume in enumerate_filter_manager_volumes():
    for operation in interesting_operations:
        nodes = walk_operation_list(volume, operation)

        for node in nodes:
            owner = classify_filter_owner(node)

            if owner == "third-party-security-filter":
                saved.append(save_list_node(volume, operation, node))
                unlink_node(node)

perform_one_lab_file_operation()

restore_nodes_in_reverse_order(saved)
verify_filter_lists()
```

### Invariant

```text
Filter Manager operation lists should accurately represent which filters receive
which file-system operations on which volume
```

### Why It Works

File operations are dispatched through operation-specific callback lists. If a
filter node is removed from a list, that filter may not see that operation on
that volume.

### Why It Fails

```text
wrong volume
wrong operation class
internal filter node removed
list corrupted
filter reattaches
another layer observes the file action
operation list layout changed
```

### Real Lesson

Minifilter blinding is scoped by volume and operation type. It is not a global
"files become invisible" switch.

## Sketch 15: ETW Provider Code-Path Tamper

### Toy Model

```text
function telemetry_log_sensitive_event(event):
    encode_event(event)
    publish_to_consumers(event)

function sensitive_operation():
    telemetry_log_sensitive_event(event)
    perform_operation()
```

### Pseudo-PoC

```text
provider = locate_telemetry_provider()
log_function = resolve_provider_log_path(provider, "sensitive-event-class")

if code_page_is_integrity_protected(log_function):
    stop("code tamper not expected to work")

original_code = read_code_bytes(log_function)

replace_log_path_with_noop_for_short_window(log_function)

perform_one_lab_operation()

restore_code_bytes(log_function, original_code)
verify_code_restored(log_function)
```

### Invariant

```text
loaded kernel code should remain immutable and match Code Integrity expectations
```

### Why It Works

If the telemetry path returns early or no-ops, the sensitive operation may still
run while the intended event is not published from that path.

### Why It Fails

```text
HVCI blocks write
PatchGuard detects code tamper
wrong function path
another telemetry path logs the same event
instruction boundary corrupted
code is inlined or moved
restore fails
```

### Real Lesson

Code tamper is more fragile than data-only tamper. It interacts directly with
Code Integrity, PatchGuard, HVCI, and control-flow assumptions.

## Sketch 16: Win32k Callback Reentrancy

### Toy Model

```text
Window {
    type
    extra_bytes
    alive
}

function create_window(user_callback):
    wnd = allocate_window()
    validate(wnd)

    call_user_mode(user_callback, wnd.handle)

    use_window_as_if_still_valid(wnd)
```

### Pseudo-PoC

```text
function user_callback(handle):
    wnd = lookup_window(handle)
    mutate_window_state(wnd)
    return

create_window(user_callback)
```

### Invariant

```text
state validated before a user-mode callback must still be valid after the
callback returns
```

### Why It Works

The kernel validates one representation, gives user mode a reentrant execution
window, then resumes with stale assumptions.

### Why It Fails

```text
object strongly referenced across callback
state revalidated after callback
dangerous transition blocked
object layout changed
callback no longer reachable
Win32k syscalls disabled for the process
```

### Real Lesson

The exploitability is in the time split:

```text
check
  -> user-mode reentry
  -> use
```

## Sketch 17: Win32k/GDI Metadata Mismatch

### Toy Model

```text
Surface {
    width
    height
    bytes_per_pixel
    backing_memory
}

function draw(surface, src):
    bytes = surface.width * surface.height * surface.bytes_per_pixel
    copy(surface.backing_memory, src, bytes)
```

### Pseudo-PoC

```text
surface = create_surface(normal_dimensions)

corrupt_metadata(surface, {
    width: larger_than_backing_allocation
})

draw(surface, controlled_source)
observe_adjacent_object_metadata_change()
```

### Invariant

```text
graphics metadata must accurately describe the backing memory used by drawing
operations
```

### Why It Works

Drawing code trusts metadata. If metadata and allocation size disagree, normal
graphics behavior can become out-of-bounds memory access.

### Why It Fails

```text
checked arithmetic
consistent size validation
object isolation
metadata hidden from attacker
allocation adjacency not controllable
modern GDI hardening
```

### Real Lesson

GDI primitives teach a general pattern:

```text
corrupt object metadata
  -> normal subsystem operation becomes memory primitive
```

## Sketch 18: Limited Write Upgrade

### Toy Model

```text
primitive.write_one_byte(address, value)
```

### Pseudo-PoC

```text
candidate_targets = [
    boolean_policy_flag,
    caller_mode_byte,
    protection_level_byte,
    reference_count_low_bits,
    enabled_flag
]

for target in candidate_targets:
    if target.size == one_byte:
        if target.semantic_change_is_understood:
            if target.restore_is_possible:
                consider_bridge(target)
```

### Invariant

```text
small fields can encode large trust decisions
```

### Why It Works

Some kernel decisions depend on compact state:

```text
mode byte
protection byte
enabled flag
policy bit
callback active flag
```

A weak primitive becomes powerful if it hits one of those semantic fields.

### Why It Fails

```text
field not actually one byte
neighbor fields corrupted
state cached elsewhere
integrity check notices impossible value
write is not atomic for target semantics
restore impossible
```

### Real Lesson

Primitive strength is not only about write size. It is about semantic leverage.

## Sketch 19: Object Metadata Adapter Pattern

### General Pattern

```text
Object {
    pointer_to_buffer
    length
    permissions
}

function normal_api(object):
    copy(object.pointer_to_buffer, object.length)
```

### Pseudo-PoC

```text
object = create_normal_object()
original = snapshot_metadata(object)

write_field(object, "pointer_to_buffer", target_address)
write_field(object, "length", safe_length)

normal_api(object)

restore_metadata(object, original)
```

### Invariant

```text
object metadata should describe resources owned by that object
```

### Why It Works

The subsystem is not "exploited" at the API layer. The object it trusts has
been corrupted underneath it.

### Examples Of This Pattern

```text
GDI bitmap/palette history
I/O ring registered buffers
MDL misuse
driver copy descriptors
Win32k USER object extra state
kernel queue entries
```

### Real Lesson

Many modern exploit bridges are object metadata adapter attacks.

## Sketch 20: Restore Discipline

### Toy Model

```text
StateMutation {
    target
    original_value
    new_value
    apply()
    verify()
    restore()
}
```

### Pseudo-PoC

```text
mutation = prepare_mutation(target, new_value)

original = read_target(target)
mutation.original_value = original

if not validate_original(original):
    stop("target not safe")

mutation.apply()

if not mutation.verify():
    mutation.restore()
    stop("write failed")

perform_one_objective()

mutation.restore()

if read_target(target) != original:
    stop("system state still inconsistent")
```

### Invariant

```text
kernel subsystems assume their state remains internally consistent over time
```

### Why It Matters

Many exploit notes treat restore as cleanup. In kernel research, restore is a
stability primitive.

Without restore:

```text
PatchGuard may fire
callbacks remain missing
lists remain corrupt
thread trust state remains wrong
policy state remains impossible
object cleanup later crashes
```

### Real Lesson

Every state tamper note should answer:

```text
what was saved?
what was changed?
what proves the change took effect?
what proves the original state came back?
what happens if restore fails?
```

## Mapping Sketches To Existing Docs

| Sketch | Read next |
|---|---|
| Kernel base anchor | `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md` |
| Physical-to-virtual bridge | `03_byovd/00_index-and-matrix/BYOVD_PHYSICAL_MEMORY_PRIMITIVES_DEEP_DIVE.md` |
| Token relationship | `docs/windows-internals/eprocess-token-object-model.md` |
| Protection metadata | `docs/kernel-research/offensive-driver-exploitability-map.md` |
| PreviousMode | `docs/kernel-research/previousmode-research-notes.md` |
| Code Integrity state | `docs/mitigations/dse-code-integrity-research-notes.md` |
| DKOM process hide | `docs/kernel-research/hkom-process-hide-crossview.md` |
| I/O ring metadata | `docs/kernel-research/io-ring-research-notes.md` |
| Callback storage | `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md` |
| Minifilter object graph | `docs/detection-and-mitigation/minifilter-and-edr-visibility.md` |
| Win32k callback | `docs/kernel-research/win32k-research-notes.md` |
| Win32k cases | `docs/kernel-research/win32k-case-study-atlas.md` |
| LnvMSRIO chain | `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md` |

## Study Questions

1. Which snippets demonstrate a read bridge, and which demonstrate a write
   bridge?
2. Which snippets rely on object metadata rather than direct access to a final
   target?
3. Which snippets are data-only, and which modify code or code-adjacent state?
4. Which snippets require restore to avoid long-term inconsistency?
5. Which snippets would fail if HVCI protects the target page?
6. Which snippets would fail if the process lacks Win32k syscall access?
7. Which snippets are scoped to one visibility surface instead of global
   invisibility?
8. Which snippets require a kernel information leak before the primitive is
   useful?
9. Which snippets depend on private object layout?
10. Which snippets can be described as "normal subsystem API trusts corrupted
    metadata"?
11. Why is a one-byte write sometimes enough?
12. Why is a full arbitrary write sometimes still not enough?
13. What does every restore path need to verify?
14. How would you rewrite a public PoC into one of these invariant patterns?
15. Which bridge would be most fragile across Windows builds?


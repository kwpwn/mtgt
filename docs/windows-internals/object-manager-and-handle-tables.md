# Object Manager and Handle Tables

## Purpose

This document explains the Windows Object Manager and handle-table model from the perspective of kernel research, driver review, debugging, and defensive analysis. It focuses on namespace structure, handle mediation, reference counting, and why overly permissive device exposure becomes a security boundary problem.

## Background

The Windows kernel does not ask user mode to work directly with most kernel object pointers. Instead, it inserts a managed layer:

- named objects and namespaces,
- handle creation and access checks,
- object typing,
- reference counting,
- security descriptors,
- symbolic links across namespaces.

That layer is the Object Manager. When a driver exposes a device object to user mode, it is not bypassing the Object Manager; it is relying on it. Understanding this is essential for reverse engineering `CreateFile` and `DeviceIoControl` paths safely.

### Object Manager role

The Object Manager provides a common model for many kernel-managed entities:

- directories,
- symbolic links,
- devices,
- files,
- events,
- sections,
- processes,
- threads,
- tokens,
- registry keys through related subsystem interactions.

It is both a naming system and a lifetime-management system.

### Kernel objects

A kernel object is more than an address. It is:

- an object body with type-specific state,
- metadata that describes type and lifetime,
- optional name and security state,
- references from handles, pointers, lists, or subsystem-private ownership.

### Object namespace, directories, and symbolic links

Windows implements an object namespace conceptually similar to a hierarchical directory tree. Directories can contain:

- named objects,
- other directories,
- symbolic links to other object paths.

This is why device exposure often involves both a kernel name like `\Device\VendorThing` and a user-visible name in `\??` or `\DosDevices`.

### Handles vs pointers

Handles are mediated references. Pointers are raw in-memory references. A handle value does not equal an object pointer, and confusing the two leads to both driver bugs and flawed exploit reasoning.

### Reference counts vs handle counts

Object lifetime is not controlled only by handles. Windows also tracks pointer-style references. Conceptually:

- handle count reflects open handle-based references,
- pointer count reflects broader live references inside the kernel.

An object can have zero visible user handles and still remain alive because the kernel or a driver still holds pointer references.

### Security descriptors and access checks

Named objects can carry security descriptors. Access masks determine what a granted handle may do. This makes device exposure a security question, not just a plumbing question.

## Core Concepts

### `OBJECT_HEADER` concept

The object header is the metadata region conceptually associated with an object body. It represents state such as:

- type identity,
- reference-related counts,
- optional name or security attachments,
- lifetime-management metadata.

The important research lesson is that a pointer to an object body does not reveal the full object-management picture.

### Object type and object body

Windows uses object typing to keep semantics coherent. The object body is the type-specific payload. The type determines:

- what access rights mean,
- what callbacks or parse logic may apply,
- how the object participates in the namespace,
- which APIs are valid for it.

### `HANDLE_TABLE` concept

Each process has a handle table used to translate handle values into object references plus granted access information. That means a handle is a lookup key into per-process state, not a universal object address.

### Handle value vs object pointer

This distinction matters in both defense and debugging:

- the same object can be referenced by multiple handles,
- different processes can hold different handles to the same object,
- the granted access on those handles can differ,
- the kernel can also hold pointer references without exposing handles.

### Access mask and granted access

Requested access is what the caller asks for. Granted access is what the system actually allows on the resulting handle. Many driver security issues arise when code accepts a caller-supplied handle but fails to validate:

- object type,
- granted access,
- origin mode,
- and whether the handle should be treated as user or kernel context.

### `ObReferenceObjectByHandle`

This routine is conceptually the bridge from handle world to pointer world. Microsoft documents that it performs access validation and returns a pointer to the object's body if access can be granted. That makes it a critical trust-boundary function in driver review.

### `ObDereferenceObject`

Pointer-based references must eventually be released. Failure to dereference can leak lifetime. Wrongly retaining a pointer beyond valid ownership can turn a logic bug into a stale-reference hazard.

### Named vs unnamed objects and session scope

Not every object is named in a globally visible namespace. Some objects are unnamed and reachable only through existing references. Session-aware paths also matter because user-visible naming can differ by session context even when the underlying device object model looks similar.

## Technical Deep Dive

### Process handle table

At a practical level, a process handle table is the process's active map of mediated object access. Research relevance:

- it explains why user mode normally cannot name arbitrary object pointers directly,
- it gives defenders a way to inspect which processes own what kinds of object references,
- it explains why passing a handle into kernel mode is still a security decision, not merely a pointer conversion.

### System/global namespace idea

Several namespaces matter often in driver research:

- `\Device`
- `\Driver`
- `\??` or `\DosDevices`
- directory objects that group related names

The namespace is where symbolic-link exposure becomes visible and where weak device-naming or ACL choices can widen attack surface.

### `\Device`

Device objects often live under `\Device`. This is the kernel-facing name that a driver or subsystem creates.

### `\DosDevices` / `\??`

These paths provide the user-visible symbolic-link layer that lets ordinary Win32 code open `\\.\Name` style handles. The DOS-device symbolic link is therefore not cosmetic; it is the bridge from user naming into the kernel object namespace.

### Driver-created device objects and userland opening handles

Conceptual path:

```text
driver creates \Device\VendorObject
  -> driver creates symbolic link under \?? or \DosDevices
  -> user process calls CreateFile on \\.\VendorObject
  -> Object Manager resolves the DOS-device symbolic link
  -> file/device object handle is created
  -> DeviceIoControl later depends on that handle
```

This is why weak device security is dangerous. The privilege boundary is often:

```text
Can an untrusted user obtain a valid handle to the device object?
```

If yes, every private IOCTL behind that handle becomes part of the reachable attack surface.

### Object lifetime bugs

Important bug families:

- stale pointer:
  code keeps using an object pointer after the ownership assumption changed.
- missing dereference:
  reference leak keeps objects alive longer than expected.
- use after free:
  object body reused after final lifetime ends.
- leaked reference:
  system behavior changes because objects never leave the live set.
- confused object type:
  handle or pointer treated as one object class when it actually names another.

These are lifetime and typing failures, not just memory-layout mistakes.

### Handle access downgrade and monitoring

Security products and kernel callbacks may observe or constrain handle operations at a conceptual level through object callbacks and related policy mechanisms. This does not make the Object Manager a universal defense layer, but it does mean:

- handle creation and duplication are meaningful telemetry points,
- unexpected process-to-device handle patterns can be suspicious,
- broad device ACLs erase an early opportunity for containment.

## Object Namespace Diagram

```text
userland path
  \\.\VendorDevice
      |
      v
\??\VendorDevice      or      \DosDevices\VendorDevice
      |
      v
\Device\VendorDevice
      |
      v
DEVICE_OBJECT
      |
      v
DRIVER_OBJECT dispatch table
```

## Research Matrices

| Concept | Kernel structure | Research relevance | Defensive visibility |
|---|---|---|---|
| Handle | `HANDLE_TABLE_ENTRY` concept | Shows mediated access rather than raw pointer use | `!handle`, process-level handle telemetry, object callbacks |
| Object pointer | `OBJECT_HEADER` plus object body | Explains lifetime, type, and kernel ownership | Mostly debugger/forensics visibility |
| Symbolic link | Object namespace | Explains how user mode reaches device objects | Namespace inspection, WinObj, `!object` |
| Access mask | GrantedAccess on handle state | Tells what operations the handle should authorize | Debugger inspection, callback/EDR enrichment when available |

## Debugging / Inspection Notes

Useful inspection commands:

- `!object`
  Used to inspect object namespace entries, names, types, handle counts, and pointer counts.
- `!handle`
  Used to inspect which handles a process owns, with granted access and object type context.
- `!process`
  Used to pick process context and inspect object table references from a process-centric view.
- `!drvobj`
  Used to inspect a driver object and its dispatch table relationships.
- `!devobj`
  Used to inspect a device object, its name, attached devices, and queue-related state.
- `!object \Device`
  Used to enumerate the kernel device namespace.
- `!object \??`
  Used to inspect the DOS-device symbolic-link layer exposed to user mode.

The safe debugging goal is namespace and lifetime understanding, not weaponization.

## Defensive Angle

### Suspicious device object exposure

Warning signs:

- low-privilege processes can open hardware or security-sensitive drivers,
- device names appear in unusual namespaces,
- user-writable or rarely used applications open low-level device handles.

### Weak device ACLs

Overly permissive ACLs can turn a signed but otherwise "local-only" utility driver into a reachable broker for privileged work. This is one of the cleanest examples of how namespace and access control become a security boundary.

### Unusual user process opening driver devices

Caller-role mismatch is often more informative than the device name alone. A document viewer or scripting host opening a hardware utility device is inherently more suspicious than the vendor's own service doing so.

### Handle access anomalies and object callback visibility

Abnormal patterns include:

- bursts of device-handle creation,
- unexpected `Token`, `Process`, `Thread`, or `File` handle activity,
- strange handle duplication flows,
- security product callbacks reporting unexpected object-access attempts.

### Sysmon / ETW ideas

Sysmon and ETW will not explain private object-manager semantics by themselves, but they can help correlate:

- process creation,
- driver load,
- service creation,
- image load,
- and subsequent suspicious device interaction.

## Common Mistakes

- Treating a handle as if it were the object pointer.
- Assuming handle count equals total object lifetime.
- Ignoring symbolic-link exposure and focusing only on the kernel device name.
- Concluding that a signed driver is safe because it lives in the Object Manager namespace like any other driver.
- Forgetting that access checks happen at handle-creation and handle-validation boundaries, not just once at driver install time.

## Research Notes

- Object Manager knowledge scales well across exploit research, forensics, and driver auditing because it explains how names, handles, and pointers relate.
- Device exploitation often begins as a namespace and ACL problem before it becomes an IOCTL problem.
- Handle-table understanding is one of the cleanest bridges between userland API traces and kernel object reasoning.

## Lab-Safe Exercises

1. In a lab VM, enumerate `\Device` and `\??` with debugger or namespace tools and map one user-visible device path to its kernel device object.
2. Use `!handle` on a process known to talk to a driver and record object type and granted access for the relevant handle.
3. Use `!drvobj` and `!devobj` to connect a device object back to its driver object and note the dispatch surface conceptually.

## References / Further Reading

- Microsoft Learn, `Windows kernel-mode Object Manager`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-object-manager
- Microsoft Learn, `Object Handles`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles
- Microsoft Learn, `ObReferenceObjectByHandle`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle
- Microsoft Learn, `Failure to Validate Object Handles`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/failure-to-validate-object-handles
- Microsoft Learn, `!object`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-object
- Microsoft Learn, `!handle`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-handle
- Microsoft Learn, `!drvobj`:
  https://learn.microsoft.com/ja-jp/windows-hardware/drivers/debuggercmds/-drvobj
- Microsoft Learn, `!devobj`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-devobj
- Existing repo note, [eprocess-token-object-model.md](E:\Windows-kernel-exploit-research-resource\docs\windows-internals\eprocess-token-object-model.md)
- Anquanke, `Windows nei he dui xiang guan li quan jing jie xi`:
  https://www.anquanke.com/post/id/220061

# HKOM / DKOM Driver and Module Hide: Cross-View Reasoning

## Technique Summary

Driver or module hiding by kernel object manipulation tries to make a loaded kernel component disappear from one inventory view while its code or objects still remain active.

Conceptual model:

```text
driver is loaded
  -> one module/list view is desynchronized
  -> ordinary inventory may miss it
  -> driver object, device objects, dispatch pointers, services, memory, or telemetry still reveal it
```

This document explains how to reason about the object graph and detection paths. It does not describe how to unlink or hide a driver.

## Required Assumptions

Driver hide reasoning assumes:

- a loaded driver has more evidence than one module-list entry,
- driver code must live somewhere in executable kernel memory,
- dispatch routines and device objects often point back into the image,
- service-control and Code Integrity telemetry may record the load,
- object namespace artifacts may survive even if a module list is inconsistent.

The hiding assumption:

```text
some driver inventory view depends on mutable loader/module metadata
```

The detection assumption:

```text
runtime objects and historical telemetry do not all depend on that same metadata
```

## Why This Works

Ask:

```text
Why can a hidden driver still function?
```

Because the driver has several relationships:

```text
loaded image memory
  -> DRIVER_OBJECT
  -> DEVICE_OBJECT chain
  -> dispatch table
  -> symbolic links
  -> service registry key
  -> callback registrations
  -> timers / work items
  -> Code Integrity and driver-load history
```

If a hide attempt affects one module inventory structure, the driver may still be callable through its device object and dispatch routines. That is exactly why cross-view detection works.

## Step-by-Step Reasoning

### Step 1: Define what "driver exists" means

Question:

```text
What evidence proves the driver exists?
```

Possible evidence:

- loaded executable kernel memory,
- `DRIVER_OBJECT`,
- `DEVICE_OBJECT`,
- dispatch routine addresses,
- symbolic links in object namespace,
- service registry key,
- file on disk,
- Code Integrity event,
- Sysmon or EDR driver-load event,
- callback registrations owned by the image.

Reasoning:

No single evidence source is complete. Driver existence is a graph claim.

### Step 2: Identify the missing view

Question:

```text
Which view no longer reports the driver?
```

Possibilities:

- loaded module list,
- user-mode driver inventory API,
- EDR module inventory,
- memory forensic module plugin,
- debugger command relying on one list.

Reasoning:

If only module inventory is missing the driver, the hide is probably list-specific.

### Step 3: Find active runtime edges

Question:

```text
What active objects still point into the hidden image?
```

Important edges:

- `DRIVER_OBJECT.MajorFunction` entries,
- device object back-pointers,
- symbolic links resolving to the device,
- callbacks with function pointers inside the image,
- active worker items or timers,
- open handles to device objects.

Reasoning:

Active code needs entry points. Entry points often expose ownership.

### Step 4: Compare code ownership

Question:

```text
Does this function pointer belong to a known loaded module range?
```

Conceptual check:

```text
dispatch routine VA
  -> find containing executable kernel region
  -> compare region with loaded module inventory
```

If a dispatch routine points into executable memory not associated with a normal module view, that mismatch is suspicious.

## Why Module Hiding Is Fragile

Driver hiding has more moving pieces than process-list hiding:

- object namespace may reveal devices,
- service manager may reveal install/load history,
- Code Integrity may log signing decisions,
- EDR may keep historical driver-load events,
- callbacks may still point into the image,
- device handles may remain open,
- unload cleanup may rely on intact bookkeeping.

The driver can be hidden from a list while still leaving many active edges.

## Cross-View Detection Matrix

| Evidence source | What it reveals | Why it matters |
|---|---|---|
| Module inventory | Normal loaded-driver view | Can be manipulated or incomplete |
| Executable kernel memory | Code still mapped | Hidden code must execute from somewhere |
| `DRIVER_OBJECT` | Dispatch table and device chain | Runtime entry points expose ownership |
| `DEVICE_OBJECT` | Device exposure | User or kernel clients may still reach it |
| Object namespace | `\Device`, `\Driver`, symbolic links | Names can survive module-list tamper |
| Service registry | Install/start configuration | Historical and configuration evidence |
| Code Integrity logs | Signature and load decisions | Records policy path |
| Sysmon / EDR | Driver-load history | Historical telemetry may outlive hide |
| Callback inventory | Registered function pointers | Hidden module may still own callbacks |

## Defensive Questions

Ask:

- Is there a device object whose driver is absent from module inventory?
- Does a dispatch routine point outside every known module range?
- Did Code Integrity log a driver load that current inventory cannot explain?
- Does a service exist for a driver whose module is missing?
- Are there executable kernel memory regions without normal module ownership?
- Are callbacks registered to addresses outside known modules?
- Are user processes opening a device whose driver cannot be cleanly inventoried?

## Failure Modes

Driver/module hide breaks when:

- unload path expects intact loader metadata,
- callbacks remain registered after image state is inconsistent,
- device objects outlive their expected driver relationship,
- function pointers point into memory that inventory cannot explain,
- PatchGuard notices protected structure tamper,
- EDR correlates earlier load telemetry with later missing inventory,
- build-specific structure assumptions are wrong.

Reasoning:

```text
the more places the driver participates,
the more places a hide attempt must keep consistent
```

## Relationship to BYOVD

BYOVD research often focuses on a signed vulnerable helper driver. Driver hiding is a different question:

```text
BYOVD: can a signed driver expose unsafe capability?
hide: can a loaded object be made inconsistent across views?
```

They can overlap in incidents, but they should be documented separately.

For this repository:

- BYOVD notes should classify primitive, loadability, reachability, and mitigation pressure.
- Hide notes should classify object graph, cross-view gaps, telemetry contradictions, and cleanup risk.

## Study Questions

- What does it mean for a driver to "exist" besides appearing in a module list?
- Which runtime objects point back to a driver?
- Why is executable memory ownership important?
- Which evidence is live state and which evidence is historical telemetry?
- Why can a driver be hidden from one inventory but still callable?
- How would you detect a dispatch routine whose owning module is missing?

## Summary

Driver/module hide is a consistency problem:

```text
module list says absent
runtime objects say present
telemetry says loaded
memory says executable code remains
```

The strongest analysis compares those views rather than trusting one inventory source.

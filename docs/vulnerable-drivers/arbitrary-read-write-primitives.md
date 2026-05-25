# Arbitrary Read Write Primitives

## Purpose

This document defines common privileged primitive classes exposed by vulnerable drivers and explains how to triage them from a defensive and reverse-engineering perspective. It deliberately stops at primitive theory, stability analysis, and mitigation impact.

## Background

A vulnerable driver does not need to expose a full exploit chain to be dangerous. It only needs to expose a primitive that lets an untrusted caller ask the kernel to perform an operation that breaks isolation. The key question is not "can this become SYSTEM?" but:

```text
What capability does the driver expose,
how reliable is it,
and what trust boundary failed?
```

Primitive-driven thinking scales better than CVE-by-CVE memorization.

## Core Concepts

### What is an arbitrary read or write primitive?

A primitive is an operation that gives the caller influence over a protected resource. In driver research, the most important families are:

- arbitrary kernel virtual read,
- arbitrary kernel virtual write,
- physical memory read/write,
- MSR read/write,
- port I/O,
- PCI configuration access,
- memcpy-like copies where attacker controls source, destination, or size.

The word "arbitrary" is often imprecise in write-ups. A better classification asks:

- which address space is affected,
- whether the primitive is read, write, or both,
- whether length is caller-controlled,
- whether the address must meet alignment or range restrictions,
- whether the path requires a special device, privilege, or process context.

## Technical Deep Dive

### Primitive classes

| Primitive | Strength | Main limitations | Typical defensive concern |
|---|---|---|---|
| Kernel virtual R/W | High for object-level manipulation | Needs correct kernel VA and build-aware targeting | Fast path to object corruption |
| Physical memory R/W | High for discovery and broad reach | Needs VA->PA translation or scanning logic | Harder to reason about blast radius |
| MSR write | Potentially catastrophic | Very crash-prone and CPU-state-sensitive | Can affect syscall path or global CPU behavior |
| Port I/O | Device-specific | Often hardware- and platform-dependent | Direct hardware interaction from user mode |
| PCI config access | Strong in niche cases | Hardware and firmware dependent | Device reconfiguration and attack-surface expansion |
| Arbitrary memcpy-like primitive | Often equivalent to constrained R/W | Depends on who controls source, destination, size | Easy to underestimate if wrapped in helper logic |

### Kernel virtual read/write

This is often the cleanest primitive from an engineering perspective because the driver already speaks the same address language as executive objects, pool allocations, and kernel globals. If the driver lets a user caller provide a kernel virtual address and a length, then the analyst should ask:

- is the address range filtered,
- is the target expected to be user or kernel space,
- does the driver call a helper like `memcpy`, `RtlCopyMemory`, or `MmCopyMemory`,
- does the driver write directly or through mapped MDLs,
- does it support both read and write.

### Physical memory read/write

Physical memory primitives are often overhyped and underspecified. They are powerful because they can touch backing pages directly, but they are harder to use safely because the analyst must bridge from kernel virtual concepts to physical pages. Defensively, they matter because a driver exposing unrestricted physical mapping behaves like a generic hardware access broker.

### MSR write

MSR access is not just "another write primitive". It targets CPU control state rather than ordinary kernel objects. That makes it:

- highly privileged,
- often highly crash-prone,
- sometimes useful for discovery,
- sometimes strategically important even when too unstable for broad use.

From a defensive triage standpoint, a user-reachable MSR write path deserves immediate attention even if no clean proof of practical exploitation exists.

### Port I/O and PCI config access

These primitives are common in hardware utility and monitoring drivers. They may look narrower than arbitrary memory access, but they often expose device state, chipset behavior, or privileged control flows that were never meant to be user-reachable.

### Bug classes that commonly generate primitives

| Bug class | Primitive shape | Why it appears |
|---|---|---|
| Unchecked user pointer | Read/write through attacker-controlled address | Driver assumes trusted caller or trusted address space |
| `METHOD_NEITHER` misuse | Raw pointer dereference, copy, or callback | Driver omits probing and context checks |
| Missing `ProbeForRead` / `ProbeForWrite` | Unsafe user buffer access | Driver skips boundary validation |
| `MmMapIoSpace` misuse | Physical mapping primitive | Driver maps caller-chosen physical ranges |
| Integer overflow in size calculation | Truncated bounds leading to overrun or undersized validation | Length arithmetic not normalized |
| Unsafe `MmCopyMemory` / `MmCopyVirtualMemory` wrapper | Generalized read/write broker | Driver provides address-based copy service |
| Arbitrary MSR write | CPU state mutation primitive | Driver exposes hardware feature to user mode |

### Primitive quality matrix

| Primitive | Reliability | Crash risk | Version sensitivity | Mitigation impact | Detection surface |
|---|---|---|---|---|---|
| Kernel virtual read | High | Low-medium | Medium | Lower direct impact from code-integrity defenses | Handle open + IOCTL + unusual address patterns |
| Kernel virtual write | Medium-high | Medium-high | Medium | Data-only routes may remain viable under HVCI | Driver telemetry, crash, object anomalies |
| Physical read | Medium | Low-medium | Medium | Good for discovery despite HVCI | Driver load and memory-mapping telemetry |
| Physical write | Medium | High | Medium | Can bypass many high-level assumptions, not all VBS protections | Crash artifacts and driver monitoring |
| MSR read | Medium | Low-medium | CPU/platform sensitive | Useful for discovery more than end state | Rare hardware access behavior |
| MSR write | Low-medium | Very high | CPU/platform sensitive | Mitigation interaction is complex | Highly suspicious if visible |
| Port I/O | Medium | Medium | Hardware dependent | Niche | Rare and unusual in normal software |
| PCI config access | Medium | Medium-high | Hardware dependent | Niche | Rare and unusual in normal software |

### Defensive triage checklist

- Is the device object broadly reachable?
- Does the IOCTL accept addresses, PFNs, physical ranges, handles, or lengths?
- Is the primitive virtual, physical, CPU-state, or device-state oriented?
- Can it read, write, or both?
- Does the path appear synchronized and bounded, or raw and direct?
- What is the likely operational blast radius: object corruption, memory corruption, system crash, device instability?
- Which defenses matter most: blocklist, ACL, verifier, HVCI, WDAC, telemetry, or hardware gating?

## Windows Version Notes

- Primitive categories are stable across versions, but their practical value changes with mitigation pressure.
- Modern Windows versions make control-flow-centric payloads less attractive and data-only or semantic abuse more attractive.
- A primitive can remain dangerous even when HVCI, CET, or PatchGuard make classic code-patching routes unattractive.
- Driver blocklist and WDAC/App Control materially affect whether a vulnerable primitive is operationally reachable.

## Common Mistakes

- Calling every address-based copy path "arbitrary read/write" without checking restrictions.
- Assuming physical memory access automatically defeats all VBS-backed protections.
- Treating MSR write as equivalent to stable memory corruption.
- Ignoring access control around the device object because the primitive itself looks impressive.
- Confusing proof-of-crash with proof-of-useful-primitive.

## Debugging / Inspection Notes

Suggested review flow:

```text
Find IOCTL
  -> recover structure hypothesis
  -> locate sink API or sink instruction
  -> classify address domain
  -> classify read/write direction
  -> record restrictions
  -> estimate crash risk and mitigation pressure
```

Inspection-focused tools:

- IDA / Ghidra for sink discovery.
- WinDbg for structure and object inspection.
- DeviceTree / WinObj for device exposure.
- Driver Verifier for boundary and pool behavior during lab testing.

## Defensive Angle

From a defensive perspective, the most important distinction is not "LPE vs no LPE". It is:

```text
Can an untrusted caller coerce signed kernel code
into touching memory, CPU state, or objects
that should never have been user-directed?
```

That framing supports better prioritization than CVSS alone because it accounts for:

- reachability,
- primitive quality,
- system-policy interaction,
- realistic telemetry opportunities.

## Lab-Safe Exercises

1. Take three documented drivers and classify each primitive without describing a final payload.
2. Build a one-page matrix comparing virtual R/W, physical R/W, and MSR write in terms of crash risk and mitigation interaction.
3. For one `MmMapIoSpace`-based case, write down the exact trust-boundary failure without describing how to operationalize it.

## References / Further Reading

- Microsoft Learn, `Using Neither Buffered Nor Direct I/O`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-neither-buffered-nor-direct-i-o
- Microsoft Learn, `Driver security checklist`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist
- Quarkslab, `BYOVD to the next level (part 1) - exploiting a vulnerable driver (CVE-2025-8061)`:
  https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- Microsoft Learn, `Microsoft recommended driver block rules`:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Anquanke, `Windows Kernel Exploitation Notes (2) - HEVD Write What Where`:
  https://www.anquanke.com/post/id/246289
- Anquanke, `HEVD chi yi chu fen xi`:
  https://www.anquanke.com/post/id/170446

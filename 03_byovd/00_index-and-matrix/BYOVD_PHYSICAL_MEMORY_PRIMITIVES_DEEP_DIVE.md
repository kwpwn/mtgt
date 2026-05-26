# BYOVD Physical Memory Primitives Deep Dive

Updated: 2026-05-27

## Technique Summary

Physical-memory BYOVD primitives let a user-mode controller ask a signed driver to read, write, or map physical addresses.

Companion driver/family case studies:

- `BYOVD_CASE_PHYSICAL_MEMORY_FAMILY.md`
- `BYOVD_CASE_LNVMSRIO.md`

```text
user process
  -> opens vulnerable driver device
  -> requests physical address range
  -> driver maps/copies physical memory
  -> user gains physical read/write or mapping primitive
```

This is one of the most important BYOVD families because many hardware, tuning, RGB, diagnostics, and firmware utilities were designed to access low-level memory or device resources.

## Representative Drivers

| Driver / family | Source context | Primitive shape |
|---|---|---|
| `ASTRA64.sys` | BlackSnufkin / repo-local Astra64 notes | physical memory R/W, MSR read |
| `ThrottleStop.sys` | public CVE-2025-7771 write-up | physical memory R/W via `MmMapIoSpace` |
| `LnvMSRIO.sys` | Lenovo CVE-2025-8061 | physical memory and MSR access family |
| `eneio64.sys` | RGB/hardware control research | physical memory, MSR, port I/O |
| `pstrip64.sys` | PowerStrip / EnTech family | physical memory mapping |
| `ipctype.sys` | LOLDrivers | physical memory R/W through `MmMapIoSpace` |
| `WinIo64.sys` / `MsIo64.sys` | LOLDrivers | mapping `\Device\PhysicalMemory` into user process |

Sources:

- LOLDrivers catalog: https://www.loldrivers.io/drivers/
- LOLDrivers `ipctype.sys`: https://www.loldrivers.io/drivers/509edc55-1881-4fac-8640-b9c516396505/
- LOLDrivers `WinIo64.sys`: https://www.loldrivers.io/drivers/96501e5b-e4f2-41a9-a8ee-d09e36d31a39/
- LOLDrivers `MsIo32/MsIo64`: https://www.loldrivers.io/drivers/4e5064b4-48d3-418c-a7a8-f0dc7ac0a176/
- ThrottleStop write-up: https://www.poh0.dev/windows/driver/vulnerability/2025/09/22/throttlestop-vulnerable-driver/
- NVD CVE-2025-8061: https://nvd.nist.gov/vuln/detail/CVE-2025-8061

## Required Assumptions

A physical-memory primitive needs:

- the vulnerable driver can load under current policy,
- the caller can open the device object,
- an IOCTL exposes physical address or mapping control,
- the target physical range is not constrained to safe device resources,
- the researcher can safely identify what the physical page represents.

If any one of those assumptions fails, the primitive may be low value.

## Why This Works

Windows separates user virtual memory, kernel virtual memory, and physical memory.

Normal user mode sees:

```text
user virtual address
  -> process page tables
  -> allowed physical page
```

A kernel driver can map hardware resources:

```text
physical device/register range
  -> MmMapIoSpace or section mapping
  -> kernel/user-visible mapping depending on driver design
```

The bug appears when the driver treats user-supplied physical addresses as trusted:

```text
attacker chooses physical address
  -> driver maps/copies it
  -> attacker reads/writes memory outside normal process boundary
```

The core invariant being broken:

```text
only trusted kernel code should decide which physical ranges are safe to touch
```

## What The Primitive Can Do

Physical memory primitives can support:

- kernel object discovery,
- token or protection-field modification after locating backing pages,
- page-table inspection,
- kernel base and module reconstruction,
- memory forensics from a live system,
- arbitrary crash if the wrong physical page is modified,
- hardware or firmware interaction if MMIO ranges are exposed.

But physical memory access alone does not answer:

```text
Where is my target object?
Which physical page backs it?
Is this page stable while I touch it?
Is this target protected by VBS/KDP?
```

That is why the real technique is usually a bridge.

## Bridge 1: Virtual-to-Physical Translation

Most Windows internals are reasoned about by virtual address:

```text
nt!PsInitialSystemProcess
EPROCESS
KTHREAD
TOKEN
DRIVER_OBJECT
callback state
```

A physical-memory driver wants physical addresses.

So the bridge is:

```text
kernel virtual address
  -> page-table walk
  -> physical address
  -> physical R/W primitive
```

Why page-table walking works:

- x64 address translation is defined by paging structures,
- the current or kernel CR3 gives a root for translation,
- PML4/PDPT/PD/PT entries describe the physical page backing a virtual address,
- once translated, the physical primitive can touch the page.

Why it is hard:

- CR3 selection matters,
- large pages change walk logic,
- invalid or paged-out mappings fail,
- VBS/HVCI can change assumptions,
- wrong PFN means corrupting unrelated memory.

Study question:

```text
If you know an EPROCESS virtual address but only have physical R/W,
what exact information is still missing?
```

Answer:

```text
the physical page that currently backs that virtual address
```

## Bridge 2: Physical Object Scanning

If translation is not solved, some research scans physical memory for object patterns.

Example reasoning for process objects:

```text
look for plausible image name
  -> nearby PID-looking value
  -> list links look canonical
  -> token-like pointer exists
  -> fields agree with known process
```

Why this can work:

- kernel objects contain recognizable fields,
- some fields have constrained values,
- multiple fields can validate each other.

Why it is weaker than translation:

- false positives,
- object layout drift,
- stale freed objects,
- high read volume,
- high crash risk if writing.

Good rule:

```text
physical scanning can suggest candidates;
cross-field validation decides whether a candidate is credible.
```

## Bridge 3: PE Header and Module Reconstruction

Physical memory can also be used to recover mapped images:

```text
find pointer into kernel module
  -> locate backing physical page
  -> inspect mapped PE headers
  -> reconstruct module range
```

This overlaps with:

- `MSR_LSTAR` kernel base discovery,
- `PsLoadedModuleList`,
- loaded module scanning,
- crash dump module triage.

Related local document:

- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`

## Why HVCI Does Not Automatically Save You

HVCI is about code integrity and related virtualization-backed policy. A signed driver that exposes arbitrary physical memory access can still create a dangerous semantic path.

Reasoning:

```text
HVCI can make kernel shellcode harder
but the vulnerable driver is already trusted code
and its IOCTL can still perform dangerous operations
```

Some specific drivers or versions may be blocked by HVCI compatibility, Core Isolation, or vulnerable driver policy. Do not generalize from one driver.

## What Makes A Physical Primitive High Quality

| Property | Why it matters |
|---|---|
| read + write | read validates target, write changes it |
| arbitrary physical address | not limited to safe device ranges |
| arbitrary length | easier object and page-table inspection |
| stable mapping lifecycle | less race/crash risk |
| no hardware requirement | broad BYOVD usefulness |
| device reachable by attacker | actual exploitability |
| not blocklisted | loadability |

## Failure Modes

Physical memory primitives fail through:

- wrong physical address,
- stale object candidate,
- large page handling bug,
- CR3 mismatch,
- MMIO region mistaken for RAM,
- writing read-only/protected data,
- touching VTL1/protected regions,
- driver range checks,
- Microsoft blocklist / WDAC denial,
- HVCI incompatibility preventing driver load.

The most important failure mode:

```text
thinking physical access equals object understanding
```

It does not. The primitive is powerful only after target discovery is reliable.

## Detection Angle

Detection should correlate:

- vulnerable driver load,
- service creation for a hardware utility driver,
- driver path outside normal vendor install directory,
- unexpected user-mode controller opening the device,
- physical-memory helper driver on a non-lab endpoint,
- crash after driver IOCTL use,
- sudden privilege/protection state change after hardware driver load.

High-risk product categories:

- overclocking,
- RGB,
- mining,
- hardware monitoring,
- firmware flashing,
- board vendor utilities,
- diagnostics and benchmarking.

## Study Questions

- Is the primitive copy-based or mapping-based?
- Does the caller control physical address, length, and direction?
- Can the driver map real RAM or only device MMIO?
- Does the primitive include readback?
- What bridge converts physical address space into kernel object control?
- What would prove a candidate physical page is the intended object?
- Which mitigation blocks loadability rather than impact?

## Summary

Physical-memory BYOVD is dangerous because it crosses underneath normal virtual-memory boundaries:

```text
signed driver exposes physical access
  -> attacker bridges physical pages to kernel objects
  -> data-only or hardware impact becomes possible
```

The key skill is not "write physical memory." The key skill is proving what that memory is.

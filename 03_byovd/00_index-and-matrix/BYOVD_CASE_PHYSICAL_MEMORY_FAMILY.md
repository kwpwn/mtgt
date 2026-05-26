# BYOVD Case Study: Physical Memory Driver Family

Updated: 2026-05-27

## Technique Summary

This case study compares several drivers where the main primitive is physical memory read/write or mapping:

- `ThrottleStop.sys`
- `eneio64.sys`
- `pstrip64.sys`
- `ipctype.sys`
- related `ASTRA64.sys` / hardware utility families

```text
hardware utility driver
  -> physical memory map/read/write
  -> VA-to-PA bridge or object scan
  -> data-only kernel impact
```

## Sources

- ThrottleStop write-up:
  https://www.poh0.dev/windows/driver/vulnerability/2025/09/22/throttlestop-vulnerable-driver/
- GitHub advisory CVE-2025-7771:
  https://github.com/advisories/GHSA-f8p7-vvxp-hcxv
- NVD CVE-2026-29923 PowerStrip:
  https://nvd.nist.gov/vuln/detail/CVE-2026-29923
- SentinelOne PowerStrip CVE-2026-29923 summary:
  https://www.sentinelone.com/vulnerability-database/cve-2026-29923/
- LOLDrivers IPCType:
  https://www.loldrivers.io/drivers/509edc55-1881-4fac-8640-b9c516396505/
- Feedly CVE-2020-12446 context for ENE:
  https://feedly.com/cve/CVE-2020-12446

## Primitive

Primitive classes:

- physical memory read/write,
- physical memory mapping into user process,
- sometimes MSR or port I/O in the same driver family.

## Why This Pattern Repeats

Hardware utilities often need to inspect or control low-level state:

- CPU tuning,
- RGB control,
- display/graphics utilities,
- industrial device helpers,
- firmware or board management.

The intended behavior:

```text
vendor app chooses safe hardware resource
  -> driver maps or reads it
  -> product function works
```

The vulnerable behavior:

```text
caller chooses arbitrary physical address
  -> driver maps or reads it
  -> arbitrary physical memory primitive
```

The invariant failure:

```text
the driver does not prove that the requested physical range belongs to a safe device resource
```

## Driver Notes

### `ThrottleStop.sys`

Public write-ups describe exposed interfaces that allow physical memory read/write through `MmMapIoSpace`.

Why it is useful:

- clean example of physical primitive,
- teaches VA-to-PA and object discovery,
- shows consumer utility driver risk.

Why it fails:

- wrong physical page,
- stale public offsets,
- blocklist or vendor remediation,
- crash through invalid memory.

### `eneio64.sys`

ENE/G.SKILL-style RGB/hardware driver research commonly discusses:

- physical memory mapping,
- MSR access,
- port I/O.

Why it is useful:

- teaches multi-primitive hardware utility risk,
- shows HVCI-compatible does not automatically mean safe,
- illustrates physical-to-virtual bridge on modern Windows.

Why it fails:

- driver version and product packaging differ,
- hardware assumptions,
- physical translation mistakes.

### `pstrip64.sys`

PowerStrip cases describe arbitrary physical memory mapping into user address space.

Why it is useful:

- mapping primitive is easier to reason about visually,
- demonstrates old utility driver risk on modern systems,
- shows that "legacy software" can still be a BYOVD asset.

Why it fails:

- old product may not load under modern policy,
- blocklist/WDAC can deny,
- mapped page may not be the intended object.

### `ipctype.sys`

LOLDrivers describes IPCType as exposing physical memory R/W through `MmMapIoSpace`.

Why it is useful:

- expands the mental model beyond gaming/RGB tools,
- industrial or device-control drivers can have the same primitive family,
- reinforces that product category is not the primitive.

## Bridge Choices

### VA-to-PA translation

Best when:

- kernel virtual address is known,
- page table root can be identified,
- target is stable.

Reasoning:

```text
virtual target
  -> page table translation
  -> physical page
```

### Physical object scanning

Best when:

- translation is unavailable,
- object pattern is distinctive,
- only read is needed first.

Reasoning:

```text
scan physical RAM
  -> candidate object fields
  -> cross-field validation
```

### Mapping inspection

Best when:

- driver maps physical page into user mode,
- researcher can inspect mapped bytes,
- writes are carefully bounded.

Reasoning:

```text
map page
  -> inspect
  -> validate
  -> maybe modify
```

## Failure Modes

- physical address is MMIO, not RAM,
- target page changes,
- wrong CR3 or page-table root,
- large-page handling wrong,
- object signature false positive,
- HVCI/blocklist prevents driver load,
- write corrupts kernel memory and bugchecks.

## Detection Ideas

Hunt for:

- physical-memory helper drivers on non-lab endpoints,
- `MmMapIoSpace`-style vulnerable drivers loaded from unusual paths,
- hardware utility driver service creation followed by privilege anomaly,
- old RGB/tuning/display tools,
- ThrottleStop/ENE/PowerStrip/IPCType files outside approved software,
- crash after device IOCTL activity.

## Study Questions

- Is this driver mapping or copying physical memory?
- Does it restrict physical ranges to device resources?
- Which bridge is used: VA-to-PA or physical scan?
- How is object identity validated before write?
- Why does HVCI not automatically fix unsafe physical memory IOCTLs?
- Which product categories in your fleet may contain the same primitive?

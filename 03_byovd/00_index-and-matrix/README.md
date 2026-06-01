# BYOVD Index

Day la diem bat dau cho nhanh BYOVD. Cac writeup chi tiet duoc tach theo primitive, khong de chung trong mot folder phang nua.

## Files trong folder nay

- `BYOVD_RECENT_WRITEUPS.md`: index cac BYOVD/writeup gan day va y tuong hunting.
- `BYOVD_CHINA_SOURCE_MAP.md`: map nguon Trung Quoc/Chinese-language ve driver da bi abuse, primitive, campaign va hunting note; khong copy IOCTL/trigger/PoC.
- `BYOVD_PRIMITIVE_MATRIX.md`: bang so sanh primitive, do on dinh, rui ro BSOD, version sensitivity.
- `BYOVD_BLOCKLIST_AND_REACHABILITY.md`: model danh gia driver theo loadability, reachability, usefulness va mitigation pressure.
- `BYOVD_NON_TERMINATE_PRIMITIVES_TAXONOMY.md`: taxonomy dai ve cac primitive BYOVD khong tinh process-termination-only: physical R/W, virtual R/W, MSR, port I/O, PCI/MMIO, limited write, callback/security-state tamper.
- `BYOVD_PRIMITIVE_BRIDGE_REASONING.md`: offensive research note ve cach noi primitive -> bridge -> objective, giai thich vi sao primitive chua du de thanh impact.
- `BYOVD_DRIVERSHIELD_BLOG_TECHNIQUE_ATLAS.md`: atlas ky thuat tu DriverShield BYOVD index, loc tool-only va gom cac pattern trong blog/writeup thanh primitive/invariant/bridge/failure mode.
- `BYOVD_PHYSICAL_MEMORY_PRIMITIVES_DEEP_DIVE.md`: physical memory R/W va mapping, VA->PA bridge, scanning, HVCI/WDAC impact.
- `BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`: virtual kernel R/W, memcpy primitive, data-only object modification.
- `BYOVD_MSR_PORT_MMIO_HARDWARE_PRIMITIVES.md`: MSR, port I/O, PCI config, MMIO, firmware/hardware primitives.
- `BYOVD_LIMITED_WRITE_AND_PREVIOUSMODE.md`: limited write, arithmetic/bitwise primitive, `PreviousMode` reasoning.
- `BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`: callback/security-state tamper, EDR visibility, PatchGuard/HVCI pressure.
- `BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`: S12Deff process-creation callback tamper case-study, classified under callback/security-state tamper.
- `BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`: catalog case-study theo driver/vendor, khong tinh process-termination-only.
- `BYOVD_CASE_RTCORE64.md`: MSI Afterburner `RTCore64.sys`, virtual kernel R/W va data-only object modification.
- `BYOVD_CASE_DBUTIL_2_3.md`: Dell `dbutil_2_3.sys`, firmware/update helper va kernel copy/write primitive.
- `BYOVD_CASE_GDRV.md`: GIGABYTE `gdrv.sys`, multi-primitive memory/MSR/port/PCI/MMIO.
- `BYOVD_CASE_WINRING0_WINIO_MSIO.md`: WinRing0/WinIo/MsIo hardware access family.
- `BYOVD_CASE_LNVMSRIO.md`: Lenovo `LnvMSRIO.sys`, physical memory + MSR, HVCI/Core Isolation nuance.
- `BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md`: normalized review of the external Lenovo LPE draft set, grouped by primitive, invariant, bridge and failure mode.
- `BYOVD_CASE_PHYSICAL_MEMORY_FAMILY.md`: ThrottleStop/ENE/PowerStrip/IPCType physical memory family comparison.
- Detection checklist: `..\..\docs\detection-and-mitigation\byovd-hunting-and-hardening-checklists.md`
- Offensive exploitability map: `..\..\docs\kernel-research\offensive-driver-exploitability-map.md`
- Public PoC annotation template: `..\..\docs\kernel-research\public-poc-reading-and-annotation-template.md`
- Primitive pseudo-PoC sketchbook: `..\..\docs\kernel-research\primitive-pseudocode-sketchbook.md`
- DriverShield BYOVD blog technique atlas: `BYOVD_DRIVERSHIELD_BLOG_TECHNIQUE_ATLAS.md`
- Win32k USER/GDI bridge notes: `..\..\docs\kernel-research\win32k-research-notes.md`
- Win32k case-study atlas: `..\..\docs\kernel-research\win32k-case-study-atlas.md`
- Master map: `..\..\docs\research-index\master-driver-research-map.md`

## External BYOVD indexes

- DriverShield BYOVD Research Index: https://drivershield.io/byovd/
  - Useful as a metadata index for public GitHub repositories tagged around BYOVD or vulnerable-driver research.
  - Treat it as a discovery aid, then verify claims against upstream source, Microsoft blocklist state, signer metadata, and local lab behavior.
- LOLDrivers: https://www.loldrivers.io/
  - Useful for vulnerable, malicious, and suspicious driver inventory context.

## Folder writeup theo primitive

```text
03_byovd
|-- 00_index-and-matrix
|-- 01_physical-memory-rw
|-- 02_virtual-kernel-rw
|-- 03_process-kill
|-- 04_limited-primitives
|-- 05_msr-and-multi-primitive
`-- 99_workflow
```

## Physical memory R/W

Folder:

```text
03_byovd\01_physical-memory-rw
```

Drivers/writeups:

- `ASTRA64_RW_CODE_WALKTHROUGH.md`
- `ASTRA64_DIRECT_DKOM_DEEP_DIVE.md`
- `LENOVO_LNVMSRIO_DEEP_DIVE.md`
- `THROTTLESTOP_PHYSICAL_RW_DEEP_DIVE.md`
- `ENEIO64_PHYSICAL_RW_DEEP_DIVE.md`
- `PSTRIP64_POWERSTRIP_DEEP_DIVE.md`

Technique-level note:

- `BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
- `BYOVD_PHYSICAL_MEMORY_PRIMITIVES_DEEP_DIVE.md`
- `BYOVD_CASE_PHYSICAL_MEMORY_FAMILY.md`
- `BYOVD_CASE_LNVMSRIO.md`
- `BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md`

## Virtual kernel R/W

Folder:

```text
03_byovd\02_virtual-kernel-rw
```

Drivers/writeups:

- `RTCORE64_MSI_AFTERBURNER_DEEP_DIVE.md`
- `DBUTIL_2_3_DELL_DEEP_DIVE.md`
- `DSARK64_QIHOO_DEEP_DIVE.md`

Technique-level note:

- `BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
- `BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`
- `BYOVD_CASE_RTCORE64.md`
- `BYOVD_CASE_DBUTIL_2_3.md`

## Process kill

Folder:

```text
03_byovd\03_process-kill
```

Drivers/writeups:

- `K7RKSCAN_CODE_WALKTHROUGH.md`
- `K7RKSCAN_PROCESS_KILLER_DEEP_DIVE.md`
- `BDAPIUTIL64_CODE_WALKTHROUGH.md`
- `BDAPIUTIL64_PROCESS_KILLER_DEEP_DIVE.md`
- `ZEMANA_TERMINATOR_DEEP_DIVE.md`
- `TFSYSMON_THREATFIRE_DEEP_DIVE.md`

## Limited primitive

Folder:

```text
03_byovd\04_limited-primitives
```

Drivers/writeups:

- `ASIO3_PREVIOUSMODE_DEEP_DIVE.md`

Technique-level note:

- `BYOVD_LIMITED_WRITE_AND_PREVIOUSMODE.md`

## MSR / multi-primitive

Folder:

```text
03_byovd\05_msr-and-multi-primitive
```

Drivers/writeups:

- `WINRING0_AWESOME_MINER_MSR_DEEP_DIVE.md`
- `GDRV_GIGABYTE_DEEP_DIVE.md`

Technique-level notes:

- `BYOVD_MSR_PORT_MMIO_HARDWARE_PRIMITIVES.md`
- `BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`
- `BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`
- `BYOVD_CASE_GDRV.md`
- `BYOVD_CASE_WINRING0_WINIO_MSIO.md`
- `BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md`

## Non-terminate case studies

Start here:

- `BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`

Driver/family notes:

- `BYOVD_CASE_RTCORE64.md`
- `BYOVD_CASE_DBUTIL_2_3.md`
- `BYOVD_CASE_GDRV.md`
- `BYOVD_CASE_WINRING0_WINIO_MSIO.md`
- `BYOVD_CASE_LNVMSRIO.md`
- `BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md`
- `BYOVD_CASE_PHYSICAL_MEMORY_FAMILY.md`
- `BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`

## Workflow

Folder:

```text
03_byovd\99_workflow
```

Files:

- `NEW_DRIVER_REVERSING_WORKFLOW.md`

## Local source reference

Code snapshot/checkouts nam o:

```text
90_sources\_source\BYOVD
```

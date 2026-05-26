# Master Driver Research Map

Updated: 2026-05-27

## Purpose

This is the high-level map for the whole repository. Use it when you want to know:

```text
Where do I start?
Which docs explain the primitive?
Which docs explain detection?
Which docs explain why the technique works?
What is still missing?
```

The repo is now large enough that reading files by directory order is no longer ideal. Read by task.

## Fast Tracks

### Track 1: New Driver Reverse Engineering

Read in this order:

1. `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md`
2. `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md`
3. `docs/userland-to-kernel/ioctl-reverse-engineering.md`
4. `docs/userland-to-kernel/method-neither-research-notes.md`
5. `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md`
6. `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md`
7. `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
8. `docs/kernel-research/driver-exploit-technique-atlas.md`
9. `docs/kernel-research/offensive-driver-exploitability-map.md`
10. `docs/kernel-research/race-and-toctou-in-drivers.md`
11. `docs/debugging/crash-dump-driver-triage.md`

Goal:

```text
driver sample
  -> device/IOCTL map
  -> bug-class classification
  -> primitive classification
  -> research note
```

### Track 2: BYOVD Primitive Research

Read in this order:

1. `03_byovd/00_index-and-matrix/README.md`
2. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md`
3. `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_PRIMITIVES_TAXONOMY.md`
4. `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`
5. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
6. `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`
7. `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md`

Goal:

```text
signed driver
  -> loadability
  -> reachability
  -> primitive
  -> bridge
  -> objective
  -> reliability and failure modes
```

### Track 2B: Public PoC Reading

Read in this order:

1. `docs/kernel-research/public-poc-reading-and-annotation-template.md`
2. `docs/kernel-research/offensive-driver-exploitability-map.md`
3. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
4. `docs/kernel-research/kernel-object-layout-drift.md`
5. `docs/kernel-research/runtime-pdb-symbol-resolution.md`

Goal:

```text
public PoC
  -> preconditions
  -> primitive
  -> bridge
  -> objective
  -> failure modes
  -> teaching note
```

### Track 3: Physical Memory / Page Table Path

Read in this order:

1. `03_byovd/00_index-and-matrix/BYOVD_PHYSICAL_MEMORY_PRIMITIVES_DEEP_DIVE.md`
2. `03_byovd/00_index-and-matrix/BYOVD_CASE_PHYSICAL_MEMORY_FAMILY.md`
3. `docs/windows-internals/page-table-walking.md`
4. `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md`
5. `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`

Goal:

```text
physical primitive
  -> kernel virtual target
  -> VA-to-PA bridge
  -> validated object access
```

### Track 4: Virtual Kernel R/W and Data-Only Impact

Read in this order:

1. `03_byovd/00_index-and-matrix/BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`
2. `03_byovd/00_index-and-matrix/BYOVD_CASE_RTCORE64.md`
3. `03_byovd/00_index-and-matrix/BYOVD_CASE_DBUTIL_2_3.md`
4. `docs/windows-internals/eprocess-token-object-model.md`
5. `docs/kernel-research/kernel-object-layout-drift.md`
6. `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`

Goal:

```text
virtual R/W
  -> object discovery
  -> minimal semantic field change
  -> mitigation reasoning
```

### Track 5: MSR / Port / MMIO / Hardware

Read in this order:

1. `03_byovd/00_index-and-matrix/BYOVD_MSR_PORT_MMIO_HARDWARE_PRIMITIVES.md`
2. `03_byovd/00_index-and-matrix/BYOVD_CASE_GDRV.md`
3. `03_byovd/00_index-and-matrix/BYOVD_CASE_WINRING0_WINIO_MSIO.md`
4. `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO.md`
5. `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`

Goal:

```text
hardware primitive
  -> classify CPU vs device vs firmware state
  -> avoid false universal assumptions
```

### Track 6: Evasion and Defensive Pressure

Read in this order:

1. `docs/detection-and-mitigation/driver-evasion-pressure-map.md`
2. `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`
3. `docs/kernel-research/hkom-dkom-hide-research-notes.md`
4. `docs/kernel-research/hkom-driver-module-hide-crossview.md`
5. `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
6. `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`

Goal:

```text
evasion pressure
  -> violated invariant
  -> telemetry gap
  -> cross-view detection
```

## Core Concept Anchors

| Concept | Best doc |
|---|---|
| IOCTL bug classes | `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md` |
| Driver exploit primitives | `docs/kernel-research/driver-exploit-technique-atlas.md` |
| Offensive exploitability reasoning | `docs/kernel-research/offensive-driver-exploitability-map.md` |
| Public PoC annotation | `docs/kernel-research/public-poc-reading-and-annotation-template.md` |
| BYOVD primitive bridges | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md` |
| WDF/KMDF reversing | `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md` |
| Device ACL and SDDL | `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md` |
| IDA/Ghidra patterns | `docs/kernel-research/ida-ghidra-driver-re-patterns.md` |
| Verifier / SDV / CodeQL workflow | `docs/kernel-research/driver-verifier-sdv-codeql-research-workflow.md` |
| Runtime symbols | `docs/kernel-research/runtime-pdb-symbol-resolution.md` |
| Layout drift | `docs/kernel-research/kernel-object-layout-drift.md` |
| Kernel base from LSTAR | `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md` |
| Object Manager | `docs/windows-internals/object-manager-and-handle-tables.md` |
| EPROCESS/TOKEN | `docs/windows-internals/eprocess-token-object-model.md` |
| MDLs | `docs/kernel-research/mdl-misuse-and-direct-io.md` |
| Race/TOCTOU | `docs/kernel-research/race-and-toctou-in-drivers.md` |
| HVCI/VBS | `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` |
| Detection | `docs/detection-and-mitigation/byovd-detection.md` |

## What "Strong Research Note" Means Here

A strong note should answer:

- what driver or subsystem is being studied,
- what trust boundary is crossed,
- what primitive exists,
- why the primitive works,
- what bridge is needed,
- what can fail,
- what mitigations matter,
- what defenders can observe.

If a note only says:

```text
driver has arbitrary R/W
```

it is incomplete.

## Current High-Value Gaps

Priority gaps still worth adding:

1. Per-driver reachability templates applied to every existing BYOVD case.
2. More public-PoC annotation notes for specific public blogs.
3. More crash dump examples for common bugchecks.
4. More WDF object-context examples from real drivers.
5. More source-available driver CodeQL pattern examples.

These are documentation gaps, not blockers for current use.

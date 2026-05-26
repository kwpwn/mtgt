# Driver Research Topic Index

## Purpose

This index links the main research areas in the repository so the material is easier to navigate. It prioritizes Windows kernel driver research, BYOVD, mitigations, telemetry, and modern primitive-upgrade topics.

Top-level maps:

- `docs/research-index/master-driver-research-map.md`
- `docs/research-index/resource-coverage-audit-2026-05-27.md`

## Driver Internals

| Topic | Start here | Supporting docs |
|---|---|---|
| Driver reversing workflow | `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md` | `docs/userland-to-kernel/ioctl-reverse-engineering.md` |
| IOCTL analysis | `docs/userland-to-kernel/ioctl-reverse-engineering.md` | `docs/userland-to-kernel/method-neither-research-notes.md` |
| Device ACL / SDDL reachability | `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md` | `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md` |
| WDF/KMDF reversing | `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md` | `docs/kernel-research/ida-ghidra-driver-re-patterns.md` |
| IDA/Ghidra driver RE patterns | `docs/kernel-research/ida-ghidra-driver-re-patterns.md` | `docs/userland-to-kernel/ioctl-reverse-engineering.md` |
| Verifier / SDV / CodeQL workflow | `docs/kernel-research/driver-verifier-sdv-codeql-research-workflow.md` | `docs/debugging/crash-dump-driver-triage.md` |
| IOCTL bug-class playbook | `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md` | `docs/kernel-research/driver-exploit-technique-atlas.md` |
| Driver exploit technique atlas | `docs/kernel-research/driver-exploit-technique-atlas.md` | `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_PRIMITIVES_TAXONOMY.md` |
| Offensive exploitability reasoning | `docs/kernel-research/offensive-driver-exploitability-map.md` | `docs/kernel-research/public-poc-reading-and-annotation-template.md` |
| Public PoC annotation | `docs/kernel-research/public-poc-reading-and-annotation-template.md` | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md` |
| User/kernel boundary | `docs/userland-to-kernel/userland-to-kernel-boundary.md` | `docs/kernel-research/previousmode-research-notes.md` |
| Direct I/O and MDLs | `docs/kernel-research/mdl-misuse-and-direct-io.md` | `docs/kernel-research/race-and-toctou-in-drivers.md` |
| Object Manager and handles | `docs/windows-internals/object-manager-and-handle-tables.md` | `docs/windows-internals/eprocess-token-object-model.md` |
| Runtime symbols and layout drift | `docs/kernel-research/runtime-pdb-symbol-resolution.md` | `docs/kernel-research/kernel-object-layout-drift.md` |
| Kernel base discovery | `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md` | `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md` |
| Crash dump triage | `docs/debugging/crash-dump-driver-triage.md` | `docs/debugging/windbg-kernel-research-workflow.md` |
| HKOM / DKOM hide concepts | `docs/kernel-research/hkom-dkom-hide-research-notes.md` | `docs/windows-internals/object-manager-and-handle-tables.md` |
| HKOM process hide cross-view | `docs/kernel-research/hkom-process-hide-crossview.md` | `docs/windows-internals/eprocess-token-object-model.md` |
| HKOM driver/module hide cross-view | `docs/kernel-research/hkom-driver-module-hide-crossview.md` | `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md` |

## BYOVD

| Topic | Start here | Supporting docs |
|---|---|---|
| BYOVD section overview | `03_byovd/00_index-and-matrix/README.md` | `03_byovd/00_index-and-matrix/BYOVD_RECENT_WRITEUPS.md` |
| Primitive matrix | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md` | `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` |
| Primitive bridge reasoning | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md` | `docs/kernel-research/offensive-driver-exploitability-map.md` |
| Loadability and reachability | `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md` | `docs/detection-and-mitigation/byovd-detection.md` |
| Physical memory R/W | `03_byovd/01_physical-memory-rw/` | `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md` |
| Virtual kernel R/W | `03_byovd/02_virtual-kernel-rw/` | `docs/windows-internals/page-table-walking.md` |
| Process kill | `03_byovd/03_process-kill/` | `docs/detection-and-mitigation/byovd-detection.md` |
| Limited primitives | `03_byovd/04_limited-primitives/` | `docs/kernel-research/previousmode-research-notes.md` |
| MSR and multi-primitive drivers | `03_byovd/05_msr-and-multi-primitive/` | `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` |

External indexes:

- [DriverShield BYOVD Research Index](https://drivershield.io/byovd/) - metadata index of public GitHub BYOVD and vulnerable-driver research repositories.
- [LOLDrivers](https://www.loldrivers.io/) - vulnerable, malicious, and suspicious driver catalog.

## Mitigations

| Topic | Start here | Supporting docs |
|---|---|---|
| Mitigation matrix | `02_mitigations-vbs-hvci-vtrp/MITIGATION_MATRIX.md` | `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md` |
| HVCI and VBS | `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` | `02_mitigations-vbs-hvci-vtrp/CONNOR_HVCI_KCFG_DEEP_DIVE_VI.md` |
| VT-rp and HLAT | `02_mitigations-vbs-hvci-vtrp/VT_RP_HLAT_DEEP_DIVE_VI.md` | `docs/kernel-research/hypervisor-assisted-introspection.md` |
| DSE and Code Integrity | `docs/mitigations/dse-code-integrity-research-notes.md` | `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md` |
| PatchGuard and KPTI | `docs/mitigations/patchguard-kpti-kva-shadow.md` | `04_connor-mcgarr-study/06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md` |

## Telemetry and Detection

| Topic | Start here | Supporting docs |
|---|---|---|
| BYOVD detection | `docs/detection-and-mitigation/byovd-detection.md` | `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md` |
| BYOVD hunting and hardening | `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md` | `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md` |
| MDE/KQL BYOVD hunt templates | `docs/detection-and-mitigation/mde-kql-byovd-hunting-patterns.md` | `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md` |
| Driver load, ETW, and CI | `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md` | `docs/mitigations/dse-code-integrity-research-notes.md` |
| ETW Threat Intelligence | `docs/detection-and-mitigation/etw-threat-intelligence-notes.md` | `docs/detection-and-mitigation/minifilter-and-edr-visibility.md` |
| Minifilter and EDR visibility | `docs/detection-and-mitigation/minifilter-and-edr-visibility.md` | `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md` |
| Driver evasion pressure | `docs/detection-and-mitigation/driver-evasion-pressure-map.md` | `docs/kernel-research/hkom-dkom-hide-research-notes.md` |

## Modern Research Surfaces

| Topic | Start here | Supporting docs |
|---|---|---|
| I/O rings | `docs/kernel-research/io-ring-research-notes.md` | `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md` |
| HKOM / DKOM hide | `docs/kernel-research/hkom-dkom-hide-research-notes.md` | `docs/windows-internals/eprocess-token-object-model.md` |
| Technique writing format | `docs/research-index/technique-writing-standard.md` | `docs/research-index/driver-research-topic-index.md` |
| Callback surfaces | `docs/kernel-research/callback-surfaces.md` | `docs/windows-internals/object-manager-and-handle-tables.md` |
| CLFS / ALPC / RPC / COM | `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md` | `docs/detection-and-mitigation/minifilter-and-edr-visibility.md` |
| Kernel pool | `docs/windows-heap/kernel-pool-internals.md` | `04_connor-mcgarr-study/04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md` |
| User-mode versus kernel-mode heap | `docs/windows-heap/userland-vs-kernelland-heap.md` | `docs/windows-heap/usermode-heap-internals.md` |

## Suggested Reading Paths

Driver researcher path:

1. `docs/userland-to-kernel/userland-to-kernel-boundary.md`
2. `docs/userland-to-kernel/ioctl-reverse-engineering.md`
3. `docs/userland-to-kernel/method-neither-research-notes.md`
4. `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md`
5. `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md`
6. `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
7. `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md`
8. `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md`
9. `docs/kernel-research/driver-exploit-technique-atlas.md`
10. `docs/kernel-research/offensive-driver-exploitability-map.md`
11. `docs/kernel-research/race-and-toctou-in-drivers.md`
12. `docs/kernel-research/driver-verifier-sdv-codeql-research-workflow.md`
13. `docs/debugging/crash-dump-driver-triage.md`

Public PoC reading path:

1. `docs/kernel-research/public-poc-reading-and-annotation-template.md`
2. `docs/kernel-research/offensive-driver-exploitability-map.md`
3. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
4. `docs/kernel-research/kernel-object-layout-drift.md`
5. `docs/kernel-research/runtime-pdb-symbol-resolution.md`
6. `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`

BYOVD analyst path:

1. `03_byovd/00_index-and-matrix/README.md`
2. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md`
3. `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`
4. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
5. `docs/detection-and-mitigation/byovd-detection.md`
6. `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md`
7. `docs/detection-and-mitigation/mde-kql-byovd-hunting-patterns.md`
8. `docs/mitigations/dse-code-integrity-research-notes.md`

Modern Windows LPE concept path:

1. `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md`
2. `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`
3. `docs/kernel-research/io-ring-research-notes.md`
4. `docs/kernel-research/kernel-object-layout-drift.md`
5. `docs/windows-internals/eprocess-token-object-model.md`

# Driver Research Topic Index

## Purpose

This index links the main research areas in the repository so the material is easier to navigate. It prioritizes Windows kernel driver research, BYOVD, mitigations, telemetry, and modern primitive-upgrade topics.

Top-level maps:

- `docs/research-index/master-driver-research-map.md`
- `docs/research-index/resource-coverage-audit-2026-05-27.md`
- `05_global-research-map/DRIVERSHIELD_SOURCE_BUILD_PLAN.md`

## Driver Internals

| Topic | Start here | Supporting docs |
|---|---|---|
| Driver reversing workflow | `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md` | `docs/userland-to-kernel/ioctl-reverse-engineering.md` |
| IOCTL analysis | `docs/userland-to-kernel/ioctl-reverse-engineering.md` | `docs/userland-to-kernel/method-neither-research-notes.md` |
| Device ACL / SDDL reachability | `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md` | `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md` |
| Driver fundamentals primer | `docs/kernel-research/windows-kernel-driver-fundamentals-er-notes.md` | `docs/kernel-research/ida-ghidra-driver-re-patterns.md` |
| WDF/KMDF reversing | `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md` | `docs/kernel-research/ida-ghidra-driver-re-patterns.md` |
| IDA/Ghidra driver RE patterns | `docs/kernel-research/ida-ghidra-driver-re-patterns.md` | `docs/userland-to-kernel/ioctl-reverse-engineering.md` |
| Patch diff and binary comparison | `docs/kernel-research/patch-diff-and-binary-comparison-workflow-er-notes.md` | `docs/kernel-research/public-poc-reading-and-annotation-template.md` |
| Verifier / SDV / CodeQL workflow | `docs/kernel-research/driver-verifier-sdv-codeql-research-workflow.md` | `docs/debugging/crash-dump-driver-triage.md` |
| IOCTL bug-class playbook | `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md` | `docs/kernel-research/driver-exploit-technique-atlas.md` |
| Driver exploit technique atlas | `docs/kernel-research/driver-exploit-technique-atlas.md` | `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_PRIMITIVES_TAXONOMY.md` |
| Offensive exploitability reasoning | `docs/kernel-research/offensive-driver-exploitability-map.md` | `docs/kernel-research/public-poc-reading-and-annotation-template.md` |
| Public PoC annotation | `docs/kernel-research/public-poc-reading-and-annotation-template.md` | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md` |
| Primitive pseudo-PoC sketches | `docs/kernel-research/primitive-pseudocode-sketchbook.md` | `docs/kernel-research/offensive-driver-exploitability-map.md` |
| User/kernel boundary | `docs/userland-to-kernel/userland-to-kernel-boundary.md` | `docs/kernel-research/previousmode-research-notes.md` |
| Direct I/O and MDLs | `docs/kernel-research/mdl-misuse-and-direct-io.md` | `docs/kernel-research/race-and-toctou-in-drivers.md` |
| Object Manager and handles | `docs/windows-internals/object-manager-and-handle-tables.md` | `docs/windows-internals/eprocess-token-object-model.md` |
| Runtime symbols and layout drift | `docs/kernel-research/runtime-pdb-symbol-resolution.md` | `docs/kernel-research/kernel-object-layout-drift.md` |
| Kernel base discovery | `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md` | `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md` |
| Prefetch KASLR side channel | `docs/kernel-research/prefetch-kaslr-side-channel-notes.md` | `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md` |
| Crash dump triage | `docs/debugging/crash-dump-driver-triage.md` | `docs/debugging/windbg-kernel-research-workflow.md` |
| Win32k USER/GDI research | `docs/kernel-research/win32k-research-notes.md` | `docs/kernel-research/public-poc-reading-and-annotation-template.md` |
| Windows IPC boundary atlas | `docs/kernel-research/windows-ipc-boundary-atlas.md` | `docs/kernel-research/com-and-rpc-research-notes.md` |
| ALPC deep research | `docs/kernel-research/alpc-research-notes.md` | `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md` |
| COM / RPC deep research | `docs/kernel-research/com-and-rpc-research-notes.md` | `docs/windows-internals/object-manager-and-handle-tables.md` |
| HKOM / DKOM hide concepts | `docs/kernel-research/hkom-dkom-hide-research-notes.md` | `docs/windows-internals/object-manager-and-handle-tables.md` |
| HKOM process hide cross-view | `docs/kernel-research/hkom-process-hide-crossview.md` | `docs/windows-internals/eprocess-token-object-model.md` |
| HKOM driver/module hide cross-view | `docs/kernel-research/hkom-driver-module-hide-crossview.md` | `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md` |

## BYOVD

| Topic | Start here | Supporting docs |
|---|---|---|
| BYOVD section overview | `03_byovd/00_index-and-matrix/README.md` | `03_byovd/00_index-and-matrix/BYOVD_RECENT_WRITEUPS.md` |
| Primitive matrix | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md` | `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` |
| Primitive bridge reasoning | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md` | `docs/kernel-research/offensive-driver-exploitability-map.md` |
| LnvMSRIO technique chain | `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md` | `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO.md` |
| Process-create callback tamper | `03_byovd/00_index-and-matrix/BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md` | `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md` |
| Loadability and reachability | `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md` | `docs/detection-and-mitigation/byovd-detection.md` |
| Physical memory R/W | `03_byovd/01_physical-memory-rw/` | `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md` |
| Virtual kernel R/W | `03_byovd/02_virtual-kernel-rw/` | `docs/windows-internals/page-table-walking.md` |
| Process kill | `03_byovd/03_process-kill/` | `docs/detection-and-mitigation/byovd-detection.md` |
| Limited primitives | `03_byovd/04_limited-primitives/` | `docs/kernel-research/previousmode-research-notes.md` |
| MSR and multi-primitive drivers | `03_byovd/05_msr-and-multi-primitive/` | `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` |

## Source Mining

| Topic | Start here | Supporting docs |
|---|---|---|
| DriverShield source build plan | `05_global-research-map/DRIVERSHIELD_SOURCE_BUILD_PLAN.md` | `05_global-research-map/DRIVERSHIELD_TRIAGE_QUEUE.md` |
| Global source map | `05_global-research-map/GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md` | `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md` |
| S12Deff Medium source map | `docs/research-index/s12deff-medium-source-map.md` | `03_byovd/00_index-and-matrix/BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md` |
| Pwn2Nimron source map | `docs/research-index/pwn2nimron-source-map.md` | `docs/kernel-research/prefetch-kaslr-side-channel-notes.md` |

External indexes:

- [DriverShield BYOVD Research Index](https://drivershield.io/byovd/) - metadata index of public GitHub BYOVD and vulnerable-driver research repositories.
- [LOLDrivers](https://www.loldrivers.io/) - vulnerable, malicious, and suspicious driver catalog.

## Mitigations

| Topic | Start here | Supporting docs |
|---|---|---|
| Mitigation matrix | `02_mitigations-vbs-hvci-vtrp/MITIGATION_MATRIX.md` | `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md` |
| HVCI and VBS | `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` | `02_mitigations-vbs-hvci-vtrp/CONNOR_HVCI_KCFG_DEEP_DIVE.md` |
| VT-rp and HLAT | `02_mitigations-vbs-hvci-vtrp/VT_RP_HLAT_DEEP_DIVE.md` | `docs/kernel-research/hypervisor-assisted-introspection.md` |
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
| AV/EDR user-mode tamper and spoofing | `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md` | `docs/detection-and-mitigation/driver-evasion-pressure-map.md` |
| AV self-protection product case studies | `docs/detection-and-mitigation/av-self-protection-research-index.md` | `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md` |
| Huorong self-protection | `docs/detection-and-mitigation/av-case-huorong-self-protection.md` | `docs/detection-and-mitigation/av-self-protection-research-index.md` |
| Qihoo / 360 self-protection | `docs/detection-and-mitigation/av-case-qihoo-360-self-protection.md` | `docs/detection-and-mitigation/av-self-protection-research-index.md` |

## Modern Research Surfaces

| Topic | Start here | Supporting docs |
|---|---|---|
| Win32k USER/GDI | `docs/kernel-research/win32k-research-notes.md` | `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md` |
| Win32k case studies | `docs/kernel-research/win32k-case-study-atlas.md` | `docs/kernel-research/win32k-research-notes.md` |
| Primitive pseudo-PoC sketches | `docs/kernel-research/primitive-pseudocode-sketchbook.md` | `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md` |
| I/O rings | `docs/kernel-research/io-ring-research-notes.md` | `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md` |
| HKOM / DKOM hide | `docs/kernel-research/hkom-dkom-hide-research-notes.md` | `docs/windows-internals/eprocess-token-object-model.md` |
| Technique writing format | `docs/research-index/technique-writing-standard.md` | `docs/research-index/driver-research-topic-index.md` |
| Callback surfaces | `docs/kernel-research/callback-surfaces.md` | `docs/windows-internals/object-manager-and-handle-tables.md` |
| CLFS / ALPC / RPC / COM | `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md` | `docs/detection-and-mitigation/minifilter-and-edr-visibility.md` |
| IPC boundary atlas | `docs/kernel-research/windows-ipc-boundary-atlas.md` | `docs/kernel-research/alpc-research-notes.md` |
| ALPC broker reasoning | `docs/kernel-research/alpc-research-notes.md` | `docs/kernel-research/com-and-rpc-research-notes.md` |
| COM / RPC boundary reasoning | `docs/kernel-research/com-and-rpc-research-notes.md` | `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md` |
| Prefetch / KASLR side channel | `docs/kernel-research/prefetch-kaslr-side-channel-notes.md` | `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md` |
| Windows Audio / audiodg LPE | `docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md` | `docs/windows-internals/eprocess-token-object-model.md` |
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
14. `docs/kernel-research/windows-ipc-boundary-atlas.md`
15. `docs/kernel-research/alpc-research-notes.md`
16. `docs/kernel-research/com-and-rpc-research-notes.md`
17. `docs/kernel-research/prefetch-kaslr-side-channel-notes.md`

Public PoC reading path:

1. `docs/kernel-research/public-poc-reading-and-annotation-template.md`
2. `docs/kernel-research/offensive-driver-exploitability-map.md`
3. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
4. `docs/kernel-research/primitive-pseudocode-sketchbook.md`
5. `docs/kernel-research/win32k-research-notes.md`
6. `docs/kernel-research/win32k-case-study-atlas.md`
7. `docs/kernel-research/kernel-object-layout-drift.md`
8. `docs/kernel-research/runtime-pdb-symbol-resolution.md`
9. `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`
10. `docs/kernel-research/windows-ipc-boundary-atlas.md`
11. `docs/kernel-research/alpc-research-notes.md`
12. `docs/kernel-research/com-and-rpc-research-notes.md`
13. `docs/kernel-research/prefetch-kaslr-side-channel-notes.md`

BYOVD analyst path:

1. `03_byovd/00_index-and-matrix/README.md`
2. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md`
3. `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`
4. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
5. `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md`
6. `docs/detection-and-mitigation/byovd-detection.md`
7. `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md`
8. `docs/detection-and-mitigation/mde-kql-byovd-hunting-patterns.md`
9. `docs/mitigations/dse-code-integrity-research-notes.md`

Modern Windows LPE concept path:

1. `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md`
2. `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`
3. `docs/kernel-research/io-ring-research-notes.md`
4. `docs/kernel-research/primitive-pseudocode-sketchbook.md`
5. `docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md`
6. `docs/kernel-research/win32k-research-notes.md`
7. `docs/kernel-research/kernel-object-layout-drift.md`
8. `docs/windows-internals/eprocess-token-object-model.md`
9. `docs/kernel-research/windows-ipc-boundary-atlas.md`
10. `docs/kernel-research/alpc-research-notes.md`
11. `docs/kernel-research/com-and-rpc-research-notes.md`
12. `docs/kernel-research/prefetch-kaslr-side-channel-notes.md`

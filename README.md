# Windows Kernel Exploit Research Resource

This repository is a structured Windows kernel research notebook focused on driver internals, BYOVD analysis, modern mitigations, and defensive telemetry. It is written for lab research, reverse engineering, detection engineering, and exploit-development literacy without providing turnkey abuse runbooks.

## Scope

Core themes:

- Windows kernel object and memory internals
- Driver attack surface and IOCTL review
- BYOVD primitive taxonomy and vulnerable-driver reachability
- HVCI, VBS, KDP, PatchGuard, KPTI, WDAC, and driver blocklist pressure
- ETW, Sysmon, Code Integrity, minifilter, and EDR visibility
- AV/EDR user-mode tamper, state spoofing, and product-health consistency analysis
- Windows Audio / `audiodg.exe` user-mode LPE composition and service-token research
- Build-specific offset drift, PDB symbols, and WinDbg workflows
- Kernel base discovery from syscall-entry anchors and PE header scanning
- HKOM / DKOM hide concepts and cross-view detection
- Driver exploit bug-class reasoning and defensive evasion-pressure mapping
- Offensive driver exploitability reasoning and public PoC annotation without runnable trigger material
- Modern research surfaces such as Win32k, I/O rings, CLFS, ALPC, callbacks, MDLs, and `PreviousMode`
- Windows IPC boundary reasoning across ALPC, RPC, COM, named pipes, and broker/service trust transitions

Safety boundary:

- No new exploit chains, shellcode, token stealing code, DSE bypass code, EDR bypass payloads, or weaponized trigger buffers should be added.
- Existing PoC material should be treated as lab-only reference material and wrapped with defensive analysis, version assumptions, and mitigation notes.
- Prefer internals, primitive classification, crash triage, policy impact, and detection logic.

## Repository Map

| Path | Purpose |
|---|---|
| `01_core-handbook/` | Broad Windows kernel exploitation and mitigation handbook material |
| `02_mitigations-vbs-hvci-vtrp/` | VBS, HVCI, KDP, VT-rp, HLAT, and mitigation-aware primitive analysis |
| `03_byovd/` | BYOVD research organized by primitive class and workflow |
| `04_connor-mcgarr-study/` | Study notes around paging, PTEs, pool, control-flow mitigations, and HVCI concepts |
| `05_global-research-map/` | External source map and reading plan |
| `docs/windows-internals/` | Object Manager, handle tables, EPROCESS/TOKEN, paging, and related internals |
| `docs/userland-to-kernel/` | IOCTLs, transfer methods, `METHOD_NEITHER`, and user/kernel boundary notes |
| `docs/kernel-research/` | Focused research notes for Win32k, callbacks, MDLs, races, I/O rings, CLFS/ALPC/RPC/COM, symbols, and layout drift |
| `docs/detection-and-mitigation/` | BYOVD detection, ETW, driver-load telemetry, Code Integrity, minifilter, and EDR visibility |
| `docs/mitigations/` | PatchGuard, KPTI/KVA shadow, DSE, and Code Integrity notes |
| `docs/research-index/` | Repo audit, summaries, and topic indexes |
| `90_sources/` | Imported upstream reference material; not first-party guidance |

## Best Starting Points

For a fast overview:

1. `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md`
2. `03_byovd/00_index-and-matrix/README.md`
3. `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`
4. `02_mitigations-vbs-hvci-vtrp/MITIGATION_MATRIX.md`
5. `docs/research-index/driver-research-topic-index.md`
6. `docs/research-index/master-driver-research-map.md`
7. `docs/research-index/resource-coverage-audit-2026-05-27.md`

For driver reversing:

1. `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md`
2. `docs/userland-to-kernel/ioctl-reverse-engineering.md`
3. `docs/userland-to-kernel/method-neither-research-notes.md`
4. `docs/kernel-research/mdl-misuse-and-direct-io.md`
5. `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md`
6. `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md`
7. `docs/kernel-research/ida-ghidra-driver-re-patterns.md`
8. `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md`
9. `docs/kernel-research/driver-exploit-technique-atlas.md`
10. `docs/kernel-research/race-and-toctou-in-drivers.md`
11. `docs/kernel-research/driver-verifier-sdv-codeql-research-workflow.md`
12. `docs/debugging/crash-dump-driver-triage.md`

For offensive research reading and public PoC annotation:

1. `docs/kernel-research/offensive-driver-exploitability-map.md`
2. `docs/kernel-research/public-poc-reading-and-annotation-template.md`
3. `docs/kernel-research/primitive-pseudocode-sketchbook.md`
4. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
5. `docs/kernel-research/driver-exploit-technique-atlas.md`
6. `03_byovd/99_workflow/IOCTL_BUG_CLASS_PLAYBOOK.md`
7. `docs/kernel-research/kernel-object-layout-drift.md`
8. `docs/kernel-research/runtime-pdb-symbol-resolution.md`
9. `docs/kernel-research/prefetch-kaslr-side-channel-notes.md`

For BYOVD:

1. `03_byovd/00_index-and-matrix/BYOVD_CHINA_SOURCE_MAP.md`
2. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md`
3. `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`
4. `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_PRIMITIVES_TAXONOMY.md`
5. `03_byovd/00_index-and-matrix/BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`
6. `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md`
7. `03_byovd/00_index-and-matrix/BYOVD_PHYSICAL_MEMORY_PRIMITIVES_DEEP_DIVE.md`
8. `03_byovd/00_index-and-matrix/BYOVD_VIRTUAL_KERNEL_RW_DEEP_DIVE.md`
9. `03_byovd/00_index-and-matrix/BYOVD_MSR_PORT_MMIO_HARDWARE_PRIMITIVES.md`
10. `03_byovd/00_index-and-matrix/BYOVD_LIMITED_WRITE_AND_PREVIOUSMODE.md`
11. `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`
12. `03_byovd/00_index-and-matrix/BYOVD_PROCESS_CREATE_CALLBACK_TAMPER_S12DEFF.md`
13. `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md`
14. `docs/detection-and-mitigation/byovd-detection.md`
15. `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md`
16. `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
17. External reference: [DriverShield BYOVD Research Index](https://drivershield.io/byovd/)

For source mining and research queue building:

1. `05_global-research-map/DRIVERSHIELD_SOURCE_BUILD_PLAN.md`
2. `05_global-research-map/DRIVERSHIELD_TRIAGE_QUEUE.md`
3. `05_global-research-map/GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md`
4. `docs/research-index/s12deff-medium-source-map.md`
5. External source hub: [DriverShield](https://drivershield.io/)

For modern mitigation-aware research:

1. `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`
2. `docs/mitigations/dse-code-integrity-research-notes.md`
3. `docs/mitigations/patchguard-kpti-kva-shadow.md`
4. `docs/kernel-research/io-ring-research-notes.md`
5. `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
6. `docs/kernel-research/win32k-research-notes.md`
7. `docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md`
8. `docs/kernel-research/hkom-dkom-hide-research-notes.md`

For IPC / broker-boundary research:

1. `docs/kernel-research/windows-ipc-boundary-atlas.md`
2. `docs/kernel-research/alpc-research-notes.md`
3. `docs/kernel-research/com-and-rpc-research-notes.md`
4. `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md`
5. `docs/windows-internals/object-manager-and-handle-tables.md`
6. `docs/windows-internals/windows-audio-audiodg-lpe-research-notes.md`
7. `docs/kernel-research/win32k-research-notes.md`

For single-technique deep dives:

1. `docs/research-index/technique-writing-standard.md`
2. `docs/research-index/master-driver-research-map.md`
3. `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`
4. `docs/kernel-research/io-ring-research-notes.md`
5. `docs/kernel-research/primitive-pseudocode-sketchbook.md`
6. `docs/kernel-research/win32k-research-notes.md`
7. `docs/kernel-research/win32k-case-study-atlas.md`
8. `03_byovd/00_index-and-matrix/BYOVD_CASE_LNVMSRIO_TECHNIQUE_CHAIN_ATLAS.md`
9. `docs/kernel-research/hkom-process-hide-crossview.md`
10. `docs/kernel-research/hkom-driver-module-hide-crossview.md`
11. `docs/kernel-research/prefetch-kaslr-side-channel-notes.md`

For detection:

1. `docs/detection-and-mitigation/byovd-detection.md`
2. `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
3. `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`
4. `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
5. `docs/detection-and-mitigation/driver-evasion-pressure-map.md`
6. `docs/detection-and-mitigation/av-self-protection-research-index.md`
7. `docs/detection-and-mitigation/av-case-microsoft-defender-self-protection.md`
8. `docs/detection-and-mitigation/av-case-huorong-self-protection.md`
9. `docs/detection-and-mitigation/av-case-qihoo-360-self-protection.md`
10. `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`
11. `docs/detection-and-mitigation/byovd-hunting-and-hardening-checklists.md`

## Research Method

Use this model for any driver:

```text
identify driver and signer
  -> decide loadability under current policy
  -> map device objects and dispatch table
  -> classify IOCTL transfer methods and access bits
  -> trace user-controlled data into kernel routines
  -> classify primitive, reachability, reliability, and mitigation pressure
  -> document defensive detection and hardening notes
```

Important questions:

- Does the driver load on the target Windows build and policy state?
- Is the driver blocked by Microsoft vulnerable driver rules, WDAC, HVCI compatibility, or enterprise policy?
- Does a user-accessible device object exist without rare hardware?
- Which caller can open the device?
- What does each reachable IOCTL trust?
- Is the effect a crash, semantic action, read/write primitive, MSR/physical access, or policy tamper?
- Which telemetry would expose load, service creation, device access, Code Integrity friction, or post-interaction crash evidence?

## External Indexes

- [DriverShield BYOVD Research Index](https://drivershield.io/byovd/) - curated metadata index of public BYOVD and vulnerable-driver GitHub research repositories.
- [DriverShield Driver Database](https://drivershield.io/database/) - driver intelligence database for source triage, risk/verdict metadata, and hash pivots.
- [LOLDrivers](https://www.loldrivers.io/) - vulnerable, malicious, and suspicious driver catalog.
- [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) - Microsoft vulnerable driver blocklist guidance.

## Contribution Rules

- Keep new documents concept-heavy and lab-safe.
- Add source links for external claims.
- Prefer primary Microsoft documentation for Windows APIs, driver signing, Code Integrity, and mitigation behavior.
- Separate upstream exploit repository notes from first-party defensive analysis.
- Do not normalize old offsets or structure layouts as universal facts; note Windows build assumptions.

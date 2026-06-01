# Phase 2B Summary

## Files created

- `docs/userland-to-kernel/method-neither-research-notes.md`
- `docs/windows-internals/object-manager-and-handle-tables.md`
- `docs/mitigations/patchguard-kpti-kva-shadow.md`
- `docs/debugging/windbg-kernel-research-workflow.md`
- `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`
- `docs/research-index/phase-2b-summary.md`

## Files modified

- None beyond creation of the new Phase 2B files.

## Topics covered

- Dedicated `METHOD_NEITHER` trust-boundary analysis
- Object Manager internals and handle-table model
- PatchGuard and KPTI/KVA Shadow
- WinDbg-safe kernel research workflow
- Driver-load telemetry, ETW concepts, and Code Integrity

## Topics still missing

- Callback surfaces and notify routines
- Object callbacks as a dedicated document
- Minifilter altitude and visibility
- ETW Threat Intelligence provider deep dive
- Standalone handle-table research beyond general Object Manager coverage
- Standalone `PreviousMode` general research note
- MDL misuse as a focused topic
- TOCTOU and race-condition hunting as a dedicated methodology note
- CLFS / ALPC / RPC / COM research tracks
- Hypervisor-assisted introspection
- Crash-dump-guided exploit triage as a dedicated methodology note
- Kernel object layout drift tracking and version-diff workflow

## References found

Primary and official sources used:

- Microsoft Learn driver documentation for:
  - `IRP_MJ_DEVICE_CONTROL`
  - `PreviousMode`
  - `ProbeForRead`
  - `METHOD_NEITHER` / buffer descriptions
  - Object Manager and object handles
  - `ObReferenceObjectByHandle`
  - Code Integrity event logging
  - driver signing and blocklist guidance
  - WinDbg command references and symbol-path guidance
- MSRC Blog on KVA Shadow
- Microsoft Security Blog on vulnerable and malicious driver reporting
- Sysinternals Sysmon documentation
- Supplemental Chinese technical sources from Anquanke for namespace and debugging context

## References not verified

- No intentionally fabricated or placeholder references were added.
- Some Chinese secondary sources remain supplemental and should be treated as context rather than as authoritative replacements for Microsoft or primary vendor documentation.

## Overlap avoided

Phase 2B avoided duplicating Phase 2A content by:

- keeping `METHOD_NEITHER` separate from the broader userland-to-kernel boundary and IOCTL RE documents,
- treating Object Manager and handle tables as a namespace/lifetime/handle-mediation deep dive instead of repeating the `EPROCESS` and token model,
- focusing the mitigation file on PatchGuard and KVA Shadow rather than re-covering the repo's already deep HVCI/VBS material,
- making the WinDbg document workflow-oriented instead of repeating the Phase 2A pages on paging, PDBs, or pool internals,
- making the telemetry file driver-load and Code-Integrity specific rather than repeating the broader BYOVD detection overview.

## Suggested Phase 2C prompt

```text
Phase 2C: expand the rare and advanced Windows kernel research areas that are still missing.

Requirements:
- Do not edit README.md.
- Do not refactor code.
- Do not write exploit chains, PoC payloads, shellcode, token stealing code, DSE bypass code, EDR bypass code, or rootkit code.
- Create focused technical docs for:
  1. docs/advanced/callback-surfaces-and-notify-routines.md
  2. docs/advanced/object-callbacks-and-handle-filtering.md
  3. docs/advanced/minifilter-altitudes-and-visibility.md
  4. docs/advanced/mdl-misuse-and-memory-mapping-risks.md
  5. docs/advanced/toctou-and-race-condition-hunting.md
  6. docs/advanced/clfs-alpc-rpc-com-kernel-research-map.md
  7. docs/advanced/hypervisor-assisted-introspection.md
  8. docs/advanced/crash-dump-guided-exploit-triage.md
  9. docs/advanced/kernel-object-layout-drift.md
- Cross-check repo-audit.md, phase-2a-summary.md, and phase-2b-summary.md before writing.
- Keep every file internals-heavy, defensive, lab-safe, and reference-backed.
```

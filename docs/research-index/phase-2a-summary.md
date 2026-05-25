# Phase 2A Summary

## Files created

- `docs/userland-to-kernel/userland-to-kernel-boundary.md`
- `docs/userland-to-kernel/ioctl-reverse-engineering.md`
- `docs/vulnerable-drivers/arbitrary-read-write-primitives.md`
- `docs/windows-heap/usermode-heap-internals.md`
- `docs/windows-heap/kernel-pool-internals.md`
- `docs/windows-heap/userland-vs-kernelland-heap.md`
- `docs/windows-internals/page-table-walking.md`
- `docs/kernel-research/runtime-pdb-symbol-resolution.md`
- `docs/windows-internals/eprocess-token-object-model.md`
- `docs/detection-and-mitigation/byovd-detection.md`

## Files modified

- `docs/research-index/phase-2a-summary.md`

## Topics covered

- User-mode to kernel-mode trust boundary
- Device control path and IRP-based IOCTL handling
- Generalized IOCTL reverse engineering workflow
- Vulnerable-driver primitive taxonomy
- User-mode heap internals
- Kernel pool internals
- User heap versus kernel pool comparison
- Page-table walking and virtual-to-physical translation
- Runtime PDB symbol resolution
- `EPROCESS`, token, handle table, and Object Manager concepts
- BYOVD detection and mitigation

## Topics still missing

- Dedicated `METHOD_NEITHER` standalone deep dive
- Dedicated PatchGuard and KPTI/KVA shadow note
- Dedicated WinDbg workflow playbook
- Dedicated Object Manager symbolic link / namespace abuse note
- CLFS / ALPC / RPC / COM research tracks
- Rare advanced techniques collection
- Dedicated ETW and MDE-focused telemetry guide beyond BYOVD overview

## References found

Primary or official references used:

- Microsoft Learn driver and debugger documentation for:
  - `IRP_MJ_DEVICE_CONTROL`
  - `ZwDeviceIoControlFile`
  - `PreviousMode`
  - `ProbeForRead`
  - I/O buffering and `METHOD_NEITHER`
  - Object Manager and object handles
  - `!heap`, `!pte`, `!vtop`, `!verifier`
  - `ExAllocatePool2`
  - Driver Verifier and Special Pool
  - Symbol server, SymSrv, DbgHelp, PE format
  - DIA SDK
  - Microsoft vulnerable driver blocklist
  - Sysmon
- Quarkslab Lenovo vulnerable-driver article
- Elastic Security Labs BYOVD and detection material
- Chinese-language technical articles from Anquanke used as supplemental reading

## References not verified

- None of the references listed in the new docs are intentionally marked unverified.
- Some Chinese-language secondary sources remain supplemental rather than authoritative and should not override official Microsoft or primary vendor documentation when conflicts appear.

## Suggested Phase 2B prompt

```text
Phase 2B: expand the next missing areas from phase-2a-summary.md.

Requirements:
- Do not edit README.md.
- Do not refactor code.
- Do not write exploit chains or runnable payloads.
- Create focused new docs for:
  1. docs/userland-to-kernel/method-neither-research-notes.md
  2. docs/windows-internals/object-manager-and-handle-tables.md
  3. docs/mitigations/patchguard-kpti-kva-shadow.md
  4. docs/debugging/windbg-kernel-research-workflow.md
  5. docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md
- Keep the content internals-heavy, defensive, and lab-safe.
- Cross-check repo-audit.md and phase-2a-summary.md before writing to avoid overlap.
```

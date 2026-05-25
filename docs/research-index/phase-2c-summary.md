# Phase 2C Summary

## Files created

- `docs/kernel-research/callback-surfaces.md`
- `docs/kernel-research/previousmode-research-notes.md`
- `docs/kernel-research/mdl-misuse-and-direct-io.md`
- `docs/kernel-research/race-and-toctou-in-drivers.md`
- `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`
- `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`
- `docs/kernel-research/clfs-alpc-rpc-com-research-tracks.md`
- `docs/kernel-research/hypervisor-assisted-introspection.md`
- `docs/kernel-research/kernel-object-layout-drift.md`
- `docs/research-index/phase-2c-summary.md`

## Files modified

- None beyond creation of the new Phase 2C files.

## Topics covered

- Kernel callback surfaces and callback-family lifecycle risks
- `PreviousMode` / `RequestorMode` trust-boundary analysis
- MDL misuse and Direct I/O lifecycle problems
- Race conditions and TOCTOU in drivers
- Minifilter-based visibility and EDR telemetry boundaries
- ETW Threat Intelligence as a correlation surface
- CLFS / ALPC / RPC / COM safe research tracks
- Hypervisor-assisted kernel introspection
- Kernel object layout drift across Windows builds

## Topics still missing

- Dedicated object-callback-only deep dive
- Dedicated process/thread/image notify routine inventory by subsystem
- Dedicated registry callback deep dive
- Dedicated crash-dump-guided exploit triage methodology note
- Dedicated safe lab roadmap and learning path documents
- Cross-linking and consistency pass across the full docs tree
- Unified glossary and WinDbg command index
- Dedicated reference-verification pass for all documents

## References found

Primary and high-quality references used:

- Microsoft Learn for:
  - process/image/thread notify routines
  - registry callback registration
  - Object Manager callback registration structures
  - Filter Manager concepts and minifilter callback flows
  - MDL, Direct I/O, and mapping routines
  - VBS / VSM / virtualization concepts
  - symbol, PE, and debugger concepts
- MSRC Blog on KVA Shadow
- Project Zero registry and kernel-object analysis series
- Sysinternals Sysmon documentation
- Supplemental Chinese technical references from Anquanke for callback and namespace context

## References not verified

- No fabricated references were added.
- Some Chinese-language secondary sources remain supplemental and should not override primary Microsoft or direct vendor documentation if there is any disagreement.

## Overlap avoided

Phase 2C avoided duplicating Phase 2A and 2B by:

- keeping callback analysis separate from the broader Object Manager, boundary, and telemetry docs,
- treating `PreviousMode` / `RequestorMode` as a trust-boundary semantics topic rather than repeating the AsIO3 case-study focus,
- making the MDL document specifically about Direct I/O ownership and cleanup instead of repeating `METHOD_NEITHER` or general heap/pool material,
- focusing the race document on concurrency and lifetime rather than re-covering raw pointer models or minifilter semantics,
- treating minifilters and ETW as visibility-specific documents rather than repeating the broader BYOVD or driver-load telemetry docs,
- presenting CLFS / ALPC / RPC / COM as safe research tracks rather than duplicating existing exploit-oriented case-study areas,
- making hypervisor introspection and layout drift complement the existing PDB/paging/HVCI docs rather than restating them.

## Suggested Phase 2D prompt

```text
Phase 2D: documentation quality and navigation pass.

Requirements:
- Do not edit README.md.
- Do not refactor code.
- Do not add exploit code or runnable payloads.
- Focus on documentation quality, consistency, and discoverability only.
- Create:
  1. docs/research-index/topic-index.md
  2. docs/research-index/glossary.md
  3. docs/research-index/learning-paths.md
  4. docs/research-index/defensive-checklists.md
  5. docs/research-index/windbg-command-index.md
  6. docs/research-index/reference-verification-pass.md
  7. docs/research-index/safe-lab-roadmap.md
- Cross-link existing Phase 2A/2B/2C docs by topic.
- Normalize terminology where needed with light edits only if they avoid duplication or inconsistency.
- Add a final consistency matrix showing which topics are deep, medium, or still missing.
```

# Repository Documentation Audit

## 1. Current folder structure

Relevant documentation-oriented tree:

```text
E:\Windows-kernel-exploit-research-resource
|-- MEMORY.md
|-- README.md                        (empty)
|-- 01_core-handbook
|   `-- WINDOWS_KERNEL_EXPLOIT_RESEARCH.md
|-- 02_mitigations-vbs-hvci-vtrp
|   |-- CONNOR_HVCI_KCFG_DEEP_DIVE_VI.md
|   |-- MITIGATION_MATRIX.md
|   |-- RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md
|   `-- VT_RP_HLAT_DEEP_DIVE_VI.md
|-- 03_byovd
|   |-- 00_index-and-matrix
|   |   |-- BYOVD_BLOCKLIST_AND_REACHABILITY.md
|   |   |-- BYOVD_PRIMITIVE_MATRIX.md
|   |   |-- BYOVD_RECENT_WRITEUPS.md
|   |   `-- README.md
|   |-- 01_physical-memory-rw
|   |   |-- ASTRA64_DIRECT_DKOM_DEEP_DIVE.md
|   |   |-- ASTRA64_RW_CODE_WALKTHROUGH.md
|   |   |-- ENEIO64_PHYSICAL_RW_DEEP_DIVE.md
|   |   |-- LENOVO_LNVMSRIO_DEEP_DIVE.md
|   |   |-- PSTRIP64_POWERSTRIP_DEEP_DIVE.md
|   |   `-- THROTTLESTOP_PHYSICAL_RW_DEEP_DIVE.md
|   |-- 02_virtual-kernel-rw
|   |   |-- DBUTIL_2_3_DELL_DEEP_DIVE.md
|   |   |-- DSARK64_QIHOO_DEEP_DIVE.md
|   |   `-- RTCORE64_MSI_AFTERBURNER_DEEP_DIVE.md
|   |-- 03_process-kill
|   |   |-- BDAPIUTIL64_CODE_WALKTHROUGH.md
|   |   |-- BDAPIUTIL64_PROCESS_KILLER_DEEP_DIVE.md
|   |   |-- K7RKSCAN_CODE_WALKTHROUGH.md
|   |   |-- K7RKSCAN_PROCESS_KILLER_DEEP_DIVE.md
|   |   |-- TFSYSMON_THREATFIRE_DEEP_DIVE.md
|   |   `-- ZEMANA_TERMINATOR_DEEP_DIVE.md
|   |-- 04_limited-primitives
|   |   `-- ASIO3_PREVIOUSMODE_DEEP_DIVE.md
|   |-- 05_msr-and-multi-primitive
|   |   |-- GDRV_GIGABYTE_DEEP_DIVE.md
|   |   `-- WINRING0_AWESOME_MINER_MSR_DEEP_DIVE.md
|   |-- 99_workflow
|   |   `-- NEW_DRIVER_REVERSING_WORKFLOW.md
|   `-- astra64_lpe
|       `-- *.cpp                    (code, not documentation)
|-- 04_connor-mcgarr-study
|   |-- 01_PAGING_AND_PTE_DEEP_DIVE.md
|   |-- 02_SMEP_NX_PTE_BYPASS_CONCEPTS.md
|   |-- 04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md
|   |-- 06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md
|   |-- 07_HVCI_EXISTING_CODE_INVOCATION.md
|   |-- CONNOR_MCGARR_WINDOWS_KERNEL_DEEP_RESEARCH_VI.md
|   `-- README.md
|-- 05_global-research-map
|   |-- GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md
|   `-- README.md
|-- 90_sources
|   `-- _source\BYOVD               (upstream reference material)
|       |-- README.md
|       |-- Astra64-RW\README.md
|       |-- BdApiUtil-Killer\README.md
|       |-- K7Terminator\README.md
|       `-- TfSysMon-Killer\README.md
`-- docs
    `-- research-index
        `-- repo-audit.md
```

Observations:

- The repo already has a strong document spine in `01_core-handbook`, `02_mitigations-vbs-hvci-vtrp`, `03_byovd`, and `04_connor-mcgarr-study`.
- `README.md` at repo root is currently empty, but this phase does not modify it.
- `90_sources\_source\BYOVD` looks like imported upstream reference content, not first-party documentation.
- `03_byovd\astra64_lpe` currently contains code only and has no local documentation wrapper.

## 2. Existing documentation map

| File | Main topic | Depth | Notes |
|---|---|---|---|
| `README.md` | Root landing page | shallow | Empty file. No usable documentation yet. |
| `MEMORY.md` | Repo memory/index/meta-summary | medium | Strong overview of scope and current themes; not a technical deep dive itself. |
| `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md` | Windows kernel exploitation master handbook | deep | Broadest first-party foundation doc; mixes internals, mitigations, offsets, BYOVD, reading path. |
| `02_mitigations-vbs-hvci-vtrp/CONNOR_HVCI_KCFG_DEEP_DIVE_VI.md` | Connor McGarr HVCI/kCFG concepts | deep | Strong concept translation and mitigation reasoning. |
| `02_mitigations-vbs-hvci-vtrp/MITIGATION_MATRIX.md` | Mitigation matrix by layer/version/primitive | deep | High-value reference; broad and structured. |
| `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` | R/W primitive behavior under HVCI/VBS | deep | One of the strongest repo docs; modern mitigation-aware framing. |
| `02_mitigations-vbs-hvci-vtrp/VT_RP_HLAT_DEEP_DIVE_VI.md` | VT-rp, HLAT, EPT, KDP, remapping | deep | Very deep and specialized. |
| `03_byovd/00_index-and-matrix/README.md` | BYOVD section index | shallow | Navigation/index only. |
| `03_byovd/00_index-and-matrix/BYOVD_RECENT_WRITEUPS.md` | Recent BYOVD cases and notes | deep | Good case inventory and idea map. |
| `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_MATRIX.md` | Primitive comparison matrix | medium | Useful taxonomy, but compact relative to the topic. |
| `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md` | Loadability/reachability/usefulness model | deep | Strong modern BYOVD screening model. |
| `03_byovd/01_physical-memory-rw/ASTRA64_DIRECT_DKOM_DEEP_DIVE.md` | ASTRA64 physical-memory path and direct DKOM | deep | Extremely detailed; also creates overlap pressure with page-table, token, and HVCI docs. |
| `03_byovd/01_physical-memory-rw/ASTRA64_RW_CODE_WALKTHROUGH.md` | ASTRA64 code walkthrough | deep | Detailed driver/PoC reasoning anchored in upstream source. |
| `03_byovd/01_physical-memory-rw/ENEIO64_PHYSICAL_RW_DEEP_DIVE.md` | eneio64 physical R/W | medium | Good conceptual case note; less exhaustive than ASTRA64. |
| `03_byovd/01_physical-memory-rw/LENOVO_LNVMSRIO_DEEP_DIVE.md` | Lenovo physical R/W + MSR | medium | Good comparative case note. |
| `03_byovd/01_physical-memory-rw/PSTRIP64_POWERSTRIP_DEEP_DIVE.md` | PowerStrip physical memory mapping | medium | Useful but shorter case coverage. |
| `03_byovd/01_physical-memory-rw/THROTTLESTOP_PHYSICAL_RW_DEEP_DIVE.md` | ThrottleStop physical R/W | medium | Useful but not exhaustive. |
| `03_byovd/02_virtual-kernel-rw/DBUTIL_2_3_DELL_DEEP_DIVE.md` | Dell virtual kernel write | medium | Short but focused. |
| `03_byovd/02_virtual-kernel-rw/DSARK64_QIHOO_DEEP_DIVE.md` | DsArk64 virtual R/W + auth/protocol | medium | Richer than the other virtual R/W docs, but still more case-note than handbook. |
| `03_byovd/02_virtual-kernel-rw/RTCORE64_MSI_AFTERBURNER_DEEP_DIVE.md` | RTCore64 virtual R/W | medium | Good practical framing. |
| `03_byovd/03_process-kill/BDAPIUTIL64_CODE_WALKTHROUGH.md` | BdApiUtil code walkthrough | medium | Solid implementation walkthrough. |
| `03_byovd/03_process-kill/BDAPIUTIL64_PROCESS_KILLER_DEEP_DIVE.md` | BdApiUtil process-kill primitive | medium | Good generic-framework explanation. |
| `03_byovd/03_process-kill/K7RKSCAN_CODE_WALKTHROUGH.md` | K7Terminator code walkthrough | medium | Useful source-driven doc. |
| `03_byovd/03_process-kill/K7RKSCAN_PROCESS_KILLER_DEEP_DIVE.md` | K7 process-kill primitive | deep | Deeper than most process-kill notes. |
| `03_byovd/03_process-kill/TFSYSMON_THREATFIRE_DEEP_DIVE.md` | ThreatFire process-kill primitive | shallow | Short case note. |
| `03_byovd/03_process-kill/ZEMANA_TERMINATOR_DEEP_DIVE.md` | Zemana process-kill pattern | medium | Useful operational note, limited low-level reverse detail. |
| `03_byovd/04_limited-primitives/ASIO3_PREVIOUSMODE_DEEP_DIVE.md` | PreviousMode abuse via limited primitive | medium | Strong topic choice; deserves deeper generalization beyond single case. |
| `03_byovd/05_msr-and-multi-primitive/GDRV_GIGABYTE_DEEP_DIVE.md` | gdrv multi-primitive / arbitrary write / MSR | medium | Good study case, limited deeper internals. |
| `03_byovd/05_msr-and-multi-primitive/WINRING0_AWESOME_MINER_MSR_DEEP_DIVE.md` | WinRing0 MSR abuse | medium | Good MSR-focused case note. |
| `03_byovd/99_workflow/NEW_DRIVER_REVERSING_WORKFLOW.md` | BYOVD analysis workflow | medium | Strong process skeleton; could expand on IOCTL reversing and bug-class taxonomy. |
| `04_connor-mcgarr-study/README.md` | Connor track index | shallow | Navigation only. |
| `04_connor-mcgarr-study/CONNOR_MCGARR_WINDOWS_KERNEL_DEEP_RESEARCH_VI.md` | Connor master study notes | deep | Broad cross-linking doc; part roadmap, part synthesis. |
| `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md` | Paging, PTE, VA->PA, HVCI interaction | deep | Strong internals foundation. |
| `04_connor-mcgarr-study/02_SMEP_NX_PTE_BYPASS_CONCEPTS.md` | SMEP/NX/PTE bypass thinking | medium | Good concept doc; narrower than title family suggests. |
| `04_connor-mcgarr-study/04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md` | Kernel pool, kLFH, segment heap | medium | Valuable but still compact for allocator depth. |
| `04_connor-mcgarr-study/06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md` | Control-flow mitigations | medium | Good conceptual slice. |
| `04_connor-mcgarr-study/07_HVCI_EXISTING_CODE_INVOCATION.md` | HVCI and existing-code invocation | medium | Strong conceptual distillation; not a full internals treatment. |
| `05_global-research-map/README.md` | Global research map index | shallow | Navigation only. |
| `05_global-research-map/GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md` | International source map | medium | Helpful research-planning meta doc, not a core internals doc. |
| `90_sources/_source/BYOVD/README.md` | Upstream BYOVD project README | unknown | Third-party upstream reference. Useful context, but not repo-authored documentation. |
| `90_sources/_source/BYOVD/Astra64-RW/README.md` | Upstream Astra64-RW README | unknown | Source reference; contains exploit-oriented upstream description. Needs careful separation from first-party docs. |
| `90_sources/_source/BYOVD/BdApiUtil-Killer/README.md` | Upstream BdApiUtil README | unknown | Source reference only. |
| `90_sources/_source/BYOVD/K7Terminator/README.md` | Upstream K7Terminator README | unknown | Source reference only. |
| `90_sources/_source/BYOVD/TfSysMon-Killer/README.md` | Upstream TfSysMon README | unknown | Source reference only. |

## 3. Existing Windows kernel / internals coverage

Current first-party coverage is strongest in these areas:

- Windows kernel exploitation overview:
  `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md` is the repo's main umbrella handbook.
- Mitigation-aware exploit thinking:
  HVCI, VBS, KDP, VT-rp/HLAT, SMEP, SMAP, kCFG, CET, KASLR, PatchGuard, WDAC/blocklist are already discussed in meaningful depth.
- Page-table and translation concepts:
  `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md` plus the ASTRA64 docs cover CR3, PTEs, PFNs, VA->PA, and the modern HVCI caveat.
- Arbitrary kernel read/write primitives:
  Strong discussion exists across `RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`, the physical R/W folder, the virtual R/W folder, and some workflow material.
- Physical memory primitives:
  This is one of the deepest areas in the repo. ASTRA64 coverage is especially strong, with comparison docs for Lenovo, ThrottleStop, eneio64, and PowerStrip.
- BYOVD methodology:
  Strongly covered via primitive matrix, blocklist/reachability model, recent writeups index, and driver-reversing workflow.
- Vulnerable driver case studies:
  Strong coverage overall, especially in BYOVD.
- Driver / IOCTL reverse engineering:
  Present in workflow and several code walkthroughs, but more case-driven than general.
- `EPROCESS` / token / process object themes:
  Present across the core handbook, Connor study, ASTRA64 docs, and AsIO3 notes.
- Kernel pool exploitation:
  Present, but mostly as a conceptual introduction rather than a full allocator research track.
- WinDbg / lab workflow:
  Present indirectly in paging and handbook notes, but not yet as a dedicated debugging guide.
- Detection / mitigation:
  Present throughout many docs, especially blocklist/reachability, mitigation matrix, and some case study defensive views.
- Research source mapping:
  `05_global-research-map` already supports planning future reading.

Areas present but still uneven:

- Object Manager:
  Mentioned in `MEMORY.md` and implied in some docs, but not yet a dedicated deep dive.
- Handle tables:
  Mentioned sporadically, not deeply covered as a first-class topic.
- Userland-to-kernel boundary:
  Touched via HVCI, PreviousMode, and signed driver IOCTL discussion, but lacks one dedicated conceptual document.
- Windows heap internals:
  Very light. Kernel pool has some coverage; user-mode heap coverage is effectively absent.
- Rare / advanced techniques:
  VT-rp/HLAT is strong, but other advanced topics are still thin or absent.

## 4. Missing technical areas

The repo is already strong on mitigation-aware BYOVD and physical/virtual primitive analysis. The main missing or underdeveloped areas are:

- Runtime PDB symbol resolution as a standalone topic.
  Current status: implied by the handbook and ASTRA64 materials, but there is no dedicated first-party doc on symbol servers, DIA/DbgHelp, public vs private symbols, type recovery, build drift, and offset validation.
- Vulnerable IOCTL analysis as a generalized method.
  Current status: workflow exists, but there is no dedicated doc on IRP stack locations, transfer methods, input/output buffer semantics, access bits, dispatch flow, and how to reason from IOCTL to bug class.
- `METHOD_NEITHER` as a bug class.
  Current status: effectively missing as a standalone technical topic.
- User-mode heap internals.
  Current status: missing. No dedicated coverage of NT heap, segment heap, LFH, frontend/backend allocators, or exploit-relevant differences from kernel pool.
- Kernel pool internals beyond conceptual overview.
  Current status: `04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md` is useful, but shallow-to-medium for allocator mechanics, pool headers, bucket behavior, pool tags, quotas, object adjacency, and modern exploitation constraints.
- Object Manager and handle tables.
  Current status: missing as dedicated docs. This is notable because object pointers, handles, reference counts, `PreviousMode`, and access checks connect directly to exploit primitives.
- Dedicated `EPROCESS` / `TOKEN` internals handbook.
  Current status: scattered across multiple docs, especially ASTRA64 and Connor notes, but not centralized.
- Userland vs kernelland exploitation differences.
  Current status: touched repeatedly, but not distilled into one clear comparison doc.
- PatchGuard as a standalone deep dive.
  Current status: present in matrix/mentions, but no dedicated deep technical note.
- KPTI / KVA shadow.
  Current status: mentioned, but no direct treatment.
- Detection engineering for BYOVD.
  Current status: present in notes, but there is no dedicated ETW / Sysmon / MDE / driver-load telemetry document.
- WinDbg workflow and lab debugging.
  Current status: missing as its own guide.
- Rare / advanced kernel research techniques outside VT-rp.
  Missing or thin examples:
  page-table self-reference and PTE base derivation on modern builds,
  secure kernel / VTL1 boundary observations,
  kernel callback surfaces,
  object header / reference count abuse patterns,
  MDL-based attack surfaces,
  I/O manager internals,
  ALPC / RPC / COM-to-kernel pathways,
  CLFS and filesystem-oriented kernel research,
  KUSER_SHARED_DATA mapping changes as a dedicated doc,
  firmware / SMM / DMA-adjacent boundary notes.
- Documentation wrapper for `03_byovd/astra64_lpe`.
  Current status: code exists but no local explanatory doc. This is a repo-structure gap even if phase 1 does not fill it.

## 5. Duplicate / overlapping areas

These overlaps are not necessarily bad, but they should be managed in later phases:

- HVCI / VBS / existing-code invocation:
  `02_mitigations-vbs-hvci-vtrp/CONNOR_HVCI_KCFG_DEEP_DIVE_VI.md`
  `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`
  `04_connor-mcgarr-study/07_HVCI_EXISTING_CODE_INVOCATION.md`
  `04_connor-mcgarr-study/CONNOR_MCGARR_WINDOWS_KERNEL_DEEP_RESEARCH_VI.md`
  Notes: strong conceptual overlap; each has a different angle, but terminology can drift.
- Paging / PTE / translation:
  `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md`
  `02_mitigations-vbs-hvci-vtrp/VT_RP_HLAT_DEEP_DIVE_VI.md`
  `03_byovd/01_physical-memory-rw/ASTRA64_DIRECT_DKOM_DEEP_DIVE.md`
  `03_byovd/01_physical-memory-rw/ASTRA64_RW_CODE_WALKTHROUGH.md`
  Notes: this is the most repeated technical substrate in the repo.
- ASTRA64 coverage:
  `03_byovd/01_physical-memory-rw/ASTRA64_DIRECT_DKOM_DEEP_DIVE.md`
  `03_byovd/01_physical-memory-rw/ASTRA64_RW_CODE_WALKTHROUGH.md`
  `03_byovd/00_index-and-matrix/BYOVD_RECENT_WRITEUPS.md`
  `90_sources/_source/BYOVD/Astra64-RW/README.md`
  Notes: high overlap, but still justified because one is repo analysis, one is upstream reference, and one is indexing.
- Process-killer BYOVD framework:
  `03_byovd/03_process-kill/BDAPIUTIL64_CODE_WALKTHROUGH.md`
  `03_byovd/03_process-kill/BDAPIUTIL64_PROCESS_KILLER_DEEP_DIVE.md`
  `03_byovd/03_process-kill/K7RKSCAN_CODE_WALKTHROUGH.md`
  `03_byovd/03_process-kill/K7RKSCAN_PROCESS_KILLER_DEEP_DIVE.md`
  `03_byovd/03_process-kill/TFSYSMON_THREATFIRE_DEEP_DIVE.md`
  `03_byovd/03_process-kill/ZEMANA_TERMINATOR_DEEP_DIVE.md`
  Notes: there is useful repetition, but a future taxonomy doc could reduce duplication.
- Mitigation timeline / matrix / research map:
  `01_core-handbook/WINDOWS_KERNEL_EXPLOIT_RESEARCH.md`
  `02_mitigations-vbs-hvci-vtrp/MITIGATION_MATRIX.md`
  `05_global-research-map/GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md`
  Notes: some overlap in source lists and high-level framing.

Potential structural duplication problem:

- `MEMORY.md` repeats a substantial amount of inventory/detail already present in the docs themselves. It is useful for workspace memory, but it also risks becoming stale.

## 6. Recommended documentation expansion plan

Priority is ordered to maximize technical value while minimizing overlap with material already written.

1. `docs/research-index/runtime-pdb-symbol-resolution.md`
   Focus:
   runtime PDB lookup, symbol servers, DbgHelp/DIA choices, public symbol limitations, field offset verification, build drift, safe lab workflow.
   Why first:
   the repo repeatedly depends on offsets and symbol reasoning, but this topic is still fragmented.

2. `04_connor-mcgarr-study/03_USERLAND_VS_KERNELLAND_EXPLOITATION_DIFFERENCES.md`
   Focus:
   exploit goals, trust boundaries, allocation models, control-flow assumptions, mitigation differences, telemetry differences.
   Why:
   the repo repeatedly contrasts old shellcode logic vs modern data-only/existing-code logic, but lacks a direct comparison document.

3. `03_byovd/99_workflow/VULNERABLE_IOCTL_ANALYSIS.md`
   Focus:
   IOCTL layout, access bits, device object ACLs, dispatch paths, transfer methods, common dangerous APIs, buffer trust mistakes, primitive extraction.
   Why:
   this is central to vulnerable driver analysis and reverse engineering.

4. `03_byovd/99_workflow/METHOD_NEITHER_RESEARCH_NOTES.md`
   Focus:
   probe/lock semantics, raw user pointers, IRQL constraints, TOCTOU, common crash modes, why the bug class is attractive and unstable.
   Why:
   explicitly requested priority topic and currently absent.

5. `01_core-handbook/EPROCESS_TOKEN_OBJECT_MANAGER_INTERNALS.md`
   Focus:
   `EPROCESS`, `_EX_FAST_REF`, primary vs impersonation token, protection fields, object headers, handles, reference counting, access checks.
   Why:
   the repo already leans on these objects heavily, but the coverage is scattered.

6. `01_core-handbook/OBJECT_MANAGER_AND_HANDLE_TABLES.md`
   Focus:
   object headers, pointer vs handle, per-process handle tables, access masks, `ObReferenceObjectByHandle`, exploit-relevant implications.
   Why:
   directly supports `PreviousMode`, token, and process object research.

7. `04_connor-mcgarr-study/05_WINDOWS_HEAP_AND_POOL_FOUNDATIONS.md`
   Focus:
   user-mode heap vs kernel pool, LFH vs kLFH, segment heap, backend behavior, object adjacency, research heuristics.
   Why:
   bridges the current gap between sparse user-mode heap coverage and medium kernel pool coverage.

8. `04_connor-mcgarr-study/08_KERNEL_POOL_INTERNALS_DEEP_DIVE.md`
   Focus:
   pool headers, tags, bucket behavior, quota/charge, allocator metadata, common adjacent object patterns, modern exploitation constraints.
   Why:
   the existing pool document is a strong introduction but not a deep allocator reference.

9. `02_mitigations-vbs-hvci-vtrp/PATCHGUARD_KPTI_AND_KERNEL_BOUNDARY_NOTES.md`
   Focus:
   PatchGuard watch surfaces, KPTI/KVA shadow, what these change and what they do not, implications for data-only and page-table tricks.
   Why:
   both topics are currently scattered.

10. `02_mitigations-vbs-hvci-vtrp/ETW_SYSMON_DRIVER_LOAD_TELEMETRY.md`
    Focus:
    ETW providers, Sysmon event families, service creation, image load, kernel driver load visibility, MDE/Defender/WDAC signals, hunting ideas.
    Why:
    detection exists as notes today, not as an organized operational doc.

11. `04_connor-mcgarr-study/09_RARE_WINDOWS_KERNEL_RESEARCH_TECHNIQUES.md`
    Focus:
    PTE self-reference, KUSER_SHARED_DATA mapping changes, MDLs, callback surfaces, secure kernel boundary observations, unusual object targets, research-only ideas.
    Why:
    this creates a home for advanced topics without diluting the core handbook.

12. `03_byovd/astra64_lpe/README.md`
    Focus:
    document the existing local `.cpp` files at a high level only: purpose of each file, lab context, offsets/symbol assumptions, safe scope.
    Why:
    current code folder is undocumented inside the repo.

Secondary priorities:

- `04_connor-mcgarr-study/10_WINDBG_LAB_WORKFLOW.md`
- `01_core-handbook/IO_MANAGER_AND_IRP_INTERNALS.md`
- `01_core-handbook/CLFS_ALPC_RPC_COM_KERNEL_RESEARCH_MAP.md`
- `03_byovd/00_index-and-matrix/PROCESS_KILLER_TAXONOMY.md`

## 7. Safe writing constraints for next phase

The next phase should stay inside these constraints:

- Do not write a complete exploit chain.
- Do not write shellcode.
- Do not write token stealing code.
- Do not write EDR/AV bypass payloads.
- Do not write DSE bypass code.
- Do not write weaponized trigger buffers or runnable exploit steps.
- Only write:
  internals,
  primitive analysis,
  debugging workflow,
  reverse-engineering methodology,
  mitigation reasoning,
  detection and telemetry,
  defensive interpretation,
  lab-safe notes.

Additional repo-specific note:

- When discussing existing code in `03_byovd/astra64_lpe` or upstream `90_sources`, prefer architectural explanation and safety constraints over operational instructions.

## 8. Proposed next prompt

Recommended phase 2 prompt:

```text
Phase 2: write one new technical document only.

Create:
docs/research-index/runtime-pdb-symbol-resolution.md

Requirements:
- Do not edit README.md.
- Do not refactor code.
- Do not add exploit code.
- Write a defensive/lab-safe technical document about runtime PDB symbol resolution for Windows kernel research.
- Cover:
  - why offsets drift by build and cumulative update,
  - public symbols vs private symbols,
  - DbgHelp/DIA/symsrv concepts,
  - how to validate `_EPROCESS`, `_KTHREAD`, `_TOKEN` offsets safely,
  - how WinDbg `dt` and symbol loading fit into the workflow,
  - common failure modes,
  - how this supports BYOVD primitive analysis without becoming an exploit guide.
- Cross-reference existing repo topics only where needed to avoid duplication.
- Keep it concept-heavy, lab-safe, and non-operational.
```

Alternative strong phase 2 prompt if symbol work is postponed:

```text
Create:
03_byovd/99_workflow/VULNERABLE_IOCTL_ANALYSIS.md

Focus on generalized vulnerable IOCTL analysis, transfer methods, dispatch routines, access control, common dangerous APIs, and METHOD_NEITHER risk patterns.
Keep it defensive, reverse-engineering oriented, and non-operational.
```

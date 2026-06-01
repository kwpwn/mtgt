# Repository Audit

Backlinks: [README](../../README.md) | [topic index](topic-index.md) | [learning path](windows-kernel-pwn-learning-path.md)

## Purpose

This audit records the June 1, 2026 upgrade pass for turning the repository into a Windows Kernel Pwn Research Notebook. It is intentionally conservative: existing material is preserved, new files add structure, and ambiguous overlap is marked for later human review.

## Audit Scope

Primary Markdown areas observed:

| Area | Role in notebook | Action |
|---|---|---|
| `01_core-handbook/` | Core handbook material | Keep, cross-link from learning path. |
| `02_mitigations-vbs-hvci-vtrp/` | HVCI/VBS/VT-rp notes | Keep, map to new mitigation deep dive. |
| `03_byovd/` | BYOVD notes | Keep, map to modern Windows 11 threat model. |
| `04_connor-mcgarr-study/` | Connor McGarr HVCI study | Keep, map to HVCI and primitive reasoning. |
| `05_global-research-map/` | Research map | Keep, use as historical index. |
| `docs/kernel-research/` | Technique and primitive docs | Expanded with primitive reasoning and MSR notes. |
| `docs/detection-and-mitigation/` | Defensive playbooks | Expanded with BYOVD detection playbook. |
| `docs/research-index/` | Indexes and learning aids | Expanded heavily. |
| `docs/userland-to-kernel/` | Userland/kernel boundary | Expanded with IOCTL reversing workflow. |
| `docs/windows-internals/` | Internals | Expanded with page-table deep dive. |
| `docs/windows-heap/` | Heap/pool | Expanded with pool exploitation study map. |
| `docs/debugging/` | Debugging | Keep, should be linked from Level 0/1 learning path. |
| `docs/mitigations/` | Mitigation notes | Expanded with HVCI/VBS/KDP/VT-rp/HLAT deep dive. |
| `docs/vulnerable-drivers/` | Vulnerable driver material | Keep, should link into BYOVD taxonomy later. |
| `dsark64/README.md` | Driver-specific note | Left untouched because it already had uncommitted changes. |
| `90_sources/` | Source notes | Expanded with curated source notebook. |

## Markdown Count

The user-provided baseline says the repository has about 139 primary Markdown files excluding cache/dependency folders and `90_sources`. During this pass, shell enumeration failed after the initial directory listing due to the sandbox error `windows sandbox: spawn setup refresh`; therefore the exact automated count is marked as an assumption.

Assumption for this upgrade:

- Baseline primary Markdown count: approximately 139.
- `90_sources` is treated as source notebook material and excluded from the baseline count.
- Newly added files are counted in [upgrade changelog](upgrade-changelog.md).

## Worktree Safety

Pre-existing modified files observed before this upgrade:

| File | Handling |
|---|---|
| `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md` | Left untouched. |
| `03_byovd/00_index-and-matrix/BYOVD_PRIMITIVE_BRIDGE_REASONING.md` | Left untouched. |
| `dsark64/README.md` | Left untouched. |
| `upgrade_kernel_repo_prompt.txt` | Left untouched. |

## Thin Areas

| Gap | Why it matters | New coverage |
|---|---|---|
| Version-aware reasoning | Kernel exploitability changes across Windows 7, 10, 11, Server, and HVCI states. | [case-study matrix](case-study-matrix.md), [learning path](windows-kernel-pwn-learning-path.md). |
| Primitive reasoning | Students often memorize chains without knowing why a primitive is sufficient. | [primitive reasoning framework](../kernel-research/primitive-reasoning-framework.md). |
| Physical R/W to virtual R/W | BYOVD research often hinges on page-table walking. | [page-table deep dive](../windows-internals/page-table-and-address-translation-deep-dive.md). |
| HVCI/VBS/KDP/VT-rp | Modern Windows 11 changes exploit goals from shellcode to data-only and existing-code invocation. | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md). |
| BYOVD detection | Existing BYOVD notes need defensive operational mapping. | [BYOVD detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md). |
| Source provenance | PoC repos, forums, vendor blogs, and research papers need trust labels. | [source integration status](source-integration-status.md), `90_sources/curated-windows-kernel-pwn/`. |

## Duplicate-Risk Areas

The repository likely contains overlapping material around:

| Topic | Possible overlap | Recommendation |
|---|---|---|
| HVCI and VBS | `02_mitigations-vbs-hvci-vtrp/`, `04_connor-mcgarr-study/`, `docs/mitigations/` | Keep detailed notes, use the new deep dive as a hub. |
| BYOVD primitive chains | `03_byovd/`, `docs/vulnerable-drivers/`, source notes | Avoid merging until every driver-specific note has metadata. |
| Kernel pool exploitation | `docs/windows-heap/` and exploit case studies | Use the new study map as the taxonomy layer. |
| IOCTL reversing | Driver-specific notes may repeat CTL_CODE and METHOD_* explanations | Centralize conceptual explanation in the IOCTL reversing workflow. |

## Verification Limitations

Shell commands after the initial directory listing failed with `windows sandbox: spawn setup refresh`, so link checking and Markdown counting could not be completed automatically in this pass. This is recorded in [remaining work](remaining-work.md).

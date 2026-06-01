# Duplicate and Gap Report

Backlinks: [README](../../README.md) | [repo audit](repo-audit.md) | [topic index](topic-index.md)

## Duplicate Risks

| Topic | Existing locations | Risk | Resolution in this pass |
|---|---|---|---|
| HVCI/VBS explanations | `02_mitigations-vbs-hvci-vtrp/`, `04_connor-mcgarr-study/`, `docs/mitigations/` | Multiple versions may teach the same terms without a single version-aware matrix. | Added [HVCI/VBS/KDP/VT-rp/HLAT deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) as the hub. |
| BYOVD primitive chains | `03_byovd/`, `docs/vulnerable-drivers/`, source notes | Driver-specific chains can blur offensive steps with research concepts. | Added [modern BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) and [detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md). |
| Page-table notes | `MEMORY.md`, mitigation folders, case studies | Physical R/W explanations may repeat translation basics. | Added [page-table deep dive](../windows-internals/page-table-and-address-translation-deep-dive.md). |
| IOCTL reversing basics | Driver case studies | CTL_CODE/METHOD_* material may be repeated in each case study. | Added [IOCTL reversing workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md). |
| Primitive vocabulary | Many case studies | Students may see primitives as exploit recipes instead of reasoning units. | Added [primitive reasoning framework](../kernel-research/primitive-reasoning-framework.md). |

## Content Gaps Closed

| Gap | New doc |
|---|---|
| Master roadmap from fundamentals to capstone | [learning path](windows-kernel-pwn-learning-path.md) |
| Question-driven study | [question bank](windows-kernel-pwn-question-bank.md) |
| Source provenance and trust | [source integration status](source-integration-status.md), source notebook |
| Version-aware case study map | [case-study matrix](case-study-matrix.md) |
| Terminology normalization | [glossary](glossary.md) |

## Remaining Gaps

| Gap | Suggested next action |
|---|---|
| Exact Markdown count and dead-link scan | Run a link checker once shell tooling works. |
| Existing file cross-linking | Carefully update old docs after reviewing their current language and uncommitted changes. |
| Vendor-official validation for CVE-2026-21222 | Check MSRC Update Guide directly when available; current source is low-confidence. |
| Build-specific offset tables | Add a version matrix sourced from Vergilius, symbols, or lab notes, but avoid exploit recipes. |
| Detection examples | Add sample KQL/Sigma only at behavioral level; keep them non-evasive and defender-focused. |

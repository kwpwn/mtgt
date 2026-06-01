# Upgrade Changelog

Backlinks: [README](../../README.md) | [repo audit](repo-audit.md) | [source coverage](source-coverage-report.md)

## 2026-06-01 Notebook Upgrade

### Added

- Research index and audit docs:
  - `repo-audit.md`
  - `topic-index.md`
  - `source-integration-status.md`
  - `duplicate-and-gap-report.md`
  - `windows-kernel-pwn-learning-path.md`
  - `case-study-matrix.md`
  - `windows-kernel-pwn-question-bank.md`
  - `glossary.md`
  - `mitigation-version-matrix.md`
  - `remaining-work.md`
  - `source-coverage-report.md`
- Deep-dive docs:
  - `docs/windows-internals/page-table-and-address-translation-deep-dive.md`
  - `docs/kernel-research/primitive-reasoning-framework.md`
  - `docs/mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md`
  - `docs/byovd/byovd-modern-windows-11-threat-model.md`
  - `docs/detection-and-mitigation/byovd-detection-engineering-playbook.md`
  - `docs/userland-to-kernel/ioctl-reversing-workflow-deep-dive.md`
  - `docs/kernel-research/msr-wrmsr-research-notes.md`
  - `docs/windows-heap/kernel-pool-exploitation-study-map.md`
  - `docs/kernel-research/win32k-and-gui-kernel-attack-surface.md`
- Source notebook folder:
  - `90_sources/curated-windows-kernel-pwn/`

### Modified

No pre-existing content files were intentionally modified in this pass. Existing uncommitted changes were left intact.

### Assumptions

- Baseline primary Markdown count is approximately 139, based on the user-provided repo description.
- Blocked sources are recorded as blocked, not treated as integrated facts.
- Forum/GitHub PoC sources are treated as lower trust until independently verified.

### Safety Constraints Applied

- No runnable exploit code was added.
- No credential dumping, EDR bypass, DSE bypass, HVCI bypass, BYOVD exploit, loader, or callback tamper tool was created.
- Sensitive sources were summarized as concept, mitigation, detection, and lab-safe takeaway only.

# Resource Coverage Audit

Date: 2026-05-27

## Purpose

This audit checks whether the repository now covers the major Windows kernel driver research areas requested so far:

- BYOVD primitives,
- exploit driver bug classes,
- evasion pressure,
- detection,
- debugging,
- mitigation reasoning.

It also records what still needs work.

## Coverage Summary

| Area | Current depth | Main docs | Status |
|---|---|---|---|
| BYOVD primitive taxonomy | Deep | `BYOVD_NON_TERMINATE_PRIMITIVES_TAXONOMY.md`, primitive deep dives | Strong |
| BYOVD case studies | Medium-deep | `BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`, `BYOVD_CASE_*.md` | Strong but expandable |
| Physical memory primitives | Deep | physical BYOVD deep dive, page-table docs | Strong |
| Virtual kernel R/W | Deep | virtual R/W deep dive, RTCore/DBUtil/gdrv docs | Strong |
| MSR/port/MMIO | Medium-deep | hardware primitives deep dive, gdrv/WinRing0 docs | Strong enough |
| Limited write / `PreviousMode` | Medium-deep | limited write doc, PreviousMode notes | Strong enough |
| Callback/security-state tamper | Medium | callback tamper doc, evasion map | Needs more callback-family detail |
| Driver exploit bug classes | Medium-deep | technique atlas, IOCTL playbook | Strong |
| Offensive exploitability reasoning | Deep | exploitability map, PoC annotation template, primitive bridge reasoning | Strong |
| Evasion pressure | Medium-deep | driver evasion pressure map, HKOM docs | Strong but defensive-only |
| Detection and telemetry | Medium-deep | BYOVD detection, ETW, driver load, minifilter docs | Strong |
| Crash triage | Medium | WinDbg workflow, new crash triage doc | Needs examples later |
| WDF/KMDF internals | Medium-deep | WDF/KMDF reversing notes | Strong enough |
| Device ACL / SDDL | Medium-deep | Device ACL / SDDL / IOCTL access note | Strong enough |
| MDE/KQL concrete hunts | Medium | MDE/KQL hunting patterns | Strong enough |
| IDA/Ghidra driver RE patterns | Medium-deep | IDA/Ghidra pattern notebook | Strong enough |

## Existing Strengths

### 1. BYOVD is now organized by primitive

The repo no longer treats BYOVD as one bucket. It separates:

- physical memory,
- virtual kernel R/W,
- MSR,
- port/MMIO,
- limited writes,
- callback/security-state tamper,
- process termination,
- reachability/loadability.

This is the correct structure for serious research because each primitive has different reliability, mitigation pressure and detection.

### 2. The repo now teaches "why"

Recent docs use the pattern:

```text
technique
  -> invariant
  -> assumptions
  -> bridge
  -> failure modes
  -> detection
```

This is much better than a list of CVEs.

### 3. Evasion is framed defensively

The `driver-evasion-pressure-map.md` document keeps evasion discussion focused on:

- what visibility surface is pressured,
- which primitive enables it,
- what contradiction remains,
- what defenders can correlate.

This is safer and more useful than runnable bypass instructions.

## Important Gaps

### Closed Gap 1. WDF/KMDF Reverse Engineering

Added:

- `docs/kernel-research/wdf-kmdf-reverse-engineering-notes.md`

This covers `WdfDriverCreate`, `WdfDeviceCreate`, queues, `EvtIoDeviceControl`, request lifetime, object context, request forwarding, and cleanup callbacks.

### Closed Gap 2. Device ACL and SDDL Deep Dive

Added:

- `docs/userland-to-kernel/device-acl-sddl-ioctl-access.md`

Why it matters remains:

```text
reachability often decides exploitability before memory corruption matters
```

### Closed Gap 3. Concrete Hunting Queries

Added:

- `docs/detection-and-mitigation/mde-kql-byovd-hunting-patterns.md`

### Gap 4. Crash Dump Triage Examples

The repo has bugcheck-to-bug-class mapping, but can still use real example-style walkthroughs later.

### Closed Gap 5. Tooling Pattern Notebook

Added:

- `docs/kernel-research/ida-ghidra-driver-re-patterns.md`

### New Gap 6. Specific Public PoC Annotation Notes

The repo now has a template for reading public PoCs, but needs more per-blog/per-driver annotation notes.

Good future format:

```text
public PoC
  -> primitive
  -> bridge
  -> objective
  -> why
  -> failure modes
```

## Recommended Next Additions

Priority order:

1. Write per-public-PoC annotation notes for the highest-value blogs.
2. Apply reachability templates to every existing BYOVD case study.
3. Add crash dump example walkthroughs.
4. Add WDF object-context examples from real stripped drivers.
5. Add source-available driver CodeQL pattern examples.

## Quality Gate

Before calling any future doc "done", check:

- does it name the trust boundary,
- does it classify the primitive,
- does it explain why the primitive works,
- does it describe failure modes,
- does it include detection/defense,
- does it avoid runnable exploit steps,
- does it link to the correct topic index.

## Summary

The repo is now strong for BYOVD primitive research and driver exploit reasoning. The highest-value next upgrades are not more generic BYOVD prose; they are:

```text
WDF/KMDF reversing
device ACL/SDDL reachability
concrete hunting checklists
crash triage
IDA/Ghidra pattern recognition
```

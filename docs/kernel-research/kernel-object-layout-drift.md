# Kernel Object Layout Drift Across Windows Builds

## Purpose

This document explains why kernel object layouts drift across Windows builds and why that drift matters for research, debugging, detection, forensics, and vulnerable-driver analysis.

## Background

### Public symbols, private symbols, and PDBs

Kernel object layout understanding depends heavily on symbol quality. Public symbols, private symbols, and PDB identity determine how much the analyst can trust a field interpretation. When build provenance is missing, layout drift turns a technical note into a guess.

### Build-specific structure layouts

Windows kernel structures are implementation artifacts, not fixed ABI contracts for external consumers. Layouts can move because of:

- compiler changes,
- feature additions,
- hardening work,
- policy-related state,
- internal cleanup and refactoring,
- optional mitigation support.

### Why hardcoded offsets are fragile

Hardcoded offsets assume one build lineage and one structure shape. Windows servicing breaks that assumption often enough that build-aware workflows are mandatory for serious research.

## Core Concepts

### Example object families

Researchers often care about:

- `EPROCESS`
- `ETHREAD`
- `KTHREAD`
- `TOKEN`
- `FILE_OBJECT`
- `DRIVER_OBJECT`
- `DEVICE_OBJECT`

These are not special because they are magic targets; they are special because they sit at the intersection of debugging, policy, identity, and driver behavior.

### Field offset drift

Field drift matters when a note assumes:

- identity field offset,
- list linkage offset,
- protection-related field offset,
- object body substructure layout,
- callback or reference-related location.

Even a small move can invalidate:

- debugger scripts,
- detection parsers,
- memory forensics profiles,
- crash triage notes,
- driver-analysis hypotheses.

### Compiler changes and feature changes

Structure layout is not only a security hardening story. Ordinary engineering changes can reorder or resize fields, alter padding, or split structures differently.

### Mitigation-driven layout changes

Mitigation and hardening work can add state or reorganize internals. That means build drift is often a byproduct of defenses as much as of features.

### Symbol correctness

Correct layout interpretation depends on:

- correct build,
- correct image,
- correct PDB match,
- correct symbol loading state,
- and careful recording of what is known versus inferred.

## Technical Deep Dive

### How layout drift affects debugging

Typed debugger output becomes misleading when symbols are stale or mismatched. The analyst may think:

```text
field X is wrong on this machine
```

when the real problem is:

```text
I am applying the wrong layout description to this build.
```

### How layout drift affects detection logic

Detection tooling that inspects memory directly must be build-aware. Otherwise it risks:

- false positives,
- false negatives,
- broken object reconstruction,
- or silently reading the wrong field.

### How layout drift affects vulnerable-driver research

Driver analyses frequently discuss kernel objects, but the real question is whether the driver gives a capability that can reach meaningful state. If the state mapping is built on stale offsets, the research becomes unreliable or dangerously misleading.

### Runtime symbol resolution as the safer approach

Runtime symbol resolution is safer because it binds field interpretation to:

- actual build identity,
- symbol provenance,
- and current type information.

It is not magic, but it is usually better than copy-pasting offsets from a blog post or repository.

### Pattern scanning risk and false positives

Pattern scanning can help in some constrained cases, but it is risky because:

- patterns drift too,
- multiple matches may exist,
- mitigations and compiler changes alter nearby code/data shape,
- and a "found something that looks close" mindset easily produces false confidence.

### Cross-build validation workflow

A safer workflow:

```text
record exact Windows build
  -> verify image and symbols
  -> inspect field/type with debugger or symbol-aware tooling
  -> record provenance with notes
  -> compare across builds explicitly rather than assuming stability
```

## Layout Drift Matrix

| Object | Fields researchers care about | Why layout changes matter | Safer way to inspect |
|---|---|---|---|
| `EPROCESS` | PID, list links, token/protection state | Identity and security reasoning fail if offsets drift | Build-aware `dt` or symbol-backed tooling |
| `ETHREAD` | thread identity and execution-related state | Thread debugging and lifetime analysis break | Verified symbols and thread-context inspection |
| `KTHREAD` | scheduling/trust-boundary related internals | Subtle assumptions about execution state become wrong | Symbol-backed inspection with build notes |
| `TOKEN` | privilege and integrity-related fields | Security-state interpretation becomes misleading | Symbol-aware inspection and careful provenance |
| `FILE_OBJECT` | name/context pointers, flags | File-state and minifilter analysis misread semantics | Typed debugger output with matching symbols |
| `DRIVER_OBJECT` | dispatch pointers, extension relationships | RE and crash triage can mis-map ownership | `!drvobj` plus symbol hygiene |
| `DEVICE_OBJECT` | stack and extension relationships | Device exposure and stack reasoning drift | `!devobj` plus correct symbols |

## Debugging / Inspection Notes

### Symbol hygiene

Symbol hygiene means:

- correct symbol path,
- clean enough cache discipline,
- matching image and symbol identity,
- explicit note of what symbol source was used.

### `lmv` and `dt`

`lmv` is useful for module identity and symbol confidence. `dt` is useful for typed layout inspection. Both become misleading if symbol correctness is not established first.

### Verifying PDB age and GUID conceptually

The PDB identity problem is not solved by matching on filename alone. GUID and age matter because they bind the symbol file to the binary's debug identity.

### Avoiding stale symbols

If a typed field looks implausible, a stale symbol state should be ruled out before concluding the kernel changed in a surprising way.

### Documenting Windows build

Every layout note should preserve:

- exact Windows build,
- module version,
- symbol source,
- whether the field was directly observed or inferred.

## Defensive Angle

Detection tools must be build-aware because:

- memory parsing against stale layouts is operationally dangerous,
- forensics can fail silently with the wrong profile,
- symbol cache integrity and provenance matter for trustworthy analysis.

This is also why enterprise debugging and EDR engineering teams must treat build drift as a maintenance reality, not as an edge case.

## Common Mistakes

- Recording offsets without build provenance.
- Assuming one Windows 11 build represents all current Windows 11 systems.
- Treating pattern-scanned matches as equivalent to symbol-backed field identity.
- Ignoring symbol-cache contamination when outputs look strange.

## Research Notes

- Layout drift is one of the main reasons modern kernel research must be build-aware by default.
- The safest note is often the one that records uncertainty and provenance, not the one that presents one offset as universal truth.
- This topic connects directly to runtime PDB resolution, WinDbg workflow discipline, and out-of-guest introspection accuracy.

## Lab-Safe Exercises

1. On two different Windows builds in VMs, compare one typed kernel object with matching symbols and note which fields shifted or need revalidation.
2. Build a template for documenting object-layout observations with build number, module version, and symbol source.
3. Take one old research note and rewrite it with explicit provenance and uncertainty labels.

## References / Further Reading

- Microsoft Learn, `PE Format`:
  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Microsoft Learn, `Using a Symbol Server`:
  https://learn.microsoft.com/en-ca/windows-hardware/drivers/debugger/using-a-symbol-server
- Microsoft Learn, `Debug Interface Access SDK`:
  https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk?view=vs-2022
- Existing repo note, [runtime-pdb-symbol-resolution.md](E:\Windows-kernel-exploit-research-resource\docs\kernel-research\runtime-pdb-symbol-resolution.md)
- Existing repo note, [windbg-kernel-research-workflow.md](E:\Windows-kernel-exploit-research-resource\docs\debugging\windbg-kernel-research-workflow.md)

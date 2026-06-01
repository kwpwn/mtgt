# Runtime PDB Symbol Resolution

## Purpose

This document explains why runtime symbol resolution is a safer and more defensible approach than hardcoded offsets when studying Windows kernel structures. It focuses on symbol identity, offset drift, safe validation, and detection considerations.

## Background

Windows kernel research often relies on structure fields such as:

- `_EPROCESS.UniqueProcessId`
- `_EPROCESS.ActiveProcessLinks`
- `_EPROCESS.Token`
- `_EPROCESS.Protection`

The problem is not that these fields stop existing. The problem is that their layout and offsets drift across:

- major releases,
- monthly cumulative updates,
- checked versus retail differences,
- optional feature changes,
- symbol availability and type exposure differences.

Hardcoding offsets can therefore turn a research note into a crash note.

## Core Concepts

### Why hardcoded offsets break

Hardcoded offsets assume:

- one build,
- one type layout,
- one servicing state,
- one symbol interpretation.

That assumption is brittle in Windows kernel work. Even when a field concept remains stable, its byte offset can move.

### PDB symbols

Program database (PDB) files carry debug information such as:

- type definitions,
- field layouts,
- symbol names,
- address relationships,
- line and source mapping where available.

For kernel research, they are valuable because they provide a structured path to build-aware type information without relying only on reverse-engineered magic numbers.

### CodeView `RSDS`

Portable Executable images can contain debug directory entries that point to CodeView information. The familiar `RSDS` record is conceptually the identity link between a binary and its matching PDB metadata. Analysts should understand it as:

```text
binary debug record
  -> PDB identity
  -> GUID
  -> Age
  -> original PDB path hint
```

### GUID + Age

Matching the correct symbol file is not only about filename. The GUID and age identify which PDB instance belongs to the image. This matters because a "nearby" PDB with the same name but wrong build lineage can yield convincing but wrong type information.

### Microsoft symbol server

The Microsoft symbol server is the central public source for many Windows symbols. Public symbols are extremely useful, but analysts should remember:

- they are not equivalent to full private source-level knowledge,
- not every internal field is equally exposed,
- public symbol quality varies by component and build.

## Technical Deep Dive

### Runtime offset discovery

Three broad strategies exist:

| Strategy | Strength | Weakness |
|---|---|---|
| Hardcoded offsets | Fast and simple | Brittle across builds and servicing |
| Pattern scanning | Independent of symbol availability in some cases | Fragile, heuristic, easy to overfit |
| Runtime PDB symbols | Structured and build-aware | Depends on symbol availability and correct matching |

From a documentation quality standpoint, runtime symbols are usually the best conceptual default because they make the build dependency explicit.

### DbgHelp and DIA SDK concepts

Two common symbol-access paths are:

- DbgHelp:
  convenient Win32 symbol APIs used by many tools and debuggers.
- DIA SDK:
  richer structured access to PDB contents through `IDiaSession`, `IDiaSymbol`, and related interfaces.

The practical difference is often not "which is better universally", but:

- DbgHelp is common for symbol loading and lookup tasks,
- DIA is attractive when you need structured type introspection and richer symbol traversal.

### Safe validation workflow

Lab-safe symbol validation should look like:

```text
identify exact target build
  -> ensure image and PDB identity match
  -> load symbols in debugger or analysis tool
  -> inspect target type
  -> verify fields needed for the research question
  -> record build provenance with the offsets
```

The defensive documentation lesson is that offsets should never float free from provenance.

### Conceptual example fields

Why these fields matter conceptually:

| Field | Why researchers care |
|---|---|
| `_EPROCESS.UniqueProcessId` | Process identity mapping |
| `_EPROCESS.ActiveProcessLinks` | Executive process-list navigation |
| `_EPROCESS.Token` | Security context attachment |
| `_EPROCESS.Protection` | Protected process / protection-level state |

This document intentionally stops at the structure-understanding level and does not turn field discovery into a payload recipe.

### Failure modes

| Failure mode | Consequence |
|---|---|
| Wrong PDB matched by name only | Convincing but false offsets |
| Public symbols omit needed type detail | Partial or unusable structure view |
| Kernel image and symbols from different servicing level | Misleading field layout |
| Pattern scan overfitted to one build | Silent failure on later builds |
| Offset copied from a write-up without provenance | Research debt and instability |

### Detection considerations

Runtime symbol resolution is not inherently malicious. Debuggers, profilers, crash triage tools, and developer diagnostics use it legitimately. But in a defensive context, unusual patterns can still be informative:

- unexpected symbol-server access by an otherwise ordinary application,
- DbgHelp or symbol-resolution library use by a binary with no obvious debugging role,
- new symbol cache artifacts on systems where such activity is atypical,
- a process resolving detailed kernel type information shortly before suspicious driver interaction.

These are contextual signals, not standalone verdicts.

## Windows Version Notes

- Public symbol availability and richness vary across components and releases.
- Windows 10 and Windows 11 servicing cadence makes provenance recording especially important.
- Analysts should record absolute versions and build numbers when discussing offsets rather than speaking generically about "Windows 11" or "24H2-era" alone.

## Common Mistakes

- Treating PDB filename as sufficient proof of match.
- Copying offsets from public repos without build metadata.
- Assuming public symbols always expose every internal field needed.
- Treating pattern scans as maintenance-free replacements for symbol-aware reasoning.
- Confusing debugger convenience with symbol correctness.

## Debugging / Inspection Notes

Safe debugging and inspection points:

- WinDbg symbol loading and `dt` for type inspection.
- DbgHelp concepts such as symbol initialization and named lookup.
- DIA SDK concepts such as `IDiaSession` and `IDiaSymbol`.
- PE debug-directory inspection when verifying CodeView linkage.

Inspection checklist:

- Which binary build am I analyzing?
- What symbol source am I using?
- Does the PDB identity actually match?
- Which fields are confirmed versus inferred?
- What would break if this offset is wrong?

## Defensive Angle

From a defensive standpoint, runtime symbols are a double-edged capability:

- they improve crash response, debugging, and root-cause quality,
- but they can also reduce uncertainty for any actor trying to reason about current kernel structure layouts.

That does **not** mean symbol access is suspicious by default. It means defenders should baseline where symbol tooling is expected and where it is not.

## Lab-Safe Exercises

1. Pick a Windows kernel build in a VM and record the exact build string before looking at any structure fields.
2. In WinDbg, load symbols and inspect a benign type with `dt`, then note what information is explicit versus omitted.
3. Create a comparison table for one field using:
   hardcoded-offset note,
   pattern-based hypothesis,
   symbol-backed confirmation.

## References / Further Reading

- Microsoft Learn, `Using a Symbol Server`:
  https://learn.microsoft.com/en-ca/windows-hardware/drivers/debugger/using-a-symbol-server
- Microsoft Learn, `Using SymSrv`:
  https://learn.microsoft.com/en-us/windows/win32/debug/using-symsrv
- Microsoft Learn, `PE Format`:
  https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Microsoft Learn, `SymFromName`:
  https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/nf-dbghelp-symfromname
- Microsoft Learn, `SYMBOL_INFO`:
  https://learn.microsoft.com/en-us/windows/win32/api/dbghelp/ns-dbghelp-symbol_info
- Microsoft Learn, `Debug Interface Access SDK`:
  https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk?view=vs-2022
- Microsoft Learn, `IDiaSession`:
  https://learn.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/idiasession?view=visualstudio
- Anquanke, `Windows nei he ti quan lou dong CVE-2018-8120 fen xi - shang`:
  https://www.anquanke.com/post/id/241057

# Driver Verifier, KMDF Verifier, SDV, and CodeQL Research Workflow

Updated: 2026-05-27

## Purpose

This note explains how to use verifier-style tooling as part of Windows driver research.

It is useful for:

- understanding crash evidence,
- validating suspected bug classes,
- hardening internal drivers,
- writing better reverse-engineering notes,
- mapping exploit primitives to the contract violation that enabled them.

Safety boundary:

- no exploit chains,
- no fuzzing harness recipes,
- no trigger buffers,
- focus on contracts, diagnostics, and defensive validation.

## Why Verifier Matters

A normal crash often says:

```text
bad pointer
```

Verifier often says:

```text
which driver contract was violated
```

That distinction matters because exploitability begins with a broken invariant:

- wrong IRQL,
- invalid pool ownership,
- user pointer trusted in the wrong context,
- request completed twice,
- callback not unregistered,
- MDL misused,
- WDF object lifetime broken,
- DDI called with illegal parameters.

## Tool Roles

| Tool | Role |
|---|---|
| Driver Verifier | Runtime checking for kernel driver contract violations |
| KMDF Verifier | Framework-specific runtime validation for KMDF drivers |
| Static Driver Verifier | Static rules for supported driver models in older WDK/EWDK flows |
| CodeQL | Modern static analysis path for driver code patterns |
| WinDbg verifier extensions | Inspect verifier state and crash context |

## Runtime Versus Static

Runtime tools answer:

```text
when this path executes, which contract breaks?
```

Static tools answer:

```text
which paths appear capable of breaking a contract?
```

For research, the best workflow is:

```text
static hypothesis
  -> runtime verifier signal
  -> crash dump triage
  -> source/binary review
  -> defensive note
```

## Driver Verifier Focus Areas

High-value checks for driver research include:

- special pool,
- pool tracking,
- force IRQL checking,
- I/O verification,
- deadlock detection,
- DMA checking,
- security checks,
- miscellaneous checks,
- DDI compliance checking.

Why:

```text
these checks turn silent memory/lifetime bugs into explicit evidence
```

Do not enable aggressive verifier settings on production endpoints. Use lab systems and test snapshots.

## KMDF Verifier

KMDF Verifier validates framework-specific behavior, including:

- framework method arguments,
- WDF object state,
- I/O queue usage,
- cancellation behavior,
- lock acquisition and hierarchy,
- IRQL correctness around framework calls,
- timeout behavior for framework events.

Why:

```text
WDF removes some manual IRP handling,
but introduces framework object lifetime and queue contracts
```

Research examples:

| Symptom | KMDF angle |
|---|---|
| crash after request cancellation | queue/request ownership |
| unload hang | pending framework object or queue state |
| random callback crash | object context lifetime |
| verifier break in WDF method | invalid handle/state/IRQL |

## Static Driver Verifier Status

Microsoft documentation notes an important modern tooling change:

```text
SDV is not available in Windows 24H2 WDK/EWDK releases;
Microsoft points to Windows 11 version 22H2 EWDK for SDV,
and CodeQL as the primary static analysis tool going forward.
```

Implication:

```text
old SDV notes remain useful historically,
but new research workflows should include CodeQL-style static checks
```

## CodeQL-Oriented Driver Questions

For source-available drivers, CodeQL queries should look for patterns like:

- user-controlled size to copy,
- user-controlled pointer to kernel dereference,
- missing length check before fixed-offset parse,
- integer overflow before allocation,
- lock/unlock imbalance,
- request completion on multiple paths,
- `METHOD_NEITHER` without probe/SEH/lifetime discipline,
- physical address mapping with user-controlled range,
- MSR/port/MMIO helpers with weak authorization,
- device creation without appropriate access control.

Why:

```text
source analysis can find families of bugs before a crash gives a single example
```

## Verifier-To-Bug-Class Map

| Verifier signal | Likely research class |
|---|---|
| special pool overrun | length confusion or off-by-one |
| freed pool access | use-after-free, request lifetime, callback lifetime |
| IRQL violation | pageable code/data or illegal DDI at elevated IRQL |
| I/O verification failure | IRP/request ownership bug |
| deadlock warning | lock order or cancellation race |
| DMA/MDL violation | direct I/O or MDL misuse |
| DDI compliance failure | wrong API context or parameter contract |
| WDF queue/request error | KMDF object lifecycle or queue semantics |

## BYOVD Research Use

For third-party vulnerable drivers, verifier is not always practical because:

- binaries may be signed but unsupported,
- source is unavailable,
- verifier can change timing and crash earlier than the primitive path,
- production machines are unsafe for this testing.

Still, in a lab it helps answer:

```text
is the observed crash a reliability bug,
or does it indicate a controllable primitive boundary?
```

Examples of safe research questions:

- Does malformed input crash at parse, sink, or cleanup?
- Does the crash occur before privileged state mutation?
- Is the failure deterministic?
- Does verifier point to lifetime, IRQL, or buffer contract?
- Does HVCI/blocklist state change reachability?

## Crash Dump Integration

After a verifier crash, record:

```text
bugcheck:
verifier stop:
faulting driver:
faulting instruction:
IRQL:
request/IRP state:
queue state if WDF:
pool tag:
recent driver load:
recent device interaction:
violated invariant:
likely bug class:
```

Cross-link:

- `docs/debugging/crash-dump-driver-triage.md`

## Defensive Hardening Workflow

For internally owned drivers:

1. Review device ACL and IOCTL access bits.
2. Run static checks for user-controlled pointer/size flows.
3. Enable Driver Verifier in a lab.
4. Enable KMDF Verifier for KMDF drivers.
5. Exercise normal and boundary-case workflows.
6. Review crash dumps and verifier findings.
7. Fix contract violations before adding exploit mitigations.
8. Add regression tests for the violated invariant.
9. Re-check driver signing, HVCI compatibility, and WDAC policy.

Why:

```text
mitigations cannot compensate for a driver that exposes privileged operations
to the wrong caller with weak validation
```

## Reverse Engineering Workflow

For binary-only drivers:

```text
static import and string scan
  -> WDM/WDF dispatch map
  -> device ACL and reachability
  -> dangerous sink map
  -> crash/verifier lab signal if safe
  -> primitive classification
  -> detection/hardening note
```

Use verifier as evidence, not as the only proof.

## Common Mistakes

- Enabling verifier on production systems.
- Treating verifier crash as exploitability proof.
- Ignoring verifier because the exploit path "works" without it.
- Running only runtime tools and skipping device ACL review.
- Using outdated SDV assumptions without checking current WDK support.
- Forgetting KMDF Verifier for WDF drivers.

## Study Questions

1. Why does verifier help identify the broken invariant?
2. Why is a verifier crash not automatically an exploitable primitive?
3. What extra bugs can KMDF Verifier expose compared with generic Driver Verifier?
4. Why does SDV tooling status matter for modern workflows?
5. How would you map a verifier stop to a defensive code-review checklist?

## References

- Microsoft Learn, `Driver Verifier`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier
- Microsoft Learn, `Using KMDF Verifier`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/using-kmdf-verifier
- Microsoft Learn, `Static Driver Verifier Reference`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/static-driver-verifier-reference
- Microsoft Learn, `Determining if Static Driver Verifier supports your driver or library`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/determining-if-static-driver-verifier-supports-your-driver-or-library
- Microsoft Learn, `!verifier` WinDbg extension:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-verifier
- Existing repo note:
  `docs/debugging/crash-dump-driver-triage.md`


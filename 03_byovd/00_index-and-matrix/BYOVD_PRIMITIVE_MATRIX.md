# BYOVD Primitive Matrix

This file groups the researched drivers by primitive class and exploit engineering style.

## Summary Matrix

| Driver | Primitive class | Best-fit technique | Main stability problem | Main BSOD risk |
|---|---|---|---|---|
| `ASTRA64.sys` | Physical R/W + MSR read | VA->PA + direct token DKOM | CR3/offsets/mapping quirk | wrong physical write |
| `LnvMSRIO.sys` | Physical R/W + MSR R/W | physical R/W data-only; MSR read for KASLR | driver version/blocklist/VA->PA | MSR write or wrong PA |
| `ThrottleStop.sys` | Physical R/W via `MmMapIoSpace` | VA->PA or OS-assisted translation + data-only | translation strategy/offsets | wrong PA |
| `eneio64.sys` | Physical R/W + MSR + port I/O | VA->PA + data-only | old driver compatibility/offsets | wrong PA/MSR write |
| `pstrip64.sys` | Physical memory mapping | physical scan or VA->PA + DKOM | object discovery/driver compatibility | wrong PA |
| `RTCore64.sys` | Virtual kernel R/W | direct token/PPL data write | KASLR/object offsets | wrong kernel VA |
| `dbutil_2_3.sys` | Virtual write | direct data-only write | driver blocklist/offsets | wrong kernel VA |
| `gdrv.sys` | arbitrary write + MSR/physical paths | arbitrary write token DKOM | primitive constraints/offsets | wrong VA/MSR write |
| `AsIO3.sys` | decrement primitive + auth bypass | `PreviousMode` flip -> Nt* kernel R/W | Windows version/PreviousMode mitigations | failed restore/wrong decrement |
| `K7RKScan.sys` | process termination | kill protected/security process | driver version/access control | killing critical process |
| `BdApiUtil64.sys` | process termination | generic process-killer framework | driver protocol/blocklist | target selection/unload |
| `TfSysMon/SysMon.sys` | process termination | generic process-killer with structured PID buffer | buffer format/blocklist gap | target selection/unload |
| `zam64/zamguard64.sys` | process/security-tool control | Terminator-style EDR/AV kill | renamed driver/hash detection | critical process/security self-defense |
| `DsArk64.sys` | process kill + virtual R/W + KASLR leak | auth/protocol bypass -> direct virtual R/W | Authenticode bypass/AES/inter-driver auth | wrong kernel VA/DPC write |
| WinRing0/Awesome Miner | MSR read/write | `LSTAR` leak or syscall hijack proof | per-core/MSR state/mitigations | wrong MSR write |

## Primitive Classes

### Physical memory R/W

Examples:

- ASTRA64
- Lenovo
- ThrottleStop
- eneio64
- PowerStrip

Best for:

- data-only kernel object modification,
- page-table research,
- building virtual R/W through VA->PA.

Hard part:

- translating or discovering the right physical page.

Avoid unless needed:

- PTE patch,
- code patch,
- broad physical scanning writes.

### Virtual kernel R/W

Examples:

- RTCore64
- dbutil_2_3
- some DirectIO-style drivers

Best for:

- direct token swap,
- PPL/protection field tamper,
- selected object writes.

Hard part:

- kernel object address discovery,
- KASLR,
- offsets.

Advantage:

- no VA->PA bridge.

### Limited arithmetic/write primitive

Example:

- AsIO3 decrement primitive.

Best for:

- semantic field flips such as `PreviousMode`.

Hard part:

- finding a field where one decrement has privileged meaning.

Fragility:

- extremely version and field-layout sensitive.

### MSR read/write

Examples:

- WinRing0,
- Lenovo,
- eneio64,
- gdrv.

Best for:

- KASLR leak through `IA32_LSTAR`,
- syscall hijack research,
- DoS proof.

Hard part:

- stable code execution without crashing.

Recommendation:

- use MSR read as anchor,
- avoid MSR write for stable LPE if data-only alternatives exist.

### Process-kill primitive

Examples:

- K7RKScan,
- BdApiUtil,
- ThreatFire.
- Zemana.

Best for:

- EDR/AV kill,
- PPL process termination,
- ransomware pre-stage.

Hard part:

- target selection,
- persistence against restart,
- avoiding critical process crash.

Advantage:

- no kernel offsets,
- low BSOD risk compared with memory writes.

## Technique Selection Rules

1. If you have virtual R/W, prefer data-only object write.
2. If you have physical R/W, first build reliable VA->PA or object discovery.
3. If you only have MSR write, expect fragility; use it mainly for research/proof.
4. If you have process-kill, do not overcomplicate it into memory exploitation.
5. If you have a limited primitive, search for semantic one-bit/one-byte targets.
6. Avoid global kernel dispatch patching unless the primitive forces you there.
7. Prefer minimal reversible state changes.

## Reliability Ranking

From generally most operationally stable to least, assuming driver loads:

1. Process-kill IOCTL against non-critical target.
2. Virtual R/W token swap with validated offsets.
3. Physical R/W token swap with validated VA->PA.
4. Limited primitive to `PreviousMode`, on supported Windows build.
5. Callback/PPL tamper.
6. PTE/code patch.
7. MSR syscall hijack.

This ranking changes if the goal changes. For pure research, MSR hijack may be interesting. For reliable LPE, it is usually a last resort.

# Qihoo 360 DsArk64.sys Deep Dive

Sources:

- LOLDrivers issue #308: https://github.com/magicsword-io/LOLDrivers/issues/308

`DsArk64.sys` is a WHQL-signed anti-rootkit driver from Qihoo 360 Total Security. It is an important case because it combines several BYOVD classes in one driver:

```text
process kill
kernel virtual read
kernel virtual write
module enumeration / KASLR leak
custom auth gate
static crypto protocol
inter-driver authorization
```

This makes it more complex than simple process killers like K7/BdApiUtil and more convenient than physical R/W drivers like ASTRA.

## 1. Primitive Overview

Public issue #308 describes:

| Capability | Interface | Notes |
|---|---|---|
| Process kill | `0x80863008`, `0x80863080` | 4-byte PID, `ZwOpenProcess(PROCESS_ALL_ACCESS)` + `ZwTerminateProcess`, no encryption |
| Kernel read | `0x80863028`, subcmd 1 | `memcpy(buf, kernel_addr, size)`, max 512 bytes |
| Kernel write | `0x80863028`, subcmd 2 | MDL map + DPC broadcast `memcpy`, max 32 bytes |
| Module enum | `0x80863028`, subcmd 4 | `ZwQuerySystemInformation(SystemModuleInformation)` leak |
| Driver state dump | `0x80863028`, subcmd 7 | internal protection-list data |

The key distinction:

```text
DsArk gives kernel virtual R/W, not physical R/W
```

That means no VA->PA page-table bridge is needed once the R/W IOCTL is reachable.

## 2. Why This Is Stronger Operationally Than Physical R/W

Physical R/W drivers force the exploit to solve:

- CR3,
- page-table walk,
- physical mapping quirks,
- object discovery from physical pages.

DsArk's virtual R/W lets the exploit reason directly in kernel virtual addresses:

```text
read kernel VA
write kernel VA
```

This is often easier to weaponize.

Physical R/W may be stronger in theory, but virtual R/W is more convenient in practice.

## 3. Why It Is More Complicated Than RTCore/dbutil

DsArk adds gates:

- admin token requirement,
- custom Authenticode caller check,
- AES-128-CBC encrypted R/W protocol,
- MD5-wrapped payload,
- inter-driver auth against `360SelfProtection`.

So the primitive is convenient once reached, but reaching it is more complex.

Exploit engineering splits into two phases:

```text
1. access/protocol bypass
2. kernel R/W usage
```

## 4. Authenticode Caller Check

The driver checks the caller's image file and validates PE signature against Qihoo root certificates.

Public issue #308 says the bypass uses process hollowing:

```text
spawn Qihoo-signed executable suspended
inject code
call CreateFileW on DsArk device from that process
duplicate handle back
```

Why this bypass works conceptually:

- the driver validates the on-disk image identity of the current process,
- the process object still points to a Qihoo-signed image,
- code executing in that process is attacker-controlled,
- the driver grants access to the process, not to the actual code intent.

This is a classic identity-vs-control failure.

## 5. Why Process Hollowing Is Used

Alternative auth bypasses:

- patch driver,
- steal trusted service token,
- inject into running Qihoo service,
- abuse DLL search order,
- exploit broker.

Process hollowing/suspended injection is attractive because:

- it reuses a legitimate signed Qihoo binary,
- the donor executable never needs to run its own logic,
- driver sees a trusted image path/signature,
- handle can be duplicated back to the controller.

Defensive downside for attacker:

- process injection telemetry,
- suspended trusted installer process,
- duplicate handle behavior,
- unusual child/process tree.

## 6. Static AES Protocol

The R/W IOCTL is encrypted:

```text
AES-CBC encrypted([MD5(payload)] [payload])
```

Issue #308 reports static key and IV extracted from `.data`.

Why vendors do this:

- obfuscate IOCTL protocol,
- prevent casual callers,
- make reverse engineering slightly harder.

Why it is not real security:

- key is in the driver binary,
- IV is static,
- all builds share values according to the issue,
- attacker can reverse and reproduce protocol.

Security principle:

```text
client-side/static secret in shipped binary is not an authorization boundary
```

## 7. Kernel Read: Why 512 Bytes Is Enough

The read primitive is capped at 512 bytes.

That sounds small, but it is enough for:

- reading pointer fields,
- reading `_EPROCESS` chunks,
- walking linked lists,
- dumping token values,
- validating structure fields,
- reading callback pointers,
- reading module headers.

Kernel exploitation rarely needs huge reads if the goal is data-only mutation.

Small reads can be chained.

## 8. Kernel Write: Why 32 Bytes Is Enough

The write primitive is capped at 32 bytes.

That is enough for:

- `_EPROCESS.Token` 8-byte fast-ref,
- `PreviousMode` byte/field style targets,
- PPL protection bytes,
- callback pointer entries,
- flags,
- small function pointer/object field changes.

For stable LPE, an 8-byte token write is sufficient.

So size limits reduce blast radius but do not prevent exploitation.

## 9. MDL Map + DPC Broadcast Write

The issue describes the write as MDL mapping plus DPC broadcast `memcpy`.

Why a driver might do that:

- safely map target pages into a writable system address,
- synchronize across CPUs,
- perform write in a context the driver expects.

Why it matters to exploiters:

- the driver does the hard virtual memory access,
- the primitive may write reliably even where direct dereference would fault,
- broadcast/DPC behavior can make it more global and race-sensitive.

BSOD risk:

- wrong kernel VA can crash,
- writing protected/code pages can trigger integrity issues,
- cross-CPU broadcast raises complexity.

## 10. Module Enum as KASLR Leak

Subcmd 4 uses `ZwQuerySystemInformation(SystemModuleInformation)`.

Why this matters:

- gives `ntoskrnl` base,
- gives loaded driver bases,
- supports target address calculation,
- avoids separate kernel-base leak.

This makes DsArk more convenient than drivers that only provide write.

## 11. Process Kill Path

The raw process kill IOCTL needs only a 4-byte PID after device access.

Why this is operationally valuable:

- no AES protocol needed,
- no kernel offsets,
- kills PPL/security processes if driver permits,
- useful even if R/W inter-driver auth blocks memory operations.

This makes DsArk two tools in one:

```text
simple process killer
advanced kernel R/W driver
```

## 12. Why `MmIsAddressValid` Is Weak Validation

Issue #308 says R/W uses `MmIsAddressValid` only.

Problems:

- it is not a security boundary,
- validity can change after check,
- does not prove address belongs to safe range,
- does not enforce intended object class,
- does not validate page protections or target semantics.

Good validation would require:

- allowed address ranges,
- allowed object types,
- explicit command semantics,
- caller authorization,
- no raw arbitrary address at all.

## 13. Best-Fit Exploit Technique

If R/W is reachable:

```text
module enum -> nt base
read PsInitialSystemProcess
walk EPROCESS
read System token
write current token
restore if desired
```

This is easier than ASTRA because:

- no physical translation,
- read/write directly use kernel VA,
- module enum is included.

But harder at access layer because:

- auth bypass,
- AES protocol,
- inter-driver auth.

## 14. Stability Across Windows Versions

Stable:

- virtual R/W is convenient,
- 32-byte write enough for token,
- module enum leak useful.

Variable:

- `_EPROCESS` offsets,
- driver protocol builds,
- Qihoo auth behavior,
- inter-driver auth,
- blocklist status,
- Windows mitigations around target fields.

The driver protocol may be more stable than Windows internals, but both matter.

## 15. BSOD Risk Matrix

| Stage | Risk | Why |
|---|---|---|
| Auth bypass | Low-medium | Mostly access failure/injection telemetry. |
| AES protocol | Low | Bad packet rejected. |
| Module enum | Low | Intended query. |
| Kernel read bad VA | Medium | Driver may fault despite checks. |
| Kernel write bad VA | High | Corrupts or faults kernel memory. |
| Token write | Medium | Offset-sensitive but small. |
| Callback/code patch | High | PatchGuard/HVCI/EDR. |
| Process kill | Low-medium | Target choice risk. |

## 16. Why This Driver Is High Priority Defensively

It is dangerous because it combines:

- WHQL signature,
- not necessarily blocklisted at disclosure time,
- process kill,
- kernel read,
- kernel write,
- KASLR leak,
- bypassable auth,
- static crypto.

That is a very complete BYOVD capability set.

## 17. Defensive Detection

Hunt for:

- `DsArk64.sys` / `DsArk.sys`,
- `\Device\DsArk`,
- registry gate `HKLM\SYSTEM\CCS\Services\360FsFlt\daboot = 1`,
- suspended Qihoo-signed process followed by injection,
- handle duplication from Qihoo process to unknown controller,
- non-360 process using duplicated device handle,
- security process kill,
- SYSTEM token anomaly after driver load.

Controls:

- WDAC deny hashes,
- block vulnerable driver versions locally,
- monitor Qihoo installer binaries used outside install context,
- prevent unapproved 360 Total Security drivers on enterprise endpoints.

## 18. Final Takeaway

DsArk is a high-end BYOVD case:

```text
process killer + virtual kernel R/W + KASLR leak + bypassable auth
```

The primitive is easier to use than physical R/W, but the access layer is more complex. It is a good example of modern BYOVD where reverse engineering the protocol/auth is as important as kernel exploitation.


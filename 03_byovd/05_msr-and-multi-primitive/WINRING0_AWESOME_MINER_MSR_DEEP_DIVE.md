# WinRing0 / Awesome Miner CVE-2025-63602 MSR Deep Dive

Sources:

- DreadSec write-up: https://dreadsec.co/p/cve-2025-63602-hijacking-system-calls-with-a-popular-crypto-miner.html
- D7EAD PoC repo: https://github.com/D7EAD/CVE-2025-63602
- Vulmon summary: https://vulmon.com/vulnerabilitydetails?qid=CVE-2025-63602
- Microsoft WinRing0 vulnerable driver description: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=VulnerableDriver%3AWinNT%2FWinring0.B

This case is a WinRing0-style MSR primitive repackaged/renamed by a popular crypto-mining management tool.

Primitive class:

```text
MSR read/write available to insufficiently privileged callers
```

## 1. Why WinRing0 Keeps Appearing

WinRing0 is a low-level hardware access driver used by many monitoring, RGB, fan-control and benchmarking tools.

It is useful to legitimate apps because it provides:

- MSR access,
- port I/O,
- low-level hardware information,
- sometimes memory access patterns depending on variant.

It is useful to attackers for the same reason.

The recurring BYOVD pattern:

```text
trusted utility bundles WinRing0
WinRing0 exposes dangerous primitives
device ACL is weak
malware reuses driver
```

## 2. What Awesome Miner Changed

Public reporting describes Awesome Miner shipping a renamed WinRing0-derived driver:

```text
IntelliBreeze.Maintenance.Service.sys
```

The name changes, but the dangerous primitive remains.

This matters because filename-based detection fails. Defenders must identify:

- hash,
- code similarity,
- imports,
- device names,
- behavior,
- signer/product metadata.

## 3. Why MSR Access Is Dangerous

MSRs are CPU model-specific registers. Some control critical kernel execution paths.

Relevant example:

```text
IA32_LSTAR = syscall entry target in long mode
```

If attacker can read it:

- KASLR leak.

If attacker can write it:

- syscall redirection,
- kernel control-flow impact,
- crash/DoS,
- possible ring-0 execution chain.

## 4. Why MSR Read Is Low-Risk and Useful

MSR read is often the first step:

- leak `IA32_LSTAR`,
- derive `ntoskrnl` base,
- identify syscall entry,
- confirm primitive works.

It is low risk because it does not change system state.

For physical-memory drivers like ASTRA/Lenovo, MSR read is often used only as a KASLR anchor.

## 5. Why MSR Write Is High-Risk

MSR write changes CPU/kernel behavior.

Risks:

- invalid syscall entry -> immediate crash on next syscall,
- per-core state mismatch,
- wrong calling convention,
- SMEP/SMAP/NX issues if target is user address,
- kCFG/CET/control-flow assumptions,
- PatchGuard/integrity checks for persistent tamper.

MSR write is strong but unstable.

For stable LPE, data-only object modification is usually better if available. But WinRing0-style cases may not offer physical/virtual memory R/W; then MSR write becomes the main impact path.

## 6. Why Hijacking Syscalls Is Chosen in MSR-Only Cases

If the only primitive is MSR write, one obvious target is syscall entry.

Why:

- user mode can trigger `syscall` repeatedly,
- `IA32_LSTAR` controls where syscall enters kernel,
- changing it gives a transition into attacker-selected kernel path if the payload environment is prepared.

Why this is hard:

- target must be executable kernel memory,
- CPU state must match expected entry path,
- must restore original MSR,
- must handle multiple cores,
- bad pointer causes BSOD quickly.

This is a proof-heavy technique, not a comfortable general primitive.

## 7. Why This Is Less Stable Than Physical R/W

Physical R/W path:

```text
write one data field
```

MSR syscall hijack:

```text
change global CPU entry path
execute controlled path
restore correctly
avoid concurrent syscalls
handle mitigations
```

More moving parts means less stability.

MSR write is often used because it is what the driver exposes, not because it is the best possible primitive.

## 8. HVCI/SMEP/kCFG Interaction

MSR write does not automatically bypass:

- SMEP,
- SMAP,
- NX,
- kCFG,
- CET,
- HVCI.

If the target address is user memory, SMEP can block execution.

If the target is unsigned/writable kernel memory, HVCI can matter.

If indirect control-flow is used, kCFG/CET can matter.

Therefore, a serious chain needs a kernel-resident legitimate target or carefully prepared path.

## 9. Why This Case Is Mostly About Access Control

The core issue is that untrusted callers can reach MSR operations.

A safe design would:

- not expose arbitrary MSR access,
- restrict device ACL,
- broker operations through a trusted service,
- whitelist allowed MSRs,
- prevent writes to control-flow-sensitive MSRs,
- log privileged hardware operations.

WinRing0-style designs often expose raw hardware access because they were built for convenience, not modern threat models.

## 10. BSOD Risk Matrix

| Operation | Risk | Why |
|---|---|---|
| Open device | Low | Access fail if ACL fixed. |
| MSR read | Low | Read-only. |
| MSR write to harmless register | Medium | Hardware-dependent. |
| MSR write to `LSTAR` | High | Affects syscall entry. |
| Trigger syscall after bad write | Very high | Immediate bugcheck likely. |
| Restore MSR | Medium | Must restore on all relevant cores. |
| Code-exec chain | High | Mitigation/calling-convention issues. |

## 11. Stability Across Versions

Stable:

- MSR concept,
- `IA32_LSTAR` role on x64,
- WinRing0 family risk.

Variable:

- driver name/hash,
- device ACL,
- product bundling,
- Defender/blocklist behavior,
- HVCI policy,
- exploit payload assumptions,
- CPU/core behavior.

This class is stable as a risk category, but individual exploit chains are fragile.

## 12. Defensive View

Hunt for:

- WinRing0 variants,
- renamed WinRing0-derived drivers,
- Awesome Miner old versions,
- Defender `VulnerableDriver:WinNT/Winring0.*`,
- driver load from monitoring/mining/RGB tools,
- service creation for unfamiliar hardware helper,
- system crash after MSR-capable driver load.

Controls:

- remove unnecessary hardware monitoring drivers,
- WDAC deny WinRing0 hashes,
- keep vulnerable driver blocklist enabled,
- prefer vendor versions that removed/replaced WinRing0.

## 13. Final Takeaway

WinRing0/Awesome Miner is a pure reminder that:

```text
MSR write is powerful but not comfortable
```

It is excellent for proving kernel influence and KASLR leakage. It is less attractive than physical/virtual memory R/W for stable data-only LPE.

The defensive answer is not another memory mitigation. It is preventing unsafe hardware-access drivers from loading or being reachable.


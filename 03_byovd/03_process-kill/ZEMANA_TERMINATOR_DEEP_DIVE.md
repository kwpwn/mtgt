# Zemana zam64.sys / zamguard64.sys Terminator Deep Dive

Sources:

- VoidSec reverse engineering: https://voidsec.com/reverse-engineering-terminator-aka-zemana-antimalware-antilogger-driver/
- SC Media summary: https://www.scworld.com/brief/novel-terminator-antivirus-killer-found-to-be-a-byovd-attack
- SentinelOne CVE-2024-1853 summary: https://www.sentinelone.com/vulnerability-database/cve-2024-1853/
- LOLDrivers Zemana entry: https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/

Zemana drivers are associated with Terminator-style EDR/AV killer tooling. This is primarily a process/security-tool disabling class rather than a general physical R/W LPE class.

## 1. What Makes Zemana Operationally Important

Terminator-style tools reportedly:

- drop a legitimate signed Zemana driver,
- often rename it randomly,
- use it to terminate AV/EDR processes,
- sell the capability as an "AV killer".

This is the same process-killer category as K7/BdApiUtil/TfSysMon, but with substantial real-world criminal adoption.

## 2. Primitive Class

The practical primitive is:

```text
privileged process/security-product control through signed anti-malware driver
```

Some Zemana vulnerabilities also involve disk read/write or DoS IOCTLs depending on version/CVE, but Terminator coverage focuses on EDR/AV killing.

Important distinction:

- process-killer primitive is narrow,
- operational impact is high,
- no arbitrary kernel R/W is required for the main attack goal.

## 3. Why Security Product Drivers Are Attractive

Security drivers already need powerful capabilities:

- inspect processes,
- terminate malicious processes,
- filter file operations,
- monitor registry,
- protect services,
- bypass normal user-mode restrictions.

If old versions expose those capabilities to attackers, they become perfect anti-security tools.

The irony:

```text
driver built to stop malware becomes malware's EDR killer
```

## 4. Why Random Renaming Matters

Terminator-style tooling may rename the driver before dropping it.

Why:

- avoid filename detections,
- avoid simple block rules,
- make triage harder,
- blend with random service names.

Defensive implication:

- detect by hash/signature/behavior,
- not only filename.

Good identifiers:

- PE hash,
- certificate signer,
- device object,
- imports,
- service type,
- kernel image load,
- behavior after load.

## 5. Why Process-Kill BYOVD Is Enough

Ransomware/EDR-killer workflows need a short window:

```text
stop EDR
stop AV
stop backup/logging
deploy payload
encrypt/exfiltrate
```

They do not need:

- stable SYSTEM shell,
- arbitrary kernel write,
- rootkit persistence,
- sophisticated PTE manipulation.

That is why simple process-killer BYOVD remains common.

## 6. Why PPL Is Not Sufficient

PPL blocks normal user-mode tampering. It does not protect against every signed kernel driver.

If a Zemana driver exposes a terminate/control operation and does not enforce correct caller/target authorization, a user-mode attacker can make the driver act as a privileged deputy.

Same confused-deputy model:

```text
attacker process -> trusted Zemana driver -> terminate protected process
```

## 7. Why This Class Is Lower BSOD Than R/W Drivers

Compared to arbitrary write:

- no random kernel memory writes,
- no offsets,
- no KASLR,
- no page tables,
- no code patching.

Crash risk comes from:

- killing critical processes,
- buggy old driver behavior,
- unload issues,
- security product self-defense interactions.

So it is operationally reliable enough for commodity tooling.

## 8. CVE-2024-1853 Note

SentinelOne describes `zam64.sys` / `zamguard64.sys` DoS via IOCTL `0x80002048`.

This reinforces a broader point:

- the same driver family may contain multiple vulnerable operations,
- some are DoS,
- some are process/security control,
- some may be LPE in older versions.

BYOVD triage should catalog all exposed IOCTLs, not only the one used by a public tool.

## 9. Stability Across Versions

Stable:

- process-killer operational model,
- security-driver capability class,
- random rename evasion pattern.

Variable:

- exact IOCTLs,
- driver versions,
- device names,
- blocklist status,
- whether driver loads under HVCI,
- whether target security products detect/block it.

## 10. BSOD Risk Matrix

| Operation | Risk | Why |
|---|---|---|
| Load old Zemana driver | Low-medium | Driver/blocklist compatibility. |
| Open device | Low | Fails if ACL fixed. |
| Kill user process | Low | Intended operation. |
| Kill AV/EDR process | Medium | Self-defense/watchdog reaction. |
| Kill critical system process | High | System instability. |
| DoS IOCTL | Medium-high | Designed crash/bug trigger. |
| Driver unload | Medium | Old drivers may not unload cleanly. |

## 11. Defensive View

Hunt for:

- `zam64.sys`, `zamguard64.sys`,
- renamed Zemana driver hashes,
- random kernel service names with Zemana-signed image,
- driver load followed by AV/EDR process termination,
- creation in `System32\drivers` from unusual parent,
- Terminator/AuKill-like process tree.

Controls:

- WDAC deny known hashes,
- remove Zemana legacy drivers,
- block vulnerable driver loads,
- centralize driver load telemetry,
- alert on security process kill after driver load.

## 12. Final Takeaway

Zemana/Terminator is a reminder that BYOVD is not only about elegant kernel primitives.

The operationally valuable primitive can simply be:

```text
kill the defender
```

That is enough for many intrusion chains.


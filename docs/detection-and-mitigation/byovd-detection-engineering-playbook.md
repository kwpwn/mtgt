# BYOVD Detection Engineering Playbook

Backlinks: [README](../../README.md) | [topic index](../research-index/topic-index.md) | [learning path](../research-index/windows-kernel-pwn-learning-path.md) | [mitigation matrix](../research-index/mitigation-version-matrix.md) | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md)

## Purpose

Give defenders a practical, high-level playbook for detecting BYOVD activity without publishing bypass procedures.

## What You Will Learn

- Which telemetry sources matter for driver load and device abuse.
- How to map driver identity, path, signer, device object, and behavior.
- How to handle false positives from legitimate hardware software.

## Telemetry Map

| Layer | Signals |
|---|---|
| File system | Driver file creation, unusual path, alternate extension, temp/user-writable staging. |
| Registry | New or modified kernel service keys, `ImagePath`, `Type=1`, `Start`, rapid create/delete. |
| Code Integrity | Blocked/audited loads, signer validation, vulnerable driver blocklist hits. |
| Kernel image load | Driver image name, base, signer, hash, load time. |
| Device object | `\Device\...`, DOS symbolic link, SDDL/ACL, low-privileged access. |
| Process behavior | Process opening driver device and issuing repeated control requests. |
| Follow-on effects | Security service failure, PPL changes, token anomalies, crash/reboot, callback/list anomalies. |

## ETW and Event Sources

| Source | Use |
|---|---|
| Code Integrity operational logs | Confirm blocked or allowed driver loads. |
| Kernel image load telemetry | Establish driver inventory and rarity. |
| Sysmon driver load events | Collect hashes, signatures, and paths at endpoint scale. |
| MDE advanced hunting | Correlate driver load, service creation, process lineage, and device behavior. |
| EDR kernel sensor telemetry | Watch callback/object/process protection anomalies where available. |
| Crash dump and reliability data | Identify failed primitive probing. |

## Sysmon High-Level Mapping

| Event type | Defensive use |
|---|---|
| Driver loaded | Driver path, hash, signer baseline. |
| File create | Driver staging before load. |
| Registry set | Kernel service configuration. |
| Process create | Parent/child lineage for loader process. |
| Process access | Sensitive process access after driver load. |

## MDE Hunting Fields

Use available fields conceptually:

| Field family | Why |
|---|---|
| Device file events | Locate `.sys` staging and path anomalies. |
| Device registry events | Detect service creation and driver path changes. |
| Device image load events | Confirm kernel driver load and signer. |
| Device process events | Link loader process to driver staging. |
| Alert/evidence graph | Correlate security service tamper or credential access after load. |

## Behavioral Detections

| Behavior | Rationale |
|---|---|
| Rare signed driver loaded from user-writable path | Hardware drivers normally live in controlled paths. |
| Kernel service created and deleted within minutes | Short-lived BYOVD chain pattern. |
| Driver signer not seen in enterprise baseline | Prioritize unknown or uncommon vendors. |
| Blocked driver load followed by alternate driver load | Operator may be testing policy boundaries. |
| Security service termination near driver load | Possible kernel-level process-control abuse. |
| LSASS protection/read anomalies after driver load | Treat as high severity; do not reproduce dumping behavior. |
| System crash after IOCTL-heavy process | May indicate primitive probing. |

## False Positive Handling

| Scenario | Triage |
|---|---|
| OEM updater installs driver | Validate signer, path, update product, prevalence, and timing. |
| Hardware monitoring software | Check expected device names and vendor package. |
| Security product driver update | Confirm with vendor version and deployment system. |
| Developer/test signing lab | Isolate from production and label telemetry. |

## Incident Response Checklist

1. Preserve the driver file, signature metadata, service key, and loader process lineage.
2. Check Code Integrity and blocklist state.
3. Identify every process that opened the device object if telemetry exists.
4. Collect crash dumps or bugcheck history.
5. Hunt for follow-on privilege, protection, callback, and security service changes.
6. Quarantine affected hosts if sensitive process tamper or credential access is suspected.
7. Add driver hash, signer, certificate, path, and behavior to detection content.
8. Review WDAC/HVCI/Secure Boot/vulnerable driver blocklist posture.

## Questions to Ask Yourself

1. Did policy allow the driver, or did it fail open?
2. Is the signer common and expected in this environment?
3. Which user-mode process controlled the load?
4. Did a sensitive event happen after the driver became active?
5. Can this be prevented with WDAC allowlisting instead of only detected?

## Related Repo Docs

- [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md)
- [Mitigation and version matrix](../research-index/mitigation-version-matrix.md)
- [HVCI/VBS deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md)
- [Primitive reasoning framework](../kernel-research/primitive-reasoning-framework.md)
- [Case-study matrix](../research-index/case-study-matrix.md)

## References

- G3tSyst3m BYOVD/LSASS post, treated as unsafe/needs-review: https://g3tsyst3m.com/byovd/BYOVD-and-Looting-LSASS-in-the-Modern-EDR-Era/
- S12 driver loading post, treated as needs-review: https://medium.com/@s12deff/loading-kernel-drivers-in-memory-fc5d71c576e2
- GhostWolfLab BYOVD trend post: https://blog.ghostwolflab.com/apt/737/
- Quarkslab Lenovo BYOVD research: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html

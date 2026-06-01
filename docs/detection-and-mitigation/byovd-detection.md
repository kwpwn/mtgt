# BYOVD Detection

## Purpose

This document organizes defensive detection and mitigation thinking for BYOVD in one place. It focuses on driver inventory, load telemetry, device exposure, suspicious caller patterns, and incident-response workflow.

## Background

BYOVD is not one exploit. It is an operational pattern:

```text
load or access a signed but unsafe driver
  -> reach a privileged IOCTL or hardware primitive
  -> use the driver's semantics to weaken system protections
```

Because the signed driver is often legitimate software, purely signature-based trust is not enough.

## Core Concepts

### BYOVD threat model

The essential components are:

- a driver that can load or is already present,
- a reachable device object or other request path,
- a dangerous capability exposed to an untrusted caller,
- weak enough policy or telemetry that the action is not blocked early.

### Vulnerable driver inventory

A mature defense program needs an inventory view that includes:

- loaded drivers,
- drivers present on disk,
- signer and certificate metadata,
- known vulnerable-driver status,
- whether the driver is blocklisted,
- whether the environment actually needs the software.

### Driver load telemetry

Useful telemetry sources include:

- Sysmon Event ID 6 for driver load,
- Windows Event Log and Code Integrity events,
- EDR endpoint telemetry around image load, service creation, and kernel driver registration,
- incident-specific crash dumps and bugchecks.

### Code-signing metadata

Signing is necessary for kernel trust policy, but not sufficient for safety. Detection should preserve:

- signer,
- original filename,
- hash,
- path,
- certificate chain,
- timestamp,
- whether the driver is unexpectedly renamed or dropped into unusual directories.

### Driver blocklist

The Microsoft vulnerable driver blocklist is a critical control, but not a complete one:

- it is not guaranteed to cover every vulnerable driver,
- compatibility tradeoffs slow some entries,
- environmental drift means enforcement may differ across systems.

### Device object exposure

Even when a vulnerable driver loads, the decisive question may be:

```text
Can an unexpected user process actually open the device
and reach a dangerous control path?
```

This makes device ACLs and caller baselining important.

## Technical Deep Dive

### Suspicious `DeviceIoControl` patterns

The exact semantics of private IOCTLs are rarely visible in commodity telemetry, but defenders can still reason about suspicious patterns:

- a process that rarely talks to drivers begins opening many device handles,
- a productivity or scripting process opens a hardware utility driver,
- short-lived unsigned or unusual binaries interact with a newly loaded driver,
- one process both drops/loads a driver and rapidly opens its device object.

### Unusual user process opening driver handles

A strong heuristic is caller-role mismatch. Example categories that deserve scrutiny:

- scripting engines,
- macro hosts,
- document readers,
- web-exposed service workers,
- temporary unpackers,
- renamed binaries in user-writable paths.

The signal is stronger when the target device belongs to:

- overclocking tools,
- RGB or hardware monitoring tools,
- anti-cheat/security products,
- old OEM utilities,
- debugging or low-level system access software.

### Symbol-server access by unusual binaries

Symbol access is legitimate in developer and debugging contexts. It becomes more suspicious when:

- the binary has no normal diagnostic role,
- symbol cache artifacts appear on a non-development endpoint,
- the same process also interacts with kernel drivers or dumps unusual system metadata.

This is supporting context, not a standalone alert.

### Kernel crash artifacts

Not every BYOVD operation crashes the host, but unstable primitives often leave traces:

- bugchecks,
- verifier stops,
- Code Integrity logs,
- repeated service creation and load attempts,
- inconsistent post-crash driver presence.

Crash triage should preserve:

- loaded module list,
- recent driver installs,
- device-object exposure observations,
- process ancestry near the driver interaction.

### ETW, Sysmon, and Event Log ideas

Useful collection ideas:

| Signal | Why it matters |
|---|---|
| Sysmon Event ID 6 | Driver load with signature and image context |
| Code Integrity operational events | Blocklist and policy enforcement visibility |
| Service creation / start events | Many BYOVD paths stage drivers as services |
| File creation in driver-like paths | Disk staging before load |
| Device-handle opens by unusual processes | Reachability of the dangerous path |

### Sigma and YARA ideas at conceptual level

Avoid hardcoding one family only. Better concepts:

- first-time-seen driver load by host,
- known-vulnerable original filename with unexpected signer/path mismatch,
- unusual driver load from user-writable path,
- process opens handle to rare low-level device object,
- binary with symbol-resolution behavior plus kernel-driver interaction.

### Incident response checklist

- Identify the loaded or attempted driver.
- Capture signer, hash, original filename, path, service name, and device name.
- Check blocklist and policy state on the endpoint.
- Determine which process created, loaded, or opened the driver.
- Review whether the driver was already present or dropped during the incident.
- Assess whether the device object was broadly reachable.
- Review crash, verifier, or Code Integrity artifacts.
- Scope for the same driver hash or signer across the fleet.

## Windows Version Notes

- Windows 11 22H2 and later improved default posture through broader blocklist defaults, but coverage is still not universal.
- HVCI and Smart App Control can strengthen enforcement posture, yet they do not sanitize dangerous IOCTL semantics in drivers that are allowed to load.
- Older Windows installations and compatibility-heavy environments usually need more explicit policy work.

## Common Mistakes

- Trusting signer reputation alone.
- Treating the blocklist as complete coverage.
- Ignoring device-object reachability because driver load telemetry exists.
- Alerting only on unsigned drivers and missing signed unsafe ones.
- Treating all symbol-server use as malicious.

## Debugging / Inspection Notes

Useful sources during triage:

- Sysmon:
  Event ID 6 for driver load.
- Event Viewer:
  Code Integrity operational logs.
- WinDbg / kernel dump analysis:
  loaded modules, bugcheck context, object and device inspection.
- Fleet inventory:
  service entries, driver files, hashes, and signer metadata.

Detection checklist:

- Was a new or rare driver loaded?
- Is the signer expected in this environment?
- Was the driver blocklisted or should it have been?
- Which process opened the device or created the service?
- Is the device object unusually reachable?
- Are there nearby crashes or verifier artifacts?

## Defensive Angle

The best BYOVD defense is layered:

- reduce reachable vulnerable drivers,
- enforce current blocklists and App Control,
- baseline driver load and device-handle activity,
- inspect rare or first-seen drivers,
- treat signed low-level utility drivers as privileged attack surface, not neutral software.

## Lab-Safe Exercises

1. Build a local inventory table for drivers in a test VM: filename, signer, service name, device name, expectedness.
2. Review Sysmon Event ID 6 samples and note what fields help with driver provenance.
3. Compare one hardware utility driver and one ordinary inbox driver from a policy perspective: why should one receive stricter scrutiny?

## References / Further Reading

- Microsoft Learn, `Microsoft recommended driver block rules`:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Microsoft Learn, `Driver security checklist`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist
- Microsoft Learn, `Kernel-Mode Code Signing Requirements`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-
- Sysinternals Sysmon:
  https://learn.microsoft.com/en-ca/sysinternals/downloads/sysmon
- Elastic Security Labs, `Forget vulnerable drivers - Admin is all you need`:
  https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need
- Elastic detection guide, `First Time Seen Driver Loaded`:
  https://www.elastic.co/guide/en/security/8.19/first-time-seen-driver-loaded.html
- Existing repo note, `03_byovd/00_index-and-matrix/BYOVD_BLOCKLIST_AND_REACHABILITY.md`
- Anquanke, `REF4578: faxian xin de jia mi jie chi huo dong`:
  https://www.anquanke.com/post/id/296712

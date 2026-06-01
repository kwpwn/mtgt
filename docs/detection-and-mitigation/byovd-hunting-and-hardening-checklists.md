# BYOVD Hunting and Hardening Checklists

Updated: 2026-05-27

## Purpose

This document turns the BYOVD research notes into practical defensive checklists. It is designed for triage, hardening, and research lab validation.

It does not provide exploit steps. It focuses on:

- what to inventory,
- what to correlate,
- what to block,
- what inconsistencies to investigate.

## Checklist 1: Driver Inventory

Collect for every loaded and on-disk third-party driver:

```text
filename
full path
hash
signer
certificate chain
original filename
product name
version
service name
start type
device object
symbolic link
loaded status
blocklist status
business owner
```

Why:

```text
BYOVD begins when a signed driver is loadable or already loaded
```

## Checklist 2: Loadability

Ask:

- Is the driver Microsoft-signed, WHQL-signed, or vendor-signed?
- Is it blocked by Microsoft recommended driver block rules?
- Is it blocked by local WDAC?
- Is HVCI / Memory Integrity enabled?
- Is the driver compatible with HVCI?
- Is the driver already present on disk?
- Is it already loaded?
- Is Secure Boot enabled?
- Is test signing/debug mode enabled?

Decision:

```text
if driver cannot load, primitive is theoretical for that host
if driver can load, continue to reachability
```

## Checklist 3: Reachability

Ask:

- Does the driver create a device object?
- Does it create a symbolic link?
- Can non-vendor processes open it?
- Can low-privileged users open it?
- Is admin required?
- Does the vulnerable path require real hardware?
- Does the driver require PnP state?
- Does the IOCTL path require vendor service context?
- Is there auth, magic, license, or process-name checking?

Decision:

```text
loaded driver is not enough;
dangerous path must be reachable
```

## Checklist 4: Primitive Classification

Classify the strongest reachable primitive:

| Primitive | Priority |
|---|---|
| physical memory R/W or mapping | critical |
| virtual kernel R/W | critical |
| kernel memcpy-like operation | critical |
| MSR read/write | high |
| port I/O / PCI / MMIO | high |
| limited semantic write | medium-high |
| callback/security-state tamper | high but fragile |
| process termination only | separate process-kill track |
| crash only | lower unless high-value DoS |

Ask:

- read, write, or both?
- physical or virtual?
- fixed-size or arbitrary length?
- can it cross pages?
- is readback available?
- does it require hardware?

## Checklist 5: Driver Load Telemetry

Correlate:

- Sysmon Event ID 6,
- Windows Code Integrity events,
- service creation,
- file creation,
- signer/hash inventory,
- process ancestry of service creator,
- driver path,
- MDE/EDR driver load event if available.

Suspicious:

- driver loaded from temp/user-writable path,
- rare driver on endpoint,
- old hardware utility on server,
- signer not expected in environment,
- driver load shortly before telemetry gap or privilege change.

## Checklist 6: Device Interaction

Ask:

- Which process opened the device?
- Is the process the expected vendor controller?
- Was the process recently dropped or renamed?
- Is the process signed?
- Does the process also access symbols, kernel dumps, or system internals?
- Is there a burst of device I/O after load?

Detection idea:

```text
rare driver load
  + non-vendor controller process
  + device handle open
  + high-risk primitive family
```

## Checklist 7: Evasion Pressure

Investigate if driver load is followed by:

- EDR service state change,
- callback disappearance,
- minifilter unload or failure,
- Code Integrity anomaly,
- PPL/protection field anomaly,
- handle access to protected process,
- security process crash,
- telemetry volume drop,
- module inventory mismatch.

Do not treat "no telemetry" as clean. A telemetry gap can be the signal.

Related doc:

- `docs/detection-and-mitigation/driver-evasion-pressure-map.md`

## Checklist 8: Hardening

Controls:

- enable Microsoft vulnerable driver blocklist,
- enforce WDAC deny rules for known bad drivers,
- remove unused hardware/RGB/overclocking/mining utilities,
- prevent driver loading from user-writable paths,
- restrict admin rights,
- monitor service creation,
- baseline approved third-party drivers,
- document exceptions with business owner and expiry.

Policy rule:

```text
if a driver exposes physical memory, MSR, port I/O, or kernel R/W
and has no business owner,
block it
```

## Checklist 9: Incident Triage

Preserve:

- driver binary,
- hash,
- signature chain,
- service registry key,
- event logs,
- Code Integrity logs,
- Sysmon/EDR timeline,
- crash dumps,
- list of open handles if available,
- loaded module list,
- WDAC/blocklist policy state.

Timeline:

```text
file written
  -> service created
  -> driver loaded
  -> device opened
  -> primitive-related behavior
  -> privilege/evasion/crash outcome
```

## Checklist 10: Research Lab Note Quality

Every lab note should include:

- Windows build,
- HVCI state,
- Secure Boot state,
- driver hash,
- signer,
- blocklist state,
- device ACL,
- reachable IOCTL family,
- primitive class,
- failure mode,
- detection idea.

## Summary

Good BYOVD defense is a join problem:

```text
driver identity
  + loadability
  + reachability
  + primitive
  + caller behavior
  + post-load outcome
```

No single signal is enough.

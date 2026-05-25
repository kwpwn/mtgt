# Driver Load Telemetry, ETW, and Code Integrity

## Purpose

This document explains defensive visibility around driver loading, Code Integrity, vulnerable-driver risk, and BYOVD-style activity. It focuses on telemetry strategy and triage logic, not on exploit mechanics.

## Background

### Driver load path at a high level

Kernel driver loading is not just "a binary starts running." It involves:

- a service configuration or device-install path,
- image signature and policy checks,
- kernel loader participation,
- Code Integrity evaluation,
- runtime exposure of device objects and driver dispatch surfaces.

### Service Control Manager relationship

For many software drivers, Service Control Manager state is the administrative layer that precedes runtime load. A useful mental model is:

```text
service creation or configuration
  -> start attempt
  -> image signature and policy evaluation
  -> kernel module load
  -> device-object exposure if the driver initializes successfully
```

### Code signing and catalog signatures

Driver trust policy depends on valid signing chains and, in many cases, catalog-backed integrity. Signing proves policy eligibility to load. It does **not** prove that the driver's IOCTL semantics, device ACLs, or internal authorization logic are safe.

### Vulnerable driver blocklist

The blocklist is one of the strongest practical defenses against known BYOVD cases, but it is still only one layer:

- it lags newly discovered cases,
- it may depend on configuration and update state,
- it cannot reason about unknown unsafe drivers,
- it does not tell defenders which already-present drivers are over-privileged in design.

### Code Integrity and HVCI / Memory Integrity

Code Integrity checks signatures and image trust during driver load. HVCI strengthens runtime assumptions about kernel code integrity. Both matter operationally, but neither automatically makes a reachable signed driver safe.

## Telemetry Sources

### Windows Event Log

The Event Log provides operational context around:

- service activity,
- Code Integrity outcomes,
- some device and driver failures,
- boot or runtime load anomalies.

### Sysmon driver-load event concept

Sysmon Event ID 6 is a useful high-level source because it records driver load activity with image and signature context. For many environments, it is the easiest fleet-wide starting point for suspicious-driver visibility.

### ETW providers conceptually

ETW is important because it lets Microsoft components and security products emit structured events for:

- process activity,
- image load,
- Code Integrity,
- service and driver operations,
- kernel or driver framework behavior depending on instrumentation.

Defenders do not need every provider by default; they need a documented idea of which questions require which telemetry families.

### Code Integrity events

Microsoft documents that Code Integrity runs during driver loading and logs diagnostic events to the Code Integrity channels. These are especially useful for:

- failed loads,
- signature problems,
- unexpected unsigned-driver situations,
- policy-related compatibility debugging,
- verbose confirmation of image verification behavior when enabled.

### Defender for Endpoint-style telemetry conceptually

EDR platforms can enrich raw Windows telemetry with:

- reputation,
- rare-on-endpoint or rare-in-fleet scoring,
- signer context,
- device-handle ancestry,
- correlation with suspicious userland behavior.

The exact product fields differ, but the conceptual value is consistent.

### Kernel image-load callbacks and EDR visibility

Security software can also observe kernel activity through callback-style visibility at a high level. This does not expose every private IOCTL, but it can help join:

- driver load,
- device exposure,
- handle opens,
- subsequent crashes or verifier failures.

## Detection Ideas

- newly loaded kernel driver on an endpoint that rarely changes driver inventory,
- rare driver on the endpoint or in the fleet,
- unsigned or invalidly signed driver load attempt,
- old but signed driver whose hash, product, or filename is associated with known vulnerable cases,
- driver loaded from a user-writable or operationally strange path,
- service creation immediately followed by a driver load,
- user process opening a handle to an exposed device object that is normally touched only by vendor services,
- burst of `DeviceIoControl` activity to a rare device,
- unusual symbol-server access by a binary near suspicious driver activity,
- crashes or verifier events soon after device interaction,
- Memory Integrity / HVCI disabled where policy expects it enabled.

## Detection Matrix

| Signal | Source | Suspicion | False positives | Enrichment |
|---|---|---|---|---|
| New kernel driver load | Sysmon Event ID 6, EDR | Medium-high | Legitimate updates | signer, path, fleet prevalence, service creator |
| Rare driver on endpoint | EDR inventory, fleet analytics | Medium | Niche hardware software | device role, signer, version age |
| Invalid or unsigned load attempt | Code Integrity log | High | Test/lab systems | system role, debugger state, policy context |
| Old signed vulnerable-style driver | inventory plus blocklist intel | High | Legacy admin utilities | hash, version, device exposure, process ancestry |
| Driver from user-writable path | file + service + load telemetry | High | Mispackaged software | signer, parent process, creation time |
| Service creation before load | SCM + event logs + EDR | Medium-high | Legitimate installer behavior | actor process, command line, path, timing |
| User process opens rare device object | handle/EDR telemetry where available | High | Vendor GUI tools | process role, signature, parent lineage |
| Burst of `DeviceIoControl` to rare driver | API telemetry / EDR / custom sensors | High | Vendor diagnostics | process role, device baseline, crash correlation |
| Symbol access near driver activity | network + process telemetry | Medium | Debugging tools | binary role, symbol cache path, subsequent driver interaction |
| Crash after IOCTL activity | crash dumps, WER, EDR | Medium-high | Bad software quality | dump analysis, driver hash, repro clustering |
| Memory Integrity disabled | policy / security settings | Medium | Compatibility exceptions | driver inventory, exception owner, timing |

## BYOVD Defensive Playbook

1. Inventory kernel drivers on disk and in memory.
2. Verify signatures and signer chains.
3. Compare inventory against blocklists and local allow/deny policy.
4. Check the load path and storage location.
5. Check service creation time and responsible process.
6. Inspect device objects and user-visible links.
7. Inspect which userland processes are communicating with the driver.
8. Collect crash dumps, verifier output, or Code Integrity events if any.
9. Isolate the endpoint if the driver appears malicious or actively abused.
10. Preserve hashes, signer metadata, service config, and the certificate chain.

## YARA / Sigma Notes

Use conceptual field logic rather than ready-made high-noise packages:

- match on unusual kernel driver load plus weak path hygiene,
- enrich on signer plus original filename plus hash reputation,
- correlate service creation with subsequent device interaction,
- baseline rare hardware utility drivers separately from common inbox drivers.

For YARA-like thinking:

- original filename,
- vendor strings,
- certificate subject,
- known product metadata,
- device names and service names.

For Sigma-like thinking:

- event source,
- image path,
- signed state,
- signer,
- service name,
- rare-process ancestry,
- temporal correlation with driver IOCTL activity or crashes.

## Common Mistakes

- Treating signature validity as proof of safety.
- Looking only at driver load and ignoring device-object reachability.
- Over-alerting on all symbol-server usage without role context.
- Ignoring legacy drivers already present on endpoints because they are "normal there."
- Treating the vulnerable-driver blocklist as complete ecosystem coverage.

## Research Notes

- Driver load telemetry is most useful when joined with object exposure and caller identity.
- BYOVD risk lives in the gap between "trusted enough to load" and "safe enough to expose."
- Code Integrity logs are often underused in triage because teams focus on endpoint alerts but do not preserve the OS-native signing diagnostics.

## Lab-Safe Exercises

1. In a lab VM, review Sysmon Event ID 6 samples and write down which fields you would use for fleet baselining.
2. Open the Code Integrity operational log on a test machine and map its categories to driver-load troubleshooting questions.
3. Build a triage worksheet for one harmless vendor driver: signer, path, service name, device name, expected userland process, and whether HVCI compatibility is documented.

## References / Further Reading

- Microsoft Learn, `Code Integrity Event Log Messages`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/code-integrity-event-log-messages
- Microsoft Learn, `Detecting Driver Load Errors`:
  https://learn.microsoft.com/et-ee/windows-hardware/drivers/install/detecting-driver-load-errors
- Microsoft Learn, `Troubleshooting Driver Signing Installation`:
  https://learn.microsoft.com/th-th/windows-hardware/drivers/install/troubleshooting-driver-signing-installation
- Sysinternals, `Sysmon`:
  https://learn.microsoft.com/en-ca/sysinternals/downloads/sysmon
- Microsoft Learn, `Microsoft recommended driver block rules`:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Microsoft Learn, `Enable memory integrity`:
  https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft Security Blog, `Improve kernel security with the new Microsoft Vulnerable and Malicious Driver Reporting Center`:
  https://www.microsoft.com/en-us/security/blog/2021/12/08/improve-kernel-security-with-the-new-microsoft-vulnerable-and-malicious-driver-reporting-center/
- Existing repo note, [byovd-detection.md](E:\Windows-kernel-exploit-research-resource\docs\detection-and-mitigation\byovd-detection.md)

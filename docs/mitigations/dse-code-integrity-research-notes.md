# DSE, Code Integrity, and Driver Trust Research Notes

## Purpose

This document explains Driver Signature Enforcement, kernel-mode Code Integrity, and related policy surfaces from a Windows kernel research and defense perspective. It intentionally avoids operational DSE bypass instructions or code.

## Core Model

Driver trust has multiple layers:

```text
driver package or service configuration
  -> signature and catalog verification
  -> Code Integrity policy decision
  -> optional HVCI / Memory Integrity enforcement
  -> optional WDAC / vulnerable-driver block rules
  -> runtime driver behavior and IOCTL exposure
```

Driver Signature Enforcement answers a narrow question:

```text
Is this kernel-mode image allowed to load under current signing policy?
```

It does not answer:

```text
Are the driver's IOCTLs safe?
Are device ACLs correct?
Can the driver write physical memory, MSRs, kernel virtual memory, or process state?
Is an old signed version still dangerous?
```

That gap is why BYOVD remains relevant.

## Terminology

| Term | Meaning | Research importance |
|---|---|---|
| DSE | Driver Signature Enforcement policy for kernel-mode driver loading | Stops unsigned or improperly signed kernel code in normal configurations |
| Code Integrity | Windows component that verifies image integrity and signing state | Produces driver signing decisions and diagnostic events |
| KMCS | Kernel-mode code signing requirements | Defines signing expectations by Windows version and driver type |
| HVCI / Memory Integrity | VBS-backed enforcement that protects kernel code integrity assumptions | Raises cost of code patching and unsigned code execution |
| WDAC | Windows Defender Application Control | Allows enterprise policy to allow, deny, or constrain drivers |
| Vulnerable driver blocklist | Microsoft-maintained rules for known abused vulnerable drivers | Blocks some signed-but-unsafe drivers before runtime exposure |

## Why DSE Bypass Is a Poor Modern Research Goal

Historical DSE bypass research often centered on toggling Code Integrity state, patching global data, abusing boot/debug policy, or using a signed vulnerable driver to alter trust decisions. On modern systems this is brittle and noisy:

- HVCI and VBS move parts of code-integrity trust into a stronger boundary.
- KDP and secure-kernel policy can protect sensitive data.
- PatchGuard can detect long-lived kernel tampering.
- WDAC and the vulnerable-driver blocklist can prevent the helper driver from loading.
- EDR products correlate service creation, driver load, Code Integrity anomalies, and crash evidence.
- Build-specific symbols and structure layouts drift over time.

For research quality, treat DSE/CI tamper as a mitigation-pressure topic, not as the default route to impact.

## Modern Analysis Questions

When studying a driver or a public writeup, record:

- Did impact require unsigned code to load, or was a signed driver enough?
- Was Code Integrity bypassed, or was Code Integrity irrelevant because the driver was already trusted?
- Did the action modify code, mutable kernel data, policy state, or driver-controlled semantics?
- Would HVCI change the viability of the technique?
- Would WDAC or the Microsoft vulnerable driver blocklist stop the helper driver?
- Are Code Integrity operational or verbose events expected?
- Would the behavior create service-control, driver-load, or crash telemetry?

## Research-Safe DSE/CI Taxonomy

| Category | Description | Stability | Defensive focus |
|---|---|---|---|
| Unsigned driver load attempt | Driver fails normal signing policy | Low on protected systems | Code Integrity events, service creation, failed load telemetry |
| Signed vulnerable driver | Driver passes signing policy but exposes unsafe functionality | High when not blocked | Blocklist, WDAC, inventory, reachability, IOCTL detection |
| CI policy tamper | Attempts to alter Code Integrity decision state | Low to medium, build-sensitive | HVCI, KDP, PatchGuard, CI logs, crash artifacts |
| Kernel code patching | Attempts to change executable kernel code | Low under HVCI | HVCI, PatchGuard, memory protection telemetry |
| Data-only impact | Uses signed driver semantics to alter mutable data or object state | Often more realistic | Object integrity, least-privilege device ACLs, detection correlation |

## Relationship to BYOVD

BYOVD is not primarily "bypass DSE." In many cases the driver is already signed, so DSE succeeds. The relevant failure is that trust policy allowed a driver whose runtime semantics are unsafe.

Good BYOVD analysis separates:

- loadability: can the driver load?
- reachability: can an unexpected caller reach the vulnerable path?
- usefulness: does the primitive matter?
- mitigation resistance: does the primitive still work under HVCI, WDAC, KDP, PatchGuard, and blocklist policy?
- detectability: what telemetry appears before, during, and after the action?

## Detection and Triage

Useful defensive signals:

- Code Integrity operational warnings for driver signing failures.
- Code Integrity verbose events in lab or diagnostic modes.
- Sysmon Event ID 6 or EDR driver-load events.
- Service creation followed by driver load.
- Driver image path in user-writable or unusual directories.
- Validly signed but rare or legacy driver versions.
- HVCI or Memory Integrity disabled where expected.
- Driver load followed by unusual device handle opens.
- Crash, verifier, or bugcheck evidence after IOCTL activity.

Triage worksheet:

| Question | Why it matters |
|---|---|
| Is the driver signed, and by whom? | Establishes trust path and signer reputation |
| Is the driver in the Microsoft vulnerable driver blocklist or LOLDrivers? | Checks known-risk status |
| Is the driver expected on this host role? | Reduces false positives |
| Which process created or started the service? | Connects load to actor behavior |
| Which process opened the device object? | Establishes reachability |
| Did Code Integrity log a failure or diagnostic event? | Explains policy friction |
| Was HVCI enabled? | Changes viability of code-patching style techniques |

## Common Mistakes

- Treating signature validity as a safety guarantee.
- Treating DSE bypass as necessary for all kernel impact.
- Ignoring WDAC and blocklist state.
- Writing fixed offsets into notes without build context.
- Equating "driver loads" with "vulnerable path is reachable."
- Ignoring Code Integrity logs because EDR already alerted.

## Lab-Safe Exercises

1. Compare a Microsoft inbox driver, a vendor utility driver, and a blocked vulnerable-driver sample by metadata only: signer, timestamp, service name, path, and expected host role.
2. Build a worksheet that joins driver-load telemetry, Code Integrity events, service-control activity, and device-object access.
3. Review an existing BYOVD writeup and classify whether the trust failure is signing policy, blocklist gap, unsafe IOCTL semantics, or device ACL exposure.

## References

- Microsoft Learn, Driver signing:
  https://learn.microsoft.com/windows-hardware/drivers/install/driver-signing
- Microsoft Learn, Kernel-Mode Code Signing Requirements:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-
- Microsoft Learn, Code Integrity Event Log Messages:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/code-integrity-event-log-messages
- Microsoft Learn, Code Integrity Event Logging and System Auditing:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/install/enabling-code-integrity-event-logging-and-system-auditing
- Microsoft Learn, Microsoft recommended driver block rules:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Existing repo note, `02_mitigations-vbs-hvci-vtrp/RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`
- Existing repo note, `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`

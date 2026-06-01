# Driver-Based Evasion Pressure Map

Updated: 2026-05-27

## Purpose

This document maps driver-based evasion pressure from a defensive research perspective. It also links adjacent AV/EDR user-mode tamper cases when they create the same kind of visibility or health-state contradiction. It explains what kinds of primitives can weaken visibility or protection, why those approaches are fragile, and what defenders can correlate.

It does not provide bypass payloads, rootkit code, trigger buffers, or operational evasion steps.

Core model:

```text
driver primitive
  -> security invariant weakened
  -> one telemetry/protection view changes
  -> other views still expose contradiction
```

Adjacent user-mode product tamper follows the same reasoning shape without a
kernel primitive:

```text
product state or update surface
  -> health/reporting invariant weakened
  -> local view diverges from service, file, or backend reality
```

## Evasion vs Detection Language

This repository uses "evasion" to mean:

```text
an attacker tries to reduce what defenders can see or enforce
```

The documentation goal is:

```text
identify the invariant, the side effects, and the detection joins
```

## Quick Map

| Evasion pressure | Enabling primitive | What changes | Defensive join |
|---|---|---|---|
| vulnerable driver load | signed vulnerable driver | attacker gains kernel broker | CI, Sysmon, service, WDAC |
| callback state tamper | arbitrary write | event visibility weakens | callback inventory vs service state |
| minifilter disruption | privileged driver action or state tamper | file visibility weakens | filter stack vs product state |
| PPL/protection tamper | data-only write | protected process boundary changes | process protection vs lineage |
| handle access tamper | object state or callback tamper | access monitoring weakens | handle events vs object callbacks |
| driver/module hiding | DKOM/HKOM | inventory view changes | module list vs driver/device objects |
| ETW/telemetry gap | callback/provider/session state pressure | timeline has holes | ETW health vs endpoint behavior |
| AV/EDR state spoofing | registry/config/update-file pressure | product status diverges from real sensor/update health | local state vs service, file, backend, and event consistency |
| blocklist gap abuse | loadable signed driver | policy permits known-risk component | driver inventory vs LOLDrivers/WDAC |
| hardware/firmware path | MSR/MMIO/firmware primitive | below-OS state changes | firmware/device telemetry vs driver load |

## 1. Vulnerable Driver Load as Evasion Setup

### What It Is

The first evasion pressure point is often just loading a driver that should not be present.

```text
signed vulnerable driver
  -> Code Integrity accepts or policy misses it
  -> attacker gets privileged helper
```

### Why It Works

Driver Signature Enforcement validates signing policy. It does not prove IOCTL behavior is safe.

### Defensive Join

Correlate:

- service creation,
- driver file creation,
- driver load event,
- signer/hash,
- user-mode controller process,
- vulnerable-driver catalog status,
- WDAC/blocklist state.

Sources:

- Microsoft recommended driver block rules:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Driver security checklist:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist

## 2. Callback State Tamper

### What It Is

Security products often register callbacks for process, thread, image, registry, object, and file activity.

Pressure pattern:

```text
kernel write primitive
  -> callback registration state changes
  -> product sees less
```

### Why It Is Fragile

- PatchGuard may monitor sensitive structures.
- EDR may self-check.
- callback pointers must remain valid.
- removing one callback rarely removes all visibility.
- telemetry gap itself is suspicious.

### Defensive Join

Compare:

- security service running,
- expected callbacks present,
- callback pointers inside valid module ranges,
- vulnerable driver load immediately before callback change,
- event volume before/after.

Related docs:

- `docs/kernel-research/callback-surfaces.md`
- `03_byovd/00_index-and-matrix/BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`

## 3. Minifilter Disruption

### What It Is

Minifilters are a major file-system visibility surface for EDR and DLP products.

Pressure pattern:

```text
file/security product uses minifilter
  -> filter state unload/tamper/failure
  -> file visibility weakens
```

### Why It Is Fragile

Filter Manager has ordering, altitude, registration, and unload semantics. Products may also have service watchdogs.

### Defensive Join

Compare:

- expected filter loaded,
- product service state,
- filter altitude inventory,
- driver-load telemetry before disruption,
- file activity volume before/after,
- crashes involving minifilter callbacks.

Related doc:

- `docs/detection-and-mitigation/minifilter-and-edr-visibility.md`

## 4. PPL and Process Protection Tamper

### What It Is

Data-only writes can target process protection or signature-related fields.

Pressure pattern:

```text
kernel object write
  -> process protection semantics change
  -> access that should fail may succeed
```

### Why It Works

Windows consults process security state during access decisions. If that state changes, later legitimate checks may produce different outcomes.

### Why It Is Detectable

Process protection state should match:

- process lineage,
- signer,
- service role,
- image path,
- product expectations.

### Defensive Join

Look for:

- vulnerable R/W driver load,
- protection/signature field anomaly,
- handle opens that were previously denied,
- LSASS/security process access changes,
- EDR self-protection state mismatch.

## 5. Handle and Object Callback Pressure

### What It Is

Security products can observe or constrain handle creation through object callbacks.

Pressure pattern:

```text
object callback state changes
  -> handle monitoring/protection weakens
```

### Why It Is Fragile

Handle activity can still be visible through other telemetry:

- process events,
- API monitoring,
- kernel object state,
- historical EDR timeline,
- memory forensics.

### Defensive Join

Compare:

- expected object callbacks,
- handle opens to sensitive processes,
- callback pointer module ownership,
- product service health,
- vulnerable driver load timing.

## 6. Driver / Module Hide Pressure

### What It Is

A driver may be hidden from one inventory view by corrupting module/list state.

Pressure pattern:

```text
module list says absent
driver object / device object / code memory says present
```

### Defensive Join

Compare:

- loaded module list,
- executable kernel memory ranges,
- `DRIVER_OBJECT`,
- `DEVICE_OBJECT`,
- dispatch routine addresses,
- service registry,
- Code Integrity history.

Related docs:

- `docs/kernel-research/hkom-driver-module-hide-crossview.md`
- `docs/kernel-research/hkom-dkom-hide-research-notes.md`

## 7. ETW and Telemetry Gap Pressure

### What It Is

Telemetry may weaken because callbacks, providers, consumers, sessions, or product state are disrupted.

Pressure pattern:

```text
security events expected
  -> event volume drops
  -> endpoint behavior continues
```

### Defensive Join

Compare:

- ETW session health,
- product service health,
- event volume,
- driver-load events,
- process/file/network behavior,
- crash or restart telemetry.

Related docs:

- `docs/detection-and-mitigation/etw-threat-intelligence-notes.md`
- `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`

## 8. AV/EDR User-Mode State Spoofing

### What It Is

Some AV/EDR tamper research does not use a vulnerable driver at all. It pressures
user-mode product state, registry-backed status, update metadata, service
lifecycle windows, or product files.

Pressure pattern:

```text
local product state says healthy
  + update/signature/sensor reality is impaired
  -> console or UI may briefly disagree with endpoint reality
```

### Why It Is Different From BYOVD

There is no kernel primitive. The technique depends on product-specific trust
decisions:

- which registry/config fields are treated as authoritative,
- which file locks or update races are honored,
- whether the backend trusts local state,
- whether self-protection repairs or blocks the change.

### Example: SNEK Equinox

SNEK Equinox is classified as user-mode Defender state spoofing and signature
file-lock interference, not as BYOVD. It writes Defender health/version-looking
registry values and keeps file locks on selected definition/update files so the
reported state can diverge from actual signature/update behavior.

Related doc:

- `docs/detection-and-mitigation/av-self-protection-research-index.md`
- `docs/detection-and-mitigation/av-edr-user-mode-tamper-spoofing.md`

## 9. Blocklist Gap and Signed-Driver Masquerade

### What It Is

Attackers may use a signed driver that is not yet blocked, an older vulnerable version, or a renamed copy of a known component.

Pressure pattern:

```text
signed driver
  -> accepted by load policy
  -> unsafe IOCTL still reachable
```

### Defensive Join

Do not rely only on filename. Join:

- hash,
- signer,
- version,
- original filename,
- import/function behavior,
- device name,
- service name,
- LOLDrivers/Microsoft blocklist status,
- fleet prevalence.

## 10. Hardware and Firmware Evasion Pressure

### What It Is

Hardware primitives can affect state below normal OS telemetry:

- MSR,
- port I/O,
- PCI config,
- MMIO,
- firmware update paths.

### Why It Matters

Below-OS state may persist or influence the OS without looking like normal process behavior.

### Defensive Join

Correlate:

- hardware utility driver load,
- firmware update tooling,
- BIOS/UEFI event logs if available,
- device health changes,
- platform security settings,
- endpoint crash or device failure.

Related doc:

- `03_byovd/00_index-and-matrix/BYOVD_MSR_PORT_MMIO_HARDWARE_PRIMITIVES.md`

## Detection Strategy

High-signal patterns:

```text
rare driver load
  + non-vendor controller
  + device open
  + security state change
```

```text
security product running
  + expected callback/filter missing
  + vulnerable driver recently loaded
```

```text
driver load accepted
  + driver appears in LOLDrivers or local denylist
  + endpoint role does not justify hardware utility
```

## Hardening Strategy

Priorities:

1. WDAC deny rules for known vulnerable drivers.
2. Keep Microsoft vulnerable driver blocklist enabled.
3. Remove unnecessary hardware/RGB/overclocking/mining tools.
4. Inventory loaded and on-disk drivers.
5. Monitor service creation and driver load.
6. Baseline expected callbacks/minifilters for security products.
7. Correlate telemetry gaps instead of treating "no event" as clean.

## Study Questions

- What visibility or enforcement surface is being pressured?
- Which primitive enables that pressure?
- Which other view should still show the object or event?
- Did a vulnerable driver load before the visibility change?
- Is the driver expected for this endpoint role?
- Which policy would have blocked the setup stage?

## References

- Microsoft recommended driver block rules:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Device security in Windows Security app:
  https://support.microsoft.com/en-us/windows/device-security-in-the-windows-security-app-afa11526-de57-b1c5-599f-3a4c6a61c5e2
- Driver security checklist:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist
- Driver load telemetry repo note:
  `docs/detection-and-mitigation/driver-load-etw-and-code-integrity.md`

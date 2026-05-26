# BYOVD Case Study: `LnvMSRIO.sys`

Updated: 2026-05-27

## Technique Summary

`LnvMSRIO.sys` is a Lenovo driver discussed in CVE-2025-8061 research. It is useful as a modern BYOVD teaching case because it exposes both physical memory and MSR-style privileged operations in affected versions.

```text
signed OEM driver
  -> exposed device interface
  -> physical memory + MSR primitives
  -> Ring-0 capability if mitigation/config allows
```

## Sources

- Quarkslab write-up:
  https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- NVD CVE-2025-8061:
  https://nvd.nist.gov/vuln/detail/CVE-2025-8061
- Microsoft driver block rules:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

## Primitive

Primitive classes:

- physical memory read/write,
- MSR read/write,
- access-control weakness around IOCTL exposure in affected versions.

Quarkslab describes the target as a Lenovo driver and notes affected version context, including fixed versions. The write-up also highlights security configuration nuance around Core Protection / HVCI.

NVD classifies CVE-2025-8061 as an exposed IOCTL with insufficient access control and notes Memory Integrity conditions for impact.

## Why It Works

The driver exists to expose low-level MSR and physical memory functionality to Lenovo software.

Intended model:

```text
Lenovo management component
  -> Lenovo MSR/IO driver
  -> controlled privileged operation
```

Broken model:

```text
unexpected caller
  -> driver device
  -> privileged physical/MSR operation
```

The invariant failure:

```text
privileged hardware operation is reachable without sufficient caller authorization
```

## What It Can Do

Physical primitive:

- read or write physical RAM,
- become kernel object access after VA-to-PA translation,
- support data-only object modification.

MSR primitive:

- read `LSTAR`-style syscall-entry anchors,
- support kernel-base discovery,
- support fragile control-flow experiments if writing MSRs.

## Technique Path

### Path A: MSR read as layout anchor

```text
read syscall-entry MSR
  -> obtain pointer inside ntoskrnl
  -> locate kernel base
```

Why:

```text
kernel base is needed before many object/global symbol paths become meaningful
```

### Path B: physical memory bridge

```text
physical R/W
  -> translate virtual target to physical page
  -> modify object data
```

Why:

```text
physical memory access is powerful only after target discovery
```

### Path C: avoid MSR write when possible

MSR write is dramatic but fragile. If the goal can be achieved by data-only object modification, that is usually a more stable research route.

## HVCI / Core Isolation Nuance

Do not generalize from one driver.

For `LnvMSRIO.sys`, public CVE descriptions and Quarkslab's write-up emphasize configuration and HVCI/Core Protection differences. That means documentation should record:

- driver version,
- Windows build,
- HVCI / Memory Integrity state,
- vulnerable driver blocklist state,
- whether the vulnerable driver loads at all.

## Failure Modes

- fixed Lenovo version,
- HVCI/Core Isolation prevents the relevant path,
- vulnerable driver blocklist or WDAC blocks load,
- wrong physical translation,
- MSR write crashes,
- assuming Quarkslab's lab config matches enterprise endpoints.

## Detection Ideas

Hunt for:

- `LnvMSRIO.sys` versions below fixed builds,
- Lenovo driver loads on non-Lenovo or unexpected hosts,
- service creation from temp/user path,
- non-Lenovo process opening the device,
- driver load followed by kernel crash or privilege anomaly,
- endpoints with Memory Integrity disabled where policy expects it enabled.

## Study Questions

- What does NVD mean by exposed IOCTL with insufficient access control?
- Why does HVCI matter for this driver specifically?
- What does MSR read give that physical memory read does not?
- Why is physical memory write not enough until target page is known?
- Which facts must be recorded before comparing two LnvMSRIO write-ups?

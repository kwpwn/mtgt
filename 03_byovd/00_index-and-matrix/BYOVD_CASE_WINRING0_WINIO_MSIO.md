# BYOVD Case Study: WinRing0 / WinIo / MsIo Family

Updated: 2026-05-27

## Technique Summary

WinRing0, WinIo, and MsIo-style drivers represent a reusable low-level hardware access family. They appear across monitoring, RGB, gaming, overclocking, fan-control, and diagnostics products.

```text
shared low-level driver library
  -> reused by many products
  -> exposes MSR / port I/O / physical memory access
  -> product name changes but primitive family remains
```

This family is important because defenders cannot rely on one filename or one vendor product.

## Sources

- Microsoft Defender WinRing0 alert:
  https://support.microsoft.com/en-us/windows/microsoft-defender-antivirus-alert-vulnerabledriver-winnt-winring0-eb057830-d77b-41a2-9a34-015a5d203c42
- LOLDrivers WinIo64 entry:
  https://www.loldrivers.io/drivers/96501e5b-e4f2-41a9-a8ee-d09e36d31a39/
- LOLDrivers MsIo entry:
  https://www.loldrivers.io/drivers/4e5064b4-48d3-418c-a7a8-f0dc7ac0a176/
- Eclypsium Screwed Drivers:
  https://eclypsium.com/blog/screwed-drivers-signed-sealed-delivered/

## Primitive

Primitive classes:

- MSR read/write,
- I/O port access,
- physical memory mapping or access depending driver,
- generic hardware access.

Microsoft documents Defender alerts for WinRing0 and notes the driver is classified as a known vulnerability under CVE-2020-14979. Microsoft also lists many affected application categories, including hardware monitoring and gaming/tuning tools.

## Why It Works

These libraries were designed to make low-level hardware access easy for user-mode tools.

Intended model:

```text
hardware monitor or tuning app
  -> shared helper driver
  -> read sensors / ports / CPU state
```

Broken model:

```text
unexpected caller
  -> same helper driver
  -> direct privileged hardware or memory operation
```

The invariant failure:

```text
a generic hardware helper is treated like a safe product-specific interface
```

## What It Can Do

Depending on variant:

- read MSRs for kernel address anchors,
- write MSRs in fragile lab proofs,
- read/write port I/O,
- map physical memory,
- touch platform hardware,
- crash or destabilize host,
- support further kernel object manipulation if memory access is available.

## Why Filename Detection Fails

The same lineage can appear as:

- original driver filename,
- renamed vendor helper,
- product-specific wrapper,
- bundled copy in RGB/fan/mining/gaming software.

Detection should consider:

- hash,
- signer,
- version metadata,
- import/function behavior,
- device names,
- product lineage,
- vulnerable-driver blocklist state.

## Technique Path

### MSR path

```text
read LSTAR
  -> kernel base anchor
  -> mitigation/context knowledge
```

### Port I/O path

```text
read/write port
  -> platform-specific device/chipset effect
```

### Physical mapping path

```text
map physical memory
  -> inspect page
  -> bridge to object or hardware state
```

## Failure Modes

- product uses patched or alternate backend,
- Defender blocks vulnerable driver,
- Core Isolation / vulnerable-driver blocklist blocks load,
- port operation has no meaning on target system,
- MSR write crashes machine,
- physical mapping does not point to intended RAM/device region.

## Detection Ideas

Hunt for:

- Defender `VulnerableDriver:WinNT/Winring0` alerts,
- WinRing0/WinIo/MsIo files outside approved software,
- hardware-monitoring drivers on servers and business endpoints,
- driver service creation by non-installer process,
- renamed copies with same signer/hash lineage,
- sudden hardware instability after driver load.

## Study Questions

- Is this a product-specific driver or reused low-level library?
- Which primitive is exposed: MSR, port, memory, or mapping?
- Can the driver be identified by behavior rather than filename?
- Which products legitimately need it in this environment?
- What does Microsoft Defender or blocklist policy do on this host?

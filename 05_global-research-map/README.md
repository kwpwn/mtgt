# Global Research Map

This folder maps international sources for Windows kernel, HVCI/VBS/KDP, BYOVD, vulnerable drivers and R/W primitive research.

## Files

- `GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md`
- `DRIVERSHIELD_SOURCE_BUILD_PLAN.md`
- `DRIVERSHIELD_TRIAGE_QUEUE.md`

## Purpose

Use this folder when deciding what to research next. It is organized by:

- country / region,
- source / lab,
- technique family,
- driver/vendor class,
- next output documents.

## DriverShield Workflow

Use `DRIVERSHIELD_SOURCE_BUILD_PLAN.md` when mining DriverShield as a source
hub:

```text
DriverShield database / CVE library / signer atlas / BYOVD index
  -> triage queue
  -> cross-check with LOLDrivers, MSRC/NVD, vendor advisories
  -> primitive classification
  -> local case-study doc
```

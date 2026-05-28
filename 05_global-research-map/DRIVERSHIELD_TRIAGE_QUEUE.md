# DriverShield Triage Queue

Updated: 2026-05-27

## Purpose

This queue tracks DriverShield-derived candidates before they become local case
studies. Use it as a staging area:

```text
DriverShield metadata
  -> cross-check with LOLDrivers/vendor/MSRC/NVD
  -> primitive guess
  -> local verification
  -> case-study doc
```

Do not treat a queued item as verified until the `Verification` column is
updated.

For the first technique-level extraction pass, read:

- `03_byovd/00_index-and-matrix/BYOVD_DRIVERSHIELD_BLOG_TECHNIQUE_ATLAS.md`

## Queue Schema

| Priority | Driver / family | Hash | DriverShield | Primitive guess | Confidence | Verification | Output target |
|---|---|---|---|---|---|---|---|
| P1 | TBD from DriverShield database | TBD | https://drivershield.io/database/ | unknown | low | not started | TBD |

## CVE Seed List

These CVEs were observed on DriverShield's CVE library page and should be used
as starting points for source verification:

| CVE | Status | Next step |
|---|---|---|
| CVE-2013-3956 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2017-9769 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2022-26522 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2022-26523 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2023-1453 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2024-41498 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2024-26229 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2022-42046 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2022-3699 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2023-52271 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2019-18845 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2024-26506 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2018-16712 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2018-5713 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2009-0824 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2024-22830 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2007-5633 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2023-21768 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2020-17382 | queued | map to driver family, vendor advisory, LOLDrivers entry |
| CVE-2015-2291 | queued | map to driver family, vendor advisory, LOLDrivers entry |

## API Lookup Notes

DriverShield hash lookup endpoint:

```text
https://drivershield.io/?r=apilookup&sha256=<sha256>
```

Record only metadata that is useful for triage:

```text
filename
risk_score
verdict
yara_matches
mitre
scanned_at
```

Then verify the sample independently.

## Promotion Criteria

Promote an entry from queue to a local case-study doc only when at least two
source classes agree:

```text
DriverShield + LOLDrivers
DriverShield + vendor advisory
DriverShield + MSRC/NVD
DriverShield + local reversing
DriverShield + high-quality public technical writeup
```

## References

- DriverShield source build plan: `05_global-research-map/DRIVERSHIELD_SOURCE_BUILD_PLAN.md`
- DriverShield database: https://drivershield.io/database/
- DriverShield CVE library: https://drivershield.io/cves/
- DriverShield BYOVD index: https://drivershield.io/byovd/
- LOLDrivers: https://www.loldrivers.io/

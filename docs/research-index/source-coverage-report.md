# Source Coverage Report

Backlinks: [README](../../README.md) | [source status](source-integration-status.md) | [case-study matrix](case-study-matrix.md)

## Summary

| Category | Count | Notes |
|---|---:|---|
| Sources requested | 31 | All were added to the integration table and source notebook plan. |
| Readable via browser | 28 | Content or metadata was fetched for most sources. |
| Blocked/fetch failed | 3 | UnknownCheats, pwn2nimron, kernullist. |
| Integrated into deep docs | 23 | Core concepts mapped to hubs. |
| Marked needs-review | 11 | GitHub PoCs, forum/AI-like pages, or operationally sensitive posts. |

## Coverage by Topic

| Topic | Sources |
|---|---|
| WRMSR/MSR | Idafchev, xacone, Synacktiv |
| Physical memory R/W | xacone, Quarkslab, Datafarm, BusterCall |
| HVCI/VBS/KDP/VT-rp/HLAT | Connor, XPN, Tandasat, Datafarm, worawit, BusterCall, Synacktiv, NCC |
| BYOVD | Quarkslab, xacone, jeffaf, BlackSnufkin, GhostWolfLab, G3tSyst3m |
| IOCTL reversing | Idafchev, Julian Pena, xacone, Quarkslab |
| Pool/wild copy | Theori, vp777 |
| Win32k | Unit42, SecWiki, big5 component filter |
| Information disclosure | WindowsForum CVE-2026-21222 |
| DSE/CI concepts | XPN, Cryptoplague, worawit, Datafarm |

## Blocked Sources

| Source | Reason | Handling |
|---|---|---|
| UnknownCheats HVCI bypass forum | Fetch returned no readable content in browser tool. Forum content is also low-trust and potentially unsafe. | Source note marked `blocked/needs-review`. |
| pwn2nimron blog | Fetch/search did not return readable source content. | Source note marked `blocked`. |
| kernullist hiding on Windows | Direct fetch failed and search did not identify the exact page. | Source note marked `blocked`. |

## Safety Handling

Sources containing exploit code, LSASS dumping, EDR bypass, DSE/HVCI bypass, or BYOVD operational steps were reduced to:

- Problem statement.
- Primitive class.
- Preconditions.
- Mitigation impact.
- Detection telemetry.
- Version caveats.
- Lab-safe takeaway.

No runnable exploit steps were integrated.

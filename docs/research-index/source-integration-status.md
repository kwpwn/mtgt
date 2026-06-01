# Source Integration Status

Backlinks: [README](../../README.md) | [topic index](topic-index.md) | [learning path](windows-kernel-pwn-learning-path.md) | [source notebook](../../90_sources/curated-windows-kernel-pwn/README.md)

## Status Table

| Source | Trust | Status | Primary topic | Integrated docs |
|---|---|---|---|---|
| Idafchev WRMSR | researcher blog | integrated | MSR write, syscall path | [MSR notes](../kernel-research/msr-wrmsr-research-notes.md), [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| Quarkslab Lenovo CVE-2025-8061 part 2 | researcher/org blog | integrated | BYOVD, reflective driver loading concept | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |
| S12 driver loading in memory | blog | needs-review | driver loading and evasion framing | [BYOVD detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) |
| G3tSyst3m BYOVD/LSASS | blog | needs-review | BYOVD, PPL/LSASS abuse | [BYOVD detection playbook](../detection-and-mitigation/byovd-detection-engineering-playbook.md) |
| xacone eneio64 | researcher blog | integrated | physical memory R/W, HVCI-compatible BYOVD | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md), [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |
| Julian Pena driver exploitation | researcher blog | integrated | IOCTL reversing, arbitrary R/W | [IOCTL workflow](../userland-to-kernel/ioctl-reversing-workflow-deep-dive.md) |
| jeffaf AsIO3 CVE-2025-3464 | GitHub PoC | needs-review | TOCTOU, PreviousMode | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| BlackSnufkin BYOVD | GitHub repo | needs-review | BYOVD methodology | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |
| Securelist SAS CTF Windows 7 | vendor research | integrated | Windows 7 persistence/registry overflow | [case-study matrix](case-study-matrix.md) |
| XPN g_CiOptions | researcher blog | integrated | DSE, VBS/HVCI | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| Tandasat VT-rp/HLAT | researcher blog | integrated | HLAT, remapping attack | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| Connor McGarr HVCI | researcher blog | integrated | HVCI, KCFG, existing-code invocation | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| worawit/malk | GitHub PoC | needs-review | HVCI existing-code callback concept | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| Datafarm HVCI | blog | needs-review | HVCI, physical mapping, callbacks | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| BusterCall | GitHub PoC | needs-review | PFN swaps, HVCI gap claim | [page tables](../windows-internals/page-table-and-address-translation-deep-dive.md) |
| Cryptoplague offset-free DSE | blog | needs-review | PDB-based offsets, DSE concept | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| UnknownCheats HVCI forum | forum | blocked | HVCI bypass claim | Source note only; blocked by 403. |
| pwn2nimron blog | blog | blocked | unknown | Source note only; blocked by 403. |
| GhostWolfLab BYOVD paradigm | blog | needs-review | BYOVD trends, certificate trust | [BYOVD threat model](../byovd/byovd-modern-windows-11-threat-model.md) |
| kernullist hiding on Windows | unknown/blog | blocked | hiding concepts | Source note only; fetch failed. |
| Theori CVE-2023-28218 | researcher/org blog | integrated | wild copy, AFD, pool | [pool map](../windows-heap/kernel-pool-exploitation-study-map.md) |
| Unit42 Win32k part 1 | vendor research | integrated | win32k internals | [win32k attack surface](../kernel-research/win32k-and-gui-kernel-attack-surface.md) |
| HN Security pointer deref | researcher/org blog | integrated | arbitrary pointer deref, IoRing | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| yardenshafir IoRing | GitHub PoC | needs-review | post-exploitation primitive | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| WindowsForum CVE-2026-21222 | forum/AI | needs-review | info disclosure risk | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |
| NCC Group mitigation list | GitHub reference | integrated | mitigation timeline | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| Synacktiv kernel shadow stack PDF | research slides | integrated | CET/shadow stack | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| SecWiki kernel exploits | GitHub index | needs-review | historical CVE index | [case-study matrix](case-study-matrix.md) |
| big5 component filter | researcher blog | integrated | component filter mitigation | [mitigation deep dive](../mitigations/hvci-vbs-kdp-vtrp-hlat-deep-dive.md) |
| vp777 non-paged pool overflow | GitHub research | integrated | pool overflow | [pool map](../windows-heap/kernel-pool-exploitation-study-map.md) |
| ExploitPack Shadow SSDT | vendor/blog | needs-review | Shadow SSDT, R/W primitive | [primitive framework](../kernel-research/primitive-reasoning-framework.md) |

## Blocked or Low-Confidence Handling

Blocked sources are not treated as factual beyond URL/title/access status. Low-confidence PoC/forum/blog sources are integrated only as claims to reason about and verify, not as authoritative recipes.

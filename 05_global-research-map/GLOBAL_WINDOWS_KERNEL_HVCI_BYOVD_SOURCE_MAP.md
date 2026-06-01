# Global Windows Kernel / HVCI / BYOVD Source Map

Ngay cap nhat: 2026-05-25

Muc tieu cua file nay:

- Mo rong resource ra ngoai cac link ban dau.
- Lap ban do nguon theo quoc gia/khu vuc, lab, vendor, campaign va technique.
- Tach ro "research source country", "driver vendor country", "threat actor geography", va "victim geography".
- Giu focus vao cau hoi hien tai: khi co R/W primitive, HVCI/VBS/KDP/kCFG/CET con chan gi, va BYOVD/driver primitive dang tien hoa ra sao.

Can luu y:

- Quoc gia cua cong ty/lab khong dong nghia voi attribution.
- Driver vendor country khong dong nghia voi threat actor country.
- Victim country chi la noi campaign duoc quan sat, khong noi nguon goc ky thuat.
- Mot so cong ty la global; country trong file nay chi de dieu huong nguon.

## 1. Core reading stack

Neu chi doc 10 nguon de nam topic, doc theo thu tu:

1. Microsoft Memory Integrity / HVCI  
   https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity

2. Microsoft Kernel Data Protection  
   https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/

3. Microsoft Kernel-mode Hardware-enforced Stack Protection  
   https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection

4. Microsoft recommended vulnerable driver block rules  
   https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

5. Connor McGarr - HVCI / kCFG  
   https://connormcgarr.github.io/hvci/

6. Satoshi Tanda - Intel VT-rp Part 1  
   https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html

7. Satoshi Tanda - Intel VT-rp Part 2  
   https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html

8. Fortinet - DSE tampering, KDP, page swapping  
   https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering

9. Windows Internals - I/O Ring full R/W primitive  
   https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/

10. NDSS/EURECOM - Unveiling BYOVD Threats  
   https://www.ndss-symposium.org/ndss-paper/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/

## 2. Country / region map

### United States

Main relevance:

- Microsoft platform mitigations: HVCI, VBS, KDP, CET/kernel shadow stack, WDAC/blocklist.
- Google Project Zero Windows exploit research.
- Cisco Talos, CrowdStrike, Elastic, IBM X-Force, Rapid7 style threat/exploit/detection research.
- Dell/dbutil and many OEM/security driver cases.

Key sources:

- Microsoft HVCI: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft KDP: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Microsoft kernel shadow stack: https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
- Microsoft driver blocklist: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Google Project Zero Windows in-the-wild exploitation: https://projectzero.google/2021/01/in-wild-series-windows-exploits.html
- Google Project Zero Windows exploitation tricks: https://projectzero.google/2021/01/windows-exploitation-tricks-trapping.html
- Cisco Talos DeadLock/BdApiUtil BYOVD: https://blog.talosintelligence.com/byovd-loader-deadlock-ransomware/
- Elastic BYOVD/admin trust boundary: https://www.elastic.co/security-labs/forget-vulnerable-drivers-admin-is-all-you-need/
- IBM X-Force DKOM ETW providers: https://www.ibm.com/think/x-force/direct-kernel-object-manipulation-attacks-etw-providers

What to learn:

- Official mitigation guarantees and exact scope.
- Why "admin" is not automatically kernel, but BYOVD bridges that gap.
- How modern attackers use BYOVD for defense evasion rather than elegant code execution.
- Detection angle: service creation, driver load, blocklist/WDAC/ASR.

### France

Main relevance:

- Quarkslab Windows driver exploitation.
- EURECOM/NDSS academic BYOVD measurement.
- French/European security ecosystem around driver research and threat modeling.

Key sources:

- Quarkslab Lenovo CVE-2025-8061: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- Quarkslab Lenovo part 2: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html
- EURECOM BYOVD publication page: https://www.eurecom.fr/en/publication/8384
- NDSS BYOVD paper page: https://www.ndss-symposium.org/ndss-paper/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/

What to learn:

- Driver protocol reverse engineering.
- How hardware/OEM drivers expose physical memory/MSR primitives.
- How to move from individual PoC to systematic BYOVD dataset thinking.

### Singapore

Main relevance:

- STAR Labs publishes high-quality Windows 11 kernel bug discovery/exploitation writeups.

Key sources:

- STAR Labs CimFS Windows 11 kernel LPE: https://starlabs.sg/blog/2025/03-cimfs-crashing-in-memory-finding-system-kernel-edition/
- STAR Labs CVE-2024-30085 exploit writeup: https://starlabs.sg/blog/2024/12-all-i-want-for-christmas-is-a-cve-2024-30085-exploit/

What to learn:

- Modern Windows 11 kernel vulnerability discovery.
- Exploit reliability thinking, not just final primitive.
- File system / kernel object bug classes outside BYOVD.

### United Kingdom

Main relevance:

- Sophos BYOVD threat reports.
- NCC Group/MWR Labs historical Windows kernel exploitation and Pwn2Own-style research.

Key sources:

- Sophos AuKill / Process Explorer driver abuse: https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/
- NCC Group attacking Windows kernel archive: https://www.nccgroup.com/research/attacking-the-windows-kernel-black-hat-las-vegas-2007/
- MWR Labs Pwn2Own 2013 kernel exploit: https://labs.reversec.com/posts/2013/09/mwr-labs-pwn2own-2013-write-up-kernel-exploit

What to learn:

- Historical kernel exploit development.
- How old process/handle/kernel-driver functionality becomes modern BYOVD.
- Difference between exploit dev and operational EDR-killer abuse.

### Israel

Main relevance:

- Check Point Research BYOVD campaigns and vulnerable-driver methodology.
- SentinelOne/SentinelLabs Dell driver research and signed-driver abuse.
- enSilo/Fortinet lineage for Windows kernel/HVCI/KDP/PatchGuard research.

Key sources:

- Check Point Truesight campaign: https://blog.checkpoint.com/research/how-hunting-for-vulnerable-drivers-unraveled-a-widespread-attack/
- Check Point vulnerable driver investigation: https://research.checkpoint.com/2024/breaking-boundaries-investigating-vulnerable-drivers-and-mitigating-risks/
- SentinelOne signed malicious Microsoft drivers: https://www.sentinelone.com/labs/driving-through-defenses-targeted-attacks-leverage-signed-malicious-microsoft-drivers/
- Fortinet/enSilo KDP/DSE page swapping: https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering
- Fortinet/enSilo PatchGuard/KPTI: https://www.fortinet.com/blog/threat-research/melting-down-patchguard-leveraging-kpi-to-bypass-kernel-patch-protection

What to learn:

- Large-scale driver abuse campaigns.
- Authenticode/signing edge cases and legacy driver trust.
- Page swapping, callback swapping and why KDP/VT-rp exist.

### Canada

Main relevance:

- Fortinet/FortiGuard as global threat research with important Windows kernel mitigation analysis.
- BlackBerry/Cylance historically relevant for kernel threat detection, though not central to this current R/W/HVCI focus.

Key sources:

- Fortinet DSE/KDP: https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering
- Fortinet PatchGuard/KPTI: https://www.fortinet.com/blog/threat-research/melting-down-patchguard-leveraging-kpi-to-bypass-kernel-patch-protection

What to learn:

- KDP bypass class reasoning.
- PatchGuard interaction with OS mitigation changes.

### Japan / Taiwan

Main relevance:

- Trend Micro low-level Windows kernel threat reporting.
- HITCON/Taiwan conference materials on Windows kernel drivers.
- Driver/product origins: EnTech Taiwan `ASTRA64.sys`/PowerStrip, G.SKILL `eneio64`, other hardware/RGB/control utilities.

Key sources:

- Trend Micro Windows kernel threats: https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/the-evolution-of-windows-kernel-threats
- Trend Micro Windows kernel threats PDF: https://documents.trendmicro.com/assets/white_papers/wp-an-in-depth-look-at-windows-kernel-threats.pdf
- Trend Micro mhyprot2 threat encyclopedia: https://www.trendmicro.com/vinfo/my/threat-encyclopedia/malware/trojan.win64.mhyprotinst.b
- HITCON AMD Windows kernel drivers slides: https://hitcon.org/2023/CMT/slide/Uncovering%20Kernel%20Exploits_%20Exploring%20Vulnerabilities%20in%20AMD%27s%20Windows%20Kernel%20Drivers.pdf

What to learn:

- BYOVD as a real-world malware/ransomware technique.
- Hardware/anti-cheat drivers as a repeated vulnerable-driver class.
- Why physical memory, MSR and process-kill capabilities keep recurring in hardware-adjacent drivers.

### China

Main relevance:

- Driver vendor/product origins: Huawei audio driver, Baidu Antivirus driver, Qihoo 360 `DsArk64.sys`, game anti-cheat `mhyprot2.sys`.
- Chinese vendor drivers appear repeatedly in BYOVD/process-kill/RW case studies.

Key sources:

- CSA Lab Space Huawei `HWAuidoOs2Ec.sys`: https://labs.cloudsecurityalliance.org/research/csa-research-note-hwaudkiller-byovd-edr-bypass-malvertising/
- Cisco Talos DeadLock/Baidu driver: https://blog.talosintelligence.com/byovd-loader-deadlock-ransomware/
- LOLDrivers DsArk64: https://www.loldrivers.io/drivers/399fb787-5b06-46f0-86cb-dff7374bb015/
- Trend Micro mhyprot2 abuse: https://www.trendmicro.com/vinfo/my/threat-encyclopedia/malware/trojan.win64.mhyprotinst.b

What to learn:

- Security/AV/anti-cheat/OEM utilities often have powerful kernel functionality by design.
- Process termination primitives can be as operationally valuable as full R/W.
- Vendor-signed does not mean safe IOCTL semantics.

### South Korea / North Korea

Main relevance:

- AhnLab/ESET reporting on Lazarus BYOVD/rootkit activity.
- North Korea-linked Lazarus is a key public example of BYOVD used for deep Windows monitoring evasion.

Key sources:

- AhnLab Lazarus BYOVD rootkit: https://asec.ahnlab.com/en/38993/
- AhnLab PDF report: https://asec.ahnlab.com/wp-content/uploads/2022/10/Analysis-Report-on-Lazarus-Groups-Rootkit-Attack-Using-BYOVD_Oct-05-2022-3.pdf
- ESET/Virus Bulletin Lazarus BYOVD: https://www.virusbulletin.com/uploads/pdf/conference/vb2022/papers/VB2022-Lazarus-and-BYOVD-evil-to-the-Windows-core.pdf

What to learn:

- BYOVD can be used for generic blinding of security telemetry, not only process killing.
- Arbitrary kernel R/W can disable monitoring mechanisms at the OS level.
- State-sponsored usage shows why driver policy matters.

### Slovakia / Czech Republic

Main relevance:

- ESET is Slovak and has high-value Lazarus/BYOVD analysis.
- Avast/AVG/Gen ecosystem historically provides kernel driver vulnerability case studies.
- Virus Bulletin Prague materials include Lazarus/BYOVD research.

Key sources:

- ESET Netherlands/Belgium Lazarus report page: https://www.eset.com/nl/over/newsroom/persberichten-overzicht/persberichten/lazarus-richt-zich-op-luchtvaartbedrijf-in-nederland-en-politieke-journalist-in-belgie/
- Virus Bulletin 2022 Lazarus/BYOVD: https://www.virusbulletin.com/uploads/pdf/conference/vb2022/papers/VB2022-Lazarus-and-BYOVD-evil-to-the-Windows-core.pdf
- Avast virtualization driver pool overflow historical paper: https://anti-reversing.com/Downloads/Sec_Research/Exploiting_a_Kernel_PagedPool_Buffer_Overflow_in_Avast_Virtualization_Driver.pdf

What to learn:

- Kernel-mode security product drivers are themselves high-value attack surfaces.
- BYOVD in real campaigns often targets telemetry and security-product mechanisms.

### Germany

Main relevance:

- German research/blog ecosystem documents BYOVD signing loopholes and Truesight campaign.
- NSIDE gives practical BYOVD background from a European offensive/defensive perspective.

Key sources:

- NSIDE BYOVD and vulnerable drivers: https://www.nsideattacklogic.de/en/kernel-access-please-byovd-and-vulnerable-drivers/
- BornCity Truesight coverage: https://borncity.com/blog/2025/03/03/check-point-research-deckt-angriffe-ueber-veraltete-truesight-sys-treiber-auf/

What to learn:

- Legacy signing/cert-padding issues.
- Why blocklists lag behind signed-driver mutation and hash variation.

### Romania

Main relevance:

- Bitdefender provides good defensive explainers around BYOVD, VBS/HVCI and why signed driver abuse matters.

Key sources:

- Bitdefender BYOVD explainer: https://techzone.bitdefender.com/en/tech-explainers/what-is-bring-your-own-vulnerable-driver--byovd-.html

What to learn:

- Defensive framing.
- Why HVCI makes code injection harder but BYOVD remains useful for kernel-level operations.

### Russia

Main relevance:

- Kaspersky reports on BYOVD growth and Windows vulnerable driver targeting.

Key sources:

- Kaspersky vulnerable Windows drivers increase: https://www.kaspersky.com/about/press-releases/kaspersky-detects-23-increase-in-attacks-targeting-vulnerable-windows-drivers
- Kaspersky PuzzleMaker Windows exploit chain: https://www.kaspersky.com/blog/chrome-windows-zero-day/40191/

What to learn:

- Threat landscape scale.
- Windows kernel exploit chains used in the wild.

### Netherlands / Belgium

Main relevance:

- Victim geography in ESET Lazarus campaign: aerospace target in Netherlands and political journalist in Belgium.
- Useful because it grounds BYOVD in real intrusion context, not only lab exploitation.

Key sources:

- ESET report page: https://www.eset.com/nl/over/newsroom/persberichten-overzicht/persberichten/lazarus-richt-zich-op-luchtvaartbedrijf-in-nederland-en-politieke-journalist-in-belgie/

What to learn:

- BYOVD appears in targeted espionage, not only ransomware.
- Kernel R/W can be used to blind telemetry before higher-level activity.

### Switzerland / broader Europe

Main relevance:

- Secondary reporting and threat intelligence around Cisco Talos/DeadLock and BYOVD campaigns.
- Useful for following campaign propagation, but not primary exploit research.

Key sources:

- Cyberveille DeadLock/Baidu summary: https://cyberveille.ch/posts/2025-12-14-deadlock-une-campagne-ransomware-exploite-un-driver-baidu-byovd-pour-neutraliser-ledr/

What to learn:

- Campaign-level propagation of driver-abuse techniques.

## 3. Technique map by source

### HVCI / VBS / KDP / CET fundamentals

Primary:

- Microsoft HVCI: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft KDP: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Microsoft kernel shadow stack: https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
- Microsoft silicon-assisted security: https://learn.microsoft.com/en-us/windows/security/book/hardware-security-silicon-assisted-security

Use these for:

- exact mitigation scope,
- prerequisites,
- terminology,
- what is guaranteed vs what is not.

### R/W primitive under HVCI

Primary:

- Connor HVCI: https://connormcgarr.github.io/hvci/
- Windows Internals I/O Ring: https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/
- Connor paging: https://connormcgarr.github.io/paging/

Use these for:

- data-only vs code-execution mental model,
- arbitrary R/W to kernel API invocation,
- object-based primitive upgrade,
- VA/PA/PTE foundation.

### KDP remapping / page swapping / VT-rp

Primary:

- Fortinet DSE/KDP page swapping: https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering
- Satoshi VT-rp Part 1: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html
- Satoshi VT-rp Part 2: https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html

Use these for:

- why physical/GPA protection is not the same as virtual address protection,
- why changing guest PTE can attack KDP assumptions,
- why HLAT/VT-rp exists.

### BYOVD measurement / datasets

Primary:

- NDSS BYOVD paper: https://www.ndss-symposium.org/ndss-paper/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/
- EURECOM publication page: https://www.eurecom.fr/en/publication/8384
- LOLDrivers database: https://www.loldrivers.io/
- Microsoft driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

Use these for:

- known vulnerable driver corpus,
- blocklist gaps,
- empirical driver abuse patterns,
- detection research.

### Hardware-gated driver reachability

Primary:

- Atos BYOVD perspective: https://atos.net/en/lp/making-vulnerable-drivers-exploitable-without-hardware-the-byovd-perspective

Use this for:

- deciding if a driver vulnerability remains reachable without the original hardware,
- BYOVD exploitability triage,
- why hardware utilities are not automatically irrelevant on machines without that hardware.

### Process-kill / EDR-killer BYOVD

Primary:

- Sophos AuKill/Process Explorer: https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/
- Check Point Truesight: https://blog.checkpoint.com/research/how-hunting-for-vulnerable-drivers-unraveled-a-widespread-attack/
- Cisco Talos DeadLock/Baidu: https://blog.talosintelligence.com/byovd-loader-deadlock-ransomware/
- AhnLab Lazarus BYOVD: https://asec.ahnlab.com/en/38993/

Use these for:

- process termination primitive,
- PPL/security-tool bypass logic,
- real-world driver loading and service patterns,
- why "narrow primitive" can still be operationally powerful.

### Physical memory / MSR / OEM drivers

Primary:

- Quarkslab Lenovo LnvMSRIO: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- Quarkslab part 2: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html
- LOLDrivers Astra64 issue: https://github.com/magicsword-io/LOLDrivers/issues/294
- BlackSnufkin BYOVD: https://github.com/BlackSnufkin/BYOVD

Use these for:

- physical map primitive,
- MSR read/write risk,
- VA->PA bridge,
- data-only token DKOM.

## 4. What this source map changes in the resource

Before this map, the resource was mostly:

```text
individual writeup -> individual primitive -> local conclusion
```

After this map, use:

```text
country/source ecosystem -> technique family -> driver case -> mitigation interaction
```

This matters because BYOVD/HVCI research is not one paper. It is a collision between:

- Microsoft platform hardening,
- hardware/vendor driver design,
- threat actor operational pressure,
- security product self-protection,
- academic measurement,
- exploit developer adaptation.

## 5. Current research priorities from global map

### Priority 1: R/W primitive under HVCI

Read:

- Connor HVCI.
- Microsoft HVCI/KDP.
- Windows Internals I/O Ring.
- Fortinet page swapping.
- Satoshi VT-rp.

Output to build:

- technique-by-technique "what still works if HVCI on, CET on, KDP target protected".

### Priority 2: BYOVD corpus and blocklist gaps

Read:

- NDSS/EURECOM BYOVD.
- LOLDrivers.
- Microsoft block rules.
- Check Point Truesight.
- Atos hardware-gating.

Output to build:

- `BYOVD_BLOCKLIST_AND_REACHABILITY.md`

### Priority 3: process-kill vs full R/W

Read:

- Sophos AuKill.
- Cisco Talos DeadLock/Baidu.
- BlackSnufkin K7/BdApiUtil/TfSysMon.
- AhnLab/ESET Lazarus.

Output to build:

- `PROCESS_KILL_VS_RW_BYOVD_DEEP_DIVE.md`

### Priority 4: physical R/W drivers

Read:

- Quarkslab Lenovo.
- ASTRA64.
- eneio64.
- ThrottleStop.
- pstrip64.

Output to build:

- `PHYSICAL_RW_DRIVER_EXPLOITABILITY_MODEL.md`

### Priority 5: driver origin/vendor class analysis

Group driver origins by vendor class:

- OEM/firmware utility: Dell, Lenovo, Gigabyte, ASUS.
- Hardware/RGB/monitoring: EnTech, G.SKILL, WinRing0, ThrottleStop.
- Security/AV: Baidu, K7, Qihoo, Zemana, Avast, Trend Micro/other AV drivers.
- Anti-cheat/game: mhyprot2/Genshin.
- Forensic/admin tools: Process Explorer, EnCase/forensics tools.

Output to build:

- `DRIVER_VENDOR_CLASS_THREAT_MODEL.md`

## 6. Key conclusions after expanding globally

1. HVCI raised the cost of kernel code execution, but did not remove data-only exploitation.

2. KDP is the direct answer to data corruption, but it is selective. This creates the central question: is the target data protected?

3. Physical R/W is not outside VBS. It is still a VTL0 capability and may be constrained by SLAT/EPT-protected pages.

4. Virtual R/W is usually better for final exploitation; physical R/W is usually better for discovery, translation and low-level memory reasoning.

5. Process-kill BYOVD is operationally valuable because many attackers only need to disable security controls, not execute arbitrary kernel code.

6. The world has moved from "find a vulnerable driver" to "find a reachable vulnerable driver not blocked by current policy".

7. Country/vendor geography matters mainly because vulnerable drivers cluster around OEM, security, hardware monitoring, anti-cheat and administrative tool ecosystems.

8. Modern Windows exploit research must record exact mitigation state: Windows build, HVCI, VBS, KDP target, CET/kernel shadow stack, WDAC/blocklist, Secure Boot and CPU features.


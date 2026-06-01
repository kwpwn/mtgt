# BYOVD China Source Map - abused drivers, primitives, and defensive notes

Updated: 2026-06-02

Scope: Chinese-language blogs, forums, vendor posts, and mirrored WeChat writeups found during the June 2026 pass. This note focuses on drivers that have been observed in malware/ransomware/EDR-killer chains, plus a short watchlist for newly disclosed Chinese security-product drivers.

Safety boundary: this file intentionally summarizes abuse primitives at a defensive level. It does not reproduce exact IOCTL values, trigger buffers, exploit code, service commands, DSE-bypass recipes, or target process lists even when the linked source contains them.

## Confidence labels

| Label | Meaning |
|---|---|
| Observed in the wild | Reported in a real malware/ransomware campaign or incident response case. |
| Public PoC / public issue | Public exploit/research material exists, but this pass did not confirm criminal deployment. |
| Tool ecosystem | Driver appears inside public or commercial EDR-killer tooling; actor adoption may vary. |
| Watchlist | Useful BYOVD candidate or newly disclosed driver; keep detections ready but do not overclaim active exploitation. |

## High-signal Chinese sources

| Source | Why it matters |
|---|---|
| 火绒安全 - `BYOVD攻击泛滥！火绒专项防护守护系统安全` | Broad China-side statement that 银狐, miners, and ransomware frequently use signed vulnerable drivers to gain kernel capability and terminate security processes; uses `WinRing0.sys` as a typical example. Link: https://www.huorong.cn/document/info/classroom/1944 |
| 火绒安全 - `聚焦银狐丨探究病毒肆虐传播背后隐藏的迭代玄机` | Silver Fox overview; explicitly says Win0s-era Silver Fox uses BYOVD at the driver layer for defense evasion and persistence. Link: https://www.huorong.cn/document/tech/vir_report/1800 |
| 微步在线 / ThreatBook mirror - `连用四个驱动！银狐开始硬刚EDR和杀软` | Strongest China-source case for multi-driver Silver Fox: process kill, kernel memory R/W, callback blinding, process hiding, and network hiding. Mirror: https://cn-sec.com/archives/4659914.html |
| 金山毒霸/鹰眼威胁情报中心 mirror - `银狐新进展：多Rootkit配合，内核InfinityHook+穿透读写` | Silver Fox chain using multiple signed/leaked drivers: arbitrary R/W, InfinityHook process hiding, network hiding, and a Ping32/NSec process-kill driver. Mirror: https://cn-sec.com/archives/4283049.html |
| 看雪 - `持续演进的银狐——不断增加脆弱驱动通过BYOVD结束防病毒软件` | Fresh STProcessMonitor/Safetica case. It reports a WHQL-signed driver exposing a process-termination path to user mode and assigns/reserves CVE-2025-70795. Link: https://bbs.kanxue.com/thread-290009-1.htm |
| CN-SEC mirrors of Trend/Sophos/ESET/Trellix reports | Useful Chinese-language mirrors for Kasseika, BlackByte, EDRKillShifter, Avast/aswArPot, and GhostEngine. Treat as secondary; verify against original vendor reports for publication-grade work. |

## Driver abuse matrix

| Driver / family | Vendor / product | Status | Abuse primitive, high level | Reported actor / malware | China-source links |
|---|---|---|---|---|---|
| `STProcessMonitor*.sys` / STProcessMonitor Driver | Safetica Technologies | Observed in the wild, public forum analysis | Exposes a privileged process-termination operation to user mode; Silver Fox sample used it to kill AV/EDR processes before loading Win0s. | 银狐 / Win0s | 看雪: https://bbs.kanxue.com/thread-290009-1.htm ; Kafan mirror/discussion: https://bbs.kafan.cn/thread-2288675-2-1.html |
| `BdApiUtil64.sys` / `BdApiUtil.sys` | Baidu Antivirus | Observed in the wild, public PoC | Process-killer driver. Malware enumerates AV/EDR process names and asks the driver to terminate matching PIDs from kernel mode. | 银狐, BlackSnufkin BYOVD tooling | ThreatBook mirror: https://cn-sec.com/archives/4659914.html ; local deep dive: `03_byovd\03_process-kill\BDAPIUTIL64_PROCESS_KILLER_DEEP_DIVE.md` |
| Ping32 / `NSecKrnl.sys` | 山东安在信息技术 / Ping32 behavior-management product | Observed in the wild | Kernel process termination by PID due to insufficient authorization on a vendor driver intended for endpoint management/security control. | 银狐 | Kingsoft/EagleEye mirror: https://cn-sec.com/archives/4283049.html ; ThreatBook mirror notes earlier Ping32 use: https://cn-sec.com/archives/4659914.html |
| `rwdriver.sys` | NanoWraith-derived R/W driver, leaked/expired ZTE signature reported by China sources | Observed in the wild | Arbitrary kernel address read/write; used to locate and neutralize security product callbacks so EDR/AV stops collecting process/thread/file/registry telemetry. | 银狐 | Kingsoft/EagleEye mirror: https://cn-sec.com/archives/4283049.html ; ThreatBook mirror: https://cn-sec.com/archives/4659914.html |
| `Cndom6.sys` | Reported expired China-side signature | Observed in the wild | InfinityHook-style syscall interception for process hiding and handle-open denial against protected malware processes. This is closer to malicious/signed rootkit tooling than classic BYOVD. | 银狐 | Kingsoft/EagleEye mirror: https://cn-sec.com/archives/4283049.html ; ThreatBook mirror: https://cn-sec.com/archives/4659914.html |
| `XiaoH.sys` | Reported expired China-side signature | Observed in the wild | Hooks/patches `nsiproxy.sys` dispatch path to hide network connection information from user-mode enumeration tools and security products. | 银狐 | Kingsoft/EagleEye mirror: https://cn-sec.com/archives/4283049.html ; ThreatBook mirror: https://cn-sec.com/archives/4659914.html |
| `WinRing0.sys` | OpenLibSys / hardware access helper | Observed in malware ecosystem; broad China-source mention | Low-level hardware access, including I/O ports, MSR, PCI config, and physical memory classes. China sources describe malicious loaders dropping/decrypting it and abusing kernel capability against security processes. | Miners, ransomware, 银狐; also legitimate XMRig tuning use | 火绒: https://www.huorong.cn/document/info/classroom/1944 |
| `mhyprot2.sys` | miHoYo Genshin Impact anti-cheat | Observed in the wild | Vulnerable anti-cheat driver used as a kernel deputy to terminate AV/security processes and services during ransomware staging. | Ransomware actor reported by Trend Micro | Solidot: https://www.solidot.org/story?sid=72579 ; cnBeta: https://www.cnbeta.com.tw/articles/game/1308973.htm ; 4hou: https://www.4hou.com/posts/500B |
| `RTCore64.sys` | MSI Afterburner | Observed in the wild | Kernel memory/control primitive abused to disable security product callbacks and blind EDR; also a common BYOVD primitive in public tooling. | BlackByte | FreeBuf/CN-SEC mirror: https://cn-sec.com/archives/3193730.html ; FreeBuf mirror search result: https://www.aqtd.com/nd.jsp?id=7443 |
| `DBUtil_2_3.sys` | Dell firmware/update utility | Observed in the wild | Signed OEM driver with kernel memory primitive; used as one of BlackByte's vulnerable drivers. | BlackByte; also broader BYOVD ecosystem | BlackByte/Talos mirror: https://cn-sec.com/archives/3193730.html |
| `gdrv.sys` | GIGABYTE Tools | Observed in the wild | Kernel R/W and hardware access family; used as one of BlackByte's vulnerable drivers and historically associated with BYOVD ransomware tradecraft. | BlackByte, RobbinHood references in broader reports | BlackByte/Talos mirror: https://cn-sec.com/archives/3193730.html |
| `zamguard64.sys` / `zam64.sys` | Zemana Anti-Malware | Observed in the wild / tool ecosystem | Process/security-tool control primitive used by Terminator-style EDR killers; BlackByte also carried it as part of a four-driver set. | BlackByte, Terminator-style EDR killer ecosystem | BlackByte/Talos mirror: https://cn-sec.com/archives/3193730.html ; local deep dive: `03_byovd\03_process-kill\ZEMANA_TERMINATOR_DEEP_DIVE.md` |
| `rentdrv2.sys` | RentDrv2 / BadRentdrv2 ecosystem | Tool ecosystem, observed in RansomHub EDR killer reporting | EDR-killer driver payload used by EDRKillShifter-style chains to disable security processes after privilege is obtained. | RansomHub / EDRKillShifter; later shared among ransomware affiliates | CN-SEC EDRKillShifter summaries: https://cn-sec.com/archives/3071058.html , https://cn-sec.com/archives/3893348.html |
| `TfSysMon.sys` / `sysmon.sys` | ThreatFire System Monitor | Tool ecosystem, observed in RansomHub EDR killer reporting | Kernel process-kill primitive through an old security product driver. Important name collision: this is not Sysinternals Sysmon. | EDRKillShifter, public killer modules | CN-SEC EDRKillShifter summary: https://cn-sec.com/archives/3071058.html ; local deep dive: `03_byovd\03_process-kill\TFSYSMON_THREATFIRE_DEEP_DIVE.md` |
| `Martini.sys` / `viragt64.sys` | TG Soft VirtIT Agent | Observed in the wild | Driver-backed process termination of AV, security tools, analysis tools, and system utilities before ransomware encryption. | Kasseika ransomware | 安全客: https://www.anquanke.com/post/id/292882 ; CN-SEC/Trend mirrors: https://cn-sec.com/archives/2441959.html , https://cn-sec.com/archives/2490424.html |
| `aswArPot.sys` / `asWarPot.sys` | Avast / AVG Anti-Rootkit | Observed in the wild | Kernel anti-rootkit driver reused to terminate security processes; later campaigns also pair it with tools that delete or disable security agent files. | AvosLocker, Cuba/BurntCigar, GhostEngine, 2024 AV-killer campaign | 安全客/Trellix: https://www.anquanke.com/post/id/302192 ; CN-SEC/GhostEngine: https://cn-sec.com/archives/2767914.html |
| `IObitUnlockers.sys` | IObit Unlocker | Observed in the wild | File deletion/unlock primitive used after security process termination to remove security agent binaries. More of a file-operation abuse than pure process-kill. | GhostEngine / cryptomining campaign | CN-SEC/GhostEngine: https://cn-sec.com/archives/2767914.html , https://cn-sec.com/archives/2771763.html |
| `PROCEXP.SYS` / `PROCEXP152.sys` | Sysinternals Process Explorer driver | Tool ecosystem / historical abuse | Legitimate admin/security driver family abused by EDR killers such as AuKill to get privileged process-control behavior. | AuKill / AvNeutralizer-style ecosystem | CN-SEC MS-SCMR BYOVD note lists ProcessExplorer-style terminate-process class: https://cn-sec.com/archives/1827688.html |
| Process Hacker / KProcessHacker family | Process Hacker | Tool ecosystem / historical abuse | Privileged process/handle manipulation driver abused by AV-killer tooling. Treat as family-level because filenames vary by fork/build. | Commodity EDR-killer ecosystem | CN-SEC MS-SCMR BYOVD note: https://cn-sec.com/archives/1827688.html |
| `DsArk64.sys` / `DsArk.sys` | Qihoo 360 Total Security / 360 security tooling | Public issue / watchlist; vendor dispute exists | Public reports describe process-kill plus kernel virtual read/write and a bypassable authorization model. 360 publicly disputed exploitability in an IT之家 update; keep as watchlist until independently validated in your lab. | No China-source in-the-wild campaign confirmed in this pass | IT之家 with 360 response: https://www.ithome.com/0/938/777.htm ; local deep dive: `03_byovd\02_virtual-kernel-rw\DSARK64_QIHOO_DEEP_DIVE.md` |
| `kdhacker64_ev.sys` | Kingsoft Antivirus | Public issue / watchlist | Public reports describe an EV-signed kernel pool overflow in a Chinese AV driver. Include for exposure tracking, not as confirmed criminal abuse. | Watchlist | IT之家: https://www.ithome.com/0/938/777.htm |
| `POORTRY` / BurntCigar driver family | Custom signed/malicious EDR-killer driver | Observed in the wild, but not classic "vulnerable legit driver" | Custom kernel driver used to terminate EDR processes; often discussed adjacent to BYOVD because it relies on trusted or cross-signed kernel loading. | Scattered Spider, Cuba-related reporting, ransomware ecosystem | CN-SEC cross-signing discussion: https://cn-sec.com/archives/5179034.html ; CN-SEC Cuba/BurntCigar context: https://cn-sec.com/archives/2064132.html |

## Abuse patterns extracted from the China-source set

### 1. Process-kill drivers

Representative drivers:

- `STProcessMonitor*.sys`
- `BdApiUtil64.sys`
- Ping32 / `NSecKrnl.sys`
- `mhyprot2.sys`
- `Martini.sys` / `viragt64.sys`
- `aswArPot.sys`
- `TfSysMon.sys`
- `zamguard64.sys`

Pattern:

1. Attacker already has local code execution, usually admin or SYSTEM in ransomware cases.
2. Loader drops or finds a signed driver.
3. Driver is loaded as a kernel service.
4. User-mode controller enumerates security processes.
5. Controller asks the driver to terminate targets from kernel mode.

Defensive meaning: PPL and user-mode anti-tamper do not help if a trusted kernel driver acts as a confused deputy. Detection should correlate driver load with security-process termination, not only flag the final ransomware binary.

### 2. Kernel memory read/write and callback blinding

Representative drivers:

- `rwdriver.sys`
- `RTCore64.sys`
- `DBUtil_2_3.sys`
- `gdrv.sys`
- `DsArk64.sys` watchlist

Pattern:

1. Driver exposes raw or semi-raw kernel memory capability.
2. Malware locates security product callback or telemetry structures.
3. Instead of killing the EDR service, malware modifies or clears collection paths so the product remains running but blind.

Defensive meaning: a "healthy" EDR process is not enough. Watch kernel driver loads, callback integrity where available, sudden telemetry gaps, and sensor state mismatch.

### 3. Rootkit hiding and network blinding

Representative drivers:

- `Cndom6.sys`
- `XiaoH.sys`

Pattern:

1. Signed or expired-signed rootkit driver is loaded.
2. It hooks syscall or network enumeration paths.
3. Malware process and C2 connection become hidden from common user-mode tools.

Defensive meaning: this is beyond commodity BYOVD process kill. Memory forensics, kernel image load history, and offline collection become more important than live user-mode enumeration.

### 4. File deletion / file overwrite abuse

Representative drivers:

- `IObitUnlockers.sys`
- File-writing minifilter technique discussed in CN-SEC's "BYOVD next level" article.

Pattern:

1. Security process is stopped or bypassed.
2. A privileged file-operation driver deletes, unlocks, overwrites, or damages security agent binaries.
3. Reboot or service restart leaves the agent broken.

Defensive meaning: include file integrity checks for EDR/AV installation paths and alert on signed third-party drivers touching those paths.

## Silver Fox-specific driver stack

The China-source set is unusually rich for 银狐 because multiple domestic vendors tracked it in 2025-2026.

| Phase | Driver(s) | Purpose |
|---|---|---|
| Kill AV/EDR | `BdApiUtil64.sys`, Ping32 / `NSecKrnl.sys`, `STProcessMonitor*.sys` | Terminate security processes from kernel mode. |
| Blind telemetry | `rwdriver.sys` | Kernel memory R/W to disable callback-based telemetry without necessarily killing the product. |
| Hide process | `Cndom6.sys` | InfinityHook-style syscall interception and handle-open denial. |
| Hide network | `XiaoH.sys` | Hook network enumeration path around `nsiproxy.sys` to hide reverse connections. |
| Persistence/control payload | Win0s user-mode RAT, plus IP-Guard/Ping32 abuse in some reports | Long-term control, screen/keyboard/file access, enterprise behavior-management software abuse. |

Key sources:

- 火绒 Silver Fox overview: https://www.huorong.cn/document/tech/vir_report/1800
- 金山/鹰眼 Rootkit chain mirror: https://cn-sec.com/archives/4283049.html
- 微步/ThreatBook four-driver chain mirror: https://cn-sec.com/archives/4659914.html
- 看雪 STProcessMonitor update: https://bbs.kanxue.com/thread-290009-1.htm

## Defensive checklist

Prioritize controls in this order:

1. WDAC / App Control deny rules for known-bad driver hashes, not only filenames.
2. Enable Microsoft vulnerable driver blocklist and HVCI where compatible, but do not rely on them as complete coverage.
3. Sysmon Event ID 6 or equivalent EDR telemetry for all driver image loads.
4. Alert on kernel service creation from `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, `C:\ProgramData`, downloads, and unusual staging folders.
5. Correlate driver load within a short time window with AV/EDR process termination, service stop, driver unload, or telemetry gap.
6. Track signer and product category. Old security products, behavior-management tools, anti-cheat, RGB/overclocking, firmware update, miner, and unlocker utilities are high-risk buckets.
7. Monitor for security-agent file deletion/overwrite and unexpected writes to AV/EDR install directories.
8. For China-facing environments, specifically hunt Silver Fox patterns: fake software installers, Inno Setup loaders, Win0s payloads, behavior-management software abuse, and multi-driver stacks.

## Notes on source handling

- CN-SEC often mirrors WeChat/vendor reports and may include operational screenshots. Use it as discovery and Chinese-language context, then verify with original vendor posts where possible.
- 看雪/Kafan forum posts may contain exploit-relevant values and PoCs. This repo should not mirror trigger details; keep those links as references only.
- Several entries are not "vulnerable legit driver" in the strict BYOVD sense. `Cndom6.sys`, `XiaoH.sys`, and `POORTRY` are better treated as signed/expired-signed malicious kernel tooling. They are included because defenders see them in the same operational phase: kernel-level AV/EDR defeat.

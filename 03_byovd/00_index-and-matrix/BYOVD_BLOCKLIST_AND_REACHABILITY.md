# BYOVD Blocklist and Reachability Deep Dive

Ngay cap nhat: 2026-05-25

Muc tieu:

- Nang cap cach danh gia mot driver BYOVD tu "co vulnerability" len "co thuc su exploitable/reachable/loadable/useful tren Windows hien tai khong".
- Dua vao cac nguon moi: Microsoft blocklist, NDSS/EURECOM BYOVD measurement, Atos hardware-gating research, Check Point Truesight campaign, Cisco Talos/Sophos/AhnLab campaign cases.
- Giu muc tieu nghien cuu/phong thu: khong tao runbook khai thac, ma tao model danh gia.

## 1. Sai lam pho bien: "driver co CVE la exploitable"

Khong du.

Mot driver co CVE nhung van co the khong co gia tri BYOVD neu:

- khong load duoc tren build/policy hien tai,
- bi Microsoft vulnerable driver blocklist chan,
- bi WDAC enterprise policy chan,
- can phan cung that moi tao device object,
- code path vulnerable chi reachable qua PnP/AddDevice/IRP_MJ_PNP trong dieu kien dac biet,
- IOCTL device ACL khong cho caller mo handle,
- bug chi DoS, khong co meaningful primitive,
- primitive khong dung duoc duoi HVCI/KDP/CET,
- target action khong co gia tri operational/research.

Atos tom gon hai dieu kien quan trong cho BYOVD candidate:

```text
1. Exploitation tao meaningful disruption/capability.
2. Exploitability khong phu thuoc vao dieu kien hiem nhu phan cung cu the.
```

## 2. Ba lop can danh gia

### 2.1 Loadability

Driver co load duoc khong?

Factors:

- Signature chain.
- Microsoft signing policy.
- HVCI compatibility.
- WDAC/App Control policy.
- Microsoft vulnerable driver blocklist.
- Kernel-mode hardware stack protection incompatible driver blocklist.
- Secure Boot / test signing / debug state.
- Driver package/INF/PnP requirements.

Neu khong load duoc, primitive khong quan trong.

### 2.2 Reachability

Vulnerable code path co reachable tu attacker-controlled user-mode process khong?

Factors:

- Device object co duoc tao unconditional khi DriverEntry khong?
- Device object chi tao khi PnP AddDevice thanh cong?
- Driver can hardware ID / device node khong?
- IOCTL dispatch co registered khong?
- Device ACL / SDDL co cho user/admin mo handle khong?
- IOCTL co auth/magic/version/license check khong?
- Vulnerable path co yeu cau internal state khong?
- Hardware probing fail co unload/disable path khong?

Atos research quan trong vi no chi ra nhieu driver tuong "hardware-gated" van co the duoc tuong tac neu co cach tao/emulate device state o muc Windows driver architecture. Phan can hoc la model reachability, khong phai copy deployment trick.

### 2.3 Usefulness

Primitive co dang gia khong?

High-value:

- virtual kernel R/W,
- physical memory R/W,
- MSR read/write,
- arbitrary process termination,
- arbitrary handle close,
- callback/security state tamper,
- file overwrite/delete in kernel context,
- object/policy modification.

Low-value or risky:

- only crash,
- write without address control,
- hardware-only side effect,
- global hook/MSR write only with high BSOD risk,
- primitive cannot target useful data under HVCI/KDP.

## 3. Blocklist is necessary but not sufficient

Microsoft vulnerable driver blocklist matters because it attacks BYOVD at the correct layer:

```text
do not let known-bad signed driver load
```

But it is not complete:

- Microsoft explicitly balances compatibility/reliability against blocking.
- New driver vulnerabilities appear before blocklist updates.
- Legacy versions may evade if rules do not cover them.
- Hash-only detection can fail when signature remains valid but file hash changes.
- Enterprise policy may be outdated.
- Some devices need old drivers, creating exceptions.

Check Point's Truesight case is the clearest example:

- attackers used legacy `Truesight.sys` 2.0.2,
- generated over 2,500 variants,
- changed hashes while keeping digital signature valid,
- blocklist initially missed that exact legacy version,
- Microsoft later updated the blocklist.

Lesson:

```text
Blocklist answers "is this exact known bad thing blocked?"
Behavioral reachability answers "can this driver still perform dangerous action?"
```

## 4. Why signature-based driver defense fails alone

Driver signing proves:

```text
this binary/publisher/signature chain satisfies a trust policy
```

It does not prove:

```text
IOCTLs are safe
access control is correct
driver validates user buffers
MSR/physical memory access is restricted
process-kill operation checks caller privilege
old vulnerable version is not abusable
```

BYOVD exists because signed code can have unsafe semantics.

## 5. Blocklist bypass classes at research level

This section is defensive/modeling only.

### 5.1 Version gap

Blocklist catches one version but misses another with same vulnerable code.

Example class:

```text
Truesight 3.x known, but older 2.0.2 retained vulnerable process-kill code.
```

Research task:

- diff vulnerable and blocked versions,
- inspect whether older/newer versions retain same IOCTL path,
- check if Microsoft/LOLDrivers rules cover all vulnerable versions.

### 5.2 Hash mutation with valid signature

If a signing/verification edge case allows non-semantic PE changes without invalidating trust, hash-based detections can miss variants.

Research task:

- do not rely on hash only,
- track signer, version, PE metadata, imported routines, IOCTL behavior,
- use behavior/semantic detection.

### 5.3 Not-yet-known vulnerable driver

NDSS/EURECOM found previously unknown vulnerable drivers through dynamic tracing, showing corpus-based detection is always behind.

Research task:

- triage driver behavior, not only known CVE tags,
- look for dangerous kernel APIs reachable from user-originating IOCTL.

### 5.4 Hardware-gated but reachable

Driver seems irrelevant without hardware, but Windows driver architecture may still create reachable code paths.

Research task:

- classify device creation pattern,
- identify whether IOCTL device object exists without hardware,
- understand PnP/hardware probing failure behavior.

### 5.5 Already-loaded driver

Blocklist prevents loading; it may not remove risk from an already-loaded or vendor-required driver depending on timing/policy state.

Research task:

- inventory loaded drivers,
- detect vulnerable versions already present,
- do not focus only on driver drops.

## 6. Reachability taxonomy

### Pattern A: unconditional device object

Driver creates `\Device\Name` and symbolic link during load.

BYOVD value:

- high reachability,
- easy user-mode interaction if ACL allows,
- no hardware needed.

Common in:

- utility drivers,
- old monitoring/RGB tools,
- some AV/security helper drivers.

### Pattern B: conditional device object

Driver creates device object only if hardware probe/config succeeds.

BYOVD value:

- medium,
- may require device state,
- may fail on generic target.

Research questions:

- Does failure leave any control device?
- Is there a fallback diagnostic interface?
- Can driver be installed as legacy service?

### Pattern C: PnP AddDevice path

Device object created during PnP lifecycle.

BYOVD value:

- depends on whether attacker can cause matching device node/stack.

Research questions:

- Which hardware IDs?
- Which INF?
- Is there software-enumerated device support?
- Does driver require real MMIO/PCI resource?

### Pattern D: filter driver / stack attachment

Driver attaches to existing stack/class.

BYOVD value:

- high if target class common,
- lower if exact stack missing.

Research questions:

- Per-class filter or per-device filter?
- Does it expose user IOCTL control device?
- Does it require upper/lower filter registry configuration?

### Pattern E: active hardware probing

Driver expects MMIO/ports/MSRs/device registers.

BYOVD value:

- high if vulnerable path reachable before hardware-specific failure,
- low if every interesting path depends on hardware response.

Research questions:

- Does it fail open or fail closed?
- Are dangerous routines reachable before probe?
- Does driver trust registry/config values for physical addresses?

## 7. BYOVD candidate scoring

Use this score for each driver.

```text
Loadability:
  0 = blocked/not signed/not loadable
  1 = loadable only with special config
  2 = loadable on common Windows config
  3 = already loaded or broadly deployed

Reachability:
  0 = no reachable user path
  1 = reachable only with hardware/special PnP
  2 = reachable as admin/service
  3 = reachable by low/medium user or weak device ACL

Primitive value:
  0 = crash only
  1 = narrow side effect
  2 = process/handle/file semantic action
  3 = virtual R/W, physical R/W, MSR, powerful state tamper

Mitigation resistance:
  0 = breaks under HVCI/KDP/CET/WDAC
  1 = works only HVCI off or old build
  2 = data-only/semantic under HVCI but blocklist risk
  3 = useful if already loaded and not blocked, no code execution needed

Operational stability:
  0 = easy BSOD
  1 = race/global patch/MSR-heavy
  2 = stable with validation/restore
  3 = narrow stable semantic operation
```

Interpretation:

- 12-15: high-priority BYOVD research target.
- 8-11: useful but needs conditions.
- 4-7: lab/edge case.
- 0-3: low practical value.

## 8. How this applies to primitive classes

### Physical R/W driver

Loadability:

- often blocked if known,
- often from OEM/hardware utility.

Reachability:

- may require hardware or may expose universal physical map device.

Usefulness:

- high if read/write both work,
- must solve VA->PA.

Mitigation:

- HVCI does not stop mutable data writes,
- KDP/SLAT can stop protected data writes,
- WDAC/blocklist is main control.

### Virtual R/W driver

Loadability:

- often blocked if famous.

Reachability:

- strong if device ACL weak and IOCTL path direct.

Usefulness:

- best final exploitation primitive.

Mitigation:

- data-only works if target unprotected,
- code patching/shellcode poor under HVCI.

### Process-kill driver

Loadability:

- commonly blocked once abused.

Reachability:

- usually simple if device opens.

Usefulness:

- high for EDR/AV kill,
- not general LPE unless target/process semantics provide it.

Mitigation:

- PPL may not help if kernel driver terminates,
- WDAC/blocklist/tamper protection/behavior detection matter.

### MSR driver

Loadability:

- hardware/monitoring drivers common.

Reachability:

- often direct IOCTL.

Usefulness:

- MSR read excellent for KASLR,
- MSR write high-risk.

Mitigation:

- HVCI/CET/kCFG complicate syscall hijack,
- data-only route usually safer.

## 9. Case notes from new sources

### Atos: hardware-gating changes exploitability

Key lesson:

```text
A vulnerable code path inside a driver is not enough.
You must prove the path is reachable without rare hardware conditions.
```

Atos separates driver/device-object creation patterns and highlights PnP/hardware probing as the missing piece in many BYOVD analyses.

Research action:

- add "Reachability" section to every driver writeup,
- note whether vulnerable IOCTL exists after service load without hardware.

### NDSS/EURECOM: dynamic behavior beats static lists

Key facts from NDSS page:

- paper analyzes malware abusing signed drivers,
- introduces dynamic taxonomy of BYOVD behavior,
- traces from user-mode request to kernel instructions,
- analyzed 8,779 malware samples loading 773 distinct signed drivers,
- suspicious behavior in 48 drivers,
- seven previously unknown vulnerable drivers disclosed.

Research action:

- build our own manual taxonomy:
  - load driver,
  - open device,
  - send IOCTL,
  - dangerous kernel API,
  - effect.

### Check Point: Truesight shows blocklist gaps

Key lessons:

- attackers used legacy version with vulnerable code,
- generated many variants,
- changed hashes while retaining valid signature,
- blocklist later updated after report,
- victims mostly in Asia in that campaign.

Research action:

- do not trust "driver family is blocked" as enough,
- track version + signer + semantic behavior,
- include Authenticode/cert-padding/signature edge cases in detection notes.

### Microsoft: blocklist is a compatibility tradeoff

Microsoft notes the blocklist is useful but not guaranteed to block every vulnerable driver, because blocking can break devices/software and sometimes cause blue screens.

Research action:

- treat blocklist as one signal,
- combine with WDAC allowlist, ASR, telemetry and driver inventory.

## 10. Per-driver reachability template

Add this to each writeup:

```text
Driver:
Vendor:
Country/vendor class:
Known CVE/public issue:
Primitive:

Loadability:
  Signed:
  WHQL/Microsoft signed:
  HVCI-compatible:
  Blocklisted by Microsoft:
  Blocklisted by vendor/EDR:
  Requires test mode:

Reachability:
  Device object created:
  Symbolic link:
  Device ACL:
  Needs hardware:
  Needs PnP device node:
  Needs INF:
  IOCTL dispatch reachable:
  Auth/magic/license check:
  Works without original product installed:

Usefulness:
  Read:
  Write:
  Physical/virtual:
  MSR:
  Process kill:
  File/handle operation:
  Can upgrade primitive:

Mitigation:
  HVCI impact:
  KDP target risk:
  kCFG/CET impact:
  PatchGuard risk:
  WDAC/blocklist risk:

Reliability:
  BSOD risk:
  Restore needed:
  Version sensitivity:
  Tested Windows builds in public source:
```

## 11. Main conclusions

1. A BYOVD candidate needs loadability, reachability and usefulness. Missing any one makes the driver low value.

2. Blocklists are necessary but lag the threat and can miss versions, variants or newly discovered drivers.

3. Hardware-gating is now a first-class research question. A bug reachable only with rare hardware is much less useful than an unconditional IOCTL bug.

4. Behavioral tracing from user IOCTL to dangerous kernel API is stronger than hash/CVE tracking alone.

5. Under HVCI, the best primitives are data-only or semantic. Code-execution-oriented driver abuse faces HVCI/kCFG/CET pressure.

6. Every per-driver writeup in this resource should now include a reachability/loadability section, not just primitive analysis.

## 12. Sources

- Microsoft recommended driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
- Microsoft vulnerable driver blocklist support note: https://support.microsoft.com/en-au/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936
- Atos - Making Vulnerable Drivers Exploitable Without Hardware: https://atos.net/en/lp/cybershield/making-vulnerable-drivers-exploitable-without-hardware-the-byovd-perspective
- NDSS - Unveiling BYOVD Threats: https://www.ndss-symposium.org/ndss-paper/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/
- Check Point - Truesight campaign: https://blog.checkpoint.com/research/how-hunting-for-vulnerable-drivers-unraveled-a-widespread-attack/
- Cisco Talos - DeadLock/Baidu BYOVD loader: https://blog.talosintelligence.com/byovd-loader-deadlock-ransomware/
- Sophos - AuKill Process Explorer driver abuse: https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/
- AhnLab - Lazarus BYOVD rootkit: https://asec.ahnlab.com/en/38993/
- LOLDrivers database: https://www.loldrivers.io/


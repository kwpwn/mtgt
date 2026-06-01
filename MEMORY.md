# Memory - Windows Kernel / BYOVD Research Resource

Workspace resource path:

```text
E:\Windows-kernel-exploit-research-resource
```

## Folder Layout

```text
E:\Windows-kernel-exploit-research-resource
|-- README.md
|-- MEMORY.md
|-- 01_core-handbook
|-- 02_mitigations-vbs-hvci-vtrp
|-- 03_byovd
|   |-- 00_index-and-matrix
|   |-- 01_physical-memory-rw
|   |-- 02_virtual-kernel-rw
|   |-- 03_process-kill
|   |-- 04_limited-primitives
|   |-- 05_msr-and-multi-primitive
|   `-- 99_workflow
|-- 04_connor-mcgarr-study
|-- 05_global-research-map
`-- 90_sources
```

## Main Documents

- `README.md`
- `01_core-handbook\WINDOWS_KERNEL_EXPLOIT_RESEARCH.md`
- `02_mitigations-vbs-hvci-vtrp\VT_RP_HLAT_DEEP_DIVE.md`
- `02_mitigations-vbs-hvci-vtrp\CONNOR_HVCI_KCFG_DEEP_DIVE.md`
- `02_mitigations-vbs-hvci-vtrp\MITIGATION_MATRIX.md`
- `02_mitigations-vbs-hvci-vtrp\RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`
- `03_byovd\00_index-and-matrix\BYOVD_RECENT_WRITEUPS.md`
- `03_byovd\00_index-and-matrix\BYOVD_PRIMITIVE_MATRIX.md`
- `03_byovd\00_index-and-matrix\BYOVD_BLOCKLIST_AND_REACHABILITY.md`
- `03_byovd\99_workflow\NEW_DRIVER_REVERSING_WORKFLOW.md`
- `04_connor-mcgarr-study\CONNOR_MCGARR_WINDOWS_KERNEL_DEEP_RESEARCH.md`
- `04_connor-mcgarr-study\01_PAGING_AND_PTE_DEEP_DIVE.md`
- `04_connor-mcgarr-study\02_SMEP_NX_PTE_BYPASS_CONCEPTS.md`
- `04_connor-mcgarr-study\04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`
- `04_connor-mcgarr-study\06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md`
- `04_connor-mcgarr-study\07_HVCI_EXISTING_CODE_INVOCATION.md`
- `05_global-research-map\GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md`

## Current Scope

This resource is a Windows kernel exploitation / BYOVD research handbook focused on:

- Windows kernel mitigations by version and year.
- VBS/HVCI/KDP/CET/kCFG/PatchGuard impact.
- `_EPROCESS` offsets and offset acquisition strategy.
- Physical memory R/W primitives.
- Virtual kernel R/W primitives.
- MSR read/write primitives.
- Process-killer BYOVD primitives.
- `PreviousMode` and limited-write primitives.
- Pool, Win32k, CLFS, Object Manager, ALPC/RPC/COM, token/PPL and detection topics.
- Driver review and reverse-engineering workflow.

## Core Handbook

### `01_core-handbook\WINDOWS_KERNEL_EXPLOIT_RESEARCH.md`

General handbook. Contains:

- Mitigation timeline from XP/Vista/Win7 through Windows 11 24H2/25H2.
- EPROCESS offset table for major Windows builds.
- Primitive taxonomy.
- Pool exploitation notes.
- BYOVD landscape.
- Windows release/build matrix.
- Mitigation layers.
- How to enumerate mitigation state.
- Offset acquisition workflow.
- Attack surface taxonomy.
- CLFS/Object Manager/I/O Manager/ALPC/Win32k/PPL/rootkit/firmware tracks.
- Learning roadmap.

## Mitigations / VBS / HVCI / VT-rp

### `02_mitigations-vbs-hvci-vtrp\VT_RP_HLAT_DEEP_DIVE.md`

Vietnamese deep-dive explaining Satoshi Tanda's Intel VT-rp Part 1/2 posts and related links.

Contains:

- LA/GPA/PA concepts.
- x64 paging.
- EPT/SLAT.
- VBS/VTL0/VTL1.
- HVCI vs KDP.
- KDP read-only data protection.
- Remapping/page swapping attack.
- `ci!g_CiOptions` demo concept.
- Intel VT-rp overview.
- HLAT and HLATP.
- HLAT prefix size and Restart bit.
- PW/PWA.
- GPV/VGP.
- Remapping vs aliasing.
- Why data remapping is easier than code remapping.
- SMEP/MBEC/kCFG/CET relation.
- Connection to ASTRA64/physical R/W/BYOVD.
- Study roadmap.

### `02_mitigations-vbs-hvci-vtrp\CONNOR_HVCI_KCFG_DEEP_DIVE.md`

Vietnamese deep-dive explaining Connor McGarr's HVCI/kCFG post.

Contains:

- Token stealing baseline.
- HVCI, VBS, VTL0/VTL1, SLAT/EPT.
- MBEC and RUM.
- Why PTE shellcode tricks fail under HVCI.
- Why data-only token stealing remains possible.
- Why token stealing is less powerful than arbitrary kernel API invocation.
- Dummy thread model.
- KTHREAD leak through handle information.
- Kernel stack control.
- kCFG forward-edge protection.
- Why return address overwrite avoids kCFG.
- Why kCET/shadow stack would break this route.
- ROP chain as HVCI-compliant existing-code invocation.
- IRQL, SMAP, stack alignment, Windows x64 calling convention.
- Why `ZwTerminateThread` is used for cleanup.
- Relation to VT-rp and ASTRA64 direct DKOM.

### `02_mitigations-vbs-hvci-vtrp\MITIGATION_MATRIX.md`

Windows kernel mitigation matrix organized by version, layer and exploit primitive.

Contains:

- Version timeline from XP SP2/Server 2003 SP1 through Windows 11 25H2/current servicing era.
- Layer model: CPU, hypervisor/VBS, memory manager, control-flow, object policy, driver load policy and telemetry.
- Per-mitigation notes for DEP/NX, KASLR, KMCS, PatchGuard, NonPagedPoolNx, SMEP, SMAP, kCFG, CET/kernel shadow stack, VBS, HVCI, KDP, VT-rp/HLAT, PPL and WDAC/blocklist.
- Primitive-vs-mitigation matrix for token DKOM, `PreviousMode`, physical R/W, virtual R/W, process-kill BYOVD, MSR hijack, pool shellcode, ROP and page remapping attacks.
- Practical Windows version view for Windows 7, 8/8.1, Windows 10 and Windows 11 22H2+.
- Checklist for recording mitigation state when reading or testing a writeup.

### `02_mitigations-vbs-hvci-vtrp\RW_PRIMITIVES_VS_HVCI_DEEP_DIVE.md`

Deep dive for the current focus: what to do when a virtual or physical R/W primitive exists under HVCI/VBS.

Contains:

- Clarifies that most public "HVCI bypass" chains avoid HVCI's scope rather than directly breaking HVCI.
- Explains VTL0/VTL1, guest PTE, GPA, EPT/SLAT and why physical R/W from VTL0 is not outside the hypervisor.
- Compares virtual kernel R/W and physical memory R/W:
  - virtual R/W is easier for object-level final exploitation,
  - physical R/W is stronger for discovery, CR3/page-table introspection, KASLR recovery and VA->PA bridging,
  - neither automatically bypasses KDP/HVCI-protected pages.
- Technique families:
  - data-only DKOM,
  - token swap,
  - `PreviousMode`,
  - primitive upgrade through trusted kernel objects,
  - physical-to-virtual R/W conversion,
  - existing-code invocation,
  - PTE/page-table manipulation,
  - remapping/page swapping,
  - DSE/CI tamper,
  - MSR/syscall path hijack,
  - process-kill/semantic BYOVD.
- Ranking by stability, HVCI pressure, BSOD risk and version sensitivity.
- Checklist to add to every per-driver writeup.

## BYOVD Index

Folder:

```text
03_byovd\00_index-and-matrix
```

Files:

- `README.md`
- `BYOVD_RECENT_WRITEUPS.md`
- `BYOVD_PRIMITIVE_MATRIX.md`
- `BYOVD_BLOCKLIST_AND_REACHABILITY.md`

Main grouping:

- Physical R/W: ASTRA64, Lenovo, ThrottleStop, eneio64, pstrip64.
- Virtual kernel R/W: RTCore64, dbutil, DsArk64.
- Limited primitive: AsIO3 decrement -> `PreviousMode`.
- MSR read/write: WinRing0, Lenovo, eneio64, gdrv.
- Process-kill: K7RKScan, BdApiUtil, TfSysMon, Zemana.

Reliability ranking, generally:

1. Process-kill IOCTL against non-critical target.
2. Virtual R/W token swap with validated offsets.
3. Physical R/W token swap with validated VA->PA.
4. Limited primitive to `PreviousMode`, on supported Windows build.
5. Callback/PPL tamper.
6. PTE/code patch.
7. MSR syscall hijack.

### `03_byovd\00_index-and-matrix\BYOVD_BLOCKLIST_AND_REACHABILITY.md`

Deep dive explaining how to evaluate a BYOVD candidate beyond "has CVE".

Contains:

- Loadability, reachability and usefulness model.
- Microsoft blocklist limitations.
- Hardware-gating and device-object reachability from Atos research.
- NDSS/EURECOM dynamic BYOVD taxonomy and measurement takeaways.
- Check Point Truesight case: legacy version gap, variant mutation, blocklist update.
- Driver scoring model.
- Per-driver reachability template to add to future writeups.

## BYOVD Per-Primitive Write-ups

### Physical Memory R/W

Folder:

```text
03_byovd\01_physical-memory-rw
```

Files:

- `ASTRA64_RW_CODE_WALKTHROUGH.md`
- `ASTRA64_DIRECT_DKOM_DEEP_DIVE.md`
- `LENOVO_LNVMSRIO_DEEP_DIVE.md`
- `THROTTLESTOP_PHYSICAL_RW_DEEP_DIVE.md`
- `ENEIO64_PHYSICAL_RW_DEEP_DIVE.md`
- `PSTRIP64_POWERSTRIP_DEEP_DIVE.md`

Key conclusions:

- Physical R/W is powerful but not automatically useful until VA->PA/object discovery is solved.
- ASTRA64 exposes physical mapping and MSR read.
- Direct DKOM token swap is usually more practical than shadow SSDT/Win32k hijack for simple LPE.
- Main risks: wrong CR3, wrong `_EPROCESS` offset, wrong physical mapping, protected physical page, failed token restore.
- MSR read is useful for `IA32_LSTAR`/KASLR; MSR write is usually more crash-prone than data-only writes.

### Virtual Kernel R/W

Folder:

```text
03_byovd\02_virtual-kernel-rw
```

Files:

- `RTCORE64_MSI_AFTERBURNER_DEEP_DIVE.md`
- `DBUTIL_2_3_DELL_DEEP_DIVE.md`
- `DSARK64_QIHOO_DEEP_DIVE.md`

Key conclusions:

- Virtual kernel R/W is often easier to weaponize than physical R/W because no VA->PA bridge is needed.
- DsArk64 combines process kill, virtual kernel read, virtual kernel write and module enum/KASLR leak.
- dbutil/gdrv-style OEM drivers remain archetypal BYOVD examples because trusted deployment made them useful in real environments.

### Process Kill

Folder:

```text
03_byovd\03_process-kill
```

Files:

- `K7RKSCAN_CODE_WALKTHROUGH.md`
- `K7RKSCAN_PROCESS_KILLER_DEEP_DIVE.md`
- `BDAPIUTIL64_CODE_WALKTHROUGH.md`
- `BDAPIUTIL64_PROCESS_KILLER_DEEP_DIVE.md`
- `ZEMANA_TERMINATOR_DEEP_DIVE.md`
- `TFSYSMON_THREATFIRE_DEEP_DIVE.md`

Key conclusions:

- Process-killer BYOVD is narrow but operationally valuable.
- It is generally less OS-version-sensitive than token DKOM because it depends on driver protocol, not Windows offsets.
- Main risk is killing a critical process or triggering vendor/self-protection instability.

### Limited Primitives

Folder:

```text
03_byovd\04_limited-primitives
```

Files:

- `ASIO3_PREVIOUSMODE_DEEP_DIVE.md`

Key conclusions:

- AsIO3 is not physical R/W.
- It uses auth bypass + decrement primitive.
- Target is `KTHREAD.PreviousMode`: decrement `UserMode` 1 to `KernelMode` 0.
- Then normal `NtReadVirtualMemory`/`NtWriteVirtualMemory` style APIs can become kernel R/W.
- This is version-sensitive and requires restore.

### MSR / Multi-Primitive

Folder:

```text
03_byovd\05_msr-and-multi-primitive
```

Files:

- `WINRING0_AWESOME_MINER_MSR_DEEP_DIVE.md`
- `GDRV_GIGABYTE_DEEP_DIVE.md`

Key conclusions:

- MSR write can hijack syscall entry but is high-risk and BSOD-prone.
- MSR read is useful as a KASLR anchor.
- Multi-primitive drivers should be analyzed by choosing the most stable primitive, not the flashiest primitive.

## Workflow

Folder:

```text
03_byovd\99_workflow
```

Files:

- `NEW_DRIVER_REVERSING_WORKFLOW.md`

Purpose:

- Checklist for triaging a new driver.
- How to identify device names, IOCTLs, buffer formats, primitive class, exploitability and stability risk.

## Connor McGarr Study Track

Folder:

```text
04_connor-mcgarr-study
```

Files:

- `README.md`
- `CONNOR_MCGARR_WINDOWS_KERNEL_DEEP_RESEARCH.md`
- `01_PAGING_AND_PTE_DEEP_DIVE.md`
- `02_SMEP_NX_PTE_BYPASS_CONCEPTS.md`
- `04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`
- `06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md`
- `07_HVCI_EXISTING_CODE_INVOCATION.md`

Scope:

- Connor McGarr paging, SMEP, write-what-where, XFG, pool exploitation, KUSER_SHARED_DATA and HVCI posts.
- Explains concepts in Vietnamese with "why" questions and Windows 11 24H2/25H2-era mitigation framing.
- Focuses on exploit-thinking, mitigation interaction and research checklists rather than copying weaponized PoC code.

Key conclusions:

- Paging/PTE knowledge is the common foundation for SMEP/NX bypasses, physical R/W translation, KUSER_SHARED_DATA mappings and HVCI limitations.
- Modern Windows exploit thinking should separate code execution, data-only corruption, existing-code reuse and driver-load policy.
- HVCI blocks unsigned/new kernel code execution but does not automatically stop mutable-data corruption through allowed signed drivers.
- kCFG/XFG-style mitigations protect forward-edge indirect calls; CET/shadow stack protects return-address abuse.
- Pool exploitation in the segment heap/kLFH era is mainly object selection, layout grooming and leak engineering.

## Global Research Map

Folder:

```text
05_global-research-map
```

Files:

- `README.md`
- `GLOBAL_WINDOWS_KERNEL_HVCI_BYOVD_SOURCE_MAP.md`

Scope:

- Maps international Windows kernel / HVCI / BYOVD sources by country/region, lab, vendor class and technique family.
- Separates research-source country, driver-vendor country, threat-actor geography and victim geography.
- Includes United States, France, Singapore, United Kingdom, Israel, Canada, Japan/Taiwan, China, South Korea/North Korea, Slovakia/Czech Republic, Germany, Romania, Russia, Netherlands/Belgium and broader Europe.
- Provides next-output priorities:
  - `BYOVD_BLOCKLIST_AND_REACHABILITY.md`
  - `PROCESS_KILL_VS_RW_BYOVD_DEEP_DIVE.md`
  - `PHYSICAL_RW_DRIVER_EXPLOITABILITY_MODEL.md`
  - `DRIVER_VENDOR_CLASS_THREAT_MODEL.md`

Key conclusions:

- BYOVD/HVCI research is global and crosses Microsoft platform hardening, OEM/security/hardware driver ecosystems, threat actor operations and academic measurement.
- The central current question is not only "does the driver have a primitive?" but "is the vulnerable path reachable, allowed to load, and useful under HVCI/KDP/CET/WDAC?"
- Physical R/W remains powerful but does not automatically escape VBS/SLAT.
- Process-kill primitives remain valuable because many real campaigns only need to disable security controls.

## Important Engineering Conclusions

- HVCI/VBS do not make unsafe signed driver IOCTL semantics safe.
- Physical memory map R/W is strong, but object discovery and translation decide practical value.
- Virtual kernel R/W is usually the most convenient general-purpose BYOVD primitive.
- Data-only attacks remain important because modern mitigations focus heavily on preventing unsigned code execution.
- `PreviousMode` abuse shows weak primitives can be powerful if they hit the right semantic field.
- WDAC/blocklist/driver inventory are primary controls for BYOVD.
- kCFG constrains indirect calls, but return-address/ROP style control lives in a different mitigation space.
- kCET/shadow stack is important because it attacks return-address tampering directly.
- VT-rp/HLAT is conceptually valuable because it targets remapping/page-swapping attacks that bypass classic read-only page assumptions.

## Source Repositories / Pages Used

Important sources referenced:

- BlackSnufkin BYOVD: https://github.com/BlackSnufkin/BYOVD
- BlackSnufkin Astra64-RW: https://github.com/BlackSnufkin/BYOVD/tree/main/Astra64-RW
- BlackSnufkin K7Terminator: https://github.com/BlackSnufkin/BYOVD/tree/main/K7Terminator
- BlackSnufkin BdApiUtil-Killer: https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer
- BlackSnufkin TfSysMon-Killer: https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer
- Satoshi Tanda VT-rp Part 1: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html
- Satoshi Tanda VT-rp Part 2: https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html
- Connor McGarr HVCI/kCFG: https://connormcgarr.github.io/hvci/
- Quarkslab Lenovo CVE-2025-8061: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- Quarkslab Lenovo part 2: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html
- xacone eneio64: https://xacone.github.io/eneio-driver.html
- jeffaf AsIO3: https://github.com/jeffaf/CVE-2025-3464-AsIO3-LPE
- D7EAD CVE-2025-63602: https://github.com/D7EAD/CVE-2025-63602
- VoidSec Dell dbutil: https://voidsec.com/reverse-engineering-and-exploiting-dell-cve-2021-21551/
- Amit Moshel gdrv: https://amitmoshel1.github.io/posts/exploiting-gdrv-sys-a-vulnerable-gigabyte-driver/
- LOLDrivers DsArk64 issue #308: https://github.com/magicsword-io/LOLDrivers/issues/308
- LOLDrivers Astra64 issue #294: https://github.com/magicsword-io/LOLDrivers/issues/294
- VoidSec Zemana/Terminator: https://voidsec.com/reverse-engineering-terminator-aka-zemana-antimalware-antilogger-driver/
- Microsoft recommended driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules
- LOLDrivers database: https://www.loldrivers.io/
- Microsoft Win32k syscall disable policy: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-process_mitigation_system_call_disable_policy
- Tarjei Mandt Win32k callback paper: https://media.blackhat.com/bh-us-11/Mandt/BH_US_11_Mandt_win32k_WP.pdf
- Bluefrost GDI primitive evolution: https://labs.bluefrostsecurity.de/publications/2017/10/02/abusing-gdi-for-ring0-exploit-primitives-evolution/
- Unit42 Win32k analysis part 1: https://unit42.paloaltonetworks.com/win32k-analysis-part-1/

## Local Source Checkout

Partial sparse checkout exists at:

```text
90_sources\_source\BYOVD
```

Checked source included:

- `Astra64-RW\src\*.rs`
- `K7Terminator\src\main.rs`
- `BdApiUtil-Killer\src\main.rs`
- `TfSysMon-Killer\src\main.rs`
- `byovd-lib\src\*.rs`

## Suggested Next Work

- Add `DirectIo64.sys` deep-dive if a verified public exploit/write-up is found.
- Add `mhyprot2.sys` deep-dive.
- Add `aswArPot.sys` / Avast anti-rootkit BYOVD case.
- Add `zamguard64` exact IOCTL/code-path details if stronger primary source is found.
- Add `OFFSETS_AND_SYMBOLS.md` with automated PDB/Vergilius offset workflow.
- Add `DETECTION_HUNTING.md` with Sysmon/MDE/WDAC queries.
- Add `CLFS_RESEARCH.md` as a separate non-BYOVD track.
- Split remaining Connor study notes into WWW target selection and KUSER_SHARED_DATA mapping-specific files.

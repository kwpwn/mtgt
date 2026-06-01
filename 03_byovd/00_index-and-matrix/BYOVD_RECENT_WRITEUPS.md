# Recent BYOVD Write-ups and Exploit Technique Notes

Scope: Windows BYOVD cases with recent write-ups, public PoC/exploit repositories, or detailed public technical notes. This file explains the technique and defensive relevance. It intentionally avoids reproducing exploit source code, exact trigger buffers, or run commands.

## Quick Index

Per-driver code walkthroughs based on repository source are now grouped by primitive under `03_byovd\01_physical-memory-rw`, `03_byovd\02_virtual-kernel-rw`, `03_byovd\03_process-kill`, `03_byovd\04_limited-primitives`, and `03_byovd\05_msr-and-multi-primitive`.

Chinese-language source-mining for abused drivers and malware campaigns is tracked separately in `BYOVD_CHINA_SOURCE_MAP.md`. That file keeps campaign/source links and defensive summaries while deliberately omitting exact IOCTL values, trigger buffers, and PoC steps.

| Case | Driver | Vendor/product | Public material | Primitive | Impact theme |
|---|---|---|---|---|---|
| Astra64-RW | `ASTRA64.sys` | EnTech Taiwan Astra32 / TVicHW | BlackSnufkin repo | Physical memory R/W, MSR read | HVCI/VBS-aware physical-memory BYOVD |
| CVE-2025-8061 | `LnvMSRIO.sys` | Lenovo Dispatcher | Quarkslab write-up, PoCs | Physical memory R/W, MSR R/W | Ring-0 capability through signed Lenovo driver |
| CVE-2025-7771 | `ThrottleStop.sys` | TechPowerUp ThrottleStop | poh0 write-up, PoC refs | Physical memory R/W via `MmMapIoSpace` | Ransomware/AV-killer BYOVD |
| CVE-2025-63602 | `IntelliBreeze.Maintenance.Service.sys` / WinRing0 | Awesome Miner | DreadSec write-up + GitHub PoC | MSR read/write | Syscall path / MSR abuse |
| CVE-2025-61156 | `TfSysMon.sys` | ThreatFire System Monitor | D7EAD repo | Kernel-privileged process termination | EDR/PPL process kill |
| CVE-2025-52915 / CVE-2025-1055 | `K7RKScan.sys` | K7 Ultimate Security | BlackSnufkin write-up + repo | Kernel process termination | LPE/BYOVD dual mode |
| CVE-2026-29923 | `pstrip64.sys` | EnTech Taiwan PowerStrip | GitHub disclosure | Physical memory mapping | Token/data-only LPE concept |
| CVE-2020-12446, 2025 write-up | `eneio64.sys` | G.SKILL Trident Z Lighting Control | xacone write-up + exploit repo | Physical memory R/W, MSR, port I/O | Virtual-to-physical bridge on Win11/HVCI |
| CVE-2024-51324 | `BdApiUtil64.sys` | Baidu Antivirus | BlackSnufkin repo | Process termination | Process-killer BYOVD pattern |
| CVE-2025-52347 | `DirectIo64.sys` | PassMark tools | advisories, no verified public PoC seen | Kernel memory R/W | Watchlist, hardware-access driver risk |

## 1. Astra64-RW - EnTech Taiwan `ASTRA64.sys`

Source:

- https://github.com/BlackSnufkin/BYOVD/tree/main/Astra64-RW
- LOLDrivers issue mentioned by the repo: https://github.com/magicsword-io/LOLDrivers/issues/294

What makes it interesting:

- This is close to the style you pointed at: self-contained repo, driver included, README explains the exploit engineering.
- The driver exposes access to physical memory through a user-reachable IOCTL without caller authentication.
- It also exposes MSR read capability.
- The public PoC is notable because it was tested on a current Windows 11 24H2/25H2-style system with HVCI/VBS enabled.

Technique summary:

- The driver gives a physical-memory primitive rather than a direct virtual kernel memory primitive.
- The exploit must bridge physical memory to useful kernel virtual objects. The repo describes finding page-table context, deriving kernel base from syscall-related information, and resolving kernel/Win32k structures dynamically.
- Instead of a simple hardcoded token overwrite, the PoC uses a temporary kernel dispatch redirection to call a legitimate memory-copy gadget in kernel context, then restores the modified state.
- The visible payload is a SYSTEM token transfer to the caller context.

Why the primitive bypasses some modern assumptions:

- HVCI protects kernel virtual code/data through virtualization-backed policy, but this class writes through physical-memory exposure provided by a signed driver.
- VBS/HVCI do not magically make a driver safe if the driver itself exposes `\Device\PhysicalMemory`-style access.
- The key defensive control becomes driver load prevention, driver blocklist/WDAC, and vendor remediation.

Defensive notes:

- Hunt for `ASTRA64.sys` and Astra32/TVicHW driver artifacts on hosts where the software is not approved.
- Monitor unexpected process opens to the driver device object.
- Track driver hash and signer. The repo lists the SHA256 and signer.
- Add explicit WDAC deny rules where Microsoft blocklist/LOLDrivers lag.

## 2. Lenovo `LnvMSRIO.sys` - CVE-2025-8061

Sources:

- https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- https://support.lenovo.com/us/en/product_security/LEN-200860
- https://github.com/spawn451/CVE-2025-8061-Exploit
- https://github.com/segura2010/lenovo-dispatcher-poc

What makes it interesting:

- Modern, signed OEM driver.
- Quarkslab explicitly frames it as BYOVD research and tests against a recent Windows 11 environment.
- The driver exposes privileged hardware-facing operations such as physical memory and MSR access.

Technique summary:

- The root issue is insufficient access control around privileged IOCTLs.
- The useful primitives include physical memory R/W and MSR R/W.
- MSR read can reveal syscall-entry related kernel addresses and assist KASLR bypass.
- MSR write can, in unsafe lab chains, redirect CPU syscall behavior. This is powerful but unstable and very visible.
- A more robust exploit normally tries to turn low-level primitives into data-only kernel object manipulation or controlled kernel execution with cleanup.

Mitigation interaction:

- Driver Signature Enforcement does not help if the driver is legitimately signed.
- HVCI can make classic kernel shellcode paths harder, but it does not remove the danger of MSR/physical-memory primitives.
- Blocklist/WDAC policy is the practical control once a driver becomes known bad.

Defensive notes:

- Inventory Lenovo Dispatcher driver versions.
- Version 3.2 is reported as not affected by Lenovo; older 3.0/3.1 branches should be updated.
- Hunt for service creation/loading of `LnvMSRIO.sys` outside expected Lenovo software context.
- Alert on unsigned/untrusted user-mode tools interacting with Lenovo driver device objects.

## 3. ThrottleStop `ThrottleStop.sys` - CVE-2025-7771

Sources:

- https://www.poh0.dev/windows/driver/vulnerability/2025/09/22/throttlestop-vulnerable-driver/
- https://github.com/advisories/GHSA-f8p7-vvxp-hcxv
- https://github.com/Demoo1337/ThrottleStop
- https://hivepro.com/threat-advisory/medusalocker-uses-throttlestop-sys-flaw-to-kill-av-on-windows/

What makes it interesting:

- This is a good modern example where a consumer utility driver becomes ransomware tradecraft.
- Public reporting says MedusaLocker/Gentlemen-style AV killer activity abused the driver, sometimes under renamed filenames.
- The PoC write-up focuses on turning exposed physical memory access into useful kernel object analysis.

Technique summary:

- The driver exposes IOCTL interfaces that allow arbitrary physical memory read/write via `MmMapIoSpace`.
- The hard part is not merely "write memory"; it is identifying the right physical pages for target kernel objects.
- The poh0 write-up discusses using Windows memory-manager knowledge, process structure reading, module-base discovery, and VAD traversal.
- This case is useful for learning the gap between physical-memory primitive and reliable virtual-object manipulation.

Defensive notes:

- Hunt for `ThrottleStop.sys` and renamed copies such as ransomware-specific aliases.
- Treat use of ThrottleStop on enterprise endpoints as high risk unless explicitly approved.
- Endpoint controls should alert on driver load plus rapid process termination of AV/EDR services.
- Add hash/path/signature-based WDAC rules rather than only relying on process name.

## 4. Awesome Miner WinRing0 rename - CVE-2025-63602

Sources:

- https://dreadsec.co/p/cve-2025-63602-hijacking-system-calls-with-a-popular-crypto-miner.html
- https://github.com/D7EAD/CVE-2025-63602
- https://vulmon.com/vulnerabilitydetails?qid=CVE-2025-63602

What makes it interesting:

- The driver is essentially WinRing0 1.2.0.5 renamed as an Awesome Miner helper.
- The root problem is not a novel memory corruption bug; it is unsafe privileged functionality exposed through weak access control.
- The public PoC demonstrates MSR abuse as a proof of impact.

Technique summary:

- MSR read leaks privileged CPU state, including syscall-entry related addresses.
- MSR write is a very strong primitive because it can influence CPU control flow.
- This class can be used for denial of service, kernel execution research, and potentially LPE depending on chain quality.
- MSR-based chains are usually less stable and more detectable than data-only object modification.

Key lesson:

- "WinRing0 embedded under another product name" is a recurring BYOVD pattern.
- Auditing only filenames misses renamed vulnerable drivers. Hash, signer, version resources, imports, and device object names matter.

Defensive notes:

- Hunt for WinRing0-derived drivers by hash and behavior, not just exact filename.
- Monitor access to driver symbolic links associated with WinRing0-style APIs.
- Crypto-mining/admin utilities should not be present on normal enterprise workstations.

## 5. ThreatFire `TfSysMon.sys` - CVE-2025-61156

Sources:

- https://github.com/D7EAD/CVE-2025-61156
- https://www.cve.org/CVERecord?id=CVE-2025-61156

What makes it interesting:

- Unlike physical-memory R/W cases, this one is a kernel-privileged operation abuse case.
- It exposes arbitrary process termination with kernel privileges.
- The repo states low-privileged users can terminate PPL and security processes due to missing DACL restrictions.

Technique summary:

- The driver has a privileged "terminate process" capability intended for a security product.
- Because user-mode access is not restricted correctly, a non-admin caller can ask the driver to perform privileged termination.
- The result is not arbitrary kernel R/W, but it is still operationally valuable: EDR bypass, AV kill, denial of service.

Why it matters:

- BYOVD does not require arbitrary memory R/W to be dangerous.
- Process-kill primitives are enough for many ransomware/operator playbooks.
- PPL is not meaningful if a trusted kernel driver will terminate the PPL process on behalf of an untrusted caller.

Defensive notes:

- Hunt for `TfSysMon.sys` and the SHA256 listed in the repo.
- Track unexpected termination attempts against security processes.
- Enforce WDAC and vulnerable driver deny rules for obsolete security-product drivers.

## 6. K7 `K7RKScan.sys` - CVE-2025-52915 / CVE-2025-1055

Sources:

- https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/
- https://github.com/BlackSnufkin/BYOVD/tree/main/K7Terminator

What makes it interesting:

- BlackSnufkin documents an "evolution" story: legacy builds allowed low-privileged abuse, current builds changed the operational model but remained BYOVD-abusable.
- The repo supports two modes conceptually: wait for a legitimate service to load the driver, or load the vulnerable driver as BYOVD.
- It is a clean example of "kernel process killer" rather than memory-R/W exploit.

Technique summary:

- The vulnerable driver exposes process termination functionality through IOCTL.
- Legacy access control allowed lower-privileged users to call into the driver.
- Current attack model depends on attacker ability to load/use the signed vulnerable driver, then terminate protected/security processes.

Key lesson:

- Vendor "fixed one access path" does not always remove BYOVD usefulness if the driver still exposes dangerous kernel operations.
- BYOVD evaluation must ask: if an attacker can load this driver, what privileged operations become reachable?

Defensive notes:

- Track both legacy and current `K7RKScan.sys` hashes.
- Vendor update is necessary but may not be enough if old signed versions remain loadable.
- Add deny policies for obsolete builds.

## 7. PowerStrip `pstrip64.sys` - CVE-2026-29923

Sources:

- https://github.com/Smarttfoxx/CVE-2026-29923
- https://vulmon.com/vulnerabilitydetails?qid=CVE-2026-29923

What makes it interesting:

- Very similar family to Astra64: EnTech Taiwan hardware utility driver exposing physical-memory mapping.
- The write-up states a public PoC was developed but code was not released to avoid misuse.
- It connects a modern issue to older PowerStrip driver bugs.

Technique summary:

- The driver opens `\Device\PhysicalMemory` and maps caller-controlled physical ranges into the current process.
- That primitive allows scanning physical RAM for process structures and modifying security-relevant fields.
- The write-up describes token-focused LPE at the conceptual level.

Defensive notes:

- Hunt for `pstrip64.sys`, PowerStrip installs, and `PSTRIP64` device names.
- Legacy hardware utility drivers should be removed from non-lab endpoints.
- Add deny rules for affected versions because the vendor/product is old and unlikely to be broadly needed.

## 8. `eneio64.sys` / `ene.sys` - CVE-2020-12446, modern 2025 write-up

Sources:

- https://xacone.github.io/eneio-driver.html
- https://www.hendryadrian.com/eneio-driver/
- https://www.loldrivers.io/

What makes it interesting:

- The CVE is older, but the 2025 write-up is modern and explicitly tests Windows 11/HVCI conditions.
- It is a strong learning case for translating physical memory primitives into virtual kernel memory operations.
- The driver exposes physical memory mapping, MSR access, and port I/O.

Technique summary:

- The exploit obtains physical-memory R/W from the driver.
- It derives the page-table base and walks page tables to translate kernel virtual addresses into physical addresses.
- Once virtual-to-physical translation is solved, the driver behaves like a virtual kernel R/W primitive.
- The payload can be data-only, such as token manipulation, instead of raw kernel shellcode.

Why this is useful:

- This case explains the missing middle layer many BYOVD summaries skip: physical primitive -> virtual object primitive.
- It is directly relevant to Astra64, pstrip64, ThrottleStop and many hardware utility drivers.

Defensive notes:

- Hunt driver hashes from LOLDrivers.
- HVCI-compatible does not mean safe if the driver exposes physical memory.
- Block known vulnerable physical-memory utility drivers even when they are signed.

## 9. Baidu `BdApiUtil64.sys` - CVE-2024-51324

Source:

- https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer

What makes it interesting:

- This is a minimal process-killer style BYOVD PoC.
- The README states that as of June 2025 the driver was not listed in LOLDrivers or Microsoft recommended block rules.
- It uses BlackSnufkin's shared BYOVD library pattern, making it useful to compare with the other `*-Killer` modules.

Technique summary:

- The driver exposes a privileged operation that can be used to terminate a target process.
- The exploit wrapper normalizes driver loading, device interaction and target process selection.
- This represents the commodity BYOVD pattern: many drivers, one common operator abstraction.

Defensive notes:

- Do not only hunt for one famous driver like `dbutil_2_3.sys` or `RTCore64.sys`.
- Build detections around behavior: service creation, driver load, new device handle, security process termination.

## 10. PassMark `DirectIo64.sys` - CVE-2025-52347

Sources:

- https://www.sentinelone.com/vulnerability-database/cve-2025-52347/
- https://whiteknightlabs.com/2025/06/17/understanding-arbitrary-access-primitives-in-windows-kernel/

Status:

- I found advisories and technical descriptions, but no verified public exploit repository in the quick search.
- Keep this in a watchlist rather than treating it like Astra64/K7/ThrottleStop where public PoC material is clearer.

Technique summary:

- Affected PassMark products ship `DirectIo64.sys` for low-level hardware access.
- Public advisories describe unsafe IOCTL handling that can expose kernel memory read/write.
- Historically, DirectIO-family drivers have appeared in BYOVD and physical-memory research because they bridge user mode to hardware/kernel operations.

Defensive notes:

- Inventory PassMark tools on workstations and forensic/admin jump boxes.
- Alert if non-PassMark processes open the DirectIO device object.
- Patch to fixed builds or remove the tools from endpoints where not needed.

## Technique taxonomy from these cases

| Technique class | Cases | Core risk | Defensive priority |
|---|---|---|---|
| Physical memory mapping/RW | Astra64, ThrottleStop, pstrip64, eneio64, Lenovo | Bypasses virtual memory assumptions and can become arbitrary kernel object access | Block vulnerable signed drivers; hunt physical-memory APIs |
| MSR read/write | Lenovo, Awesome Miner/WinRing0, eneio64 | KASLR leak, syscall path tamper, crash/code-exec potential | Block WinRing0-class drivers; detect MSR helper drivers |
| Process termination | K7, ThreatFire, BdApiUtil | Kill AV/EDR/PPL/security processes without full kernel R/W | Detect security process kill sequences and driver load |
| Weak DACL/device access | Awesome Miner, ThreatFire, K7 legacy | Low-privileged caller can access privileged driver device | Audit device SDDL and restrict device object ACLs |
| Driver not in blocklist yet | Astra64, BdApiUtil, ThreatFire claims | Microsoft/LOLDrivers lag leaves exploit window | Maintain local WDAC deny list |
| Renamed known-bad component | Awesome Miner WinRing0, ThrottleStop renamed in attacks | Filename-based detection fails | Hash/import/device-name/signature behavior hunting |

## How to analyze a new BYOVD repo like Astra64-RW

Use this repeatable read-through:

1. Identify the driver: filename, vendor, signer, hash, version, product family.
2. Identify exposed device object and symbolic link.
3. Determine caller access: admin-only, low-privileged, service-loaded timing window, or attacker-loaded BYOVD.
4. Classify primitive:
   - Physical memory map/RW
   - Virtual memory R/W
   - MSR read/write
   - Port I/O
   - Process/thread/object operation
   - Callback/filter tamper
5. Identify exploit bridge:
   - Physical -> virtual translation
   - MSR -> KASLR/control-flow
   - Process-kill -> EDR/PPL bypass
   - Limited write -> token/PreviousMode/I/O ring/WNF
6. Identify mitigation assumptions:
   - HVCI/VBS on or off
   - Vulnerable driver blocklist status
   - WDAC/App Control
   - Secure Boot
7. Extract detection points:
   - Driver load event
   - Service creation
   - Device open
   - IOCTL pattern if telemetry exists
   - Security process tamper
   - SYSTEM child process from unexpected parent

## Hunting ideas

- Maintain a local denylist for drivers in this file even before Microsoft blocklist catches up.
- Use Sysmon Event ID 6 or MDE DeviceTvmSoftwareVulnerabilities/DeviceEvents-style telemetry for driver loads.
- Correlate driver load with:
  - new kernel service creation,
  - unsigned/suspicious user-mode controller,
  - handle open to a hardware utility device,
  - AV/EDR process termination,
  - token/PPL anomaly,
  - new SYSTEM shell/process.
- Normalize by signer and product category. Hardware monitoring, overclocking, RGB, antivirus, crypto-mining and forensic/admin tools are high-risk BYOVD buckets.

## Source list

- BlackSnufkin BYOVD root: https://github.com/BlackSnufkin/BYOVD
- Astra64-RW: https://github.com/BlackSnufkin/BYOVD/tree/main/Astra64-RW
- K7Terminator: https://github.com/BlackSnufkin/BYOVD/tree/main/K7Terminator
- BdApiUtil-Killer: https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer
- BlackSnufkin CVE-2025-52915 write-up: https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/
- Quarkslab Lenovo CVE-2025-8061: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- Lenovo advisory LEN-200860: https://support.lenovo.com/us/en/product_security/LEN-200860
- ThrottleStop write-up: https://www.poh0.dev/windows/driver/vulnerability/2025/09/22/throttlestop-vulnerable-driver/
- ThrottleStop GitHub advisory: https://github.com/advisories/GHSA-f8p7-vvxp-hcxv
- DreadSec CVE-2025-63602: https://dreadsec.co/p/cve-2025-63602-hijacking-system-calls-with-a-popular-crypto-miner.html
- D7EAD CVE-2025-63602 repo: https://github.com/D7EAD/CVE-2025-63602
- D7EAD CVE-2025-61156 repo: https://github.com/D7EAD/CVE-2025-61156
- PowerStrip CVE-2026-29923 repo: https://github.com/Smarttfoxx/CVE-2026-29923
- eneio64 write-up: https://xacone.github.io/eneio-driver.html
- PassMark DirectIo64 advisory: https://www.sentinelone.com/vulnerability-database/cve-2025-52347/
- White Knight Labs arbitrary primitives overview: https://whiteknightlabs.com/2025/06/17/understanding-arbitrary-access-primitives-in-windows-kernel/
- Microsoft recommended driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules
- LOLDrivers: https://www.loldrivers.io/

## Deep Dive 1. Astra64-RW / `ASTRA64.sys`

Driver type: hardware/system information driver from EnTech Taiwan, used by Astra32 / TVicHW-style tooling.

Primitive exposed:

- Physical memory section access.
- MSR read.
- User-accessible device object without meaningful caller authentication.

Why this driver is powerful:

- Most modern kernel mitigations assume attacker primitives operate through normal kernel virtual memory semantics.
- This driver lets user mode ask a signed kernel driver to operate around those assumptions by touching physical memory.
- Physical memory access is broad enough to reconstruct virtual memory state, inspect page tables, locate kernel objects and change security-relevant fields.

Why the exploit uses physical-memory translation:

- The objects the exploit wants, such as `_EPROCESS`, token references, service tables and module images, are normally addressed by kernel virtual addresses.
- The driver does not simply provide `write_kernel_virtual(address, bytes)`.
- Therefore the exploit needs a bridge: virtual address -> physical address -> driver-backed physical write.
- This explains the page-table walk, CR3 discovery and KUSER_SHARED_DATA validation in the public README. Those steps are not decorative; they convert a raw hardware primitive into a normal exploit developer primitive.

Why it uses MSR read:

- `IA32_LSTAR` points at the syscall entry path.
- Reading it leaks a kernel address that is useful for defeating KASLR.
- It gives a reliable anchor to find `ntoskrnl` without depending on user-mode kernel pointer leaks that Microsoft has steadily restricted.

Why it avoids a naive token overwrite only:

- A direct token overwrite needs reliable target object addresses and offsets.
- On modern Windows 11, hardcoded offsets and static assumptions break often.
- The PoC instead resolves kernel and Win32k state dynamically and temporarily redirects a dispatch path to call a legitimate kernel memory-copy routine.
- The reason is reliability: let existing kernel code perform the copy in kernel context, then restore the modified dispatch state quickly.

Why it touches Win32k / shadow SSDT:

- GUI syscalls go through the Win32k service path.
- A Win32k host module provides reachable dispatch machinery and aligned indirect thunks that can be repurposed temporarily.
- Triggering a GUI syscall gives the exploit a controlled kernel transition without needing to inject a new unsigned driver or allocate executable kernel memory.

Why this is risky:

- Service table or dispatch redirection is PatchGuard-adjacent and telemetry-sensitive.
- The exploit has to restore the modified state quickly.
- Any mismatch in build, Win32k module layout, page-table translation or token offset can crash the system.

Mitigation interaction:

- HVCI blocks many classic writable+executable kernel tricks, but it does not neutralize a signed driver that exposes physical memory.
- VBS makes some protected regions harder to tamper with, but normal VTL0 kernel objects remain reachable if physical-memory access is not constrained.
- The real mitigation is to prevent the driver from loading or being opened by untrusted code.

Detection logic:

- Driver load of `ASTRA64.sys`.
- Process opens to Astra32/TVicHW device objects by non-Astra processes.
- Short-lived driver service creation followed by privilege jump.
- Suspicious GUI syscall activity directly after hardware-driver load is weak alone, but useful when correlated.
- WDAC deny by hash/signer/product where not required.

## Deep Dive 2. Lenovo `LnvMSRIO.sys` / CVE-2025-8061

Driver type: Lenovo Dispatcher / MSR and low-level hardware helper.

Primitive exposed:

- Physical memory read/write.
- MSR read/write.
- Insufficient access control around privileged IOCTLs.

Why this driver is attractive:

- OEM drivers often have trusted signatures and are expected on enterprise fleets.
- Hardware helper drivers commonly expose exactly the capabilities exploit developers need: MSR access, physical memory access, port I/O or PCI access.
- The driver is useful even if the bug is not a memory corruption bug; the unsafe feature itself is the vulnerability.

Why MSR R/W matters:

- MSR read can leak privileged CPU state and kernel addresses.
- MSR write can redirect critical CPU-controlled paths such as syscall entry.
- That is why many BYOVD demos use `LSTAR`: it is a compact proof that the driver can influence ring transitions.

Why a robust exploit may prefer data-only after gaining low-level access:

- MSR hijack is dramatic but fragile. A bad write causes immediate bugcheck.
- Modern Windows with HVCI/kCFG/CET makes arbitrary kernel code execution harder to stabilize.
- Data-only changes, such as token or process protection changes, can achieve the operational goal with fewer moving parts.

Why Quarkslab frames it as "BYOVD to the next level":

- The interesting part is not just loading a bad driver.
- It is turning basic hardware access into a reliable Windows 11 exploit path while respecting modern mitigation constraints.
- The technique teaches the same theme as Astra64 and eneio64: physical/MSR primitives are raw materials, not final exploitation by themselves.

Mitigation interaction:

- Driver Signature Enforcement accepts signed Lenovo components.
- HVCI does not make an unsafe driver API safe.
- Vulnerable driver blocklist and WDAC become the security boundary.
- Lenovo fixed affected versions, so version inventory is important.

Detection logic:

- Loads of `LnvMSRIO.sys` outside Lenovo service lifecycle.
- Any service creation pointing to copied Lenovo driver in temp/user-writeable directories.
- Non-Lenovo controller process opening the driver.
- Kernel crash with MSR/syscall-path symptoms after driver load.
- Endpoint query for Lenovo Dispatcher 3.0/3.1 versions below fixed build.

## Deep Dive 3. `ThrottleStop.sys` / CVE-2025-7771

Driver type: CPU throttling/overclocking utility driver.

Primitive exposed:

- Physical memory read/write through `MmMapIoSpace`.
- Public reporting describes exposed IOCTL interfaces around those operations.

Why this driver is common in attacks:

- It is a legitimate consumer utility, so its driver may be signed and familiar to security products.
- Attackers can bring the driver even if the victim never used ThrottleStop.
- Ransomware crews do not necessarily need elegant kernel code execution. They often need to disable AV/EDR quickly.

Why physical memory R/W is enough:

- Security-relevant kernel objects eventually live in physical RAM.
- If the attacker can locate those physical pages, they can change token fields, process state or security product data structures.
- The hard engineering work is discovery: finding the right process structures and translating or scanning physical memory safely.

Why write-ups discuss VAD traversal and process/module discovery:

- A raw physical dump is not self-describing enough for reliable exploitation.
- VADs, EPROCESS fields, module lists and PE headers provide anchors to identify what memory represents.
- This improves reliability versus blind scanning.

Why attackers use it for AV killing:

- With kernel-level memory access, a user-mode controller can either directly tamper with process/security state or call into vulnerable driver functionality to disrupt security processes.
- Even if full LPE is possible, many ransomware chains only need defense evasion before payload deployment.

Mitigation interaction:

- HVCI does not stop `MmMapIoSpace` misuse if the signed driver exposes it.
- Microsoft blocklist or vendor/AV block rules may catch known vulnerable versions.
- Renaming the file does not change the driver hash or behavior, but weak detections based only on filename can miss it.

Detection logic:

- `ThrottleStop.sys` or renamed copies loaded from `%TEMP%`, `%APPDATA%`, downloads, staging directories.
- Process creation chain: remote admin/RDP tool -> driver service creation -> AV/EDR process termination -> ransomware.
- Driver load on servers or enterprise workstations where CPU tuning utilities are not approved.
- Memory integrity/blocklist disabled shortly before driver load.

## Deep Dive 4. Awesome Miner / WinRing0 rename / CVE-2025-63602

Driver type: WinRing0-style low-level helper embedded/renamed by a crypto-mining management product.

Primitive exposed:

- MSR read/write.
- Weak device access control depending on load context.

Why this case matters:

- WinRing0 is a long-known dangerous component.
- Repackaging it under another product name can bypass simple filename-centric controls.
- Crypto/mining/monitoring tools frequently need low-level telemetry and sometimes ship overly powerful drivers.

Why MSR abuse is selected:

- MSRs are small, privileged CPU control registers.
- A single MSR can influence kernel entry/exit behavior.
- For a proof of impact, MSR access is easier to demonstrate than building a full physical-memory translation layer.

Why the PoC uses syscall-related MSR:

- It proves both read and write influence on a critical kernel transition path.
- It demonstrates KASLR implications because syscall-entry addresses live in kernel address space.
- It shows that the vulnerability is beyond information disclosure; it can crash or redirect privileged execution.

Why this is less stable than data-only exploitation:

- MSR writes affect the entire machine, not one target process.
- Bad values crash quickly.
- Modern mitigations and PatchGuard-like checks make persistent control-flow tampering brittle.

Defensive lesson:

- The bug is not only "WinRing0 exists"; the practical issue is device object access control.
- If low-privileged users can open the driver, the system boundary collapses.
- Even if admin is required, the driver remains a BYOVD asset for post-exploitation.

Detection logic:

- Identify WinRing0 by hash/imports/device names, not just `WinRing0.sys`.
- Hunt `\\.\WinRing0_1_2_0` style device access from unexpected processes.
- Flag mining/admin utilities on endpoints where not business-approved.
- Correlate with bugchecks or sudden kernel crashes after MSR-capable driver load.

## Deep Dive 5. ThreatFire `TfSysMon.sys` / CVE-2025-61156

Driver type: security product system monitor.

Primitive exposed:

- Arbitrary or unauthorized process termination with kernel privileges.
- Weak DACL/access control around device interaction.

Why no arbitrary R/W is needed:

- Many attackers do not need to become a kernel programmer if the driver already provides the privileged action they want.
- Killing AV/EDR/PPL processes is directly useful for ransomware and post-exploitation.
- Kernel process termination bypasses many user-mode protections and access checks.

Why security product drivers are risky:

- They intentionally have powerful capabilities: process control, image monitoring, callback registration, file/network filtering.
- If an old signed security driver exposes those capabilities without strict authorization, it becomes an attacker tool.

Why this bypasses PPL in practice:

- PPL blocks normal user-mode process termination and handle access.
- A kernel driver is above that boundary.
- If the driver accepts termination requests from an untrusted caller, PPL no longer protects the target.

Mitigation interaction:

- HVCI does not stop legitimate kernel APIs from being called by a signed driver.
- PatchGuard does not care if a driver uses legitimate termination routines.
- The critical control is access control and driver load policy.

Detection logic:

- Old ThreatFire driver load.
- Low-integrity or standard-user process opening the driver.
- Security process termination shortly after driver load.
- Repeated attempts to terminate PPL/AV processes.
- Driver not present in Microsoft blocklist yet should still be blocked locally.

## Deep Dive 6. K7 `K7RKScan.sys` / CVE-2025-52915 and CVE-2025-1055

Driver type: antivirus rootkit scanner / security helper.

Primitive exposed:

- Kernel-privileged process termination.
- Two operational models: legacy low-privilege abuse and newer admin/BYOVD abuse.

Why the exploit has two modes:

- Legacy versions allowed weaker caller access, so the vulnerability behaves like local privilege/authorization bypass.
- Newer versions may require admin or driver-loading ability, but the driver still contains a dangerous capability.
- BYOVD turns "admin can load old signed driver" into "admin can bypass PPL/EDR assumptions".

Why process-killer drivers are operationally valuable:

- Process termination is enough to disable AV, EDR sensors, backup agents, logging agents or anti-ransomware tools.
- It is simpler and more reliable than building a full kernel memory exploit.
- Operators can wrap many such drivers behind one generic "kill target process" interface.

Why the write-up calls it an evolution story:

- Vendor changes can reduce one abuse path while leaving another.
- For defenders, the question is not only "can low-priv users open it today?"
- The question is also "can attackers load a still-signed vulnerable version and get useful kernel actions?"

Detection logic:

- Track both old and current vulnerable hashes.
- Alert on K7 driver loads on hosts not running K7.
- Correlate with termination of security processes.
- Block obsolete signed versions with WDAC even if latest vendor version is fixed.

## Deep Dive 7. PowerStrip `pstrip64.sys` / CVE-2026-29923

Driver type: EnTech Taiwan hardware/display utility driver.

Primitive exposed:

- Arbitrary physical memory mapping into caller process.
- User-accessible device object/symbolic link.

Why it resembles Astra64:

- Same vendor family and same dangerous design pattern: user-controllable physical memory exposure.
- Both cases show why old hardware utility drivers are high-value BYOVD assets.

Why mapping physical memory is different from a normal read/write API:

- The driver maps physical pages into user-mode virtual address space.
- Once mapped, the user process can inspect or modify what those pages contain.
- The driver may not "know" the attacker is modifying kernel objects; it only provided the mapping.

Why scanning for `_EPROCESS` appears in write-ups:

- If you do not have virtual-to-physical translation, one fallback is scanning RAM for recognizable object patterns.
- `_EPROCESS` has fields like PID, image name and list links that can be validated.
- Once own process and System process are identified, token/data-only LPE becomes conceptually straightforward.

Why this is fragile:

- Physical memory scanning is noisy, slow and build-dependent.
- False positives can corrupt arbitrary memory and crash the host.
- Windows layout, memory pressure and virtualization settings affect reliability.

Detection logic:

- `pstrip64.sys` load or `PSTRIP64` device object.
- Legacy PowerStrip on modern endpoints.
- Driver service creation by non-installer processes.
- Block affected versions; old utility has low business justification.

## Deep Dive 8. `eneio64.sys` / `ene.sys` / CVE-2020-12446

Driver type: RGB / hardware control driver.

Primitive exposed:

- Physical memory mapping/RW.
- MSR access.
- I/O port access.

Why it remains relevant despite old CVE:

- The 2025 write-up tests it against modern Windows 11/HVCI assumptions.
- It is a clean teaching case for physical-to-virtual primitive conversion.
- Many RGB/monitoring utilities ship drivers with similar low-level access.

Why virtual-to-physical translation is the core technique:

- Exploit developers usually reason in kernel virtual addresses: `ntoskrnl` base, `_EPROCESS`, `_TOKEN`, pool objects.
- The driver operates on physical memory.
- Page tables are the translation mechanism between those two worlds.
- By finding the relevant CR3/page-table base, the exploit can translate a desired kernel virtual address into a physical address the driver can touch.

Why this beats blind physical scanning:

- Blind scanning can work for stable structures but is slow and unreliable.
- Page-table walking gives deterministic access to the target virtual address if the translation is valid.
- This generalizes: once translation is solved, many virtual-memory exploit techniques become possible.

Why HVCI compatibility is not safety:

- A driver can satisfy code integrity requirements and still expose dangerous hardware primitives.
- HVCI checks code integrity; it does not automatically authorize every IOCTL semantics.
- Vulnerable-driver policy has to classify and block these drivers.

Detection logic:

- RGB/hardware utility drivers on enterprise endpoints.
- Access to physical-memory mapping APIs by drivers not in a narrow approved list.
- Driver load followed by unusual privileged process creation or security product disruption.

## Deep Dive 9. Baidu `BdApiUtil64.sys` / CVE-2024-51324

Driver type: antivirus/security utility helper.

Primitive exposed:

- Privileged process termination.

Why it fits the BlackSnufkin `*-Killer` pattern:

- Many BYOVD process-kill exploits share the same operator workflow:
  - load or find vulnerable driver,
  - open device,
  - identify target process,
  - ask driver to perform privileged termination.
- A shared library can abstract service creation and device communication while each module only defines the driver-specific configuration.

Why process termination is a separate primitive category:

- It does not give arbitrary kernel R/W.
- It does not directly give SYSTEM shell.
- But it solves a real attacker problem: removing protection before deploying next-stage payloads.

Why this case matters defensively:

- Security tools themselves can become BYOVD tools when old components remain signed and loadable.
- Blocklist lag matters: a driver can be public and still not be in Microsoft or LOLDrivers at disclosure time.

Detection logic:

- `BdApiUtil64.sys` on non-Baidu hosts.
- Driver service creation in staging directories.
- Process termination requests against AV/EDR.
- Block by hash and signer/product where Baidu Antivirus is not approved.

## Deep Dive 10. PassMark `DirectIo64.sys` / CVE-2025-52347

Driver type: hardware diagnostics/performance utility driver.

Primitive described publicly:

- Kernel memory read/write through unsafe IOCTL handling.
- Hardware-access driver family historically associated with physical memory and port/MSR operations.

Why this is in watchlist:

- I found advisories and technical descriptions, but not a verified public exploit repo during this pass.
- The primitive class is still important because PassMark tools are common in IT/admin/forensic contexts.

Why hardware diagnostic drivers are risky:

- Their purpose is to expose low-level hardware details to user-mode tools.
- Without strict ACLs and narrow IOCTL semantics, they become generic kernel access brokers.
- They are more likely to be allowed by admins because the product appears legitimate.

Likely exploit shape, conceptually:

- Open the driver device.
- Use unsafe IOCTL path to cause privileged memory operation.
- Convert read/write into data-only impact such as token change, process protection change or disabling security tooling.

Defensive notes:

- Treat this as watchlist until a trustworthy public PoC/write-up is confirmed.
- Inventory PassMark product versions.
- Alert on `DirectIo64.sys` loads by non-PassMark processes.
- WDAC block on endpoints where PassMark is not explicitly needed.

## Why different BYOVD exploits choose different techniques

| Available driver capability | Best-fit exploitation technique | Why that technique is chosen |
|---|---|---|
| Physical memory map/RW | Page-table walk or physical object scan | Driver sees physical addresses, but target objects are known virtually. Translation/scanning bridges the gap. |
| MSR read/write | KASLR leak or syscall-path proof of control | MSRs expose compact, high-impact CPU state. Good for proving impact, but fragile for stable exploitation. |
| Virtual kernel R/W | Direct object/data-only modification | No translation layer needed; fastest route to token/PPL/process state impact. |
| Process termination API | EDR/PPL kill workflow | Operational goal is defense evasion, not full kernel control. |
| Port I/O / PCI config | Hardware abuse or platform-specific escalation | Useful only if target platform has sensitive device paths reachable. |
| Weak DACL only | Low-privileged access to intended privileged feature | The vulnerability is authorization failure, not memory corruption. |

## Why modern BYOVD chains prefer data-only outcomes

- HVCI makes unsigned kernel code and writable+executable tricks harder.
- kCFG/CET raise the cost of control-flow hijack.
- PatchGuard makes long-lived kernel patching risky.
- EDRs watch obvious global callback/table tampering.
- Token, protection, handle, process and security-policy data changes can achieve the goal with less code execution.

This is why many recent BYOVD write-ups emphasize:

- physical -> virtual memory bridge,
- token copy/swap,
- `PreviousMode`-style API boundary abuse,
- process termination,
- PPL/security process bypass,
- short-lived modification followed by restore.

## Defensive priority ranking

1. Block physical-memory and MSR-capable drivers first.
2. Block process-killer security-product drivers next.
3. Hunt renamed WinRing0/DirectIO/TVicHW-style components by hash and behavior.
4. Maintain local WDAC deny rules instead of waiting for Microsoft blocklist updates.
5. Correlate driver load with security-process tamper and privilege changes.
6. Remove unneeded hardware tuning, RGB, mining, diagnostics and legacy AV drivers from endpoints.

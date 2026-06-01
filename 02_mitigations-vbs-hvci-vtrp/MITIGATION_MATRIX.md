# Windows Kernel Mitigation Matrix

The purpose of this file is not merely to list mitigations, but to explain how each one changes exploit thinking. When looking at a primitive such as physical R/W, virtual kernel R/W, MSR write, pool overflow, use-after-free, callback overwrite, token DKOM, PTE tamper, shadow SSDT hijack, or kernel ROP, the right question is not just "can it be bypassed?", but:

- Does this mitigation protect code, data, control-flow, page tables, driver load, or the boot chain?
- Does it live in the normal kernel, secure kernel, hypervisor, hardware, or policy layer?
- Which primitives does it directly counter?
- Does it merely make exploitation harder, or does it nearly kill an entire technique class?
- Is it enabled by default on a given version, or is it optional/OEM/config-dependent?
- Can BYOVD neutralize it?

This file should be read alongside:

- `VT_RP_HLAT_DEEP_DIVE_VI.md`
- `CONNOR_HVCI_KCFG_DEEP_DIVE_VI.md`
- `..\..\03_byovd\00_index-and-matrix\BYOVD_PRIMITIVE_MATRIX.md`

## 1. Mental model: mitigation layers

Windows kernel exploit mitigations do not all live at the same layer. A common mistake is to lump everything together as "Windows 11 has HVCI so kernel exploits no longer work." That is wrong. The layers must be separated:

```text
Hardware / CPU
  NX, SMEP, SMAP, CET shadow stack, MBEC/GMET, IOMMU

Hypervisor / VBS
  VTL0/VTL1 separation, HVCI, KDP, secure kernel, EPT/SLAT permission

Kernel memory manager
  KASLR, pool hardening, NonPagedPoolNx, PTE validation, session isolation

Kernel control-flow
  kCFG, CET kernel shadow stack, PatchGuard checks

Kernel object / policy
  PPL, object callbacks, token semantics, silo/session/job restrictions

Driver trust / load policy
  KMCS, EV signing, Attestation signing, WDAC, vulnerable driver blocklist

Telemetry / response
  Defender, MDE, Sysmon, ETW, driver inventory, ASR rules
```

Why separate them? Because each mitigation only targets a subset of attack classes. HVCI blocks unsigned kernel code execution very effectively, but does not automatically make a signed driver's IOCTLs safe. kCFG blocks indirect call hijacking, but does not block data-only token overwrites. KDP protects registered data regions, but does not protect every field in every kernel object. The driver blocklist blocks known-bad drivers, but not newly discovered drivers that are not yet listed.

## 2. Version timeline overview

This table is a practical map. "Introduced" means the feature/baseline appeared or became significant during that period; "default" can vary by SKU, hardware, OEM, clean install, upgrade path, and policy.

| Era / Version | Year | Important mitigations | Exploit impact |
|---|---:|---|---|
| Windows XP SP2 / Server 2003 SP1 | 2004-2005 | DEP/NX for userland and broader platform support | Stack/heap shellcode direct execution is increasingly blocked; ROP/JOP becomes more important. |
| Windows Server 2003 SP1 x64 / Vista x64 | 2005-2007 | Kernel Patch Protection/PatchGuard, kernel driver signing on x64, ASLR era | SSDT/IDT/GDT inline hooks and rootkit-style patching start being monitored on x64; loading unsigned kernel drivers becomes harder. |
| Windows 7 | 2009 | ASLR/DEP maturity, pool metadata hardening better than XP/Vista | Kernel exploits need better leaks; generic pool overflow primitives are less reliable. |
| Windows 8 | 2012 | NonPagedPoolNx, broader pool hardening, modern app/container foundations | Kernel pool shellcode in nonpaged pool becomes harder; data-only/ROP/gadget paths become more important. |
| Windows 8.1 | 2013 | SMEP on capable CPUs; KASLR/CFG ecosystem grows | Kernel cannot execute user pages when SMEP is enabled; ret2usr pattern dies unless SMEP/PTE tamper is used. |
| Windows 10 1507/1511 | 2015 | CFG platform, Device Guard/VBS direction, modern KMCI policy work | More control-flow constraints; enterprise code integrity starts to matter. |
| Windows 10 1607 / Server 2016 | 2016 | VBS/HVCI/Credential Guard usable baseline; Device Guard era | Code Integrity can move outside normal kernel trust boundary; attacker with kernel bug no longer automatically controls CI decision layer. |
| Windows 10 1703 Creators Update | 2017 | Kernel CFG becomes a major kernel exploitation factor | Function pointer overwrite / indirect call hijack less reliable unless target is valid CFG target or bypass route exists. |
| Windows 10 1803/1809 | 2018 | More VBS hardening, WDAC usable beyond early Device Guard framing; vulnerable driver blocklist optional from 1809 | Driver policy starts becoming a real BYOVD control, but optional/config-dependent. |
| Windows 10 1903/1909 | 2019 | CET implementation work starts appearing; HVCI adoption grows | Return-address attacks start facing future hardware direction, but deployment still limited. |
| Windows 10 2004 / 20H1 | 2020 | User-mode CET support matures; KDP announced; KDP protects selected kernel/driver data with VBS | Pure data corruption attacks get a new defense if target data is KDP-protected. Not universal. |
| Windows 11 21H2 | 2021 | New hardware baseline: TPM 2.0, Secure Boot capable, VBS/HVCI support expected on new devices | Security posture improves, but HVCI/default state depends on device/OEM/upgrade/config. |
| Windows 11 22H2 | 2022 | Broader default HVCI on capable new devices; vulnerable driver blocklist enabled by default; kernel-mode hardware stack protection prerequisites appear | BYOVD becomes more dependent on blocklist gaps; ROP/return-address tamper faces kernel shadow stack if enabled. |
| Windows 11 23H2/24H2 | 2023-2024 | Continued VBS/HVCI, driver blocklist, CET/stack protection, secured-core defaults | Data-only, signed-driver abuse, logic bugs and policy bypass remain important. |
| Windows 11 25H2 / current servicing era | 2025-2026 | Same families, stronger defaults and blocklist updates over time | Main issue is not one magic mitigation; exploit viability depends on exact hardware + policy + driver allow/block state. |

## 3. Mitigation-by-mitigation deep matrix

### DEP / NX

| Item | Detail |
|---|---|
| Main purpose | Mark data pages non-executable. |
| Layer | CPU page permission + OS memory manager. |
| Windows era | User-visible DEP becomes important from XP SP2 / Server 2003 SP1. Kernel/no-execute pool story matures later, especially Windows 8 `NonPagedPoolNx`. |
| Directly hurts | Stack shellcode, heap shellcode, pool shellcode if memory is NX. |
| Does not stop | Data-only attacks, token DKOM, object field corruption, signed-driver IOCTL abuse, ROP using already executable code. |
| Bypass style conceptually | ROP/JOP, reuse existing executable code, find executable pool/code cave, flip page permissions if primitive allows. |
| BYOVD relevance | A signed driver with arbitrary write can modify data without executing injected code; DEP/NX does not stop that. |

Why it matters: before DEP/NX, exploit chains often ended by placing shellcode in writable memory and jumping to it. After NX, the exploit has to either reuse existing executable code or change memory permissions. In kernel land, that pushed attackers toward ROP, function pointer reuse, token stealing and object manipulation.

### Kernel ASLR / KASLR

| Item | Detail |
|---|---|
| Main purpose | Randomize kernel image and module base addresses. |
| Layer | Loader / memory manager. |
| Windows era | Vista era onward, then gradually improved. |
| Directly hurts | Hardcoded gadget addresses, hardcoded `ntoskrnl` exports, static SSDT/shadow SSDT assumptions. |
| Does not stop | Any exploit with a reliable kernel leak; physical memory scanning if robust; exported pointer disclosure; MSR `IA32_LSTAR` read as an anchor. |
| Bypass style conceptually | Leak loaded module list, query kernel addresses where allowed, use `IA32_LSTAR`, scan backward for MZ/PE from syscall entry, read `PsLoadedModuleList` if primitive allows. |
| BYOVD relevance | Many hardware drivers expose MSR read or physical read, so KASLR often becomes a speed bump rather than a wall. |

Why KASLR is not enough: KASLR is secrecy. If the attacker gets one strong info leak or physical/virtual read primitive, KASLR collapses for that boot session. In your ASTRA64 chain, `IA32_LSTAR` gives a pointer into the syscall path; walking back to `MZ` recovers `ntoskrnl` base. That is the classic reason MSR read is useful even when MSR write is too risky.

### Kernel driver signing / KMCS

| Item | Detail |
|---|---|
| Main purpose | Prevent arbitrary unsigned kernel drivers from loading on x64. |
| Layer | Code integrity / loader policy. |
| Windows era | x64 Vista/Server 2008 era onward; policy became stricter over time. |
| Directly hurts | "Just load my rootkit driver" attacks. |
| Does not stop | Vulnerable signed drivers, stolen certificates, mis-signed/attestation-signed bad drivers, already-loaded vulnerable OEM/security drivers. |
| Bypass style conceptually | BYOVD: bring a legitimately signed vulnerable driver and use its IOCTL interface. |
| BYOVD relevance | This is the reason BYOVD exists as a major category. |

The important mental shift: driver signing validates publisher/chain/policy, not semantic safety. A signed driver can still expose arbitrary physical memory mapping, MSR write, process termination, kernel virtual R/W or broken access control.

### PatchGuard / Kernel Patch Protection

| Item | Detail |
|---|---|
| Main purpose | Detect unsupported patching of critical kernel structures/code on x64. |
| Layer | Kernel integrity monitoring with delayed/randomized checks. |
| Windows era | Introduced in the x64 Windows Server 2003 SP1 / Vista x64 era; evolved continually. |
| Directly hurts | SSDT hook, IDT/GDT hook, inline patching `ntoskrnl`, global callback/list tampering that PatchGuard watches. |
| Does not stop | Short-lived modifications that restore before check, data fields not watched, token stealing if not monitored in that exact way, process-kill IOCTLs, legitimate kernel APIs. |
| Bypass style conceptually | Avoid persistent global patching; do data-only per-object changes; use transient hooks; restore fast; prefer legitimate dispatch path. |
| BYOVD relevance | Pushes practical BYOVD LPE toward DKOM token writes or legitimate-kernel-code invocation instead of permanent kernel patching. |

PatchGuard is not a pre-execution guard. It is a delayed integrity watchdog. That means it can miss short-lived changes but will crash the box if you corrupt protected state and leave it inconsistent. This is why direct token swap + restore is generally less risky than SSDT/shadow SSDT patching for simple LPE.

### NonPagedPoolNx

| Item | Detail |
|---|---|
| Main purpose | Make default/non-executable kernel pool allocations easier and encouraged. |
| Layer | Kernel pool allocator + page permissions. |
| Windows era | Windows 8 introduced NX nonpaged pool types and migration mechanisms. |
| Directly hurts | Pool overflow -> place shellcode in pool -> jump to it. |
| Does not stop | Pool overflow that corrupts object metadata/function pointer/data; ROP; arbitrary write; token/object DKOM. |
| Bypass style conceptually | Reuse existing code; corrupt control/data structures; target executable memory only if a legitimate executable allocation exists. |
| BYOVD relevance | Physical/virtual R/W drivers do not need pool shellcode; they can write fields directly. |

Why this changed pool exploitation: old pool exploitation often tried to get code execution from kernel pool. Modern pool exploitation asks a different question: "What object can I corrupt so the kernel does useful work for me without executing my bytes?"

### SMEP

| Item | Detail |
|---|---|
| Main purpose | Prevent supervisor/kernel mode from executing user-mode pages. |
| Layer | CPU CR4.SMEP + page U/S bit. |
| Windows era | Important in Windows 8.1+ on capable Intel CPUs. |
| Directly hurts | ret2usr: kernel RIP jumps to user shellcode. |
| Does not stop | Kernel ROP using kernel code, data-only writes, kernel executable gadget chains, token DKOM. |
| Bypass style conceptually | Disable SMEP if CR4 write primitive/gadget; mark user page supervisor via PTE tamper; run code from kernel executable region; use data-only attack. |
| BYOVD relevance | If your driver gives MSR/physical/PTE write, SMEP can sometimes be bypassed, but a data-only route is usually safer. |

Why data-only wins here: token overwrite never asks the CPU to execute user pages. SMEP is irrelevant to direct `_EPROCESS.Token` copy except insofar as you need code to perform the write. If the vulnerable driver performs the write/mapping for you, SMEP is not the main barrier.

### SMAP

| Item | Detail |
|---|---|
| Main purpose | Prevent supervisor/kernel mode from directly reading/writing user-mode pages unless explicitly allowed. |
| Layer | CPU CR4.SMAP + AC flag-controlled access pattern. |
| Windows era | Hardware feature; Windows usage is more nuanced and less central than SMEP in public exploit writeups. |
| Directly hurts | Kernel ROP that dereferences user buffers as arguments/state. |
| Does not stop | Kernel data-only corruption if target is kernel memory; properly probed/copied user buffers; driver-mediated copies. |
| Bypass style conceptually | Use kernel buffers, valid probe/copy APIs, gadgets that set AC if available, or avoid user pointers. |
| BYOVD relevance | Many BYOVD primitives copy from user input through the driver into kernel/physical memory; SMAP does not automatically stop driver logic. |

SMAP matters more for "kernel code is executing and wants to read attacker-controlled user memory" chains. It matters less when the primitive is an IOCTL that already copies the user's input through a legitimate I/O buffer path.

### CFG / kCFG

| Item | Detail |
|---|---|
| Main purpose | Restrict indirect calls/jumps to valid compiler/loader-known targets. |
| Layer | Compiler instrumentation + Windows runtime/kernel support. |
| Windows era | User CFG in Windows 8.1 update / Windows 10 era; kernel CFG becomes important around Windows 10 1703. |
| Directly hurts | Function pointer overwrite to arbitrary gadget, vtable hijack to non-CFG target, callback target abuse. |
| Does not stop | Direct calls, returns, data-only attacks, token DKOM, ROP that uses returns unless CET/shadow stack is active. |
| Bypass style conceptually | Use valid CFG targets, corrupt data instead of control flow, target return address rather than indirect call, use logic/API invocation path. |
| BYOVD relevance | Virtual/physical R/W token write bypasses the need for function pointer control. Connor-style kernel stack ROP cares because kCFG protects indirect calls but not classic returns by itself. |

Why kCFG does not equal "no ROP": CFG validates indirect branch targets. A `ret` instruction is a return, not an indirect call through a function pointer in the CFG model. That is why kernel shadow stack/kCET is the natural companion mitigation.

### CET / Kernel-mode Hardware-enforced Stack Protection

| Item | Detail |
|---|---|
| Main purpose | Protect return addresses with hardware shadow stacks. |
| Layer | CPU CET/AMD shadow stack + Windows kernel integration + VBS/HVCI prerequisites for kernel mode feature. |
| Windows era | User-mode hardware stack protection appears around Windows 10 20H1 support era; kernel-mode hardware-enforced stack protection requires Windows 11 2022 Update or newer and supported hardware per Microsoft docs. |
| Directly hurts | Return-address overwrite, classic ROP, Connor-style kernel stack ROP if fully enforced. |
| Does not stop | Data-only token DKOM, process-kill IOCTL, legitimate API use, vulnerable driver physical/virtual write by itself. |
| Bypass style conceptually | Avoid return hijack; use data-only primitive; use valid call path; find shadow-stack sync/exception weakness if any exists. |
| BYOVD relevance | It strongly affects ROP-based HVCI bypass chains, but does not make arbitrary data writes safe. |

This is the key contrast with kCFG:

```text
kCFG protects forward-edge indirect calls/jumps.
CET shadow stack protects backward-edge returns.
```

So:

- function pointer overwrite -> kCFG problem.
- return address overwrite -> CET/shadow stack problem.
- token field overwrite -> neither kCFG nor CET directly solves it.

### VBS

| Item | Detail |
|---|---|
| Main purpose | Use virtualization to isolate sensitive security services/data from the normal kernel. |
| Layer | Hyper-V hypervisor, VTL0/VTL1, secure kernel. |
| Windows era | Windows 10 / Server 2016 Device Guard/Credential Guard era; default/enabled state improves across Windows 11 capable devices. |
| Directly hurts | Assumption that ring 0 owns the whole machine. |
| Does not stop | All normal-kernel data corruption; vulnerable signed driver semantics; BYOVD if driver is allowed to load and target data is not protected by VBS policy. |
| Bypass style conceptually | Attack unprotected VTL0 data, abuse signed drivers, find policy gaps, attack boot/firmware/hypervisor boundary. |
| BYOVD relevance | VBS changes the ceiling of what ring-0 can modify, but many BYOVD goals live entirely in VTL0. |

The important idea: before VBS, kernel compromise often meant "I can patch Code Integrity, secrets, token, code, page tables, everything". With VBS, some decisions and memory live outside VTL0. But the normal Windows kernel still has massive mutable state. BYOVD exploits usually target that mutable state.

### HVCI / Memory Integrity

| Item | Detail |
|---|---|
| Main purpose | Enforce kernel code integrity with hypervisor support. Prevent unsigned/unapproved executable kernel code and W+X style tricks. |
| Layer | VBS + hypervisor-enforced page permissions + Code Integrity service isolation. |
| Windows era | Available in Windows 10, Windows 11, Server 2016+; Windows 11 22H2 broadened default enablement on capable new devices. |
| Directly hurts | Kernel shellcode, executable pool tricks, PTE trick to mark attacker bytes executable, unsigned code injection. |
| Does not stop | Data-only attacks, token stealing, physical/virtual write to mutable kernel object, process-kill IOCTLs, allowed signed vulnerable driver load if not blocked. |
| Bypass style conceptually | Avoid new code; use existing signed kernel code; data-only DKOM; ROP with executable signed code if not stopped by CET; exploit HVCI policy gaps. |
| BYOVD relevance | HVCI makes "execute my payload in kernel" harder; it does not sanitize dangerous IOCTLs in signed drivers. |

This is why Connor's post is valuable: it shows the mental shift from "make shellcode executable" to "invoke existing kernel code under HVCI-compatible constraints." It is also why your ASTRA64 direct DKOM path is conceptually clean: it does not need unsigned kernel code execution at all.

### KDP

| Item | Detail |
|---|---|
| Main purpose | Protect selected kernel/driver data from corruption using VBS-backed protections. |
| Layer | VBS + memory manager + driver opt-in/static/dynamic protected data. |
| Windows era | Microsoft announced KDP in 2020 for Windows 10. |
| Directly hurts | Data-only attacks against protected driver/kernel data regions. |
| Does not stop | Writes to unprotected data, process-kill IOCTLs, token DKOM if token/field is not KDP-protected, driver logic bugs. |
| Bypass style conceptually | Target unprotected equivalent data, remapping/page swapping attacks if platform lacks stronger translation protections, abuse legitimate update path. |
| BYOVD relevance | KDP is the mitigation family that actually aims at data corruption, but coverage is selective. |

The key distinction:

```text
HVCI: "Do not execute untrusted kernel code."
KDP:  "Do not let selected kernel data be modified."
```

Most old exploit mitigations are code-execution mitigations. KDP is important because it acknowledges that data-only attacks are enough.

### VT-rp / HLAT-style protection direction

| Item | Detail |
|---|---|
| Main purpose | Prevent guest page-table remapping/page-swapping attacks against protected memory assumptions. |
| Layer | CPU virtualization paging extension direction; hypervisor can distinguish intended guest linear-to-physical mappings. |
| Windows era | Intel VT-rp/HLAT appears as newer hardware direction; deployment depends on CPU/platform/OS support. |
| Directly hurts | Remap protected virtual address to attacker-controlled physical page while preserving apparent virtual address. |
| Does not stop | Ordinary writes to unprotected data, vulnerable driver load, process kill, logic bugs. |
| Bypass style conceptually | Avoid remapping; target mutable data; attack policy/setup; use primitives outside protected mapping region. |
| BYOVD relevance | Physical R/W primitives can try remapping/page-table games; VT-rp is designed for this class of problem. |

Why this belongs in the matrix: KDP/HVCI can mark memory read-only/executable in EPT, but page-table remapping attacks challenge the assumption "this virtual address still points to the protected physical page." HLAT/VT-rp-style thinking tries to bind translation expectations more tightly.

### PPL / Protected Process Light

| Item | Detail |
|---|---|
| Main purpose | Prevent lower-trust processes/admin tools from opening/tampering with protected security processes. |
| Layer | Kernel object/process access policy + signer levels. |
| Windows era | Windows 8.1 era onward, expanded for LSASS/AV/EDR. |
| Directly hurts | User-mode admin-to-LSASS dumping/tamper, simple OpenProcess kill/inject. |
| Does not stop | Kernel-mode writes, vulnerable signed driver process-kill, token/object tampering from kernel. |
| Bypass style conceptually | BYOVD process-kill, kernel object modification, signed trusted component abuse. |
| BYOVD relevance | Process-killer drivers are valuable exactly because PPL blocks normal user-mode kill/open paths. |

PPL is a policy layer, not a memory safety boundary against ring-0. Once a vulnerable driver accepts a PID and terminates from kernel context, PPL may be bypassed unless the target/driver path has additional checks.

### WDAC and Microsoft Vulnerable Driver Blocklist

| Item | Detail |
|---|---|
| Main purpose | Prevent known vulnerable/malicious drivers from loading. |
| Layer | Application Control / Code Integrity policy. |
| Windows era | Vulnerable driver blocklist optional from Windows 10 1809; enabled by default for all devices starting Windows 11 22H2 per Microsoft support docs. |
| Directly hurts | BYOVD with known blocklisted driver hashes/certs/rules. |
| Does not stop | Unknown vulnerable drivers, newly disclosed drivers before blocklist update, already allowed enterprise exceptions, renamed same driver if rule misses hash/cert/version semantics. |
| Bypass style conceptually | Use driver not yet listed, abuse already-loaded driver, exploit allow policy gaps, downgrade policy in misconfigured environments. |
| BYOVD relevance | This is one of the most relevant direct mitigations for BYOVD. |

This is the defense that maps most directly onto the BYOVD problem. HVCI says "only trusted code executes"; WDAC/blocklist says "this signed driver is known bad, do not load it."

## 4. Primitive vs mitigation matrix

Legend:

- `Strong`: mitigation directly disrupts the primitive/chain.
- `Partial`: mitigation raises cost or blocks common route.
- `Weak`: mitigation barely matters unless paired with another control.
- `None`: not meaningfully relevant.

| Primitive / Chain | DEP/NX | KASLR | SMEP | HVCI | KDP | kCFG | CET/kShadowStack | PatchGuard | WDAC/blocklist |
|---|---|---|---|---|---|---|---|---|---|
| User shellcode from kernel RIP / ret2usr | Strong | Partial | Strong | Partial | None | Partial | Strong if return path | Weak | None |
| Pool shellcode | Strong | Partial | Weak | Strong | None | Partial | Partial | Weak | None |
| Kernel ROP | Weak | Strong until leak | Weak | Partial | None | Partial | Strong | Weak | None |
| Function pointer/vtable overwrite | Weak | Partial | Weak | Partial | None | Strong | Weak | Partial | None |
| Return address overwrite | Weak | Partial | Weak | Partial | None | Weak | Strong | Weak | None |
| Token DKOM | None | Partial | None | Weak | Partial if protected | None | None | Weak/Partial | None |
| `PreviousMode` DKOM | None | Partial | None | Weak | Partial if protected | None | None | Weak/Partial | None |
| Process-kill BYOVD | None | None | None | Weak | None | None | None | None | Strong if driver blocked |
| Physical memory R/W BYOVD | None | Partial | None | Partial | Partial/Strong for protected data | None | None | Partial | Strong if driver blocked |
| Virtual kernel R/W BYOVD | None | Partial | None | Partial | Partial/Strong for protected data | None | None | Partial | Strong if driver blocked |
| MSR syscall hijack | Partial | Partial | Partial | Strong/Partial | None | Partial | Partial | Strong risk | Strong if driver blocked |
| SSDT/shadow SSDT hook | Partial | Partial | Weak | Partial | None | Partial | Partial | Strong | Strong if driver blocked |
| PTE executable-bit tamper | Strong target | Partial | Strong if U/S | Strong | Partial | None | None | Partial | None |
| Page remapping attack against protected data | None | Partial | None | Partial | Strong target but remap-sensitive | None | None | Partial | None |

Important interpretation:

- BYOVD is best mitigated at driver load/policy layer.
- HVCI is excellent against unsigned code execution, not against every signed-driver data write.
- KDP is the data-corruption mitigation, but only for protected data.
- kCFG and CET protect different control-flow edges.
- PatchGuard punishes persistent unsupported patching, but not every short data-only change.

## 5. Windows version practical view for exploit research

### Windows 7 / Server 2008 R2

Research flavor:

- Fewer modern mitigations.
- Kernel exploits often rely on pool corruption, function pointer overwrite, token stealing.
- No HVCI/VBS default world.

Practical implication:

- Good for learning old primitives.
- Bad if you want to understand modern Windows 11 exploit engineering.

### Windows 8 / 8.1

Research flavor:

- NonPagedPoolNx and SMEP change classic kernel exploitation.
- ret2usr becomes unreliable on SMEP hardware.
- Pool shellcode becomes less central.

Practical implication:

- Good transition platform: old bugs still understandable, but modern constraints appear.

### Windows 10 1607-1809

Research flavor:

- VBS/HVCI/Device Guard era starts to matter.
- kCFG arrives and starts shaping control-flow exploit design.
- Driver blocklist exists later but is not the universal default defense.

Practical implication:

- This is where "ring 0 is not highest trust" becomes a practical idea.

### Windows 10 1903-2004

Research flavor:

- CET implementation direction appears.
- KDP is introduced/publicly documented in 2020.
- More systems have VBS/HVCI capability.

Practical implication:

- Good for studying data-only attack/defense tension: HVCI blocks code; KDP tries to protect selected data.

### Windows 11 21H2

Research flavor:

- Hardware baseline is stricter.
- VBS/HVCI support is expected on many new devices, but exact enablement varies.

Practical implication:

- Do not assume HVCI is on just because it is Windows 11.
- Always verify `msinfo32`, `Win32_DeviceGuard`, Windows Security, or policy state.

### Windows 11 22H2+

Research flavor:

- Broader default HVCI on capable new devices.
- Microsoft vulnerable driver blocklist enabled by default for all devices starting 22H2 according to Microsoft support documentation.
- Kernel-mode hardware-enforced stack protection requires Windows 11 2022 Update or newer, supported hardware, VBS and HVCI.

Practical implication:

- BYOVD research must include "does the driver load under current blocklist/policy?"
- ROP research must ask "is kernel shadow stack active?"
- HVCI-aware exploit chains need data-only or existing-code approaches.

## 6. Why BYOVD survives modern mitigations

BYOVD survives because many mitigations assume the dangerous code is untrusted, injected, unsigned, or control-flow-corrupting. BYOVD uses trusted code with bad semantics.

Example:

```text
Attacker user process
  -> opens signed vulnerable driver
  -> sends IOCTL with attacker-controlled buffer
  -> driver calls MmMapIoSpace / writes MSR / terminates PID / copies to kernel VA
  -> kernel executes signed driver code
```

From HVCI's point of view, the executing code can be signed and executable. From SMEP's point of view, the CPU may never execute user pages. From kCFG's point of view, there may be no invalid indirect branch. From CET's point of view, no return address may be corrupted. Yet the result can still be arbitrary kernel data corruption.

That is why driver blocklist, WDAC, least-privileged driver IOCTL design, access checks and removing bad drivers matter so much.

## 7. "What should I check first?" per exploit type

### Physical R/W driver

Ask:

- Is the driver blocked by WDAC/vulnerable driver blocklist?
- Is HVCI on, and does the driver still load?
- Does the primitive map physical pages, copy physical memory, or expose bus/port/MMIO access?
- Can I discover kernel object physical addresses safely?
- Are target fields KDP-protected?
- Does the technique require remapping/page table tamper?
- Is the chain data-only, or does it need code execution?

Mitigation pressure:

- Driver blocklist: high.
- KASLR: medium if read primitive exists.
- HVCI: medium/high only if code execution is needed.
- KDP: high only for protected target data.
- VT-rp/HLAT direction: relevant if remapping/page swapping is involved.

### Virtual kernel R/W driver

Ask:

- Is the target address known or leakable?
- Are `_EPROCESS`, `_KTHREAD`, token, callback or list offsets correct for this build?
- Is write aligned/width-limited?
- Can I validate before writing?
- Does PatchGuard watch the object/field I plan to touch?

Mitigation pressure:

- KASLR: medium.
- KDP: high for protected data.
- PatchGuard: medium/high for persistent global tamper.
- HVCI: low for pure data-only.
- Driver blocklist: high.

### Process-killer driver

Ask:

- Does it terminate by PID, handle, process name, or internal lookup?
- Does it check signer/PPL/vendor allowlist?
- Does it accept protected process targets?
- Can it kill critical system processes and BSOD the machine?
- Is the driver already blocked?

Mitigation pressure:

- PPL: often bypassed because action is kernel-originated.
- HVCI: low if driver loads.
- Driver blocklist: high.
- OS offsets: usually low sensitivity.

### MSR write driver

Ask:

- Which MSRs are readable/writable?
- Is `IA32_LSTAR` readable only or writable?
- Does the chain require global syscall entry patch?
- How is concurrency handled?
- How fast is restore?

Mitigation pressure:

- PatchGuard/stability: high.
- HVCI: high if syscall hook jumps to unsigned/non-approved code.
- SMEP/SMAP: relevant if path touches user pages.
- CET/kCFG: depends on dispatch style.
- Driver blocklist: high.

### Pool overflow / UAF

Ask:

- What pool type is allocated?
- Is memory executable?
- What object is adjacent/reusable?
- Is exploit goal control-flow or data-only?
- Does kCFG constrain target callback?
- Does CET constrain return overwrite?
- Does HVCI block making shellcode executable?

Mitigation pressure:

- NonPagedPoolNx/HVCI: high for shellcode.
- kCFG: high for function pointer control.
- CET: high for return control.
- KASLR: high until leak.
- KDP: depends on target data.

## 8. Common misconceptions

### "HVCI bypass means HVCI is broken"

Not necessarily. If a chain avoids unsigned code execution and only corrupts mutable VTL0 data, it may not violate HVCI's main guarantee. HVCI is doing its job, but the system still has dangerous mutable data and dangerous signed drivers.

### "Physical memory R/W bypasses every mitigation"

Too broad. Physical R/W is very strong, but modern systems can still protect selected memory through VBS/EPT policy, block the driver, or make target discovery fragile. Physical R/W gives capability; exploit engineering decides whether it becomes reliable.

### "KDP protects all kernel data"

No. KDP protects selected data that Windows or a driver registers/places under KDP protection. Unprotected kernel objects remain mutable.

### "kCFG stops ROP"

No. kCFG is primarily forward-edge control-flow integrity for indirect calls/jumps. ROP is backward-edge return abuse. Kernel shadow stack/CET is the relevant mitigation.

### "PatchGuard prevents token stealing"

Not reliably as a universal statement. PatchGuard monitors selected critical structures and patching patterns. Per-process token field changes can be short-lived and may not be caught in the same way as SSDT/IDT/code patching. It is still dangerous to rely on this without build-specific testing.

### "Driver signing means driver is safe"

No. Driver signing means the driver passed a trust/signing policy. It says little about IOCTL access control, memory safety, authorization checks, or whether the driver exposes hardware primitives.

## 9. Practical verification commands / places to check

Do not assume mitigation state. Verify it.

Useful places:

- `msinfo32`: VBS running, Credential Guard, HVCI/memory integrity-related state, Kernel DMA Protection.
- Windows Security -> Device Security -> Core Isolation.
- PowerShell WMI/CIM `Win32_DeviceGuard`.
- `System Information`: Secure Boot, VBS services running.
- WDAC policy state and vulnerable driver blocklist state.
- `fltmc`, `driverquery`, `sc query type= driver`, ETW/Sysmon/MDE telemetry for driver load.

Example read-only checks:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
Confirm-SecureBootUEFI
driverquery /v /fo csv
```

For exploit research notes, always record:

- Windows edition.
- Version/build, for example `10.0.22621` or `10.0.26100`.
- HVCI state.
- VBS state.
- Secure Boot state.
- WDAC/blocklist state.
- CPU generation and CET/MBEC support.
- Whether test signing/debug mode is enabled.
- Exact driver hash/version/signature.

## 10. Research workflow when reading a new writeup

For every writeup, fill this:

```text
Driver:
Primitive:
Needs driver load?:
Blocked by current Microsoft blocklist?:
Requires KASLR bypass?:
Requires code execution?:
Requires ROP?:
Requires PTE tamper?:
Requires physical->virtual bridge?:
Targets protected data?:
Likely HVCI impact:
Likely KDP impact:
Likely kCFG impact:
Likely CET impact:
PatchGuard risk:
BSOD risk:
Version sensitivity:
```

This avoids the common trap of saying "works on Windows 11" without specifying which Windows 11, which build, which mitigation state and which driver policy.

## 11. Sources

Primary/high-value references used for this matrix:

- Microsoft Learn - Enable memory integrity / HVCI: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft Learn - OEM HVCI enablement: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-hvci-enablement
- Microsoft Security Blog - Kernel Data Protection: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Microsoft Learn - Kernel-mode Hardware-enforced Stack Protection: https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
- Microsoft Support - Vulnerable driver blocklist after October 2022 preview release: https://support.microsoft.com/en-us/topic/kb5020779-the-vulnerable-driver-blocklist-after-the-october-2022-preview-release-3fcbe13a-6013-4118-b584-fcfbc6a09936
- Microsoft Learn - Recommended driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules
- Microsoft Learn - NX and Execute Pool Types: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/nx-and-execute-pool-types
- Microsoft Learn - No-Execute Nonpaged Pool: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/no-execute-nonpaged-pool
- Microsoft Learn - Windows 10 threat mitigations overview: https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10
- Microsoft Defender exploit protection reference: https://learn.microsoft.com/en-us/defender-endpoint/exploit-protection-reference
- Microsoft Learn - Credential Guard overview: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- Microsoft Learn - System Guard / hardware root of trust: https://learn.microsoft.com/en-gb/windows/security/hardware-security/how-hardware-based-root-of-trust-helps-protect-windows
- Connor McGarr - Code Execution against Windows HVCI: https://connormcgarr.github.io/hvci/
- Satoshi Tanda - Intel VT-rp Part 1: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html
- Satoshi Tanda - Intel VT-rp Part 2: https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html

# BYOVD Non-Terminate Primitive Taxonomy

Updated: 2026-05-26

## Scope

This document explains BYOVD primitives **except process-termination-only primitives**.

Companion case-study catalog:

- `BYOVD_NON_TERMINATE_DRIVER_CASE_STUDIES.md`

Excluded on purpose:

- pure `ZwTerminateProcess` / process-killer drivers,
- EDR-killer cases where the only exposed useful action is process termination,
- process-kill-only discussion already covered in `03_byovd/03_process-kill`.

Included:

- physical memory read/write,
- physical memory mapping into user mode,
- virtual kernel memory read/write,
- MSR read/write,
- I/O port access,
- PCI config / MMIO / BAR mapping,
- kernel memcpy-style primitives,
- limited arithmetic or constrained writes,
- `PreviousMode` / requestor-mode style pivots,
- token / PPL / protection-field data-only manipulation,
- callback and security-state tamper,
- firmware and hardware-control impact,
- device ACL / exposed IOCTL as the root enabler.

The goal is to teach what each primitive can do, why it works, which technique normally fits it, and how to reason about mitigations. This is not a step-by-step exploit guide.

## Sources Used

Primary sources and indexes checked during this pass:

- LOLDrivers driver catalog:
  https://www.loldrivers.io/drivers/
- LOLDrivers `gdrv.sys` entry:
  https://www.loldrivers.io/drivers/2bea1bca-753c-4f09-bc9f-566ab0193f4a/
- LOLDrivers `dbutil_2_3.sys` entry:
  https://www.loldrivers.io/drivers/a4eabc75-edf6-4b74-9a24-6a26187adabf/
- LOLDrivers `RTCore64.sys` entry:
  https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd/
- LOLDrivers `WinIo64.sys` entry:
  https://www.loldrivers.io/drivers/96501e5b-e4f2-41a9-a8ee-d09e36d31a39/
- LOLDrivers `DsArk64.sys` entry:
  https://www.loldrivers.io/drivers/399fb787-5b06-46f0-86cb-dff7374bb015/
- LOLDrivers `MsIo32/MsIo64` entry:
  https://www.loldrivers.io/drivers/4e5064b4-48d3-418c-a7a8-f0dc7ac0a176/
- LOLDrivers `ipctype.sys` entry:
  https://www.loldrivers.io/drivers/509edc55-1881-4fac-8640-b9c516396505/
- BlackSnufkin CVE-2025-52915 write-up:
  https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/
- Eclypsium Screwed Drivers:
  https://eclypsium.com/blog/screwed-drivers-signed-sealed-delivered/
- NDSS BYOVD paper page:
  https://www.ndss-symposium.org/ndss-paper/unveiling-byovd-threats-malwares-use-and-abuse-of-kernel-drivers/
- Lenovo CVE-2025-8061 NVD entry:
  https://nvd.nist.gov/vuln/detail/CVE-2025-8061
- ThrottleStop physical memory write-up:
  https://www.poh0.dev/windows/driver/vulnerability/2025/09/22/throttlestop-vulnerable-driver/
- Paranoid Security BYOVD technique overview:
  https://paranoid.security/en/blog/p/byovd
- Microsoft recommended driver block rules:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

Important caveat:

```text
LOLDrivers is a living catalog, not a fixed primitive taxonomy.
Use it for discovery, then verify each driver by version, hash, signer,
device ACL, IOCTL reachability, blocklist state, and local lab behavior.
```

## Big Picture

BYOVD works because Windows driver signing answers this question:

```text
Is this driver allowed to load?
```

It does **not** answer:

```text
Are the driver's IOCTLs safe?
Can user mode ask it to map arbitrary physical memory?
Can it read or write MSRs?
Can it copy kernel memory on behalf of a caller?
Can an untrusted process open the device object?
```

That gap produces the BYOVD primitive model:

```text
signed vulnerable driver loads
  -> user-mode controller opens device object
  -> controller sends IOCTL
  -> driver performs privileged kernel or hardware action
  -> primitive is converted into impact
```

The primitive is the important unit of analysis. Driver names change, filenames are renamed, and hashes multiply. But the underlying primitive families repeat.

## Quick Taxonomy

| Primitive family | Representative drivers / cases | What it gives | Common technique |
|---|---|---|---|
| Physical memory R/W | `ASTRA64.sys`, `ThrottleStop.sys`, `LnvMSRIO.sys`, `eneio64.sys`, `pstrip64.sys`, `ipctype.sys` | Read/write physical RAM | VA-to-PA translation, page-table walking, physical object scan |
| Physical memory mapping | `WinIo64.sys`, `MsIo64.sys`, `pstrip64.sys` | Maps physical pages into caller address space | Map target PFN, inspect/modify through user VA |
| Virtual kernel R/W | `RTCore64.sys`, `dbutil_2_3.sys`, `DsArk64.sys` | Direct read/write of kernel virtual addresses | Data-only object modification |
| MSR read/write | `gdrv.sys`, `WinRing0`, `LnvMSRIO.sys`, `RTCore64.sys`, `eneio64.sys` | Read/write CPU model-specific registers | KASLR anchor, syscall-path research, fragile control-flow proof |
| I/O port access | `gdrv.sys`, `WinIo64.sys`, `eneio64.sys`, DirectIO-family drivers | Raw x86 port I/O | Hardware/platform manipulation |
| PCI config / MMIO / BAR mapping | `gdrv.sys`, `WinIo64.sys`, hardware utility drivers | Device config and MMIO access | Platform-specific hardware abuse |
| Kernel memcpy-like primitive | `gdrv.sys`, `dbutil_2_3.sys` style cases | Kernel copy between caller-controlled addresses | Build stronger read/write primitive |
| Limited write / arithmetic | `AsIO3.sys` style cases | One-byte, decrement, bitwise or constrained mutation | Find semantic field where small change matters |
| `PreviousMode` pivot | AsIO3-style limited primitive chains | Makes selected native API paths treat caller as kernel mode | API-mediated kernel read/write under strict assumptions |
| Token / PPL / protection field tamper | RTCore64, physical R/W drivers, `wfshbr64.sys` style field mutation | Changes process security semantics | Data-only DKOM |
| Callback/security-state tamper | arbitrary write drivers, malicious demo drivers | Disables or corrupts security callbacks/state | Short-lived object/state mutation |
| Firmware / UEFI / device persistence | Eclypsium-class hardware drivers | Access below OS boundary | Firmware update path abuse, SPI/BIOS/device firmware risk |

## 1. Physical Memory Read/Write

### What It Is

Physical memory R/W means the driver allows a user-mode caller to read or write physical addresses.

The driver may expose this through:

- `MmMapIoSpace`,
- `\Device\PhysicalMemory`,
- vendor-specific memory map helpers,
- physical address plus size parameters in an IOCTL,
- helper functions intended for diagnostics, overclocking, flashing, or hardware monitoring.

Representative cases:

- `ThrottleStop.sys`: public write-up describes arbitrary physical memory read/write through `MmMapIoSpace`.
- `LnvMSRIO.sys`: CVE-2025-8061 reports insufficient access control in Lenovo Dispatcher drivers; public summaries describe MSR and physical-memory primitives.
- `ASTRA64.sys`: repo-local docs already cover physical-memory R/W and MSR read.
- `eneio64.sys`: RGB/hardware control driver family with physical memory, MSR and port I/O discussion.
- `pstrip64.sys`: old hardware/display utility family with physical mapping behavior.
- `ipctype.sys`: LOLDrivers describes physical memory R/W via `MmMapIoSpace`.

### Why It Works

Windows normally prevents user-mode code from directly touching arbitrary physical RAM.

But a kernel driver can map physical ranges because legitimate hardware drivers need to access device memory:

```text
device register or physical range
  -> driver maps it
  -> driver reads/writes it
```

The vulnerability appears when the driver lets the caller choose the physical address without strict validation:

```text
user controls physical address
  -> driver maps that address
  -> driver reads or writes it
  -> user gains access to memory outside normal process boundaries
```

### What It Can Do

Physical R/W can enable:

- reading kernel memory after translation,
- writing kernel object fields,
- token/security-state modification,
- process protection field changes,
- page-table research,
- locating kernel objects by physical scanning,
- corrupting kernel data accidentally and causing BSOD,
- in some environments, interacting with memory-mapped device or firmware regions.

The important distinction:

```text
physical R/W is raw material.
It is not automatically reliable kernel object control.
```

### Main Technique: VA-to-PA Translation

Most Windows kernel targets are known as virtual addresses:

```text
ntoskrnl base
EPROCESS address
TOKEN address
driver object
callback array
```

But the driver expects physical addresses.

So the researcher needs a bridge:

```text
kernel virtual address
  -> page-table walk
  -> physical address
  -> physical R/W driver touches it
```

Why page-table walking is preferred:

- It is more deterministic than blind physical scanning.
- It explains exactly which PFN backs the target virtual address.
- It scales from one object to many object types.

Why physical scanning still appears:

- Sometimes the page-table base is unavailable.
- Some structures have recognizable patterns.
- Scanning can find `_EPROCESS`-like objects by PID, image name, and list links.

Why scanning is fragile:

- false positives,
- memory pressure,
- version drift,
- object reuse,
- crash risk on writes.

### Reasoning Questions

Ask:

- Does the driver expose physical read, write, or both?
- Does it map memory into the caller process, or does it copy bytes through an IOCTL?
- Can the caller choose arbitrary physical addresses?
- Does the driver restrict ranges to real device BARs or safe hardware resources?
- Does HVCI block driver load, or only make later code execution harder?
- How will virtual kernel targets be translated into physical addresses?
- What proves the physical address really backs the object you think it does?

### Mitigation Pressure

Physical R/W is dangerous even with HVCI enabled. HVCI protects code integrity assumptions; it does not automatically sanitize an allowed driver's IOCTL semantics.

Practical defenses:

- block known vulnerable drivers with WDAC or Microsoft recommended block rules,
- remove unnecessary hardware/RGB/overclocking/mining/diagnostic tools,
- monitor driver load and device opens,
- inventory driver versions and signers,
- treat `MmMapIoSpace`-style helper drivers as high-risk.

## 2. Physical Memory Mapping Into User Mode

### What It Is

This is a close cousin of physical memory R/W. Instead of the driver performing read/write copies, it maps a physical range into the user-mode process address space.

Representative cases:

- `WinIo64.sys`: LOLDrivers describes mapping `\Device\PhysicalMemory` into user space and offering port I/O.
- `MsIo64.sys` / `MsIo32.sys`: LOLDrivers describes mapping `\Device\PhysicalMemory` into the caller process.
- `pstrip64.sys`: PowerStrip-style physical memory mapping.

### Why It Works

The dangerous boundary crossing is:

```text
kernel opens/maps physical memory
  -> user process receives virtual mapping
  -> user reads/writes mapped physical page
```

The driver may believe it is enabling legitimate hardware diagnostics. But if the caller controls the target physical range, the user process can inspect or modify memory that should never be user-accessible.

### What It Can Do

It can support:

- physical RAM inspection,
- physical-memory object scanning,
- kernel object mutation after locating physical pages,
- device MMIO access,
- platform-specific hardware manipulation,
- denial of service through invalid writes.

### Why It Is Often More Dangerous Than Copy-Based R/W

With copy-based R/W:

```text
each IOCTL reads or writes a bounded chunk
```

With mapping:

```text
user process gets a window onto physical memory
```

That can allow repeated direct reads/writes without a fresh IOCTL for every byte, depending on mapping permissions and driver design.

### Defensive Questions

- Does the driver call `ZwOpenSection` or `ZwMapViewOfSection` for `\Device\PhysicalMemory`?
- Does it map physical ranges into user mode?
- Are mapped ranges limited to real device resources?
- Can low-integrity or standard users open the device?
- Are there user-mode processes with suspicious mappings after driver load?

## 3. Virtual Kernel Read/Write

### What It Is

Virtual kernel R/W means the driver accepts kernel virtual addresses and reads/writes them directly, or performs a copy that effectively gives that ability.

Representative cases:

- `RTCore64.sys`: LOLDrivers says MSI Afterburner driver versions allow arbitrary memory, I/O port, and MSR access.
- `dbutil_2_3.sys`: Dell driver case with memory copy/read/write style issues and long public history.
- `DsArk64.sys`: LOLDrivers describes arbitrary kernel read and write in addition to process termination.
- `gdrv.sys`: exposes memory and hardware operations including memcpy-like functionality.

### Why It Works

Kernel-mode code can dereference kernel virtual addresses. If a driver uses caller-controlled addresses as source or destination without validating them, it becomes a broker:

```text
user supplies kernel VA
  -> signed driver reads/writes that VA
  -> result crosses user/kernel isolation
```

This is simpler than physical R/W because the researcher can target the same address model used by WinDbg and symbols.

### What It Can Do

Virtual R/W is one of the strongest BYOVD primitives:

- read kernel pointers and defeat KASLR,
- read process/token/security object state,
- modify token or protection fields,
- manipulate callback registration state,
- patch selected writable data,
- build a stronger arbitrary read/write abstraction,
- crash the system on invalid write.

### Best-Fit Technique

The best-fit technique is usually data-only object modification:

```text
find object
  -> validate build and offset
  -> change minimal field
  -> verify effect
  -> restore if possible
```

Why not jump straight to code execution?

- HVCI makes unsigned/new executable kernel code harder.
- PatchGuard watches many global code and dispatch targets.
- Data-only changes can achieve LPE or protection changes with fewer moving parts.

### Reasoning Questions

- Is read available, write available, or only write?
- Can the primitive access all kernel VA ranges or only a limited region?
- Does the driver enforce alignment/size restrictions?
- Does it use `memcpy`, `MmCopyMemory`, MDLs, or direct pointer dereference?
- How will kernel object addresses be discovered?
- Is the target field stable on this Windows build?

## 4. Kernel Memcpy-Like Primitive

### What It Is

Some drivers expose operations equivalent to:

```text
copy from address A to address B for length N
```

If the caller controls `A`, `B`, and `N`, this becomes a read/write primitive depending on direction.

Representative cases:

- `dbutil_2_3.sys` public analyses discuss IOCTL memory copy behavior.
- `gdrv.sys` LOLDrivers describes ring0 memcpy-like functionality.

### Why It Works

The driver is trusted kernel code. If it copies memory between caller-controlled addresses, it can be tricked into copying:

```text
kernel -> user
user -> kernel
kernel -> kernel
```

Each direction has different impact:

| Direction | Meaning | Impact |
|---|---|---|
| kernel -> user | arbitrary read | leak pointers, object state, secrets |
| user -> kernel | arbitrary write | modify kernel object/data |
| kernel -> kernel | internal copy | duplicate or corrupt privileged state |

### Why This Primitive Is Valuable

It often avoids physical translation. It also allows controlled small writes, which are enough for many data-only targets.

But it has the same core risk:

```text
wrong address or wrong size = likely crash
```

## 5. MSR Read/Write

### What It Is

MSRs are CPU model-specific registers. They hold privileged CPU state such as syscall entry points, feature controls, debugging/performance state, and platform-specific configuration.

Representative cases:

- `gdrv.sys`: LOLDrivers lists MSR read/write.
- WinRing0 / Awesome Miner style drivers: MSR access is a recurring primitive.
- `LnvMSRIO.sys`: public CVE-2025-8061 summaries describe MSR operations.
- `RTCore64.sys`: LOLDrivers describes MSR access.
- `eneio64.sys`: public research discusses MSR plus physical memory and port I/O.

### Why It Works

Normal user mode cannot execute `rdmsr` or `wrmsr`.

A vulnerable driver can expose:

```text
user asks driver to read/write MSR X
  -> driver executes privileged CPU instruction
  -> result returns to user or changes CPU state
```

### What It Can Do

MSR read can:

- leak syscall-entry addresses,
- provide KASLR anchors,
- expose CPU/platform state,
- help locate `ntoskrnl` base through `LSTAR`.

MSR write can:

- corrupt critical CPU state,
- redirect syscall transition paths in lab proofs,
- trigger immediate crash if wrong,
- support fragile kernel-control demonstrations.

### Main Technique: `LSTAR` as Anchor

`IA32_LSTAR` stores the x64 syscall entry target.

The common reasoning chain:

```text
read LSTAR
  -> get pointer inside ntoskrnl syscall entry path
  -> scan backward for PE header
  -> recover ntoskrnl base
```

See:

- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`

### Why MSR Write Is Usually a Bad Stable Exploit Choice

MSR write is powerful but unstable:

- affects CPU control flow,
- often per-core sensitive,
- bad value bugchecks immediately,
- PatchGuard and telemetry pressure are high,
- HVCI/kCFG/CET complicate follow-on code execution.

Better rule:

```text
Use MSR read as a research anchor.
Treat MSR write as high-risk proof-of-control, not the default path.
```

## 6. I/O Port Access

### What It Is

I/O port access exposes x86 `in` / `out` style port operations through a driver.

Representative cases:

- `gdrv.sys`,
- `WinIo64.sys`,
- `eneio64.sys`,
- DirectIO / WinIO-family drivers.

### Why It Works

User mode normally cannot perform arbitrary port I/O. Hardware utility drivers sometimes expose port reads/writes so vendor tools can talk to chipset, sensor, embedded controller, or board-specific hardware.

The dangerous pattern:

```text
caller chooses port number and width
  -> driver performs in/out instruction
  -> user controls hardware-facing operation
```

### What It Can Do

Port I/O can enable:

- device or chipset manipulation,
- reading hardware state,
- writing device control registers,
- platform-specific escalation research,
- denial of service,
- bricking or destabilizing hardware in worst cases.

It is less universal than kernel memory R/W because impact depends heavily on hardware.

### Reasoning Questions

- Which ports are reachable?
- Does the driver restrict port ranges?
- Is the target platform known?
- Is the operation safe on virtual machines?
- Does the driver combine port I/O with MMIO or PCI config access?

## 7. PCI Config, MMIO, and BAR Mapping

### What It Is

Some drivers expose PCI configuration space, MMIO BAR mapping, or memory-mapped device register access.

Representative cases:

- `gdrv.sys` class drivers,
- `WinIo64.sys` and WinIO-family drivers,
- hardware monitoring / tuning / flashing utilities.

### Why It Works

Hardware devices expose configuration and MMIO regions. Legitimate drivers need controlled access to those regions.

The vulnerability occurs when user mode controls:

- bus/device/function,
- PCI config offset,
- MMIO physical address,
- BAR selection,
- mapping size,
- read/write width.

### What It Can Do

Impact is platform-dependent:

- tamper with device configuration,
- map device memory into user mode,
- change DMA-relevant settings,
- access firmware update paths,
- disrupt devices,
- potentially pivot into persistence below the OS if firmware update mechanisms are reachable.

Eclypsium's research highlights why this matters beyond normal LPE: insecure hardware drivers can expose firmware and device-management surfaces below the operating system.

### Defensive Questions

- Is this driver required on the endpoint?
- Does it expose generic PCI/MMIO access or only device-specific safe operations?
- Does it run on servers or security-sensitive workstations?
- Can WDAC block it without business impact?
- Are there event logs or EDR telemetry around driver load before firmware anomalies?

## 8. Limited Write, Arithmetic, or Bitwise Primitive

### What It Is

Not every primitive is full arbitrary R/W. Some drivers expose:

- decrement,
- increment,
- OR/AND/XOR bit operation,
- fixed-size write,
- write to constrained offset,
- fixed destination family,
- write only when a condition passes.

Representative cases:

- `AsIO3.sys` style limited primitive research.
- `wfshbr64.sys` LOLDrivers entry describes bitwise operations against process protection/signature fields.

### Why It Works

Windows security often depends on small fields:

- mode byte,
- protection level,
- signature level,
- privilege bit,
- flag field,
- reference count,
- list state.

A tiny write can matter if it targets a semantic field:

```text
small mutation
  -> large policy interpretation change
```

### What It Can Do

Depending on target:

- flip or downgrade requestor mode,
- change process protection semantics,
- change signature level,
- influence object flags,
- create unstable object lifetime behavior,
- trigger controlled denial of service.

### Main Technique: Find a Semantic Target

For limited primitives, exploitability is not about write size. It is about field meaning.

Reasoning process:

```text
What exactly can be changed?
  -> which kernel fields are that size/type?
  -> would a one-step change alter security behavior?
  -> can it be restored?
  -> is the field protected or checked elsewhere?
```

### Why This Is Fragile

- offsets drift,
- small fields are packed,
- wrong byte can crash,
- modern builds may harden the target,
- verifier or PatchGuard may detect corruption,
- target effect may vary by call path.

## 9. `PreviousMode` / Requestor-Mode Pivot

### What It Is

`PreviousMode` is a thread/requestor-mode concept used by native APIs to decide whether a caller should be treated as user mode or kernel mode for probing and access validation.

Some limited primitives try to change a field such that later native API calls treat the caller as more trusted than it really is.

Representative:

- AsIO3-style limited primitive chains in this repo.
- Lazarus/DBUtil discussion in public BYOVD material often references `PreviousMode`-style impact.

### Why It Works

Many kernel routines distinguish:

```text
UserMode caller
  -> probe buffers
  -> enforce user pointer restrictions
  -> perform access checks

KernelMode caller
  -> trust kernel caller more
  -> skip some probing paths
```

If a user-originating thread is misclassified, later API behavior changes.

### What It Can Do

Under the right build and call path, it can support:

- API-mediated kernel memory read/write,
- bypass of user-buffer probing,
- handle/object access semantics changes,
- privilege escalation research without direct arbitrary write.

### Why It Is Not Universal

It depends on:

- exact Windows build,
- exact thread structure layout,
- target API behavior,
- whether the changed state is restored,
- whether mitigations or validation logic changed,
- whether the primitive can target the right byte safely.

### Reasoning Questions

- Which thread is affected?
- Which future API call consumes the field?
- Does that API still branch on the field in this build?
- Is the field byte-sized, packed, or guarded?
- How is the field restored?
- What telemetry sees the abnormal native API behavior?

## 10. Token, PPL, Signature, and Protection Field Manipulation

### What It Is

This is data-only DKOM focused on process security state:

- token relationship,
- process protection level,
- signature level,
- section signature level,
- mitigation flags,
- access-related fields.

Representative cases:

- `RTCore64.sys` and other virtual R/W drivers can support direct field modification.
- Physical R/W drivers can support this after translation.
- `wfshbr64.sys` LOLDrivers entry describes protection/signature field bit operations.
- `DsArk64.sys` exposes constrained kernel R/W according to LOLDrivers.

### Why It Works

Windows makes security decisions from kernel object state:

```text
process asks for access
  -> kernel consults token/protection/signature state
  -> decision changes based on object fields
```

If a primitive changes those fields, future legitimate checks may produce different results.

### What It Can Do

Possible impacts:

- privilege escalation,
- PPL bypass or downgrade in lab contexts,
- making a process appear more trusted,
- enabling access that should be denied,
- disabling or weakening security product self-protection,
- creating forensic inconsistencies.

### Why Data-Only Is Popular

It avoids:

- new unsigned kernel code,
- executable memory allocation,
- long-lived code patching,
- many HVCI/kCFG/CET problems.

But it still requires:

- correct object address,
- correct field offset,
- build validation,
- safe restore plan,
- understanding of reference/fast-ref semantics.

### Failure Modes

- wrong offset corrupts unrelated field,
- token fast-reference bits mishandled,
- protection level changed inconsistently,
- security product notices impossible state,
- PatchGuard/KDP protects selected data,
- object lifetime changes while primitive is in use.

## 11. Callback and Security-State Tamper

### What It Is

Security products use callbacks and filters for:

- process/thread/image notifications,
- object handle callbacks,
- registry callbacks,
- minifilter callbacks,
- network and filesystem inspection,
- self-protection.

An arbitrary write primitive may target callback registration state or security product data.

Representative cases:

- arbitrary write drivers like `RTCore64.sys`, `gdrv.sys`, `dbutil_2_3.sys` can theoretically support this.
- LOLDrivers includes malicious demo material describing callback and notify callback nulling.
- Repo-local docs cover callback surfaces separately.

### Why It Works

Callbacks are data-driven registration systems:

```text
security product registers callback
  -> kernel stores callback pointer/state
  -> event occurs
  -> kernel invokes callback
```

If callback state is corrupted, the security product may stop seeing events or the system may crash.

### What It Can Do

- blind selected security telemetry,
- weaken process handle protection,
- disrupt image load monitoring,
- interfere with registry/file callbacks,
- crash the system,
- create PatchGuard-sensitive corruption.

### Why This Is High Risk

This class is more dangerous and less stable than token-style data-only changes:

- callbacks are often guarded,
- PatchGuard may monitor critical lists,
- EDR products watch for callback anomalies,
- a wrong pointer causes immediate crash,
- persistence is hard without detection.

### Defensive Questions

- Did a vulnerable R/W driver load before callback disappearance?
- Do callback pointers point into valid module ranges?
- Are security product callbacks absent after service remains running?
- Is driver-load telemetry followed by loss of EDR visibility?
- Do crash dumps show callback list corruption?

## 12. Firmware, UEFI, and Hardware-Control Impact

### What It Is

Some BYOVD primitives cross below the Windows kernel into platform hardware or firmware management.

Representative source:

- Eclypsium Screwed Drivers research describes drivers exposing access to processor/chipset I/O space, MSRs, control/debug registers, physical memory, kernel virtual memory, and firmware/device surfaces.

### Why It Works

Hardware management tools often need privileged access to:

- flash firmware,
- read/write BIOS settings,
- update device firmware,
- control fans/voltage/sensors,
- configure PCI devices,
- talk to embedded controllers.

If those tools expose generic access, they become platform attack surfaces.

### What It Can Do

Depending on hardware and driver:

- firmware tamper,
- persistent implant path,
- device disruption,
- destructive configuration changes,
- bypass OS reinstall by persisting below OS,
- denial of service or bricking.

### Why This Is Different From Token LPE

Token LPE changes Windows state. Firmware/hardware abuse changes platform state.

That means:

- remediation may require firmware reflash,
- forensic visibility is weaker,
- persistence can survive OS reinstall,
- blast radius may include device integrity, not just OS integrity.

### Defensive Priority

Block or tightly govern:

- firmware update helpers,
- BIOS/UEFI utilities,
- RGB/overclocking drivers,
- direct hardware access libraries,
- mining/monitoring tools with WinRing0/WinIO/DirectIO lineage.

## 13. Device ACL / Exposed IOCTL as Root Primitive

### What It Is

Sometimes the "primitive" is not a memory bug. It is an authorization failure:

```text
driver exposes privileged IOCTL
  -> weak device ACL allows unexpected caller
  -> caller asks driver to perform privileged action
```

NVD classifies Lenovo CVE-2025-8061 under CWE-782: exposed IOCTL with insufficient access control.

### Why It Works

Drivers often create:

```text
\Device\VendorThing
  -> symbolic link
  -> user opens \\.\VendorThing
```

If the device object security descriptor is too permissive, user mode can reach privileged code paths.

### What It Can Enable

Depending on driver:

- physical memory access,
- MSR access,
- port I/O,
- virtual memory read/write,
- callback manipulation,
- process/security object manipulation,
- firmware access.

### Analysis Questions

- Who can open the device object?
- Does the driver check caller identity after open?
- Does it require a signed/vendor controller process?
- Is that controller check bypassable?
- Are IOCTL access bits meaningful or ignored?
- Does the driver use `FILE_ANY_ACCESS` for privileged operations?

This question comes before primitive details:

```text
Can an unexpected caller reach the dangerous path at all?
```

## 14. Primitive Selection: Why Different Drivers Lead to Different Techniques

| If the driver gives... | Researcher usually tries... | Why |
|---|---|---|
| physical R/W | VA-to-PA bridge or physical object scan | Target objects are understood virtually, driver works physically |
| virtual R/W | direct object/data mutation | No translation needed |
| MSR read | kernel base discovery | `LSTAR` gives pointer into `ntoskrnl` |
| MSR write | syscall-path proof or crash PoC | Very powerful but unstable |
| port I/O | platform-specific hardware control | Impact depends on chipset/device |
| PCI/MMIO | device or firmware manipulation | Hardware registers may be reachable |
| limited write | semantic field target | Small write can change policy if field is meaningful |
| weak ACL only | call intended privileged feature | The bug is authorization, not memory safety |
| callback-state write | blind or disrupt telemetry | High risk, PatchGuard/EDR-sensitive |

## 15. Why "Arbitrary Kernel R/W" Is Not One Thing

People often say "arbitrary R/W" too loosely.

There are several different strengths:

| Primitive | Strength | Hard part |
|---|---|---|
| physical read only | medium | finding target physical pages |
| physical write only | high but dangerous | safe target discovery |
| physical read/write | high | VA-to-PA bridge |
| virtual read only | medium | turning leak into useful action |
| virtual write only | high but blind | knowing exact target and value |
| virtual read/write | strongest | safe object selection |
| fixed-size write | medium/high | finding suitable field |
| bitwise mutation | narrow | semantic target choice |
| MSR write | very high but unstable | not crashing |

Good documentation should never stop at:

```text
driver has arbitrary write
```

It should ask:

```text
write where?
write how much?
write from what source?
with readback?
virtual or physical?
aligned or unaligned?
can it cross pages?
is target protected?
```

## 16. Mitigation Interaction

### DSE

Driver Signature Enforcement does not help when the vulnerable driver is legitimately signed and accepted by policy.

### HVCI / Memory Integrity

HVCI helps against unsigned code execution and many code-patching strategies. It does not automatically make unsafe IOCTLs safe.

Lenovo's CVE-2025-8061 NVD entry notes that the issue does not affect systems when Core Isolation Memory Integrity is enabled. That is important for that specific driver/version path, but it should not be generalized to all BYOVD.

### WDAC / Vulnerable Driver Blocklist

This is the most important practical control:

```text
do not let known dangerous drivers load
```

But blocklists lag. LOLDrivers and Microsoft rules are inputs, not complete truth.

### PatchGuard

PatchGuard pressures long-lived kernel patching, callback tamper, SSDT/service table mutation, and some global structure corruption. It is less relevant to short-lived semantic changes, but not irrelevant.

### KDP / VBS Protected Data

KDP can protect selected data regions. A primitive may be strong in general but fail against a protected target.

### EDR and ETW

EDR may not see private IOCTL semantics, but it can correlate:

- driver load,
- service creation,
- signer/hash,
- device handle open,
- crash,
- security process tamper,
- sudden privilege change,
- loss of telemetry.

## 17. Defensive Priority Ranking, Excluding Process Termination

1. Physical memory R/W or mapping drivers.
   - Reason: can become broad kernel object control.
2. Virtual kernel R/W drivers.
   - Reason: direct data-only impact with less translation.
3. MSR read/write drivers.
   - Reason: strong KASLR/control-flow primitive, high crash risk.
4. PCI/MMIO/port I/O drivers.
   - Reason: hardware/firmware impact and platform-specific risk.
5. Limited write/arithmetic primitives.
   - Reason: narrow but can be devastating if target field is semantic.
6. Callback/security-state tamper targets.
   - Reason: high-value but noisy and fragile.
7. Weak ACL/exposed IOCTL without confirmed dangerous operation.
   - Reason: may become high priority once reachable privileged action is confirmed.

## 18. How to Write a Per-Driver Primitive Note

Use this template:

```text
Driver:
Vendor:
Product:
Signer:
Known vulnerable versions:
Known safe/fixed versions:
LOLDrivers link:
Public write-up:

Loadability:
  Signed:
  Blocklisted:
  HVCI compatible:
  WDAC policy needed:

Reachability:
  Device object:
  Symbolic link:
  Device ACL:
  Requires hardware:
  Requires vendor service:
  IOCTL auth:

Primitive:
  Physical read:
  Physical write:
  Physical map:
  Virtual read:
  Virtual write:
  MSR read/write:
  Port I/O:
  PCI/MMIO:
  Limited write:
  Callback/security state:
  Firmware/hardware control:

Technique:
  What can this primitive realistically do?
  What bridge is needed?
  Why does that bridge work?
  What is build-sensitive?
  What can crash?

Detection:
  Driver load:
  Service creation:
  Device open:
  Unusual caller:
  Post-load behavior:
  Crash/CI/EDR telemetry:
```

## 19. Study Questions

Use these after reading any BYOVD write-up:

- Is the driver dangerous because of memory corruption, unsafe intended functionality, or weak access control?
- Is the primitive physical or virtual?
- Does it provide read, write, or both?
- Does it require hardware?
- Does it require admin to load, or can low-priv users open an already-loaded device?
- Is the best impact data-only, control-flow, hardware, firmware, or telemetry disruption?
- Which mitigation actually blocks it: HVCI, WDAC, blocklist, vendor patch, device ACL, or EDR correlation?
- If a write-up says "kernel R/W", what address space does it mean?
- If it says "MSR", is the MSR used for leak, control, or just proof of crash?
- If it says "physical memory", how does it find the target object?

## 20. Summary

Non-terminate BYOVD primitives fall into a few repeatable families:

```text
physical memory
virtual kernel memory
MSR
port I/O
PCI/MMIO
limited semantic write
callback/security-state tamper
firmware/hardware control
weak device access
```

The core reasoning pattern is:

```text
What privileged operation does the driver perform?
Who can ask it to perform that operation?
What does the primitive directly expose?
What bridge turns it into impact?
What mitigations break that bridge?
What telemetry shows the setup or result?
```

If a note answers those questions clearly, it is useful. If it only names a driver and says "arbitrary R/W", it is incomplete.

# BYOVD Non-Terminate Driver Case Studies

Updated: 2026-05-27

## Scope

This catalog covers BYOVD cases whose main value is **not** a process-termination-only primitive.

Included:

- physical memory read/write or mapping,
- virtual kernel read/write,
- kernel memcpy / copy primitive,
- MSR read/write,
- port I/O, PCI config, MMIO, firmware-facing access,
- limited write / `PreviousMode` style impact,
- callback or security-state tamper enabled by memory primitives.

Excluded:

- pure process-killer drivers,
- EDR-killer cases where the only meaningful operation is process termination.

## How To Read Each Case

Each case asks the same questions:

```text
What primitive does the driver expose?
Why does that primitive cross a Windows trust boundary?
What can it realistically do?
What bridge is needed to turn primitive into impact?
What fails?
What should defenders hunt?
```

The goal is not to memorize driver names. The goal is to learn the primitive families that keep repeating across signed vulnerable drivers.

## Quick Map

| Driver / family | Vendor / product family | Primitive class | Main lesson |
|---|---|---|---|
| `RTCore64.sys` | MSI Afterburner / hardware tuning | virtual kernel R/W, MSR/I/O family | Direct virtual R/W is a short path to data-only object modification |
| `dbutil_2_3.sys` | Dell firmware update utility | insufficient access control, memory copy/write family | Firmware/update helper drivers can become generic kernel memory brokers |
| `gdrv.sys` | GIGABYTE utility driver | multi-primitive: memory, MSR, port I/O, PCI/MMIO | One driver can expose several independent primitive families |
| WinRing0 / WinIo / MsIo | hardware monitoring/control libraries | MSR, port I/O, physical mapping | Reused low-level libraries create broad ecosystem risk |
| `LnvMSRIO.sys` | Lenovo Dispatcher / MSR helper | physical memory + MSR | Core Isolation/HVCI nuance matters per driver/version |
| ThrottleStop / ENE / PowerStrip / IPCType | tuning/RGB/display/industrial utility drivers | physical memory R/W or mapping | Physical primitives need a bridge: VA-to-PA or object scanning |
| AsIO3-style limited primitive | ASUS utility family | limited write / `PreviousMode` | Small writes matter when the target field is semantic |
| Callback/security-state targets | R/W-capable drivers as enablers | callback/security state tamper | Defense evasion is usually consistency tamper, not magic invisibility |

## Case 1. `RTCore64.sys`

Deep dive:

- `BYOVD_CASE_RTCORE64.md`

Primitive:

- virtual kernel read/write,
- hardware/MSR-adjacent capability depending version/context,
- widely referenced in BYOVD tooling and EDR bypass research.

Why it matters:

```text
virtual R/W skips the physical translation problem
```

With physical memory drivers, the researcher must translate from kernel virtual address to physical address. With virtual kernel R/W, the driver already accepts addresses in the model used by symbols, debugger output, and kernel object references.

What it can do:

- read kernel pointers,
- discover process and token state,
- modify data-only fields,
- support PPL/protection-field research,
- enable callback/security-state tamper if the target is known.

Technique path:

```text
find kernel object
  -> validate build-specific offsets
  -> read current field
  -> perform minimal data-only mutation
  -> verify or restore
```

What fails:

- wrong offset,
- object lifetime race,
- encoded pointer / fast-ref handling error,
- writing PatchGuard-sensitive state,
- vulnerable driver blocked by Windows policy.

Sources:

- LOLDrivers RTCore64 entry: https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd/
- EDRSandblast: https://github.com/wavestone-cdt/EDRSandblast

## Case 2. `dbutil_2_3.sys`

Deep dive:

- `BYOVD_CASE_DBUTIL_2_3.md`

Primitive:

- insufficient access control in a Dell firmware update driver,
- memory corruption / memory copy / arbitrary write family depending public write-up path,
- local authenticated user can reach dangerous behavior in vulnerable versions.

Why it matters:

Firmware/update drivers are trusted because they need privileged system access. If the driver exposes generic copy/write behavior, it becomes a kernel memory broker.

What it can do:

- privilege escalation,
- information disclosure,
- denial of service,
- low-level disk/storage or firmware-adjacent impact depending path.

Technique path:

```text
unsafe driver copy/write behavior
  -> attacker controls meaningful source/destination semantics
  -> kernel memory or privileged state changes
```

What fails:

- Dell remediation removed affected driver,
- vulnerable driver blocklist / WDAC blocks load,
- wrong copy direction assumption,
- modern mitigations make old exploit path stale.

Sources:

- NVD CVE-2021-21551: https://nvd.nist.gov/vuln/detail/CVE-2021-21551
- Dell advisory referenced by NVD: https://www.dell.com/support/kbdoc/en-us/000186019/dsa-2021-088-dell-client-platform-security-update-for-dell-driver-insufficient-access-control-vulnerability
- Connor McGarr write-up: https://connormcgarr.github.io/cve-2020-21551-sploit/
- EDRSandblast: https://github.com/wavestone-cdt/EDRSandblast

## Case 3. `gdrv.sys`

Deep dive:

- `BYOVD_CASE_GDRV.md`

Primitive:

- multi-primitive driver,
- memory copy / kernel memory operations,
- MSR read/write,
- port I/O,
- PCI/MMIO style low-level access.

Why it matters:

`gdrv.sys` is useful as a teaching case because it shows that one vulnerable driver can provide multiple different primitive classes. A defender cannot label it only as "arbitrary write" and be done.

What it can do:

- kernel memory read/write style research,
- MSR-based KASLR anchor,
- port or hardware access,
- platform-specific device manipulation,
- callback/security-state tamper if paired with object discovery.

Technique path:

```text
choose primitive branch
  -> memory path for data-only object changes
  -> MSR path for kernel-base anchor or fragile syscall research
  -> port/MMIO path for platform-specific hardware impact
```

What fails:

- choosing the wrong primitive for the goal,
- MSR write instability,
- hardware-specific assumptions,
- driver blocked or renamed but behavior still detected.

Sources:

- LOLDrivers gdrv entry: https://www.loldrivers.io/drivers/2bea1bca-753c-4f09-bc9f-566ab0193f4a/
- EDRSandblast: https://github.com/wavestone-cdt/EDRSandblast

## Case 4. WinRing0 / WinIo / MsIo Family

Deep dive:

- `BYOVD_CASE_WINRING0_WINIO_MSIO.md`

Primitive:

- MSR read/write,
- port I/O,
- physical memory access or mapping depending library/driver,
- broad reuse inside hardware monitoring, RGB, gaming, and tuning tools.

Why it matters:

The same vulnerable low-level component appears under many product names. Filename-only detection is weak.

What it can do:

- expose CPU state,
- read/write privileged memory ranges,
- manipulate hardware ports,
- create KASLR anchors,
- destabilize host if misused.

Technique path:

```text
identify library lineage
  -> classify exposed hardware/memory operations
  -> decide whether impact is kernel object, CPU state, or hardware state
```

What fails:

- driver variant differs from expected,
- Defender or blocklist blocks WinRing0 family,
- hardware operation is platform-specific,
- product update switches driver backend.

Sources:

- Microsoft WinRing0 Defender alert: https://support.microsoft.com/en-us/windows/microsoft-defender-antivirus-alert-vulnerabledriver-winnt-winring0-eb057830-d77b-41a2-9a34-015a5d203c42
- LOLDrivers WinIo64 entry: https://www.loldrivers.io/drivers/96501e5b-e4f2-41a9-a8ee-d09e36d31a39/
- LOLDrivers MsIo entry: https://www.loldrivers.io/drivers/4e5064b4-48d3-418c-a7a8-f0dc7ac0a176/

## Case 5. `LnvMSRIO.sys`

Deep dive:

- `BYOVD_CASE_LNVMSRIO.md`

Primitive:

- physical memory read/write,
- MSR read/write,
- weak or missing device access controls in affected versions.

Why it matters:

This is a modern OEM case. It shows that a signed driver distributed through legitimate channels can expose Ring-0 capabilities through logical access-control mistakes.

What it can do:

- physical memory inspection/mutation,
- MSR-based kernel-base anchor,
- fragile MSR control-flow research,
- data-only impact after physical-to-virtual bridge.

Technique path:

```text
physical/MSR primitive
  -> use MSR read or other anchor for kernel layout
  -> bridge physical memory to virtual targets
  -> avoid code execution when data-only impact is enough
```

What fails:

- Core Isolation / HVCI behavior differs by version/config,
- fixed Lenovo versions,
- MSR write instability,
- blocklist or WDAC policy prevents load.

Sources:

- Quarkslab Lenovo CVE-2025-8061: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- NVD CVE-2025-8061: https://nvd.nist.gov/vuln/detail/CVE-2025-8061

## Case 6. Physical Memory Family: ThrottleStop / ENE / PowerStrip / IPCType

Deep dive:

- `BYOVD_CASE_PHYSICAL_MEMORY_FAMILY.md`

Primitive:

- physical memory read/write,
- physical memory mapping,
- sometimes MSR and port I/O.

Why it matters:

These drivers show the same root pattern across different product categories:

```text
legitimate utility needs low-level hardware access
  -> driver exposes too-generic physical memory operation
  -> user-mode caller can turn hardware helper into kernel memory primitive
```

What it can do:

- map or inspect physical RAM,
- bridge to kernel virtual object targets,
- mutate process/token/protection state,
- crash through wrong physical writes,
- support hardware-specific effects.

Technique path:

```text
physical primitive
  -> VA-to-PA translation or physical object scan
  -> data-only kernel object modification
```

What fails:

- no reliable target discovery,
- wrong physical page,
- driver needs hardware,
- HVCI/blocklist prevents load,
- old write-up assumptions stale on current Windows.

Sources:

- ThrottleStop write-up: https://www.poh0.dev/windows/driver/vulnerability/2025/09/22/throttlestop-vulnerable-driver/
- GitHub advisory CVE-2025-7771: https://github.com/advisories/GHSA-f8p7-vvxp-hcxv
- NVD CVE-2026-29923 PowerStrip: https://nvd.nist.gov/vuln/detail/CVE-2026-29923
- LOLDrivers IPCType entry: https://www.loldrivers.io/drivers/509edc55-1881-4fac-8640-b9c516396505/

## Case 7. AsIO3-Style Limited Primitive

Primitive:

- constrained decrement / limited arithmetic mutation,
- useful only if target field has matching semantics.

Why it matters:

Limited primitives teach an important lesson:

```text
exploitability is not only write size;
exploitability is field meaning
```

What it can do:

- influence `PreviousMode` / requestor-mode style behavior in specific builds,
- change small security fields,
- create API-mediated read/write paths under strict assumptions.

Technique path:

```text
limited mutation
  -> semantic field
  -> future kernel API consumes changed value
```

What fails:

- wrong build offset,
- wrong thread,
- field no longer consumed,
- no restore,
- adjacent packed field corruption.

Sources:

- Local AsIO3 deep dive: `03_byovd/04_limited-primitives/ASIO3_PREVIOUSMODE_DEEP_DIVE.md`
- Local PreviousMode notes: `docs/kernel-research/previousmode-research-notes.md`

## Case 8. Callback / Security-State Tamper Enabled By R/W Drivers

Deep dive:

- `BYOVD_CALLBACK_SECURITY_STATE_TAMPER.md`

Primitive:

- not a driver-specific primitive by itself,
- an impact class enabled by virtual/physical R/W drivers.

Why it matters:

Many real-world BYOVD uses care more about weakening defense than getting a pretty kernel exploit.

What it can do:

- interfere with process/image/object callbacks,
- weaken EDR state,
- create telemetry gaps,
- crash host if callback state is wrong.

Technique path:

```text
R/W-capable vulnerable driver
  -> locate callback/security state
  -> short-lived or persistent tamper
  -> defender sees cross-view contradiction
```

What fails:

- PatchGuard,
- EDR self-check,
- wrong module ownership,
- callback restored by product,
- telemetry gap becomes alert.

Sources:

- EDRSandblast: https://github.com/wavestone-cdt/EDRSandblast
- Microsoft driver block rules: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

## Study Questions

- Is this driver exposing a memory primitive, hardware primitive, or authorization failure?
- Is the address space physical, virtual, CPU register, port, or device MMIO?
- What bridge turns the primitive into impact?
- Is the best impact data-only, control-flow, hardware, firmware, or telemetry tamper?
- Which mitigation blocks loadability rather than exploitation?
- Which defensive signal appears before impact?

## Defensive Summary

Prioritize blocking and hunting:

1. physical memory and virtual kernel R/W drivers,
2. MSR/port/MMIO generic hardware drivers,
3. reused low-level libraries like WinRing0/WinIO,
4. update/firmware helper drivers with insufficient access control,
5. R/W-capable drivers used near EDR telemetry gaps.

Do not rely on filename alone. Track signer, hash, product lineage, device object, load path, and caller process.

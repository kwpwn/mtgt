# BYOVD MSR, Port I/O, PCI, and MMIO Hardware Primitives

Updated: 2026-05-27

## Technique Summary

Some vulnerable drivers expose hardware-facing primitives rather than plain kernel memory access.

Companion case studies:

- `BYOVD_CASE_GDRV.md`
- `BYOVD_CASE_WINRING0_WINIO_MSIO.md`
- `BYOVD_CASE_LNVMSRIO.md`

```text
user process
  -> vulnerable hardware utility driver
  -> MSR / port I/O / PCI config / MMIO operation
  -> CPU, chipset, device, or firmware state is read or changed
```

These primitives are common in overclocking, monitoring, RGB, mining, board vendor, diagnostics, and firmware tools.

## Representative Drivers

| Driver / family | Primitive |
|---|---|
| `gdrv.sys` | MSR R/W, port I/O, PCI config, memcpy-like operations |
| WinRing0 family | MSR, physical memory, port I/O depending build |
| `WinIo64.sys` | port I/O and physical memory mapping |
| `LnvMSRIO.sys` | MSR and physical memory access family |
| `RTCore64.sys` | MSR and memory access family |
| `eneio64.sys` | MSR, port I/O, physical memory |
| DirectIO-family drivers | port I/O, physical/memory hardware access |

Sources:

- LOLDrivers `gdrv.sys`: https://www.loldrivers.io/drivers/2bea1bca-753c-4f09-bc9f-566ab0193f4a/
- LOLDrivers `WinIo64.sys`: https://www.loldrivers.io/drivers/96501e5b-e4f2-41a9-a8ee-d09e36d31a39/
- Microsoft WinRing0 detection: https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=VulnerableDriver%3AWinNT%2FWinring0.D
- Eclypsium Screwed Drivers: https://eclypsium.com/blog/screwed-drivers-signed-sealed-delivered/
- Eclypsium PDF: https://eclypsium.com/wp-content/uploads/Screwed-Drivers.pdf

## Why Hardware Primitives Exist

Legitimate tools may need to:

- monitor CPU temperature or voltage,
- configure fans,
- talk to embedded controllers,
- read board sensors,
- flash firmware,
- inspect PCI devices,
- tune overclocking settings,
- benchmark low-level hardware.

The driver is supposed to constrain those operations to safe, product-specific actions.

The vulnerability appears when the driver exposes generic operations:

```text
read any MSR
write any MSR
read/write any port
map arbitrary physical/MMIO range
read/write arbitrary PCI config
```

## 1. MSR Read/Write

### What It Is

MSRs are model-specific CPU registers. User mode cannot read or write them directly.

BYOVD pattern:

```text
user supplies MSR index and value
  -> driver executes rdmsr/wrmsr
  -> user receives privileged CPU state or changes it
```

### What MSR Read Can Do

MSR read can:

- leak syscall-entry pointers,
- support kernel base discovery,
- reveal platform state,
- validate CPU mitigation state,
- support exploit research without memory scanning.

The classic anchor is `IA32_LSTAR`:

```text
read LSTAR
  -> pointer into syscall entry
  -> scan back to ntoskrnl PE header
  -> kernel base
```

Related document:

- `docs/kernel-research/kernel-base-from-lstar-pattern-scan.md`

### What MSR Write Can Do

MSR write can:

- crash the machine,
- alter syscall-entry behavior in lab proofs,
- change critical CPU control state,
- create per-core inconsistency,
- support fragile control-flow experiments.

Why it is fragile:

- wrong value = immediate bugcheck,
- multi-core state matters,
- PatchGuard/telemetry pressure is high,
- HVCI/kCFG/CET complicate follow-on control flow,
- the operation may affect the whole system, not one process.

Good reasoning rule:

```text
MSR read is often a good anchor.
MSR write is rarely the most stable final impact.
```

## 2. I/O Port Access

### What It Is

I/O port access uses x86 `in` and `out` style instructions to communicate with hardware through port addresses.

BYOVD pattern:

```text
caller chooses port + width + value
  -> driver executes in/out
  -> hardware-facing state changes
```

### What It Can Do

Port I/O can:

- read hardware state,
- manipulate embedded controller or chipset paths,
- disrupt devices,
- perform platform-specific research,
- cause denial of service,
- be useless on a different platform.

### Why It Is Platform-Specific

Unlike kernel object fields, port meanings depend on hardware. The same port operation may mean:

- something important on one motherboard,
- nothing on another,
- crash or device lockup on a third.

Question:

```text
Is this primitive universally useful, or only useful on the exact platform?
```

For port I/O, the answer is usually platform-specific.

## 3. PCI Config Access

### What It Is

PCI configuration space controls device identity and settings. Some drivers expose reads/writes by bus/device/function and offset.

BYOVD pattern:

```text
caller supplies bus/device/function/offset
  -> driver reads/writes PCI config
  -> device configuration changes
```

### What It Can Do

Depending on device and platform:

- enumerate hardware,
- change device settings,
- alter BAR configuration,
- influence DMA-relevant behavior,
- disrupt a device,
- enable access to MMIO ranges.

### Why It Matters for Security

PCI config access can be a bridge:

```text
PCI config
  -> discover BAR
  -> map MMIO
  -> talk directly to device registers
```

This can move impact from Windows kernel objects to hardware state.

## 4. MMIO / BAR Mapping

### What It Is

Memory-mapped I/O exposes device registers as physical memory ranges. Drivers map those ranges and read/write them.

BYOVD pattern:

```text
caller controls physical/MMIO address
  -> driver maps range
  -> caller reads/writes device registers
```

### What It Can Do

MMIO access can:

- manipulate device registers,
- interact with firmware update mechanisms,
- disrupt hardware,
- read device memory,
- potentially support persistence if firmware-writing paths are exposed.

### Why It Is More Than LPE

Kernel LPE changes OS state. Hardware or firmware writes can change platform state:

```text
OS compromise may be fixed by reinstall
firmware compromise may survive reinstall
```

That is why Eclypsium's driver research is important: some driver primitives can move below Windows.

## 5. Firmware and UEFI Impact

### What It Is

Some vulnerable drivers expose access that can reach:

- SPI flash,
- BIOS/UEFI update paths,
- device firmware,
- embedded controller state,
- peripheral firmware.

### Why It Works

Firmware update utilities need high privilege. If a generic signed driver exposes firmware-adjacent access, the OS trusts it because it is a kernel driver.

The risk:

```text
trusted driver
  -> generic hardware access
  -> firmware state modified by untrusted caller
```

### What It Can Do

Potential impact:

- persistence below OS,
- firmware tamper,
- secure boot weakening depending platform,
- device bricking,
- hard-to-forensic compromise,
- bypass OS-level remediation.

This is not the most common BYOVD path, but it has high severity.

## Failure Modes

Hardware primitives fail through:

- wrong platform assumptions,
- invalid port or MSR,
- per-core MSR inconsistency,
- virtualized hardware differences,
- chipset lockdown,
- firmware write protections,
- device-specific timing,
- immediate system hang,
- bricking risk.

Important reasoning:

```text
kernel memory primitives fail like software bugs;
hardware primitives can fail like platform damage
```

## Detection Angle

Hunt for:

- WinRing0, WinIO, DirectIO, gdrv, RTCore, ENE, Lenovo MSR helper drivers,
- hardware utility drivers on servers,
- driver load followed by crash or hardware instability,
- firmware/BIOS utilities outside approved change windows,
- suspicious access by non-vendor controller process,
- unexpected Core Isolation / vulnerable driver blocklist disablement.

## Study Questions

- Is the primitive CPU, chipset, device, or firmware-facing?
- Does it work on every system or only on specific hardware?
- Does it read state, write state, or map state?
- Can the effect survive reboot or OS reinstall?
- Is the best defense driver block, firmware lockdown, or endpoint detection?
- Does the write affect one process, one CPU core, one device, or the whole machine?

## Summary

Hardware BYOVD primitives are powerful because they let user mode borrow a signed driver's hardware authority:

```text
signed driver exposes generic hardware access
  -> attacker controls low-level operation
  -> impact may be kernel, device, or firmware-level
```

Treat these drivers as high risk even when no simple token-LPE PoC exists.

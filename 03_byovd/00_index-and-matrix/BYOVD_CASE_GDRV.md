# BYOVD Case Study: `gdrv.sys`

Updated: 2026-05-27

## Technique Summary

`gdrv.sys` is a GIGABYTE utility driver frequently referenced in BYOVD research because it exposes several low-level primitive families.

```text
signed vendor utility driver
  -> memory operations
  -> MSR access
  -> port I/O / PCI / MMIO-style access
  -> multiple possible impact paths
```

This case is useful because it teaches primitive selection: the same driver can support very different techniques.

## Sources

- LOLDrivers gdrv entry:
  https://www.loldrivers.io/drivers/2bea1bca-753c-4f09-bc9f-566ab0193f4a/
- EDRSandblast:
  https://github.com/wavestone-cdt/EDRSandblast
- Eclypsium Screwed Drivers:
  https://eclypsium.com/blog/screwed-drivers-signed-sealed-delivered/

## Primitive

Primitive classes:

- memory copy / kernel memory access,
- MSR read/write,
- port I/O,
- PCI config / MMIO style low-level operations.

Why this matters:

```text
multi-primitive drivers require choosing the safest path for the goal
```

If the goal is kernel object state, use memory primitive reasoning. If the goal is kernel base discovery, MSR read may be enough. If the goal is hardware/device impact, port/PCI/MMIO matters.

## Why It Works

Board vendor utility drivers often need to expose low-level controls to vendor software.

Intended model:

```text
vendor utility
  -> gdrv
  -> board/hardware/system operation
```

Broken model:

```text
unexpected controller
  -> gdrv device
  -> generic privileged operation
```

The invariant failure:

```text
driver exposes generic low-level capability rather than narrow product-specific behavior
```

## What It Can Do

Depending on path:

- kernel read/write style impact,
- KASLR anchor through MSR read,
- fragile control-flow proof through MSR write,
- port or hardware register manipulation,
- platform-specific device effects,
- callback/security-state tamper if memory primitive is paired with object discovery.

## Technique Path

### Path A: Memory primitive

```text
kernel memory operation
  -> discover target object
  -> data-only mutation
```

Best when:

- you need process/token/protection/security-state impact,
- you can validate object address and offsets,
- readback is available.

### Path B: MSR primitive

```text
MSR read
  -> LSTAR or CPU state anchor
  -> kernel base / mitigation context
```

Best when:

- you need a kernel address anchor,
- you want proof of privileged CPU access.

Avoid treating MSR write as default impact. It is brittle and crash-prone.

### Path C: Hardware primitive

```text
port / PCI / MMIO operation
  -> hardware-specific state
```

Best when:

- the research target is device/firmware/platform behavior,
- the platform is known and controlled.

## Failure Modes

- conflating all primitive paths into "arbitrary write",
- using MSR write where data-only memory path would be safer,
- port/MMIO assumption wrong for target platform,
- driver blocked by policy,
- hardware operation causes hang,
- callback/security-state target triggers PatchGuard or EDR self-defense.

## Detection Ideas

Hunt for:

- `gdrv.sys` load outside approved GIGABYTE utility context,
- service creation pointing to renamed copies,
- non-vendor process opening device object,
- MSR/port-capable utility driver on servers,
- driver load followed by EDR telemetry gap,
- known gdrv hash or signer in vulnerable-driver inventory.

## Study Questions

- Which primitive path does the goal actually need?
- Is the operation memory, CPU register, port, PCI, or MMIO?
- Which path is most stable under HVCI?
- What makes MSR write more dangerous than MSR read?
- Why is generic hardware access riskier than narrow vendor behavior?

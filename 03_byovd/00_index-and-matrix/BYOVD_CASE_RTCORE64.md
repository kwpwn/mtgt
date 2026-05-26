# BYOVD Case Study: `RTCore64.sys`

Updated: 2026-05-27

## Technique Summary

`RTCore64.sys` is commonly associated with MSI Afterburner and related GPU/overclocking utility ecosystems. In BYOVD research it is valuable because public tooling and catalogs describe it as exposing kernel memory access primitives.

```text
signed hardware utility driver
  -> reachable device interface
  -> virtual kernel memory read/write style primitive
  -> data-only object manipulation or security-state tamper
```

This note is defensive and educational. It does not include IOCTL layouts, trigger buffers, or runnable exploit steps.

## Sources

- LOLDrivers RTCore64 entry:
  https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd/
- EDRSandblast vulnerable-driver support:
  https://github.com/wavestone-cdt/EDRSandblast
- Microsoft recommended driver block rules:
  https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

## Primitive

Primitive class:

- virtual kernel read/write,
- hardware utility driver risk,
- sometimes discussed alongside MSR/I/O access families depending version and tooling context.

Why this primitive matters:

```text
virtual kernel R/W skips physical address translation
```

The attacker does not first need to turn kernel virtual addresses into physical addresses. If the target object address is known or discoverable, the primitive can operate directly in the same address space used by symbols and debugger output.

## Why It Works

Hardware tuning drivers often need privileged access to device or system state. The intended trust model is:

```text
trusted vendor application
  -> trusted driver
  -> controlled low-level operation
```

The vulnerable trust model becomes:

```text
unexpected user-mode controller
  -> same driver device
  -> privileged operation with attacker-controlled address or value
```

The broken invariant:

```text
driver assumes the caller and request are trusted enough for kernel memory access
```

## What It Can Do

If read and write are both available, `RTCore64.sys`-style primitives can support:

- leaking kernel pointers,
- validating kernel object addresses,
- reading `_EPROCESS` / token-related state,
- modifying small process protection or token-adjacent fields,
- changing security product state,
- supporting callback/security-state tamper research.

The stable route is normally data-only:

```text
kernel object address
  -> read current field
  -> modify minimal semantic data
  -> verify or restore
```

## Technique Path

### 1. Establish loadability and reachability

Questions:

- Is this driver already present?
- Can it load under current HVCI/WDAC/blocklist policy?
- Which process can open the device?
- Is the host supposed to run MSI Afterburner or similar tooling?

Why:

```text
a strong primitive is irrelevant if the driver cannot load or cannot be reached
```

### 2. Classify read/write strength

Questions:

- Is there readback?
- Is the target kernel virtual address arbitrary?
- Is the write fixed-size or variable-size?
- Does the operation cross pages safely?

Why:

```text
read/write quality controls reliability and crash risk
```

### 3. Prefer data-only impact

Do not assume code patching is the best path.

Reason:

- HVCI pressures unsigned code execution,
- PatchGuard pressures global code/table tamper,
- data-only object changes are often shorter and more stable,
- EDR may still detect the surrounding driver-load and privilege-change sequence.

## Failure Modes

- driver blocklisted or denied by WDAC,
- driver version differs from public research,
- object address discovery fails,
- wrong build offset,
- write corrupts encoded pointer or reference bits,
- PatchGuard-sensitive target selected,
- security product notices impossible state.

## Detection Ideas

Hunt for:

- `RTCore64.sys` loads on endpoints without approved overclocking software,
- driver loaded from temp or user-writable path,
- unexpected process opening RTCore device,
- vulnerable-driver load followed by privilege/protection change,
- EDR telemetry gap after RTCore load,
- known vulnerable hash or stale MSI Afterburner package.

## Study Questions

- Why is virtual R/W simpler than physical R/W?
- What object address must be known before this primitive is useful?
- Why is readback important before writing?
- Which mitigation blocks the driver before the primitive matters?
- What defensive signal appears before any kernel object is modified?

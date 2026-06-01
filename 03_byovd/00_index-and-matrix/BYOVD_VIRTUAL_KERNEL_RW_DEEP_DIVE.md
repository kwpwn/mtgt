# BYOVD Virtual Kernel Read/Write Deep Dive

Updated: 2026-05-27

## Technique Summary

Virtual kernel read/write means a vulnerable signed driver lets a caller read or write kernel virtual addresses directly, or provides a memory-copy operation that can be shaped into the same capability.

Companion case studies:

- `BYOVD_CASE_RTCORE64.md`
- `BYOVD_CASE_DBUTIL_2_3.md`
- `BYOVD_CASE_GDRV.md`

```text
user process
  -> opens vulnerable driver
  -> supplies kernel virtual address
  -> driver reads/writes/copies in kernel context
  -> caller gains kernel VA primitive
```

Compared with physical memory primitives, virtual kernel R/W removes the VA-to-PA bridge. That makes it simpler and often more dangerous.

## Representative Drivers

| Driver / family | Source context | Primitive shape |
|---|---|---|
| `RTCore64.sys` | MSI Afterburner / LOLDrivers / public BYOVD tooling | kernel memory read/write, MSR and I/O access |
| `dbutil_2_3.sys` | Dell DBUtil / CVE-2021-21551 | memory copy / arbitrary write family |
| `gdrv.sys` | Gigabyte driver / LOLDrivers | kernel memcpy-like functions, MSR, port I/O |
| `DsArk64.sys` | LOLDrivers | arbitrary kernel read/write plus process operations |
| DirectIO-family drivers | PassMark / WinIO-like tools | memory or hardware access depending version |

Sources:

- LOLDrivers `RTCore64.sys`: https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd/
- LOLDrivers `dbutil_2_3.sys`: https://www.loldrivers.io/drivers/a4eabc75-edf6-4b74-9a24-6a26187adabf/
- LOLDrivers `gdrv.sys`: https://www.loldrivers.io/drivers/2bea1bca-753c-4f09-bc9f-566ab0193f4a/
- LOLDrivers `DsArk64.sys`: https://www.loldrivers.io/drivers/399fb787-5b06-46f0-86cb-dff7374bb015/
- EDRSandblast repository context: https://github.com/wavestone-cdt/EDRSandblast

## Required Assumptions

Virtual R/W needs:

- driver can load,
- caller can open driver device,
- IOCTL accepts or derives kernel virtual addresses,
- driver does not validate caller-supplied addresses safely,
- target address is valid and writable/readable in kernel context,
- researcher knows what object or field is being touched.

The last assumption matters most:

```text
arbitrary write without object understanding is just a crash primitive
```

## Why This Works

Kernel mode can access kernel virtual memory. If a driver uses caller-controlled addresses as source or destination, it can become a memory oracle or writer.

Conceptual bug:

```text
driver trusts caller address
  -> performs kernel memcpy/read/write
  -> crosses user/kernel boundary
```

Common implementation shapes:

- direct pointer dereference,
- `memcpy` / `memmove`,
- custom copy helper,
- MDL mapping misuse,
- vendor "read/write memory" diagnostic command,
- one IOCTL for read and another for write.

## What It Can Do

Virtual R/W can support:

- kernel pointer leaks,
- kernel base discovery,
- object field reads,
- token and privilege state inspection,
- token/data-only modifications,
- PPL/protection field mutation,
- callback/security-state tamper,
- DKOM research,
- crash/debug proof of impact.

The most common stable impact pattern is data-only:

```text
discover target object
  -> read current field
  -> modify small semantic field
  -> verify behavior
  -> restore if possible
```

## Read vs Write vs Read/Write

| Primitive | What it gives | Main difficulty |
|---|---|---|
| virtual read only | leaks kernel state | finding a second bug or abuse path |
| virtual write only | can modify known target | knowing exact address/value safely |
| virtual read/write | strongest | controlling blast radius |
| kernel memcpy | can become read/write depending direction | understanding source/destination control |

Why readback matters:

```text
read validates assumptions before write
```

Without readback, a write-only primitive is much more dangerous to use because there is no direct confirmation that the target field contains the expected value.

## Technique 1: Kernel Base and Symbol-Guided Object Discovery

A virtual R/W primitive is much more useful after kernel base is known.

Ways to get base:

- system module query where available,
- `MSR_LSTAR` if MSR read exists,
- leaked kernel pointer,
- known driver/module pointer,
- debugger/lab symbols.

Then:

```text
kernel base
  -> exported symbol or public symbol offset
  -> global pointer or object list
  -> target object
```

Why symbols matter:

- Windows offsets drift by build.
- Public symbols help validate structure fields.
- Hardcoded offsets age badly.

Related local documents:

- `docs/kernel-research/runtime-pdb-symbol-resolution.md`
- `docs/kernel-research/kernel-object-layout-drift.md`

## Technique 2: Data-Only Object Manipulation

Why data-only is preferred:

- avoids unsigned kernel code,
- avoids executable pool tricks,
- reduces HVCI friction,
- can be short-lived and reversible,
- usually needs fewer moving parts than control-flow hijack.

Common target families:

- process token relationship,
- protection/signature fields,
- handle access state,
- callback registration state,
- driver object/device object fields,
- policy flags.

Reasoning pattern:

```text
Which future Windows decision reads this field?
If the field changes, what behavior changes?
Can the field be restored?
Is the field protected or checked elsewhere?
```

## Technique 3: Kernel Memory Copy Primitive

Some drivers are best understood as copy gadgets:

```text
copy(dst, src, len)
```

If caller controls `dst`, `src`, and `len`, then:

```text
kernel src -> user dst = arbitrary read
user src -> kernel dst = arbitrary write
kernel src -> kernel dst = internal state copy/corruption
```

Question:

```text
Which side of the copy is trusted incorrectly?
```

That question often explains the whole vulnerability.

## Why Not Always Patch Code?

Because modern Windows punishes code patching:

- HVCI protects code integrity assumptions,
- PatchGuard watches many global structures,
- kCFG/CET complicate indirect control-flow abuse,
- EDRs monitor suspicious memory and callback changes,
- one wrong instruction patch crashes the host.

Virtual R/W is often strongest when it avoids code execution:

```text
change data so legitimate kernel code makes a different decision
```

## Failure Modes

Virtual R/W fails through:

- wrong kernel address,
- wrong build offset,
- target object freed or reused,
- bad size/alignment,
- crossing invalid page boundary,
- writing encoded pointer without preserving tag bits,
- corrupting reference count,
- writing protected data,
- PatchGuard-sensitive target,
- unhandled driver exception causing BSOD.

Common reasoning mistake:

```text
assuming a public exploit offset works on every Windows build
```

## Detection Angle

Detection is indirect:

- vulnerable driver load,
- service creation,
- device object open by unexpected process,
- rapid sequence of IOCTLs to known vulnerable device,
- privilege or PPL change soon after driver load,
- crash dump showing memory corruption near kernel objects,
- EDR telemetry loss after R/W-capable driver load,
- known drivers such as RTCore64, DBUtil, gdrv, DsArk64 outside approved software.

## Study Questions

- Does the primitive operate on kernel virtual addresses or physical addresses?
- Is there readback?
- Is the write bounded?
- Does the driver copy user to kernel, kernel to user, or kernel to kernel?
- Which kernel object is the target?
- Which Windows decision consumes the field being changed?
- What would prove the write went to the wrong object?
- What mitigation blocks the driver before the primitive matters?

## Summary

Virtual kernel R/W is one of the most direct BYOVD primitives:

```text
driver exposes kernel VA access
  -> researcher discovers object
  -> data-only modification changes behavior
```

The hard part is not the write. The hard part is choosing a valid, meaningful, build-correct target.

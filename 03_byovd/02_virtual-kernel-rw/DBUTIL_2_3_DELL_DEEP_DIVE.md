# Dell dbutil_2_3.sys / CVE-2021-21551 Deep Dive

Sources:

- VoidSec write-up: https://voidsec.com/reverse-engineering-and-exploiting-dell-cve-2021-21551/
- Ars Technica summary: https://arstechnica.com/gadgets/2021/05/dell-patches-a-12-year-old-privilege-escalation-vulnerability/
- VB2022 Lazarus/BYOVD paper: https://www.virusbulletin.com/uploads/pdf/conference/vb2022/papers/VB2022-Lazarus-and-BYOVD-evil-to-the-Windows-core.pdf

`dbutil_2_3.sys` is one of the classic BYOVD examples. It was a Dell firmware update driver with multiple vulnerabilities grouped under CVE-2021-21551.

Primitive class:

```text
kernel arbitrary write / virtual write-style IOCTL
```

It became widely known because of both broad enterprise exposure and real-world abuse.

## 1. Why dbutil_2_3.sys Matters

It had:

- major OEM trust,
- very broad install base,
- long vulnerability lifetime,
- powerful kernel primitive,
- real-world BYOVD adoption.

This makes it a model case for why signed vendor drivers can become worse than unsigned malware from a trust perspective.

## 2. Primitive Model

Public analyses describe IOCTL paths that enable kernel memory writes. VB2022 material references an `IOCTL_VIRTUAL_WRITE` path.

Conceptually:

```text
attacker-controlled data
  -> vulnerable driver IOCTL
  -> write into kernel virtual address
```

This is more convenient than physical R/W because the target is already a virtual address.

## 3. Why Virtual Write Is Strong

With virtual write, you can target:

- `_EPROCESS.Token`,
- function pointers,
- kernel global variables,
- driver dispatch tables,
- callback-related data,
- PPL/protection fields.

You still need:

- kernel address leak,
- target object address,
- correct offsets,
- write size/control.

But you do not need:

- CR3,
- VA->PA translation,
- physical mapping recovery.

## 4. Natural LPE Route

The standard route is:

```text
find current process EPROCESS
find System EPROCESS
read or know System token
write System token into current process Token
```

If the primitive is write-only:

- a separate read/leak is needed,
- or a known value target is needed.

If read/write exists:

- token swap is straightforward.

## 5. Why OEM Firmware Drivers Are Risky

Firmware/update drivers often need powerful operations:

- BIOS/firmware update,
- physical memory access,
- port I/O,
- privileged device access,
- kernel memory operations.

They may be installed temporarily but left behind.

Risk pattern:

```text
temporary update component persists as signed vulnerable driver
```

This creates long-term attack surface from a short-term maintenance tool.

## 6. Why Real-World Actors Used It

Operators prefer drivers that are:

- signed,
- widely trusted,
- reliable,
- already known,
- compatible with many systems,
- not immediately blocked everywhere.

`dbutil_2_3.sys` fit that profile.

It was used not because it was new, but because it was dependable.

## 7. Why Direct Data-Only Impact Is Preferred

With arbitrary kernel write, the cleanest goal is data-only:

- token swap,
- disable protection field,
- alter security product state.

Avoid:

- code patching,
- SSDT hooks,
- MSR tricks,
- page-table modifications,

unless required, because those raise BSOD and detection risk.

## 8. BSOD Risk Matrix

| Operation | Risk | Why |
|---|---|---|
| Driver load | Low-medium | Blocklist/compatibility. |
| Kernel virtual write | High | Wrong VA corrupts memory. |
| Token write | Medium | Small target but offset-sensitive. |
| Function pointer patch | High | kCFG/PatchGuard/crash risk. |
| Code patch | High | HVCI/PatchGuard. |
| Callback tamper | High | Delayed bugcheck/detection. |

## 9. Stability Across Versions

Stable:

- vulnerable driver primitive for exact driver version,
- virtual write concept,
- token swap concept.

Variable:

- Windows offsets,
- KASLR leak method,
- Dell remediation/blocklist,
- driver presence,
- WDAC policy.

`dbutil_2_3.sys` is old enough that many modern systems block it, but unmanaged or poorly configured systems may still be exposed.

## 10. Defensive View

Hunt for:

- `dbutil_2_3.sys`,
- Dell firmware update driver remnants,
- driver load/service creation,
- known vulnerable hashes,
- Lazarus/BYOVD style driver staging,
- arbitrary kernel-write capable driver activity.

Controls:

- Dell cleanup/remediation tooling,
- Microsoft vulnerable driver blocklist,
- WDAC deny rules,
- inventory update-tool drivers,
- remove stale firmware update components.

## 11. Final Takeaway

`dbutil_2_3.sys` is the archetype:

```text
trusted OEM driver + kernel write primitive + broad deployment = high-value BYOVD
```

The exploit engineering lesson is simple:

```text
virtual write is often easier to weaponize than physical write,
but it is still only safe if address discovery and target validation are strong
```


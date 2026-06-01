# PowerStrip pstrip64.sys / CVE-2026-29923 Deep Dive

Sources:

- Smarttfoxx disclosure/repo: https://github.com/Smarttfoxx/CVE-2026-29923
- SentinelOne CVE summary: https://www.sentinelone.com/vulnerability-database/cve-2026-29923/
- Vulmon summary: https://vulmon.com/vulnerabilitydetails?qid=CVE-2026-29923

`pstrip64.sys` is the PowerStrip driver from EnTech Taiwan. This is notable because Astra64 is also EnTech Taiwan related. Both belong to the old hardware/display utility world where physical memory mapping was exposed for legitimate low-level control but becomes a serious BYOVD primitive.

Primitive class:

```text
arbitrary physical memory mapping into user-mode address space
```

## 1. Why PowerStrip Is Similar to ASTRA64

Both drivers are hardware/display utility drivers.

Both expose physical-memory access.

Both can be abused to:

- map physical pages,
- inspect kernel memory,
- locate process objects,
- modify token/security fields.

Conceptually:

```text
user controls physical address -> driver maps it -> user reads/writes RAM
```

That is the same dangerous design pattern as ASTRA64.

## 2. What Primitive It Gives

Public summaries describe an IOCTL path that maps arbitrary physical memory ranges into user-mode virtual address space.

This gives:

- physical read,
- physical write,
- object scanning,
- kernel structure modification.

It does not directly give:

- kernel virtual R/W,
- kernel code execution,
- symbol resolution,
- process object addresses.

Those must be built on top.

## 3. Why Arbitrary Physical Mapping Is Worse Than a Narrow Hardware Mapping

Mapping MMIO for the driver's own hardware is a normal driver task.

Mapping arbitrary physical RAM based on user input is unsafe.

The difference:

| Safe-ish design | Vulnerable design |
|---|---|
| map only assigned device BAR | map caller-chosen physical address |
| validate resource range | no meaningful range validation |
| privileged caller only | any local/weak caller |
| limited size/access | arbitrary size/read-write |

The bug is not simply "uses mapping API"; the bug is user-directed arbitrary mapping.

## 4. Why Physical Scan Is Often Mentioned

Some PowerStrip summaries describe locating kernel structures in mapped physical memory.

If the exploit does not implement page-table walking, it can scan physical RAM for:

- `_EPROCESS`-like structures,
- PID 4,
- current PID,
- image names,
- linked-list pointers,
- token-looking pointers.

Why scanning is attractive:

- simpler to explain,
- does not require CR3,
- works in controlled lab if signatures are strong.

Why scanning is weaker:

- false positives,
- slow,
- memory-layout dependent,
- high risk if used for writes.

For robust engineering, page-table walk or symbol-assisted translation is preferable.

## 5. Why Direct DKOM Is the Natural Impact

Once process structures are found, direct token DKOM is straightforward:

```text
copy System token fast-ref into current EPROCESS.Token
```

Why this is natural:

- physical write is available,
- `_EPROCESS` is nonpaged,
- token swap is one 8-byte write,
- no shellcode,
- no code patch,
- no SSDT.

The technique is the same final stage as the ASTRA direct route.

## 6. Why This May Be Easier or Harder Than ASTRA

Potentially easier:

- direct arbitrary physical mapping may be simple to use,
- same vendor family may have similar design assumptions.

Potentially harder:

- mapping API/protocol differs,
- no MSR read anchor like ASTRA's `IA32_LSTAR` path unless driver provides one,
- may require physical scanning if no clean kernel pointer leak,
- old driver may be less compatible with modern Windows.

The exploit difficulty depends less on "physical R/W exists" and more on:

- how to find kernel objects,
- how to translate addresses,
- how reliable the mapping API is.

## 7. Why It Is Dangerous Even for Low-Privileged Users

The public summaries emphasize unprivileged local access.

If true in the target environment, the impact is more severe than admin-only BYOVD:

- no need for prior admin to load a driver if already installed,
- low-privileged user can map physical memory,
- direct LPE to SYSTEM becomes possible.

If the driver is not installed and attacker must load it, it becomes admin-to-kernel BYOVD instead.

The deployment context matters.

## 8. HVCI/VBS Interaction

Like ASTRA:

- physical R/W can avoid unsigned kernel code execution,
- data-only token modification can still work on normal VTL0 objects,
- HVCI does not make a bad driver API safe.

But:

- blocklist/WDAC may prevent loading,
- VBS/KDP can protect some pages,
- code patch/PTE patch is still risky.

So PowerStrip should be treated as a data-only physical-R/W candidate, not automatically as universal HVCI bypass.

## 9. Stability Across Versions

Stable:

- physical mapping concept,
- token DKOM concept,
- x64 paging if page-table walk is used.

Variable:

- driver IOCTL structure,
- device name,
- access permissions,
- driver compatibility,
- Windows offsets,
- blocklist state,
- physical scanning signatures.

Physical scan approaches are less stable than VA->PA translation approaches.

## 10. BSOD Risk Matrix

| Operation | Risk | Why |
|---|---|---|
| Driver load/open | Low-medium | Old driver/blocklist issues. |
| Physical map | Low-medium | Bad ranges or cache attributes can fail. |
| Physical read | Low-medium | Usually safer than write. |
| Physical scan | Low | Read-only, but can mislead. |
| Physical write | High | Wrong page corrupts RAM. |
| Token DKOM | Medium | Small write but offset/object sensitive. |
| PTE/code patch | High | HVCI/PatchGuard risk. |

## 11. Defensive View

Hunt for:

- `pstrip64.sys`,
- PowerStrip installs on modern endpoints,
- `PSTRIP64` service/device names,
- driver load from non-standard path,
- unexpected process opening PowerStrip device,
- SYSTEM process spawned from low-priv user context.

Controls:

- remove PowerStrip from production endpoints,
- WDAC deny vulnerable hashes,
- enable vulnerable driver blocklist,
- monitor old display/overclocking utility drivers.

## 12. Final Takeaway

PowerStrip `pstrip64.sys` is essentially the same exploit category as ASTRA64:

```text
legacy hardware utility driver exposes arbitrary physical memory mapping
```

The best research direction is:

- reverse exact IOCTL protocol,
- build reliable physical read/write wrapper,
- prefer page-table translation over blind scan,
- use minimal data-only write for impact,
- avoid code patch/MSR/PTE routes unless specifically studying them.


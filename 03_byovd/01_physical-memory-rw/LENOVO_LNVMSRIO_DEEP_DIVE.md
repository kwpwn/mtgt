# Lenovo LnvMSRIO.sys / CVE-2025-8061 Deep Dive

Sources:

- Quarkslab part 1: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061.html
- Quarkslab part 2: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html
- Lenovo advisory: https://support.lenovo.com/us/en/product_security/LEN-200860
- symeonp PoC notes: https://github.com/symeonp/Lenovo-CVE-2025-8061

This driver is in the same broad family as ASTRA64 and ThrottleStop: a signed hardware/OEM helper driver exposes low-level operations that can be abused as exploit primitives.

The core primitive set is:

```text
MSR read/write
physical memory read/write through MmMapIoSpace-style paths
```

## 1. What Makes This Driver Different From ASTRA64

ASTRA64:

- maps `\Device\PhysicalMemory`-style pages into user mode,
- gives physical R/W,
- has MSR read,
- requires the exploit to build most of the translation/discovery stack.

`LnvMSRIO.sys`:

- exposes multiple hardware-oriented IOCTLs,
- includes MSR read/write,
- includes physical memory read/write paths through insecure `MmMapIoSpace()` usage,
- is an OEM driver from a major vendor, which makes fleet exposure more realistic.

The primitive class is similar. The exploit design decisions differ because Lenovo exposes more than one low-level capability.

## 2. Primitive Taxonomy

| Primitive | Meaning | Exploit value |
|---|---|---|
| MSR read | Read model-specific registers | Kernel pointer leak through `IA32_LSTAR`, CPU/control-state discovery |
| MSR write | Write model-specific registers | Potential syscall-path redirection, crash/code-exec research |
| Physical memory read | Read physical RAM via driver mapping/copy | Inspect kernel objects, page tables, modules |
| Physical memory write | Write physical RAM | Data-only kernel object modification or page-table/code tamper attempts |

The strongest practical primitive is physical R/W. MSR write is spectacular but dangerous.

## 3. Why MSR Read Is Used First

`IA32_LSTAR` contains the long-mode syscall entry address. Reading it gives a kernel pointer inside the syscall entry path.

Why this is useful:

- It bypasses KASLR for the main kernel image.
- It gives a stable anchor into `ntoskrnl`.
- It avoids relying on user-mode module leaks.
- It is low risk compared with MSR write.

This is the same logic as ASTRA64. If a driver offers MSR read, `LSTAR` is one of the cleanest anchors.

## 4. Why MSR Write Is Usually Not the Best First Choice

MSR write can redirect critical CPU behavior. For example, changing syscall entry is a direct control-flow attack.

Why it is attractive:

- One register can affect every syscall on a CPU.
- It can prove ring-0 influence quickly.
- It can be used to build dramatic PoCs.

Why it is fragile:

- Wrong value means immediate crash.
- It affects global CPU/kernel behavior.
- Modern mitigations make arbitrary kernel control-flow less stable.
- Multi-core systems complicate per-core MSR state.
- PatchGuard/security products may notice persistent tamper.

For LPE, physical memory data-only modification is usually cleaner than MSR hijack.

## 5. Why Physical R/W Is the Practical Core

Physical R/W lets the exploit modify kernel data without needing kernel code execution.

Targets can include:

- `_EPROCESS.Token`,
- `_EPROCESS.Protection`,
- process flags,
- callback/object state,
- selected kernel globals,
- page tables in older/no-HVCI contexts.

Under HVCI/kCFG/CET, data-only paths are attractive because:

- no user shellcode,
- no unsigned executable kernel memory,
- no direct ROP requirement,
- less dependence on return/indirect-call control.

The trade-off is the VA->PA problem. Kernel objects are known by virtual addresses; the driver primitive operates on physical memory.

## 6. Bridge Strategies: Physical R/W to Useful Kernel R/W

There are several ways to bridge physical R/W:

### A. Page-table walk

Same as ASTRA:

```text
find CR3
walk PML4/PDPT/PD/PT
translate target kernel VA to PA
write physical page
```

Pros:

- deterministic,
- generic,
- conceptually clean.

Cons:

- need CR3,
- need page-table reads,
- VBS/KVA shadow/PCID can confuse validation,
- wrong CR3 means dangerous writes.

### B. Superfetch / memory combining APIs

Some PoCs use Windows memory-manager information APIs to obtain virtual-to-physical hints.

Pros:

- avoids implementing full low-level CR3 scan,
- may be faster for user-mode tooling,
- useful when APIs still expose enough information.

Cons:

- API availability/restrictions vary,
- can be patched/hardened,
- may require admin,
- less universal than architecture-level page walk.

### C. Physical scan

Scan RAM for recognizable kernel structures.

Pros:

- no CR3 needed,
- works when object signatures are strong.

Cons:

- slow,
- false positives,
- high corruption risk if used for writes.

For a research-grade exploit, page-table walk or reliable OS-assisted VA->PA is better than blind scan.

## 7. Why Quarkslab Focuses on "BYOVD to the Next Level"

The interesting part is not just "there is a vulnerable driver". It is the engineering required to convert low-level hardware access into stable modern Windows impact.

The problems are:

- KASLR,
- HVCI/VBS assumptions,
- driver blocklist,
- page translation,
- safe target selection,
- avoiding unstable code execution,
- avoiding persistent patching.

This is why modern BYOVD research often looks like kernel exploitation research rather than simple IOCTL fuzzing.

## 8. Lenovo vs ASTRA Direct DKOM

Both can support direct DKOM token swap if you can:

```text
kernel VA of token field -> physical address -> physical write
```

Differences:

- Lenovo has MSR write as well as read, which creates extra possible chains.
- Lenovo is vendor/OEM fleet-relevant.
- ASTRA has a very clear physical mapping path but requires its mapping quirks to be handled.
- Lenovo PoCs may use different VA->PA bridge techniques depending on implementation.

If the goal is just SYSTEM LPE:

```text
physical R/W -> token fast-ref write
```

is usually more stable than syscall/MSR hijack.

## 9. Why Not Use MSR Write for SYSTEM Shell

A syscall MSR hijack can be used to run controlled kernel code, but it is usually worse for stable LPE:

- must handle calling convention and CPU state,
- must avoid SMEP/SMAP/NX issues,
- must restore MSR,
- must handle per-core state,
- can crash on any syscall during the patch window,
- creates global control-flow tamper.

Direct data-only write is narrower but safer:

```text
one field, one process, restore possible
```

## 10. HVCI/VBS Reality

If `LnvMSRIO.sys` is allowed to load, HVCI did not prevent the vulnerable signed code from executing.

HVCI helps with:

- code integrity,
- blocking incompatible drivers,
- preventing writable+executable kernel memory,
- making code patching harder.

It does not automatically prevent:

- a signed driver from exposing dangerous IOCTL semantics,
- physical memory read/write to normal VTL0 kernel data,
- data-only token manipulation.

VBS can still protect:

- VTL1/secure kernel memory,
- KDP-protected data,
- certain hypervisor-protected pages.

So the correct statement is:

```text
Lenovo physical R/W can bypass many HVCI-era code-exec assumptions,
but it does not bypass every VBS-protected memory boundary.
```

## 11. Version Stability

Stable:

- MSR `IA32_LSTAR` as a kernel pointer anchor.
- x64 page-table format.
- physical R/W concept if driver version remains vulnerable.

Variable:

- driver IOCTL codes,
- driver access control,
- Lenovo fixed versions,
- Windows `_EPROCESS` offsets,
- blocklist/WDAC state,
- memory-manager APIs if used for VA->PA.

For PoCs with hardcoded offsets, stability is narrow. The symeonp repo notes hardcoded offsets for a specific Windows 11 24H2 build. That is normal for PoC quality but not portable exploit engineering.

## 12. BSOD Risk Model

| Technique | Risk | Why |
|---|---|---|
| MSR read | Low | Read-only, used for leak. |
| MSR write | High | Global CPU behavior, easy immediate crash. |
| Physical read | Low-medium | Bad mappings can fail; usually recoverable. |
| Physical write to validated data field | Medium | One wrong PA corrupts kernel memory. |
| Physical write to page tables | High | HVCI/VBS/PTE consistency issues. |
| Kernel code patch | High | HVCI/PatchGuard/code integrity. |
| Direct token DKOM | Medium | Offset/translation/refcount issues. |

Lenovo is powerful, but the safest practical route is still a minimal data-only write after strong validation.

## 13. Defensive Priority

Defenders should focus on:

- Lenovo driver version inventory,
- `LnvMSRIO.sys` load events,
- service creation from unexpected path,
- non-Lenovo process opening the device,
- CodeIntegrity/WDAC block events,
- SYSTEM child process after driver load,
- local WDAC deny for vulnerable hashes.

Because the exploit can be data-only, waiting for obvious kernel shellcode signals is too late.

## 14. Final Takeaway

`LnvMSRIO.sys` is a strong BYOVD target because it exposes both physical memory and MSR primitives.

The best exploit engineering lesson is:

```text
do not use the strongest-looking primitive if a safer primitive achieves the goal
```

MSR write looks powerful, but for LPE, physical R/W plus a small data-only kernel object modification is usually more reliable and less BSOD-prone.


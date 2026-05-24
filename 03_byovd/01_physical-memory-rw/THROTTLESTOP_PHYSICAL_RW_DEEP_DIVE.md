# ThrottleStop.sys / CVE-2025-7771 Physical R/W Deep Dive

Sources:

- poh0 write-up: https://www.poh0.dev/windows/driver/vulnerability/2025/09/22/throttlestop-vulnerable-driver/
- GitHub advisory mirror: https://github.com/advisories/GHSA-f8p7-vvxp-hcxv
- Public PoC references: https://github.com/Demoo1337/ThrottleStop
- CVE summaries and active-abuse reporting around ransomware/AV-killer activity.

`ThrottleStop.sys` is a hardware/CPU utility driver. The vulnerability class is:

```text
unrestricted IOCTL access to physical memory through MmMapIoSpace
```

This puts it in the same broad class as ASTRA64, PowerStrip and eneio64: the driver turns physical RAM into a user-controlled primitive.

## 1. What Primitive This Driver Gives

Public write-ups describe two IOCTL interfaces that allow arbitrary physical memory read/write through `MmMapIoSpace`.

Conceptually:

```text
caller supplies physical address
driver maps physical range
driver copies to/from mapped memory
caller gains physical R/W
```

This is not a direct kernel virtual R/W primitive.

The exploit must solve:

- where is the target kernel object virtually?
- what physical address backs it?
- is the page safe to read/write?

## 2. Why `MmMapIoSpace` Is Dangerous Here

`MmMapIoSpace` is legitimate for mapping device physical memory such as MMIO BARs.

It becomes dangerous when:

- user controls the physical address,
- user controls size,
- driver does not restrict ranges to owned hardware resources,
- driver exposes mapping to low-privileged or attacker-controlled callers.

The function itself is not the vulnerability. The vulnerability is using it as a user-directed arbitrary physical memory mapper.

Good driver design:

- map only hardware resources assigned to the device,
- reject arbitrary RAM ranges,
- restrict device access,
- never expose raw physical memory to user mode.

## 3. Why Physical R/W Is Enough for LPE

The Windows security model ultimately relies on data structures in memory:

- process token pointers,
- privileges,
- process protection state,
- handle tables,
- callback lists,
- object metadata.

If physical R/W can reach those structures, an attacker can change security state without executing kernel code.

This is why physical R/W remains dangerous under HVCI:

- HVCI makes code execution harder.
- Data-only object mutation can still be enough.

## 4. The Main Engineering Problem: Finding the Right Physical Page

ThrottleStop gives physical R/W. It does not tell you:

- where `_EPROCESS` is,
- where the token field is,
- what the kernel CR3 is,
- what physical page backs a kernel VA.

So the exploit needs a bridge.

Common bridges:

- page-table walk,
- Superfetch/Memory Manager APIs,
- VAD traversal and process/module discovery,
- physical scanning.

The poh0 write-up focuses on the practical bridge from physical memory access to useful Windows object manipulation.

## 5. Why Superfetch/Memory-Manager Assisted Translation Is Attractive

Some ThrottleStop PoCs discuss using Windows-provided memory information to help translate or discover physical backing.

Why this is attractive:

- avoids writing a full CR3 scanner,
- can be easier in Rust/C++ user-mode code,
- leverages OS knowledge,
- can be faster than blind scanning.

Why it is not universal:

- APIs can be restricted by version or privilege.
- Windows hardening can reduce exposed physical memory metadata.
- It may not work the same on all SKUs/builds.

Compared with ASTRA page-table walk:

- OS-assisted translation is easier when available.
- Page-table walk is more architecture-level and self-contained.

## 6. Why VAD Traversal Appears in Write-ups

VADs describe user-mode virtual address regions for a process.

Why would VAD traversal matter in a kernel exploit?

- It helps reason about process memory layout.
- It helps locate image mappings, heaps, stacks, mapped files.
- It can support module discovery or payload staging.
- It can help bridge from process abstraction to memory ranges.

In physical-memory BYOVD exploitation, VAD traversal is often part of building a reliable map of:

```text
process -> address ranges -> backing pages -> useful objects/modules
```

It is not always required for token DKOM, but it is useful for richer primitives.

## 7. ThrottleStop vs ASTRA64

Similarities:

- both expose physical memory access,
- both can support token DKOM,
- both bypass need for unsigned kernel code,
- both require VA/PA or object discovery bridge.

Differences:

- ASTRA has MSR read and a specific physical mapping quirk.
- ThrottleStop's public write-ups emphasize `MmMapIoSpace` IOCTLs and physical R/W through driver copy/map logic.
- ThrottleStop has public reporting around ransomware/AV-killer abuse.

Exploit engineering lesson:

```text
same primitive class does not mean same exploit structure
```

The driver protocol and helper APIs determine the cleanest chain.

## 8. Why It Is Useful for AV/EDR Killing

An attacker with physical R/W can:

- modify process/token/protection state,
- disable callbacks or hooks in some contexts,
- interfere with security process memory,
- escalate to SYSTEM and then stop services,
- potentially manipulate PPL-related fields.

Ransomware may not need elegant kernel code execution. It needs a reliable way to suppress defenses.

This is why a CPU tuning driver becomes operationally serious.

## 9. Why Direct Token DKOM Is a Natural Route

Given physical R/W, the shortest LPE route is often:

```text
find System EPROCESS
find current EPROCESS
copy System token fast-ref into current token field
spawn SYSTEM child
restore original token
```

Pros:

- one 8-byte write,
- no shellcode,
- no PTE patch,
- no SSDT hook,
- no SMEP bypass.

Cons:

- requires offsets,
- requires VA->PA,
- has reference-count cleanliness issues,
- wrong write can crash.

This is the same reasoning as ASTRA direct DKOM.

## 10. Why Not Use Code Execution First

Physical R/W can sometimes be turned into code execution by:

- patching code,
- changing PTE permissions,
- redirecting function pointers,
- modifying syscall path,
- altering callbacks.

Why not start there:

- HVCI and kCFG make it harder.
- PatchGuard risk is higher.
- BSOD surface is larger.
- For LPE, token data-only write is simpler.

Modern BYOVD chains often prefer data-only outcomes precisely because code execution is more constrained.

## 11. HVCI and Secure Boot Claims

Public PoC summaries often say physical-memory BYOVD can bypass HVCI or Secure Boot.

Precise reading:

- Secure Boot/HVCI may allow the signed vulnerable driver to load if not blocked.
- Once loaded, the driver's dangerous IOCTL can expose physical memory.
- The exploit can avoid unsigned kernel code execution, so HVCI's code-exec protections are less relevant.

But:

- WDAC/blocklist can block the driver.
- VBS/KDP can protect some memory regions.
- HVCI does not guarantee every physical write succeeds.

So the bypass is practical, not absolute.

## 12. Stability Across Windows Versions

Stable:

- `MmMapIoSpace` as a kernel API concept.
- physical R/W primitive if the vulnerable driver version is loaded.
- data-only token swap concept.

Version-sensitive:

- `_EPROCESS` offsets,
- translation strategy,
- exposed memory-manager APIs,
- PPL fields,
- driver blocklist state,
- HVCI compatibility.

If a PoC says it works on a particular Windows 11 build, do not assume it works everywhere.

## 13. BSOD Risk Matrix

| Stage | Risk | Reason |
|---|---|---|
| Driver load | Low-medium | Blocklist/incompatibility can fail or crash. |
| Physical read | Low-medium | Bad mapping can fail; reads usually safer. |
| Physical write | High | Wrong PA corrupts kernel memory. |
| VA->PA translation | Medium | Wrong bridge poisons all writes. |
| Token DKOM | Medium | Small write but offset-sensitive. |
| PTE/code patch | High | HVCI/PatchGuard/crash risk. |
| AV/EDR process tamper | Medium | Watchdogs/self-defense can react. |

The exploit reliability is dominated by address discovery and target validation.

## 14. Defensive View

Hunt for:

- `ThrottleStop.sys` load on enterprise endpoints,
- renamed copies,
- driver service creation from staging directories,
- processes opening the ThrottleStop device outside normal utility,
- AV/EDR process deaths after driver load,
- CodeIntegrity/blocklist events.

Controls:

- remove driver where not needed,
- WDAC deny known vulnerable hashes,
- Microsoft vulnerable driver blocklist,
- monitor old tuning/RGB/mining drivers as high-risk.

## 15. Final Takeaway

ThrottleStop is a physical-memory BYOVD case. The key exploitation problem is not "how do I get kernel code execution?" The better question is:

```text
How do I safely convert physical R/W into a minimal data-only security-state change?
```

That is the same core lesson as ASTRA direct DKOM:

```text
primitive power is useful only after reliable translation, validation and target selection
```


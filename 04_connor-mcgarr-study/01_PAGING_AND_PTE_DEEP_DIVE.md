# 01 - Paging and PTE Deep Dive

Based on Connor McGarr: https://connormcgarr.github.io/paging/

Last updated: 2026-05-25

## 1. Why paging is the first thing to learn

In Windows kernel exploitation, a huge number of topics ultimately come back to page tables:

- SMEP asks: is the kernel currently executing a user page?
- NX asks: is this page executable?
- KASLR asks: where does the kernel image's virtual address live?
- Physical R/W asks: which physical page does this virtual object reside on?
- HVCI asks: is the guest PTE sufficient to determine executable permission?
- KDP/VT-rp asks: does this mapping point to the correct protected physical page?
- KUSER_SHARED_DATA asks: can a single physical page have two virtual mappings with different permissions?

Without understanding paging, an exploit looks like a sequence of magic offsets. With paging understood, mitigations are revealed as policies attached to the translation path.

## 2. Virtual address is not physical address

Virtual address:

```text
fffff800`12345678
```

does not tell the CPU "read RAM at offset 0xfffff80012345678". It tells the CPU:

```text
Use the current CR3 and the current page tables to translate this address to a physical address.
```

Why does Windows need this?

- Each process has its own address space.
- The kernel can be mapped into multiple processes.
- Files/images/shared DLLs can share physical pages.
- Memory can be demand-paged.
- Pages have individual permissions: read/write/execute/user/supervisor.
- Copy-on-write allows multiple processes to see the same page until a write occurs.

Exploit implications:

- Leaking a virtual pointer is not enough when the primitive is physical R/W only.
- Physical R/W is powerful but requires translation.
- Page permissions can change an exploit result without changing the pointer.

## 3. CR0, CR4, CR3: three registers to know

### CR0.PG

The paging-enable bit. If paging is off, Windows x64 does not run as we know it. In a normal Windows x64 environment paging is on.

### CR4.PAE

PAE is required for 64-bit paging/long mode. Connor uses it to explain paging modes.

### CR3

Holds the physical base of the PML4. This is the entry point for a page walk.

Important: `CR3` is a physical address. With a physical memory read primitive, PML4 can be read directly from the physical address stored in CR3.

## 4. 4-level translation

Canonical 48-bit virtual address:

```text
| sign extend | PML4 | PDPT | PD | PT | page offset |
| 63......48  |47..39|38..30|29..21|20..12|11......0 |
```

Pseudo-code:

```text
pml4_base = CR3 & page_mask
pml4e = read64_phys(pml4_base + pml4_index * 8)

pdpt_base = pml4e.PFN * 0x1000
pdpte = read64_phys(pdpt_base + pdpt_index * 8)

pd_base = pdpte.PFN * 0x1000
pde = read64_phys(pd_base + pd_index * 8)

pt_base = pde.PFN * 0x1000
pte = read64_phys(pt_base + pt_index * 8)

physical = pte.PFN * 0x1000 + page_offset
```

For large pages:

- A PDPTE large mapping covers 1 GB.
- A PDE large mapping covers 2 MB.
- The PT/PTE level is skipped.

A common researcher mistake: writing a page walker that only supports 4 KB pages. Kernel code/data can reside in large pages depending on the build/configuration. A correct page walker must check the large-page bit.

## 5. Canonical address and crashes

Windows x64 addresses must be canonical. If bit 47 is 1, the high bits must all be 1. If bit 47 is 0, the high bits must all be 0.

A valid-looking kernel pointer:

```text
fffff800`abcd1234
```

Suspicious/non-canonical:

```text
0000f800`abcd1234
ffff0800`abcd1234
```

In an exploit, validate a pointer before dereferencing/writing:

```text
is_kernel_canonical(ptr):
  ptr >= ffff8000`00000000
  ptr <  ffffffff`fffffff0
```

This is not sufficient to prove the pointer is valid, but it filters out garbage.

## 6. PTE fields to know

A PTE contains:

- PFN: page frame number.
- Present/Valid.
- R/W.
- U/S.
- Accessed.
- Dirty.
- Global.
- NX.

Exploit meaning:

| Bit | Exploit relevance |
|---|---|
| Present | Is the page resident/valid? Invalid access -> fault. |
| R/W | Is a kernel/user write permitted at the guest PTE layer? |
| U/S | User vs supervisor. SMEP/SMAP care about this bit. |
| NX | Can the CPU fetch instructions from this page? DEP/NX depends on this bit. |
| Global | TLB behavior; kernel global mappings may persist across context switches. |

## 7. What is a PFN?

PFN = physical page number.

```text
physical_page_base = PFN * 0x1000
physical_address   = physical_page_base + offset
```

Connor uses WinDbg `!pte`/`!vtop` to show that the PFN from a PTE is multiplied by `0x1000` to obtain the physical address.

Why does PFN matter for BYOVD?

A driver physical map typically needs the physical page base. If you have the PTE/PFN, you can tell the driver to map that page and read/write at the desired offset.

## 8. PTE address vs physical page address

These are two different things:

```text
PTE address:
  where the entry describing the page is stored

Physical page address:
  the page that entry points to
```

If your arbitrary write targets the PTE, you change the mapping/permissions.
If you write to the physical page backing the object, you change the object's data.

Example:

```text
EPROCESS.Token VA -> PTE -> PFN -> PA token field
```

Writing to the PA token field: token changed.
Writing to the PTE of the page holding EPROCESS: mapping/permissions changed, higher risk.

## 9. Why PTE tampering bypassed old mitigations

Old mitigations:

- NX: page not executable.
- SMEP: page is user.

PTE tamper idea:

- Clear NX -> executable.
- Clear U/S -> supervisor.

If the kernel then jumps to that page, the CPU may allow it.

But this is the old model. On HVCI/VBS, the guest PTE is no longer the single source of truth. EPT/SLAT can say "no execute" even when the guest PTE says execute.

## 10. HVCI changes the PTE mental model

Without HVCI:

```text
Guest PTE permission -> CPU permission mostly follows it.
```

With HVCI:

```text
Guest PTE permission
  + EPT/SLAT permission
  + secure kernel code integrity policy
  -> actual execute/write behavior
```

Therefore "I cleared NX in the PTE" is no longer sufficient. If the page is not accepted by Code Integrity as kernel executable code, HVCI can still block execution.

Research conclusion:

- PTE tampering is still a concept to understand.
- On Windows 11 with HVCI enabled, PTE tampering should not be the default route for kernel code execution.
- Data-only or existing-code routes are more practical.

## 11. Page table self-reference / PTE base idea

Windows has mechanisms to map paging structures into the virtual address space, allowing the kernel to compute the virtual address of a PTE from any virtual address it wants to inspect.

Connor uses the concept of `MiGetPteAddress`.

Mental formula:

```text
PTE_for_VA = PteBase + ((VA >> 12) * 8)
```

There are canonical/sign-extension/mask details in practice. But the idea is: a VA indexes into the PTE array. Given the PTE base, you can compute the entry that describes any VA.

Exploit implications:

- Having the kernel base and a symbol/gadget -> find the PTE base helper.
- Having arbitrary read -> read a PTE.
- Having arbitrary write -> modify a PTE.

Modern caveats:

- KASLR.
- Symbol/offset changes.
- HVCI/secure kernel.
- PatchGuard/PTE integrity expectations.

## 12. KUSER_SHARED_DATA as a paging case study

`KUSER_SHARED_DATA` demonstrates:

```text
One physical page
  -> static read-only mapping
  -> randomized writable mapping
```

This is an alias mapping. Same backing physical memory, different permissions.

Lessons:

- Permissions belong to the mapping/PTE/EPT, not just the physical page.
- A single physical page can have multiple virtual addresses.
- Mitigations can maintain compatibility by keeping a static read mapping while creating a separate writable alias.

## 13. Physical R/W page walk example concept

Scenario:

```text
Primitive: map physical page read/write
Goal: read kernel object at VA ffffa507`11112222
Known: CR3
```

Research steps:

1. Check VA canonical.
2. Extract indexes.
3. Read PML4E physical from CR3.
4. Validate Present.
5. Read PDPTE.
6. Check large page.
7. Read PDE.
8. Check large page.
9. Read PTE.
10. Validate Present.
11. PA = PFN * 0x1000 + offset.
12. Map PA page via driver.
13. Read bytes.
14. Unmap.

Safety questions:

- Page boundary crossing?
- Large page?
- Present bit?
- Page belongs to RAM, not MMIO?
- Read operation itself safe under HVCI/EPT?
- Mapping API returns user VA safely?
- Need cache attributes?

## 14. Why this matters for ASTRA64

ASTRA64 gives physical map. It does not natively understand Windows objects.

Paging knowledge turns it into:

```text
physical primitive -> virtual kernel object read/write
```

Without page walk, attacker may scan RAM for patterns, which is noisy and unstable.

With page walk, attacker can:

- Find `ntoskrnl` from `LSTAR`.
- Resolve `PsInitialSystemProcess`.
- Walk `ActiveProcessLinks`.
- Translate token field VA to PA.
- Write exactly 8 bytes.

That is much more stable.

## 15. Why current Windows makes paging harder but more important

Windows 11 era adds:

- HVCI: second-layer execute policy.
- KDP: selected data read-only via VBS-backed protection.
- CET: return protection.
- kCFG: indirect branch target validation.
- blocklist/WDAC: driver load policy.
- possible LA57/5-level paging on future/compatible systems.
- KVA shadow/PCID/global mapping complexities.

Paging knowledge still matters because these features all attach to translation/control-flow, but the exploit cannot assume editing the guest PTE is enough.

## 16. Research exercises

Safe/lab-oriented exercises:

1. In WinDbg, run `!pte` on a user VA and kernel VA. Compare U/S and NX.
2. Use `!vtop` with a known CR3 to translate a VA.
3. Inspect `KUSER_SHARED_DATA` static mapping permission.
4. Compare PTE for a read-only mapping and writable alias if symbols/build expose it.
5. Inspect whether a page is large or 4 KB.
6. Record how output changes with HVCI on/off in a VM.

Avoid drawing conclusions without recording:

- Windows build.
- HVCI state.
- VBS state.
- CPU features.
- Debug/test signing state.

## 17. Key takeaways

- Virtual address is a recipe, not RAM.
- CR3 is the root of translation.
- PTE is where many exploit mitigations become concrete bits.
- Physical R/W needs VA->PA to become precise.
- SMEP/NX bypass via PTE is historically important but HVCI weakens it.
- Modern exploit research prefers data-only/existing-code routes when HVCI is on.
- KUSER_SHARED_DATA shows how Windows can preserve compatibility while changing write permissions through alias mappings.

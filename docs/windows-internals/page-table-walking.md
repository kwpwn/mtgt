# Page Table Walking

## Purpose

This document explains Windows-relevant x64 page-table walking, virtual-to-physical translation, and debugger inspection in a lab-safe form. It complements existing repo notes by isolating the translation model into one focused reference.

## Background

Many Windows kernel research topics eventually depend on one question:

```text
What physical page backs this virtual address,
and what translation layers or protections stand in between?
```

This matters for:

- crash triage,
- memory forensics,
- vulnerable driver analysis,
- physical-memory primitive assessment,
- understanding why some old bypass ideas fail on modern systems.

## Core Concepts

### CR3

On x64, `CR3` identifies the base of the current page-table hierarchy. Conceptually, it is the starting physical address for the top-level translation structure used by the CPU for that address space context.

### PML4, PDPT, PD, PT, PTE

Standard four-level x64 translation can be viewed as:

```text
virtual address
  -> PML4 index
  -> PDPT index
  -> PD index
  -> PT index
  -> PTE
  -> page frame number + page offset
  -> physical address
```

Each level narrows the translation until a page frame number (PFN) and offset identify the final physical location.

### PFN and page offset

The PFN identifies the physical page frame. The low bits of the virtual address become the offset inside that page. This is why many debugger and internals discussions split addresses into:

- page-aligned physical base,
- intra-page offset.

### Large pages

Translation can terminate early when a higher-level entry maps a large page. Analysts should not assume every virtual address walks all the way to a leaf PTE.

### User VA vs kernel VA

User virtual addresses and kernel virtual addresses exist in different privilege portions of the canonical x64 address space. The translation mechanics are similar, but:

- access policy differs,
- residency expectations differ,
- KPTI and mitigation behavior complicate visibility and assumptions.

## Technical Deep Dive

### Why physical R/W primitives need translation

A vulnerable driver that accepts a physical address is not automatically a general kernel-object primitive. Windows kernel structures are usually discussed in virtual-address terms. Bridging the gap requires either:

- page-table walking,
- a trusted helper mechanism,
- or less reliable physical scanning.

That is why translation knowledge remains central even in a mitigation-aware research environment.

### Conceptual walk

```text
Input: target virtual address
Need: page-table root that maps the target range

1. Split VA into indexes and page offset
2. Read PML4 entry
3. Read PDPT entry
4. Read PD entry
5. Read PT entry if needed
6. Extract PFN from leaf entry
7. Combine PFN with offset
```

This is a diagnostic and reasoning model, not an instruction to abuse physical memory.

### KPTI impact

Kernel page-table isolation (KPTI, often discussed with KVA shadow) changes assumptions about which mappings are visible in which mode and under which context. Research implications:

- a user-mode context may not expose the same kernel mapping view that older literature assumed,
- context matters when interpreting a page-table root,
- "works on one build" is not enough evidence for generalized translation assumptions.

### Common mistakes in translation reasoning

| Mistake | Why it is wrong |
|---|---|
| Assuming every walk ends at a normal PTE | Large pages can terminate the walk early |
| Assuming any valid `CR3` is enough | The relevant mappings must exist in that context |
| Confusing PTE address with mapped page address | One describes translation state, the other the data page |
| Assuming guest PTE permission is the only policy | Modern systems can add hypervisor-backed enforcement layers |
| Assuming user-visible and kernel-visible mappings are interchangeable | KPTI and policy layers break that simplification |

### WinDbg inspection view

Debugger work is the safest place to internalize the model:

- `!process` helps establish process context.
- `!pte` shows translation entries and status bits for a virtual address.
- `!vtop` translates a virtual address using a page directory base.
- `dq` / `dd` help inspect related memory in context.

The goal is to learn how the translation looks, not to build an abuse chain.

### Translation checklist

- What is the virtual address being reasoned about?
- Which context or process root is being used?
- Is the target likely mapped in that context?
- Is there a large-page shortcut?
- Is the analyst confusing translation metadata with the backing object itself?
- Do mitigation layers make a simple guest-PTE conclusion incomplete?

## Windows Version Notes

- Four-level x64 paging remains the baseline model for current Windows systems covered by this repo.
- KPTI/KVA shadow changed practical assumptions about kernel mapping visibility after major speculative-execution mitigation waves.
- Modern Windows with HVCI/VBS requires analysts to distinguish guest translation from higher-layer execution or protection policy.

## Common Mistakes

- Overgeneralizing old SMEP/NX/PTE-bypass literature to modern HVCI-enabled systems.
- Assuming translation knowledge automatically gives a safe or meaningful write target.
- Ignoring large pages and context-specific mappings.
- Using one successful translation example as proof that all relevant kernel objects are reachable the same way.

## Debugging / Inspection Notes

WinDbg commands for inspection:

- `!process`
- `!pte`
- `!vtop`
- `dq`
- `dd`

Lab-safe exercise pattern:

```text
select process context
  -> inspect a user VA with !pte
  -> inspect a kernel VA with !pte
  -> compare privilege bits, write bits, and backing PFN behavior
```

## Defensive Angle

Translation knowledge helps defenders and researchers:

- interpret crash dumps more accurately,
- judge claims about physical-memory vulnerabilities,
- separate discovery capability from stable end-state capability,
- understand why some mitigations break old mental models without making unsafe driver semantics safe.

## Lab-Safe Exercises

1. In a lab VM, run `!pte` on one user address and one kernel address and record the differences you can explain.
2. Use `!vtop` to confirm the PFN and page offset concept on a known mapped address.
3. Write a short note comparing "PTE state" versus "object security state" for the same kernel object.

## References / Further Reading

- Microsoft Learn, `!pte`:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-pte
- Microsoft Learn, `!vtop`:
  https://learn.microsoft.com/ga-ie/windows-hardware/drivers/debugger/-vtop
- Existing repo note, `04_connor-mcgarr-study/01_PAGING_AND_PTE_DEEP_DIVE.md`
- Existing repo note, `02_mitigations-vbs-hvci-vtrp/VT_RP_HLAT_DEEP_DIVE_VI.md`

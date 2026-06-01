# Intel VT-rp, HLAT, EPT, KDP - Deep Dive

Primary sources:

- Satoshi Tanda, Intel VT-rp Part 1: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html
- Satoshi Tanda, Intel VT-rp Part 2: https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html
- Sample hypervisor/course: https://github.com/tandasat/Hypervisor-101-in-Rust
- Microsoft KDP: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Fortinet DSE/KDP/remapping context: https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering
- Connor McGarr HVCI/kCFG context: https://connormcgarr.github.io/hvci/
- Andrea Allievi Alder Lake features: https://www.andrea-allievi.com/blog/alder-lake-and-the-new-intel-features/
- Intel HLAT reference page: https://edc.intel.com/content/www/us/en/design/products/platforms/details/raptor-lake-s/13th-generation-core-processors-datasheet-volume-1-of-2/005/hypervisor-managed-linear-address-translation/
- Intel VT-rp community explanation: https://community.intel.com/t5/Blogs/Tech-Innovation/Client/Intel-Virtualization-Technology-Redirect-Protection-Intel-VT-rp/post/1672593

## 1. One-sentence summary of the whole article

Tandasat's article explains a very specific problem:

```text
Hypervisors use EPT to make kernel data read-only.
An attacker with kernel R/W can still modify the guest's page tables to "reroute" a linear address to a different physical page.
That is the remapping attack.
Intel VT-rp, specifically HLAT, was created to lock the entire LA -> GPA translation process, not just the GPA -> PA permission.
```

In shorter form:

```text
EPT protects "this physical page is not writable".
Remapping attack bypasses that by making "the old virtual address point to a different physical page".
HLAT gives the hypervisor the authority to decide which physical page a virtual address must resolve to.
```

## 2. Address layers: LA, GPA, PA

The article uses three concepts:

| Abbreviation | Name | Meaning |
|---|---|---|
| LA | Linear Address | The address that code in the guest/OS sees after segmentation, before paging. On x64 this is essentially the same as a virtual address. |
| GPA | Guest Physical Address | "Physical address" from the guest OS's perspective. The Windows kernel treats this as real RAM. |
| PA / HPA / SPA | Host/System Physical Address | The true physical address on the host machine, managed by the hypervisor/EPT. |

Without virtualization:

```text
LA -> PA
```

With EPT/SLAT:

```text
LA -> GPA -> PA
```

In VMX non-root mode, the guest OS manages the step:

```text
LA -> GPA
```

The hypervisor manages the step:

```text
GPA -> PA
```

## 3. Traditional paging: LA -> physical

On x64 4-level paging:

```text
CR3 -> PML4 -> PDPT -> PD -> PT -> page frame
```

The virtual address is split into indices:

```text
bits 47..39 = PML4 index
bits 38..30 = PDPT index
bits 29..21 = PD index
bits 20..12 = PT index
bits 11..0  = offset within page
```

Example:

```text
LA = fffff8024b082004
```

The CPU uses CR3 to locate the page table, walks through PML4E/PDPTE/PDE/PTE, and finally takes the PFN and adds the offset `0x004`.

If the PTE contains PFN `0x11ceaa`, then:

```text
GPA = 0x11ceaa000 + 0x004 = 0x11ceaa004
```

## 4. What is EPT / SLAT?

EPT is Intel Extended Page Table. It is a form of SLAT: Second Level Address Translation.

Guest Windows believes:

```text
GPA 0x11ceaa004 is physical RAM
```

But in reality when running under a hypervisor, the CPU takes one additional step:

```text
GPA 0x11ceaa004 -> some real PA/HPA
```

EPT entries have their own permissions:

- Read
- Write
- Execute
- memory type
- accessed/dirty
- other extended bits

Key strength:

```text
Even a guest kernel with ring 0 cannot modify the EPT.
```

Only the hypervisor has authority over the EPT.

## 5. How does EPT help protect the kernel?

If a hypervisor wants to protect a page containing sensitive data, it can set the EPT permission:

```text
GPA containing sensitive data: Read = 1, Write = 0
```

Even if an attacker has an arbitrary kernel write in the guest:

```text
write to LA -> guest paging resolves to protected GPA -> EPT blocks the write
```

That is the foundation of:

- HVCI: protecting code integrity, kernel code is not writable.
- KDP: protecting kernel data, sensitive data is not writable from VTL0.

Microsoft's KDP documentation explicitly states that KDP uses VBS/SLAT to make memory read-only from the VTL0 perspective.

## 6. VBS, VTL0, VTL1

In Windows VBS:

| Layer | Meaning |
|---|---|
| VTL0 | Normal Windows kernel, drivers, and user mode |
| VTL1 | Secure kernel / isolated trustlets |
| Hypervisor | Manages isolation via SLAT/EPT |

An attacker with kernel R/W is typically only in VTL0.

KDP/HVCI aim to assert:

```text
The VTL0 kernel is not unconditionally trusted.
Only the secure kernel/hypervisor decides whether certain pages are writable.
```

## 7. What is KDP?

KDP = Kernel Data Protection.

Microsoft describes two forms:

- Static KDP: a driver/kernel marks a data section of an image as protected.
- Dynamic KDP: a secure pool where data is initialized once and then made read-only.

The idea:

```text
important data -> hypervisor marks EPT read-only -> VTL0 cannot modify it
```

Examples of sensitive data:

- code integrity policy data,
- callback/config tables,
- security product immutable config,
- "initialize once" data.

## 8. How does HVCI differ from KDP?

HVCI:

```text
protects code integrity / executable memory
```

KDP:

```text
protects data integrity / read-only data
```

HVCI is concerned with:

- unsigned code,
- W^X,
- kernel code pages not being patched.

KDP is concerned with:

- sensitive data pages not being modified.

But Tandasat's article argues that EPT read-only protection as used by KDP still has a design gap: remapping.

## 9. What is the remapping attack?

Suppose:

```text
LA A -> GPA X
GPA X is EPT read-only
```

The attacker cannot write to GPA X.

But with kernel R/W, the attacker can modify the guest PTE:

```text
LA A -> GPA Y
```

Where GPA Y is a different page, writable in the EPT.

Result:

```text
Reading LA A now returns the contents of GPA Y.
```

The attacker did not modify page X. The attacker changed the mapping so that LA A points to page Y.

This is "remapping" or "page swapping".

## 10. An everyday analogy

Imagine:

- `LA A` is a street address: "10 Kernel Street".
- `GPA X` is the actual house containing a safe.
- The hypervisor locks house X: nobody can modify the contents inside.

The attacker does not break the lock on house X.

The attacker modifies the map so that:

```text
"10 Kernel Street" -> house Y
```

When someone goes to "10 Kernel Street", they arrive at Y, not X.

The hypervisor is still protecting X, but the system has been deceived because the virtual name/address now points somewhere else.

## 11. The demo in the article: `ci!g_CiOptions`

Tandasat uses the variable:

```text
ci!g_CiOptions
```

This is a Code Integrity-related variable in `ci.dll`.

Demo steps:

1. Find the LA of `ci!g_CiOptions`.
2. Find the GPA backing it.
3. Confirm that EPT page is read-only.
4. Find a zero-filled GPA.
5. Modify the guest PTE of `ci!g_CiOptions` to point to the zero page.
6. Read `ci!g_CiOptions` again and observe that it is zero.

Key point:

```text
The protected GPA is never written to.
Only the guest page table is modified so that the LA points to a different GPA.
```

## 12. Why doesn't KDP block remapping?

KDP protects a page at the EPT level:

```text
GPA X is not writable
```

But KDP does not necessarily enforce:

```text
LA A must always resolve to GPA X
```

Microsoft itself calls out this limitation: KDP does not enforce how a virtual address range is translated.

So if the guest kernel PTE is modified by an attacker:

```text
LA A -> GPA Y
```

KDP still correctly protects X, but LA A now reads from Y.

## 13. Why does this matter for BYOVD?

BYOVD typically gives an attacker a kernel write primitive.

Examples:

- Dell DBUtil write.
- RTCore64 write.
- ASTRA/Lenovo physical R/W.

If an attacker can modify PTEs or page tables, they can perform remapping.

Therefore HVCI/KDP do not always mean "game over" for the attacker. Modern exploits shift toward:

- data-only,
- remapping,
- PTE manipulation,
- aliasing,
- object state abuse.

## 14. Does demo `g_CiOptions = 0` allow loading unsigned drivers?

According to the article, it is not that simple.

Tandasat notes that when HVCI is enabled, forcing `ci!g_CiOptions` in VTL0 is not sufficient to load unsigned drivers. The secure kernel still performs its own certificate check and will crash the system if a problem is detected.

Meaning:

```text
Remapping can make VTL0 read manipulated data,
but the secure kernel/VTL1 still has its own independent logic.
```

Do not confuse this with:

```text
remap g_CiOptions = instant unsigned driver load
```

It is not.

## 15. More interesting remapping targets

The article suggests other targets:

- valid kCFG bitmaps,
- sensitive function pointers,
- data that is read-only due to EPT protection.

The idea:

```text
If data is protected by EPT but the semantic of the LA matters,
remapping the LA can change behavior without writing to the original page.
```

Concept example:

```text
LA of kCFG bitmap -> new GPA with desired "valid target" bits set
```

This is concept research, not a complete exploitation guide.

## 16. What is Intel VT-rp?

VT-rp = Intel Virtualization Technology Redirect Protection.

According to the article, VT-rp consists of three features:

1. HLAT: Hypervisor-managed Linear Address Translation.
2. PW: Paging-write.
3. GPV: Guest-paging verification.

Common goal:

```text
help hypervisors enforce guest memory translation/permissions more effectively,
blocking remapping/aliasing without needing to trap every write to a page table.
```

## 17. Why not just make guest page tables read-only?

The obvious idea:

```text
Hypervisor marks all guest page tables read-only via EPT.
Every time the guest wants to modify a PTE -> VM-exit -> hypervisor checks.
```

Problems:

- The OS modifies page tables very frequently.
- Each write triggers an expensive VM-exit.
- Performance would degrade severely.

VT-rp was created to provide efficient hardware assistance.

## 18. What is HLAT?

HLAT = Hypervisor-managed Linear Address Translation.

Normally:

```text
CPU uses the guest CR3 to translate LA -> GPA.
```

When HLAT is active for a range:

```text
CPU uses the HLATP VMCS field to access page tables managed by the hypervisor.
```

That is:

```text
LA -> GPA is no longer decided by the guest CR3.
LA -> GPA is decided by hypervisor-managed paging structures.
```

This is the key point.

## 19. What is HLATP?

HLATP = Hypervisor-managed Linear Address Translation Pointer.

It is a VMCS field.

VMCS is the control structure for Intel VT-x. The hypervisor configures the VMCS so that the CPU knows:

- guest state,
- host state,
- VM-execution controls,
- EPT pointer,
- exit controls,
- and with VT-rp: HLATP.

HLATP points to the root paging structure managed by the hypervisor, analogous to CR3 but owned by the hypervisor.

## 20. What is the HLAT prefix size?

HLAT does not necessarily apply to every linear address.

The article states that the CPU decides whether to use HLAT based on:

```text
HLAT enabled
LA falls within the range determined by the HLAT prefix size VMCS field
```

This means the hypervisor can say:

```text
only a specific LA range uses HLAT
```

This matters for performance and compatibility.

## 21. How does HLAT block remapping?

Without HLAT:

```text
LA A -> guest PTE -> GPA X
attacker modifies guest PTE
LA A -> GPA Y
```

With HLAT:

```text
LA A -> HLAT page table -> GPA X
guest PTE modifications are not used
```

After the attacker modifies the guest page table:

```text
LA A still translates via the HLAT table held by the hypervisor
```

Remapping therefore becomes a no-op.

## 22. A very simple example

Before protection:

```text
guest CR3 table:
  ci!g_CiOptions LA -> GPA 0x111000
```

Attacker modifies:

```text
guest CR3 table:
  ci!g_CiOptions LA -> GPA 0x200000
```

Reading the LA returns the zero page.

After HLAT:

```text
HLAT table:
  ci!g_CiOptions LA -> GPA 0x111000

guest CR3 table:
  ci!g_CiOptions LA -> GPA 0x200000
```

CPU uses the HLAT table, not the guest CR3 table.

Reading the LA still returns GPA 0x111000.

## 23. The Restart bit in HLAT

Part 1 notes that the major difference between traditional paging and HLAT paging is bit 11, called the Restart bit.

When the CPU encounters a Restart bit during HLAT paging:

```text
abort HLAT paging
fall back to traditional guest paging
```

Why is this needed?

- Not every page needs HLAT.
- The hypervisor can protect select pages.
- Compatibility and performance are maintained for non-sensitive regions.

Example:

```text
kernel security data region -> HLAT enforced
normal region -> Restart -> guest CR3 manages on its own
```

## 24. HLAT demo in the article

The article uses a custom hypervisor.

Conceptual flow:

1. Boot Windows as a guest of the custom hypervisor.
2. Find the LA/PTE of `ci!g_CiOptions`.
3. Issue a hypercall so the hypervisor enables HLAT for that LA.
4. The hypervisor copies current guest paging structures into hypervisor-managed structures.
5. Attempt the remapping attack again.
6. `ci!g_CiOptions` does not change.

Meaning:

```text
the guest PTE was successfully modified,
but the CPU no longer uses the guest PTE for that LA.
```

## 25. PW - What is Paging-write?

Part 2 explains Paging-write.

The problem:

HLAT page tables are managed by the hypervisor, but the CPU still reads them while in VMX non-root. These page tables reside at GPAs that, from an address perspective, are visible to the guest.

The hypervisor wants to mark them read-only via EPT so the guest cannot modify them.

But the CPU, when page-walking, may automatically set Accessed/Dirty bits in paging structures.

That is a "paging write":

```text
the hardware page walk writes A/D bits into page table entries on its own
```

If the EPT for the page table page is read-only, a hardware paging write will cause an EPT violation/VM-exit.

## 26. What does the PWA bit solve?

VT-rp adds PWA: Paging-Write Access bit in an EPT entry.

The idea:

```text
EPT Write = 0, but PWA = 1
```

Meaning:

- guest software is not allowed to write to the page table.
- the hardware page-walk is allowed to write the necessary A/D bits.

This is an important performance optimization.

Without PWA:

```text
every time the CPU wants to set an A/D bit -> VM-exit
```

With PWA:

```text
hardware paging writes go through without requiring a VM-exit
```

## 27. GPV - What is Guest Paging Verification?

GPV = Guest-paging verification.

Goal:

```text
prevent a sensitive GPA from being accessed via an unexpected LA or alias mapping
```

Aliasing means:

```text
LA A -> GPA X
LA B -> GPA X
```

If the hypervisor wants GPA X to only be accessible via LA A, GPV helps verify the page-walk path.

## 28. How does GPV work conceptually?

Part 2 states:

When the EPT leaf entry for a GPA has the VGP bit set, the CPU will verify the EPT leaf entries used to read the guest paging structures during the LA->GPA translation.

It requires those paging-structure pages to be marked PWA.

In plain terms:

```text
GPA X is only valid if the translation path traverses page tables that the hypervisor has marked as "ok".
```

If an attacker creates an alias via different page tables that are not marked:

```text
LA B -> attacker page tables -> GPA X
```

The CPU sees the page-walk did not pass through PWA-approved structures -> EPT violation.

## 29. HLAT vs GPV

HLAT:

```text
hypervisor replaces guest page tables for a LA range
```

GPV:

```text
hypervisor verifies whether the guest paging path to a GPA passed through approved page tables
```

HLAT blocks remapping by not using the guest PTE.

GPV blocks aliasing by checking the provenance of the translation path.

## 30. PW vs GPV

PW/PWA:

```text
allows hardware page-walk to write A/D bits into paging structures even when EPT write=0
```

GPV/VGP:

```text
enforces that access to a GPA must pass through paging structures marked PWA
```

They are related because the PWA bit:

- helps performance for paging writes,
- marks the paging structure path as approved for GPV.

## 31. Remapping vs aliasing

Remapping:

```text
LA A originally -> GPA X
attacker changes -> GPA Y
```

Aliasing:

```text
LA A -> GPA X
LA B -> GPA X
```

Remapping targets the identity of the LA.

Aliasing targets accessing the same GPA via a different LA.

HLAT is effective against remapping.

GPV is useful against aliasing/provenance of translation.

## 32. Why is code integrity harder to attack via remapping than data?

Part 2 notes that remapping attacks against code integrity are harder.

For data:

```text
find a writable GPA containing fake data -> remap the data LA to point there
```

For code:

You need a GPA that is simultaneously:

- writable so you can plant shellcode,
- executable at the EPT level so it can run.

HVCI/W^X tries to guarantee:

```text
no page is both writable and executable
```

So remapping is easier for data-protection bypass and harder for code execution.

## 33. How do SMEP, MBEC/GMET, kCFG, and CET relate?

Part 2 emphasizes that VT-rp only addresses a subset of the problem.

Other mitigations are still needed:

| Mitigation | What it blocks |
|---|---|
| W^X / HVCI | writable code or executable unsigned code |
| SMEP | kernel executing user-mode pages |
| SMAP | kernel accessing user-mode pages without proper context |
| MBEC / GMET | finer-grained user/kernel execute permission separation |
| kCFG | invalid indirect call targets |
| CET shadow stack | return address / ROP tampering |

VT-rp does not replace these mitigations.

Its primary role is:

```text
translation integrity
```

## 34. Relationship to ASTRA64 / physical R/W

With ASTRA64, you have physical R/W.

If you use it to directly write `_EPROCESS.Token`:

```text
this has little to do with remapping/KDP targets
```

Because `_EPROCESS.Token` is typically normal VTL0 kernel data, not a KDP-protected page.

But if you use physical/kernel writes to modify PTEs:

```text
that falls into the same family of techniques as remapping attacks
```

HLAT/VT-rp will render PTE tampering ineffective for protected LAs.

## 35. Relationship to BYOVD

BYOVD provides kernel primitives:

- arbitrary write,
- physical R/W,
- MSR,
- virtual R/W.

EPT/KDP/HVCI attempt to make certain targets non-writable.

The remapping attack says:

```text
if the attacker can still modify guest page tables,
they can avoid writing to the protected GPA by changing LA->GPA.
```

VT-rp says:

```text
the hypervisor must also protect the translation, not just page permissions.
```

This is a natural evolution:

```text
Code patch -> HVCI
Data patch -> KDP
Page remap -> VT-rp/HLAT/GPV
```

## 36. Why hadn't Hyper-V adopted VT-rp at the time of writing?

The article states that at the time, major hypervisors including Hyper-V had not widely adopted VT-rp.

Practical reasons likely include:

- hardware support was not yet widespread,
- only a subset of Intel 12th gen and later supports it,
- no AMD equivalent,
- complex integration,
- compatibility/performance concerns,
- requires significant changes to the hypervisor memory manager.

A later Intel community post states that VT-rp provides a root of page walk, PWA, GPV, and restart-bit compatibility.

## 37. Availability

According to the article:

- VT-rp is available on a subset of Intel 12th gen and later processors.
- No direct AMD equivalent existed at the time of writing.
- Requires hypervisor support, not just CPU support.

This matters:

```text
CPU supporting VT-rp != Windows/Hyper-V is using VT-rp for the protections you care about.
```

## 38. What is VMCS?

VMCS = Virtual Machine Control Structure.

Intel VT-x uses the VMCS so that the CPU knows:

- what state to use when running the guest,
- what state to restore when exiting to the host,
- which conditions trigger a VM-exit,
- where the EPT pointer is,
- which execution controls are enabled,
- with VT-rp: HLATP, HLAT prefix, PW/GPV controls.

The hypervisor configures the VMCS via VMREAD/VMWRITE.

## 39. VMX root vs non-root

Intel VT-x separates:

| Mode | Who runs |
|---|---|
| VMX root | Hypervisor |
| VMX non-root | Guest OS |

Even a Windows guest kernel at ring 0 is:

```text
VMX non-root ring 0
```

The hypervisor operates at:

```text
VMX root
```

Therefore the guest kernel cannot modify EPT/VMCS.

## 40. What is a VM-exit?

A VM-exit is when the CPU leaves the guest and returns to the hypervisor due to a condition:

- EPT violation,
- privileged instruction,
- CPUID if configured,
- MSR access if configured,
- external interrupt,
- paging-write violation,
- GPV violation,
- etc.

VM-exits are more expensive than normal execution.

This is why hypervisors do not want to trap every page-table write if a more efficient hardware mechanism exists.

## 41. How does TLB relate?

The TLB caches translation results.

When page tables, EPT, or HLAT structures change, the hypervisor/OS needs appropriate invalidation:

- INVLPG,
- INVVPID,
- INVEPT,
- context-switch invalidation,
- PCID/VPID optimizations.

In a remapping attack:

```text
modify guest PTE -> need TLB flush so the CPU uses the new mapping
```

With HLAT:

```text
guest PTE is modified but the CPU uses HLAT translation for protected LAs
```

TLB handling remains an important implementation detail, but the conceptual protection is: the source of translation has shifted to hypervisor-managed structures.

## 42. EPT permissions vs guest PTE permissions

There are two layers of permissions:

Guest PTE:

- Present
- RW
- User/Supervisor
- NX

EPT PTE:

- Read
- Write
- Execute
- EPT memory type
- PWA/VGP extensions with VT-rp

An access succeeds only when both layers permit it in context.

Example:

```text
guest PTE writable = 1
EPT writable = 0
=> write is still blocked by EPT
```

But a remapping attack changes the guest PTE to point to a different GPA:

```text
guest PTE points to GPA Y
EPT writable for GPA Y = 1
=> write/read semantics can change
```

## 43. Why is HLAT not just "an upgraded EPT"?

EPT manages:

```text
GPA -> PA
```

HLAT intervenes in:

```text
LA -> GPA
```

These are different layers.

Remapping attacks live at the LA->GPA layer, so EPT alone is insufficient.

HLAT gives the hypervisor authority over LA->GPA for sensitive regions.

## 44. Why is it called Redirect Protection?

Because the attack is a redirect:

```text
redirect the LA from a protected GPA to an attacker-controlled GPA
```

VT-rp blocks that redirect.

It does not merely say "this page is read-only" but says:

```text
this linear address must resolve according to the path the hypervisor has decided
```

## 45. Topics the blog did not cover deeply, but you should study further

1. Intel VT-x basics:
   - VMXON
   - VMCS
   - VMLAUNCH/VMRESUME
   - VM-exit handling

2. EPT implementation:
   - EPTP
   - EPT walk
   - INVEPT
   - EPT violation qualification

3. Windows VBS:
   - VTL0/VTL1
   - Secure Kernel
   - Isolated User Mode
   - HVCI
   - KDP

4. Windows memory manager:
   - PTE layout
   - PFN database
   - large pages
   - KVA shadow
   - PCID

5. Modern kernel exploit mitigations:
   - SMEP
   - SMAP
   - MBEC/GMET
   - kCFG
   - CET shadow stacks
   - PatchGuard

6. BYOVD:
   - physical R/W drivers
   - virtual R/W drivers
   - MSR drivers
   - process-killer drivers

## 46. Recommended learning order

A sensible sequence:

1. x64 normal paging.
2. EPT/SLAT.
3. Windows VBS/HVCI/KDP.
4. Remapping attack.
5. HLAT.
6. PW/PWA.
7. GPV/VGP.
8. kCFG/CET/MBEC/SMEP as supplementary context.
9. BYOVD physical R/W connected to real-world primitives.

Starting directly from HLAT is very difficult because HLAT is a protection layer for a design gap at the LA->GPA level.

## 47. Synthesis diagram

Without VT-rp:

```text
Guest code uses LA
  -> guest CR3 page tables decide LA -> GPA
  -> EPT decides GPA -> PA
  -> memory access

Attacker with kernel write:
  -> edits guest PTE
  -> LA now points to different GPA
```

With HLAT:

```text
Guest code uses protected LA
  -> CPU uses HLATP, not guest CR3
  -> hypervisor-managed page tables decide LA -> GPA
  -> EPT decides GPA -> PA
  -> memory access

Attacker edits guest PTE:
  -> ignored for protected LA
```

With GPV:

```text
Access to sensitive GPA
  -> CPU verifies translation path used approved paging structures
  -> alias through unapproved page tables causes EPT violation
```

## 48. A simple self-constructed example

Suppose the kernel has a variable:

```text
PolicyEnabled at LA 0xffff8000`10002000
```

Initially:

```text
LA PolicyEnabled -> GPA 0xABC000
EPT for 0xABC000: R=1 W=0
```

The attacker cannot write to `0xABC000`.

The attacker creates a fake page:

```text
GPA 0xDEF000: contains PolicyEnabled = 0
EPT for 0xDEF000: R=1 W=1
```

The attacker modifies the guest PTE:

```text
LA PolicyEnabled -> GPA 0xDEF000
```

Without HLAT:

```text
the kernel reads PolicyEnabled and sees 0
```

With HLAT:

```text
HLAT table still says LA PolicyEnabled -> GPA 0xABC000
the kernel reads PolicyEnabled and sees the true value
```

## 49. Relating to "does physical memory R/W bypass HVCI?"

Physical R/W can help:

- modify normal VTL0 data,
- modify guest page tables,
- perform remapping if VT-rp/HLAT is not protecting those regions,
- avoid needing kernel shellcode.

But physical R/W does not automatically:

- write to VTL1 secure kernel memory,
- bypass secure kernel certificate checks,
- bypass KDP if HLAT/VT-rp enforces translation,
- bypass code integrity if there is no W+X/executable path.

Therefore:

```text
physical R/W is a very powerful primitive,
but modern hypervisor protections are shifting the goal from "protect the page" to "protect the translation path".
```

## 50. Final conclusion

Tandasat's article contains three deep insights:

1. EPT/KDP protects a physical page, but does not necessarily protect the virtual-address identity.
2. The remapping attack exploits that gap by modifying guest page tables.
3. VT-rp/HLAT/PW/GPV is the hardware answer enabling hypervisors to protect the entire translation path efficiently.

If you are studying modern Windows kernel exploitation, this is an important bridge between:

```text
BYOVD arbitrary write
-> PTE/page-table manipulation
-> HVCI/KDP bypass ideas
-> hardware-assisted mitigation
```

## 51. Going deeper: what does the CPU actually do when translating an address?

When code running in the guest executes an instruction like:

```asm
mov eax, dword ptr [fffff8024b082004]
```

The CPU does not "know" this is `ci!g_CiOptions`. The CPU only sees a linear address:

```text
LA = fffff8024b082004
```

When in VMX non-root mode with EPT enabled, the CPU must perform two translations:

```text
guest paging: LA  -> GPA
EPT paging:   GPA -> HPA/PA
```

Crucially, these two translations have different owners:

- The guest OS manages page tables for LA -> GPA.
- The hypervisor manages EPT for GPA -> PA.

A kernel exploit within the guest can modify guest page tables because page tables are guest memory. But it cannot modify EPT without escaping the VMX non-root/hypervisor boundary.

This is why EPT was originally very appealing for security:

```text
a compromised guest kernel still cannot alter EPT permissions
```

But the remapping attack emerged because that security property alone was not sufficient.

## 52. Concrete numeric example: 4-level page-table walk

Take a hypothetical LA:

```text
LA = fffff8024b082004
```

On x64 canonical 48-bit paging, the CPU extracts indices:

```text
PML4 index = (LA >> 39) & 0x1ff
PDPT index = (LA >> 30) & 0x1ff
PD index   = (LA >> 21) & 0x1ff
PT index   = (LA >> 12) & 0x1ff
offset     = LA & 0xfff
```

Suppose these compute to:

```text
PML4 index = 0x1f0
PDPT index = 0x009
PD index   = 0x058
PT index   = 0x082
offset     = 0x004
```

CR3 holds the physical address of the PML4:

```text
CR3 = 0x12345000
```

The CPU reads:

```text
PML4E address = 0x12345000 + 0x1f0 * 8
```

The PML4E contains the PFN of the PDPT:

```text
PML4E = 0x00000000aaa00123
PFN base = 0xaaa00000
```

Then:

```text
PDPTE address = 0xaaa00000 + 0x009 * 8
PDE address   = PFN(PDPTE) + 0x058 * 8
PTE address   = PFN(PDE)   + 0x082 * 8
```

If the PTE contains:

```text
PTE = 0x000000011ceaa121
```

then the PFN base is:

```text
0x11ceaa000
```

Final GPA:

```text
GPA = 0x11ceaa000 + 0x004 = 0x11ceaa004
```

This is exactly the logic that physical R/W exploits like ASTRA64 must implement themselves when converting a kernel VA to a physical address.

## 53. Concrete numeric example: EPT walk

After obtaining the GPA:

```text
GPA = 0x11ceaa004
```

The CPU continues using EPTP, the EPT pointer that the hypervisor has configured in the VMCS.

EPT also has a multi-level paging structure. The concept is similar:

```text
EPTP -> EPT PML4 -> EPT PDPT -> EPT PD -> EPT PT -> HPA
```

But EPT entries differ from guest PTEs in their permission fields.

Guest PTE has:

- Present
- RW
- User/Supervisor
- NX

EPT PTE has:

- Read
- Write
- Execute
- memory type
- accessed/dirty
- extended bits such as PWA/VGP with VT-rp.

Suppose the EPT PTE for GPA page `0x11ceaa000` is:

```text
EPT: Read=1, Write=0, Execute=0
```

When the guest reads:

```text
mov eax, [LA]
```

that succeeds.

When the guest writes:

```text
mov [LA], eax
```

the CPU translates LA -> GPA to `0x11ceaa004`, the EPT sees Write=0, and triggers an EPT violation VM-exit.

The hypervisor can log/deny/crash depending on policy.

## 54. The problem: EPT protects a GPA, not "the semantic of an LA"

The subtle point:

EPT knows:

```text
GPA 0x11ceaa000 is not writable.
```

EPT does not know on its own:

```text
LA fffff8024b082004 must always resolve to GPA 0x11ceaa000.
```

The LA -> GPA relationship lives in guest page tables.

If an attacker modifies the guest PTE:

```text
PTE for LA fffff8024b082004:
  before: PFN 0x11ceaa
  after:  PFN 0x200
```

then the CPU will translate:

```text
LA -> GPA 0x200004
```

If EPT for GPA `0x200000` is writable/readable, reading the LA will return the contents of that page.

EPT is still protecting `0x11ceaa000`. But the LA no longer resolves there.

That is the entire spirit of remapping.

## 55. Remapping attack with a 4-page model

Suppose there are 4 pages:

```text
GPA A = page containing the real policy, protected by KDP
GPA B = page created/copied by attacker, writable
GPA C = a page-table page
GPA D = ordinary data
```

Initially:

```text
LA policy -> GPA A
EPT[GPA A].Write = 0
EPT[GPA B].Write = 1
```

The attacker has arbitrary kernel write. They do not write to GPA A. They write to the PTE inside GPA C:

```text
PTE(policy LA).PFN = B
```

Afterwards:

```text
LA policy -> GPA B
```

When kernel/security logic reads `policy LA`, it reads the fake version at B.

This is a "remap the map" attack, not a "break the lock on the house" attack.

## 56. Why is this called "bypassing KDP" even though the protected page is not modified?

KDP protects the contents of page A from being modified. That statement remains true.

But the actual security goal is not just:

```text
page A is unchanged
```

The real goal is:

```text
when the kernel reads the policy at LA policy, it receives the true policy
```

Remapping defeats the second goal.

It is therefore a semantic bypass:

```text
KDP protected bytes intact,
but the protected virtual address no longer resolves to those bytes.
```

This is the core insight.

## 57. Why can't the hypervisor simply inspect every PTE write?

It can, but the cost is prohibitive.

Windows modifies page tables very frequently:

- allocate/free memory,
- page fault handling,
- process creation,
- driver loading,
- copy-on-write,
- working set trimming,
- memory compression,
- large page splitting,
- KVA shadow transitions.

If the hypervisor marks page tables read-only and VM-exits on every guest PTE write:

```text
every time the OS adjusts a memory mapping -> trap into hypervisor
```

Performance would degrade significantly.

HLAT/VT-rp is hardware support to address only the sensitive regions without trapping everything.

## 58. HLAT viewed as "a second CR3" held by the hypervisor

An intuitive way to understand it:

```text
guest CR3 = the map maintained by Windows
HLATP     = the map maintained by the hypervisor
```

Normally the CPU uses:

```text
guest CR3
```

With HLAT active for a given LA, the CPU uses:

```text
HLATP
```

If an attacker modifies Windows's map:

```text
guest CR3 table is tampered
```

protected LAs still resolve via the hypervisor's map.

That is why HLAT is "Hypervisor-managed Linear Address Translation".

## 59. HLAT does not mean copying the entire address space permanently

A common misconception:

```text
HLAT means the hypervisor manages the guest's entire page table.
```

Not necessarily.

HLAT has:

- an enable control,
- prefix/range logic,
- Restart bit for fallback,
- hypervisor-managed structures only for regions that need protection.

The goal is:

```text
protect selected sensitive translations
```

not replace the guest's entire memory manager.

If the hypervisor managed the full address space, the complexity and performance impact would be enormous.

## 60. Restart bit: the "escape hatch" mechanism

In HLAT paging, if a Restart bit is encountered:

```text
CPU stops the HLAT walk and returns to normal guest paging.
```

Think of the HLAT table as a firewall rule set:

```text
rule for a protected page: enforce via HLAT
rule for a normal page: restart/fall back to guest
```

This allows:

- only sensitive regions to be protected,
- no duplication of the full guest page tables,
- reduced overhead,
- maintained compatibility.

## 61. HLAT demo: why does "write succeed but value not change"?

In Tandasat's demo, the attacker still successfully modifies the guest PTE.

That is:

```text
the write primitive works
the guest PTE is replaced
```

But when reading `ci!g_CiOptions`, the value does not change.

Reason:

```text
the CPU no longer uses the guest PTE for that LA.
The CPU uses HLAT paging structures.
```

This is the signature of correct protection:

- no need to block writes to the guest PTE,
- only need to ensure that write does not affect the actual translation of the protected LA.

## 62. PW/PWA in more detail: why does hardware write to page tables?

During paging, the CPU does not only read page table entries. The CPU can also update Accessed/Dirty bits.

Accessed bit:

```text
the page/table entry has been used for an access
```

Dirty bit:

```text
the page has been written to
```

These bits help the OS manage memory:

- page replacement,
- working set,
- writeback,
- aging.

When the CPU page-walks through an entry, it may set the Accessed bit. When a write is made to a page, it may set the Dirty bit.

If hypervisor-managed HLAT page tables are marked EPT read-only, CPU hardware writes of A/D bits would also be blocked by EPT in the absence of PWA.

PWA says:

```text
guest software is not allowed to write,
but hardware paging writes are permitted.
```

## 63. How does PWA differ from EPT Write?

EPT Write:

```text
is any normal write to this GPA permitted?
```

PWA:

```text
is a write made by the hardware page-walk to update paging metadata permitted?
```

So an EPT entry can have:

```text
Write = 0
PWA   = 1
```

Meaning:

- guest code cannot store to the page table.
- the CPU page walker can still set A/D bits.

This is a very subtle distinction.

## 64. GPV in more detail: "the path taken" is also a security property

Not only the destination matters. The path taken matters too.

Without GPV:

```text
LA good -> approved page tables -> GPA X
LA evil -> attacker page tables -> GPA X
```

EPT only sees that the final destination is GPA X.

If GPA X allows read/write for some reason, EPT has no way to know which LA that access came from.

GPV lets the hypervisor declare:

```text
GPA X may only be accessed if the LA->GPA process traversed paging structures that have been marked approved.
```

The approved marker is PWA on the leaf EPT entries of paging-structure pages.

## 65. GPV illustrated as "main entrance / back door"

GPA X is the server room.

Two paths in:

- main entrance: camera, badge reader, guard,
- back door: opened by the attacker.

EPT only sees:

```text
someone entered the server room
```

GPV also asks:

```text
did this person pass through the approved main entrance?
```

If they came through the back door, deny access.

In paging terms:

- main entrance = approved page tables,
- back door = attacker-created alias page tables.

## 66. Why does GPV need PWA?

PWA marks the page-table pages that the hypervisor considers approved for translation.

When the VGP bit is set for the target GPA, the CPU checks:

```text
during LA->GPA, do the page-table pages have EPT leaf entries with PWA=1?
```

If not:

```text
EPT violation
```

So PWA is simultaneously a performance feature and a trust marker for GPV.

## 67. A clear comparison table

| Feature | What it blocks | How | Without it |
|---|---|---|---|
| EPT read-only | Direct write to a GPA | EPT Write=0 | attacker cannot write that page but can remap the LA |
| HLAT | Remap LA to a different GPA | uses hypervisor page tables for LA->GPA | guest PTE tampering changes the semantic of the LA |
| PWA/PW | VM-exits from hardware A/D updates | allows paging writes even with EPT Write=0 | HLAT page tables being read-only causes many VM-exits |
| GPV/VGP | Alias a GPA via a different LA/page tables | verifies that the translation path is approved | attacker accesses same GPA via an alias path |

## 68. Common misconceptions

Misconception 1:

```text
EPT read-only is sufficient to protect data.
```

Partially false. It protects the GPA from writes, but does not protect the LA from being remapped.

Misconception 2:

```text
Physical R/W bypasses all of HVCI/VBS.
```

False. It is very powerful against normal VTL0 memory, but VTL1/KDP/HLAT/SLAT protections can still block certain targets.

Misconception 3:

```text
HLAT is a new version of EPT.
```

Incorrect. EPT is GPA->PA. HLAT is LA->GPA.

Misconception 4:

```text
GPV is the same as HLAT.
```

No. HLAT replaces the source of translation. GPV verifies the provenance of the guest paging path.

Misconception 5:

```text
If you remap `g_CiOptions` to 0, you can load an unsigned driver.
```

Not certain, and in the article's demo it does not work. The secure kernel/VTL1 still checks and triggers a bugcheck.

## 69. A short mnemonic

```text
EPT  = protects the page.
HLAT = protects the virtual address mapping.
PW   = allows hardware to update page-table metadata without opening writes to the guest.
GPV  = protects the path to the page.
```

Or:

```text
EPT asks:  is this page allowed to be written?
HLAT asks: where must this address resolve to?
GPV asks:  which path did you take to reach this page?
PW asks:   is hardware allowed to update technical paging bits?
```

## 70. Relationship to a real exploit chain

Suppose an attacker has BYOVD virtual write such as `dbutil` or `RTCore64`.

Target 1: direct token swap.

```text
write EPROCESS.Token
```

VT-rp is not directly relevant if the token page is not protected.

Target 2: KDP-protected policy data.

```text
write policy LA
```

EPT blocks it.

Attacker tries:

```text
edit PTE(policy LA) -> fake GPA
```

Without HLAT:

- the semantic can be changed.

With HLAT:

- the guest PTE edit does not affect the protected LA.

Target 3: code page.

```text
remap code LA -> writable fake code page
```

Much harder due to HVCI/W^X/kCFG/CET and executable permissions.

## 71. Why does this article matter for modern Windows kernel exploitation?

Previously, exploit thinking was:

```text
arbitrary kernel write -> patch kernel/global/callback/token
```

After HVCI/KDP:

```text
arbitrary write, but target is EPT read-only
```

After remapping:

```text
do not write the target page, change the mapping
```

After VT-rp:

```text
hypervisor locks the mapping as well
```

This is the arms race:

```text
write primitive
-> data protection
-> translation attack
-> translation protection
```

## 72. Thought exercise 1: If you are the attacker

You have arbitrary kernel write in VTL0.

Target:

```text
SensitiveData at LA A
EPT says GPA X is read-only
```

You can try:

1. Write directly to LA A.
2. Modify the guest PTE for LA A to point to GPA Y.
3. Find an alias LA B that points to GPA X.
4. Patch the code that checks SensitiveData.

Self-assessment:

- Which approach is blocked by EPT?
- Which is remapping?
- Which is aliasing?
- Which is made harder by HVCI/kCFG/CET?
- Which does HLAT block?
- Which does GPV block?

Answers:

- 1 is blocked by EPT read-only.
- 2 is remapping; HLAT blocks it if LA A is protected.
- 3 is aliasing; GPV may block it if GPA X has VGP set and the path is not approved.
- 4 is a code attack; HVCI/W^X/kCFG/CET/PatchGuard make it difficult.

## 73. Thought exercise 2: If you are the hypervisor

You want to protect LA A.

Available tools:

- EPT Write=0 for GPA X.
- HLAT for LA A.
- PWA for HLAT paging structures.
- VGP for GPA X.

What do you choose?

Minimum:

```text
EPT Write=0
HLAT for LA A
```

To also prevent aliasing to the same GPA:

```text
VGP for GPA X
PWA on approved paging-structure pages
```

If HLAT paging structures are read-only:

```text
PWA to avoid VM-exits from hardware paging writes
```

## 74. Thought exercise 3: Relating to ASTRA64

You have ASTRA64 physical R/W.

You want to modify KDP-protected data.

Options:

1. Write directly to the protected physical page.
2. Modify the guest PTE to remap the LA to a different page.
3. Direct token DKOM instead of touching KDP.

Assessment:

- 1 may be blocked by EPT.
- 2 is remapping; blocked by HLAT if active.
- 3 avoids touching a protected KDP target, more practical if the goal is only LPE.

This is why direct token DKOM can still work even when KDP exists: it targets a different object.

## 75. Short glossary

| Term | Meaning |
|---|---|
| LA | Linear Address, essentially a virtual address on x64 |
| GPA | Guest Physical Address, physical from the guest's perspective |
| PA/HPA/SPA | true physical address of the host/machine |
| CR3 | pointer to the guest PML4 |
| PTE | page table entry |
| PFN | page frame number |
| EPT | Intel's second-level page table |
| EPTP | pointer to the EPT root |
| SLAT | second-level address translation |
| VBS | virtualization-based security |
| VTL0 | normal Windows kernel world |
| VTL1 | secure kernel world |
| HVCI | hypervisor-protected code integrity |
| KDP | kernel data protection |
| HLAT | hypervisor-managed linear address translation |
| HLATP | pointer to HLAT paging structures |
| PW/PWA | paging-write / paging-write access |
| GPV/VGP | guest-paging verification / verify guest paging bit |
| VMCS | Intel VM control structure |
| VM-exit | CPU exit from guest back to hypervisor |
| INVEPT | invalidate EPT translations |
| INVVPID | invalidate VPID-tagged translations |

## 76. Further reading, in order

1. Tandasat Part 1: remapping + HLAT.
2. Tandasat Part 2: PW + GPV.
3. Microsoft KDP article.
4. Fortinet DSE/KDP/remapping background.
5. Connor McGarr HVCI/kCFG exploit context.
6. Intel VT-rp community explanation.
7. Hypervisor-101-in-Rust to understand VMX/EPT through code.

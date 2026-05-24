# 01 - Paging and PTE Deep Dive

Based on Connor McGarr: https://connormcgarr.github.io/paging/

Ngay cap nhat: 2026-05-25

## 1. Tai sao paging la bai dau tien phai hoc

Trong Windows kernel exploitation, rat nhieu thu cuoi cung quay ve page table:

- SMEP hoi: kernel co dang execute user page khong?
- NX hoi: page nay executable khong?
- KASLR hoi: virtual address cua kernel image nam dau?
- Physical R/W hoi: virtual object nay nam o physical page nao?
- HVCI hoi: guest PTE co du de quyet dinh executable permission khong?
- KDP/VT-rp hoi: mapping nay co dang tro den dung protected physical page khong?
- KUSER_SHARED_DATA hoi: mot physical page co the co hai virtual mapping voi permission khac nhau khong?

Neu khong hieu paging, ta chi thay exploit nhu mot chuoi magic offsets. Neu hieu paging, ta thay cac mitigation chi la cac policy gan vao translation path.

## 2. Dia chi ao khong phai dia chi vat ly

Virtual address:

```text
fffff800`12345678
```

khong noi CPU "doc RAM offset 0xfffff80012345678". No noi CPU:

```text
Hay dung CR3 hien tai, page tables hien tai, translate dia chi nay thanh physical address.
```

Tai sao Windows can no?

- Moi process co address space rieng.
- Kernel co the map chung vao nhieu process.
- File/image/shared DLL co the share physical pages.
- Memory co the demand-paged.
- Page co permission rieng: read/write/execute/user/supervisor.
- Copy-on-write co the cho nhieu process nhin cung mot page den khi co write.

Exploit implication:

- Leak virtual pointer chua du neu primitive chi physical R/W.
- Physical R/W manh nhung can translation.
- Page permission co the thay doi exploit result ma khong doi pointer.

## 3. CR0, CR4, CR3: ba thanh ghi nen nam

### CR0.PG

Bit paging enable. Neu paging off, long-mode Windows khong chay nhu ta biet. Trong Windows x64 binh thuong paging on.

### CR4.PAE

PAE can cho 64-bit paging/long mode. Connor dung no de giai thich paging mode.

### CR3

Chua physical base cua PML4. Day la entry point cua page walk.

Quan trong: `CR3` la physical address. Neu dung physical memory read, co the doc PML4 ngay tu physical address trong CR3.

## 4. 4-level translation

Virtual address canonical 48-bit:

```text
| sign extend | PML4 | PDPT | PD | PT | page offset |
| 63......48  |47..39|38..30|29..21|20..12|11......0 |
```

Pseudo:

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

Neu large page:

- PDPTE large maps 1 GB.
- PDE large maps 2 MB.
- PT/PTE level bi skip.

Researcher mistake hay gap: viet page walker chi support 4 KB page. Kernel code/data co the nam trong large page tuy build/config. Page walker tot phai check large bit.

## 5. Canonical address va crash

Windows x64 address phai canonical. Neu bit 47 la 1, high bits phai la 1. Neu bit 47 la 0, high bits phai la 0.

Valid-looking kernel pointer:

```text
fffff800`abcd1234
```

Suspicious/non-canonical:

```text
0000f800`abcd1234
ffff0800`abcd1234
```

Trong exploit, validate pointer truoc khi dereference/write:

```text
is_kernel_canonical(ptr):
  ptr >= ffff8000`00000000
  ptr <  ffffffff`fffffff0
```

Day khong du de chung minh pointer valid, nhung loai bot rac.

## 6. PTE fields can biet

Mot PTE chua:

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
| Present | Page co resident/valid khong. Invalid access -> fault. |
| R/W | Kernel/user write co duoc cho phep tai guest PTE layer khong. |
| U/S | User vs supervisor. SMEP/SMAP quan tam bit nay. |
| NX | CPU co duoc fetch instruction tu page nay khong. DEP/NX quan tam bit nay. |
| Global | TLB behavior; kernel global mappings co the ton tai qua context switches. |

## 7. PFN la gi?

PFN = physical page number.

```text
physical_page_base = PFN * 0x1000
physical_address   = physical_page_base + offset
```

Connor dung WinDbg `!pte`/`!vtop` de cho thay PFN trong PTE duoc nhan voi `0x1000` thanh physical address.

Tai sao PFN quan trong voi BYOVD?

Driver physical map thuong can physical page base. Neu ban co PTE/PFN, ban co the noi driver map page do va doc/ghi offset.

## 8. PTE address vs physical page address

Hai thu khac nhau:

```text
PTE address:
  noi luu entry mo ta page

Physical page address:
  page ma entry do tro toi
```

Neu arbitrary write cua ban ghi vao PTE, ban doi mapping/permission.
Neu ghi vao physical page backing object, ban doi data cua object.

Vi du:

```text
EPROCESS.Token VA -> PTE -> PFN -> PA token field
```

Ghi vao PA token field: token changed.
Ghi vao PTE cua page chua EPROCESS: mapping/permission changed, risk cao hon.

## 9. Why PTE tamper bypassed old mitigations

Old mitigation:

- NX: page not executable.
- SMEP: page is user.

PTE tamper idea:

- Clear NX -> executable.
- Clear U/S -> supervisor.

Neu kernel then jumps to that page, CPU may allow it.

Nhung day la old model. Tren HVCI/VBS, guest PTE khong con la single source of truth. EPT/SLAT co the noi "khong execute" du guest PTE noi execute.

## 10. HVCI changes the PTE mental model

Khong HVCI:

```text
Guest PTE permission -> CPU permission mostly follows it.
```

Co HVCI:

```text
Guest PTE permission
  + EPT/SLAT permission
  + secure kernel code integrity policy
  -> actual execute/write behavior
```

Vi vay "toi da clear NX trong PTE" khong con du. Neu page khong duoc Code Integrity chap nhan la kernel executable code, HVCI co the van block.

Research conclusion:

- PTE tamper van la concept can hieu.
- Tren Windows 11 HVCI-on, PTE tamper khong nen la default route cho kernel code execution.
- Data-only hoac existing-code route thuc te hon.

## 11. Page table self-reference / PTE base idea

Windows co cac mechanism de map paging structures vao virtual address space, cho phep kernel tinh virtual address cua PTE tu virtual address can inspect.

Connor dung concept `MiGetPteAddress`.

Mental formula:

```text
PTE_for_VA = PteBase + ((VA >> 12) * 8)
```

Thuc te co canonical/sign-extension/mask details. Nhung idea la: VA co index vao PTE array. Neu co PTE base, co the tinh entry mo ta VA bat ky.

Exploit implication:

- Co kernel base + symbol/gadget -> tim PTE base helper.
- Co arbitrary read -> doc PTE.
- Co arbitrary write -> modify PTE.

Modern caveat:

- KASLR.
- Symbol/offset changes.
- HVCI/secure kernel.
- PatchGuard/PTE integrity expectations.

## 12. KUSER_SHARED_DATA as paging case study

`KUSER_SHARED_DATA` cho thay:

```text
One physical page
  -> static read-only mapping
  -> randomized writable mapping
```

Day la alias mapping. Cung backing physical memory, permission khac.

Bai hoc:

- Permission la theo mapping/PTE/EPT, khong chi theo physical page.
- Mot physical page co the co nhieu VA.
- Mitigation co the giu compatibility bang cach giu static read mapping nhung tao writable alias rieng.

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

Paging knowledge still matters because these features all attach to translation/control-flow, but the exploit cannot assume editing guest PTE is enough.

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


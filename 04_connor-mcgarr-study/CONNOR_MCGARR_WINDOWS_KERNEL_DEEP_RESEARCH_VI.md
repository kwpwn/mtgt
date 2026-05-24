# Connor McGarr Windows Kernel Exploit Research - Deep Vietnamese Study Notes

Ngay cap nhat: 2026-05-25

Pham vi:

- https://connormcgarr.github.io/paging/
- https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/
- https://connormcgarr.github.io/Kernel-Exploitation-2/
- https://connormcgarr.github.io/examining-xfg/
- https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
- https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-2/
- https://connormcgarr.github.io/kuser-shared-data-changes-win-11/
- https://connormcgarr.github.io/hvci/

Muc tieu cua file nay khong phai chep lai exploit code. Muc tieu la giai thich concept, cau hoi "vi sao", va cach mot Windows kernel researcher nen doc cac bai nay tren Windows hien tai: Windows 11 24H2/25H2 era, HVCI/VBS, kCFG, CET/shadow stack, KDP, WDAC driver blocklist.

## 0. Cach doc Connor cho dung

Connor viet theo style "exploit development learns internals". Nghia la moi bai khong chi noi mot bug. Moi bai dung bug nhu cai moc de day mot concept Windows:

- `paging`: vi sao virtual address khong phai physical address; vi sao PTE bit quyet dinh permission.
- `x64 Kernel Shellcode + SMEP`: vi sao token stealing cu can doi moi tren x64; vi sao SMEP giet ret2usr; vi sao PTE/CR4 tro thanh duong bypass.
- `Kernel Exploitation 2`: vi sao write-what-where la primitive nen tang; vi sao arbitrary write co the bien thanh control flow.
- `XFG`: vi sao CFG qua coarse; vi sao type-based CFI lam function pointer hijack kho hon.
- `Swimming in Kernel Pool`: vi sao pool exploitation hien dai la allocator research, leak engineering va object selection, khong phai chi "overflow la xong".
- `KUSER_SHARED_DATA changes`: vi sao mot static RW page tung la code cave tot, va Microsoft da doi design nhu the nao.
- `HVCI`: vi sao "khong code execution" khong co nghia la het exploit; exploit hien dai co the song bang data-only hoac existing signed code.

Mot cach doc dung:

```text
Bug class -> Primitive -> Missing capability -> Leak/translation/grooming -> Mitigation pressure -> Safer primitive selection
```

Vi du:

```text
Pool OOB read
  -> chi doc vuot bounds, chua co write
  -> can leak kernel pointer de bypass KASLR
  -> can groom pool de adjacent object co pointer huu ich
  -> sau leak moi ket hop pool overflow/write primitive
```

Day la tu duy quan trong: exploit la ghep capability, khong phai mot bug tu no da thanh SYSTEM.

## 1. Paging: tai sao moi thu bat dau tu dia chi ao

### 1.1 Cau hoi goc: virtual address la gi?

Khi debug kernel, ta hay thay pointer dang:

```text
fffff800`12345678
ffffa507`deadbeef
fffff780`00000000
```

Day khong phai dia chi RAM truc tiep. Day la linear/virtual address. CPU phai dich no qua paging structures de tim physical page that su.

Cau hoi vi sao:

- Vi sao phai co virtual memory?
- Vi sao moi process co view rieng?
- Vi sao cung mot `ntoskrnl` code co the map vao nhieu context?
- Vi sao attacker co kernel virtual address chua chac co physical address?
- Vi sao physical R/W driver nhu ASTRA64 can VA->PA translation?

Tra loi: virtual memory cho phep isolation, sharing, lazy allocation, paging-to-disk, copy-on-write, va permission rieng cho tung mapping. Moi access cua CPU qua virtual address phai duoc MMU translate theo page table hien tai.

### 1.2 x64 long mode paging

Connor nhan manh Windows x64 dung long-mode paging. 4-level paging co cac level:

```text
CR3 -> PML4 -> PDPT -> PD -> PT -> physical page
```

Virtual address 48-bit canonical duoc tach thanh:

```text
bits 47..39: PML4 index
bits 38..30: PDPT index
bits 29..21: PD index
bits 20..12: PT index
bits 11..0 : offset trong page 4 KB
```

Moi entry la 8 byte. Moi table co 512 entry. Do do:

- 1 PTE map 4 KB.
- 1 PDE co the map table 2 MB neu large page bit set.
- 1 PDPTE co the map 1 GB neu huge page bit set.

### 1.3 Canonical address: vi sao kernel address hay bat dau bang `ffff`

x64 classic khong dung ca 64 bit VA. Dia chi phai canonical: bit 47 duoc sign-extend len bit 63..48.

Neu bit 47 = 0:

```text
0000....
```

Thuong la user range.

Neu bit 47 = 1:

```text
ffff....
```

Thuong la kernel range.

Vi sao quan trong? Exploit phai validate pointer. Mot gia tri "nhin giong pointer" nhung khong canonical co the gay fault. Trong kernel exploit, sai pointer thuong la BSOD, khong phai exception de bat.

### 1.4 CR3 la gi?

`CR3` chua physical address cua PML4 base. Khong phai virtual address. Do la ly do mot physical-memory primitive co the page-walk neu biet CR3:

```text
CR3 physical PML4 base
  + index(PML4) * 8 -> PML4E
  PML4E.PFN * 0x1000 -> PDPT physical base
  + index(PDPT) * 8 -> PDPTE
  ...
```

Tu duy researcher:

- Neu co virtual kernel pointer va virtual R/W primitive: doc thang.
- Neu co physical R/W primitive: can CR3 + page walker.
- Neu can dich kernel global mapping: system/process CR3 thuong co kernel half shared, nhung VBS/KVA shadow/PCID/LA57/large page co the lam viec phuc tap hon.

### 1.5 PTE la "permission contract"

PTE khong chi chua PFN. No chua control bits:

- Present/Valid.
- Read/write.
- User/supervisor.
- Accessed.
- Dirty.
- NX/no-execute.
- Global.
- Large page bit o upper levels.

Day la concept noi Connor `paging` voi `SMEP bypass`.

Vi sao PTE quan trong?

- DEP/NX dua vao execute permission.
- SMEP dua vao user/supervisor bit khi kernel fetch instruction.
- SMAP dua vao user/supervisor bit khi kernel data access.
- HVCI chen them hypervisor/EPT enforcement ben duoi guest PTE.
- KDP dua vao stronger second-level permission cho selected data.

### 1.6 Vi du tu duy: co physical R/W, muon doc `_EPROCESS.Token`

Khong nen scan physical RAM may rui neu da co kernel virtual address.

Pipeline sach hon:

```text
1. Tim CR3 phu hop.
2. Co VA cua EPROCESS.
3. VA token field = EPROCESS + token_offset.
4. Page-walk VA -> PA.
5. Physical read/write PA.
```

Tai sao cach nay stable hon scan?

- Giam pham vi doc ghi.
- It cham nham MMIO/hole/protected range.
- Co the validate tung PTE.
- Neu translation fail, dung lai truoc khi write.

Lien he ASTRA64: day la ly do physical R/W manh nhung "chua thanh exploit" cho den khi co address discovery + translation.

## 2. Token stealing x64: vi sao van la baseline

### 2.1 Token la gi?

Windows dung access token de bieu dien security context:

- SID user/group.
- Privileges.
- Integrity level.
- Logon/session.
- Default DACL.

Moi process co `_EPROCESS.Token`. Tren x64, field nay thuong la `_EX_FAST_REF`, tuc pointer + low reference bits.

Vi sao token stealing hoat dong?

Neu process attacker co token cua `SYSTEM` process, access check sau do thay attacker process co security context SYSTEM.

Concept:

```text
System EPROCESS.Token -> copy pointer part -> Current EPROCESS.Token
```

### 2.2 Vi sao phai mask `_EX_FAST_REF`

Token field khong phai raw aligned pointer thuan. Low bits dung lam refcount/cache bits. Neu copy/compare khong mask, co the:

- So sanh sai.
- Ghi gia tri token co low bits khong mong muon.
- Lam reference semantics bat on.

Tu duy:

```text
token_object_pointer = Token & ~0xF
fast_ref_bits        = Token & 0xF
```

Khi copy token, nhieu PoC copy ca fast-ref value. Khi validate, nen compare pointer part.

### 2.3 Vi sao token stealing cu khong con la full answer tren Windows hien dai

Token stealing:

- Rat tot cho LPE local.
- Data-only, it dung code execution.
- It bi SMEP/kCFG/CET anh huong truc tiep.

Nhung han che:

- Can dung offset `_EPROCESS`.
- Token/PPL/LSA/EDR world co nhieu policy layer khac.
- Neu exploit goal la arbitrary kernel API, token stealing chua du.
- Tren mot so target, spawn SYSTEM shell khong phai muc tieu cuoi.
- Neu target field duoc KDP/protection nao do bao ve, write co the fail/crash.

Connor HVCI post vi vay moi chuyen sang "kernel API invocation bang existing code", khong chi token.

## 3. SMEP: vi sao ret2usr chet

### 3.1 SMEP chong cai gi?

SMEP = Supervisor Mode Execution Prevention.

Neu kernel mode dang chay va RIP tro vao page co U/S=user, CPU fault. Dieu nay chong pattern cu:

```text
Kernel bug controls RIP
  -> jump to user-mode shellcode
  -> run token stealing shellcode
```

Truoc SMEP, attacker co the allocate RWX user memory, dat shellcode, roi dieu khien kernel return vao do. Sau SMEP, kernel khong duoc execute user page nua.

### 3.2 SMEP khong chong cai gi?

SMEP khong chong:

- Kernel ROP using kernel code pages.
- Data-only token overwrite.
- Driver IOCTL tu ghi kernel memory.
- Process-kill BYOVD.
- Existing signed kernel code invocation.

Do do SMEP lam chet "execute user shellcode from kernel", khong lam chet "kernel arbitrary write".

### 3.3 Cac huong bypass SMEP o muc concept

Connor trinh bay hai huong lon:

1. Tat SMEP bang control register manipulation.
2. Sua PTE cua user page de no khong con duoc xem la user page, hoac chay payload tu kernel-executable memory.

Trong research hien dai, nen hieu chung nhu sau:

```text
SMEP checks: kernel fetch instruction from user page?
Bypass idea A: make CPU think SMEP off.
Bypass idea B: make page not-user/supervisor.
Bypass idea C: do not execute attacker page; use kernel code/data-only.
```

### 3.4 Tai sao tat SMEP bang CR4 la fragile

Can control flow trong kernel de ghi CR4. Thuong can ROP/gadget. ROP lai can:

- Kernel base leak.
- Gadget phu hop.
- Stack control.
- Khong bi CET/shadow stack chan.
- Khong bi HVCI policy phu lam chain vo nghia.
- Khong crash do IRQL/context sai.

Tren Windows hien tai, tat SMEP bang ROP la technique lich su tot de hoc, nhung khong phai duong stable nhat neu ban da co arbitrary kernel write. Data-only write thuong dep hon.

### 3.5 Tai sao PTE bit flipping la concept quan trong nhung kem hon tren HVCI

PTE bit flipping y tuong:

- Tim PTE cua user shellcode page.
- Clear U/S bit de page thanh supervisor.
- Hoac clear NX de executable.
- Kernel jump vao page.

Nhung HVCI/VBS chen second-level translation/permission. Guest PTE noi "executable" chua chac EPT/VBS cho execute. Memory Integrity co muc tieu lam kernel khong execute unsigned/unapproved page du chi guest PTE bi sua.

Vi vay tren Windows 11 HVCI-on:

```text
Guest PTE permission != final hardware permission policy
```

Tu duy hien dai: PTE tamper la nen tang de hieu paging, nhung exploit chain tot nen tranh can unsigned code execution neu HVCI on.

## 4. Write-What-Where: primitive quan trong nhat

### 4.1 WWW la gi?

Write-what-where:

```text
*Where = What
```

Attacker dieu khien:

- Gia tri ghi.
- Dia chi dich.

No co the la:

- 1 byte write.
- 4 byte write.
- 8 byte write.
- arbitrary length copy.
- decrement/increment primitive.
- masked write.

### 4.2 Vi sao WWW khong tu dong thanh exploit

Can tra loi:

- Ghi duoc vao kernel VA hay chi physical?
- Can bypass KASLR khong?
- Write co aligned khong?
- Write co repeatable khong?
- Write co crash neu target page read-only/protected khong?
- Target field co PatchGuard/KDP/kCFG/CET lien quan khong?
- Co read primitive de validate truoc/sau khong?

Mot arbitrary write khong co read primitive giong nhu phau thuat trong bong toi. Van co the lam duoc neu target/range rat chac, nhung BSOD risk cao.

### 4.3 Old-school target: HalDispatchTable

Trong bai arbitrary overwrite cu, Connor dung `HalDispatchTable` nhu mot target de chuyen write primitive thanh control-flow hijack.

Y tuong lich su:

```text
Overwrite function pointer/global dispatch entry
Trigger legitimate kernel path that calls it
Control RIP
Run payload/ROP
Restore if needed
```

Tren Windows hien dai, target nay khong nen duoc xem la "duong mac dinh":

- PatchGuard co the monitor global dispatch tamper.
- kCFG co the chan invalid indirect call target.
- HVCI chan unsigned shellcode.
- CET chan return-oriented follow-up neu chain dua vao return corruption.
- Symbol/export/offset changes lam technique fragile.

Gia tri cua bai nay la hoc primitive transformation:

```text
arbitrary write -> overwrite sensitive pointer -> trigger -> code execution
```

Khong phai hoc mot target cu nhu cong thuc vinh vien.

### 4.4 Modern target selection

Neu co WWW tren Windows 11, researcher nen uu tien:

1. Data-only target co tac dong ro.
2. Target per-object thay vi global.
3. Target co the restore.
4. Target it bi PatchGuard.
5. Target khong can unsigned code execution.

Vi du concept:

- `_EPROCESS.Token`
- `_KTHREAD.PreviousMode`
- object access mask / handle table metadata trong lab
- callback enable flags neu hieu ro PatchGuard risk
- driver-owned object state neu exploit mot driver cu the

Khong nen mac dinh:

- SSDT hook.
- IDT/GDT hook.
- inline patch `ntoskrnl`.
- syscall MSR hijack.

Nhung thu do "ngau" hon, nhung kem stable hon.

## 5. Paging + SMEP + WWW: ghep ba bai lai

Ba bai `paging`, `SMEP bypass`, `WWW` ghep thanh mot chain thinking:

```text
1. Kernel bug gives arbitrary write.
2. Need know where to write -> KASLR leak.
3. Need know page permission model -> PTE.
4. Need defeat SMEP/NX if executing payload.
5. Or avoid execution entirely -> data-only DKOM.
```

Day la ly do paging khong phai kien thuc "theory". No quyet dinh:

- Co the dich VA->PA khong.
- Co the tim PTE khong.
- Co the hieu NX/U/S/RW bits khong.
- Co the hieu vi sao HVCI lam PTE tamper khong con du khong.
- Co the hieu KUSER_SHARED_DATA mapping doi ra sao khong.

## 6. XFG: tai sao CFG chua du

### 6.1 CFG giai quyet van de gi?

CFG = Control Flow Guard.

Muc tieu: khi program thuc hien indirect call/jump, target phai nam trong tap target hop le.

Vi du:

```text
call [function_pointer]
```

Neu attacker overwrite function pointer thanh dia chi bat ky giua gadget, CFG co the chan.

### 6.2 Diem yeu cua CFG

CFG coarse-grained. Neu target la mot function hop le trong CFG bitmap, call co the qua du function do khong phai prototype mong muon.

Problem:

```text
Expected: void callback(Context*)
Attacker target: ValidExportedFunction(...)
CFG says: target valid
Program semantics: broken / abusable
```

Noi ngan gon: CFG hoi "dia chi nay co phai target hop le khong?", chua hoi "co dung loai ham ma callsite mong doi khong?"

### 6.3 XFG them cai gi?

XFG = eXtended Flow Guard.

Connor giai thich XFG la type-based CFI layer tren CFG:

- Compiler tinh hash dua tren function prototype.
- Hash nam gan function target.
- Callsite/dispatch so sanh expected hash voi target hash.
- Neu mismatch -> crash/fail.

No hoi them:

```text
Target co hop le khong?
Target co dung type/prototype khong?
```

### 6.4 Vi sao XFG manh hon CFG

Neu attacker overwrite function pointer tu:

```text
void A(void)
```

sang:

```text
int B(int, int)
```

CFG co the cho qua neu `B` la valid target. XFG se thay prototype hash mismatch.

Tu duy exploit:

- CFG bypass: tim target hop le trong bitmap.
- XFG bypass: tim target hop le va cung compatible type hash.

Khong gian target bi thu hep rat nhieu.

### 6.5 XFG con diem mo nao?

Connor neu hai huong concept:

1. Function cung prototype co hash giong nhau.
2. Ve ly thuyet co the tim pattern/hash-compatible target dac biet, nhung kho va it huu dung.

Quan trong hon: XFG la forward-edge mitigation. No khong bao ve return address. Connor ket luan phai ket hop XFG voi CET/shadow stack.

```text
XFG/kCFG: indirect calls/jumps
CET shadow stack: returns
```

### 6.6 XFG lien quan gi den kernel?

Bai XFG cua Connor chu yeu user-mode/compiler CFI. Nhung concept ap vao kernel:

- kCFG cung danh vao forward-edge indirect call.
- Driver callback/function pointer overwrite se gap CFI pressure.
- Neu target la return address/ROP, kCFG/XFG khong phai mitigation chinh; CET/shadow stack moi la mitigation chinh.

Windows hien tai:

- kCFG co y nghia lon trong kernel.
- Kernel-mode hardware-enforced stack protection tren Windows 11 2022 Update+ voi hardware/VBS/HVCI prerequisites la huong chong ROP.
- XFG concept cho thay Microsoft dang di tu coarse CFI -> type-aware CFI -> hardware-backed CFI.

## 7. Kernel pool: vi sao "pool overflow" hien dai kho

### 7.1 Pool la gi?

Kernel pool la allocator cho kernel/driver dynamic memory.

Hai loai hay gap:

- PagedPool: co the page out, khong dung o IRQL cao.
- NonPagedPool/NonPagedPoolNx: luon resident, dung cho path can memory always present.

Chunk thuong co metadata/header. Tren x64, old `_POOL_HEADER` la concept quan trong. Segment heap/kLFH thay doi chi tiet allocator.

### 7.2 Vi sao NonPagedPoolNx thay doi exploit

Old thinking:

```text
Overflow pool -> place shellcode nearby -> jump
```

Modern thinking:

```text
Overflow pool -> corrupt adjacent object -> leak/write/control data/control flow
```

Vi sao? Pool memory NX, HVCI, SMEP, kCFG, CET deu lam "nhay vao bytes cua minh" kho hon.

### 7.3 kLFH va segment heap: vi sao grooming can thiet

Connor tap trung kLFH. kLFH co bucket theo size. Muc tieu exploitation:

- Dua vulnerable chunk vao bucket co the du doan.
- Dat object attacker-controlled ngay truoc/sau.
- Tao "hole" bang allocate/free pattern.
- Dat object co pointer/function pointer/data target vao hole.

Nhung vi sao kho?

- Kernel co nhieu allocator activity khac.
- Adjacent object phai cung size class/pool type.
- Object phai co field huu ich.
- Header invalid co the crash.
- Segment heap co metadata encoding/hardening.
- Timing/concurrency lam layout khong deterministic.

### 7.4 OOB read trong pool: vi sao leak quan trong

Part 1 cua Connor dung OOB read de leak adjacent pool memory. Tu OOB read co the:

- Leak kernel pointer.
- Bypass KASLR.
- Tim object layout.
- Lay cookie/metadata trong mot so case.
- Chuan bi cho write primitive.

Vi sao low integrity/AppContainer angle quan trong?

Low integrity bi han che cac API leak kernel base nhu `EnumDeviceDrivers`/`NtQuerySystemInformation` trong mot so context/version/policy. Do do info leak tu kernel bug tro thanh de-facto KASLR bypass.

### 7.5 Pool grooming bang Windows objects

Connor dung object co the allocate tu user mode de tac dong layout. Concept chung:

```text
Spray many same-size objects
Enable/fill kLFH bucket
Free selected objects to make holes
Allocate target/vulnerable object into predictable position
Trigger OOB read/overflow
```

Researcher questions:

- Object size co match vulnerable allocation khong?
- Object pool type co match khong?
- Object lifetime co control bang handle khong?
- Object co leak pointer huu ich khong?
- Object co field co the bien thanh arbitrary read/write khong?
- Closing handle co free chunk dung luc khong?

### 7.6 Part 2: tu pool overflow den arbitrary read/write

Part 2 tiep tuc y tuong: leak + grooming + overflow de tao primitive manh hon. Gia tri can hoc:

- Pool overflow hien dai thuong can multi-stage.
- Stage 1 leak KASLR/object.
- Stage 2 groom layout.
- Stage 3 corrupt object.
- Stage 4 dung corrupted object de read/write.
- Stage 5 dung R/W cho final goal.

Final goal khong nhat thiet la shellcode. Tren Windows hien tai, final goal tot hon la:

- Data-only privilege change trong lab.
- Controlled kernel API invocation bang existing code.
- Tamper driver-owned state.
- Tamper security tool object/state neu dang research defense.

### 7.7 Vi sao object selection la skill chinh

Pool exploit thanh cong khong phai do overflow "manh". No do object bi overflow vao co semantic tot.

Object tot:

- Allocatable from low privilege.
- Same pool type/size.
- Lifetime controllable.
- Contains pointer/length/list/function pointer.
- Has operation that can be triggered later.
- Corruption produces read/write, not immediate crash.

Object xau:

- Size khong match.
- Free path validate header/cookie manh.
- Corrupt mot bit la crash.
- Trigger path hiem/IRQL kho.
- PatchGuard/kCFG/CET pressure cao.

## 8. KUSER_SHARED_DATA: vi sao mot static page lai quan trong

### 8.1 KUSER_SHARED_DATA la gi?

`KUSER_SHARED_DATA` la shared page map vao user/kernel de expose data can doc nhanh:

- system time
- tick count
- version/build info
- processor/features flags
- mitigation-related flags trong mot so build

Dia chi kernel static noi tieng:

```text
fffff780`00000000
```

User-mode mirror historically:

```text
00000000`7ffe0000
```

### 8.2 Vi sao attacker thich KUSER_SHARED_DATA code cave

Theo Connor, cau truc chi dung mot phan page. Phan con lai trong cung 4 KB page tung co permission RW va static address. Neu page co the execute/duoc kernel access theo cach nao do, no la static cave rat hap dan:

- Khong can KASLR cho dia chi.
- Co dia chi co dinh tren moi boot.
- Co the ghi data/payload vao offset trong page.

Nhung day chinh la ly do Microsoft phai thay doi.

### 8.3 Windows 11 thay doi gi?

Connor quan sat tren Windows 11 Insider luc do:

- Static `KUSER_SHARED_DATA` van o dia chi cu.
- Nhung mapping static tro thanh read-only.
- Windows tao mot mapping khac, randomized va writable: `nt!MmWriteableUserSharedData`.
- Ca hai mapping back cung physical memory, nhung permission khac nhau.

Mental model:

```text
Static mapping:
  VA fixed, read-only, used for readers.

Writable kernel mapping:
  VA randomized, read/write, used by kernel update paths.

Same underlying data/physical backing, different virtual mappings.
```

### 8.4 Vi sao khong chi randomize static address?

Static address co compatibility value. Nhieu code/user/kernel assumptions co the doc shared data o dia chi quen thuoc. Neu randomize thang static mapping, co the gay compatibility break.

Thay vao do Microsoft tach:

- Dia chi doc van static.
- Ghi qua mapping rieng randomized.
- Static code cave/RW abuse bi giam.

Day la mitigation engineering rat Windows: giam attack surface trong khi giu compatibility.

### 8.5 Bai hoc exploit

Neu ban thay mot static address:

- Dung hoi "co static khong?" thoi.
- Hoi "permission hien tai la gi?"
- Hoi "co alias mapping khac khong?"
- Hoi "physical backing co shared khong?"
- Hoi "mapping writable nam dau, co KASLR khong?"
- Hoi "HVCI/KDP/EPT co permission rieng khong?"

KUSER_SHARED_DATA la case study ve mapping alias + permissions, rat lien quan den VT-rp/HLAT/KDP.

## 9. HVCI: vi sao "No Code Execution? No Problem"

### 9.1 HVCI chong cai gi?

HVCI/Memory Integrity dung VBS de dua kernel code integrity vao isolated environment. Muc tieu:

- Kernel khong duoc execute unsigned/untrusted code.
- Writable page khong tu nhien thanh executable.
- Guest kernel PTE tamper khong du de pha code integrity.

Nhu Microsoft mo ta, Memory Integrity la VBS feature, Code Integrity chay trong isolated virtual environment.

### 9.2 HVCI khong chong cai gi?

HVCI khong tu dong chong:

- Arbitrary write vao mutable data.
- Token DKOM.
- Process-kill driver IOCTL.
- Driver da signed va allowed nhung co IOCTL nguy hiem.
- Logic bug trong signed kernel code.
- Existing-code invocation neu khong vi pham code integrity.

Day la core cua Connor HVCI post.

### 9.3 Tai sao shellcode/PTE trick fail hon tren HVCI

Truoc HVCI:

```text
Have arbitrary write
  -> modify PTE NX/U/S/RW
  -> jump to attacker bytes
```

HVCI era:

```text
Guest PTE says executable
  but hypervisor/secure CI policy may still say no
```

Noi cach khac: page table cua VTL0 khong con la source of truth duy nhat ve executable kernel code.

### 9.4 Connor chain: arbitrary R/W -> existing kernel code invocation

Connor dat cau hoi:

Neu khong duoc execute shellcode, co the bat kernel execute code san co theo y minh khong?

Huong:

- Tao dummy thread.
- Leak `KTHREAD`.
- Tim kernel stack cua dummy thread.
- Tim return address phu hop tren stack.
- Ghi ROP chain vao kernel stack.
- Resume thread de chain chay existing signed kernel code.

Tai sao dung dummy thread?

- Co thread rieng de manipulate.
- Co kernel stack rieng.
- Co lifecycle control hon.
- Giam anh huong den thread exploit chinh.
- Co the cleanup bang terminate thread path.

Tai sao day HVCI-compliant?

- Khong execute attacker-supplied bytes.
- Chi return vao code pages hop le da signed/executable.
- HVCI khong cam reuse existing executable code.

### 9.5 kCFG anh huong chain nhu the nao?

kCFG chan forward-edge indirect call. ROP bang return address la backward-edge. Vi vay:

```text
overwrite function pointer -> kCFG relevant
overwrite return address -> CET/shadow stack relevant
```

Connor dung return-oriented path de tranh kCFG issue.

### 9.6 Vi sao CET/kernel shadow stack la blocker tu nhien

Kernel-mode hardware-enforced stack protection dung shadow stack:

- CALL push return vao normal stack va shadow stack.
- RET compare normal return voi shadow return.
- Neu mismatch -> fault/bugcheck.

Neu exploit ghi return address tren normal kernel stack ma khong update shadow stack, RET mismatch.

Do do tren Windows hien tai:

- HVCI on: shellcode/PTE trick kho.
- kCFG on: function pointer hijack kho.
- CET kernel shadow stack on: return-address ROP kho.

Neu ca ba cung on, exploit nen chuyen sang:

- data-only primitive,
- legitimate kernel API path,
- logic/policy abuse,
- driver-specific semantics,
- object state corruption khong can control-flow hijack.

## 10. Current Windows 11 thinking: 24H2/25H2 era

Tinh den 2026-05-25, khi noi "Windows hien tai", phai coi Windows 11 24H2/25H2 servicing era voi cac option/hardware-dependent features:

- VBS/HVCI supported broadly; HVCI default depends clean install/OEM/hardware/policy.
- Windows 11 22H2+ warning/UI/default posture cho Memory Integrity tot hon.
- Microsoft vulnerable driver blocklist enabled by default on Windows 11 22H2+ per Microsoft docs/support.
- Kernel-mode hardware-enforced stack protection requires Windows 11 2022 Update+, supported hardware, VBS and HVCI.
- KDP exists but selective.
- CET/shadow stack deployment is hardware/config/compatibility dependent.

Do do khong duoc viet:

```text
Windows 11 bypassed
```

Phai viet:

```text
Windows 11 build X, VBS Y, HVCI Z, blocklist state, CET state, driver policy state, CPU capability.
```

### 10.1 Neu HVCI off

Nhieu technique cu van co gia tri:

- PTE tamper co the kha thuc te hon.
- SMEP bypass bang CR4/PTE/ROP co the duoc lab lai.
- Pool shellcode van bi NX/SMEP can tro nhung it hypervisor pressure hon.

Nhung PatchGuard/kCFG/SMEP/KASLR van la van de.

### 10.2 Neu HVCI on, CET off

Connor HVCI-style existing-code ROP tro nen concept quan trong:

- Shellcode khong nen la final plan.
- ROP/API invocation bang signed code co the la huong.
- kCFG buoc tranh indirect call hijack hoac dung valid target.
- Return stack overwrite van kha thi ve concept neu shadow stack khong enforce.

### 10.3 Neu HVCI on, CET kernel shadow stack on

Return-address ROP gap blocker lon. Khi do:

- Data-only attack tro nen hap dan nhat.
- Process-kill BYOVD van nguy hiem neu driver load duoc.
- Physical/virtual R/W target mutable data van nguy hiem.
- Logic bug/semantic abuse trong signed driver van nguy hiem.
- Control-flow exploit can more advanced call-oriented/data-oriented route.

### 10.4 Neu vulnerable driver blocklist/WDAC strict

BYOVD bi chan o load layer:

- Driver known-bad khong load.
- Hash/cert/rule matched driver bi block.
- Attack phai tim driver moi/chua listed/already-loaded/policy gap.

Day la mitigation "dung lop" cho BYOVD hon HVCI.

## 11. Bypass taxonomy: noi dung nen hieu, khong nen thuoc long payload

### 11.1 Bypass KASLR

Goal: tim base cua `ntoskrnl`/driver.

Classes:

- Legit API leak in permissive context.
- Out-of-bounds read leak.
- Pool object pointer leak.
- MSR `IA32_LSTAR` read anchor.
- Physical memory scan with PE validation.
- Loaded module list read if primitive allows.

Modern pressure:

- Low integrity/AppContainer bi han che API leak.
- HVCI khong chong leak truc tiep.
- KASLR mot khi co read primitive thuong sup.

### 11.2 Bypass SMEP

Classes:

- Disable SMEP via CR4 write using ROP/gadget.
- PTE U/S manipulation.
- Execute code from supervisor executable mapping.
- Avoid execution: data-only.
- Existing code reuse.

Modern pressure:

- HVCI lam executable permission tamper kho hon.
- CET lam ROP kho hon.
- Data-only la duong on dinh hon neu primitive cho phep.

### 11.3 Bypass NX/NonPagedPoolNx

Classes:

- ROP/JOP.
- Clear NX if no HVCI/second-level block.
- Corrupt object data instead of execute pool.
- Reuse existing code.

Modern pressure:

- HVCI blocks making arbitrary bytes executable.
- Pool exploitation nen huong object corruption.

### 11.4 Bypass CFG/kCFG

Classes:

- Use valid call target.
- Same-prototype/XFG-compatible target where applicable.
- Avoid forward-edge hijack.
- Use return-address path if CET absent.
- Data-only.

Modern pressure:

- XFG narrows target set by type hash.
- CET protects returns.

### 11.5 Bypass HVCI

Nen noi chinh xac: nhieu "HVCI bypass" khong pha HVCI. Chung tranh guarantee cua HVCI.

Classes:

- Data-only corruption.
- Existing signed code reuse.
- Abuse signed vulnerable driver IOCTL.
- Target mutable VTL0 data not protected by KDP.
- Avoid unsigned kernel code execution entirely.

Modern pressure:

- CET kills many ROP paths.
- KDP protects selected data.
- WDAC/blocklist kills known vulnerable drivers.

### 11.6 Bypass KDP

KDP selective. Conceptual routes:

- Target data not protected by KDP.
- Abuse legitimate writer path.
- Remapping/page-swapping class attacks if platform protection incomplete.
- Attack adjacent policy/logic rather than protected field.

Modern pressure:

- VT-rp/HLAT direction explicitly aims at remapping/page-table tricks.
- Stronger VBS policy reduces "just write physical" assumption.

## 12. How to read each Connor article like a researcher

### 12.1 Paging article checklist

Ask:

- Which address space am I in?
- What is CR3?
- Is VA canonical?
- Is the page 4 KB, 2 MB, or 1 GB?
- Which PTE bits matter?
- Is final permission controlled only by guest PTE or also EPT/VBS?
- If I have physical R/W, how do I validate translation?

### 12.2 SMEP article checklist

Ask:

- Is the chain executing user memory?
- Is SMEP actually on?
- Is HVCI on?
- Is CET shadow stack on?
- Is code execution required, or can I do data-only?
- Is PTE tamper enough on this machine?

### 12.3 WWW article checklist

Ask:

- What is write width?
- Can I read back?
- Is target address stable?
- Is target global or per-object?
- Is PatchGuard likely?
- Can I restore?
- Is the final effect deterministic?

### 12.4 XFG article checklist

Ask:

- Is this forward-edge or backward-edge control flow?
- Is target in CFG bitmap?
- Is target prototype-compatible?
- Is XFG enabled for this binary?
- Is kernel equivalent kCFG involved?
- Would CET be the real blocker instead?

### 12.5 Pool articles checklist

Ask:

- Which allocator path: kLFH, VS, large?
- Pool type?
- Chunk size including header?
- Adjacent object controllable?
- Object lifetime controllable?
- Leak before write?
- Header/cookie/encoding concerns?
- Version-specific allocator behavior?

### 12.6 KUSER_SHARED_DATA checklist

Ask:

- Static VA still exists?
- Permission of static mapping?
- Is there a writable alias?
- Is alias randomized?
- Same physical backing?
- Can physical R/W affect both views?
- Does KDP/VBS protect it?

### 12.7 HVCI checklist

Ask:

- Does chain execute new code?
- Does chain only reuse existing code?
- Is kCFG relevant?
- Is CET/shadow stack running?
- Is target data KDP-protected?
- Is vulnerable driver blocked?
- Can same goal be done data-only?

## 13. Relation to your ASTRA64 direct DKOM chain

Your ASTRA64 approach:

```text
ASTRA64 physical map
  -> read MSR LSTAR
  -> find ntoskrnl base
  -> find system CR3
  -> page-walk VA to PA
  -> locate EPROCESS list
  -> write SYSTEM token into current EPROCESS token field
  -> spawn child
  -> restore token
```

Theo Connor mental model, chain nay:

- Dung paging knowledge de bridge physical primitive -> virtual kernel object.
- Dung KASLR anchor tu MSR/ntoskrnl base.
- Tranh SMEP vi khong execute user page.
- Tranh HVCI vi khong inject unsigned kernel code.
- Tranh kCFG/XFG vi khong hijack indirect call.
- Tranh CET vi khong overwrite return address.
- Van co risk voi KDP/protected data neu target duoc protect trong future.
- Van phu thuoc driver load policy/blocklist.
- Van phu thuoc offset `_EPROCESS` dung build.

Day la ly do data-only DKOM rat practical trong BYOVD world.

Nhung no khong phai "bypass all mitigations". No la "select a goal that most mitigations do not directly cover".

## 14. Questions a senior researcher would keep asking

Khi thay mot bypass, dung hoi "co chay khong?" truoc. Hoi:

1. Primitive toi thieu la gi?
2. Can read khong, hay write-only du?
3. Can kernel base leak khong?
4. Can object pointer leak khong?
5. Can code execution khong?
6. Neu can code execution, code cua ai?
7. Neu dung ROP, CET co bat khong?
8. Neu dung function pointer, kCFG/XFG co bat khong?
9. Neu ghi data, data co duoc KDP protect khong?
10. Neu dung driver, driver co load duoc khong?
11. Neu write sai, crash ngay hay silent corruption?
12. Co restore duoc khong?
13. Technique co version-sensitive khong?
14. Offset lay tu dau?
15. IRQL/context co dung khong?
16. Co race/concurrency window khong?
17. Co can global patch khong?
18. PatchGuard co the thay khong?
19. Neu target Windows 11 24H2/25H2, exact mitigation state la gi?
20. Neu chain "bypass HVCI", no pha HVCI hay ne HVCI?

## 15. Suggested file split for next research

File nay la master map. Nen tach tiep thanh cac deep-dive rieng:

- `01_PAGING_AND_PTE_DEEP_DIVE.md`
- `02_SMEP_NX_PTE_BYPASS_CONCEPTS.md`
- `03_WRITE_WHAT_WHERE_TARGET_SELECTION.md`
- `04_POOL_EXPLOITATION_KLFH_SEGMENT_HEAP.md`
- `05_KUSER_SHARED_DATA_MAPPING_CHANGES.md`
- `06_CFG_XFG_KCFG_CET_CONTROL_FLOW.md`
- `07_HVCI_EXISTING_CODE_INVOCATION.md`

## 16. Sources

- Connor McGarr - Paging: https://connormcgarr.github.io/paging/
- Connor McGarr - x64 Kernel Shellcode Revisited and SMEP Bypass: https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/
- Connor McGarr - Kernel Exploitation: Arbitrary Overwrites: https://connormcgarr.github.io/Kernel-Exploitation-2/
- Connor McGarr - Examining XFG: https://connormcgarr.github.io/examining-xfg/
- Connor McGarr - Swimming in the Kernel Pool Part 1: https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-1/
- Connor McGarr - Swimming in the Kernel Pool Part 2: https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-2/
- Connor McGarr - KUSER_SHARED_DATA Windows 11 changes: https://connormcgarr.github.io/kuser-shared-data-changes-win-11/
- Connor McGarr - HVCI/kCFG: https://connormcgarr.github.io/hvci/
- Microsoft Learn - Memory Integrity / HVCI: https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity
- Microsoft Learn - Kernel-mode Hardware-enforced Stack Protection: https://learn.microsoft.com/en-us/windows-server/security/kernel-mode-hardware-stack-protection
- Microsoft Learn - Windows 11 silicon-assisted security: https://learn.microsoft.com/en-us/windows/security/book/hardware-security-silicon-assisted-security
- Microsoft Learn - CFG compiler option: https://learn.microsoft.com/en-us/cpp/build/reference/guard-enable-control-flow-guard


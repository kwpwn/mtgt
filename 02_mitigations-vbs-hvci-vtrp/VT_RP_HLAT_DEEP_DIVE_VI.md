# Intel VT-rp, HLAT, EPT, KDP - Deep Dive bằng tiếng Việt

Nguồn chính:

- Satoshi Tanda, Intel VT-rp Part 1: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html
- Satoshi Tanda, Intel VT-rp Part 2: https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html
- Sample hypervisor/course: https://github.com/tandasat/Hypervisor-101-in-Rust
- Microsoft KDP: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Fortinet DSE/KDP/remapping context: https://www.fortinet.com/blog/threat-research/driver-signature-enforcement-tampering
- Connor McGarr HVCI/kCFG context: https://connormcgarr.github.io/hvci/
- Andrea Allievi Alder Lake features: https://www.andrea-allievi.com/blog/alder-lake-and-the-new-intel-features/
- Intel HLAT reference page: https://edc.intel.com/content/www/us/en/design/products/platforms/details/raptor-lake-s/13th-generation-core-processors-datasheet-volume-1-of-2/005/hypervisor-managed-linear-address-translation/
- Intel VT-rp community explanation: https://community.intel.com/t5/Blogs/Tech-Innovation/Client/Intel-Virtualization-Technology-Redirect-Protection-Intel-VT-rp/post/1672593

## 1. Một câu tóm tắt toàn bộ bài

Bài của Tandasat giải thích một vấn đề rất cụ thể:

```text
Hypervisor dùng EPT để làm kernel data read-only.
Attacker có kernel R/W vẫn có thể sửa page table của guest để "đổi đường" linear address sang một physical page khác.
Đó là remapping attack.
Intel VT-rp, đặc biệt HLAT, sinh ra để khóa cả quá trình LA -> GPA translation, không chỉ khóa GPA -> PA permission.
```

Nói ngắn hơn:

```text
EPT bảo vệ "physical page này không được ghi".
Remapping attack né bằng cách làm "địa chỉ ảo cũ trỏ sang physical page khác".
HLAT cho hypervisor quyền quyết định địa chỉ ảo đó phải trỏ tới physical page nào.
```

## 2. Các tầng địa chỉ: LA, GPA, PA

Bài dùng ba khái niệm:

| Viết tắt | Tên | Ý nghĩa |
|---|---|---|
| LA | Linear Address | Địa chỉ mà code trong guest/OS nhìn thấy sau segmentation, trước paging. Trên x64 gần như chính là virtual address. |
| GPA | Guest Physical Address | "Physical address" theo góc nhìn của guest OS. Windows kernel nghĩ đây là RAM thật. |
| PA / HPA / SPA | Host/System Physical Address | Physical address thật trên máy host, do hypervisor/EPT quản lý. |

Nếu không có virtualization:

```text
LA -> PA
```

Nếu có EPT/SLAT:

```text
LA -> GPA -> PA
```

Trong VMX non-root mode, guest OS tự quản lý bước:

```text
LA -> GPA
```

Hypervisor quản lý bước:

```text
GPA -> PA
```

## 3. Paging truyền thống: LA -> physical

Trên x64 4-level paging:

```text
CR3 -> PML4 -> PDPT -> PD -> PT -> page frame
```

Virtual address được tách thành index:

```text
bits 47..39 = PML4 index
bits 38..30 = PDPT index
bits 29..21 = PD index
bits 20..12 = PT index
bits 11..0  = offset trong page
```

Ví dụ:

```text
LA = fffff8024b082004
```

CPU dùng CR3 để tìm page table, đi qua PML4E/PDPTE/PDE/PTE, cuối cùng lấy PFN và cộng offset `0x004`.

Nếu PTE chứa PFN `0x11ceaa`, thì:

```text
GPA = 0x11ceaa000 + 0x004 = 0x11ceaa004
```

## 4. EPT / SLAT là gì?

EPT là Intel Extended Page Table. Nó là dạng SLAT: Second Level Address Translation.

Guest Windows nghĩ:

```text
GPA 0x11ceaa004 là physical RAM
```

Nhưng thật ra khi chạy dưới hypervisor, CPU còn đi thêm một bước:

```text
GPA 0x11ceaa004 -> real PA/HPA nào đó
```

EPT entry có permission riêng:

- Read
- Write
- Execute
- memory type
- accessed/dirty
- các bit mở rộng khác

Điểm mạnh:

```text
Guest kernel dù có ring 0 cũng không sửa được EPT.
```

Chỉ hypervisor có quyền quản lý EPT.

## 5. Tại sao EPT giúp bảo vệ kernel?

Nếu hypervisor muốn bảo vệ một page chứa dữ liệu nhạy cảm, nó có thể đặt EPT permission:

```text
GPA chứa sensitive data: Read = 1, Write = 0
```

Kể cả attacker có kernel arbitrary write trong guest:

```text
write vào LA -> guest paging ra GPA được bảo vệ -> EPT chặn write
```

Đó là nền tảng của:

- HVCI: bảo vệ code integrity, kernel code không writable.
- KDP: bảo vệ kernel data, data nhạy cảm không writable từ VTL0.

Microsoft KDP nói rõ KDP dùng VBS/SLAT để làm memory read-only từ góc nhìn VTL0.

## 6. VBS, VTL0, VTL1

Trong Windows VBS:

| Layer | Ý nghĩa |
|---|---|
| VTL0 | Normal Windows kernel, drivers, user mode bình thường |
| VTL1 | Secure kernel / isolated trustlets |
| Hypervisor | Quản lý isolation bằng SLAT/EPT |

Attacker có kernel R/W thường chỉ ở VTL0.

KDP/HVCI cố gắng nói:

```text
VTL0 kernel không được tin tuyệt đối.
Secure kernel/hypervisor mới quyết định một số page có writable không.
```

## 7. KDP là gì?

KDP = Kernel Data Protection.

Microsoft mô tả hai dạng:

- Static KDP: driver/kernel mark một data section của image là protected.
- Dynamic KDP: secure pool, data được init một lần rồi làm read-only.

Ý tưởng:

```text
data quan trọng -> hypervisor mark EPT read-only -> VTL0 không sửa được
```

Ví dụ dữ liệu nhạy cảm:

- code integrity policy data,
- callback/config table,
- security product immutable config,
- "initialize once" data.

## 8. HVCI khác KDP ở đâu?

HVCI:

```text
bảo vệ code integrity / executable memory
```

KDP:

```text
bảo vệ data integrity / read-only data
```

HVCI quan tâm:

- unsigned code,
- W^X,
- kernel code page không bị patch.

KDP quan tâm:

- data page nhạy cảm không bị sửa.

Nhưng bài của Tandasat nói: KDP kiểu EPT read-only vẫn có một lỗ thiết kế: remapping.

## 9. Remapping attack là gì?

Giả sử có:

```text
LA A -> GPA X
GPA X bị EPT read-only
```

Attacker không thể ghi vào GPA X.

Nhưng attacker có kernel R/W, nên sửa guest PTE:

```text
LA A -> GPA Y
```

Trong đó GPA Y là page khác, writable ở EPT.

Kết quả:

```text
Đọc LA A bây giờ thấy nội dung của GPA Y.
```

Attacker không sửa page X. Attacker đổi mapping để LA A trỏ sang page Y.

Đây là "remapping" hoặc "page swapping".

## 10. Ví dụ đời thường

Hãy tưởng tượng:

- `LA A` là biển địa chỉ nhà: "số 10 phố Kernel".
- `GPA X` là căn nhà thật chứa két sắt.
- Hypervisor khóa căn nhà X: không ai được sửa đồ trong đó.

Attacker không phá khóa căn nhà X.

Attacker sửa bản đồ thành:

```text
"số 10 phố Kernel" -> căn nhà Y
```

Khi người khác đi tới "số 10 phố Kernel", họ tới Y, không tới X.

Hypervisor vẫn bảo vệ X, nhưng hệ thống đã bị lừa vì cái tên/địa chỉ ảo giờ trỏ sang nơi khác.

## 11. Demo trong bài: `ci!g_CiOptions`

Tandasat dùng biến:

```text
ci!g_CiOptions
```

Đây là biến liên quan Code Integrity trong `ci.dll`.

Demo:

1. Tìm LA của `ci!g_CiOptions`.
2. Tìm GPA backing nó.
3. Xác nhận EPT page đó read-only.
4. Tìm một zero-filled GPA.
5. Sửa guest PTE của `ci!g_CiOptions` để trỏ tới zero page.
6. Đọc lại `ci!g_CiOptions` thấy bằng zero.

Điểm quan trọng:

```text
Không ghi vào protected GPA gốc.
Chỉ sửa guest page table để LA trỏ sang GPA khác.
```

## 12. Vì sao KDP không chặn được remapping?

KDP bảo vệ page ở mức EPT:

```text
GPA X không writable
```

Nhưng KDP không nhất thiết enforce:

```text
LA A luôn phải trỏ tới GPA X
```

Microsoft cũng gọi ra limitation này: KDP không enforce cách virtual address range được translate.

Nên nếu guest kernel PTE bị attacker sửa:

```text
LA A -> GPA Y
```

KDP bảo vệ X vẫn đúng, nhưng LA A bây giờ đọc Y.

## 13. Tại sao việc này quan trọng với BYOVD?

BYOVD thường cho attacker kernel write primitive.

Ví dụ:

- Dell DBUtil write.
- RTCore64 write.
- ASTRA/Lenovo physical R/W.

Nếu attacker có thể sửa PTE hoặc page table, họ có thể làm remapping.

Do đó HVCI/KDP không phải lúc nào cũng "hết đường". Modern exploit chuyển sang:

- data-only,
- remapping,
- PTE manipulation,
- aliasing,
- object state abuse.

## 14. Nhưng demo `g_CiOptions = 0` có load unsigned driver được không?

Theo bài, không đơn giản.

Tandasat ghi rằng khi HVCI bật, ép `ci!g_CiOptions` ở VTL0 không đủ để load unsigned driver. Secure kernel vẫn kiểm tra certificate riêng và crash hệ thống nếu phát hiện vấn đề.

Ý nghĩa:

```text
Remapping có thể làm VTL0 đọc thấy dữ liệu bị đổi,
nhưng secure kernel/VTL1 vẫn có logic riêng.
```

Nên đừng hiểu nhầm:

```text
remap g_CiOptions = instant unsigned driver load
```

Không phải.

## 15. Target thú vị hơn của remapping

Bài gợi ý target khác:

- bitmap hợp lệ của kCFG,
- function pointer nhạy cảm,
- data read-only do EPT bảo vệ.

Ý tưởng:

```text
Nếu data protected by EPT nhưng semantic của LA quan trọng,
remapping LA có thể đổi behavior mà không ghi page gốc.
```

Ví dụ concept:

```text
LA của bitmap kCFG -> GPA mới có bit "valid target" bật
```

Đây là concept research, không phải hướng dẫn khai thác hoàn chỉnh.

## 16. Intel VT-rp là gì?

VT-rp = Intel Virtualization Technology Redirect Protection.

Theo bài, VT-rp gồm ba feature:

1. HLAT: Hypervisor-managed Linear Address Translation.
2. PW: Paging-write.
3. GPV: Guest-paging verification.

Mục tiêu chung:

```text
giúp hypervisor enforce translation/permission của guest memory tốt hơn,
chống remapping/aliasing mà không cần trap mọi write vào page table.
```

## 17. Tại sao không chỉ make guest page tables read-only?

Ý tưởng dễ nghĩ:

```text
Hypervisor mark mọi guest page table read-only bằng EPT.
Mỗi khi guest muốn sửa PTE -> VM-exit -> hypervisor kiểm tra.
```

Vấn đề:

- OS sửa page table rất thường xuyên.
- Mỗi write gây VM-exit rất đắt.
- Performance sẽ tệ.

VT-rp sinh ra để có hardware assist hiệu quả hơn.

## 18. HLAT là gì?

HLAT = Hypervisor-managed Linear Address Translation.

Bình thường:

```text
CPU dùng guest CR3 để translate LA -> GPA.
```

Khi HLAT active cho một range:

```text
CPU dùng HLATP VMCS field để lấy page table do hypervisor quản lý.
```

Tức:

```text
LA -> GPA không còn do guest CR3 quyết định nữa.
LA -> GPA do hypervisor-managed paging structures quyết định.
```

Đây là điểm mấu chốt.

## 19. HLATP là gì?

HLATP = Hypervisor-managed Linear Address Translation Pointer.

Nó là một VMCS field.

VMCS là control structure của Intel VT-x. Hypervisor cấu hình VMCS để CPU biết:

- guest state,
- host state,
- VM-execution controls,
- EPT pointer,
- exit controls,
- và với VT-rp: HLATP.

HLATP trỏ tới root paging structure do hypervisor quản lý, tương tự CR3 nhưng thuộc hypervisor.

## 20. HLAT prefix size là gì?

HLAT không nhất thiết áp dụng cho mọi linear address.

Bài nói CPU quyết định có dùng HLAT không dựa trên:

```text
HLAT enabled
LA nằm trong range theo HLAT prefix size VMCS
```

Tức hypervisor có thể nói:

```text
chỉ một vùng LA nhất định dùng HLAT
```

Điều này quan trọng vì performance/compatibility.

## 21. HLAT chặn remapping như thế nào?

Không có HLAT:

```text
LA A -> guest PTE -> GPA X
attacker sửa guest PTE
LA A -> GPA Y
```

Có HLAT:

```text
LA A -> HLAT page table -> GPA X
guest PTE bị sửa cũng không được dùng
```

Attacker sửa guest page table xong:

```text
LA A vẫn translate theo HLAT table do hypervisor giữ
```

Do đó remapping trở thành no-op.

## 22. Ví dụ cực đơn giản

Trước bảo vệ:

```text
guest CR3 table:
  ci!g_CiOptions LA -> GPA 0x111000
```

Attacker sửa:

```text
guest CR3 table:
  ci!g_CiOptions LA -> GPA 0x200000
```

Đọc LA thấy zero page.

Sau HLAT:

```text
HLAT table:
  ci!g_CiOptions LA -> GPA 0x111000

guest CR3 table:
  ci!g_CiOptions LA -> GPA 0x200000
```

CPU dùng HLAT table, không dùng guest CR3 table.

Đọc LA vẫn thấy GPA 0x111000.

## 23. Restart bit trong HLAT

Part 1 note nói khác biệt lớn giữa traditional paging và HLAT paging là bit 11, gọi là Restart bit.

Khi CPU gặp Restart bit trong HLAT paging:

```text
abort HLAT paging
fallback sang traditional guest paging
```

Tại sao cần?

- Không phải mọi page cần HLAT.
- Hypervisor có thể bảo vệ select pages.
- Vẫn giữ compatibility/performance cho vùng không nhạy cảm.

Ví dụ:

```text
vùng kernel security data -> HLAT enforce
vùng bình thường -> Restart -> guest CR3 tự quản
```

## 24. Demo HLAT trong bài

Bài dùng custom hypervisor.

Flow concept:

1. Boot Windows như guest của custom hypervisor.
2. Tìm LA/PTE của `ci!g_CiOptions`.
3. Hypercall để hypervisor enable HLAT cho LA đó.
4. Hypervisor copy current guest paging structures thành hypervisor-managed structures.
5. Thử remapping attack lại.
6. `ci!g_CiOptions` không đổi.

Ý nghĩa:

```text
guest PTE bị sửa thành công,
nhưng CPU không dùng guest PTE cho LA đó nữa.
```

## 25. PW - Paging-write là gì?

Part 2 giải thích Paging-write.

Vấn đề:

HLAT page tables do hypervisor quản lý, nhưng CPU vẫn phải đọc chúng trong VMX non-root. Các page table này nằm ở GPA mà guest về mặt địa chỉ có thể thấy.

Hypervisor muốn mark chúng read-only bằng EPT để guest không sửa.

Nhưng CPU khi page-walk có thể tự set Accessed/Dirty bits trong paging structures.

Đó là "paging write":

```text
hardware page walk tự ghi A/D bits vào page table entry
```

Nếu EPT của page table là read-only, hardware paging write sẽ gây EPT violation/VM-exit.

## 26. PWA bit giải quyết gì?

VT-rp thêm PWA: Paging-Write Access bit trong EPT entry.

Ý tưởng:

```text
EPT Write = 0, nhưng PWA = 1
```

Nghĩa là:

- guest software không được ghi page table.
- hardware page-walk được phép ghi A/D bits cần thiết.

Đây là performance optimization quan trọng.

Nếu không có PWA:

```text
mỗi lần CPU muốn set A/D bit -> VM-exit
```

Nếu có PWA:

```text
hardware paging write đi qua mà không cần VM-exit
```

## 27. GPV - Guest Paging Verification là gì?

GPV = Guest-paging verification.

Mục tiêu:

```text
ngăn một GPA nhạy cảm bị truy cập qua LA không mong muốn / alias mapping
```

Alias nghĩa là:

```text
LA A -> GPA X
LA B -> GPA X
```

Nếu hypervisor muốn GPA X chỉ được truy cập qua LA A, GPV giúp kiểm tra đường page-walk.

## 28. GPV hoạt động concept như thế nào?

Part 2 nói:

Khi EPT entry cuối cho GPA có VGP bit, CPU sẽ kiểm tra các EPT leaf entries dùng để đọc guest paging structures trong quá trình LA->GPA translation.

Nó yêu cầu các paging-structure pages đó được mark PWA.

Nói dễ hiểu:

```text
GPA X chỉ hợp lệ nếu đường translation đi qua page tables đã được hypervisor đánh dấu là "ok".
```

Nếu attacker tạo alias bằng page table khác không được đánh dấu:

```text
LA B -> attacker page table -> GPA X
```

CPU thấy page-walk không đi qua PWA-approved structures -> EPT violation.

## 29. HLAT vs GPV

HLAT:

```text
hypervisor thay guest page tables cho một LA range
```

GPV:

```text
hypervisor kiểm tra đường guest paging tới một GPA có đi qua approved page tables không
```

HLAT chặn remapping bằng cách không dùng guest PTE.

GPV chặn aliasing bằng cách kiểm tra provenance của translation path.

## 30. PW vs GPV

PW/PWA:

```text
cho phép hardware page-walk ghi A/D bits vào paging structures dù EPT write=0
```

GPV/VGP:

```text
enforce rằng access tới GPA phải đi qua paging structures được mark PWA
```

Chúng liên quan vì PWA bit vừa:

- giúp performance cho paging writes,
- đánh dấu paging structure path là approved cho GPV.

## 31. Remapping vs aliasing

Remapping:

```text
LA A ban đầu -> GPA X
attacker đổi -> GPA Y
```

Aliasing:

```text
LA A -> GPA X
LA B -> GPA X
```

Remapping nhắm vào identity của LA.

Aliasing nhắm vào việc truy cập cùng GPA qua một LA khác.

HLAT mạnh với remapping.

GPV hữu ích với aliasing/provenance of translation.

## 32. Tại sao code integrity khó bị remapping hơn data?

Part 2 nói remapping attack chống code integrity khó hơn.

Với data:

```text
tìm GPA writable chứa data giả -> remap LA data sang đó
```

Với code:

Bạn cần GPA vừa:

- writable để sửa shellcode,
- executable ở EPT để chạy.

HVCI/W^X cố gắng đảm bảo:

```text
không có page vừa writable vừa executable
```

Nên remapping dễ hơn với data-protection bypass, khó hơn với code-exec.

## 33. SMEP, MBEC/GMET, kCFG, CET liên quan thế nào?

Part 2 nhấn mạnh VT-rp chỉ giải quyết một subset.

Các mitigation khác vẫn cần:

| Mitigation | Chặn gì |
|---|---|
| W^X / HVCI | writable code hoặc executable unsigned code |
| SMEP | kernel execute user page |
| SMAP | kernel access user page không đúng path |
| MBEC / GMET | tách execute permission user/kernel tốt hơn |
| kCFG | indirect call target không hợp lệ |
| CET shadow stack | return address/ROP tamper |

VT-rp không thay thế các mitigation này.

Nó chủ yếu làm:

```text
translation integrity
```

## 34. Liên hệ với ASTRA64 / physical R/W

Với ASTRA64, bạn có physical R/W.

Nếu bạn dùng nó để direct write `_EPROCESS.Token`:

```text
không liên quan nhiều tới remapping/KDP target
```

Vì `_EPROCESS.Token` thường là normal VTL0 kernel data, không phải KDP-protected page.

Nhưng nếu bạn dùng physical/kernel write để sửa PTE:

```text
đó là cùng họ kỹ thuật với remapping attack
```

HLAT/VT-rp sẽ làm PTE tamper không còn hiệu quả cho protected LA.

## 35. Liên hệ với BYOVD

BYOVD cung cấp kernel primitive:

- arbitrary write,
- physical R/W,
- MSR,
- virtual R/W.

EPT/KDP/HVCI cố gắng làm một số target không writable.

Remapping attack nói:

```text
nếu attacker vẫn có thể sửa guest page table,
họ có thể tránh ghi protected GPA bằng cách đổi LA->GPA.
```

VT-rp nói:

```text
hypervisor phải bảo vệ cả translation, không chỉ page permission.
```

Đây là tiến hóa tự nhiên:

```text
Code patch -> HVCI
Data patch -> KDP
Page remap -> VT-rp/HLAT/GPV
```

## 36. Tại sao Hyper-V lúc bài viết chưa dùng VT-rp?

Bài nói tại thời điểm đó major hypervisors, gồm Hyper-V, chưa dùng VT-rp rộng rãi.

Lý do thực tế có thể gồm:

- hardware support chưa phổ biến,
- chỉ subset Intel 12th+ hỗ trợ,
- không có AMD equivalent,
- integration phức tạp,
- compatibility/performance,
- cần thay đổi lớn trong hypervisor memory manager.

Intel community post sau này nói VT-rp cung cấp root of page walk, PWA, GPV và restart-bit compatibility.

## 37. Availability

Theo bài:

- VT-rp có trên subset Intel 12th gen trở lên.
- Không có equivalent trực tiếp trên AMD tại thời điểm bài viết.
- Cần hypervisor support, không chỉ CPU support.

Điều này quan trọng:

```text
CPU hỗ trợ VT-rp != Windows/Hyper-V đang dùng VT-rp cho bảo vệ bạn quan tâm.
```

## 38. VMCS là gì?

VMCS = Virtual Machine Control Structure.

Intel VT-x dùng VMCS để CPU biết:

- khi chạy guest, state là gì,
- khi exit về host, state là gì,
- điều kiện nào gây VM-exit,
- EPT pointer ở đâu,
- execution controls bật gì,
- với VT-rp: HLATP, HLAT prefix, PW/GPV controls.

Hypervisor cấu hình VMCS bằng VMREAD/VMWRITE.

## 39. VMX root vs non-root

Intel VT-x chia:

| Mode | Ai chạy |
|---|---|
| VMX root | Hypervisor |
| VMX non-root | Guest OS |

Windows guest kernel dù ring 0 vẫn là:

```text
VMX non-root ring 0
```

Hypervisor ở:

```text
VMX root
```

Nên guest kernel không sửa được EPT/VMCS.

## 40. VM-exit là gì?

VM-exit là khi CPU rời guest về hypervisor do một điều kiện:

- EPT violation,
- privileged instruction,
- CPUID nếu configured,
- MSR access nếu configured,
- external interrupt,
- paging-write violation,
- GPV violation,
- v.v.

VM-exit đắt hơn execution bình thường.

Đây là lý do hypervisor không muốn trap mọi page-table write nếu có cách phần cứng hiệu quả hơn.

## 41. TLB liên quan gì?

TLB cache kết quả translation.

Khi page tables/EPT/HLAT structures thay đổi, hypervisor/OS cần invalidation phù hợp:

- INVLPG,
- INVVPID,
- INVEPT,
- context switch invalidation,
- PCID/VPID optimizations.

Trong remapping attack:

```text
sửa guest PTE -> cần TLB flush để CPU dùng mapping mới
```

Trong HLAT:

```text
guest PTE bị sửa nhưng CPU dùng HLAT translation cho protected LA
```

TLB vẫn là implementation detail quan trọng, nhưng concept bảo vệ là: source of translation đã chuyển sang hypervisor-managed structures.

## 42. EPT permission vs guest PTE permission

Có hai lớp permission:

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
- PWA/VGP extensions với VT-rp

Access chỉ thành công nếu cả hai lớp cho phép theo ngữ cảnh.

Ví dụ:

```text
guest PTE writable = 1
EPT writable = 0
=> write vẫn bị EPT chặn
```

Nhưng remapping attack đổi guest PTE sang GPA khác:

```text
guest PTE points to GPA Y
EPT writable for GPA Y = 1
=> write/read semantic có thể đổi
```

## 43. Tại sao HLAT không chỉ là "EPT nâng cấp"?

EPT quản lý:

```text
GPA -> PA
```

HLAT can thiệp vào:

```text
LA -> GPA
```

Đây là tầng khác.

Remapping attack nằm ở LA->GPA layer, nên EPT-only không đủ.

HLAT cho hypervisor quyền quản lý LA->GPA cho vùng nhạy cảm.

## 44. Tại sao gọi là Redirect Protection?

Vì attack là redirect:

```text
redirect LA từ GPA protected sang GPA attacker-controlled
```

VT-rp chống redirect đó.

Nó không chỉ nói "page này read-only" mà nói:

```text
địa chỉ tuyến tính này phải resolve theo đường hypervisor đã quyết định
```

## 45. Những thứ blog chưa đào sâu nhưng bạn nên học thêm

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

## 46. Cách học đề xuất

Thứ tự học hợp lý:

1. x64 paging bình thường.
2. EPT/SLAT.
3. Windows VBS/HVCI/KDP.
4. Remapping attack.
5. HLAT.
6. PW/PWA.
7. GPV/VGP.
8. kCFG/CET/MBEC/SMEP bổ sung.
9. BYOVD physical R/W liên hệ với các primitive thực tế.

Nếu học ngược từ HLAT ngay, sẽ rất khó vì HLAT là tầng bảo vệ cho một lỗi thiết kế ở tầng LA->GPA.

## 47. Sơ đồ tổng hợp

Không có VT-rp:

```text
Guest code uses LA
  -> guest CR3 page tables decide LA -> GPA
  -> EPT decides GPA -> PA
  -> memory access

Attacker with kernel write:
  -> edits guest PTE
  -> LA now points to different GPA
```

Có HLAT:

```text
Guest code uses protected LA
  -> CPU uses HLATP, not guest CR3
  -> hypervisor-managed page tables decide LA -> GPA
  -> EPT decides GPA -> PA
  -> memory access

Attacker edits guest PTE:
  -> ignored for protected LA
```

Có GPV:

```text
Access to sensitive GPA
  -> CPU verifies translation path used approved paging structures
  -> alias through unapproved page tables causes EPT violation
```

## 48. Một ví dụ đơn giản tự chế

Giả sử kernel có biến:

```text
PolicyEnabled at LA 0xffff8000`10002000
```

Ban đầu:

```text
LA PolicyEnabled -> GPA 0xABC000
EPT for 0xABC000: R=1 W=0
```

Attacker không ghi được `0xABC000`.

Attacker tạo page giả:

```text
GPA 0xDEF000: chứa PolicyEnabled = 0
EPT for 0xDEF000: R=1 W=1
```

Attacker sửa guest PTE:

```text
LA PolicyEnabled -> GPA 0xDEF000
```

Nếu không có HLAT:

```text
kernel đọc PolicyEnabled thấy 0
```

Nếu có HLAT:

```text
HLAT table vẫn nói LA PolicyEnabled -> GPA 0xABC000
kernel đọc PolicyEnabled thấy giá trị thật
```

## 49. Liên hệ với "physical memory R/W bypass HVCI?"

Bạn hỏi trước đó physical R/W có bypass HVCI không.

Giờ có thể nói chính xác hơn:

Physical R/W có thể giúp:

- sửa normal VTL0 data,
- sửa guest page tables,
- làm remapping nếu không có VT-rp/HLAT bảo vệ,
- tránh cần kernel shellcode.

Nhưng physical R/W không tự động:

- sửa được VTL1 secure kernel memory,
- bypass secure kernel certificate check,
- bypass KDP nếu HLAT/VT-rp enforce translation,
- bypass code integrity nếu không có W+X/executable path.

Nên:

```text
physical R/W là primitive rất mạnh,
nhưng modern hypervisor protections đang chuyển mục tiêu từ "protect page" sang "protect translation path".
```

## 50. Kết luận cuối

Bài của Tandasat có ba ý rất sâu:

1. EPT/KDP bảo vệ page physical, nhưng không nhất thiết bảo vệ virtual-address identity.
2. Remapping attack lợi dụng khoảng trống đó bằng cách sửa guest page tables.
3. VT-rp/HLAT/PW/GPV là hardware answer để hypervisor bảo vệ cả translation path một cách hiệu quả.

Nếu bạn đang học Windows kernel exploit hiện đại, đây là bridge quan trọng giữa:

```text
BYOVD arbitrary write
-> PTE/page-table manipulation
-> HVCI/KDP bypass ideas
-> hardware-assisted mitigation
```

## 51. Đi sâu hơn: CPU dịch địa chỉ thật sự làm gì?

Khi code trong guest chạy một lệnh như:

```asm
mov eax, dword ptr [fffff8024b082004]
```

CPU không "biết" đây là `ci!g_CiOptions`. CPU chỉ thấy một linear address:

```text
LA = fffff8024b082004
```

Nếu đang ở VMX non-root với EPT bật, CPU phải làm hai lần dịch:

```text
guest paging: LA  -> GPA
EPT paging:   GPA -> HPA/PA
```

Điều quan trọng là hai lần dịch này có owner khác nhau:

- Guest OS quản lý page tables cho LA -> GPA.
- Hypervisor quản lý EPT cho GPA -> PA.

Một kernel exploit trong guest có thể sửa guest page tables vì page tables là memory của guest. Nhưng nó không thể sửa EPT nếu không thoát khỏi VMX non-root/hypervisor boundary.

Đây là lý do EPT ban đầu rất hấp dẫn cho security:

```text
guest kernel compromised vẫn không sửa được EPT permission
```

Nhưng remapping attack xuất hiện vì security property đó chưa đủ.

## 52. Ví dụ số cụ thể: page-table walk 4-level

Lấy LA giả định:

```text
LA = fffff8024b082004
```

Trên x64 canonical 48-bit paging, CPU tách index:

```text
PML4 index = (LA >> 39) & 0x1ff
PDPT index = (LA >> 30) & 0x1ff
PD index   = (LA >> 21) & 0x1ff
PT index   = (LA >> 12) & 0x1ff
offset     = LA & 0xfff
```

Giả sử tính ra:

```text
PML4 index = 0x1f0
PDPT index = 0x009
PD index   = 0x058
PT index   = 0x082
offset     = 0x004
```

CR3 chứa physical address của PML4:

```text
CR3 = 0x12345000
```

CPU đọc:

```text
PML4E address = 0x12345000 + 0x1f0 * 8
```

PML4E chứa PFN của PDPT:

```text
PML4E = 0x00000000aaa00123
PFN base = 0xaaa00000
```

Rồi:

```text
PDPTE address = 0xaaa00000 + 0x009 * 8
PDE address   = PFN(PDPTE) + 0x058 * 8
PTE address   = PFN(PDE)   + 0x082 * 8
```

Nếu PTE chứa:

```text
PTE = 0x000000011ceaa121
```

thì PFN base là:

```text
0x11ceaa000
```

GPA cuối:

```text
GPA = 0x11ceaa000 + 0x004 = 0x11ceaa004
```

Đây chính là logic mà các exploit physical R/W như ASTRA64 phải tự làm nếu muốn từ kernel VA tìm ra physical address.

## 53. Ví dụ số cụ thể: EPT walk

Sau khi có GPA:

```text
GPA = 0x11ceaa004
```

CPU tiếp tục dùng EPTP, tức EPT pointer do hypervisor cấu hình trong VMCS.

EPT cũng có dạng paging structure nhiều cấp. Concept tương tự:

```text
EPTP -> EPT PML4 -> EPT PDPT -> EPT PD -> EPT PT -> HPA
```

Nhưng EPT entry khác guest PTE ở permission.

Guest PTE có:

- Present
- RW
- User/Supervisor
- NX

EPT PTE có:

- Read
- Write
- Execute
- memory type
- accessed/dirty
- các bit mở rộng như PWA/VGP với VT-rp.

Giả sử EPT PTE cho GPA page `0x11ceaa000` là:

```text
EPT: Read=1, Write=0, Execute=0
```

Khi guest đọc:

```text
mov eax, [LA]
```

thì OK.

Khi guest ghi:

```text
mov [LA], eax
```

CPU translate LA -> GPA thành `0x11ceaa004`, rồi EPT thấy Write=0, gây EPT violation VM-exit.

Hypervisor có thể log/deny/crash tùy policy.

## 54. Vấn đề: EPT bảo vệ GPA, không bảo vệ "ý nghĩa của LA"

Điểm tinh tế:

EPT biết:

```text
GPA 0x11ceaa000 không writable.
```

EPT không tự biết:

```text
LA fffff8024b082004 phải luôn trỏ tới GPA 0x11ceaa000.
```

Quan hệ LA -> GPA nằm ở guest page tables.

Nếu attacker sửa guest PTE:

```text
PTE của LA fffff8024b082004:
  trước: PFN 0x11ceaa
  sau:   PFN 0x200
```

thì CPU sẽ dịch:

```text
LA -> GPA 0x200004
```

Nếu EPT cho GPA `0x200000` writable/readable, đọc LA sẽ thấy nội dung page đó.

EPT vẫn đang bảo vệ `0x11ceaa000`. Nhưng LA đã không còn đi tới đó.

Đó là toàn bộ tinh thần của remapping.

## 55. Remapping attack bằng mô hình 4 ô nhớ

Giả sử có 4 page:

```text
GPA A = page chứa policy thật, protected by KDP
GPA B = page attacker tạo/copy, writable
GPA C = page table page
GPA D = data thường
```

Ban đầu:

```text
LA policy -> GPA A
EPT[GPA A].Write = 0
EPT[GPA B].Write = 1
```

Attacker có kernel arbitrary write. Họ không ghi vào GPA A. Họ ghi vào PTE trong GPA C:

```text
PTE(policy LA).PFN = B
```

Sau đó:

```text
LA policy -> GPA B
```

Nếu kernel/security logic đọc `policy LA`, nó đọc bản giả ở B.

Đây là kiểu tấn công "đổi bản đồ", không phải "phá khóa căn nhà".

## 56. Tại sao gọi là "bypass KDP" dù page protected không bị sửa?

KDP bảo vệ nội dung của page A khỏi bị sửa. Điều đó vẫn đúng.

Nhưng mục tiêu của security không chỉ là:

```text
page A không đổi
```

Mục tiêu thực tế là:

```text
khi kernel đọc policy ở LA policy, nó nhận đúng policy thật
```

Remapping phá mục tiêu thứ hai.

Nên gọi là bypass ở mức semantic:

```text
KDP protected bytes intact,
but the protected virtual address no longer resolves to those bytes.
```

Đây là insight chính.

## 57. Tại sao hypervisor không thể đơn giản kiểm tra mọi PTE write?

Có thể làm, nhưng đắt.

Windows sửa page tables rất nhiều:

- allocate/free memory,
- page fault handling,
- process creation,
- driver load,
- copy-on-write,
- working set trimming,
- memory compression,
- large page split,
- KVA shadow transitions.

Nếu hypervisor mark page table read-only và VM-exit mỗi lần guest write PTE:

```text
mỗi lần OS chỉnh memory mapping -> trap vào hypervisor
```

Performance sẽ giảm mạnh.

HLAT/VT-rp là hardware support để giải quyết đúng vùng nhạy cảm mà không trap mọi thứ.

## 58. HLAT nhìn như "CR3 thứ hai" nhưng do hypervisor giữ

Một cách học dễ:

```text
guest CR3 = bản đồ do Windows giữ
HLATP     = bản đồ do hypervisor giữ
```

Bình thường CPU dùng:

```text
guest CR3
```

Với HLAT active cho LA đó, CPU dùng:

```text
HLATP
```

Nếu attacker sửa bản đồ của Windows:

```text
guest CR3 table bị sửa
```

thì protected LA vẫn đi qua bản đồ hypervisor.

Đó là lý do HLAT là "Hypervisor-managed Linear Address Translation".

## 59. HLAT không phải copy toàn bộ address space mãi mãi

Một hiểu nhầm thường gặp:

```text
HLAT có nghĩa hypervisor quản lý toàn bộ page table của guest.
```

Không nhất thiết.

HLAT có:

- enable control,
- prefix/range logic,
- Restart bit để fallback,
- hypervisor-managed structures cho vùng cần bảo vệ.

Mục tiêu là:

```text
protect selected sensitive translations
```

không phải thay toàn bộ memory manager của guest.

Nếu hypervisor quản lý toàn bộ address space, complexity và performance sẽ rất lớn.

## 60. Restart bit: cơ chế "đường thoát"

Trong HLAT paging, nếu gặp Restart bit:

```text
CPU dừng HLAT walk và quay lại guest paging bình thường.
```

Tưởng tượng HLAT table như một firewall rule set:

```text
rule cho protected page: enforce ở HLAT
rule cho page bình thường: restart/fallback sang guest
```

Điều này cho phép:

- chỉ bảo vệ region nhạy cảm,
- không duplicate toàn bộ guest page tables,
- giảm overhead,
- giữ compatibility.

## 61. HLAT demo: vì sao "write thành công nhưng giá trị không đổi"?

Trong demo của Tandasat, attacker vẫn sửa guest PTE được.

Tức:

```text
write primitive hoạt động
guest PTE bị thay
```

Nhưng khi đọc `ci!g_CiOptions`, giá trị không đổi.

Lý do:

```text
CPU không dùng guest PTE cho LA đó nữa.
CPU dùng HLAT paging structures.
```

Đây là dấu hiệu bảo vệ đúng:

- không cần chặn write vào guest PTE,
- chỉ cần đảm bảo write đó không ảnh hưởng translation thực tế của protected LA.

## 62. PW/PWA chi tiết hơn: vì sao hardware lại ghi page table?

Trong paging, CPU không chỉ đọc page table entries. CPU có thể update Accessed/Dirty bits.

Accessed bit:

```text
page/table entry đã được dùng để access
```

Dirty bit:

```text
page đã bị ghi
```

Các bit này giúp OS quản lý memory:

- page replacement,
- working set,
- writeback,
- aging.

Khi CPU page-walk qua một entry, nó có thể set Accessed. Khi write vào page, nó có thể set Dirty.

Nếu hypervisor-managed HLAT page tables được EPT mark read-only, CPU hardware write A/D bit cũng sẽ bị EPT chặn nếu không có PWA.

PWA nói:

```text
software guest không được ghi,
nhưng hardware paging write được phép.
```

## 63. PWA khác EPT Write thế nào?

EPT Write:

```text
mọi write bình thường vào GPA có được phép không
```

PWA:

```text
write do hardware page-walk để update paging metadata có được phép không
```

Vậy một EPT entry có thể:

```text
Write = 0
PWA   = 1
```

Nghĩa là:

- guest code không thể store vào page table.
- CPU page walker vẫn có thể set A/D bits.

Đây là điểm rất tinh tế.

## 64. GPV chi tiết hơn: "đường đi" cũng là security property

Không chỉ đích đến quan trọng. Đường đi cũng quan trọng.

Không có GPV:

```text
LA good -> approved page tables -> GPA X
LA evil -> attacker page tables -> GPA X
```

EPT chỉ thấy cuối cùng là GPA X.

Nếu GPA X cho phép read/write vì lý do nào đó, EPT không biết access đó đến từ LA nào.

GPV cho phép hypervisor nói:

```text
GPA X chỉ được access nếu quá trình LA->GPA đi qua paging structures đã được đánh dấu approved.
```

Approved marker chính là PWA trên leaf EPT entries của paging-structure pages.

## 65. Ví dụ GPV bằng "cửa chính/cửa phụ"

GPA X là phòng server.

Bạn có hai đường vào:

- cửa chính: có camera, badge, guard,
- cửa phụ: do attacker mở.

EPT chỉ nhìn thấy:

```text
ai đó vào phòng server
```

GPV hỏi thêm:

```text
người này đi qua cửa chính đã được approve không?
```

Nếu đi qua cửa phụ, chặn.

Trong paging:

- cửa chính = approved page tables,
- cửa phụ = attacker-created alias page tables.

## 66. Vì sao GPV cần PWA?

PWA đánh dấu page-table pages mà hypervisor coi là approved cho translation.

Khi VGP bit bật cho target GPA, CPU kiểm tra:

```text
trong quá trình LA->GPA, các page table pages có EPT leaf entry PWA=1 không?
```

Nếu không:

```text
EPT violation
```

Nên PWA vừa là performance feature vừa là trust marker cho GPV.

## 67. Một bảng so sánh thật rõ

| Feature | Chống cái gì | Cách làm | Nếu thiếu thì sao |
|---|---|---|---|
| EPT read-only | Ghi trực tiếp vào GPA | EPT Write=0 | attacker không ghi page đó nhưng có thể remap LA |
| HLAT | Remap LA sang GPA khác | dùng hypervisor page tables cho LA->GPA | guest PTE tamper đổi semantic của LA |
| PWA/PW | VM-exit do hardware A/D updates | cho paging write dù EPT Write=0 | HLAT page tables read-only gây nhiều VM-exit |
| GPV/VGP | Alias GPA qua LA khác/page tables khác | verify translation path approved | attacker truy cập same GPA qua alias path |

## 68. Những hiểu nhầm thường gặp

Hiểu nhầm 1:

```text
EPT read-only là đủ để bảo vệ data.
```

Sai một phần. Nó bảo vệ GPA đó khỏi write, nhưng không bảo vệ LA khỏi bị remap.

Hiểu nhầm 2:

```text
Physical R/W bypass toàn bộ HVCI/VBS.
```

Sai. Nó rất mạnh với VTL0 normal memory, nhưng VTL1/KDP/HLAT/SLAT protections vẫn có thể chặn một số target.

Hiểu nhầm 3:

```text
HLAT là EPT mới.
```

Không đúng. EPT là GPA->PA. HLAT là LA->GPA.

Hiểu nhầm 4:

```text
GPV giống HLAT.
```

Không. HLAT thay source of translation. GPV kiểm tra provenance của guest paging path.

Hiểu nhầm 5:

```text
Nếu remap `g_CiOptions` về 0 thì load unsigned driver được.
```

Không chắc, và trong bài demo thì không. Secure kernel/VTL1 vẫn kiểm tra và bugcheck.

## 69. Một cách nhớ ngắn

```text
EPT  = bảo vệ page.
HLAT = bảo vệ virtual address mapping.
PW   = cho hardware update page-table metadata mà không mở write cho guest.
GPV  = bảo vệ đường đi tới page.
```

Hoặc:

```text
EPT hỏi: page này có được ghi không?
HLAT hỏi: địa chỉ này phải trỏ đi đâu?
GPV hỏi: bạn tới page này bằng con đường nào?
PW hỏi: hardware page-walk có được update bit kỹ thuật không?
```

## 70. Liên hệ với exploit chain thực tế

Giả sử attacker có BYOVD virtual write như `dbutil` hoặc `RTCore64`.

Target 1: direct token swap.

```text
write EPROCESS.Token
```

VT-rp không trực tiếp liên quan nếu token page không protected.

Target 2: KDP-protected policy data.

```text
write policy LA
```

EPT chặn.

Attacker thử:

```text
edit PTE(policy LA) -> fake GPA
```

Không có HLAT:

- có thể đổi semantic.

Có HLAT:

- guest PTE edit không ảnh hưởng protected LA.

Target 3: code page.

```text
remap code LA -> writable fake code page
```

Khó hơn vì HVCI/W^X/kCFG/CET và executable permission.

## 71. Tại sao bài này quan trọng cho Windows kernel exploit hiện đại?

Trước đây exploit thường nghĩ:

```text
có arbitrary kernel write -> patch kernel/global/callback/token
```

Sau HVCI/KDP:

```text
có arbitrary write nhưng target bị EPT read-only
```

Sau remapping:

```text
không ghi target page, đổi mapping
```

Sau VT-rp:

```text
hypervisor khóa cả mapping
```

Đây là cuộc đua:

```text
write primitive
-> data protection
-> translation attack
-> translation protection
```

## 72. Bài tập tư duy 1: Nếu bạn là attacker

Bạn có arbitrary kernel write trong VTL0.

Target:

```text
SensitiveData at LA A
EPT says GPA X is read-only
```

Bạn có thể thử:

1. Ghi trực tiếp LA A.
2. Sửa guest PTE của LA A sang GPA Y.
3. Tìm alias LA B trỏ tới GPA X.
4. Patch code kiểm tra SensitiveData.

Hãy tự đánh giá:

- Cách nào bị EPT chặn?
- Cách nào là remapping?
- Cách nào là aliasing?
- Cách nào bị HVCI/kCFG/CET làm khó?
- Cách nào HLAT chặn?
- Cách nào GPV chặn?

Đáp án:

- 1 bị EPT read-only chặn.
- 2 là remapping, HLAT chặn nếu LA A protected.
- 3 là aliasing, GPV có thể chặn nếu GPA X bật VGP và path không approved.
- 4 là code attack, HVCI/W^X/kCFG/CET/PatchGuard làm khó.

## 73. Bài tập tư duy 2: Nếu bạn là hypervisor

Bạn muốn bảo vệ LA A.

Bạn có các công cụ:

- EPT Write=0 cho GPA X.
- HLAT cho LA A.
- PWA cho HLAT paging structures.
- VGP cho GPA X.

Bạn chọn gì?

Minimum:

```text
EPT Write=0
HLAT for LA A
```

Nếu cần ngăn aliasing tới same GPA:

```text
VGP for GPA X
PWA on approved paging-structure pages
```

Nếu HLAT paging structures read-only:

```text
PWA để tránh VM-exit do hardware paging writes
```

## 74. Bài tập tư duy 3: Liên hệ ASTRA64

Bạn có ASTRA64 physical R/W.

Bạn muốn sửa KDP-protected data.

Các hướng:

1. Ghi thẳng physical page protected.
2. Sửa guest PTE remap LA sang page khác.
3. Direct token DKOM thay vì đụng KDP.

Đánh giá:

- 1 có thể bị EPT chặn.
- 2 là remapping, bị HLAT chặn nếu active.
- 3 không đụng protected KDP target, practical hơn nếu mục tiêu chỉ là LPE.

Đây là lý do direct token DKOM có thể vẫn work dù KDP tồn tại: nó chọn target khác.

## 75. Glossary ngắn

| Thuật ngữ | Nghĩa |
|---|---|
| LA | Linear Address, gần như virtual address trên x64 |
| GPA | Guest Physical Address, physical theo guest |
| PA/HPA/SPA | physical thật của host/machine |
| CR3 | pointer tới guest PML4 |
| PTE | page table entry |
| PFN | page frame number |
| EPT | second-level page table của Intel |
| EPTP | pointer tới EPT root |
| SLAT | second-level address translation |
| VBS | virtualization-based security |
| VTL0 | normal Windows kernel world |
| VTL1 | secure kernel world |
| HVCI | hypervisor-protected code integrity |
| KDP | kernel data protection |
| HLAT | hypervisor-managed linear address translation |
| HLATP | pointer tới HLAT paging structures |
| PW/PWA | paging-write / paging-write access |
| GPV/VGP | guest-paging verification / verify guest paging bit |
| VMCS | Intel VM control structure |
| VM-exit | CPU exit từ guest sang hypervisor |
| INVEPT | invalidate EPT translations |
| INVVPID | invalidate VPID-tagged translations |

## 76. Đọc tiếp theo thứ tự

1. Tandasat Part 1: remapping + HLAT.
2. Tandasat Part 2: PW + GPV.
3. Microsoft KDP article.
4. Fortinet DSE/KDP/remapping background.
5. Connor McGarr HVCI/kCFG exploit context.
6. Intel VT-rp community explanation.
7. Hypervisor-101-in-Rust để hiểu VMX/EPT bằng code.


# Connor McGarr HVCI/kCFG Deep Dive - Giải thích từng khái niệm

Nguồn chính:

- Connor McGarr, "Exploit Development: No Code Execution? No Problem! Living The Age of VBS, HVCI, and Kernel CFG": https://connormcgarr.github.io/hvci/
- Microsoft KDP: https://www.microsoft.com/en-us/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/
- Satoshi Tanda VT-rp Part 1/2: https://tandasat.github.io/blog/2023/07/05/intel-vt-rp-part-1.html và https://tandasat.github.io/blog/2023/07/31/intel-vt-rp-part-2.html

Mục tiêu tài liệu này:

```text
Đọc bài Connor tới mức hiểu:
- HVCI chặn cái gì.
- Vì sao shellcode/PTE trick cũ chết.
- Vì sao data-only token swap vẫn sống.
- Vì sao token swap chưa đủ mạnh.
- Làm sao biến arbitrary R/W thành kernel API invocation mà vẫn "HVCI-compliant".
- kCFG chặn forward edge ra sao.
- Vì sao overwrite return address né kCFG.
- Vì sao kCET/shadow stack sẽ giết kỹ thuật này.
```

Tài liệu này giải thích concept và trade-off. Không phải runbook exploit.

## 1. Bài Connor đang trả lời câu hỏi gì?

Câu hỏi trung tâm:

```text
Nếu HVCI không cho chạy unsigned shellcode trong kernel nữa,
exploit writer còn làm gì ngoài token stealing?
```

Trước HVCI:

```text
kernel bug -> arbitrary R/W -> control RIP -> shellcode -> gọi API kernel tùy ý
```

Sau HVCI:

```text
kernel bug -> arbitrary R/W -> không thể chạy unsigned shellcode dễ dàng
```

Connor đặt vấn đề:

```text
Ta không chạy shellcode mới.
Ta dùng code hợp lệ đã có trong kernel.
Ta dựng ROP chain để gọi kernel API hợp lệ.
```

Đây không phải "disable HVCI". Đây là "sống trong luật của HVCI".

## 2. Vì sao token stealing là baseline?

Token stealing cổ điển:

```text
current EPROCESS.Token = System EPROCESS.Token
```

Kết quả:

```text
process hiện tại thành SYSTEM
```

Vì sao phổ biến:

- chỉ cần một write pointer-sized,
- không cần shellcode nếu có arbitrary write,
- dễ verify,
- nhiều exploit LPE chỉ cần SYSTEM.

Nhưng Connor nói token stealing "bán rẻ" primitive.

Vì sao?

Vì shellcode kernel cho phép:

- gọi API kernel,
- allocate pool,
- unload driver,
- tạo thread,
- disable callback,
- làm nhiều logic tùy ý.

Token swap chỉ cho:

```text
identity elevation
```

Không cho:

```text
arbitrary kernel function invocation
```

## 3. HVCI chặn shellcode bằng cách nào?

HVCI dùng Hyper-V/SLAT/EPT để enforce:

```text
kernel code page: executable nhưng không writable
kernel data page: writable nhưng không executable
```

Nó chống pattern cũ:

```text
allocate/write data page
mark executable
jump to shellcode
```

Với HVCI:

- bạn không dễ tạo kernel RWX,
- không dễ patch code page,
- không dễ đổi data page thành executable,
- không dễ chạy unsigned kernel code.

Nói bằng bảng:

| Old trick | HVCI response |
|---|---|
| write shellcode into pool | pool data not executable |
| patch kernel code | code page not writable at EPT |
| PTE mark data executable | EPT executable policy still wins |
| W+X page | HVCI/W^X tries to prevent |

## 4. Tại sao PTE manipulation không đủ?

Không có HVCI:

```text
PTE says page executable/writable -> CPU obeys guest PTE
```

Có HVCI:

```text
guest PTE says executable
EPT/SLAT may still say not executable
```

Connor nhấn mạnh "physical memory trumps virtual memory":

```text
PTE là view của VTL0.
EPTE là view của hypervisor.
EPTE có final say.
```

Nên nếu attacker sửa PTE để page data thành executable:

```text
guest PTE: X=1
EPT: X=0
=> execute fail
```

## 5. VBS và VTL: vì sao kernel không còn là boundary cao nhất?

Trước VBS:

```text
ring 0 kernel compromise = game over
```

Sau VBS:

```text
VTL0 normal kernel compromise != VTL1 secure kernel compromise
```

Connor giải thích:

- VTL0: normal kernel.
- VTL1: secure kernel.
- Hypervisor: boundary cao hơn, enforce memory views.

Secure kernel/VTL1 yêu cầu hypervisor set EPTE permission cho VTL0.

Điểm quan trọng:

```text
VTL1 không phải hypervisor.
VTL0 không sống bên trong VTL1.
VTL1 dùng hypercall nhờ hypervisor cấu hình VTL0.
```

## 6. Hypercall là gì trong context này?

Hypercall giống syscall nhưng gọi vào hypervisor.

User/kernel gọi syscall để vào kernel.

Secure kernel gọi hypercall để nhờ hypervisor làm việc privileged hơn:

```text
securekernel -> vmcall/hypercall -> hypervisor
```

Trong bài Connor:

- secure kernel code cấu hình page protections,
- gọi hypercall wrapper,
- hypervisor update EPT/SLAT view.

Vì sao cần?

```text
secure kernel không trực tiếp sửa EPT như memory thường.
EPT thuộc hypervisor.
```

## 7. MBEC là gì?

MBEC = Mode-Based Execute Control.

Nó cho EPT phân biệt execute permission theo mode:

- execute for user mode,
- execute for supervisor/kernel mode.

Vì sao quan trọng?

SMEP chặn kernel execute user pages, nhưng HVCI cần quản lý execute permission tốt hơn ở EPT layer.

Nếu CPU hỗ trợ MBEC:

```text
EPT có thể nói user page executable for user, not executable for kernel
```

Điều này làm enforcement hiệu quả.

## 8. RUM là gì?

RUM = Restricted User Mode.

Nếu CPU không có MBEC, Windows dùng workaround:

```text
hypervisor giữ second set of EPT
user pages marked non-executable for kernel
swap EPT view on transitions
```

Vì sao chậm hơn?

- phải đổi EPT context/view,
- nhiều transition user/kernel,
- overhead lớn hơn MBEC bit trực tiếp.

Nói dễ nhớ:

```text
MBEC = một EPT view có bit thông minh.
RUM = nhiều EPT view để mô phỏng bit đó.
```

## 9. Vấn đề exploit mới: không chạy shellcode thì gọi kernel API bằng gì?

Connor muốn đạt:

```text
call arbitrary kernel API
```

nhưng không dùng:

```text
unsigned kernel shellcode
```

Ý tưởng:

```text
kernel đã có code hợp lệ.
ROP chain chỉ ghép các mảnh code hợp lệ.
```

Ví dụ muốn gọi:

```text
nt!PsGetCurrentProcess()
```

Không viết shellcode gọi nó. Thay vào đó:

```text
control stack
set registers bằng gadgets
jump/return vào function thật
lưu return value
exit thread
```

## 10. Tại sao cần "dummy thread"?

Connor tạo thread suspend.

Vì sao?

- Mỗi thread có kernel stack riêng.
- Nếu ta phá stack của main thread, process có thể chết.
- Dummy thread là vật hy sinh.
- Sau khi ROP xong, có thể terminate dummy thread.

Mô hình:

```text
main exploit thread: điều khiển, sống tiếp
dummy suspended thread: bị sửa kernel stack, chạy ROP, chết sạch
```

Đây là kỹ thuật reliability engineering.

## 11. Vì sao suspended thread vẫn có kernel stack hữu ích?

Khi thread được tạo, nó đi qua kernel startup path.

Suspend không nghĩa là "không có kernel state". Nó có:

- ETHREAD/KTHREAD,
- kernel stack,
- call stack liên quan startup/APC,
- return addresses.

Connor leak `KTHREAD`, rồi từ đó lấy `StackBase`.

Vì ROP chain cần nơi để ghi:

```text
return address + fake stack frames + gadgets + arguments
```

## 12. Leak KTHREAD bằng `NtQuerySystemInformation`

Connor dùng `NtQuerySystemInformation(SystemHandleInformation)` để leak kernel object của dummy thread handle.

Concept:

```text
user process có handle tới dummy thread
SystemHandleInformation lộ object pointer associated with handle
object đó là ETHREAD/KTHREAD-related kernel object
```

Vì sao cần?

Muốn sửa kernel stack, phải biết:

```text
địa chỉ KTHREAD
KTHREAD.StackBase
```

Không có leak:

```text
arbitrary write không biết ghi vào đâu
```

## 13. Vì sao không chỉ token swap?

Token swap:

```text
get SYSTEM
```

Kernel API invocation:

```text
call any kernel API
```

Ví dụ khả năng rộng hơn:

- allocate/free pool,
- query/modify kernel objects,
- call `Ps*`, `Zw*`, `Mm*`,
- terminate thread cleanly,
- chain nhiều operations.

Connor muốn primitive tương đương shellcode về capability, nhưng không vi phạm HVCI.

## 14. kCFG là gì?

kCFG = kernel Control Flow Guard.

CFG bảo vệ forward-edge indirect calls:

```text
call [function_pointer]
jmp [register]
```

Nó kiểm tra target có nằm trong bitmap valid call targets không.

Trong kernel, kCFG bitmap được bảo vệ bởi HVCI/SLAT để attacker có arbitrary R/W cũng không sửa được dễ dàng.

Nếu attacker overwrite function pointer:

```text
indirect call -> kCFG checks target
invalid -> fail
```

## 15. Vì sao overwrite function pointer không còn ngon?

Trước kCFG:

```text
overwrite HalDispatchTable/callback/function pointer -> jump to shellcode/gadget
```

Sau kCFG:

```text
indirect call target must be valid
```

Nếu target không valid:

- crash,
- fast fail,
- no control.

Vì kCFG bitmap protected bởi HVCI, attacker không đơn giản bật bit cho target tùy ý.

## 16. Vì sao return address né kCFG?

kCFG chủ yếu bảo vệ forward-edge:

- indirect call,
- indirect jump.

Return address là backward-edge:

```text
ret
```

Classic CFG không kiểm tra mọi return.

Do đó:

```text
overwrite return address -> ROP chain
```

không bị kCFG chặn theo cùng cách.

Đây là lý do Connor chọn stack return address thay vì function pointer.

## 17. Vì sao kCET sẽ phá kỹ thuật này?

kCET/kernel CET shadow stack bảo vệ return address.

CET shadow stack giữ một bản return address riêng, protected hơn.

Khi `ret` xảy ra:

```text
normal stack return address phải khớp shadow stack return address
```

Nếu attacker chỉ sửa normal stack:

```text
mismatch -> control protection fault / bugcheck
```

Connor ghi rõ kỹ thuật ROP bằng return address sẽ obsolete khi kCET mainstream.

## 18. Vì sao ROP chain vẫn "HVCI-compliant"?

HVCI chặn:

```text
execute unsigned code
```

ROP chain dùng:

```text
code đã có trong signed kernel images
```

Không có page mới executable.

Không có shellcode unsigned.

Về mặt HVCI:

```text
CPU đang execute legitimate kernel code pages
```

Vì vậy nó "compliant" với HVCI, dù mục đích malicious.

## 19. Nhưng ROP có bị SMEP/SMAP không?

SMEP:

- chặn kernel execute user pages.
- ROP dùng kernel gadgets, không execute user page.

SMAP:

- chặn kernel access user pages trong một số context.
- Connor note rằng Windows chỉ dùng SMAP trong một số tình huống, nhất là IRQL >= DISPATCH_LEVEL.
- Nếu chain chạy ở IRQL 0/PASSIVE_LEVEL, một số data movement tới user address có thể không bị SMAP.

Vì sao IRQL quan trọng?

- Nhiều kernel APIs chỉ hợp lệ ở PASSIVE_LEVEL.
- APC/dummy thread path giúp có context phù hợp hơn so với interrupt/DPC tùy tiện.

## 20. IRQL là gì?

IRQL = Interrupt Request Level.

Nó quyết định:

- cái gì được interrupt cái gì,
- code nào được phép chạy,
- có được page fault không,
- có được gọi API blocking không.

Các mức hay gặp:

| IRQL | Ý nghĩa |
|---|---|
| PASSIVE_LEVEL = 0 | normal kernel/user work, gọi được nhiều API |
| APC_LEVEL = 1 | APC processing |
| DISPATCH_LEVEL = 2 | DPC/spinlock context, hạn chế hơn |

ROP chain muốn gọi arbitrary kernel API thường cần PASSIVE_LEVEL. Nếu gọi API sai IRQL, dễ BSOD.

## 21. Vì sao stack alignment 16-byte quan trọng?

Windows x64 calling convention yêu cầu stack alignment nhất định, thường 16-byte trước call.

Nhiều kernel/user APIs dùng XMM/SIMD hoặc prologue giả định alignment.

Nếu ROP chain gọi function với stack lệch:

- crash,
- memory access fault,
- weird behavior.

Connor dùng extra `ret` để chỉnh alignment trước khi nhảy vào `ZwTerminateThread`.

Đây là chi tiết nhỏ nhưng cực quan trọng cho exploit reliability.

## 22. Calling convention x64 cần nhớ gì?

Windows x64:

```text
arg1 -> RCX
arg2 -> RDX
arg3 -> R8
arg4 -> R9
extra args -> stack
return value -> RAX
```

Vì vậy ROP chain cần gadgets để:

- set RCX,
- set RDX,
- set R8/R9 nếu cần,
- set RAX tới function target,
- jump/call function,
- handle return value.

Nếu function không nhận args như `PsGetCurrentProcess`, chain đơn giản hơn nhiều.

## 23. Vì sao chọn `PsGetCurrentProcess` làm demo?

Nó là API kernel đơn giản:

- không cần parameter,
- trả về `PEPROCESS`,
- dễ verify,
- không gây side effect nguy hiểm.

Nó chứng minh:

```text
ROP chain có thể call kernel API và lấy return value
```

trước khi thử API phức tạp hơn.

## 24. Vì sao cần lưu return value ra user mode?

ROP chain chạy trong kernel context của dummy thread.

Sau khi gọi `PsGetCurrentProcess`, return value nằm ở RAX.

Nếu không lưu RAX ở đâu:

```text
main exploit không lấy được kết quả
```

Connor dùng gadget kiểu:

```text
mov [rcx], rax
```

với RCX là user-mode buffer.

Đó là "return channel" từ kernel ROP về user controller.

## 25. Vì sao có thể ghi về user buffer?

Trong demo, chain chạy ở IRQL thấp, và SMAP không cản trong context đó theo quan sát của Connor.

Nhưng đây là một điểm version/config dependent.

Alternative an toàn hơn concept:

- ghi return vào kernel buffer rồi đọc bằng arbitrary read,
- hoặc dùng existing copy-to-user API hợp lệ.

Trade-off:

- user buffer đơn giản hơn,
- kernel buffer ít phụ thuộc SMAP hơn nhưng cần quản lý thêm.

## 26. Vì sao kết thúc bằng `ZwTerminateThread`?

ROP chain đã phá stack/register state của dummy thread.

Khôi phục mọi thứ sạch sẽ rất khó.

Thay vì restore:

```text
call ZwTerminateThread(dummy_thread, STATUS_SUCCESS)
```

Lý do:

- dummy thread là disposable,
- main thread vẫn sống,
- Windows cleanup thread state giúp tránh crash do return path hỏng.

Đây là tư duy exploit engineering tốt:

```text
đừng restore thứ phức tạp nếu có API legitimate để dispose nó
```

## 27. Vì sao dummy thread phải là thread riêng?

Nếu ROP trên main thread:

- main thread stack bị phá,
- exploit controller mất control,
- process có thể chết,
- khó cleanup.

Dummy thread:

- có stack riêng,
- có KTHREAD riêng,
- có handle riêng,
- có thể terminate riêng.

Nó là sandbox nhỏ cho kernel ROP.

## 28. Tóm tắt chain Connor bằng pseudo-flow

Không code exploit, chỉ flow:

```text
1. Có arbitrary kernel read/write primitive.
2. Tạo dummy thread suspended.
3. Leak KTHREAD của dummy thread qua handle information.
4. Leak KTHREAD.StackBase.
5. Read kernel stack của dummy thread.
6. Tìm return address phù hợp.
7. Ghi ROP chain vào stack.
8. Chain set registers theo Windows x64 ABI.
9. Chain gọi kernel API hợp lệ.
10. Chain lưu return value.
11. Chain gọi ZwTerminateThread để thoát.
12. Resume dummy thread.
13. Main thread đọc kết quả.
```

## 29. Vì sao đây không phải "HVCI bypass" theo nghĩa vulnerability?

Connor nhấn mạnh:

```text
HVCI không bị exploit bug.
```

HVCI hứa:

```text
không execute unsigned kernel code
```

ROP chain:

```text
execute signed existing kernel code
```

Nên HVCI vẫn làm đúng việc của nó.

Exploit chỉ chuyển mục tiêu:

```text
không cần shellcode nếu có thể chain kernel code sẵn có
```

Đây là bypass về chiến thuật exploit, không phải bypass vulnerability của HVCI.

## 30. Vậy mitigation nào chặn chain này?

HVCI:

- chặn shellcode/PTE executable trick.
- không chặn return-oriented use of existing code.

kCFG:

- chặn forward-edge indirect call targets.
- không chặn return addresses.

kCET/shadow stack:

- chặn return address corruption.
- đây là mitigation trực tiếp nhất.

PatchGuard:

- không nhất thiết chặn short-lived stack ROP.
- chặn persistent global kernel patch.

SMEP:

- không ảnh hưởng nếu gadgets ở kernel.

SMAP:

- có thể ảnh hưởng user buffer access tùy IRQL/config.

## 31. Liên hệ với VT-rp Part 2

VT-rp Part 2 nói:

- PW/PWA giúp bảo vệ paging structures hiệu quả.
- GPV chặn aliasing/remapping path.

Connor nói:

- nếu không thể execute shellcode vì HVCI,
- dùng ROP trên existing kernel code.

Hai bài nằm ở hai tầng:

| Chủ đề | Tầng |
|---|---|
| VT-rp/HLAT/GPV | bảo vệ translation/page table path |
| HVCI/kCFG/CET | bảo vệ code execution/control-flow path |
| Connor ROP | kỹ thuật exploit sống trong HVCI/kCFG gap |

Nếu combine:

```text
HVCI chặn shellcode.
kCFG chặn function pointer forward-edge.
kCET chặn return ROP.
VT-rp chặn page-table remapping.
```

Exploit writer bị ép về data-only hoặc bug logic khác.

## 32. Những câu hỏi "vì sao" quan trọng

### Vì sao không patch kCFG bitmap?

Vì HVCI/SLAT protect bitmap. Guest PTE có thể nói writable, nhưng EPT có final say.

### Vì sao không overwrite function pointer?

Vì kCFG kiểm tra indirect call target.

### Vì sao overwrite return address?

Vì kCFG không kiểm tra backward-edge return.

### Vì sao kỹ thuật sẽ chết với kCET?

Vì shadow stack phát hiện return address trên normal stack bị sửa.

### Vì sao không cần shellcode?

Vì ROP dùng code có sẵn.

### Vì sao dummy thread?

Vì disposable execution context.

### Vì sao phải leak KTHREAD?

Vì cần biết kernel stack của thread nào để ghi ROP chain.

### Vì sao cần arbitrary read và write?

Read để leak stack/addresses/validate. Write để đặt chain.

### Vì sao cần kernel stack chứ không user stack?

ROP chạy khi thread đang trong kernel path; return addresses đang trên kernel stack.

### Vì sao gọi `ZwTerminateThread`?

Vì restore stack/register sạch rất khó, terminate disposable thread dễ hơn.

## 33. Những điểm dễ BSOD

| Điểm | Vì sao crash |
|---|---|
| Sai KTHREAD | ghi nhầm kernel memory |
| Sai StackBase | read/write sai page |
| Sai return address | control flow vào garbage |
| Gadget sai | register/stack corrupt |
| Stack alignment sai | API prologue/XMM fault |
| API gọi sai IRQL | kernel bugcheck |
| User buffer access bị SMAP/config chặn | fault |
| Không terminate/restore thread | return path corrupt |
| kCET enabled | shadow stack mismatch |

## 34. Vì sao post này "siêu giá trị"?

Vì nó dạy một pattern rất quan trọng:

```text
When code injection dies, invocation of existing code becomes the goal.
```

Nó cũng cho thấy exploit hiện đại không chỉ là:

```text
write what where -> token steal
```

mà là:

```text
build a reliable execution model under mitigations
```

Các câu hỏi đúng không phải:

- "Làm sao tắt HVCI?"

Mà là:

- "HVCI chặn điều gì chính xác?"
- "Cái gì nó không chặn?"
- "kCFG chặn forward-edge hay backward-edge?"
- "CET đã bật chưa?"
- "Mình có thể dùng existing signed kernel code không?"
- "Mình có disposable kernel context không?"

## 35. Liên hệ với ASTRA64 direct DKOM

ASTRA direct DKOM:

```text
physical R/W -> one data write -> SYSTEM
```

Connor chain:

```text
arbitrary R/W -> stack ROP -> arbitrary kernel API invocation
```

ASTRA direct DKOM tốt nếu:

- mục tiêu chỉ là SYSTEM,
- token field writable,
- offsets đúng.

Connor chain tốt nếu:

- cần gọi kernel APIs,
- token swap chưa đủ,
- muốn emulate shellcode capability.

Nhưng Connor chain fragile hơn:

- ROP,
- stack,
- return address,
- kCET,
- alignment,
- IRQL.

## 36. Liên hệ với AsIO3 PreviousMode

AsIO3:

```text
flip PreviousMode -> use NtRead/NtWrite as kernel R/W
```

Connor:

```text
arbitrary R/W -> use dummy thread stack ROP -> call APIs
```

Cả hai đều tránh shellcode.

Khác nhau:

- AsIO3 biến syscall APIs thành memory R/W.
- Connor biến R/W thành arbitrary kernel API call.

Một cái là:

```text
API boundary confusion
```

Cái kia là:

```text
control-flow reuse under HVCI
```

## 37. Nếu kCET bật thì còn gì?

Nếu kCET shadow stack thật sự enforced:

- return address ROP rất khó.

Exploit phải chuyển sang:

- data-only attacks,
- logic bugs,
- valid indirect call targets,
- callback/object state abuse,
- call-oriented programming qua legitimate dispatch nếu kCFG cho,
- corrupt arguments/state chứ không corrupt return,
- exploit bugs in trusted code paths.

Đây là lý do modern exploit càng ngày càng data-oriented.

## 38. Cách học post Connor

Đọc theo thứ tự:

1. Token stealing baseline.
2. HVCI/SLAT/VBS.
3. MBEC/RUM.
4. kCFG bitmap và forward-edge.
5. Vì sao return address né kCFG.
6. Dummy thread/KTHREAD leak.
7. Kernel stack anatomy.
8. Windows x64 calling convention.
9. ROP chain as API invocation.
10. Cleanup bằng thread termination.
11. kCET as future blocker.

Nếu không hiểu step nào, quay lại concept:

- "Mình đang cần address nào?"
- "Mình đang ghi vào memory nào?"
- "Mitigation nào đang chặn edge nào?"
- "Code nào đang execute: unsigned hay signed existing?"

## 39. Glossary

| Term | Nghĩa |
|---|---|
| HVCI | Hypervisor-protected Code Integrity |
| VBS | Virtualization-Based Security |
| VTL0 | normal kernel world |
| VTL1 | secure kernel world |
| SLAT/EPT | second-level translation, hypervisor memory permissions |
| EPTE | EPT entry |
| MBEC | mode-based execute control |
| RUM | restricted user mode |
| kCFG | kernel Control Flow Guard |
| kCET | kernel Control-flow Enforcement Technology |
| Shadow stack | protected return-address stack |
| KTHREAD | kernel thread object |
| Kernel stack | per-thread stack used in kernel mode |
| IRQL | interrupt request level |
| ROP | return-oriented programming |
| Forward-edge | indirect call/jump |
| Backward-edge | return |

## 40. Kết luận

Connor post có một thông điệp rất rõ:

```text
HVCI giết shellcode, không giết mọi hình thức lợi dụng arbitrary R/W.
```

Khi shellcode chết, exploit chuyển sang:

```text
data-only
existing-code invocation
ROP/call-oriented primitives
semantic field corruption
```

kCFG giết nhiều function pointer hijack, nhưng return ROP còn sống nếu kCET chưa bật.

VT-rp/HLAT/GPV lại đi ở hướng khác: bảo vệ translation path/page-table tricks.

Tổng hợp modern mitigation pressure:

```text
HVCI -> no unsigned kernel code
kCFG -> no arbitrary indirect call target
kCET -> no return-address ROP
KDP -> no direct write to protected data
VT-rp -> no remapping protected LA
```

Exploit hiện đại vì vậy phải hỏi liên tục:

```text
Mitigation này bảo vệ cái gì chính xác?
Cái gì nằm ngoài phạm vi của nó?
Primitive của mình đánh vào edge nào?
Có cách nào đạt goal bằng data-only không?
Có cần code execution thật không?
```


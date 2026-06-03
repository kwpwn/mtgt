# AMDRyzenMasterDriver.sys — Full Reverse Engineering Report
**File:** `C:\Windows\system32\AMDRyzenMasterDriver.sys`  
**Size:** 48328 bytes | **Build:** 2025-12-12  
**Signer:** Advanced Micro Devices Inc. (valid)  
**Service:** AMDRyzenMasterDriverV20 (AUTO_START — luôn chạy)  
**Device:** `\\.\AMDRyzenMasterDriverV20`  
**SDDL:** `D:P(A;;GW;;;BA)(A;;GR;;;BA)` — Administrators only  

---

## 1. Điều kiện truy cập

```
AMD CPU               bắt buộc  (CPUID check tại DriverEntry, đã pass vì driver đang chạy)
Administrator         bắt buộc  (SDDL BA only)
SeLoadDriverPrivilege không cần (khác cpuz161)
Process whitelist     không có  (chỉ ghi log process mở device, không reject)
sc start / sc create  không cần (AUTO_START)
```

Mở device:
```c
HANDLE h = CreateFileW(L"\\\\.\\AMDRyzenMasterDriverV20",
                       GENERIC_READ | GENERIC_WRITE, 0,
                       NULL, OPEN_EXISTING, 0, NULL);
```

---

## 2. IOCTL Table (đầy đủ)

| IOCTL | Function | Input | Output |
|-------|----------|-------|--------|
| `0x81112EE0` | MSR READ (allowlisted) | `{int idx}` 12B | `{int idx, uint64 val}` 12B |
| `0x81112EE4` | MSR WRITE (allowlisted) | `{int idx, uint32 lo, uint32 hi}` 12B | — |
| `0x81112EF8` | PCI READ (HalGetBusData) | `{bus,devfn,?,offset,size}` 20B | data appended |
| **`0x81112F08`** | **Arbitrary PHYS READ** | `{uint64 PA, uint32 sz}` 12B | `{PA,sz,data[sz]}` at +12 |
| **`0x81112F0C`** | **Arbitrary PHYS WRITE** | `{uint64 PA, uint32 sz, data[sz]}` 12+sz B | — |
| `0x81112F18` | CPU info enum | `{count,…}` 28B | device list |
| `0x81112F20` | MPERF/APERF freq ratio | — 8B | `{double ratio}` |
| `0x81112F24` | PCI READ variant | `{d1,d2,d3,d4,size,data}` | data returned |
| `0x81112FF8` | SMU mailbox WRITE | complex 18B | — |
| `0x81112FFC` | Session list query | `{count}` | `{pid,name[64]}×N` |
| `0x81113000` | Driver version | — | `{int 20}` |

---

## 3. Phys READ — `sub_1400023F8`

```c
char phys_read(PHYSICAL_ADDRESS PA, uint32_t size, uint8_t *output) {
    uint8_t *va = MmMapIoSpace(PA, size, MmNonCached);
    if (!va) return 0;                  // NULL → safe, no BSOD
    switch (size) {
        case 1: *output          = *va;          break;
        case 2: *(uint16_t*)output = *(uint16_t*)va; break;
        case 4: *(uint32_t*)output = *(uint32_t*)va; break;
        case 8: *(uint64_t*)output = *(uint64_t*)va; break;
        default: for (i=0; i<size; i++) output[i] = va[i]; break;
    }
    MmUnmapIoSpace(va, size);
    return 1;
}
```

**Không có PA validation.** Tối ưu hóa cho 1/2/4/8 bytes.

---

## 4. Phys WRITE — `sub_140002848`

```c
char phys_write(PHYSICAL_ADDRESS PA, uint32_t size, uint8_t *data) {
    uint8_t *va = MmMapIoSpace(PA, size, MmNonCached);
    if (!va) return 0;                  // NULL → safe, no BSOD
    for (i=0; i<size; i++) va[i] = data[i];   // byte loop, any size
    MmUnmapIoSpace(va, size);
    return 1;
}
```

**Arbitrary PA, arbitrary size, arbitrary data.** Không có range check, không có PA validation.

---

## 5. PA Format — KHÔNG bị swap

```c
// IOCTL 0x81112F08 dispatch:
sub_1400023F8(*v15, *(uint32_t*)(v15+8), (char*)v15+12)
//             ↑ *(uint64_t*)v15 = first 8 bytes = PA (standard little-endian)
```

**Gửi `{uint64_t PA, uint32_t sz}` chuẩn — không có DWORD-swap bug như cpuz161.**

---

## 6. MSR Allowlist (19 entries tại `dword_140006090`)

```
Index  MSR          Tên
  0    0xC0010062   MSRC001_0062  HW_PSTATE_STATUS (current P-state HW)
  1    0xC0010063   MSRC001_0063  CUR_PSTATE
  2    0xC0010061   MSRC001_0061  PSTATE_CURRENT_LIMIT
  3    0xC0010064   MSRC001_0064  PSTATE_DEF_0 (voltage/freq P-state 0)
  4    0xC0010065   MSRC001_0065  PSTATE_DEF_1
  5    0xC0010066   MSRC001_0066  PSTATE_DEF_2
  6    0xC0010067   MSRC001_0067  PSTATE_DEF_3
  7    0xC0010068   MSRC001_0068  PSTATE_DEF_4
  8    0xC0010015   MSRC001_0015  HWCR (Hardware Configuration Register)
  9    0x000000E7   IA32_MPERF   (max perf freq clock counter)
 10    0x000000E8   IA32_APERF   (actual perf freq clock counter)
 11    0xC0010290   MSRC001_0290 IBS_FETCH_CTL (AMD IBS fetch control)
 12    0xC0010292   MSRC001_0292 IBS related
 13    0xC0010293   MSRC001_0293 IBS related
 14    0x0000008B   IA32_BIOS_SIGN_ID (microcode version)
 15    0xC00102B0   MSRC001_02B0 SMU/NB power management
 16    0xC00102B1   MSRC001_02B1
 17    0xC00102B3   MSRC001_02B3
 18    0xC00102B4   MSRC001_02B4
```

MSR truy cập qua **index** (0-18), không phải raw MSR number:
```c
// READ: input = {int index} → reads dword_140006090[index]
__readmsr(dword_140006090[index]);

// WRITE: input = {int index, uint32 lo, uint32 hi}
__writemsr(dword_140006090[index], lo | ((uint64_t)hi << 32));
```

**Đáng chú ý:** HWCR (0xC0010015) cho phép modify hardware config. P-state MSRs cho CPU overclocking. KHÔNG có LSTAR/EFER/SYSENTER.

---

## 7. PCI Operations

### PCI READ (`0x81112EF8`, `0x81112F24`)
```c
HalGetBusDataByOffset(PCIConfiguration, bus, (dev<<5)|func, buffer, offset, size);
// Không có offset limit
```

### SMU Mailbox WRITE (`0x81112FF8`)
```c
// Lookup CPU bus number từ internal table
// Sau đó:
HalSetBusDataByOffset(PCIConfiguration, bus, (dev<<5)|func, buffer, offset, size);
// CÓ limit: offset < 0x100 (standard PCI config space only, no extended)
```

### PCI WRITE direct (`0x81112F0C` điều hướng qua `sub_140002988`)
Khác với phys WRITE — đây là PCI config write qua HAL, cũng có `offset < 0x100` limit.

---

## 8. Session Tracking

IRP_MJ_CREATE không block ai, chỉ ghi log:
```c
// Allocate 80-byte entry per opener:
struct session_entry {
    uint32_t pid;           // +0x00
    char     name[64];      // +0x04  PsGetProcessImageFileName
    uint64_t next;          // +0x48  linked list
};
qword_140006370 → linked list head
```

IOCTL `0x81112FFC` cho phép enumerate tất cả sessions (list process nào đang có handle).

---

## 9. Safety Analysis

| Risk | Verdict |
|------|---------|
| BSOD từ invalid PA (READ) | **Safe** — MmMapIoSpace NULL check |
| BSOD từ invalid PA (WRITE) | **Safe nếu** có user-mode range guard |
| BSOD từ paging pages | **Safe** — MmMapIoSpace block Win10 1803+ |
| MMIO READ | **Safe** — returns hardware value, no side effect |
| MMIO WRITE | **BSOD risk** — phải guard bằng registry ranges |

**User-mode guard cần thiết cho WRITE:**
```c
// Trước mọi phys_write(), verify PA trong registry RAM ranges
if (!pa_in_range(pa, sz)) { /* BLOCK */ return 0; }
```

---

## 10. So Sánh với cpuz161

| Feature | cpuz161 | AMD Ryzen Master |
|---------|---------|-----------------|
| Phys READ | ✅ (PA swap bug) | ✅ **Clean** |
| Phys WRITE | ❌ Removed | ✅ **Arbitrary** |
| PA format | `{pa_hi, pa_lo, sz}` SWAP | `{uint64_t PA, uint32_t sz}` chuẩn |
| PA validation | Registry ranges (sub_11220) | Không có |
| MSR allowlist | Nhiều hơn (LSTAR blocked) | 19 AMD-specific |
| SeLoadDriverPrivilege | Cần (some IOCTLs) | **Không cần** |
| Process whitelist | Không | Không |
| Deployment | sc start | **AUTO_START** |
| Access | Admin + SeLoadDriver | **Admin only** |
| Low Stub (PA 0x1000) | Zeros (registry blocked) | ✅ **Real data** |

---

## 11. BYOVD Assessment

**Rating: HIGH** — driver tốt hơn cpuz161 cho phần lớn attack scenarios.

```
Primitive chính:   Arbitrary Physical Read + Write
Deployment:        Zero (AUTO_START)
Access control:    Admin only (SDDL BA)
PA format:         Standard uint64_t (no bug)
Size limit:        None (MmMapIoSpace handles any size)
Constraints:       Registry range guard needed for WRITE (user-side)
HVCI data bypass:  YES — MmMapIoSpace writes to data pages
HVCI code bypass:  Need to verify (MmMapIoSpace paging restriction)
```

*Analysis date: May 2026 | Driver build: 2025-12-12*

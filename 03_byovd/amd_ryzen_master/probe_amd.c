/*
 * probe_amd.c — AMD Ryzen Master Driver safety probe
 *
 * Driver: AMDRyzenMasterDriverV20 (AUTO_START, no SeLoadDriverPrivilege needed)
 * Device: \\.\AMDRyzenMasterDriverV20
 * SDDL:   D:P(A;;GW;;;BA)(A;;GR;;;BA) — Administrators only
 *
 * IOCTL 0x81112F08 = Phys READ
 *   IN:  { uint64_t PA; uint32_t sz }  12 bytes
 *   OUT: { uint64_t PA; uint32_t sz; uint8_t data[sz] }  12+sz bytes
 *   Driver: MmMapIoSpace(PA, sz, NC) → read → unmap
 *   NO PA validation in driver — must guard from user side!
 *
 * IOCTL 0x81112F0C = Phys WRITE
 *   IN:  { uint64_t PA; uint32_t sz; uint8_t data[sz] }  12+sz bytes
 *   Driver: MmMapIoSpace(PA, sz, NC) → write → unmap
 *   NO PA validation — ONLY write to registry-verified RAM ranges!
 *
 * Safety: load physical RAM ranges from registry (same as cpuz161 tools).
 *         MmMapIoSpace returns NULL for paging pages (Win10 1803+) — safe.
 *         MMIO ranges are mappable and writable — BSOD risk on write.
 *
 * Build:
 *   cl /nologo /W3 /O2 probe_amd.c /link kernel32.lib advapi32.lib
 *
 * Run as Administrator (SDDL requires BA).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_NAME     L"\\\\.\\AMDRyzenMasterDriverV20"
#define IOCTL_PHYS_READ  0x81112F08u
#define IOCTL_PHYS_WRITE 0x81112F0Cu

/* ── Physical memory ranges from registry ────────────────────────────────── */
#define MAX_RANGES 64
typedef struct { uint64_t base, size; } PhysRange;
static PhysRange g_ranges[MAX_RANGES];
static int       g_nranges = 0;

static void load_ranges(void)
{
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
          "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
          0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        printf("  [!] Cannot open Physical Memory registry key\n");
        return;
    }
    char vname[256]; DWORD vname_sz, vdata_sz, type;
    uint8_t *buf = NULL; DWORD sz = 0;
    for (DWORD idx = 0; ; idx++) {
        vname_sz = sizeof vname; vdata_sz = 0;
        LONG r = RegEnumValueA(hKey, idx, vname, &vname_sz, NULL, &type, NULL, &vdata_sz);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if ((type != 3 && type != 8) || vdata_sz < 20) continue;
        buf = (uint8_t*)malloc(vdata_sz);
        if (!buf) continue;
        if (RegQueryValueExA(hKey, vname, NULL, NULL, buf, &vdata_sz) == ERROR_SUCCESS) {
            sz = vdata_sz; break;
        }
        free(buf); buf = NULL;
    }
    RegCloseKey(hKey);
    if (!buf || sz < 20) { free(buf); return; }

    DWORD count = *(DWORD*)(buf + 16);
    uint8_t *p  = buf + 20;
    for (DWORD i = 0; i < count && g_nranges < MAX_RANGES; i++, p += 20) {
        if (p + 20 > buf + sz) break;
        if (p[0] != 3) continue;
        uint64_t base = *(uint64_t*)(p + 4);
        uint64_t len  = *(uint64_t*)(p + 12);
        printf("  [range %d] PA 0x%012llX  +%llu MB\n",
               g_nranges, (unsigned long long)base, (unsigned long long)(len>>20));
        g_ranges[g_nranges].base = base;
        g_ranges[g_nranges].size = len;
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

/* ── IOCTL wrappers ──────────────────────────────────────────────────────── */
static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* Phys READ: input = {uint64_t PA, uint32_t sz}, output at out[12..12+sz] */
static int phys_read(uint64_t pa, void *buf, uint32_t sz)
{
    struct { uint64_t pa; uint32_t sz; } in = {pa, sz};
    uint32_t out_sz = 12 + sz;
    uint8_t *out    = (uint8_t*)calloc(1, out_sz);
    if (!out) return 0;
    DWORD got = 0;
    BOOL  ok  = DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                                &in, sizeof(in), out, out_sz, &got, NULL);
    if (ok && got >= 12)
        memcpy(buf, out + 12, sz);
    free(out);
    return ok && got >= 12;
}

/* Phys WRITE: input = {uint64_t PA, uint32_t sz, uint8_t data[sz]}
 * GUARD: only write to registry-validated RAM ranges! */
static int phys_write(uint64_t pa, const void *data, uint32_t sz)
{
    /* Safety: reject if PA not in valid RAM range */
    if (!pa_in_range(pa, sz)) {
        printf("  [BLOCKED] phys_write PA 0x%llX not in valid RAM range!\n",
               (unsigned long long)pa);
        return 0;
    }
    uint32_t in_sz = 12 + sz;
    uint8_t *in_buf = (uint8_t*)malloc(in_sz);
    if (!in_buf) return 0;
    *(uint64_t*)(in_buf + 0) = pa;
    *(uint32_t*)(in_buf + 8) = sz;
    memcpy(in_buf + 12, data, sz);
    DWORD got = 0;
    BOOL  ok  = DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                                in_buf, in_sz, NULL, 0, &got, NULL);
    free(in_buf);
    return ok;
}

/* ── hex dump ────────────────────────────────────────────────────────────── */
static void hexdump(const uint8_t *p, size_t n, uint64_t base)
{
    for (size_t i = 0; i < n; i += 16) {
        printf("  %012llX  ", (unsigned long long)(base + i));
        for (size_t j = 0; j < 16; j++) {
            if (i+j < n) printf("%02x ", p[i+j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf("\n");
    }
}

/* ════════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("=== AMD Ryzen Master Driver — Safety Probe ===\n\n");

    /* 1. Load valid physical RAM ranges */
    printf("[1] Physical memory ranges from registry:\n");
    load_ranges();
    if (g_nranges == 0) {
        printf("  [!] No ranges loaded — ABORTING (BSOD risk without guard)\n");
        return 1;
    }
    printf("  [+] %d ranges loaded\n\n", g_nranges);

    /* 2. Open device (requires Administrator) */
    printf("[2] Opening device...\n");
    g_dev = CreateFileW(DEVICE_NAME,
                        GENERIC_READ | GENERIC_WRITE, 0,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("  [-] CreateFile failed: %lu\n", GetLastError());
        printf("  [?] Check: run as Administrator? AMD CPU? Driver running?\n");
        return 1;
    }
    printf("  [+] Device opened (no SeLoadDriverPrivilege needed)\n\n");

    /* 3. Test READ at safe PA (first valid range base + 1MB offset) */
    printf("[3] READ test — PA within first valid range:\n");
    {
        uint64_t test_pa = g_ranges[0].base;
        /* Find a range with at least 64 bytes */
        for (int i = 0; i < g_nranges; i++) {
            if (g_ranges[i].size >= 64) { test_pa = g_ranges[i].base; break; }
        }
        uint8_t buf[64] = {0};
        if (phys_read(test_pa, buf, sizeof buf)) {
            printf("  [+] READ OK at PA 0x%llX:\n", (unsigned long long)test_pa);
            hexdump(buf, sizeof buf, test_pa);
        } else {
            printf("  [-] READ failed at PA 0x%llX (err=%lu)\n",
                   (unsigned long long)test_pa, GetLastError());
        }
    }

    /* 4. Test READ at PA 0x1000000 (1MB — should be in range on most systems) */
    printf("\n[4] READ test — PA 0x1000000 (typical RAM start):\n");
    {
        uint64_t pa = 0x1000000;
        uint8_t buf[16] = {0};
        if (!pa_in_range(pa, sizeof buf)) {
            printf("  [?] PA 0x1000000 not in registry ranges — skipping\n");
        } else if (phys_read(pa, buf, sizeof buf)) {
            printf("  [+] READ OK: ");
            for (int i = 0; i < 16; i++) printf("%02X ", buf[i]);
            printf("\n");
        } else {
            printf("  [-] READ failed\n");
        }
    }

    /* 5. Test READ outside range — expect MmMapIoSpace NULL → IOCTL fails */
    printf("\n[5] READ test — MMIO address 0xFED80000 (HPET, outside RAM):\n");
    {
        uint64_t pa = 0xFED80000;
        uint8_t buf[4] = {0};
        if (pa_in_range(pa, 4)) {
            printf("  [?] Unexpected: HPET PA in registry RAM range\n");
        }
        /* This is intentionally NOT guarded — testing MmMapIoSpace behavior */
        printf("  [*] Attempting direct READ (no range guard — testing driver safety)...\n");
        BOOL ok = FALSE;
        {
            struct { uint64_t pa; uint32_t sz; } in = {pa, 4};
            uint8_t out[16] = {0};
            DWORD got = 0;
            ok = DeviceIoControl(g_dev, IOCTL_PHYS_READ, &in, 12, out, 16, &got, NULL);
            if (ok && got >= 12) {
                uint32_t val = *(uint32_t*)(out + 12);
                printf("  [+] MmMapIoSpace mapped MMIO PA — value=0x%08X\n", val);
                printf("  [!] WARNING: MMIO readable — do NOT write here!\n");
            } else {
                printf("  [?] IOCTL returned false (err=%lu) — MmMapIoSpace may have returned NULL\n",
                       GetLastError());
                printf("  [+] Driver's NULL check protected us from BSOD\n");
            }
        }
    }

    /* 6. WRITE guard test — attempt write outside range (should be blocked) */
    printf("\n[6] WRITE guard test — attempt write to MMIO PA:\n");
    {
        uint64_t pa = 0xFED80000;
        uint32_t val = 0xDEADBEEF;
        if (!pa_in_range(pa, 4)) {
            printf("  [+] User-mode guard BLOCKED write to PA 0x%llX (not in RAM range)\n",
                   (unsigned long long)pa);
        }
    }

    /* 7. Summary */
    printf("\n=== SAFETY SUMMARY ===\n");
    printf("READ  safety: MmMapIoSpace NULL check in driver → no BSOD on invalid PA\n");
    printf("WRITE safety: user-mode pa_in_range() guard → MMIO write blocked\n");
    printf("Paging pages: MmMapIoSpace blocked by Win10 1803+ → NULL → safe\n");
    printf("\nDevice:  \\\\.\\AMDRyzenMasterDriverV20\n");
    printf("READ:    IOCTL 0x81112F08  IN={uint64 PA, uint32 sz}\n");
    printf("WRITE:   IOCTL 0x81112F0C  IN={uint64 PA, uint32 sz, data[sz]}\n");
    printf("Requires: Administrator only (no SeLoadDriverPrivilege)\n");

    CloseHandle(g_dev);
    return 0;
}

// probe_devs.c - probe world-accessible device IOCTLs
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

static HANDLE open_dev(const char *name) {
    return CreateFileA(name, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
                       NULL, OPEN_EXISTING, 0, NULL);
}

static void probe_ioctls(const char *devname, uint32_t devtype_start, uint32_t devtype_end) {
    HANDLE h = open_dev(devname);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        printf("%-30s open err=%lu\n", devname, e);
        return;
    }
    printf("%-30s OPENED\n", devname);

    uint8_t inbuf[512] = {0};
    uint8_t outbuf[512] = {0};
    DWORD ret = 0;

    for (uint32_t dt = devtype_start; dt <= devtype_end; dt++) {
        for (uint32_t fn = 0; fn <= 0x40; fn++) {
            uint32_t code = (dt << 16) | (fn << 2); // METHOD_BUFFERED, ANY_ACCESS
            ret = 0;
            memset(outbuf, 0, sizeof(outbuf));
            BOOL ok = DeviceIoControl(h, code, inbuf, sizeof(inbuf), outbuf, sizeof(outbuf), &ret, NULL);
            DWORD err = GetLastError();
            if (ok) {
                printf("  IOCTL 0x%08X: OK ret=%lu out[0..7]=%02X %02X %02X %02X %02X %02X %02X %02X\n",
                    code, ret,
                    outbuf[0],outbuf[1],outbuf[2],outbuf[3],
                    outbuf[4],outbuf[5],outbuf[6],outbuf[7]);
            } else if (err != ERROR_INVALID_FUNCTION && err != ERROR_NOT_SUPPORTED) {
                // Only print non-standard errors (skip "function not supported")
                if (err != 87 && err != 50) { // not ERROR_INVALID_PARAMETER or ERROR_NOT_SUPPORTED
                    printf("  IOCTL 0x%08X: err=%lu\n", code, err);
                }
            }
        }
    }
    CloseHandle(h);
}

int main(void) {
    printf("=== Device IOCTL Probe ===\n\n");

    // Probe amdlog (world-accessible)
    printf("--- amdlog ---\n");
    probe_ioctls("\\\\.\\amdlog", 0x8000, 0x8002);
    probe_ioctls("\\\\.\\amdlog", 0x9C40, 0x9C43);
    probe_ioctls("\\\\.\\amdlog", 0x22, 0x22);

    // Probe amdpsp with known codes
    printf("\n--- amdpsp IOCTLs 0x9C4228xx ---\n");
    {
        HANDLE h = open_dev("\\\\.\\amdpsp");
        if (h != INVALID_HANDLE_VALUE) {
            uint8_t inbuf[512] = {0};
            uint8_t outbuf[512] = {0};
            DWORD ret = 0;
            // Known codes from IDA analysis
            uint32_t codes[] = {
                0x9C422804, 0x9C422808, 0x9C42280C, 0x9C422810,
                0x9C422814, 0x9C422818, 0x9C422820, 0x9C422824,
                0x9C422828, 0x9C422830, 0x9C422834, 0x9C422838,
                0x9C42283C, 0x9C422844, 0x9C422848, 0x9C42284C,
                0x9C422850, 0x9C422854
            };
            for (int i = 0; i < (int)(sizeof(codes)/sizeof(codes[0])); i++) {
                ret = 0; memset(outbuf, 0, sizeof(outbuf));
                BOOL ok = DeviceIoControl(h, codes[i], inbuf, 512, outbuf, 512, &ret, NULL);
                DWORD err = GetLastError();
                printf("  0x%08X: %s ret=%lu err=%lu\n", codes[i], ok?"OK":"FAIL", ret, err);
            }
            CloseHandle(h);
        } else {
            printf("amdpsp open err=%lu\n", GetLastError());
        }
    }

    // Also try uiomap (will get err=5 but confirm it exists)
    printf("\n--- uiomap ---\n");
    {
        HANDLE h = open_dev("\\\\.\\uiomap");
        printf("uiomap: %s err=%lu\n", h!=INVALID_HANDLE_VALUE?"OK":"FAIL", GetLastError());
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    return 0;
}

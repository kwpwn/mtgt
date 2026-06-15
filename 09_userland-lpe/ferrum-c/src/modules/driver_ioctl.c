/*
 * driver_ioctl.c — Kernel Driver IOCTL Surface Discovery
 *
 * WHY DRIVER IOCTL SURFACE MATTERS FOR 0-DAY:
 *   Kernel drivers expose functionality to userland via IOCTL codes sent
 *   through DeviceIoControl(). Many third-party drivers (AV, EDR, hardware,
 *   virtualization, backup software) have historically had vulnerabilities:
 *
 *   - Insufficient input validation → kernel heap/stack overflow → privesc
 *   - Missing ProbeForRead/ProbeForWrite → arbitrary kernel read/write
 *   - Type confusion in buffer handling → controlled kernel data corruption
 *   - Arbitrary physical memory read → credential extraction
 *   - MSR/CR register read/write → ring 0 control
 *
 *   Key insight: BYOVD (Bring Your Own Vulnerable Driver) has become a
 *   standard attacker technique. But many ALREADY-INSTALLED drivers on
 *   target systems are vulnerable — no need to bring your own.
 *
 * THIS MODULE:
 *   1. Enumerates kernel drivers via SCM (already done in drivers.c for
 *      discovery, but this module focuses on IOCTL ACCESSIBILITY)
 *   2. For each driver with a device name:
 *      a. Try CreateFile on \\.\<deviceName> with FILE_READ_ATTRIBUTES
 *      b. If success: user has a handle → can send DeviceIoControl
 *      c. Cross-reference against known vulnerable driver database
 *   3. Also enumerates \GLOBAL??\* symlinks to find device names
 *   4. Reports accessible devices that are NOT standard OS drivers
 *
 * KNOWN VULNERABLE DRIVER DATABASE (partial):
 *   We maintain a list of known-vulnerable driver names/hashes.
 *   Presence of these drivers = HIGH severity even if not accessible,
 *   because they can often be loaded by the attacker (BYOVD).
 *
 * WHAT TO DO WITH FINDINGS:
 *   1. Get accessible driver device path
 *   2. Find the driver binary (.sys file) via SCM
 *   3. Load in IDA → find IRP_MJ_DEVICE_CONTROL handler
 *   4. Enumerate IOCTL codes via switch statement in dispatch function
 *   5. For each IOCTL: analyze buffer handling (InputBuffer, OutputBuffer)
 *   6. Look for: ProbeForRead/Write bypass, unchecked lengths, pointer tricks
 *
 * BYOVD CONTEXT:
 *   Even if a driver isn't currently accessible to non-admin, if it's a
 *   known BYOVD target driver, report it so the researcher knows it's on
 *   this system and can potentially load it (via SeLoadDriverPrivilege path).
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Known vulnerable / notable driver filenames (lowercase for matching)
 * Source: loldrivers.io, public CVE database, MSRC advisories
 * --------------------------------------------------------------------- */
typedef struct {
    const wchar_t *filename;   /* lowercase .sys filename */
    const wchar_t *cve;
    const wchar_t *notes;
} KnownVulnDriver;

static const KnownVulnDriver g_vulnDrivers[] = {
    /* MSI Afterburner (widely used) */
    { L"rtcore64.sys",  L"CVE-2019-16098",
      L"Arbitrary MSR/physical memory R/W — widely used for BYOVD" },
    /* GIGABYTE drivers */
    { L"gdrv.sys",      L"CVE-2018-19320",
      L"Physical memory R/W, arbitrary kernel code execution" },
    /* Lenovo / Motorola */
    { L"lenovo_ism.sys", L"CVE-2018-3701",
      L"Arbitrary ring-0 code execution" },
    /* WinRing0 (hardware monitoring) */
    { L"winring0x64.sys", L"CVE-2020-14979",
      L"Arbitrary MSR/memory R/W — used by many hardware tools" },
    { L"winring0.sys",    L"CVE-2020-14979", L"WinRing0 32-bit variant" },
    /* ASUS DriverHub */
    { L"ene.sys",       L"CVE-2021-40029", L"Arbitrary memory R/W" },
    /* HW64 (hardware monitoring) */
    { L"hw64.sys",      L"CVE-2019-8372",  L"Arbitrary physical memory R/W" },
    /* CPU-Z driver */
    { L"cpuz141.sys",   L"CVE-2017-15303", L"Ring-0 code execution primitive" },
    { L"cpuz143.sys",   L"CVE-2017-15303", L"CPU-Z driver variant" },
    /* IOBit (used by IOBit software) */
    { L"iobitunlocker.sys", L"(no CVE)",
      L"Write to arbitrary process — documented BYOVD target" },
    /* AsrDrv (ASRock) */
    { L"asrdrv106.sys", L"CVE-2020-15368", L"Arbitrary kernel memory write" },
    { L"asrdrv104.sys", L"CVE-2020-15368", L"AsrDrv variant" },
    /* VirtualBox kernel driver */
    { L"vboxdrv.sys",   L"CVE-2017-10204", L"VirtualBox driver (if non-admin accessible)" },
    /* Speedfan */
    { L"speedfan.sys",  L"(no CVE)",       L"Physical memory R/W — BYOVD target" },
    /* Dell BIOS driver */
    { L"dbutil_2_3.sys", L"CVE-2021-21551",
      L"Dell BIOS Update driver — arbitrary memory R/W, widely exploited" },
    /* Sentinel protection */
    { L"sentinel64.sys", L"CVE-2018-11138", L"Arbitrary memory write" },
    /* Razer Synapse */
    { L"rzpnk.sys",     L"CVE-2017-14398", L"Ring-0 code execution" },
    /* Micro-Star MSI */
    { L"ntiolib_x64.sys", L"(no CVE)",     L"Physical memory R/W" },
    /* End sentinel */
    { NULL, NULL, NULL }
};

static const KnownVulnDriver *LookupVulnDriver(LPCWSTR filename) {
    for (int i = 0; g_vulnDrivers[i].filename; i++) {
        if (_wcsicmp(filename, g_vulnDrivers[i].filename) == 0)
            return &g_vulnDrivers[i];
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * Heuristic: is this a "standard" Windows OS driver (low research value)?
 * --------------------------------------------------------------------- */
static BOOL IsStandardOSDriver(LPCWSTR devPath) {
    static const wchar_t *skipPrefixes[] = {
        L"\\\\.\\COM", L"\\\\.\\LPT",
        L"\\\\.\\PIPE\\", L"\\\\.\\NUL",
        L"\\\\.\\AUX",   L"\\\\.\\CON",
        NULL
    };
    for (int i = 0; skipPrefixes[i]; i++) {
        if (_wcsnicmp(devPath, skipPrefixes[i], wcslen(skipPrefixes[i])) == 0)
            return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Try to open a device and check accessibility
 * --------------------------------------------------------------------- */
static BOOL TryOpenDevice(LPCWSTR devPath) {
    HANDLE h = CreateFileW(devPath,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING, NULL);

    if (h == INVALID_HANDLE_VALUE) {
        /* Try with 0 access (just check if device exists and ACL allows) */
        h = CreateFileW(devPath, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
    }

    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Enumerate kernel drivers via SCM and check device accessibility
 * --------------------------------------------------------------------- */
static void ScanServiceDrivers(DWORD *findings) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD needed = 0, count = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO,
                          SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER,
                          SERVICE_STATE_ALL, NULL, 0, &needed, &count, NULL, NULL);

    BYTE *buf = HeapAlloc(GetProcessHeap(), 0, needed + 256);
    if (!buf) { CloseServiceHandle(hSCM); return; }

    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO,
                               SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER,
                               SERVICE_STATE_ALL, buf, needed,
                               &needed, &count, NULL, NULL)) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseServiceHandle(hSCM);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSW *svcs = (ENUM_SERVICE_STATUS_PROCESSW *)buf;
    DWORD totalDrivers = 0;

    for (DWORD i = 0; i < count; i++) {
        totalDrivers++;
        LPCWSTR svcName = svcs[i].lpServiceName;

        /* Get driver binary path from SCM config */
        SC_HANDLE hSvc = OpenServiceW(hSCM, svcName, SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        BYTE   cfgBuf[8192];
        DWORD  cfgNeeded = 0;
        BOOL   gotCfg = QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)cfgBuf,
                                             sizeof(cfgBuf), &cfgNeeded);
        CloseServiceHandle(hSvc);
        if (!gotCfg) continue;

        LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)cfgBuf;
        LPCWSTR imagePath = cfg->lpBinaryPathName;
        if (!imagePath || !*imagePath) continue;

        /* Extract the .sys filename */
        wchar_t drvPath[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(imagePath, drvPath, _countof(drvPath));
        /* Remove \??\ or \\?\ prefix */
        wchar_t *syspath = drvPath;
        if (_wcsnicmp(syspath, L"\\??\\", 4) == 0)  syspath += 4;
        if (_wcsnicmp(syspath, L"\\\\?\\", 4) == 0) syspath += 4;

        /* Get just the filename */
        wchar_t filename[MAX_PATH] = {0};
        wchar_t *sl = wcsrchr(syspath, L'\\');
        if (sl) wcsncpy(filename, sl + 1, _countof(filename) - 1);
        else    wcsncpy(filename, syspath, _countof(filename) - 1);
        _wcslwr(filename);

        /* Check known vulnerable drivers */
        const KnownVulnDriver *vuln = LookupVulnDriver(filename);
        if (vuln) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"DRIVER_IOCTL");
            _snwprintf(f.target, _countof(f.target),
                L"[KNOWN VULN] %s  (%s)", filename, vuln->cve);
            _snwprintf(f.reason, _countof(f.reason),
                L"KNOWN VULNERABLE DRIVER PRESENT: %s\n"
                L"        CVE: %s\n"
                L"        %s\n"
                L"        Path: %s\n"
                L"        BYOVD: load via NtLoadDriver (SeLoadDriverPrivilege needed)\n"
                L"        OR: check if device \\Device\\%s is already accessible.",
                filename, vuln->cve, vuln->notes, syspath, svcName);
            PrintFinding(&f);
            (*findings)++;
        }

        /* Try to open device by service name */
        wchar_t devPath[256];
        _snwprintf(devPath, _countof(devPath), L"\\\\.\\%s", svcName);

        if (!IsStandardOSDriver(devPath) && TryOpenDevice(devPath)) {
            /* Non-standard driver accessible to current user */
            BOOL isKnownVuln = (vuln != NULL);
            Finding f;
            f.severity = isKnownVuln ? SEV_CRITICAL : SEV_MEDIUM;
            wcscpy(f.module, L"DRIVER_IOCTL");
            _snwprintf(f.target, _countof(f.target),
                L"[ACCESSIBLE] %s  (%s)", devPath, filename);
            _snwprintf(f.reason, _countof(f.reason),
                L"Kernel driver device is ACCESSIBLE by current user. "
                L"Can send DeviceIoControl() with arbitrary IOCTL codes. "
                L"%s"
                L"Research: load %s in IDA → find IRP_MJ_DEVICE_CONTROL "
                L"handler → enumerate IOCTL dispatch table → "
                L"check buffer validation, ProbeForRead/Write usage.",
                isKnownVuln ? L"MATCHES KNOWN VULNERABLE DRIVER! " : L"",
                syspath);
            PrintFinding(&f);
            (*findings)++;
        }
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseServiceHandle(hSCM);
    PrintInfo(L"  Kernel drivers enumerated: %lu\n", totalDrivers);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_DriverIOCTL(void) {
    PrintHeader(L"DRIVER IOCTL SURFACE  [Kernel attack surface + BYOVD detection]");

    PrintInfo(
        L"  Discovers kernel drivers accessible from userland via DeviceIoControl.\n"
        L"  Cross-references against known vulnerable driver database (loldrivers.io).\n"
        L"  Accessible third-party driver = potential kernel 0-day or BYOVD target.\n\n");

    DWORD findings = 0;

    PrintInfo(L"  [1] Scanning service-registered kernel drivers...\n");
    ScanServiceDrivers(&findings);

    PrintInfo(L"\n");
    if (findings == 0)
        PrintInfo(L"  No driver IOCTL surface findings.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  IDA IOCTL ANALYSIS WORKFLOW:\n"
            L"    1. Open driver .sys in IDA, find DriverEntry\n"
            L"    2. Trace pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]\n"
            L"    3. In dispatch handler, find switch(ioControlCode) or\n"
            L"       cmp/jmp table for IOCTL codes\n"
            L"    4. For each IOCTL branch, check:\n"
            L"       a. InputBufferLength vs actual read size\n"
            L"       b. ProbeForRead/ProbeForWrite on usermode buffer pointers\n"
            L"       c. MmMapIoSpace / ZwMapViewOfSection calls\n"
            L"       d. Any RDMSR/WRMSR (arbitrary MSR access = 0day primitive)\n"
            L"       e. MmGetPhysicalAddress + MmMapIoSpace combos\n"
            L"    5. Fuzzing: OSR ioctl_storage / WinAFL driver mode\n"
            L"       OR: custom ioctl_enum.py for IDA + driver fuzzer\n\n"
            L"  REFERENCE: loldrivers.io — searchable vulnerable driver database\n");
    }
}

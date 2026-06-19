/*
 * font_provider.c — Font Provider / DWrite Font Loading Surface
 *
 * WHY FONT PROVIDERS ARE AN LPE SURFACE:
 *   Windows font loading involves multiple SYSTEM services and trusted processes:
 *
 *   1. FONT CACHE SERVICE (FontCache, FontCache3.0.0.0):
 *      Runs as NT AUTHORITY\LOCAL SERVICE (or SYSTEM in some configs).
 *      Caches font data. If font cache files/directories are user-writable:
 *      → DoS or potential TOCTOU on font cache parsing.
 *
 *   2. CUSTOM FONT PROVIDER (Windows 10+):
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts\
 *      Font files registered here are loaded by all processes (including SYSTEM).
 *      A writable font file = potential exploit via font parsing in kernel (win32k).
 *
 *   3. FONT PROVIDER REGISTRY (HKLM):
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Service Providers\
 *      Registered font provider DLLs. If writable → DLL loaded by font subsystem.
 *
 *   4. DirectWrite Font File Loaders:
 *      Third-party font managers (Adobe, Monotype, Extensis) register
 *      custom DWrite font file loaders via COM. These DLLs are loaded by
 *      any process using DWrite (including Office, Edge, Explorer).
 *      If these DLLs are in user-writable paths → code injection.
 *
 *   5. FONT SUBSTITUTION:
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\FontSubstitutes\
 *      Maps one font name to another. Some font substitute paths can point
 *      to font files in user-writable locations.
 *
 *   6. OPENTYPE/TRUETYPE FONT FILES in User-writable Directories:
 *      Registered fonts stored in locations like %APPDATA%\fonts\ or
 *      per-user font directories. If font file is writable + exploitable
 *      font parser vulnerability → ring0 escalation via win32k.
 *
 * NOVEL ANGLE:
 *   Font provider COM DLL registration paths are completely unchecked
 *   by any existing tool. Third-party font software often installs into
 *   paths writable by standard users.
 *
 * REFERENCES:
 *   CVE-2020-1435: Windows Font Driver Host Remote Code Execution
 *   CVE-2021-24091: Windows Camera Codec Pack Remote Code Execution (font parser)
 *   Google Project Zero: kernel font parsing vulnerabilities (multiple)
 *   MITRE ATT&CK: T1547.006 — Boot or Logon Autostart: Kernel Modules and Extensions
 */

#include "../common.h"

#define FONTS_KEY          L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts"
#define FONT_PROVIDERS_KEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Font Service Providers"
#define FONT_SUBSTITUTES   L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes"

/* -----------------------------------------------------------------------
 * Check Font Service Provider DLLs
 * --------------------------------------------------------------------- */
static void AuditFontProviderDLLs(DWORD *findings) {
    PrintInfo(L"  [1] Font Service Provider DLLs:\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, FONT_PROVIDERS_KEY,
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        PrintInfo(L"    (key not present)\n\n");
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t valueName[256];
    wchar_t valueData[MAX_PATH * 2];
    DWORD   vNameCch, vDataCb, type;

    while (TRUE) {
        vNameCch = _countof(valueName);
        vDataCb  = sizeof(valueData);
        LONG r = RegEnumValueW(hKey, idx++, valueName, &vNameCch,
                               NULL, &type, (LPBYTE)valueData, &vDataCb);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(valueData, expanded, _countof(expanded));

        BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(expanded);

        PrintInfo(L"    Provider: %s → %s%s\n",
                  valueName, expanded,
                  writable ? L" [WRITABLE!]" :
                  (!exists ? L" [MISSING]" : L""));

        if (writable || !exists) {
            Finding f;
            f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
            wcscpy(f.module, L"FONT");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] Font Provider DLL: %s",
                writable ? L"WRITABLE" : L"MISSING", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Font Service Provider DLL is %s: %s\n"
                L"        Provider name: %s\n"
                L"        This DLL is loaded by the Font Cache service and all font-using processes.\n"
                L"        %s → code execution in any font-using process.",
                writable ? L"WRITABLE" : L"MISSING (plant DLL)",
                expanded, valueName,
                writable ? L"Replace DLL" : L"Plant DLL at path");
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hKey);
    if (count == 0) PrintInfo(L"    (no entries)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check registered font file paths for writability
 * --------------------------------------------------------------------- */
static void AuditRegisteredFontFiles(DWORD *findings) {
    PrintInfo(L"  [2] Registered font file paths (user-writable fonts):\n");

    wchar_t winFonts[MAX_PATH * 2] = {0};
    wchar_t sysRoot[MAX_PATH] = {0};
    GetWindowsDirectoryW(sysRoot, _countof(sysRoot));
    _snwprintf(winFonts, _countof(winFonts), L"%s\\Fonts", sysRoot);

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, FONTS_KEY,
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open Fonts key\n\n");
        return;
    }

    DWORD idx = 0, total = 0, suspicious = 0;
    wchar_t valueName[256];
    wchar_t valueData[MAX_PATH * 2];
    DWORD   vNameCch, vDataCb, type;

    while (TRUE) {
        vNameCch = _countof(valueName);
        vDataCb  = sizeof(valueData);
        LONG r = RegEnumValueW(hKey, idx++, valueName, &vNameCch,
                               NULL, &type, (LPBYTE)valueData, &vDataCb);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        total++;

        wchar_t fullPath[MAX_PATH * 2] = {0};

        /* Resolve relative paths to %windir%\Fonts */
        if (wcschr(valueData, L'\\') || wcschr(valueData, L'/')) {
            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(valueData, expanded, _countof(expanded));
            wcsncpy(fullPath, expanded, _countof(fullPath) - 1);
        } else {
            _snwprintf(fullPath, _countof(fullPath), L"%s\\%s", winFonts, valueData);
        }

        /* Skip standard Windows\Fonts paths */
        if (WcsContainsI(fullPath, winFonts)) continue;

        suspicious++;
        BOOL exists   = (GetFileAttributesW(fullPath) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(fullPath);

        PrintInfo(L"    NON-STANDARD: %s → %s%s\n",
                  valueName, fullPath,
                  writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

        if (writable) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"FONT");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE FONT] Non-standard registered font: %s", fullPath);
            _snwprintf(f.reason, _countof(f.reason),
                L"Non-standard registered font file is WRITABLE: %s\n"
                L"        Font: '%s'\n"
                L"        A writable registered font file may be exploitable via:\n"
                L"          1. Win32k font parsing vulnerability (if unpatched)\n"
                L"          2. Timestamp/TOCTOU attack on font cache creation\n"
                L"          3. Malformed font → crash → AeDebug surface",
                fullPath, valueName);
            PrintFinding(&f);
            (*findings)++;
        }
    }

    RegCloseKey(hKey);
    PrintInfo(L"    Total fonts: %lu  |  Non-standard paths: %lu\n\n", total, suspicious);
}

/* -----------------------------------------------------------------------
 * Check per-user font directory (Windows 10 1803+)
 * --------------------------------------------------------------------- */
static void AuditPerUserFonts(DWORD *findings) {
    PrintInfo(L"  [3] Per-user font directory (Windows 10 1803+):\n");

    /* Per-user fonts: %LOCALAPPDATA%\Microsoft\Windows\Fonts */
    wchar_t userFontDir[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(
        L"%LOCALAPPDATA%\\Microsoft\\Windows\\Fonts",
        userFontDir, _countof(userFontDir));

    BOOL exists = (GetFileAttributesW(userFontDir) != INVALID_FILE_ATTRIBUTES);
    PrintInfo(L"    %s: %s\n\n",
              userFontDir, exists ? L"exists (user font dir)" : L"not present");

    if (exists) {
        PrintInfo(L"    Per-user fonts are user-controlled by design.\n");
        PrintInfo(L"    Research: exploit any unpatched win32k font parser via malformed .ttf/.otf.\n\n");
    }
}

/* -----------------------------------------------------------------------
 * Check Font Cache service configuration
 * --------------------------------------------------------------------- */
static void AuditFontCacheService(DWORD *findings) {
    PrintInfo(L"  [4] Font Cache service:\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) { PrintInfo(L"    Cannot open SCM\n\n"); return; }

    static const wchar_t *fontSvcs[] = {
        L"FontCache", L"FontCache3.0.0.0", NULL
    };

    for (int i = 0; fontSvcs[i]; i++) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, fontSvcs[i],
                                       SERVICE_QUERY_STATUS);
        if (!hSvc) continue;

        SERVICE_STATUS_PROCESS ssp = {0};
        DWORD needed = 0;
        QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp, sizeof(ssp), &needed);

        PrintInfo(L"    %s: %s (PID: %lu)\n",
                  fontSvcs[i],
                  ssp.dwCurrentState == SERVICE_RUNNING ? L"Running" : L"Stopped",
                  ssp.dwProcessId);
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);

    /* Check font cache directory */
    wchar_t cacheDir[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(
        L"%windir%\\ServiceProfiles\\LocalService\\AppData\\Local\\FontCache",
        cacheDir, _countof(cacheDir));
    BOOL cacheWritable = IsDirWritable(cacheDir);
    PrintInfo(L"    Font cache dir: %s  [writable: %s]\n\n",
              cacheDir, cacheWritable ? L"YES" : L"No");

    if (cacheWritable) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"FONT");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE CACHE] Font cache directory: %s", cacheDir);
        wcscpy(f.reason,
            L"Font cache directory is writable. "
            L"Font cache files (.dat) are parsed by FontCache service (LocalService). "
            L"TOCTOU: replace cache file with malformed data → crash → AeDebug. "
            L"Or: corrupt cache to force font re-parse from registered sources.");
        PrintFinding(&f);
        (*findings)++;
    }
}

void Module_FontProvider(void) {
    PrintHeader(L"FONT PROVIDER SURFACE  [Font DLL loading + font cache + per-user font attack surface]");

    PrintInfo(
        L"  Font subsystem loads DLLs and font files across SYSTEM services and user processes.\n"
        L"  Font provider DLLs: completely unchecked by all public tools.\n"
        L"  Writable registered fonts = potential win32k kernel attack surface.\n\n");

    DWORD findings = 0;
    AuditFontProviderDLLs(&findings);
    AuditRegisteredFontFiles(&findings);
    AuditPerUserFonts(&findings);
    AuditFontCacheService(&findings);

    if (findings == 0)
        PrintInfo(L"  No font provider LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  RESEARCH NOTES:\n"
            L"    Windows font parsing: GDI font loading (win32k.sys kernel driver)\n"
            L"    ALL font parsing happens in kernel mode via win32k.sys\n"
            L"    Malformed TTF/OTF = kernel-mode parse → crash or RCE if unpatched\n"
            L"    Tool: ttx (FontTools), cffdump, otcheck for font format manipulation\n"
            L"    Fuzzer: FontFuzz (Microsoft), libFuzzer with harness against AddFontResourceEx\n");
    }
}

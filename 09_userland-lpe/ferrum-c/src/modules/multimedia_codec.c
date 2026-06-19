/*
 * multimedia_codec.c — Multimedia Codec DLL Hijacking (Drivers32 + MCI + ACM)
 *
 * RESEARCH SOURCES:
 *   - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32
 *     Documented in MSDN, present since Windows 3.1 era, still used in Windows 11
 *   - ACM (Audio Compression Manager): HKLM\SOFTWARE\Microsoft\Windows NT\
 *     CurrentVersion\drivers.desc and individual codec subkeys
 *   - MCI (Media Control Interface) devices
 *   - Media Foundation Source Resolver:
 *     HKLM\SOFTWARE\Microsoft\Windows Media Foundation\ByteStreamHandlers\
 *     HKLM\SOFTWARE\Microsoft\Windows Media Foundation\SchemeHandlers\
 *   - DirectShow filter registration: HKLM\SOFTWARE\Classes\CLSID\{...}\InprocServer32
 *     (already covered by clsid.c, so focusing on unique surfaces here)
 *   - Research: Various codec DLL hijacking CTF writeups, DEFCON presentations
 *     on media subsystem DLL loading chains
 *
 * ATTACK SURFACE:
 *   Drivers32 maps codec names (wavein.1, msvideo1, vidc.MJPG) to DLL paths.
 *   These DLLs are loaded by the Windows multimedia subsystem (winmm.dll, msvfw32.dll)
 *   into ANY process that plays audio or renders video — including:
 *   - Windows Media Player (historically runs with SeDebugPrivilege on admin)
 *   - Media Foundation processes (svchost.exe -k MediaManager = NetworkService)
 *   - Windows Recording/Playback (svchost.exe -k AudioEndpointBuilder = LOCAL SYSTEM)
 *   - Screen recording tools, Teams/Zoom, browser media, many enterprise apps
 *
 * WHY THIS IS AN LPE SURFACE:
 *   1. Drivers32 DLL path is writable → every media operation loads your DLL
 *   2. Drivers32 key itself is writable → register new codec with malicious DLL
 *   3. Missing DLL at registered path → plant DLL there (phantom DLL hijack)
 *   4. Media Foundation ByteStreamHandler DLL → loaded by MediaFoundation service
 *      (runs as NetworkService; SeImpersonatePrivilege → Potato → SYSTEM)
 *
 * REFERENCES:
 *   MSDN: Drivers32 Registry Key (Audio Codecs section)
 *   MSDN: Audio Compression Manager (ACM)
 *   MITRE T1546.015 — adjacent surface
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Audit Drivers32 multimedia codec DLLs
 * --------------------------------------------------------------------- */
static void AuditDrivers32(DWORD *findings) {
    PrintInfo(L"  [1] Drivers32 multimedia codec DLLs:\n");

    static const wchar_t *D32_PATHS[] = {
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
        NULL
    };

    for (int pi = 0; D32_PATHS[pi]; pi++) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, D32_PATHS[pi], 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        /* Check key writability first */
        HKEY hW = NULL;
        BOOL keyWritable = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, D32_PATHS[pi],
                                          0, KEY_WRITE, &hW) == ERROR_SUCCESS);
        if (keyWritable) { RegCloseKey(hW); }

        PrintInfo(L"    Path: HKLM\\%s%s\n", D32_PATHS[pi],
                  keyWritable ? L" [KEY WRITABLE!]" : L"");

        if (keyWritable) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"MMCODEC");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE KEY] HKLM\\%s", D32_PATHS[pi]);
            _snwprintf(f.reason, _countof(f.reason),
                L"Drivers32 registry key is writable — can register new codec DLL.\n"
                L"        Add value: vidc.XXXX = C:\\path\\to\\payload.dll\n"
                L"        Any video decode operation using XXXX codec loads payload.dll.\n"
                L"        Target: Windows Media Player, Teams, Zoom, browser media.");
            PrintFinding(&f);
            (*findings)++;
        }

        /* Enumerate all codec values */
        DWORD valIdx = 0, vulnCount = 0;
        wchar_t valName[256];
        DWORD   valNameCch;
        wchar_t valData[MAX_PATH * 2];
        DWORD   valDataCb;

        while (TRUE) {
            valNameCch = _countof(valName);
            valDataCb  = sizeof(valData);
            LONG r = RegEnumValueW(hKey, valIdx++, valName, &valNameCch, NULL, NULL,
                                   (LPBYTE)valData, &valDataCb);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            valData[_countof(valData)-1] = L'\0';

            /* Skip non-DLL values */
            if (!valData[0]) continue;
            size_t dlen = wcslen(valData);
            if (dlen < 4 || _wcsicmp(valData + dlen - 4, L".dll") != 0) {
                /* Check if it's a bare DLL name (no extension) */
                if (wcschr(valData, L'\\') == NULL && wcschr(valData, L'/') == NULL)
                    continue; /* bare name, system32 default — skip */
            }

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(valData, expanded, _countof(expanded));

            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);

            if (writable || !exists) {
                vulnCount++;
                PrintInfo(L"      [!] %s = %s%s\n", valName, expanded,
                          writable ? L" [WRITABLE]" : L" [MISSING]");

                Finding f;
                f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
                wcscpy(f.module, L"MMCODEC");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] Drivers32 codec: %s = %s",
                    writable ? L"WRITABLE DLL" : L"MISSING DLL", valName, expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Multimedia codec '%s' DLL is %s: %s\n"
                    L"        Loaded by winmm.dll/msvfw32.dll into any process using this codec.\n"
                    L"        Media Foundation processes run as NetworkService (Potato → SYSTEM).\n"
                    L"        Windows audio service (AudioEndpointBuilder) runs as LOCAL SYSTEM.\n"
                    L"        %s → code exec on next audio/video operation using this codec.",
                    valName, writable ? L"WRITABLE" : L"MISSING (plant)", expanded,
                    writable ? L"Replace DLL" : L"Create DLL at path");
                PrintFinding(&f);
                (*findings)++;
            }
        }
        if (vulnCount == 0)
            PrintInfo(L"      No vulnerable codec DLLs\n");
        RegCloseKey(hKey);
        PrintInfo(L"\n");
    }
}

/* -----------------------------------------------------------------------
 * Audit Media Foundation ByteStream / Scheme handlers
 * --------------------------------------------------------------------- */
static void AuditMFHandlers(DWORD *findings) {
    PrintInfo(L"  [2] Media Foundation ByteStream/Scheme handler DLLs:\n");

    static const struct { const wchar_t *path; const wchar_t *desc; } MF_ROOTS[] = {
        { L"SOFTWARE\\Microsoft\\Windows Media Foundation\\ByteStreamHandlers",
          L"ByteStream (file type)" },
        { L"SOFTWARE\\Microsoft\\Windows Media Foundation\\SchemeHandlers",
          L"Scheme (protocol)" },
        { NULL, NULL }
    };

    for (int ri = 0; MF_ROOTS[ri].path; ri++) {
        HKEY hRoot = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MF_ROOTS[ri].path,
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS)
            continue;

        PrintInfo(L"    %s handlers:\n", MF_ROOTS[ri].desc);
        DWORD idx = 0;
        wchar_t handlerKey[256];
        DWORD   handlerCch;

        while (TRUE) {
            handlerCch = _countof(handlerKey);
            LONG r = RegEnumKeyExW(hRoot, idx++, handlerKey, &handlerCch,
                                   NULL, NULL, NULL, NULL);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;

            /* Open handler key and enumerate CLSIDs */
            wchar_t subPath[512];
            _snwprintf(subPath, _countof(subPath), L"%s\\%s", MF_ROOTS[ri].path, handlerKey);

            HKEY hHandler = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath, 0, KEY_READ, &hHandler) != ERROR_SUCCESS)
                continue;

            DWORD vi = 0;
            wchar_t clsidVal[256];
            DWORD   clsidCch;

            while (TRUE) {
                clsidCch = _countof(clsidVal);
                LONG vr = RegEnumValueW(hHandler, vi++, clsidVal, &clsidCch,
                                        NULL, NULL, NULL, NULL);
                if (vr == ERROR_NO_MORE_ITEMS) break;
                if (vr != ERROR_SUCCESS) continue;

                /* clsidVal should be a CLSID {GUID} — resolve it */
                if (clsidVal[0] != L'{') continue;

                wchar_t dllPath[MAX_PATH * 2] = {0};
                BOOL    isInproc = FALSE;
                wchar_t clsidKey[512];
                _snwprintf(clsidKey, _countof(clsidKey),
                           L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsidVal);

                HKEY hCLSID = NULL;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, clsidKey, 0, KEY_READ, &hCLSID) != ERROR_SUCCESS)
                    continue;

                DWORD cb = sizeof(dllPath);
                RegQueryValueExW(hCLSID, NULL, NULL, NULL, (LPBYTE)dllPath, &cb);
                RegCloseKey(hCLSID);
                if (!*dllPath) continue;
                isInproc = TRUE;

                wchar_t dllExe[MAX_PATH * 2] = {0};
                ExtractExePath(dllPath, dllExe, _countof(dllExe));
                if (!*dllExe) {
                    ExpandEnvironmentStringsW(dllPath, dllExe, _countof(dllExe));
                }

                BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
                BOOL writable = exists && IsFileWritable(dllExe);

                if (writable || !exists) {
                    PrintInfo(L"      [!] %s\\%s → %s %s\n",
                              handlerKey, clsidVal, dllExe,
                              writable ? L"[WRITABLE]" : L"[MISSING]");

                    Finding f;
                    f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
                    wcscpy(f.module, L"MMCODEC");
                    _snwprintf(f.target, _countof(f.target),
                        L"[%s] MF %s handler DLL: %s\\%s → %s",
                        writable ? L"WRITABLE" : L"MISSING",
                        MF_ROOTS[ri].desc, handlerKey, clsidVal, dllExe);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"Media Foundation %s handler for '%s' has %s DLL: %s\n"
                        L"        CLSID: %s\n"
                        L"        Loaded by MF source resolver when opening %s media.\n"
                        L"        MF service (svchost MediaFoundation) = NetworkService\n"
                        L"        → SeImpersonatePrivilege → PrintSpoofer/RoguePotato → SYSTEM",
                        MF_ROOTS[ri].desc, handlerKey,
                        writable ? L"WRITABLE" : L"MISSING", dllExe, clsidVal,
                        handlerKey);
                    PrintFinding(&f);
                    (*findings)++;
                }
            }
            RegCloseKey(hHandler);
        }
        RegCloseKey(hRoot);
    }
    PrintInfo(L"\n");
}

void Module_MultimediaCodec(void) {
    PrintHeader(L"MULTIMEDIA CODEC DLLs  [Drivers32 codec DLL hijacking + Media Foundation handlers]");

    PrintInfo(
        L"  Drivers32 maps codec names (wavein.1, vidc.*) to DLL paths.\n"
        L"  Loaded by winmm.dll/msvfw32.dll into any process doing audio/video.\n"
        L"  Media Foundation handlers loaded by NetworkService (Potato→SYSTEM).\n\n");

    DWORD findings = 0;
    AuditDrivers32(&findings);
    AuditMFHandlers(&findings);

    if (findings == 0)
        PrintInfo(L"  No multimedia codec LPE surface found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

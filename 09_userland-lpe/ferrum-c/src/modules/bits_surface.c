/*
 * bits_surface.c — Background Intelligent Transfer Service (BITS) LPE Surface
 *
 * WHY BITS IS AN LPE SURFACE:
 *   BITS (Background Intelligent Transfer Service) is a SYSTEM service that:
 *     1. Downloads/uploads files at low priority in background
 *     2. Runs as NT AUTHORITY\SYSTEM
 *     3. Persists transfers across reboots
 *     4. COM-accessible from any user (no admin required)
 *     5. Can write files to arbitrary paths (within caller permissions)
 *     6. Supports notification executables (runs when transfer completes)
 *
 * ATTACK VECTORS:
 *
 *   A. NOTIFICATION EXECUTABLE (Primary):
 *      IBackgroundCopyJob2::SetNotifyCmdLine(L"payload.exe", L"")
 *      Called by BITS service (SYSTEM) when a job completes.
 *      payload.exe runs as the job owner, NOT SYSTEM — but for privilege research,
 *      if a SYSTEM-owned BITS job has a writable notification path → SYSTEM exec.
 *
 *   B. BITS JOBS WITH SYSTEM OWNER + WRITABLE DESTINATION:
 *      Enumerate existing BITS jobs (IBackgroundCopyManager::EnumJobs)
 *      Look for: jobs owned by SYSTEM/High-IL with notification path writability.
 *      Note: EnumJobs(BG_JOB_ENUM_ALL_USERS) requires admin — but
 *      enumerating own-user jobs is always allowed.
 *
 *   C. BITS NOTIFICATION EXECUTABLE + COM AUTO-ELEVATION:
 *      If a COM auto-elevated BITS interface (in High IL) can be tricked into
 *      setting notification path to our payload → elevated exec.
 *
 *   D. BITS HELPER DLL / EXTENSION REGISTRATION:
 *      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BITS\StateIndex\
 *      HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BITS\Plugins\
 *      Third-party BITS extensions (DLLs). If writable → SYSTEM DLL load.
 *
 *   E. BITSAdmin Legacy Interface:
 *      bitsadmin /rawreturn /transfer <jobname> /download /priority normal
 *              http://... C:\path\to\writable\system\file
 *      Can write to any path that BITS service (SYSTEM) has write access to.
 *      If SYSTEM can write to a path that causes privilege escalation
 *      (e.g., C:\Windows\System32 is blocked, but some paths aren't).
 *
 * DETECTION:
 *   1. Enumerate existing BITS jobs for notification executables
 *   2. Check BITS plugin registry paths
 *   3. Check BITSVault / temporary file paths for writability
 *   4. Report active BITS jobs that may have privileged operations
 *
 * REAL-WORLD CASES:
 *   - Living-off-the-land: BITS for payload download + persistence
 *   - CVE-2020-0787: Windows BITS improper privilege management
 *   - Nation-state APT groups use BITS for C2 (Stuxnet, APT28)
 *
 * REFERENCES:
 *   MITRE ATT&CK: T1197 — BITS Jobs
 *   Hexacorn: "BITS for Evil" (research blog)
 *   Microsoft BITS documentation: IBackgroundCopyManager
 */

#include "../common.h"
#include <objbase.h>

/* BITS COM GUIDs — defined inline in AuditBITSJobs */

#define BITS_PLUGIN_KEY \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\BackgroundTransferService\\Plugins"
#define BITS_STATEINDEX_KEY \
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BITS\\StateIndex"

/* -----------------------------------------------------------------------
 * Check BITS plugin registry entries
 * --------------------------------------------------------------------- */
static void AuditBITSPlugins(DWORD *findings) {
    PrintInfo(L"  [1] BITS Plugin/Extension DLLs:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, BITS_PLUGIN_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        /* Try alternate key */
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, BITS_STATEINDEX_KEY,
                          0, KEY_READ, &hRoot) != ERROR_SUCCESS) {
            PrintInfo(L"    (no BITS plugin keys found)\n\n");
            return;
        }
    }

    DWORD idx = 0, count = 0;
    wchar_t subKey[256];
    DWORD   subKeyCch;

    while (TRUE) {
        subKeyCch = _countof(subKey);
        LONG r = RegEnumKeyExW(hRoot, idx++, subKey, &subKeyCch, NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        /* Check DLL value in subkey */
        wchar_t pluginPath[512];
        _snwprintf(pluginPath, _countof(pluginPath), L"%s\\%s", BITS_PLUGIN_KEY, subKey);
        HKEY hPlugin = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, pluginPath, 0, KEY_READ, &hPlugin) != ERROR_SUCCESS)
            continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        DWORD   cb = sizeof(dllPath), type = 0;
        RegQueryValueExW(hPlugin, L"DllPath", NULL, &type, (LPBYTE)dllPath, &cb);
        if (!*dllPath) {
            cb = sizeof(dllPath);
            RegQueryValueExW(hPlugin, NULL, NULL, &type, (LPBYTE)dllPath, &cb);
        }
        RegCloseKey(hPlugin);

        if (*dllPath) {
            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));
            BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(expanded);

            PrintInfo(L"    Plugin: %s → %s%s\n",
                      subKey, expanded,
                      writable ? L" [WRITABLE!]" : (exists ? L"" : L" [MISSING]"));

            if (writable || !exists) {
                Finding f;
                f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
                wcscpy(f.module, L"BITS");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] BITS Plugin: %s",
                    writable ? L"WRITABLE" : L"MISSING", expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"BITS plugin DLL %s: %s\n"
                    L"        Plugin: %s\n"
                    L"        BITS service (NT AUTHORITY\\SYSTEM) loads this DLL.\n"
                    L"        %s → SYSTEM code execution.",
                    writable ? L"is WRITABLE" : L"is MISSING",
                    expanded, subKey,
                    writable ? L"Replace DLL with payload" : L"Plant DLL at path");
                PrintFinding(&f);
                (*findings)++;
            }
        }
    }

    RegCloseKey(hRoot);
    if (count == 0) PrintInfo(L"    (no entries)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check BITS temporary/queue storage path
 * --------------------------------------------------------------------- */
static void AuditBITSQueuePath(DWORD *findings) {
    PrintInfo(L"  [2] BITS queue/temp paths:\n");

    /* Default BITS queue path: %ALLUSERSPROFILE%\Microsoft\Network\Downloader\ */
    wchar_t appData[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(L"%ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader",
                              appData, _countof(appData));

    BOOL exists   = (GetFileAttributesW(appData) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsDirWritable(appData);

    PrintInfo(L"    Queue dir: %s  [writable: %s]\n\n",
              appData, writable ? L"YES" : L"No");

    if (writable) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"BITS");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE QUEUE DIR] %s", appData);
        wcscpy(f.reason,
            L"BITS queue directory is writable. "
            L"BITS stores job data here. "
            L"Can interfere with BITS job processing or cause path issues. "
            L"Research: monitor BITS queue file creation for TOCTOU.");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Attempt to enumerate own-user BITS jobs via COM
 * --------------------------------------------------------------------- */
static void AuditBITSJobs(DWORD *findings) {
    PrintInfo(L"  [3] Enumerating BITS jobs (own-user):\n");

    /* Note: BITS COM requires CoInitialize */
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        PrintInfo(L"    (CoInitialize failed: 0x%08lX)\n\n", hr);
        return;
    }

    /* IBackgroundCopyManager via CoCreateInstance */
    /* Using CoCreateInstance with known BITS CLSID */
    static const CLSID CLSID_BkCopyMgr = {
        0x4991D34B, 0x80A1, 0x4291,
        {0x83, 0xB6, 0x33, 0x28, 0x36, 0x6B, 0x90, 0x97}
    };

    IUnknown *pUnk = NULL;
    hr = CoCreateInstance(&CLSID_BkCopyMgr, NULL, CLSCTX_LOCAL_SERVER,
                          &IID_IUnknown, (void**)&pUnk);
    (void)hr;
    if (FAILED(hr)) {
        PrintInfo(L"    (BITS COM not available: 0x%08lX)\n\n", hr);
        CoUninitialize();
        return;
    }

    PrintInfo(L"    BITS COM available. Job enumeration requires BITS-specific VTable.\n");
    PrintInfo(L"    Use 'bitsadmin /list /allusers' or PowerShell Get-BitsTransfer.\n\n");

    if (pUnk) pUnk->lpVtbl->Release(pUnk);
    CoUninitialize();
}

void Module_BitsSurface(void) {
    PrintHeader(L"BITS SURFACE  [Background Intelligent Transfer Service — SYSTEM DLL load + job abuse]");

    PrintInfo(
        L"  BITS runs as SYSTEM and loads plugin DLLs + executes notification commands.\n"
        L"  Used by nation-state APT (Stuxnet, APT28) for persistence.\n"
        L"  MITRE ATT&CK: T1197 — BITS Jobs.\n\n");

    DWORD findings = 0;
    AuditBITSPlugins(&findings);
    AuditBITSQueuePath(&findings);
    AuditBITSJobs(&findings);

    if (findings == 0)
        PrintInfo(L"  No BITS LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  QUICK BITS JOB ENUMERATION:\n"
            L"    bitsadmin /list\n"
            L"    bitsadmin /list /allusers  [requires admin for other users' jobs]\n"
            L"    PowerShell: Get-BitsTransfer -AllUsers\n"
            L"    Look for: jobs with notification commands in writable paths\n\n"
            L"  BITS NOTIFICATION ABUSE (if you can create a SYSTEM BITS job):\n"
            L"    $bits = [System.Type]::GetTypeFromProgID('Microsoft.BITS.Manager')\n"
            L"    bitsadmin /create download_job\n"
            L"    bitsadmin /addfile download_job http://... C:\\output.txt\n"
            L"    bitsadmin /SetNotifyCmdLine download_job C:\\payload.exe NULL\n"
            L"    bitsadmin /resume download_job\n"
            L"    [payload.exe runs as job owner when transfer completes]\n");
    }
}

/*
 * com_autoelevate.c — COM Auto-Elevation Attack Surface Audit
 *
 * WHY COM AUTO-ELEVATION IS A PRIME 0-DAY SURFACE:
 *   Windows UAC includes a COM elevation mechanism that allows specific
 *   COM servers to execute at High integrity (or SYSTEM) without a UAC
 *   prompt, even when called from a Medium-integrity process.
 *
 *   These "auto-elevated" COM servers are registered in a hardcoded Microsoft
 *   whitelist (COMAutoApproval). The servers typically run as:
 *     - LocalSystem (SYSTEM)
 *     - High integrity / full admin token
 *
 *   If ANY method on an auto-elevated COM server:
 *     a) Accepts a file path parameter WITHOUT validating it
 *     b) Performs a privileged file/registry operation on behalf of the caller
 *     c) Has a type confusion, integer overflow, or buffer overflow
 *   → The attacker at Medium IL can trigger SYSTEM code exec with NO UAC prompt.
 *
 * HISTORICAL AUTO-ELEVATION 0-DAYS:
 *   ICMLuaUtil (CMluaUtil):
 *     - Method ShellExec() called any exe as SYSTEM without UAC
 *     - Used in dozens of UAC bypass PoCs
 *   IFileOperation (shell32):
 *     - Auto-elevated file copy/move → plant DLL in System32 as SYSTEM
 *     - CVE-2019-1388 class, multiple researcher PoCs
 *   IShellDispatch (shell32):
 *     - ShellExecute() triggered elevated process launch
 *   IColorDataProxy / ICreateColorDeviceContext:
 *     - Logic bug in mscms.dll auto-elevated server
 *   IHNetFwMgr (netconn.dll):
 *     - Firewall management auto-elevated
 *   IWscAdmin (wscsvc.dll):
 *     - Security Center auto-elevated interface
 *
 * WHAT THIS MODULE DOES:
 *   1. Reads the COMAutoApproval whitelist from registry
 *      (HKLM\...\UAC\COMAutoApproval → list of AppID GUIDs)
 *   2. Enumerates ALL CLSIDs with Elevation\Enabled = 1
 *      (these are candidates for auto-elevation)
 *   3. For each: resolves the DLL/EXE path, checks writability
 *   4. Flags if: (a) writable DLL → immediate SYSTEM exec
 *                (b) DLL missing → phantom load
 *                (c) server in auto-approval list → high-value research target
 *   5. Known-abusable interface cross-reference
 *
 * 0-DAY RESEARCH WORKFLOW (for auto-elevated CLSIDs):
 *   Step 1: Load the server DLL in IDA Pro
 *   Step 2: Find the vtable for the COM interface
 *           (search for DEFINE_GUID of the IID, follow xrefs to vtable)
 *   Step 3: Decompile each method — focus on:
 *           - Parameters that are strings (file paths!)
 *           - Buffer lengths (integers) → integer overflow
 *           - Pointer dereferences without validation
 *           - File/registry operations using caller-supplied paths
 *   Step 4: Reproduce: instantiate the COM object from Medium IL
 *           $obj = [Activator]::CreateInstance([Type]::GetTypeFromCLSID("..."))
 *           Call the method with a crafted argument
 *   Step 5: Monitor with ProcMon: filter [Process=<server process>] to see
 *           what file/registry operations occur with SYSTEM context
 *
 * COMPILE: ole32.lib (MSVC) or -lole32 (GCC)
 *          No extra includes beyond windows.h
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Known-abusable auto-elevated COM interfaces (research starting points)
 * These have had public bugs or are historically interesting.
 * --------------------------------------------------------------------- */
typedef struct {
    const char  *clsidStr;      /* CLSID in lowercase */
    const wchar_t *name;        /* friendly name */
    const wchar_t *notes;       /* research notes */
} KnownAutoElevCLSID;

static const KnownAutoElevCLSID g_knownTargets[] = {
    {
        "3e5fc7f9-9a51-4367-9063-a120244fbec7",
        L"CMluaUtil (ICMLuaUtil)",
        L"ShellExec() method historically allowed SYSTEM shell execution. "
        L"IDA: find vtable for ICMLuaUtil, method index 3 (ShellExec). "
        L"Check if still exploitable or if new methods added."
    },
    {
        "d2e7041b-2927-4f90-9cc3-9b2c38bef3d2",
        L"IColorDataProxy / ColorDataProxy",
        L"Auto-elevated color management COM server. "
        L"Check for path injection in color profile operations."
    },
    {
        "1e2a2e67-42f2-42b6-903c-4ea7c4eb7aa3",
        L"IWscAdmin (WSC Security Center)",
        L"Security Center elevated management interface. "
        L"Method parameters may accept file paths → privilege file write."
    },
    {
        "c47195a0-4682-11d2-89b9-0060083f6d7c",
        L"INetFwMgr (Windows Firewall Manager)",
        L"Firewall rules management auto-elevated. "
        L"Check AddAuthorizedApplication with crafted paths."
    },
    {
        "bf4b0414-9f95-47c0-9b26-c46f3590a52b",
        L"IMsiServer (Windows Installer)",
        L"Installer COM server auto-elevated. "
        L"Logic bug research target: path validation in install methods."
    },
    {
        "f4e27c10-77dc-4e27-a3e8-f7ecd17d6040",
        L"IHNetFwPolicy2 (Advanced Firewall)",
        L"Advanced firewall auto-elevated policy interface."
    },
    {
        "6295df2b-35ee-11d1-8707-00c04fd93327",
        L"ITpmVirtualSmartCardManager",
        L"TPM Virtual Smart Card Manager — elevated. "
        L"Cryptographic operations with path parameters."
    },
    { NULL, NULL, NULL }
};

/* -----------------------------------------------------------------------
 * Build the COMAutoApproval GUID set from registry.
 * HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApproval
 * Each value name = an AppID GUID string that is auto-approved.
 * --------------------------------------------------------------------- */
#define MAX_APPROVED 256
static wchar_t g_approvedAppIDs[MAX_APPROVED][64];
static int     g_approvedCount = 0;

static void LoadCOMAutoApproval(void) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UAC\\COMAutoApproval",
        0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    wchar_t valName[64];
    DWORD nameCch = _countof(valName), type, data, dataCb = sizeof(data);

    while (g_approvedCount < MAX_APPROVED) {
        nameCch = _countof(valName);
        dataCb  = sizeof(data);
        LONG r  = RegEnumValueW(hKey, idx++, valName, &nameCch,
                                NULL, &type, (LPBYTE)&data, &dataCb);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        if (type == REG_DWORD && data == 1) {
            wcsncpy(g_approvedAppIDs[g_approvedCount++], valName,
                    _countof(g_approvedAppIDs[0]) - 1);
        }
    }
    RegCloseKey(hKey);
}

static BOOL IsAppIDAutoApproved(LPCWSTR appID) {
    if (!appID || !*appID) return FALSE;
    for (int i = 0; i < g_approvedCount; i++) {
        if (_wcsicmp(g_approvedAppIDs[i], appID) == 0) return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Look up AppID for a CLSID from HKCR\CLSID\{guid}\AppID
 * --------------------------------------------------------------------- */
static BOOL GetCLSIDAppID(LPCWSTR clsidStr, LPWSTR appIDOut, DWORD cch) {
    wchar_t keyPath[256];
    _snwprintf(keyPath, _countof(keyPath),
               L"CLSID\\%s", clsidStr);
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, keyPath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS) return FALSE;
    DWORD cb = cch * sizeof(wchar_t), type;
    BOOL ok = (RegQueryValueExW(hKey, L"AppID", NULL, &type,
                                (LPBYTE)appIDOut, &cb) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

/* -----------------------------------------------------------------------
 * Get InprocServer32 or LocalServer32 DLL/EXE path for a CLSID
 * --------------------------------------------------------------------- */
static BOOL GetCLSIDServerPath(LPCWSTR clsidStr, LPWSTR pathOut, DWORD cch,
                                BOOL *isInproc)
{
    wchar_t keyPath[256];
    HKEY hKey = NULL;
    DWORD cb, type;

    /* Try InprocServer32 first */
    _snwprintf(keyPath, _countof(keyPath),
               L"CLSID\\%s\\InprocServer32", clsidStr);
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, keyPath, 0, KEY_READ, &hKey)
            == ERROR_SUCCESS) {
        cb   = cch * sizeof(wchar_t);
        BOOL ok = (RegQueryValueExW(hKey, NULL, NULL, &type,
                                    (LPBYTE)pathOut, &cb) == ERROR_SUCCESS);
        RegCloseKey(hKey);
        if (ok) {
            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(pathOut, expanded, _countof(expanded));
            wcsncpy(pathOut, expanded, cch - 1);
            *isInproc = TRUE;
            return TRUE;
        }
    }

    /* Try LocalServer32 */
    _snwprintf(keyPath, _countof(keyPath),
               L"CLSID\\%s\\LocalServer32", clsidStr);
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, keyPath, 0, KEY_READ, &hKey)
            == ERROR_SUCCESS) {
        cb   = cch * sizeof(wchar_t);
        BOOL ok = (RegQueryValueExW(hKey, NULL, NULL, &type,
                                    (LPBYTE)pathOut, &cb) == ERROR_SUCCESS);
        RegCloseKey(hKey);
        if (ok) {
            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(pathOut, expanded, _countof(expanded));
            wcsncpy(pathOut, expanded, cch - 1);
            *isInproc = FALSE;
            return TRUE;
        }
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Audit a single CLSID that has Elevation\Enabled = 1
 * --------------------------------------------------------------------- */
static void AuditElevatedCLSID(LPCWSTR clsidStr, DWORD *findings) {
    /* Get server DLL/EXE path */
    wchar_t serverPath[MAX_PATH * 2] = {0};
    BOOL isInproc = FALSE;
    if (!GetCLSIDServerPath(clsidStr, serverPath, _countof(serverPath), &isInproc))
        return;

    /* Extract just the file path (strip args for LocalServer32 EXEs) */
    wchar_t exePath[MAX_PATH * 2] = {0};
    ExtractExePath(serverPath, exePath, _countof(exePath));
    if (!*exePath) return;

    /* Look up AppID */
    wchar_t appID[64] = {0};
    GetCLSIDAppID(clsidStr, appID, _countof(appID));
    BOOL autoApproved = IsAppIDAutoApproved(appID);

    /* Check for known-abusable CLSIDs */
    const KnownAutoElevCLSID *known = NULL;
    for (int i = 0; g_knownTargets[i].clsidStr; i++) {
        wchar_t tgt[64];
        MultiByteToWideChar(CP_ACP, 0, g_knownTargets[i].clsidStr, -1,
                            tgt, _countof(tgt));
        if (_wcsicmp(clsidStr, tgt) == 0 ||
            (clsidStr[0] == L'{' && _wcsnicmp(clsidStr+1, tgt, 36) == 0)) {
            known = &g_knownTargets[i];
            break;
        }
    }
    /* Also try without braces */
    if (!known) {
        const wchar_t *raw = clsidStr;
        if (*raw == L'{') raw++;
        for (int i = 0; g_knownTargets[i].clsidStr; i++) {
            wchar_t tgt[64];
            MultiByteToWideChar(CP_ACP, 0, g_knownTargets[i].clsidStr, -1,
                                tgt, _countof(tgt));
            if (_wcsnicmp(raw, tgt, 36) == 0) { known = &g_knownTargets[i]; break; }
        }
    }

    BOOL exists   = (GetFileAttributesW(exePath) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(exePath);

    /* Get directory writability */
    wchar_t exeDir[MAX_PATH * 2] = {0};
    wcsncpy(exeDir, exePath, _countof(exeDir) - 1);
    wchar_t *sl = wcsrchr(exeDir, L'\\');
    BOOL dirWritable = FALSE;
    if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(exeDir); }

    Finding f;
    wcscpy(f.module, L"COM_AUTOELEVATE");

    if (writable) {
        /* Best case: replace the DLL → code exec as SYSTEM via COM */
        f.severity = SEV_CRITICAL;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE] %s (%s)",
            clsidStr, known ? known->name : L"auto-elevatable CLSID");
        _snwprintf(f.reason, _countof(f.reason),
            L"Auto-elevated COM server DLL is WRITABLE. "
            L"Replace DLL → next time ANY process activates this CLSID, "
            L"your payload runs at HIGH INTEGRITY (or SYSTEM) without UAC. "
            L"DLL: %s  AutoApproved: %s",
            exePath, autoApproved ? L"YES" : L"(check AppID)");
        PrintFinding(&f);
        (*findings)++;
    } else if (!exists) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[MISSING DLL] %s (%s)",
            clsidStr, known ? known->name : L"auto-elevatable CLSID");
        _snwprintf(f.reason, _countof(f.reason),
            L"Auto-elevated COM server DLL does NOT EXIST on disk. "
            L"If the DLL load path includes a user-writable directory, "
            L"plant the DLL there → elevated code exec. "
            L"Expected: %s  IsInproc: %s",
            exePath, isInproc ? L"Yes (InprocServer32)" : L"No (LocalServer32)");
        PrintFinding(&f);
        (*findings)++;
    } else if (dirWritable) {
        f.severity = SEV_HIGH;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DIR] %s (%s)",
            clsidStr, known ? known->name : L"auto-elevatable CLSID");
        _snwprintf(f.reason, _countof(f.reason),
            L"Auto-elevated COM server directory is writable. "
            L"DLL side-loading possible: plant payload next to the server DLL. "
            L"Dir: %s  DLL: %s",
            exeDir, exePath);
        PrintFinding(&f);
        (*findings)++;
    } else if (autoApproved || known) {
        /* Server exists and is protected, but is a research target */
        f.severity = SEV_MEDIUM;
        _snwprintf(f.target, _countof(f.target),
            L"[RESEARCH TARGET] %s (%s)",
            clsidStr, known ? known->name : L"auto-approved CLSID");
        _snwprintf(f.reason, _countof(f.reason),
            L"Auto-elevated COM server confirmed. Server DLL is protected (read-only). "
            L"Research target: load %s in IDA, find interface vtable, audit methods for "
            L"(a) unchecked file path params, (b) buffer length bugs, (c) type confusion. "
            L"%s",
            exePath,
            known ? known->notes : L"Use RpcView or OleViewDotNet to list all methods.");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_COMAutoElevate(void) {
    PrintHeader(
        L"COM AUTO-ELEVATION SURFACE AUDIT  [UAC bypass logic-bug surface]");

    PrintInfo(
        L"  Enumerates COM servers marked with Elevation\\Enabled = 1.\n"
        L"  These run at HIGH INTEGRITY or SYSTEM when activated from Medium IL.\n"
        L"  Logic bugs in their method implementations = UAC bypass / LPE.\n"
        L"  Historical: ICMLuaUtil, IFileOperation, IShellDispatch UAC bypasses.\n\n");

    /* Load the COMAutoApproval whitelist */
    LoadCOMAutoApproval();
    PrintInfo(L"  COMAutoApproval whitelist entries: %d\n\n", g_approvedCount);

    /* Enumerate HKCR\CLSID for Elevation\Enabled = 1 */
    HKEY hClsid = NULL;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hClsid)
            != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open HKCR\\CLSID\n");
        return;
    }

    DWORD idx = 0, findings = 0, checked = 0;
    wchar_t clsidName[64];
    DWORD   nameCch;

    while (TRUE) {
        nameCch = _countof(clsidName);
        LONG r  = RegEnumKeyExW(hClsid, idx++, clsidName, &nameCch,
                                NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        /* Check for Elevation\Enabled subkey */
        wchar_t elevPath[128];
        _snwprintf(elevPath, _countof(elevPath),
                   L"CLSID\\%s\\Elevation", clsidName);

        HKEY hElev = NULL;
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, elevPath, 0, KEY_READ, &hElev)
                != ERROR_SUCCESS) continue;

        DWORD enabled = 0, cb = sizeof(enabled), type;
        BOOL hasElev = (RegQueryValueExW(hElev, L"Enabled", NULL, &type,
                                         (LPBYTE)&enabled, &cb) == ERROR_SUCCESS
                        && type == REG_DWORD && enabled == 1);
        RegCloseKey(hElev);

        if (!hasElev) continue;

        checked++;
        AuditElevatedCLSID(clsidName, &findings);
    }
    RegCloseKey(hClsid);

    PrintInfo(L"\n  CLSIDs with Elevation\\Enabled=1: %lu  |  Findings: %lu\n\n",
              checked, findings);

    PrintInfo(
        L"  HOW TO RESEARCH AUTO-ELEVATED COM SERVERS:\n"
        L"    1. List all methods:\n"
        L"       OleViewDotNet (James Forshaw): File → View → Registered Objects\n"
        L"       Filter by 'Elevation' → select CLSID → view interfaces\n"
        L"    2. Instantiate from Medium IL to confirm elevation:\n"
        L"       PowerShell: [Activator]::CreateInstance([Type]::GetTypeFromCLSID('{GUID}'))\n"
        L"    3. Load server DLL in IDA → find IID_* constants → follow to vtable\n"
        L"       Focus: QueryInterface, then each method stub\n"
        L"    4. For IFileOperation (auto-elevated file ops):\n"
        L"       $fop = New-Object -ComObject Shell.Application\n"
        L"       $fop.Namespace(...).CopyHere(...) with crafted source path\n"
        L"    5. ProcMon filter: [Process=<svchost/dllhost>] + [Result=SUCCESS]\n"
        L"       Watch for file/reg ops with SYSTEM context using your input path\n"
        L"    6. WinDbg: attach to the elevated host process, set bp on method entry\n"
        L"       Check argument validation before file operations\n");
}

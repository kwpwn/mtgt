/*
 * uac_policy.c — UAC Policy Configuration Audit
 *
 * UAC (User Account Control) policy settings directly control escalation feasibility.
 * This module audits ALL UAC-related registry values to comprehensively assess
 * the UAC bypass attack surface and token filter configuration.
 *
 * KEY REGISTRY VALUES:
 *   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
 *
 *   EnableLUA = 0/1
 *     0 = UAC completely disabled → any process runs as admin, no elevation needed
 *     1 = UAC enabled (default)
 *     → If 0: "LPE is trivial — any admin-level account gets unrestricted tokens"
 *
 *   ConsentPromptBehaviorAdmin = 0-5
 *     0 = Elevate without prompting (no UAC prompt for admins)
 *     1 = Prompt for credentials on secure desktop
 *     2 = Prompt for consent on secure desktop (default)
 *     3 = Prompt for credentials (not on secure desktop)
 *     4 = Prompt for consent (not on secure desktop)
 *     5 = Prompt for consent for non-Windows binaries (default on Home)
 *     → If 0: Admin processes auto-elevate silently → no visible prompt on UAC bypass
 *
 *   ConsentPromptBehaviorUser = 0-3
 *     0 = Automatically deny elevation requests (standard user can't elevate)
 *     1 = Prompt for credentials on secure desktop
 *     3 = Prompt for credentials (not secure desktop, default)
 *
 *   LocalAccountTokenFilterPolicy = 0/1
 *     0 = (default) Remote connections by local admin accounts get filtered tokens
 *         → PsExec/WMI/RDP with local admin = Medium IL unless enabled
 *     1 = Local admin tokens are NOT filtered for remote connections
 *         → Pass-the-Hash over network works for local admin accounts
 *         → Critical for lateral movement: WMI/SMB/WinRM with local admin hash
 *
 *   FilterAdministratorToken = 0/1
 *     0 = (default) Built-in Administrator (RID 500) gets unrestricted token even with UAC
 *     1 = Built-in Administrator also subject to UAC token filtering
 *
 *   PromptOnSecureDesktop = 0/1
 *     0 = UAC prompts appear on normal desktop (susceptible to UI automation attacks)
 *     1 = UAC prompts on secure desktop (default — harder to automate attack)
 *
 *   EnableVirtualization = 0/1
 *     0 = Registry/file virtualization disabled → apps that write to HKLM fail
 *     1 = UAC virtualization active (redirects to VirtualStore)
 *
 *   ValidateAdminCodeSignatures = 0/1
 *     0 = (default) Admin elevation doesn't require code signing
 *     1 = Only signed binaries can be elevated → stronger restriction
 *
 * LPE IMPLICATIONS:
 *   - EnableLUA=0: UAC bypasses irrelevant — all admin processes get full token
 *   - ConsentPromptBehaviorAdmin=0: Can silently auto-elevate without user interaction
 *   - LocalAccountTokenFilterPolicy=1: Enables PTH lateral movement over network
 *   - PromptOnSecureDesktop=0: UAC prompt susceptible to SendInput/SetForegroundWindow attacks
 *
 * REFERENCES:
 *   MS-Security Blog: "User Account Control: How UAC Works"
 *   Mark Russinovich: "Inside UAC" (SysInternals)
 *   UACME project: https://github.com/hfiref0x/UACME (bypass technique catalog)
 *   harmj0y: LocalAccountTokenFilterPolicy and lateral movement
 */

#include "../common.h"

#define UAC_KEY L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define WD_KEY  L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"

/* -----------------------------------------------------------------------
 * Read a DWORD from the system policy key
 * --------------------------------------------------------------------- */
static BOOL ReadPolicyDWORD(HKEY hRoot, LPCWSTR keyPath, LPCWSTR valueName,
                             DWORD *out) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;
    DWORD type = 0, cb = sizeof(DWORD);
    BOOL ok = (RegQueryValueExW(hKey, valueName, NULL, &type,
                                (LPBYTE)out, &cb) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

/* -----------------------------------------------------------------------
 * Audit all UAC-relevant policy values
 * --------------------------------------------------------------------- */
static void AuditUACPolicies(DWORD *findings) {
    PrintInfo(L"  [1] UAC policy values:\n");

    HKEY hPol = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, UAC_KEY, 0, KEY_READ, &hPol) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open Policies\\System key\n\n");
        return;
    }

    static const struct {
        const wchar_t *name;
        DWORD          defaultVal;
        const wchar_t *description;
        DWORD          criticalVal;  /* value that enables bypass/LPE */
    } VALUES[] = {
        { L"EnableLUA",                     1, L"UAC globally enabled",                       0 },
        { L"ConsentPromptBehaviorAdmin",    5, L"Admin consent prompt behavior",              0 },
        { L"ConsentPromptBehaviorUser",     3, L"Standard user elevation behavior",           0 },
        { L"LocalAccountTokenFilterPolicy", 0, L"Local admin token filtering (PTH surface)",  1 },
        { L"FilterAdministratorToken",      0, L"Built-in Admin token filtering",             0 },
        { L"PromptOnSecureDesktop",         1, L"Prompt on secure desktop",                   0 },
        { L"EnableVirtualization",          1, L"File/registry virtualization",               0 },
        { L"ValidateAdminCodeSignatures",   0, L"Require signed binaries for elevation",      0 },
        { NULL, 0, NULL, 0 }
    };

    for (int i = 0; VALUES[i].name; i++) {
        DWORD val = VALUES[i].defaultVal;
        DWORD type = 0, cb = sizeof(DWORD);
        BOOL set = (RegQueryValueExW(hPol, VALUES[i].name, NULL, &type,
                                     (LPBYTE)&val, &cb) == ERROR_SUCCESS);

        BOOL isLPEFavorable = (val == VALUES[i].criticalVal);
        BOOL isNonDefault   = (val != VALUES[i].defaultVal);

        PrintInfo(L"    %-38s = %lu %s%s\n",
                  VALUES[i].name, val,
                  !set        ? L"(default/absent)" : L"",
                  isLPEFavorable ? L" [WEAK — LPE FAVORABLE!]" :
                  isNonDefault   ? L" [non-default]" : L"");
    }

    RegCloseKey(hPol);
    PrintInfo(L"\n");

    /* Now evaluate and report critical settings */
    DWORD enableLUA = 1, consentAdmin = 5, localTFP = 0, secDesk = 1;
    ReadPolicyDWORD(HKEY_LOCAL_MACHINE, UAC_KEY, L"EnableLUA",                     &enableLUA);
    ReadPolicyDWORD(HKEY_LOCAL_MACHINE, UAC_KEY, L"ConsentPromptBehaviorAdmin",    &consentAdmin);
    ReadPolicyDWORD(HKEY_LOCAL_MACHINE, UAC_KEY, L"LocalAccountTokenFilterPolicy", &localTFP);
    ReadPolicyDWORD(HKEY_LOCAL_MACHINE, UAC_KEY, L"PromptOnSecureDesktop",         &secDesk);

    if (!enableLUA) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"UACPOLICY");
        wcscpy(f.target, L"[UAC DISABLED] EnableLUA = 0 — UAC completely disabled");
        wcscpy(f.reason,
            L"EnableLUA = 0 means UAC is completely disabled.\n"
            L"        ALL administrator processes run with unrestricted High IL tokens.\n"
            L"        No elevation prompt ever appears.\n"
            L"        Any code running as a local admin account has immediate SYSTEM access.\n"
            L"        UAC bypass techniques are all irrelevant — just run directly as admin.");
        PrintFinding(&f);
        (*findings)++;
    }

    if (consentAdmin == 0) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"UACPOLICY");
        wcscpy(f.target, L"[SILENT ELEVATION] ConsentPromptBehaviorAdmin = 0 — no UAC prompt");
        wcscpy(f.reason,
            L"ConsentPromptBehaviorAdmin = 0 means admin processes auto-elevate WITHOUT prompt.\n"
            L"        UAC bypass techniques work silently — no user interaction required.\n"
            L"        COM auto-elevation, fodhelper, eventvwr all work without visible prompt.\n"
            L"        Easier for automated exploitation: no timing/UI interaction needed.");
        PrintFinding(&f);
        (*findings)++;
    }

    if (localTFP) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"UACPOLICY");
        wcscpy(f.target, L"[PTH ENABLED] LocalAccountTokenFilterPolicy = 1 — remote admin PTH works");
        wcscpy(f.reason,
            L"LocalAccountTokenFilterPolicy = 1 enables Pass-the-Hash for remote local admin.\n"
            L"        Local admin accounts are NOT filtered when connecting remotely.\n"
            L"        Attack: wmiexec.py Admin@<target> -hashes :<NTLM_HASH>\n"
            L"                psexec.py Admin@<target> -hashes :<NTLM_HASH>\n"
            L"        Lateral movement: steal any local admin NTLM hash → full remote control.\n"
            L"        This is a default-insecure workgroup configuration.");
        PrintFinding(&f);
        (*findings)++;
    }

    if (!secDesk) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"UACPOLICY");
        wcscpy(f.target, L"[UI ATTACK] PromptOnSecureDesktop = 0 — UAC prompt on normal desktop");
        wcscpy(f.reason,
            L"UAC prompts appear on the normal desktop (not secure desktop).\n"
            L"        This makes UAC prompts susceptible to UI automation attacks:\n"
            L"          - SendInput to click 'Yes' on behalf of user\n"
            L"          - Window message injection (if same session)\n"
            L"          - SetForegroundWindow + SendInput timing attacks\n"
            L"        Combined with a user-triggered UAC prompt context: auto-accept.");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Audit Windows Defender / AV policy that affects exploitation
 * --------------------------------------------------------------------- */
static void AuditDefenderPolicy(DWORD *findings) {
    PrintInfo(L"  [2] Windows Defender / AV configuration:\n");

    DWORD disableAV = 0;
    ReadPolicyDWORD(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    L"DisableAntiSpyware", &disableAV);

    DWORD rtProtection = 1;
    ReadPolicyDWORD(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
                    L"DisableRealtimeMonitoring", &rtProtection);

    DWORD scriptScanning = 0;
    ReadPolicyDWORD(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
                    L"DisableScriptScanning", &scriptScanning);

    PrintInfo(L"    DisableAntiSpyware (WD disabled):         %lu %s\n",
              disableAV, disableAV ? L"[DEFENDER DISABLED!]" : L"");
    PrintInfo(L"    DisableRealtimeMonitoring:                %lu %s\n",
              rtProtection, rtProtection ? L"[REAL-TIME OFF!]" : L"");
    PrintInfo(L"    DisableScriptScanning:                    %lu %s\n\n",
              scriptScanning, scriptScanning ? L"[SCRIPT SCAN OFF!]" : L"");

    if (disableAV || rtProtection) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"UACPOLICY");
        _snwprintf(f.target, _countof(f.target),
            L"[AV DISABLED] Windows Defender: %s%s",
            disableAV ? L"AntiSpyware disabled, " : L"",
            rtProtection ? L"Real-time protection off" : L"");
        wcscpy(f.reason,
            L"Windows Defender antivirus protection is disabled by policy.\n"
            L"        Common malware/payload delivery methods are undetected:\n"
            L"          - Staged shellcode delivery\n"
            L"          - PowerShell empire/Meterpreter stages\n"
            L"          - Reflective DLL injection\n"
            L"        Payload can be placed in any path without AV interception.");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Check Windows Defender exclusion paths (AV-blind zones)
 * --------------------------------------------------------------------- */
static void AuditDefenderExclusions(DWORD *findings) {
    PrintInfo(L"  [3] Windows Defender exclusion paths (AV-blind payload staging zones):\n");

    static const wchar_t *EXCL_KEYS[] = {
        L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        NULL
    };

    DWORD totalExcl = 0;

    for (int ki = 0; EXCL_KEYS[ki]; ki++) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, EXCL_KEYS[ki],
                          0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;

        DWORD idx = 0;
        wchar_t pathVal[MAX_PATH * 2];
        DWORD   pathValCch;

        while (TRUE) {
            pathValCch = _countof(pathVal);
            DWORD type = 0, data = 0, dataCb = sizeof(data);
            LONG r = RegEnumValueW(hKey, idx++, pathVal, &pathValCch,
                                   NULL, &type, (LPBYTE)&data, &dataCb);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            totalExcl++;

            BOOL exists   = (GetFileAttributesW(pathVal) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && (IsDirWritable(pathVal) || IsFileWritable(pathVal));

            PrintInfo(L"    Excluded: %s%s\n",
                      pathVal, writable ? L" [WRITABLE EXCLUSION — AV BLIND!]" : L"");

            if (writable || exists) {
                Finding f;
                f.severity = writable ? SEV_HIGH : SEV_MEDIUM;
                wcscpy(f.module, L"UACPOLICY");
                _snwprintf(f.target, _countof(f.target),
                    L"[AV BLIND ZONE] Defender exclusion path: %s", pathVal);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Windows Defender excludes path: %s\n"
                    L"        Payloads placed here are NOT scanned by Defender.\n"
                    L"        %s → copy payload here for AV-evaded execution.",
                    pathVal,
                    writable ? L"Path is writable by current user" : L"Path exists and is excluded");
                PrintFinding(&f);
                (*findings)++;
            }
        }
        RegCloseKey(hKey);
    }
    if (totalExcl == 0) PrintInfo(L"    (no Defender exclusion paths configured)\n");
    PrintInfo(L"\n");
}

void Module_UACPolicy(void) {
    PrintHeader(L"UAC POLICY AUDIT  [UAC configuration + token filter policy + AV exclusions]");

    PrintInfo(
        L"  Audits all UAC registry policy values that affect LPE/bypass feasibility.\n"
        L"  LocalAccountTokenFilterPolicy = key for remote PTH lateral movement.\n"
        L"  Defender exclusion paths = AV-blind payload staging zones.\n\n");

    DWORD findings = 0;
    AuditUACPolicies(&findings);
    AuditDefenderPolicy(&findings);
    AuditDefenderExclusions(&findings);

    if (findings == 0)
        PrintInfo(L"  No UAC policy weaknesses found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  BYPASS TECHNIQUE SELECTION GUIDE:\n"
            L"    EnableLUA=0:           → No bypass needed, admin = SYSTEM\n"
            L"    ConsentPromptAdmin=0:  → Any bypass works silently\n"
            L"    PromptOnSecureDesktop=0: → UI automation attacks possible\n"
            L"    LocalTFP=1:            → Hash spray via WMI/SMB → lateral movement\n"
            L"  See: https://github.com/hfiref0x/UACME for 70+ bypass techniques\n");
    }
}

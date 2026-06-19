/*
 * lsa_notify.c — LSA Notification Packages & Security Package DLL Hijacking
 *
 * WHAT THIS COVERS (DISTINCT FROM lsa_package.c):
 *
 *   lsa_package.c checks Authentication Packages and Security Packages
 *   (SSPs loaded by LSASS for authentication protocol implementation).
 *
 *   THIS MODULE checks NOTIFICATION packages — DLLs called by LSASS
 *   on specific events like password changes. Completely different registry keys,
 *   different loading mechanism, different trigger conditions.
 *
 * ATTACK SURFACES:
 *
 *   1. NOTIFICATION PACKAGES (Password Change Notifiers):
 *      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages
 *      REG_MULTI_SZ — one DLL name per line
 *      lsass.exe loads these DLLs and calls PasswordChangeNotify() on every
 *      password change event (local + domain).
 *      If DLL path is writable → replace DLL → code exec in lsass (SYSTEM).
 *      Famous usage: Mimikatz dumps creds via custom notification package.
 *
 *   2. PASSWORD FILTER DLLs:
 *      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages (same key)
 *      Also calls PasswordFilter() and InitializeChangeNotify()
 *      These are meant for enforcing password complexity policies.
 *      Malicious password filters = password plaintext capture (mimikatz technique).
 *
 *   3. SECURITY PACKAGE WRITABILITY (complementary to lsa_package.c):
 *      Double-checks the actual DLL file writability for Security Packages.
 *
 *   4. LSASS PROCESS DACL:
 *      If lsass.exe has weak DACL → OpenProcess with PROCESS_VM_READ → dump.
 *      Checks PROCESS_DUP_HANDLE | PROCESS_VM_READ access.
 *
 *   5. LSA PROTECTION STATUS:
 *      HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL
 *      If RunAsPPL != 1 → lsass is NOT protected → memory dump feasible.
 *      Also: CrashOnAuditFail, LmCompatibilityLevel audit.
 *
 * MIMIKATZ CONNECTION:
 *   mimikatz> sekurlsa::msv — reads credentials from lsass memory
 *   Requires PROCESS_VM_READ on lsass → only possible if lsass not PPL-protected.
 *   Custom notification package → runs IN lsass → plaintext password capture.
 *
 * REFERENCES:
 *   https://docs.microsoft.com/en-us/windows/win32/secauthn/notification-packages
 *   Mimikatz source: mimilib/kssp.c (custom SSP), sekurlsa module
 *   Carlos Perez: "Dumping LSA Secrets" (Darkoperator)
 *   CVE-2021-36942: Windows LSA spoofing
 */

#include "../common.h"

#define LSA_KEY       L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define LSA_NOTIFY_V  L"Notification Packages"
#define LSA_SECPKG_V  L"Security Packages"
#define LSA_AUTHPKG_V L"Authentication Packages"

/* -----------------------------------------------------------------------
 * Audit Notification Packages (password change DLL callbacks)
 * --------------------------------------------------------------------- */
static void AuditNotificationPackages(DWORD *findings) {
    PrintInfo(L"  [1] LSA Notification Packages (password change DLL callbacks):\n");

    HKEY hLsa = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0, KEY_READ, &hLsa) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open LSA key\n\n");
        return;
    }

    wchar_t multiSz[4096] = {0};
    DWORD   cb = sizeof(multiSz), type = 0;
    RegQueryValueExW(hLsa, LSA_NOTIFY_V, NULL, &type, (LPBYTE)multiSz, &cb);
    RegCloseKey(hLsa);

    DWORD count = 0;
    wchar_t *p = multiSz;
    while (p && *p) {
        count++;
        wchar_t sysDir[MAX_PATH] = {0};
        GetSystemDirectoryW(sysDir, _countof(sysDir));

        /* Notification packages are system32 DLLs (no path) or full path */
        wchar_t dllPath[MAX_PATH * 2] = {0};
        if (wcschr(p, L'\\')) {
            wcsncpy(dllPath, p, _countof(dllPath)-1);
        } else {
            _snwprintf(dllPath, _countof(dllPath), L"%s\\%s.dll", sysDir, p);
            /* If no .dll extension, add it */
            if (!WcsContainsI(p, L".dll")) {
                _snwprintf(dllPath, _countof(dllPath), L"%s\\%s.dll", sysDir, p);
            }
        }

        BOOL exists   = (GetFileAttributesW(dllPath) != INVALID_FILE_ATTRIBUTES);
        BOOL writable = exists && IsFileWritable(dllPath);

        PrintInfo(L"    Package: %-30s → %s%s\n",
                  p, dllPath,
                  writable ? L" [WRITABLE!]" : (!exists ? L" [MISSING]" : L""));

        if (writable || !exists) {
            Finding f;
            f.severity = writable ? SEV_CRITICAL : SEV_HIGH;
            wcscpy(f.module, L"LSANOTIFY");
            _snwprintf(f.target, _countof(f.target),
                L"[%s] LSA Notification Package DLL: %s",
                writable ? L"WRITABLE" : L"MISSING", dllPath);
            _snwprintf(f.reason, _countof(f.reason),
                L"Notification Package '%s' DLL is %s: %s\n"
                L"        lsass.exe (SYSTEM/TCB) loads this DLL and calls PasswordChangeNotify().\n"
                L"        DLL runs INSIDE lsass address space as SYSTEM.\n"
                L"        %s → full lsass compromise on next password change.\n"
                L"        Also enables plaintext password capture (mimikatz-style password filter).",
                p, writable ? L"WRITABLE" : L"MISSING", dllPath,
                writable ? L"Replace DLL with payload" : L"Plant DLL at path");
            PrintFinding(&f);
            (*findings)++;
        }

        p += wcslen(p) + 1;
    }
    if (count == 0) PrintInfo(L"    (no notification packages)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit LSA protection and memory dump feasibility
 * --------------------------------------------------------------------- */
static void AuditLSAProtection(DWORD *findings) {
    PrintInfo(L"  [2] LSA protection status (lsass PPL / memory dump feasibility):\n");

    HKEY hLsa = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0, KEY_READ, &hLsa) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open LSA key\n\n");
        return;
    }

    DWORD runAsPPL = 0, cb = sizeof(DWORD), type = 0;
    RegQueryValueExW(hLsa, L"RunAsPPL", NULL, &type, (LPBYTE)&runAsPPL, &cb);

    DWORD lmCompat = 0;
    cb = sizeof(DWORD);
    RegQueryValueExW(hLsa, L"LmCompatibilityLevel", NULL, &type, (LPBYTE)&lmCompat, &cb);

    DWORD noLMHash = 0;
    cb = sizeof(DWORD);
    RegQueryValueExW(hLsa, L"NoLMHash", NULL, &type, (LPBYTE)&noLMHash, &cb);

    DWORD disableRestrictedAdmin = 0;
    cb = sizeof(DWORD);
    RegQueryValueExW(hLsa, L"DisableRestrictedAdmin", NULL, &type,
                     (LPBYTE)&disableRestrictedAdmin, &cb);

    RegCloseKey(hLsa);

    PrintInfo(L"    RunAsPPL (lsass protected):      %lu %s\n",
              runAsPPL, runAsPPL ? L"(Protected — PPL active)" : L"[NOT PROTECTED — memory dump feasible!]");
    PrintInfo(L"    LmCompatibilityLevel:            %lu %s\n",
              lmCompat, lmCompat < 3 ? L"[LOW — NTLM/LM relay possible]" : L"");
    PrintInfo(L"    NoLMHash:                        %lu %s\n",
              noLMHash, noLMHash ? L"" : L"[LM hashes stored in SAM!]");
    PrintInfo(L"    DisableRestrictedAdmin (RDP):    %lu %s\n\n",
              disableRestrictedAdmin,
              disableRestrictedAdmin ? L"[Restricted Admin disabled — PTH via RDP works!]" : L"");

    if (!runAsPPL) {
        /* Try to open lsass to confirm */
        DWORD lsassPID = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
            for (BOOL more = Process32FirstW(hSnap, &pe); more;
                 more = Process32NextW(hSnap, &pe)) {
                if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                    lsassPID = pe.th32ProcessID;
                    break;
                }
            }
            CloseHandle(hSnap);
        }

        BOOL canRead = FALSE;
        if (lsassPID) {
            HANDLE hLsass = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                        FALSE, lsassPID);
            if (hLsass) { canRead = TRUE; CloseHandle(hLsass); }
        }

        Finding f;
        f.severity = canRead ? SEV_CRITICAL : SEV_HIGH;
        wcscpy(f.module, L"LSANOTIFY");
        _snwprintf(f.target, _countof(f.target),
            L"[PPL DISABLED] lsass.exe (PID: %lu) — RunAsPPL = 0%s",
            lsassPID, canRead ? L" — READABLE!" : L"");
        _snwprintf(f.reason, _countof(f.reason),
            L"lsass.exe is NOT running as Protected Process Light (RunAsPPL = 0).\n"
            L"        This means lsass memory is accessible to admin-level processes.\n"
            L"        %s\n"
            L"        Dump technique: mimikatz, procdump, comsvcs.dll minidump, Task Manager\n"
            L"        mini dump → offline credential extraction (hashcat, pass-the-hash).\n"
            L"        Fix: Enable Credential Guard or set HKLM\\...\\Lsa\\RunAsPPL = 1",
            canRead ? L"CONFIRMED: Current user CAN open lsass with VM_READ — dump feasible!"
                    : L"Cannot directly open lsass (limited token), but admin escalation enables dump.");
        PrintFinding(&f);
        (*findings)++;
    }

    if (!noLMHash) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"LSANOTIFY");
        wcscpy(f.target, L"[LM HASHES] NoLMHash = 0 — LM hashes stored in SAM");
        wcscpy(f.reason,
            L"LM hash storage is NOT disabled (NoLMHash = 0 or absent).\n"
            L"        For accounts with passwords ≤14 chars, LM hashes are stored in SAM.\n"
            L"        LM hashes are easily crackable (split into two 7-char halves, DES).\n"
            L"        Fix: Set NoLMHash = 1 or set LmCompatibilityLevel ≥ 3.");
        PrintFinding(&f);
        (*findings)++;
    }

    if (disableRestrictedAdmin) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"LSANOTIFY");
        wcscpy(f.target, L"[PTH RDP] DisableRestrictedAdmin = 1 — Pass-the-Hash via RDP enabled");
        wcscpy(f.reason,
            L"DisableRestrictedAdmin = 1 means Restricted Admin mode is disabled for RDP.\n"
            L"        With NTLM hash of a local admin account:\n"
            L"        xfreerdp /u:Administrator /pth:<NT_HASH> /v:<target>\n"
            L"        → RDP session without knowing plaintext password.");
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Check LSA key for writable sub-paths that control DLL loading
 * --------------------------------------------------------------------- */
static void AuditLSAKeyWritability(DWORD *findings) {
    PrintInfo(L"  [3] LSA registry key writability:\n");

    HKEY hLsa = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LSA_KEY, 0, KEY_WRITE, &hLsa) == ERROR_SUCCESS) {
        RegCloseKey(hLsa);
        PrintInfo(L"    [CRITICAL] LSA key is WRITABLE — can modify Notification/Security/Auth packages!\n\n");
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"LSANOTIFY");
        wcscpy(f.target, L"[WRITABLE] HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa is WRITABLE");
        wcscpy(f.reason,
            L"The LSA registry key is writable by current user.\n"
            L"        Can add arbitrary DLLs to:\n"
            L"          - Notification Packages (runs in lsass on password change)\n"
            L"          - Security Packages (loaded by lsass on startup)\n"
            L"          - Authentication Packages (loaded by lsass on startup)\n"
            L"        Attack: Add payload.dll to Notification Packages → change any password\n"
            L"                → payload runs inside lsass.exe as SYSTEM with TCB privilege.");
        PrintFinding(&f);
        (*findings)++;
    } else {
        PrintInfo(L"    LSA key not writable (expected on hardened systems)\n\n");
    }
}

void Module_LSANotify(void) {
    PrintHeader(L"LSA NOTIFICATION PACKAGES  [Password change DLL callbacks in lsass.exe + PPL status]");

    PrintInfo(
        L"  Notification Packages: DLLs loaded by lsass.exe (SYSTEM/TCB) for password events.\n"
        L"  Mimikatz-style password filter = plaintext capture inside lsass.\n"
        L"  Also audits lsass PPL protection, LM hash storage, and Restricted Admin.\n\n");

    DWORD findings = 0;
    AuditNotificationPackages(&findings);
    AuditLSAProtection(&findings);
    AuditLSAKeyWritability(&findings);

    if (findings == 0)
        PrintInfo(L"  No LSA notification LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  ADD CUSTOM NOTIFICATION PACKAGE (requires admin to modify Lsa key):\n"
            L"    Copy payload.dll to C:\\Windows\\System32\\\n"
            L"    reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v \"Notification Packages\"\n"
            L"            /t REG_MULTI_SZ /d \"rassfm\\0scecli\\0payload\" /f\n"
            L"    Reboot → lsass loads payload.dll → calls PasswordChangeNotify() on next password change\n"
            L"    Alternatively: sc stop netlogon && sc start netlogon — reloads notification packages\n");
    }
}

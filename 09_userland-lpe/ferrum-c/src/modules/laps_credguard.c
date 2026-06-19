/*
 * laps_credguard.c — LAPS, Credential Guard, VBS, and Device Guard Status Audit
 *
 * RESEARCH SOURCES:
 *   - LAPS (Local Administrator Password Solution):
 *     Shay Levy: LAPS deployment misconfigurations (TechEd presentation 2016)
 *     Sean Metcalf: LAPS implementation weaknesses (ADSecurity.org)
 *     HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd — LAPS policy
 *     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS — newer LAPS v2
 *   - Credential Guard / LSA Protected Mode:
 *     HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
 *     HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags
 *     HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard
 *   - VBS (Virtualization Based Security):
 *     HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\ (EnableVirtualizationBasedSecurity)
 *   - PPL (Protected Process Light):
 *     HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL — covered in lsa_notify.c but
 *     here we check Credential Guard combination effect
 *   - Research: Benjamin Delpy (mimikatz author) — Credential Guard bypass research
 *     Alex Ionescu: Virtualization-based security internals
 *     Matt Graeber: WDAC bypass techniques
 *     Will Schroeder: BloodHound-based LAPS privilege escalation
 *
 * ATTACK SURFACE:
 *   1. LAPS not enabled → local Administrator account has static/known password
 *   2. LAPS enabled but AdmPwdEnabled=1 without proper ACL → can read AD attribute
 *   3. Credential Guard disabled → can dump NTLM hashes from lsass
 *   4. VBS disabled → no hypervisor memory isolation → kernel exploits more effective
 *   5. LAPS v2 (Windows LAPS) newer API: dsreg, recovery key location
 *   6. WDAC (Windows Defender Application Control) status — affects exploit delivery
 *   7. Secure Boot status — affects UEFI-level persistence
 *
 * REFERENCES:
 *   MS-LAPS: Local Administrator Password Solution documentation
 *   MSDN: DeviceGuard registry keys
 *   MITRE T1556 — Modify Authentication Process (adjacent)
 *   ADSecurity.org: LAPS internals
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Audit LAPS configuration
 * --------------------------------------------------------------------- */
static void AuditLAPS(DWORD *findings) {
    PrintInfo(L"  [1] LAPS (Local Administrator Password Solution) status:\n");

    /* LAPS v1 (legacy AdmPwd.dll) */
    static const struct { const wchar_t *keyPath; const wchar_t *version; } LAPS_KEYS[] = {
        { L"SOFTWARE\\Policies\\Microsoft Services\\AdmPwd", L"LAPS v1 (AdmPwd)" },
        { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\LAPS", L"LAPS v2 (Windows LAPS)" },
        { NULL, NULL }
    };

    BOOL lapsFound = FALSE;
    for (int ki = 0; LAPS_KEYS[ki].keyPath; ki++) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, LAPS_KEYS[ki].keyPath,
                          0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;

        lapsFound = TRUE;
        DWORD enabled = 0, cb = sizeof(enabled);
        RegQueryValueExW(hKey, L"AdmPwdEnabled", NULL, NULL, (LPBYTE)&enabled, &cb);

        DWORD backupDir = 0;
        cb = sizeof(backupDir);
        RegQueryValueExW(hKey, L"BackupDirectory", NULL, NULL, (LPBYTE)&backupDir, &cb);

        DWORD pwdAge = 0;
        cb = sizeof(pwdAge);
        RegQueryValueExW(hKey, L"PasswordAgeDays", NULL, NULL, (LPBYTE)&pwdAge, &cb);

        PrintInfo(L"    %s: found\n"
                  L"      AdmPwdEnabled: %lu  BackupDirectory: %lu  PasswordAgeDays: %lu\n",
                  LAPS_KEYS[ki].version, enabled, backupDir, pwdAge);

        if (!enabled) {
            PrintInfo(L"      [!] LAPS key present but AdmPwdEnabled=0 — LAPS NOT active!\n");
            Finding f;
            f.severity = SEV_MEDIUM;
            wcscpy(f.module, L"LAPSCG");
            _snwprintf(f.target, _countof(f.target),
                L"[CONFIG] %s present but disabled (AdmPwdEnabled=0)", LAPS_KEYS[ki].version);
            wcscpy(f.reason,
                L"LAPS is installed but not enabled — local Administrator password is NOT managed.\n"
                L"        Local admin account likely has static/reused password across machines.\n"
                L"        Obtain password once → lateral movement to all machines in scope.\n"
                L"        Check: net user Administrator — see if account is enabled.");
            PrintFinding(&f);
            (*findings)++;
        }
        RegCloseKey(hKey);
    }

    if (!lapsFound) {
        PrintInfo(L"    LAPS: NOT INSTALLED\n");
        PrintInfo(L"    [!] No LAPS detected — local admin password is likely static.\n");
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"LAPSCG");
        wcscpy(f.target, L"[NOT INSTALLED] LAPS not configured on this machine");
        wcscpy(f.reason,
            L"LAPS (Local Administrator Password Solution) is not installed or configured.\n"
            L"        Local Administrator account likely has a static password shared across machines.\n"
            L"        If you obtain the local admin password → lateral movement to all systems.\n"
            L"        Check: net user Administrator to see if account is enabled.");
        PrintFinding(&f);
        (*findings)++;
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit Credential Guard status
 * --------------------------------------------------------------------- */
static void AuditCredentialGuard(DWORD *findings) {
    PrintInfo(L"  [2] Credential Guard / LSA isolation status:\n");

    /* Credential Guard config */
    HKEY hDG = NULL;
    DWORD cgEnabled = 0, cgCfgFlags = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\CredentialGuard",
                      0, KEY_READ, &hDG) == ERROR_SUCCESS) {
        DWORD cb = sizeof(cgEnabled);
        RegQueryValueExW(hDG, L"Enabled", NULL, NULL, (LPBYTE)&cgEnabled, &cb);
        RegCloseKey(hDG);
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                      0, KEY_READ, &hDG) == ERROR_SUCCESS) {
        DWORD cb = sizeof(cgCfgFlags);
        RegQueryValueExW(hDG, L"LsaCfgFlags", NULL, NULL, (LPBYTE)&cgCfgFlags, &cb);
        RegCloseKey(hDG);
    }

    PrintInfo(L"    Credential Guard enabled: %lu  LsaCfgFlags: %lu\n",
              cgEnabled, cgCfgFlags);

    if (!cgEnabled && cgCfgFlags == 0) {
        PrintInfo(L"    [!] Credential Guard is DISABLED — lsass credentials may be dumpable.\n");
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"LAPSCG");
        wcscpy(f.target, L"[DISABLED] Credential Guard is not enabled — NTLM hash dump possible");
        wcscpy(f.reason,
            L"Credential Guard is disabled — lsass runs without VTL1 isolation.\n"
            L"        Credential material (NTLM hashes, Kerberos TGTs) accessible in lsass memory.\n"
            L"        With SeDebugPrivilege or kernel access: mimikatz sekurlsa::logonpasswords\n"
            L"        With PPL bypass (ProtectedProcessLight): LSASS dump → full credential access.\n"
            L"        Enable: gpedit → Computer Configuration → Credential Guard → Enable with UEFI lock");
        PrintFinding(&f);
        (*findings)++;
    } else {
        PrintInfo(L"    Credential Guard appears configured (lsass credential isolation active)\n");
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit VBS (Virtualization Based Security) status
 * --------------------------------------------------------------------- */
static void AuditVBS(DWORD *findings) {
    PrintInfo(L"  [3] Virtualization Based Security (VBS / HVCI) status:\n");

    HKEY hDG = NULL;
    DWORD vbsEnabled = 0, hvciEnabled = 0, requiredFlags = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                      0, KEY_READ, &hDG) == ERROR_SUCCESS) {
        DWORD cb = sizeof(vbsEnabled);
        RegQueryValueExW(hDG, L"EnableVirtualizationBasedSecurity", NULL, NULL,
                         (LPBYTE)&vbsEnabled, &cb);
        cb = sizeof(requiredFlags);
        RegQueryValueExW(hDG, L"RequirePlatformSecurityFeatures", NULL, NULL,
                         (LPBYTE)&requiredFlags, &cb);
        RegCloseKey(hDG);
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
                      0, KEY_READ, &hDG) == ERROR_SUCCESS) {
        DWORD cb = sizeof(hvciEnabled);
        RegQueryValueExW(hDG, L"Enabled", NULL, NULL, (LPBYTE)&hvciEnabled, &cb);
        RegCloseKey(hDG);
    }

    PrintInfo(L"    VBS enabled: %lu  HVCI enabled: %lu  RequiredFlags: %lu\n",
              vbsEnabled, hvciEnabled, requiredFlags);

    if (!vbsEnabled) {
        PrintInfo(L"    [!] VBS is DISABLED — no hypervisor memory protection.\n");
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"LAPSCG");
        wcscpy(f.target, L"[DISABLED] VBS/HVCI not enabled — kernel exploit more feasible");
        wcscpy(f.reason,
            L"Virtualization Based Security (VBS) is disabled.\n"
            L"        No Hypervisor-enforced Code Integrity (HVCI) protection.\n"
            L"        Kernel exploits and BYOVD attacks are not blocked by HVCI.\n"
            L"        Loaded kernel drivers have no integrity enforcement at VTL1.\n"
            L"        Combined with unsigned driver loading → kernel-level SYSTEM access.");
        PrintFinding(&f);
        (*findings)++;
    }
    if (!hvciEnabled) {
        PrintInfo(L"    [INFO] HVCI not enabled — kernel code integrity is not hypervisor-enforced\n");
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Audit Secure Boot status
 * --------------------------------------------------------------------- */
static void AuditSecureBoot(void) {
    PrintInfo(L"  [4] Secure Boot status:\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD uefisecureboot = 0, cb = sizeof(uefisecureboot);
        RegQueryValueExW(hKey, L"UEFISecureBootEnabled", NULL, NULL,
                         (LPBYTE)&uefisecureboot, &cb);
        RegCloseKey(hKey);
        PrintInfo(L"    UEFISecureBootEnabled: %lu (%s)\n",
                  uefisecureboot,
                  uefisecureboot ? L"Secure Boot ON" : L"Secure Boot OFF — UEFI persistence possible");
    } else {
        PrintInfo(L"    Secure Boot state key not found (legacy BIOS or key not present)\n");
    }
    PrintInfo(L"\n");
}

void Module_LAPSCredGuard(void) {
    PrintHeader(L"LAPS & CREDENTIAL GUARD  [LAPS config, Credential Guard, VBS/HVCI, Secure Boot audit]");

    PrintInfo(
        L"  LAPS absence → static local admin password → lateral movement.\n"
        L"  Credential Guard disabled → lsass credential dump possible.\n"
        L"  VBS/HVCI disabled → kernel exploit / BYOVD easier.\n\n");

    DWORD findings = 0;
    AuditLAPS(&findings);
    AuditCredentialGuard(&findings);
    AuditVBS(&findings);
    AuditSecureBoot();

    if (findings == 0)
        PrintInfo(L"  Security posture appears configured correctly for these controls.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

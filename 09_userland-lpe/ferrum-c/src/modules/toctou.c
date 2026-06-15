/*
 * toctou.c — TOCTOU / Shared-Write Directory Surface Detector
 *
 * WHAT IS TOCTOU IN WINDOWS LPE CONTEXT:
 *   Time-Of-Check Time-Of-Use race conditions arise when a privileged process:
 *     1. Checks whether a file/directory exists (CHECK)
 *     2. Between check and use, attacker swaps the target (RACE WINDOW)
 *     3. Process opens/executes the now-different target (USE)
 *
 *   Windows adds Opportunistic Lock (oplock) as the primary primitive to WIN races:
 *     - Attacker: open a file in a shared dir exclusively → grab exclusive oplock
 *     - SYSTEM process: tries to open same file → kernel blocks it, notifies attacker
 *     - Attacker: during the block window, swaps the file (junction, symlink, content)
 *     - Attacker: releases oplock → SYSTEM continues with the swapped target
 *
 *   This class of bugs powered many SandboxEscaper vulnerabilities (2018-2019)
 *   and is still an active research area.
 *
 * WHAT THIS MODULE DETECTS:
 *
 *   1. SHARED WRITABLE DIRECTORIES:
 *      Directories where BOTH the current non-admin user AND SYSTEM have write
 *      access. These are TOCTOU candidate sites — if any SYSTEM process reads
 *      or writes files there with predictable names, it's exploitable.
 *
 *   2. PREDICTABLE TEMP FILE PATTERNS:
 *      Service binaries or DLLs whose paths suggest they write to shared temp dirs:
 *        - %TEMP% in service context (service inherits env vars?)
 *        - C:\Windows\Temp (world-readable, often not world-writable but varies)
 *        - C:\ProgramData\<product>\ (sometimes both user and SYSTEM writable)
 *      These signal that the service MAY create files with predictable names.
 *
 *   3. OPLOCK CANDIDATE FILES:
 *      Files in shared-writable directories that are:
 *        - Owned by SYSTEM/TrustedInstaller (suggests SYSTEM creates them)
 *        - Readable but not writable by current user (SYSTEM-owned content)
 *        - Have predictable/enumerable names (not GUIDs)
 *      These are candidates for oplock-based TOCTOU exploitation.
 *
 * EXPLOIT FLOW (if a CRITICAL finding is found):
 *   1. Delete or acquire oplock on the flagged file in the shared dir
 *   2. Create a junction: <sharedDir> → C:\Windows\System32\
 *   3. Wait for SYSTEM service to trigger the write/read
 *   4. The SYSTEM service now writes to / reads from System32 via the junction
 *   5. Combine with a symlink in System32 pointing to target (e.g., SAM file)
 *
 * REFERENCES:
 *   SandboxEscaper:  github.com/SandboxEscaper (TOCTOU via task scheduler, etc.)
 *   CVE-2019-0841:   Windows AppX Deployment via NTFS symlink TOCTOU
 *   CVE-2021-34486:  Windows Event Log TOCTOU
 *   CVE-2022-21882:  Win32k TOCTOU (kernel, different class but same pattern)
 *   Clément Labro:   "Windows Server 2008-2022 unquoted service path + TOCTOU"
 *   James Forshaw:   "Abusing Windows Oplocks for Privilege Escalation"
 *                    (project-zero.blogspot.com)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Get SYSTEM SID
 * --------------------------------------------------------------------- */
static PSID GetSystemSid(void) {
    PSID pSid = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                             0,0,0,0,0,0,0, &pSid);
    return pSid;
}

/* -----------------------------------------------------------------------
 * Check if SYSTEM has write access to a directory (by DACL inspection,
 * not by impersonation — impersonating SYSTEM from userland is impossible)
 * We approximate: if SYSTEM appears in DACL with write/full rights,
 * report it as "SYSTEM writable". The real check would need kernel.
 * --------------------------------------------------------------------- */
static BOOL SystemHasWriteAccess(LPCWSTR path) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL pDacl = NULL;

    if (GetNamedSecurityInfoW(path, SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            NULL, NULL, &pDacl, NULL, &pSD) != ERROR_SUCCESS)
        return FALSE;

    PSID pSystemSid = GetSystemSid();
    BOOL result = FALSE;

    if (pDacl && pSystemSid) {
        ACL_SIZE_INFORMATION aclInfo = {0};
        GetAclInformation(pDacl, &aclInfo, sizeof(aclInfo), AclSizeInformation);

        for (DWORD i = 0; i < aclInfo.AceCount; i++) {
            PACE_HEADER pAce = NULL;
            if (!GetAce(pDacl, i, (LPVOID*)&pAce)) continue;
            if (pAce->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

            PACCESS_ALLOWED_ACE pAllow = (PACCESS_ALLOWED_ACE)pAce;
            PSID aceSid = (PSID)&pAllow->SidStart;

            if (EqualSid(aceSid, pSystemSid)) {
                /* SYSTEM has some access — check for write bits */
                ACCESS_MASK mask = pAllow->Mask;
                if (mask & (FILE_WRITE_DATA | FILE_ADD_FILE |
                            FILE_ADD_SUBDIRECTORY | GENERIC_WRITE |
                            GENERIC_ALL | FILE_ALL_ACCESS)) {
                    result = TRUE;
                    break;
                }
            }
        }
    }

    if (pSystemSid) FreeSid(pSystemSid);
    if (pSD)        LocalFree(pSD);
    return result;
}

/* -----------------------------------------------------------------------
 * Is this path clearly a "predictable" name (not a GUID or random string)?
 * Simple heuristic: ≤32 chars, no dashes in GUID pattern, no 8+ hex run.
 * --------------------------------------------------------------------- */
static BOOL IsPredictableName(LPCWSTR name) {
    if (!name) return FALSE;
    size_t len = wcslen(name);
    if (len == 0 || len > 48) return FALSE;

    /* GUID pattern: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} */
    if (len == 38 && name[0] == L'{' && name[37] == L'}') return FALSE;

    /* Long hex run (temp file like ~DE1234AB.tmp) — still somewhat predictable
     * but flag it as lower severity */
    int hexRun = 0;
    for (size_t i = 0; i < len; i++) {
        wchar_t c = name[i];
        if ((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') ||
            (c >= L'A' && c <= L'F')) {
            if (++hexRun >= 8) return FALSE;
        } else {
            hexRun = 0;
        }
    }
    return TRUE;
}

/* -----------------------------------------------------------------------
 * Enumerate files in a shared writable directory, flag oplock candidates.
 * --------------------------------------------------------------------- */
static void FindOplockCandidates(LPCWSTR dirPath, DWORD *findings) {
    wchar_t pattern[MAX_PATH * 2];
    _snwprintf(pattern, _countof(pattern), L"%s\\*", dirPath);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    DWORD count = 0;
    do {
        if (fd.cFileName[0] == L'.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        count++;

        /* Only check files with "predictable" names */
        if (!IsPredictableName(fd.cFileName)) continue;

        wchar_t fullPath[MAX_PATH * 2];
        _snwprintf(fullPath, _countof(fullPath), L"%s\\%s", dirPath, fd.cFileName);

        /* Check if file is NOT writable by current user (SYSTEM-created content)
         * but IS in a user-writable directory. This is the prime oplock target. */
        BOOL userCanWrite = IsFileWritable(fullPath);

        if (!userCanWrite) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"TOCTOU");
            wcsncpy(f.target, fullPath, _countof(f.target) - 1);
            _snwprintf(f.reason, _countof(f.reason),
                L"OPLOCK CANDIDATE: File in shared-writable dir is NOT writable "
                L"by user (SYSTEM-created), but has predictable name. "
                L"Attack: grab exclusive oplock before SYSTEM creates/reads it "
                L"(use SetFileCompletionNotificationModes + oplock API). "
                L"During oplock break window, replace dir with junction to target. "
                L"Verify: Process Monitor filter [Path=%s, Operation=ReadFile/WriteFile, "
                L"Process=<SYSTEMservice>]", fullPath);
            PrintFinding(&f);
            (*findings)++;
        }

    } while (FindNextFileW(hFind, &fd) && count < 500);

    FindClose(hFind);
}

/* -----------------------------------------------------------------------
 * Check a candidate "shared writable" directory
 * --------------------------------------------------------------------- */
static void CheckSharedDir(LPCWSTR path, LPCWSTR label, DWORD *findings) {
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return;

    BOOL userWrite   = IsDirWritable(path);
    BOOL systemWrite = SystemHasWriteAccess(path);

    if (!userWrite) return;  /* User can't write here, not interesting */

    PrintInfo(L"  [+] Shared writable: %s  [%s]\n", path, label);

    if (systemWrite) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"TOCTOU");
        wcsncpy(f.target, path, _countof(f.target) - 1);
        _snwprintf(f.reason, _countof(f.reason),
            L"SHARED WRITE DIRECTORY: Both SYSTEM and current user have write access. "
            L"TOCTOU attack surface: if any SYSTEM service creates files here with "
            L"predictable names, oplock + junction attack is possible. "
            L"Next: use Process Monitor to watch [Path starts with %s] AND "
            L"[Process Integrity=SYSTEM] AND [Operation=CreateFile/WriteFile]", path);
        PrintFinding(&f);
        (*findings)++;

        /* Enumerate files in the dir for oplock candidates */
        FindOplockCandidates(path, findings);
    }
}

/* -----------------------------------------------------------------------
 * Check if any service binary is located near shared writable dirs
 * (working directory hijack / service creates temp files near its binary)
 * --------------------------------------------------------------------- */
static void CheckServiceNearSharedDirs(DWORD *findings) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD needed = 0, count = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                          SERVICE_STATE_ALL, NULL, 0, &needed, &count, NULL, NULL);

    BYTE *buf = HeapAlloc(GetProcessHeap(), 0, needed);
    if (!buf) { CloseServiceHandle(hSCM); return; }

    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                               SERVICE_STATE_ALL, buf, needed,
                               &needed, &count, NULL, NULL)) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseServiceHandle(hSCM);
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSW *svcs = (ENUM_SERVICE_STATUS_PROCESSW *)buf;

    for (DWORD i = 0; i < count; i++) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, svcs[i].lpServiceName,
                                      SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        BYTE   cfgBuf[8192];
        DWORD  cfgNeeded = 0;
        if (!QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)cfgBuf,
                                 sizeof(cfgBuf), &cfgNeeded)) {
            CloseServiceHandle(hSvc);
            continue;
        }
        CloseServiceHandle(hSvc);

        LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)cfgBuf;
        if (!cfg->lpBinaryPathName) continue;

        wchar_t exePath[MAX_PATH * 2] = {0};
        ExtractExePath(cfg->lpBinaryPathName, exePath, _countof(exePath));
        if (!*exePath) continue;

        /* Extract the directory containing the service binary */
        wchar_t svcDir[MAX_PATH * 2];
        wcsncpy(svcDir, exePath, _countof(svcDir) - 1);
        wchar_t *lastSlash = wcsrchr(svcDir, L'\\');
        if (!lastSlash) continue;
        *lastSlash = L'\0';

        /* Is the service directory user-writable? */
        if (!IsDirWritable(svcDir)) continue;

        /* This is a strong signal: SYSTEM service in user-writable dir
         * (DLL hijack already catches this, but the TOCTOU angle is different:
         *  the service might create temp files in its own dir with predictable names) */

        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"TOCTOU");
        _snwprintf(f.target, _countof(f.target),
            L"[%s] %s", svcs[i].lpServiceName, svcDir);
        _snwprintf(f.reason, _countof(f.reason),
            L"Service binary in USER-WRITABLE directory. "
            L"Beyond DLL hijacking: the service may create temp/config files "
            L"in its own dir with predictable names → oplock TOCTOU target. "
            L"Verify: ProcMon filter [Path starts with %s, Process=%s]",
            svcDir, svcs[i].lpServiceName);
        PrintFinding(&f);
        (*findings)++;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseServiceHandle(hSCM);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_TOCTOU(void) {
    PrintHeader(L"TOCTOU / SHARED WRITE SURFACE  [Oplock race condition candidates]");

    PrintInfo(
        L"  Finds directories writable by both SYSTEM and current user.\n"
        L"  These are sites for oplock-based TOCTOU attacks (SandboxEscaper class).\n"
        L"  Tool: NtSetInformationFile(hFile, FileIoCompletionNotificationInfo, ...)\n"
        L"        + DeviceIoControl(FSCTL_REQUEST_OPLOCK_INPUT_BUFFER, ...)\n\n");

    DWORD findings = 0;

    /* ---- Well-known shared-write candidate directories ---- */
    wchar_t winDir[MAX_PATH]  = {0};
    wchar_t progData[MAX_PATH] = {0};
    wchar_t publicDir[MAX_PATH] = {0};
    wchar_t tempDir[MAX_PATH]  = {0};

    GetWindowsDirectoryW(winDir, _countof(winDir));

    /* C:\Windows\Temp */
    wchar_t winTemp[MAX_PATH];
    _snwprintf(winTemp, _countof(winTemp), L"%s\\Temp", winDir);

    /* Expand common locations via env vars */
    ExpandEnvironmentStringsW(L"%ProgramData%", progData, _countof(progData));
    ExpandEnvironmentStringsW(L"%PUBLIC%",       publicDir, _countof(publicDir));
    ExpandEnvironmentStringsW(L"%TEMP%",         tempDir,   _countof(tempDir));

    PrintInfo(L"  Scanning well-known shared directories:\n");
    CheckSharedDir(winTemp,    L"Windows Temp",   &findings);
    CheckSharedDir(publicDir,  L"Public Folder",  &findings);

    /* Enumerate C:\ProgramData\ top-level dirs */
    if (*progData) {
        wchar_t pattern[MAX_PATH * 2];
        _snwprintf(pattern, _countof(pattern), L"%s\\*", progData);
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(pattern, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.cFileName[0] == L'.') continue;
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                wchar_t sub[MAX_PATH * 2];
                _snwprintf(sub, _countof(sub), L"%s\\%s", progData, fd.cFileName);
                CheckSharedDir(sub, L"ProgramData subdir", &findings);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    /* ---- User TEMP in context of elevated processes ---- */
    PrintInfo(L"\n  User TEMP dir: %s\n", tempDir);
    PrintInfo(
        L"  Note: If any auto-elevated COM server inherits user's environment\n"
        L"  and writes to %%TEMP%%, this dir is fully user-controlled = trivial TOCTOU.\n");

    /* ---- Services in user-writable dirs ---- */
    PrintInfo(L"\n  Checking services in user-writable directories...\n");
    CheckServiceNearSharedDirs(&findings);

    PrintInfo(L"\n");

    if (findings == 0) {
        PrintInfo(L"  No shared-write TOCTOU surfaces found.\n");
    } else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  OPLOCK TOCTOU TECHNIQUE (to exploit confirmed findings):\n"
            L"    1. Open target file: CreateFile(path, GENERIC_READ,\n"
            L"       FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, ...)\n"
            L"    2. Request oplock: DeviceIoControl(hFile,\n"
            L"       FSCTL_REQUEST_OPLOCK, &inputBuf, sizeof(inputBuf), ...)\n"
            L"       where inputBuf.Flags = OPLOCK_LEVEL_CACHE_WRITE\n"
            L"    3. Wait: overlapped I/O on oplock handle\n"
            L"    4. When SYSTEM service tries to open → you receive oplock break\n"
            L"    5. During break window: replace dir with NTFS junction\n"
            L"       CreateJunction(dir, L\"\\\\\\\\?\\\\GLOBALROOT\\\\Device\\\\HarddiskVolume...\")\n"
            L"    6. Release oplock → SYSTEM process now opens via your junction\n"
            L"    7. Combine with object manager symlink for arbitrary file write\n\n"
            L"  REFERENCE:\n"
            L"    James Forshaw: https://googleprojectzero.blogspot.com/2015/12/\n"
            L"    SandboxEscaper: CVE-2019-0841, CVE-2019-1069, etc.\n");
    }
}

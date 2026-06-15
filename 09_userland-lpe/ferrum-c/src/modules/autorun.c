/*
 * autorun.c — Comprehensive Startup / Persistence Path Audit
 *
 * ATTACK SURFACE:
 *   Windows has many startup execution locations. If an autorun entry points
 *   to a user-writable binary or a path with a hijackable slot, it's exploitable
 *   for persistence or LPE (if the entry runs at a higher privilege than current).
 *
 * LOCATIONS CHECKED:
 *
 *   Registry Run keys (user-context startup, but some run elevated):
 *     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 *     HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 *     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
 *     HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
 *     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices (Win9x compat)
 *     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
 *     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (Shell, Userinit)
 *
 *   Startup Folders (run in user context on logon):
 *     C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\
 *     %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
 *
 *   Boot/session startup (SYSTEM context):
 *     HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
 *       → executes before any user logon (SYSTEM, smss.exe context)
 *     HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SetupExecute
 *     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\TaskMan
 *
 *   Service-adjacent startup:
 *     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
 *       → shell extension DLLs loaded into explorer.exe (medium integrity)
 *
 * LPE ANGLE:
 *   1. Winlogon\Userinit or Shell pointing to writable binary → runs at logon
 *      for ALL users, including admin logons.
 *   2. BootExecute writable → runs as smss.exe (SYSTEM, very early boot).
 *   3. HKLM Run pointing to user-writable binary → if admin logs in, attacker
 *      binary runs in admin context.
 *   4. Unquoted path in startup entry (same as service unquoted path attack).
 */

#include "../common.h"

typedef struct {
    LPCWSTR label;
    HKEY    root;
    LPCWSTR keyPath;
    LPCWSTR valueName;   /* NULL = enumerate all values */
    BOOL    isBootCtx;   /* TRUE = SYSTEM context (critical severity) */
} AutorunEntry;

/* -----------------------------------------------------------------------
 * Check a command-line string: extract EXE path, check writability,
 * check for unquoted path with spaces.
 * --------------------------------------------------------------------- */
static void AuditCommandLine(LPCWSTR cmdLine, LPCWSTR entryLabel,
                              LPCWSTR valueName, BOOL isSystemCtx,
                              DWORD *findings)
{
    if (!cmdLine || !*cmdLine) return;

    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(cmdLine, expanded, _countof(expanded));

    wchar_t exePath[MAX_PATH * 2] = {0};
    ExtractExePath(expanded, exePath, _countof(exePath));
    if (!*exePath) return;

    /* Skip non-absolute paths: bare commands like "autocheck autochk *",
     * "explorer.exe" (no drive letter), built-in boot references, etc.
     * Only report on paths we can actually verify on disk. */
    BOOL isAbsPath = (exePath[1] == L':' && exePath[2] == L'\\') ||
                     (exePath[0] == L'\\' && exePath[1] == L'\\');
    if (!isAbsPath) return;

    BOOL exists       = (GetFileAttributesW(exePath) != INVALID_FILE_ATTRIBUTES);
    BOOL writable     = exists && IsFileWritable(exePath);
    BOOL inUser       = IsUserWritablePath(exePath);

    /* Unquoted path with spaces check */
    BOOL unquoted = (expanded[0] != L'"') &&
                    (wcschr(expanded, L' ') != NULL);

    /* Directory writable for the EXE location */
    wchar_t exeDir[MAX_PATH * 2] = {0};
    wcsncpy(exeDir, exePath, _countof(exeDir) - 1);
    wchar_t *sl = wcsrchr(exeDir, L'\\');
    BOOL dirWritable = FALSE;
    if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(exeDir); }

    Severity sev = isSystemCtx ? SEV_CRITICAL : SEV_HIGH;

    Finding f;
    wcscpy(f.module, L"AUTORUN");

    if (writable) {
        f.severity = sev;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE EXE] %s : %s", entryLabel, valueName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Startup EXE is WRITABLE by current user. "
            L"Context: %s. Replace EXE → executes at next logon/boot. "
            L"EXE: %s  Full: %s",
            isSystemCtx ? L"SYSTEM/Boot" : L"User-context",
            exePath, cmdLine);
        PrintFinding(&f);
        (*findings)++;
    } else if (!exists) {
        f.severity = isSystemCtx ? SEV_HIGH : SEV_MEDIUM;
        _snwprintf(f.target, _countof(f.target),
            L"[MISSING EXE] %s : %s", entryLabel, valueName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Startup EXE does not exist: %s\n"
            L"        Dir writable: %s. Context: %s.",
            exePath, dirWritable ? L"YES" : L"No",
            isSystemCtx ? L"SYSTEM/Boot" : L"User-context");
        PrintFinding(&f);
        (*findings)++;
    } else if (dirWritable) {
        f.severity = isSystemCtx ? SEV_HIGH : SEV_MEDIUM;
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DIR] %s : %s", entryLabel, valueName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Startup EXE directory is user-writable. "
            L"DLL hijacking or EXE replacement possible. "
            L"Context: %s  Dir: %s",
            isSystemCtx ? L"SYSTEM/Boot" : L"User-context", exeDir);
        PrintFinding(&f);
        (*findings)++;
    } else if (unquoted && wcschr(expanded, L' ')) {
        /* Check if there's a writable slot between spaces */
        wchar_t *sp = expanded;
        while ((sp = wcschr(sp, L' ')) != NULL) {
            *sp = L'\0';
            wchar_t candidate[MAX_PATH * 2];
            _snwprintf(candidate, _countof(candidate), L"%s.exe", expanded);
            /* Check if dir up to that point is writable */
            wchar_t candidateDir[MAX_PATH * 2] = {0};
            wcsncpy(candidateDir, expanded, _countof(candidateDir) - 1);
            wchar_t *sl2 = wcsrchr(candidateDir, L'\\');
            if (sl2) { *sl2 = L'\0'; }
            *sp = L' ';
            if (*candidateDir && IsDirWritable(candidateDir)) {
                f.severity = isSystemCtx ? SEV_HIGH : SEV_MEDIUM;
                _snwprintf(f.target, _countof(f.target),
                    L"[UNQUOTED PATH] %s : %s", entryLabel, valueName);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Startup entry has unquoted path with spaces. "
                    L"Writable slot at: %s. Plant <name>.exe there. "
                    L"Full cmdline: %s", candidateDir, cmdLine);
                PrintFinding(&f);
                (*findings)++;
                break;
            }
            sp++;
        }
    } else if (inUser) {
        f.severity = SEV_LOW;
        _snwprintf(f.target, _countof(f.target),
            L"[USER-PATH] %s : %s", entryLabel, valueName);
        _snwprintf(f.reason, _countof(f.reason),
            L"Startup EXE in user-accessible path. Verify ACL. "
            L"EXE: %s", exePath);
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Enumerate all values under a registry key, audit each as a command line.
 * --------------------------------------------------------------------- */
static void AuditRunKey(HKEY rootHive, LPCWSTR keyPath, LPCWSTR label,
                         BOOL isSystemCtx, DWORD *findings)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(rootHive, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    /* Check if we can write to this key (add new startup entries) */
    BOOL keyWritable = (rootHive == HKEY_LOCAL_MACHINE)
                       ? IsRegKeyWritable(HKEY_LOCAL_MACHINE, keyPath)
                       : FALSE; /* HKCU Run is always user-writable by design */

    if (keyWritable && isSystemCtx) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"AUTORUN");
        _snwprintf(f.target, _countof(f.target), L"[KEY WRITABLE] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"User can write to startup key HKLM\\%s. "
            L"Add a new value → code runs at next logon. "
            L"Context: %s.", keyPath, isSystemCtx ? L"SYSTEM/admin" : L"user");
        PrintFinding(&f);
        (*findings)++;
    }

    DWORD idx = 0;
    wchar_t valName[256], valData[MAX_PATH * 2];
    DWORD   nameCch, dataCb, type;

    while (TRUE) {
        nameCch = _countof(valName);
        dataCb  = sizeof(valData);
        LONG r  = RegEnumValueW(hKey, idx++, valName, &nameCch,
                                NULL, &type, (LPBYTE)valData, &dataCb);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS)       continue;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

        AuditCommandLine(valData, label, valName, isSystemCtx, findings);
    }

    RegCloseKey(hKey);
}

/* -----------------------------------------------------------------------
 * Audit a specific single-value registry autorun (e.g. Userinit, Shell)
 * --------------------------------------------------------------------- */
static void AuditSingleValue(HKEY rootHive, LPCWSTR keyPath, LPCWSTR valName,
                              LPCWSTR label, BOOL isSystemCtx, DWORD *findings)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(rootHive, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    wchar_t valData[MAX_PATH * 2] = {0};
    DWORD   cb = sizeof(valData), type = 0;
    RegQueryValueExW(hKey, valName, NULL, &type, (LPBYTE)valData, &cb);
    RegCloseKey(hKey);

    if (!*valData) return;

    /* Userinit and Shell can be comma-separated */
    wchar_t buf[MAX_PATH * 2];
    wcsncpy(buf, valData, _countof(buf) - 1);
    wchar_t *tok = buf, *comma;

    do {
        comma = wcschr(tok, L',');
        if (comma) *comma = L'\0';
        wchar_t *t = tok;
        while (*t == L' ') t++;
        if (*t) AuditCommandLine(t, label, valName, isSystemCtx, findings);
        tok = comma ? comma + 1 : NULL;
    } while (tok);
}

/* -----------------------------------------------------------------------
 * Audit startup folder (LNK files pointing to executables)
 * --------------------------------------------------------------------- */
static void AuditStartupFolder(LPCWSTR folderPath, LPCWSTR label,
                                BOOL isSystemCtx, DWORD *findings)
{
    if (GetFileAttributesW(folderPath) == INVALID_FILE_ATTRIBUTES) return;

    BOOL folderWritable = IsDirWritable(folderPath);
    if (folderWritable && isSystemCtx) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"AUTORUN");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE STARTUP FOLDER] %s", label);
        _snwprintf(f.reason, _countof(f.reason),
            L"Startup folder is user-writable. Place .lnk or .exe here → "
            L"runs at next logon for all users. "
            L"Context: %s  Path: %s",
            isSystemCtx ? L"All users (admin on next logon)" : L"Current user only",
            folderPath);
        PrintFinding(&f);
        (*findings)++;
    }

    /* Enumerate existing items */
    wchar_t pattern[MAX_PATH * 2];
    _snwprintf(pattern, _countof(pattern), L"%s\\*", folderPath);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.cFileName[0] == L'.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        wchar_t itemPath[MAX_PATH * 2];
        _snwprintf(itemPath, _countof(itemPath), L"%s\\%s", folderPath, fd.cFileName);

        if (IsFileWritable(itemPath)) {
            Finding f;
            f.severity = isSystemCtx ? SEV_HIGH : SEV_MEDIUM;
            wcscpy(f.module, L"AUTORUN");
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE ITEM] %s : %s", label, fd.cFileName);
            _snwprintf(f.reason, _countof(f.reason),
                L"Startup item is user-writable. Context: %s. Path: %s",
                isSystemCtx ? L"All users" : L"Current user", itemPath);
            PrintFinding(&f);
            (*findings)++;
        }

    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_Autorun(void) {
    PrintHeader(L"AUTORUN / STARTUP PATH AUDIT");

    PrintInfo(
        L"  Enumerates all Windows startup locations and checks for\n"
        L"  writable binaries, missing executables, and unquoted paths.\n\n");

    DWORD findings = 0;

    /* --- SYSTEM-context startup (high value for LPE) --- */
    PrintInfo(L"  [SYSTEM context]\n");

    /* BootExecute: runs as smss.exe before user logon */
    AuditSingleValue(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        L"BootExecute",
        L"BootExecute (smss.exe/SYSTEM context)", TRUE, &findings);

    /* Winlogon Shell + Userinit: run at user logon but via winlogon (SYSTEM) */
    AuditSingleValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Shell", L"Winlogon\\Shell", TRUE, &findings);
    AuditSingleValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Userinit", L"Winlogon\\Userinit", TRUE, &findings);
    AuditSingleValue(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"TaskMan", L"Winlogon\\TaskMan", TRUE, &findings);

    /* Shared startup folder (runs for ALL users → runs for admin too) */
    wchar_t commonStartup[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(
        L"%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        commonStartup, _countof(commonStartup));
    AuditStartupFolder(commonStartup, L"Common Startup Folder", TRUE, &findings);

    /* --- User-context startup --- */
    PrintInfo(L"\n  [User context]\n");

    AuditRunKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKLM Run", TRUE, &findings);
    AuditRunKey(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"HKLM RunOnce", TRUE, &findings);
    AuditRunKey(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"HKCU Run", FALSE, &findings);
    AuditRunKey(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"HKCU RunOnce", FALSE, &findings);

    /* User startup folder */
    wchar_t userStartup[MAX_PATH] = {0};
    ExpandEnvironmentStringsW(
        L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        userStartup, _countof(userStartup));
    AuditStartupFolder(userStartup, L"User Startup Folder", FALSE, &findings);

    PrintInfo(L"\n");
    if (findings == 0)
        PrintInfo(L"  No autorun issues found.\n");
    else
        PrintInfo(L"  Total findings: %lu\n", findings);
}

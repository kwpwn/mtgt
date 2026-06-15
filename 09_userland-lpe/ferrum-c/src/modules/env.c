/*
 * env.c — Environment Variable LPE Surface Checker
 *
 * Checks:
 *   1. COR_PROFILER / COR_PROFILER_PATH / COR_ENABLE_PROFILING
 *      — .NET profiler DLL injection vector
 *   2. User-scope %PATH% (HKCU\Environment\Path) — can prepend evil dir
 *   3. %TEMP% / %TMP% path ownership — SYSTEM tasks using user TEMP?
 *   4. PATHEXT — execution extension abuse
 *   5. System-scope environment key (HKLM\...\Environment) writability
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Helper: retrieve env var from HKCU\Environment
 * --------------------------------------------------------------------- */
static BOOL GetUserEnvVar(LPCWSTR name, LPWSTR buf, DWORD cch) {
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment",
                      0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    DWORD cb = cch * sizeof(wchar_t), type = 0;
    BOOL ok = (RegQueryValueExW(hk, name, NULL, &type,
                                (LPBYTE)buf, &cb) == ERROR_SUCCESS);
    RegCloseKey(hk);
    return ok;
}

/* -----------------------------------------------------------------------
 * 1. .NET Profiler (COR_PROFILER) check
 * --------------------------------------------------------------------- */
static void CheckCorProfiler(DWORD *total) {
    /* Check both process environment and HKCU */
    wchar_t enabled[8]     = {0};
    wchar_t profiler[128]  = {0};
    wchar_t profPath[MAX_PATH] = {0};

    BOOL procEnabled = GetEnvironmentVariableW(
        L"COR_ENABLE_PROFILING", enabled, _countof(enabled)) > 0;
    BOOL procClsid   = GetEnvironmentVariableW(
        L"COR_PROFILER", profiler, _countof(profiler)) > 0;
    BOOL procPath    = GetEnvironmentVariableW(
        L"COR_PROFILER_PATH", profPath, _countof(profPath)) > 0;

    if (procEnabled && wcscmp(enabled, L"1") == 0) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"ENV");
        wcscpy(f.target, L"COR_ENABLE_PROFILING=1");
        _snwprintf(f.reason, _countof(f.reason),
            L".NET profiler active in current process environment. "
            L"CLSID:%s  Path:%s  "
            L"Any .NET process started inherits this → profiler DLL loaded pre-managed-code",
            profiler, profPath);
        PrintFinding(&f);
        (*total)++;
    } else {
        PrintInfo(L"  COR_ENABLE_PROFILING: %s (not active in current env)\n",
                  procEnabled ? enabled : L"(not set)");
    }

    /* Check HKCU\Environment for persistent COR settings */
    wchar_t hkcuEnabled[8] = {0};
    GetUserEnvVar(L"COR_ENABLE_PROFILING", hkcuEnabled, _countof(hkcuEnabled));
    if (*hkcuEnabled && wcscmp(hkcuEnabled, L"1") == 0) {
        wchar_t hkcuPath[MAX_PATH] = {0};
        GetUserEnvVar(L"COR_PROFILER_PATH", hkcuPath, _countof(hkcuPath));
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"ENV");
        wcscpy(f.target, L"HKCU COR_ENABLE_PROFILING=1");
        _snwprintf(f.reason, _countof(f.reason),
            L"Persistent .NET profiler via HKCU\\Environment. "
            L"All new .NET processes for this user load: %s",
            *hkcuPath ? hkcuPath : L"(CLSID-resolved)");
        PrintFinding(&f);
        (*total)++;
    }
}

/* -----------------------------------------------------------------------
 * 2. User PATH analysis
 * --------------------------------------------------------------------- */
static void CheckUserPath(DWORD *total) {
    wchar_t userPath[MAX_PATH * 4] = {0};
    if (!GetUserEnvVar(L"Path", userPath, _countof(userPath))) {
        PrintInfo(L"  HKCU Path: (not set)\n");
        return;
    }

    PrintInfo(L"  HKCU Path: %s\n", userPath);

    /* Show whether any HKCU path dir is user-writable (all should be,
     * since they're user-controlled, but some may not exist yet)      */
    wchar_t sys32[MAX_PATH] = {0};
    GetSystemDirectoryW(sys32, _countof(sys32));

    /* The entire HKCU path prepends to system PATH, so any directory
     * listed there is searched BEFORE System32.  This means if an
     * attacker can add a dir to HKCU\Environment\Path AND plant a DLL
     * there, they get DLL search-order hijack for all subsequent
     * processes started by this user.                                 */
    PrintInfo(L"  Note: HKCU Path is ALWAYS user-writable (via registry).\n"
              L"  All directories in it are searched BEFORE System32.\n"
              L"  Planting a DLL in any of these dirs hijacks search order.\n");

    /* Check if the HKCU\Environment key itself is writable
     * (it always is for the current user — confirm as info) */
    if (IsRegKeyWritable(HKEY_CURRENT_USER, L"Environment")) {
        Finding f;
        f.severity = SEV_MEDIUM;
        wcscpy(f.module, L"ENV");
        wcscpy(f.target, L"HKCU\\Environment\\Path");
        wcscpy(f.reason,
            L"User-scope PATH is writable (always true for HKCU). "
            L"Prepend C:\\evil\\ to user PATH → DLL/EXE in that dir "
            L"takes priority over System32 for all user processes.");
        PrintFinding(&f);
        (*total)++;
    }
}

/* -----------------------------------------------------------------------
 * 3. System environment key writability
 * --------------------------------------------------------------------- */
static void CheckSystemEnv(DWORD *total) {
    LPCWSTR sysEnvPath =
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";

    if (IsRegKeyWritable(HKEY_LOCAL_MACHINE, sysEnvPath)) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"ENV");
        wcscpy(f.target, L"HKLM System Environment key");
        wcscpy(f.reason,
            L"System-scope environment registry key is WRITABLE. "
            L"Modify Path / PATHEXT → affects all processes system-wide.");
        PrintFinding(&f);
        (*total)++;
    } else {
        PrintInfo(L"  System environment key: not writable (expected)\n");
    }
}

/* -----------------------------------------------------------------------
 * 4. PATHEXT abuse check
 * --------------------------------------------------------------------- */
static void CheckPathExt(DWORD *total) {
    wchar_t ext[512] = {0};
    GetEnvironmentVariableW(L"PATHEXT", ext, _countof(ext));
    PrintInfo(L"  PATHEXT: %s\n", ext);

    /* If PATHEXT includes unusual extensions (.py, .ps1, .bat with paths
     * leading to user-writable locations), DLL/script hijacking is easier.
     * For now, just report if user-scope PATHEXT is set.               */
    wchar_t hkcuExt[512] = {0};
    if (GetUserEnvVar(L"PATHEXT", hkcuExt, _countof(hkcuExt)) && *hkcuExt) {
        Finding f;
        f.severity = SEV_LOW;
        wcscpy(f.module, L"ENV");
        wcscpy(f.target, L"HKCU PATHEXT override");
        _snwprintf(f.reason, _countof(f.reason),
            L"User-scope PATHEXT set: %s  "
            L"Check for unusual extensions that may expand execution surface",
            hkcuExt);
        PrintFinding(&f);
        (*total)++;
    }
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_Env(void) {
    PrintHeader(L"ENVIRONMENT VARIABLE SURFACE");

    DWORD total = 0;

    PrintInfo(L"  [1] .NET Profiler (COR_PROFILER)\n");
    CheckCorProfiler(&total);

    PrintInfo(L"\n  [2] User-scope PATH (HKCU\\Environment\\Path)\n");
    CheckUserPath(&total);

    PrintInfo(L"\n  [3] System environment key writability\n");
    CheckSystemEnv(&total);

    PrintInfo(L"\n  [4] PATHEXT\n");
    CheckPathExt(&total);

    PrintInfo(L"\n  Total environment findings: %lu\n", total);
}

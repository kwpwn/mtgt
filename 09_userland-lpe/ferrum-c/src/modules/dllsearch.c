/*
 * dllsearch.c — DLL Search Path and KnownDLLs Audit
 *
 * Checks:
 *   1. Every directory in the system %PATH% for user writability.
 *      Directories that appear BEFORE System32 in the search order
 *      and are user-writable allow DLL search-order hijacking.
 *   2. Directories in the user %PATH% (HKCU\Environment\Path) that are
 *      user-writable — these prepend to system PATH.
 *   3. KnownDLLs registry list (what is immune to search order hijacking).
 *   4. Running elevated processes whose application directory is writable
 *      (allowing DLL side-loading).
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Retrieve the KnownDLLs list from the registry.
 * Returns a MULTI_SZ-style double-null-terminated list on the heap.
 * Caller must HeapFree the result.
 * --------------------------------------------------------------------- */
static wchar_t *GetKnownDLLsList(void) {
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
        0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return NULL;

    /* Enumerate values; collect dll names into a flat list */
    const DWORD BUF_CCH = 8192;
    wchar_t *list = (wchar_t *)HeapAlloc(GetProcessHeap(),
                                          HEAP_ZERO_MEMORY,
                                          BUF_CCH * sizeof(wchar_t));
    if (!list) { RegCloseKey(hKey); return NULL; }

    DWORD pos  = 0;
    DWORD idx  = 0;
    wchar_t valName[64], valData[MAX_PATH];
    DWORD   nameCch, dataCb, type;

    while (TRUE) {
        nameCch = _countof(valName);
        dataCb  = sizeof(valData);
        LONG ret = RegEnumValueW(hKey, idx++, valName, &nameCch,
                                  NULL, &type, (LPBYTE)valData, &dataCb);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS)       continue;
        if (type != REG_SZ)             continue;

        /* Store lowercase dll name */
        _wcslwr(valData);
        DWORD len = (DWORD)wcslen(valData);
        if (pos + len + 1 >= BUF_CCH) break;
        wcscpy(list + pos, valData);
        pos += len + 1;
    }
    list[pos] = L'\0';   /* double-null terminator */
    RegCloseKey(hKey);
    return list;
}

/* Returns TRUE if dllName (lowercase) is in the known list */
static BOOL IsKnownDLL(LPCWSTR dllName, LPCWSTR list) {
    if (!list) return FALSE;
    for (const wchar_t *p = list; *p; p += wcslen(p) + 1) {
        if (_wcsicmp(p, dllName) == 0) return TRUE;
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Get System32 path for comparison
 * --------------------------------------------------------------------- */
static void GetSystem32Path(LPWSTR buf, DWORD cch) {
    GetSystemDirectoryW(buf, cch);
    _wcslwr(buf);
}

/* -----------------------------------------------------------------------
 * Audit a single PATH directory
 * --------------------------------------------------------------------- */
typedef struct {
    wchar_t sys32[MAX_PATH];
    BOOL    passedSys32;
    DWORD   findings;
} PathAuditCtx;

static void AuditPathDir(LPCWSTR dir, void *ctx_) {
    PathAuditCtx *ctx = (PathAuditCtx *)ctx_;

    wchar_t lower[MAX_PATH * 2];
    wcsncpy(lower, dir, _countof(lower) - 1);
    lower[_countof(lower) - 1] = L'\0';
    _wcslwr(lower);

    /* Track if we've passed System32 in the ordering */
    if (wcsstr(lower, ctx->sys32))
        ctx->passedSys32 = TRUE;

    if (GetFileAttributesW(dir) == INVALID_FILE_ATTRIBUTES) return;

    if (IsDirWritable(dir)) {
        Finding f;
        f.severity = ctx->passedSys32 ? SEV_LOW : SEV_HIGH;
        wcscpy(f.module, L"DLLSEARCH");
        wcsncpy(f.target, dir, _countof(f.target)-1);
        _snwprintf(f.reason, _countof(f.reason),
            L"User-writable PATH directory  [before System32: %s]",
            ctx->passedSys32 ? L"No" : L"YES — DLL hijack risk");
        PrintFinding(&f);
        ctx->findings++;
    }
}

/* -----------------------------------------------------------------------
 * Elevated process application-directory audit
 * --------------------------------------------------------------------- */
static void AuditElevatedProcessDirs(DWORD *findings) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    BOOL more = Process32FirstW(hSnap, &pe);

    while (more) {
        HANDLE hProc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD rid = GetProcessIntegrityRID(hProc);
            if (rid >= SECURITY_MANDATORY_HIGH_RID) {
                wchar_t exePath[MAX_PATH * 2] = {0};
                if (GetModuleFileNameExW(hProc, NULL, exePath, _countof(exePath))) {
                    /* Get parent directory */
                    wchar_t *lastSlash = wcsrchr(exePath, L'\\');
                    if (lastSlash) {
                        *lastSlash = L'\0';
                        if (IsDirWritable(exePath)) {
                            Finding f;
                            f.severity = SEV_CRITICAL;
                            wcscpy(f.module, L"DLLSEARCH");
                            _snwprintf(f.target, _countof(f.target),
                                L"PID:%lu %s", pe.th32ProcessID, pe.szExeFile);
                            _snwprintf(f.reason, _countof(f.reason),
                                L"Elevated process app-dir is WRITABLE — "
                                L"DLL side-loading: %s\\", exePath);
                            PrintFinding(&f);
                            (*findings)++;
                        }
                    }
                }
            }
            CloseHandle(hProc);
        }
        more = Process32NextW(hSnap, &pe);
    }
    CloseHandle(hSnap);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_DLLSearch(void) {
    PrintHeader(L"DLL SEARCH PATH AUDIT");

    /* Print KnownDLLs for reference */
    wchar_t *knownList = GetKnownDLLsList();
    PrintInfo(L"  KnownDLLs (immune to search-order hijack):\n");
    if (knownList) {
        int cnt = 0;
        for (const wchar_t *p = knownList; *p; p += wcslen(p) + 1) {
            if (cnt % 6 == 0) wprintf(L"    ");
            wprintf(L"%-20s", p);
            if (++cnt % 6 == 0) wprintf(L"\n");
        }
        wprintf(L"\n\n");
    }

    DWORD findings = 0;

    /* -- System PATH audit -- */
    PrintInfo(L"  [System %%PATH%% directories]\n");
    wchar_t syspath[MAX_PATH * 8] = {0};
    GetEnvironmentVariableW(L"PATH", syspath, _countof(syspath));

    PathAuditCtx ctx;
    GetSystem32Path(ctx.sys32, _countof(ctx.sys32));
    ctx.passedSys32 = FALSE;
    ctx.findings    = 0;

    WcsSplit(syspath, L';', AuditPathDir, &ctx);
    findings += ctx.findings;

    /* -- User PATH (HKCU\Environment\Path) -- */
    PrintInfo(L"\n  [User %%PATH%% (HKCU\\Environment\\Path)]\n");
    wchar_t userPath[MAX_PATH * 4] = {0};
    HKEY hEnv = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment",
                      0, KEY_READ, &hEnv) == ERROR_SUCCESS) {
        DWORD cb = sizeof(userPath);
        RegQueryValueExW(hEnv, L"Path", NULL, NULL, (LPBYTE)userPath, &cb);
        RegCloseKey(hEnv);
    }

    if (*userPath) {
        PathAuditCtx uctx;
        GetSystem32Path(uctx.sys32, _countof(uctx.sys32));
        uctx.passedSys32 = FALSE;  /* user PATH prepends, always before Sys32 */
        uctx.findings    = 0;
        WcsSplit(userPath, L';', AuditPathDir, &uctx);
        findings += uctx.findings;
    } else {
        PrintInfo(L"    (no user-scope PATH set)\n");
    }

    /* -- Elevated process application directories -- */
    PrintInfo(L"\n  [Elevated process application directories]\n");
    AuditElevatedProcessDirs(&findings);

    if (findings == 0)
        PrintInfo(L"  No DLL search path issues found.\n");
    else
        PrintInfo(L"\n  Total findings: %lu\n", findings);

    if (knownList) HeapFree(GetProcessHeap(), 0, knownList);
}

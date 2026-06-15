#include "common.h"
#include <stdarg.h>

/* -----------------------------------------------------------------------
 * Globals
 * --------------------------------------------------------------------- */
FILE *g_outFile = NULL;
BOOL  g_noColor = FALSE;

/* -----------------------------------------------------------------------
 * Output helpers
 * --------------------------------------------------------------------- */
static const wchar_t *SeverityLabel(Severity s) {
    switch (s) {
        case SEV_INFO:     return L"INFO";
        case SEV_LOW:      return L"LOW";
        case SEV_MEDIUM:   return L"MEDIUM";
        case SEV_HIGH:     return L"HIGH";
        case SEV_CRITICAL: return L"CRITICAL";
        default:           return L"???";
    }
}

static const wchar_t *SeverityColor(Severity s) {
    if (g_noColor) return L"";
    switch (s) {
        case SEV_INFO:     return CLR_GREEN;
        case SEV_LOW:      return CLR_CYAN;
        case SEV_MEDIUM:   return CLR_YELLOW;
        case SEV_HIGH:     return CLR_RED;
        case SEV_CRITICAL: return CLR_MAGENTA;
        default:           return L"";
    }
}

void PrintHeader(const wchar_t *title) {
    if (!g_noColor)
        wprintf(L"\n" CLR_BOLD CLR_CYAN L"[*] === %s ===" CLR_RESET L"\n", title);
    else
        wprintf(L"\n[*] === %s ===\n", title);
    if (g_outFile)
        fwprintf(g_outFile, L"\n[*] === %s ===\n", title);
}

void PrintFinding(const Finding *f) {
    const wchar_t *col = SeverityColor(f->severity);
    const wchar_t *lbl = SeverityLabel(f->severity);
    const wchar_t *rst = g_noColor ? L"" : CLR_RESET;

    wprintf(L"  %s[%s]%s [%s] %s\n        -> %s\n",
            col, lbl, rst, f->module, f->target, f->reason);

    if (g_outFile)
        fwprintf(g_outFile, L"  [%s] [%s] %s\n        -> %s\n",
                 lbl, f->module, f->target, f->reason);
}

void PrintInfo(const wchar_t *fmt, ...) {
    va_list va;
    va_start(va, fmt);
    vwprintf(fmt, va);
    va_end(va);
    if (g_outFile) {
        va_start(va, fmt);
        vfwprintf(g_outFile, fmt, va);
        va_end(va);
    }
}

/* -----------------------------------------------------------------------
 * ACL / writability helpers
 * --------------------------------------------------------------------- */

/*
 * Core AccessCheck wrapper.
 * Gets the security descriptor for the named object, duplicates the
 * current process token as an impersonation token, then calls AccessCheck.
 */
static BOOL AccessCheckForObject(LPCWSTR path, SE_OBJECT_TYPE objType,
                                  DWORD desiredAccess, GENERIC_MAPPING *pgm)
{
    PSECURITY_DESCRIPTOR pSD  = NULL;
    PACL                 pDacl = NULL;
    HANDLE               hTok  = NULL, hImpTok = NULL;
    BOOL                 result = FALSE;
    DWORD                err;

    err = GetNamedSecurityInfoW(
        (LPWSTR)path, objType,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
        NULL, NULL, &pDacl, NULL, &pSD);
    if (err != ERROR_SUCCESS) goto done;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_QUERY | TOKEN_DUPLICATE, &hTok))
        goto done;

    if (!DuplicateToken(hTok, SecurityImpersonation, &hImpTok))
        goto done;

    MapGenericMask(&desiredAccess, pgm);

    PRIVILEGE_SET privSet;
    DWORD         psLen       = sizeof(privSet);
    DWORD         granted     = 0;
    BOOL          accessOK    = FALSE;

    AccessCheck(pSD, hImpTok, desiredAccess, pgm,
                &privSet, &psLen, &granted, &accessOK);
    result = accessOK;

done:
    if (pSD)     LocalFree(pSD);
    if (hTok)    CloseHandle(hTok);
    if (hImpTok) CloseHandle(hImpTok);
    return result;
}

BOOL IsFileWritable(LPCWSTR path) {
    GENERIC_MAPPING gm = {
        FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
        FILE_GENERIC_EXECUTE,
        FILE_ALL_ACCESS
    };
    return AccessCheckForObject(path, SE_FILE_OBJECT, GENERIC_WRITE, &gm);
}

BOOL IsDirWritable(LPCWSTR dir) {
    /* For directories GENERIC_WRITE includes FILE_ADD_FILE which lets us
     * create new files — that's the primitive we care about.            */
    GENERIC_MAPPING gm = {
        FILE_GENERIC_READ,
        FILE_GENERIC_WRITE,
        FILE_GENERIC_EXECUTE,
        FILE_ALL_ACCESS
    };
    return AccessCheckForObject(dir, SE_FILE_OBJECT, GENERIC_WRITE, &gm);
}

BOOL IsRegKeyWritable(HKEY hRoot, LPCWSTR subkey) {
    /* Open the key, then check with AccessCheck via SE_REGISTRY_KEY.
     * Build the full path string expected by GetNamedSecurityInfo.     */
    wchar_t fullPath[512];
    const wchar_t *rootName = L"UNKNOWN";

    if      (hRoot == HKEY_LOCAL_MACHINE)  rootName = L"MACHINE";
    else if (hRoot == HKEY_CURRENT_USER)   rootName = L"CURRENT_USER";
    else if (hRoot == HKEY_USERS)          rootName = L"USERS";
    else if (hRoot == HKEY_CLASSES_ROOT)   rootName = L"CLASSES_ROOT";

    _snwprintf(fullPath, _countof(fullPath), L"%s\\%s", rootName, subkey);

    GENERIC_MAPPING gm = {
        KEY_READ,
        KEY_WRITE,
        0,
        KEY_ALL_ACCESS
    };
    return AccessCheckForObject(fullPath, SE_REGISTRY_KEY, KEY_SET_VALUE, &gm);
}

BOOL IsUserWritablePath(LPCWSTR path) {
    wchar_t lower[MAX_PATH * 2];
    wcsncpy(lower, path, _countof(lower) - 1);
    lower[_countof(lower) - 1] = L'\0';
    _wcslwr(lower);

    return (wcsstr(lower, L"\\users\\")       != NULL ||
            wcsstr(lower, L"\\temp\\")        != NULL ||
            wcsstr(lower, L"\\programdata\\") != NULL ||
            wcsstr(lower, L"\\appdata\\")     != NULL ||
            wcsstr(lower, L"\\tmp\\")         != NULL);
}

/* -----------------------------------------------------------------------
 * Token / process helpers
 * --------------------------------------------------------------------- */
BOOL GetProcessUser(DWORD pid, LPWSTR buf, DWORD bufCch) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;

    HANDLE hTok = NULL;
    BOOL   ok   = FALSE;

    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) goto done;

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenUser, NULL, 0, &needed);
    TOKEN_USER *pTU = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (!pTU) goto done;

    if (GetTokenInformation(hTok, TokenUser, pTU, needed, &needed)) {
        wchar_t name[256], dom[256];
        DWORD   nameCch = _countof(name), domCch = _countof(dom);
        SID_NAME_USE use;
        if (LookupAccountSidW(NULL, pTU->User.Sid, name, &nameCch,
                               dom, &domCch, &use)) {
            _snwprintf(buf, bufCch, L"%s\\%s", dom, name);
            ok = TRUE;
        }
    }
    HeapFree(GetProcessHeap(), 0, pTU);

done:
    if (hTok)  CloseHandle(hTok);
    CloseHandle(hProc);
    return ok;
}

DWORD GetProcessIntegrityRID(HANDLE hProc) {
    HANDLE hTok = NULL;
    DWORD  rid  = 0;

    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) return 0;

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenIntegrityLevel, NULL, 0, &needed);
    TOKEN_MANDATORY_LABEL *pTML =
        (TOKEN_MANDATORY_LABEL *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (pTML) {
        if (GetTokenInformation(hTok, TokenIntegrityLevel, pTML, needed, &needed)) {
            DWORD subCount = *GetSidSubAuthorityCount(pTML->Label.Sid);
            rid = *GetSidSubAuthority(pTML->Label.Sid, subCount - 1);
        }
        HeapFree(GetProcessHeap(), 0, pTML);
    }

    CloseHandle(hTok);
    return rid;
}

BOOL IsProcessElevated(HANDLE hProc) {
    HANDLE hTok = NULL;
    BOOL   elevated = FALSE;

    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) return FALSE;

    TOKEN_ELEVATION te;
    DWORD needed = sizeof(te);
    if (GetTokenInformation(hTok, TokenElevation, &te, sizeof(te), &needed))
        elevated = (te.TokenIsElevated != 0);

    CloseHandle(hTok);
    return elevated;
}

/* -----------------------------------------------------------------------
 * String helpers
 * --------------------------------------------------------------------- */
BOOL WcsContainsI(LPCWSTR haystack, LPCWSTR needle) {
    if (!haystack || !needle) return FALSE;
    wchar_t h[2048], n[256];
    wcsncpy(h, haystack, _countof(h) - 1); h[_countof(h)-1] = 0;
    wcsncpy(n, needle,   _countof(n) - 1); n[_countof(n)-1] = 0;
    _wcslwr(h);
    _wcslwr(n);
    return wcsstr(h, n) != NULL;
}

int WcsSplit(LPCWSTR str, wchar_t delim, SplitCb cb, void *ctx) {
    if (!str || !cb) return 0;
    wchar_t buf[MAX_PATH * 4];
    wcsncpy(buf, str, _countof(buf) - 1);
    buf[_countof(buf) - 1] = L'\0';

    int count = 0;
    wchar_t *p = buf;
    while (p && *p) {
        wchar_t *end = wcschr(p, delim);
        if (end) *end = L'\0';
        if (*p) {
            cb(p, ctx);
            count++;
        }
        p = end ? end + 1 : NULL;
    }
    return count;
}

BOOL ExtractExePath(LPCWSTR imagePath, LPWSTR out, DWORD outCch) {
    wchar_t expanded[MAX_PATH * 2];
    ExpandEnvironmentStringsW(imagePath, expanded, _countof(expanded));

    const wchar_t *src = expanded;

    /* Strip leading quote */
    if (*src == L'"') {
        src++;
        const wchar_t *endQ = wcschr(src, L'"');
        if (endQ) {
            DWORD len = (DWORD)(endQ - src);
            if (len >= outCch) len = outCch - 1;
            wcsncpy(out, src, len);
            out[len] = L'\0';
            return TRUE;
        }
    }

    /* No quotes: find first argument (space after exe path).
     * Windows parses "C:\foo bar\a.exe args" ambiguously — just give
     * back everything up to and including .exe                       */
    wchar_t tmp[MAX_PATH * 2];
    wcsncpy(tmp, src, _countof(tmp) - 1);
    tmp[_countof(tmp) - 1] = L'\0';

    /* Find ".exe " or ".exe\0" */
    wchar_t *lower = tmp;
    _wcslwr(lower);
    wchar_t *exeEnd = wcsstr(lower, L".exe");
    if (exeEnd) {
        DWORD len = (DWORD)(exeEnd - lower) + 4;
        if (len >= outCch) len = outCch - 1;
        wcsncpy(out, src, len);
        out[len] = L'\0';
        return TRUE;
    }

    /* Fallback: take the whole string */
    wcsncpy(out, src, outCch - 1);
    out[outCch - 1] = L'\0';
    return TRUE;
}

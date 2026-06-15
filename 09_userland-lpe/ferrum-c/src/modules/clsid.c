/*
 * clsid.c — COM CLSID Hijack Candidate Scanner
 *
 * Strategy:
 *  1. Enumerate running processes; note elevated / SYSTEM ones.
 *  2. Enumerate HKLM\SOFTWARE\Classes\CLSID for all InprocServer32 entries.
 *  3. For each CLSID, check whether HKCU\SOFTWARE\Classes\CLSID\{guid} exists.
 *     If NOT: it's a hijack candidate (privileged process may look there first).
 *  4. Separately flag CLSIDs with Elevation\Enabled=1 (auto-elevate COM objects).
 *
 * Note: This enumerates ALL HKLM CLSIDs.  On a typical Windows install that is
 * 5000–15000 entries.  The registry API calls are fast; expect < 5 s total.
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Check if HKCU has a registration for this CLSID (any subkey present).
 * --------------------------------------------------------------------- */
static BOOL HkcuHasCLSID(LPCWSTR clsid) {
    wchar_t path[256];
    _snwprintf(path, _countof(path),
        L"SOFTWARE\\Classes\\CLSID\\%s", clsid);
    HKEY hk = NULL;
    BOOL found = (RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_READ, &hk)
                  == ERROR_SUCCESS);
    if (found) RegCloseKey(hk);
    return found;
}

/* -----------------------------------------------------------------------
 * Returns TRUE if HKLM CLSID has Elevation\Enabled = 1.
 * --------------------------------------------------------------------- */
static BOOL IsAutoElevateCLSID(LPCWSTR clsid) {
    wchar_t path[256];
    _snwprintf(path, _countof(path),
        L"SOFTWARE\\Classes\\CLSID\\%s\\Elevation", clsid);
    HKEY  hk  = NULL;
    BOOL  res = FALSE;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk)
            != ERROR_SUCCESS)
        return FALSE;
    DWORD val = 0, cb = sizeof(val), type = 0;
    if (RegQueryValueExW(hk, L"Enabled", NULL, &type,
                         (LPBYTE)&val, &cb) == ERROR_SUCCESS)
        res = (val == 1);
    RegCloseKey(hk);
    return res;
}

/* -----------------------------------------------------------------------
 * Check if InprocServer32 exists and get its DLL path.
 * --------------------------------------------------------------------- */
static BOOL GetInprocDLL(LPCWSTR clsid, LPWSTR dllBuf, DWORD dllCch) {
    wchar_t path[256];
    _snwprintf(path, _countof(path),
        L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hk)
            != ERROR_SUCCESS)
        return FALSE;

    DWORD type = 0, cb = dllCch * sizeof(wchar_t);
    BOOL ok = (RegQueryValueExW(hk, NULL, NULL, &type,
                                (LPBYTE)dllBuf, &cb) == ERROR_SUCCESS);
    RegCloseKey(hk);

    if (ok && *dllBuf) {
        wchar_t expanded[MAX_PATH * 2];
        ExpandEnvironmentStringsW(dllBuf, expanded, _countof(expanded));
        wcsncpy(dllBuf, expanded, dllCch - 1);
        dllBuf[dllCch - 1] = L'\0';
    }
    return ok;
}

/* -----------------------------------------------------------------------
 * Gather a short summary of elevated process names for context output.
 * --------------------------------------------------------------------- */
static void PrintElevatedProcesses(void) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    BOOL more = Process32FirstW(hSnap, &pe);
    int  cnt  = 0;

    wprintf(L"  Elevated / SYSTEM processes (COM CLSIDs they use are targets):\n");

    while (more && cnt < 20) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                   FALSE, pe.th32ProcessID);
        if (hProc) {
            DWORD rid = GetProcessIntegrityRID(hProc);
            if (rid >= SECURITY_MANDATORY_HIGH_RID) {
                wchar_t user[128] = {0};
                GetProcessUser(pe.th32ProcessID, user, _countof(user));
                wprintf(L"    PID:%-6lu %-28s %s\n",
                    pe.th32ProcessID, pe.szExeFile,
                    rid >= SECURITY_MANDATORY_SYSTEM_RID ? L"[SYSTEM]" : L"[HIGH]");
                cnt++;
            }
            CloseHandle(hProc);
        }
        more = Process32NextW(hSnap, &pe);
    }
    CloseHandle(hSnap);
    if (cnt == 0)
        wprintf(L"    (none visible — try running as standard user)\n");
    wprintf(L"\n");
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_CLSID(void) {
    PrintHeader(L"COM CLSID HIJACK CANDIDATES");

    PrintElevatedProcesses();

    HKEY hClsidKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Classes\\CLSID",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS,
                      &hClsidKey) != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open HKLM\\SOFTWARE\\Classes\\CLSID\n");
        return;
    }

    DWORD hijackCount    = 0;
    DWORD autoElevCount  = 0;
    DWORD index          = 0;
    wchar_t clsid[128];
    DWORD   clsidCch;

    while (TRUE) {
        clsidCch = _countof(clsid);
        LONG ret = RegEnumKeyExW(hClsidKey, index++, clsid, &clsidCch,
                                 NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS)       continue;

        wchar_t dllPath[MAX_PATH * 2] = {0};
        if (!GetInprocDLL(clsid, dllPath, _countof(dllPath)))
            continue;   /* no InprocServer32 → not interesting for DLL hijack */

        BOOL autoElev  = IsAutoElevateCLSID(clsid);
        BOOL hkcuMiss  = !HkcuHasCLSID(clsid);

        /* Auto-elevation CLSIDs: flag regardless of HKCU state */
        if (autoElev) {
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"CLSID");
            wcsncpy(f.target, clsid, _countof(f.target)-1);
            _snwprintf(f.reason, _countof(f.reason),
                L"Auto-elevation COM object (Elevation\\Enabled=1). "
                L"Research interface exposure. DLL: %s", dllPath);
            PrintFinding(&f);
            autoElevCount++;
        }

        /* Hijack candidates: HKLM registered but no HKCU override yet */
        if (hkcuMiss) {
            /* Only report if DLL path is NOT in a trusted location
             * (i.e., not System32) — reduces noise significantly.
             * Also report if DLL itself is missing (phantom CLSID).   */
            BOOL dllMissing  = (GetFileAttributesW(dllPath)
                                == INVALID_FILE_ATTRIBUTES);
            BOOL notSystem32 = !WcsContainsI(dllPath, L"\\system32\\") &&
                               !WcsContainsI(dllPath, L"\\syswow64\\");

            if (dllMissing || notSystem32) {
                Finding f;
                f.severity = dllMissing ? SEV_CRITICAL : SEV_MEDIUM;
                wcscpy(f.module, L"CLSID");
                wcsncpy(f.target, clsid, _countof(f.target)-1);
                if (dllMissing)
                    _snwprintf(f.reason, _countof(f.reason),
                        L"Phantom CLSID: DLL not found on disk. "
                        L"Plant at HKCU override. Missing: %s", dllPath);
                else
                    _snwprintf(f.reason, _countof(f.reason),
                        L"No HKCU override. DLL outside System32. "
                        L"Candidate: %s", dllPath);
                PrintFinding(&f);
                hijackCount++;
            }
        }
    }

    RegCloseKey(hClsidKey);
    PrintInfo(L"  Hijack candidates: %lu  |  Auto-elevation CLSIDs: %lu\n",
              hijackCount, autoElevCount);
    PrintInfo(L"  Tip: Use ProcMon (RegOpenKey + HKCU + NAME NOT FOUND) for runtime targets.\n");
}

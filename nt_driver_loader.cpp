#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <vector>

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

typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
);

typedef VOID(NTAPI* pRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

typedef NTSTATUS(NTAPI* pNtCreateKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG TitleIndex,
    PUNICODE_STRING Class,
    ULONG CreateOptions,
    PULONG Disposition
);

typedef NTSTATUS(NTAPI* pNtOpenKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS(NTAPI* pNtSetValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
);

typedef NTSTATUS(NTAPI* pNtDeleteKey)(HANDLE KeyHandle);
typedef NTSTATUS(NTAPI* pNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* pNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* pNtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI* pNtCreateFile)(
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

typedef NTSTATUS(NTAPI* pNtWriteFile)(
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

typedef NTSTATUS(NTAPI* pNtDeleteFile)(POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
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

struct NtApi {
    pRtlAdjustPrivilege RtlAdjustPrivilege;
    pRtlInitUnicodeString RtlInitUnicodeString;
    pNtCreateKey NtCreateKey;
    pNtOpenKey NtOpenKey;
    pNtSetValueKey NtSetValueKey;
    pNtDeleteKey NtDeleteKey;
    pNtLoadDriver NtLoadDriver;
    pNtUnloadDriver NtUnloadDriver;
    pNtClose NtClose;
    pNtCreateFile NtCreateFile;
    pNtWriteFile NtWriteFile;
    pNtDeleteFile NtDeleteFile;
    pNtQuerySystemInformation NtQuerySystemInformation;
};

static NtApi g_Nt = {};

bool ResolveNtApi() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        return false;
    }

    g_Nt.RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    g_Nt.RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    g_Nt.NtCreateKey = (pNtCreateKey)GetProcAddress(ntdll, "NtCreateKey");
    g_Nt.NtOpenKey = (pNtOpenKey)GetProcAddress(ntdll, "NtOpenKey");
    g_Nt.NtSetValueKey = (pNtSetValueKey)GetProcAddress(ntdll, "NtSetValueKey");
    g_Nt.NtDeleteKey = (pNtDeleteKey)GetProcAddress(ntdll, "NtDeleteKey");
    g_Nt.NtLoadDriver = (pNtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");
    g_Nt.NtUnloadDriver = (pNtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
    g_Nt.NtClose = (pNtClose)GetProcAddress(ntdll, "NtClose");
    g_Nt.NtCreateFile = (pNtCreateFile)GetProcAddress(ntdll, "NtCreateFile");
    g_Nt.NtWriteFile = (pNtWriteFile)GetProcAddress(ntdll, "NtWriteFile");
    g_Nt.NtDeleteFile = (pNtDeleteFile)GetProcAddress(ntdll, "NtDeleteFile");
    g_Nt.NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    return g_Nt.RtlAdjustPrivilege &&
        g_Nt.RtlInitUnicodeString &&
        g_Nt.NtCreateKey &&
        g_Nt.NtOpenKey &&
        g_Nt.NtSetValueKey &&
        g_Nt.NtDeleteKey &&
        g_Nt.NtLoadDriver &&
        g_Nt.NtUnloadDriver &&
        g_Nt.NtClose &&
        g_Nt.NtCreateFile &&
        g_Nt.NtWriteFile &&
        g_Nt.NtDeleteFile &&
        g_Nt.NtQuerySystemInformation;
}

void PrintStatus(const char* prefix, NTSTATUS status) {
    std::cout << prefix << "0x" << std::hex << (ULONG)status << std::dec << std::endl;
}

std::wstring StringToWString(const std::string& value) {
    int required = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (required <= 0) {
        return L"";
    }

    std::wstring result(required - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &result[0], required);
    return result;
}

std::string WStringToString(const std::wstring& value) {
    int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return "";
    }

    std::string result(required - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &result[0], required, nullptr, nullptr);
    return result;
}

std::wstring GetFileNameFromPath(const std::wstring& path) {
    size_t lastSlash = path.find_last_of(L"\\/");
    if (lastSlash == std::wstring::npos) {
        return path;
    }
    return path.substr(lastSlash + 1);
}

std::wstring GetTempDriverPath(const std::wstring& driverName) {
    wchar_t tempPath[MAX_PATH] = {};
    DWORD length = GetTempPathW(MAX_PATH, tempPath);
    if (length == 0 || length >= MAX_PATH) {
        return L"";
    }
    return std::wstring(tempPath) + driverName + L".sys";
}

std::wstring DosPathToNtPath(const std::wstring& dosPath) {
    return L"\\??\\" + dosPath;
}

std::wstring BuildServiceNtRegistryPath(const std::wstring& driverName) {
    return L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driverName;
}

bool EnableLoadDriverPrivilegeNt() {
    BOOLEAN previous = FALSE;
    NTSTATUS status = g_Nt.RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &previous);
    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] RtlAdjustPrivilege failed: ", status);
        return false;
    }
    return true;
}

bool WriteEmbeddedDriverNt(const std::wstring& outputPath) {
    std::wstring ntPath = DosPathToNtPath(outputPath);
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb = {};
    HANDLE fileHandle = nullptr;

    g_Nt.RtlInitUnicodeString(&fileName, ntPath.c_str());
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTSTATUS status = g_Nt.NtCreateFile(
        &fileHandle,
        GENERIC_WRITE | SYNCHRONIZE,
        &oa,
        &iosb,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        nullptr,
        0
    );

    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] NtCreateFile failed: ", status);
        return false;
    }

    status = g_Nt.NtWriteFile(
        fileHandle,
        nullptr,
        nullptr,
        nullptr,
        &iosb,
        (PVOID)g_DriverData,
        (ULONG)g_DriverData_size,
        nullptr,
        nullptr
    );

    g_Nt.NtClose(fileHandle);

    if (status != STATUS_SUCCESS || iosb.Information != g_DriverData_size) {
        PrintStatus("[-] NtWriteFile failed: ", status);
        return false;
    }

    std::wcout << L"[+] Driver extracted via NtCreateFile/NtWriteFile: " << outputPath
        << L" (" << (ULONG_PTR)iosb.Information << L" bytes)" << std::endl;
    return true;
}

bool DeleteFileNt(const std::wstring& dosPath) {
    std::wstring ntPath = DosPathToNtPath(dosPath);
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES oa;

    g_Nt.RtlInitUnicodeString(&fileName, ntPath.c_str());
    InitializeObjectAttributes(&oa, &fileName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTSTATUS status = g_Nt.NtDeleteFile(&oa);
    if (status == STATUS_SUCCESS || status == STATUS_OBJECT_NAME_NOT_FOUND) {
        return true;
    }

    PrintStatus("[-] NtDeleteFile failed: ", status);
    return false;
}

bool SetKeyDword(HANDLE keyHandle, const wchar_t* name, DWORD value) {
    UNICODE_STRING valueName;
    g_Nt.RtlInitUnicodeString(&valueName, name);

    NTSTATUS status = g_Nt.NtSetValueKey(
        keyHandle,
        &valueName,
        0,
        REG_DWORD,
        &value,
        sizeof(value)
    );

    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] NtSetValueKey(REG_DWORD) failed: ", status);
        return false;
    }
    return true;
}

bool SetKeyString(HANDLE keyHandle, const wchar_t* name, const std::wstring& value) {
    UNICODE_STRING valueName;
    g_Nt.RtlInitUnicodeString(&valueName, name);

    NTSTATUS status = g_Nt.NtSetValueKey(
        keyHandle,
        &valueName,
        0,
        REG_EXPAND_SZ,
        (PVOID)value.c_str(),
        (ULONG)((value.size() + 1) * sizeof(wchar_t))
    );

    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] NtSetValueKey(REG_EXPAND_SZ) failed: ", status);
        return false;
    }
    return true;
}

bool SetupDriverRegistryNt(const std::wstring& driverName, const std::wstring& driverPath) {
    std::wstring registryPath = BuildServiceNtRegistryPath(driverName);
    std::wstring imagePath = DosPathToNtPath(driverPath);
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES oa;
    HANDLE keyHandle = nullptr;
    ULONG disposition = 0;

    g_Nt.RtlInitUnicodeString(&keyName, registryPath.c_str());
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTSTATUS status = g_Nt.NtCreateKey(
        &keyHandle,
        KEY_ALL_ACCESS,
        &oa,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        &disposition
    );

    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] NtCreateKey failed: ", status);
        return false;
    }

    bool ok =
        SetKeyDword(keyHandle, L"Type", SERVICE_KERNEL_DRIVER) &&
        SetKeyDword(keyHandle, L"Start", SERVICE_DEMAND_START) &&
        SetKeyDword(keyHandle, L"ErrorControl", SERVICE_ERROR_NORMAL) &&
        SetKeyString(keyHandle, L"ImagePath", imagePath);

    g_Nt.NtClose(keyHandle);
    return ok;
}

bool DeleteDriverRegistryKeyNt(const std::wstring& driverName) {
    std::wstring registryPath = BuildServiceNtRegistryPath(driverName);
    UNICODE_STRING keyName;
    OBJECT_ATTRIBUTES oa;
    HANDLE keyHandle = nullptr;

    g_Nt.RtlInitUnicodeString(&keyName, registryPath.c_str());
    InitializeObjectAttributes(&oa, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    NTSTATUS status = g_Nt.NtOpenKey(&keyHandle, DELETE, &oa);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        return true;
    }
    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] NtOpenKey(DELETE) failed: ", status);
        return false;
    }

    status = g_Nt.NtDeleteKey(keyHandle);
    g_Nt.NtClose(keyHandle);

    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] NtDeleteKey failed: ", status);
        return false;
    }
    return true;
}

bool LoadDriverNt(const std::wstring& driverName) {
    std::wstring registryPath = BuildServiceNtRegistryPath(driverName);
    UNICODE_STRING serviceName;
    g_Nt.RtlInitUnicodeString(&serviceName, registryPath.c_str());

    std::wcout << L"[*] NtLoadDriver: " << registryPath << std::endl;
    NTSTATUS status = g_Nt.NtLoadDriver(&serviceName);

    if (status == STATUS_SUCCESS) {
        std::cout << "[+] STATUS_SUCCESS: driver loaded." << std::endl;
        return true;
    }
    if (status == STATUS_IMAGE_ALREADY_LOADED) {
        std::cout << "[!] STATUS_IMAGE_ALREADY_LOADED: driver already loaded." << std::endl;
        return true;
    }

    PrintStatus("[-] NtLoadDriver failed: ", status);
    return false;
}

bool UnloadDriverNt(const std::wstring& driverName) {
    std::wstring registryPath = BuildServiceNtRegistryPath(driverName);
    UNICODE_STRING serviceName;
    g_Nt.RtlInitUnicodeString(&serviceName, registryPath.c_str());

    NTSTATUS status = g_Nt.NtUnloadDriver(&serviceName);
    if (status == STATUS_SUCCESS) {
        std::cout << "[+] Driver unloaded via NtUnloadDriver." << std::endl;
        return true;
    }
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        std::cout << "[*] Driver was not loaded." << std::endl;
        return true;
    }

    PrintStatus("[-] NtUnloadDriver failed: ", status);
    return false;
}

bool IsDriverLoadedNt(const std::wstring& driverFileName) {
    ULONG needed = 0;
    NTSTATUS status = g_Nt.NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needed);
    if (status != STATUS_INFO_LENGTH_MISMATCH || needed == 0) {
        PrintStatus("[-] NtQuerySystemInformation(size) failed: ", status);
        return false;
    }

    std::vector<BYTE> buffer(needed + 0x1000);
    status = g_Nt.NtQuerySystemInformation(
        SystemModuleInformation,
        buffer.data(),
        (ULONG)buffer.size(),
        &needed
    );

    if (status != STATUS_SUCCESS) {
        PrintStatus("[-] NtQuerySystemInformation(modules) failed: ", status);
        return false;
    }

    std::string target = WStringToString(driverFileName);
    PRTL_PROCESS_MODULES_NATIVE modules = (PRTL_PROCESS_MODULES_NATIVE)buffer.data();

    for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
        const RTL_PROCESS_MODULE_INFORMATION_NATIVE& module = modules->Modules[i];
        const char* baseName = (const char*)module.FullPathName + module.OffsetToFileName;
        if (_stricmp(baseName, target.c_str()) == 0) {
            std::cout << "[+] NtQuerySystemInformation confirmed loaded module: "
                << baseName << " at " << module.ImageBase << std::endl;
            return true;
        }
    }

    return false;
}

void CleanupNt(const std::wstring& driverName) {
    UnloadDriverNt(driverName);
    Sleep(300);

    if (DeleteDriverRegistryKeyNt(driverName)) {
        std::cout << "[*] Driver registry key deleted via NtDeleteKey." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::wstring driverName = L"EmbeddedDriverService";
    if (argc > 1) {
        driverName = StringToWString(argv[1]);
    }

    std::cout << "========================================" << std::endl;
    std::cout << "   Native API Kernel Driver Loader" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "[*] Embedded driver size: " << g_DriverData_size << " bytes" << std::endl;

    if (!ResolveNtApi()) {
        std::cerr << "[-] Failed to resolve required ntdll exports." << std::endl;
        return 1;
    }

    if (!EnableLoadDriverPrivilegeNt()) {
        std::cerr << "[-] SeLoadDriverPrivilege is required." << std::endl;
        return 1;
    }

    std::wstring tempDriverPath = GetTempDriverPath(driverName);
    if (tempDriverPath.empty()) {
        std::cerr << "[-] Failed to resolve temp path." << std::endl;
        return 1;
    }

    std::wstring driverFile = GetFileNameFromPath(tempDriverPath);

    if (!WriteEmbeddedDriverNt(tempDriverPath)) {
        return 1;
    }

    if (IsDriverLoadedNt(driverFile)) {
        std::cout << "[!] Driver file is already loaded. Attempting NtUnloadDriver..." << std::endl;
        if (!UnloadDriverNt(driverName)) {
            DeleteFileNt(tempDriverPath);
            return 1;
        }
        Sleep(500);
    }

    std::wcout << L"[*] Cleaning stale native service key for: " << driverName << std::endl;
    CleanupNt(driverName);

    if (!SetupDriverRegistryNt(driverName, tempDriverPath)) {
        DeleteFileNt(tempDriverPath);
        return 1;
    }
    std::cout << "[+] Registry configured via NtCreateKey/NtSetValueKey." << std::endl;

    if (!LoadDriverNt(driverName)) {
        DeleteFileNt(tempDriverPath);
        return 1;
    }

    Sleep(500);
    if (!IsDriverLoadedNt(driverFile)) {
        std::cout << "[-] Driver did not appear in SystemModuleInformation." << std::endl;
        return 1;
    }

    std::wcout << L"[*] Temporary driver file remains at: " << tempDriverPath << std::endl;
    std::cout << "[*] Unload later with NtUnloadDriver against the same registry service path." << std::endl;
    std::cout << "========================================" << std::endl;
    return 0;
}

#include "common.h"
#include <winioctl.h>

/* ---------- dynamic function pointer types ---------- */
typedef HANDLE (WINAPI *pfnCreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE (WINAPI *pfnCreateEventW)(
    LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
typedef BOOL   (WINAPI *pfnDeviceIoControl)(
    HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD  (WINAPI *pfnWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *pfnGetOverlappedResult)(
    HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
typedef BOOL   (WINAPI *pfnGetFileInformationByHandle)(
    HANDLE, LPBY_HANDLE_FILE_INFORMATION);

static HMODULE g_k32 = NULL;

static void ensure_k32(void)
{
    if (!g_k32) {
        g_k32 = GetModuleHandleA("kernel32.dll");
        if (!g_k32) { printf("[x] kernel32.dll not found.\n"); exit(1); }
    }
}

/* ==================== oplock ==================== */
static void oplock_wait(const char *path)
{
    ensure_k32();
    pfnCreateFileW      pCreateFileW      = (pfnCreateFileW)GetProcAddress(g_k32, "CreateFileW");
    pfnCreateEventW     pCreateEventW     = (pfnCreateEventW)GetProcAddress(g_k32, "CreateEventW");
    pfnDeviceIoControl  pDeviceIoControl  = (pfnDeviceIoControl)GetProcAddress(g_k32, "DeviceIoControl");
    pfnWaitForSingleObject pWait          = (pfnWaitForSingleObject)GetProcAddress(g_k32, "WaitForSingleObject");
    pfnGetOverlappedResult pGetOvResult   = (pfnGetOverlappedResult)GetProcAddress(g_k32, "GetOverlappedResult");

    wchar_t *wpath = str_to_wide(path);
    HANDLE hFile = pCreateFileW(wpath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    free(wpath);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[x] Failed to open a handle to %s.\n", path);
        return;
    }
    printf("[+] Successfully opened a handle to file %s.\n", path);

    HANDLE hEvent = pCreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hEvent || hEvent == INVALID_HANDLE_VALUE) {
        printf("[x] Call to CreateEventW failed.\n");
        CloseHandle(hFile);
        return;
    }
    printf("[+] Event created. Handle: %llx.\n", (unsigned long long)(ULONG_PTR)hEvent);

    OVERLAPPED ov = {0};
    ov.hEvent = hEvent;
    DWORD bytes = 0;

    printf("[+] Requesting level 1 oplock on %s...\n", path);
    BOOL ok = pDeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK_LEVEL_1,
        NULL, 0, NULL, 0, &bytes, &ov);

    if (ok) {
        printf("[!] DeviceIoControl returned immediate success (unusual).\n");
    } else {
        DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING) {
            printf("[x] DeviceIoControl returned unexpected error: %lu.\n", err);
            CloseHandle(hEvent); CloseHandle(hFile);
            return;
        }
    }

    printf("[+] Oplock obtained. Waiting for another process to open a handle to the file...\n");
    DWORD wait = pWait(hEvent, INFINITE);
    if (wait != 0) {
        printf("[x] Call to WaitForSingleObject failed.\n");
        CloseHandle(hEvent); CloseHandle(hFile);
        return;
    }

    pGetOvResult(hFile, &ov, &bytes, FALSE);

    printf("\n[!] Another process has attempted to open the file.\n");
    printf("[-] Press ENTER to release the oplock and allow access...");
    fflush(stdout);
    getchar();

    CloseHandle(hEvent);
    CloseHandle(hFile);
    printf("[+] Oplock released.\n");
}

/* ==================== loaddll ==================== */
static void load_dll(const char *dll_path)
{
    HMODULE hDll = LoadLibraryA(dll_path);
    if (!hDll) {
        printf("[x] Call to LoadLibrary failed.\n");
        return;
    }
    printf("[+] DLL loaded at address 0x%llx.\n",
           (unsigned long long)(ULONG_PTR)hDll);
    printf("[-] Press ENTER to exit...");
    fflush(stdout);
    getchar();
}

/* ==================== query ==================== */
static void query_file(const char *path)
{
    ensure_k32();
    pfnCreateFileW pCreateFileW =
        (pfnCreateFileW)GetProcAddress(g_k32, "CreateFileW");
    pfnGetFileInformationByHandle pGetInfo =
        (pfnGetFileInformationByHandle)GetProcAddress(g_k32,
            "GetFileInformationByHandle");

    wchar_t *wpath = str_to_wide(path);
    HANDLE hFile = pCreateFileW(wpath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[x] Failed to open a handle to %s.\n", path);
        return;
    }

    BY_HANDLE_FILE_INFORMATION info = {0};
    if (!pGetInfo(hFile, &info)) {
        printf("[x] Call to GetFileInformationByHandle failed.\n");
        CloseHandle(hFile);
        return;
    }
    CloseHandle(hFile);

    ULONGLONG file_id = ((ULONGLONG)info.nFileIndexHigh << 32) |
                         (ULONGLONG)info.nFileIndexLow;
    printf("[+] File ID: 0x%016llx\n", file_id);
}

/* ==================== main ==================== */
static void print_help(const char *exe)
{
    printf("Usage:\n");
    printf("  %s oplock  C:\\path\\to\\file\n", exe);
    printf("  %s loaddll C:\\path\\to\\file.dll\n", exe);
    printf("  %s query   C:\\path\\to\\file\n", exe);
}

int main(int argc, char *argv[])
{
    if (argc < 3) { print_help(argv[0]); return 1; }

    if (_stricmp(argv[1], "oplock") == 0)       oplock_wait(argv[2]);
    else if (_stricmp(argv[1], "loaddll") == 0)  load_dll(argv[2]);
    else if (_stricmp(argv[1], "query") == 0)    query_file(argv[2]);
    else { print_help(argv[0]); return 1; }

    return 0;
}

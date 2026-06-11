// test_sysinfo.c — verify NtQuerySystemInformation(11) returns ntoskrnl base for non-admin
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
    ULONG  NextOffset;
    UCHAR  NumberOfModules;
} RTL_PROCESS_MODULES_HEADER;

typedef struct {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef NTSTATUS (WINAPI *PNtQSI)(ULONG, PVOID, ULONG, PULONG);

int main(void) {
    PNtQSI NtQSI = (PNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    // Try with increasing buffer sizes
    ULONG sz = 1024*1024; // 1MB initial
    ULONG needed = 0;
    RTL_PROCESS_MODULES *buf = NULL;

    for (int attempt = 0; attempt < 3; attempt++) {
        buf = (RTL_PROCESS_MODULES*)malloc(sz);
        NTSTATUS st = NtQSI(11, buf, sz, &needed);
        printf("NtQSI(11) status=0x%08X needed=%u\n", (UINT)st, (UINT)needed);
        if (st == 0 || (int)st > 0) break;  // SUCCESS or INFO
        if (needed > sz) { free(buf); sz = needed + 4096; continue; }
        free(buf); buf = NULL;
        printf("FAILED\n");
        return 1;
    }

    if (!buf) { printf("Allocation failed\n"); return 1; }

    printf("Number of modules: %u\n", (UINT)buf->NumberOfModules);
    for (ULONG i = 0; i < buf->NumberOfModules && i < 5; i++) {
        RTL_PROCESS_MODULE_INFORMATION *m = &buf->Modules[i];
        printf("  [%u] 0x%016llX size=0x%X %s\n",
            i, (unsigned long long)(uintptr_t)m->ImageBase,
            m->ImageSize, m->FullPathName);
    }

    // Find ntoskrnl
    for (ULONG i = 0; i < buf->NumberOfModules; i++) {
        const char *path = (const char*)buf->Modules[i].FullPathName;
        if (strstr(path, "ntoskrnl") || strstr(path, "ntkrnlmp")) {
            printf("\nntoskrnl: 0x%016llX\n",
                (unsigned long long)(uintptr_t)buf->Modules[i].ImageBase);
            break;
        }
    }

    free(buf);
    return 0;
}

#include "common.h"
#include <winternl.h>

/* ================================================================
 *  Constants
 * ================================================================ */
#define FILE_ID_TYPE_FILE_ID      0
#define MY_PROCESS_ALL_ACCESS     0x1FFFFF
#define MY_THREAD_ALL_ACCESS      0x1FFFFF
#define MY_SECTION_ALL_ACCESS     0x000F001F
#define MY_SEC_IMAGE              0x01000000
#define MY_PAGE_EXECUTE_READ      0x20
#define MY_MEM_COMMIT             0x1000
#define MY_MEM_RESERVE            0x2000
#define MY_PAGE_READWRITE         0x04
#define HANDLE_CREATE_NEW_CONSOLE ((HANDLE)(LONG_PTR)-2)
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 1

/* ================================================================
 *  NT types not in public headers
 * ================================================================ */
typedef struct {
    DWORD  dwSize;
    DWORD  Type;
    union { LARGE_INTEGER FileId; } Anonymous;
} MY_FILE_ID_DESCRIPTOR;

typedef struct _MY_CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} MY_CURDIR;

typedef struct _MY_RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG  TimeStamp;
    UNICODE_STRING DosPath;
} MY_RTL_DRIVE_LETTER_CURDIR;

typedef struct _MY_RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    MY_CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    MY_RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];
    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    PVOID DefaultThreadpoolCpuSetMasks;
} MY_RTL_USER_PROCESS_PARAMETERS;

/* ================================================================
 *  Function pointer types
 * ================================================================ */
typedef HANDLE (WINAPI *pfnCreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HANDLE (WINAPI *pfnOpenFileById)(HANDLE,void*,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD);
typedef DWORD  (WINAPI *pfnGetFinalPathNameByHandleW)(HANDLE,LPWSTR,DWORD,DWORD);
typedef BOOL   (WINAPI *pfnCreateEnvironmentBlock)(PVOID*,HANDLE,BOOL);

typedef NTSTATUS (NTAPI *pfnNtCreateSection)(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);
typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,ULONG,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(HANDLE,PVOID);
typedef NTSTATUS (NTAPI *pfnNtCreateProcessEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,ULONG,HANDLE,HANDLE,HANDLE,ULONG);
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(PHANDLE,ACCESS_MASK,PVOID,HANDLE,PVOID,PVOID,ULONG,SIZE_T,SIZE_T,SIZE_T,PVOID);
typedef NTSTATUS (NTAPI *pfnNtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI *pfnNtWriteVirtualMemory)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI *pfnNtReadVirtualMemory)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(HANDLE,ULONG,PVOID,ULONG,PULONG);
typedef NTSTATUS (NTAPI *pfnRtlCreateProcessParametersEx)(MY_RTL_USER_PROCESS_PARAMETERS**,PUNICODE_STRING,PUNICODE_STRING,PUNICODE_STRING,PUNICODE_STRING,PVOID,PUNICODE_STRING,PUNICODE_STRING,PUNICODE_STRING,PUNICODE_STRING,ULONG);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);

/* ================================================================
 *  Helpers
 * ================================================================ */
static HMODULE g_k32, g_ntdll;

static void resolve_modules(void)
{
    g_k32   = GetModuleHandleA("kernel32.dll");
    g_ntdll = GetModuleHandleA("ntdll.dll");
    if (!g_k32 || !g_ntdll) {
        printf("[x] Failed to resolve kernel32/ntdll.\n");
        exit(1);
    }
}

static HANDLE open_volume(const char *unit)
{
    char vol[16];
    snprintf(vol, sizeof(vol), "\\\\.\\%s:", unit);
    wchar_t *wvol = str_to_wide(vol);
    pfnCreateFileW pCFW = (pfnCreateFileW)GetProcAddress(g_k32, "CreateFileW");
    HANDLE h = pCFW(wvol, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wvol);
    if (h == INVALID_HANDLE_VALUE)
        printf("[x] Failed to open a handle to \\\\.\\%s:.\n", unit);
    return h;
}

static HANDLE open_by_frn(HANDLE vol, ULONGLONG frn)
{
    pfnOpenFileById pOpen =
        (pfnOpenFileById)GetProcAddress(g_k32, "OpenFileById");

    MY_FILE_ID_DESCRIPTOR desc;
    desc.dwSize = sizeof(desc);
    desc.Type   = FILE_ID_TYPE_FILE_ID;
    desc.Anonymous.FileId.QuadPart = (LONGLONG)frn;

    HANDLE h = pOpen(vol, &desc,
        GENERIC_READ | GENERIC_EXECUTE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, 0);
    if (h == INVALID_HANDLE_VALUE)
        printf("[x] Failed to open file by FRN 0x%llx.\n", frn);
    return h;
}

static ULONG get_entry_point_rva(PVOID base)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);
    return nt->OptionalHeader.AddressOfEntryPoint;
}

static size_t get_env_size(const WCHAR *env)
{
    if (!env) return 0;
    size_t i = 0;
    int zeros = 0;
    for (;;) {
        if (env[i] == 0) { zeros++; if (zeros == 2) { i++; break; } }
        else zeros = 0;
        i++;
        if (i * 2 > 1024 * 1024) return 0;
    }
    return i * 2;
}

static void init_unicode_string(UNICODE_STRING *us, const wchar_t *s)
{
    USHORT len = (USHORT)(wcslen(s) * sizeof(WCHAR));
    us->Length = len;
    us->MaximumLength = len + sizeof(WCHAR);
    us->Buffer = (PWSTR)s;
}

/* fix embedded pointers when relocating the struct to remote process */
static void fix_pointer(ULONG_PTR *ptr, ULONG_PTR local_base,
                        ULONG_PTR local_end, LONG_PTR delta)
{
    ULONG_PTR val = *ptr;
    if (val >= local_base && val < local_end)
        *ptr = (ULONG_PTR)((LONG_PTR)val + delta);
}

static void fix_us(UNICODE_STRING *us, ULONG_PTR lb, ULONG_PTR le, LONG_PTR d)
{
    fix_pointer((ULONG_PTR *)&us->Buffer, lb, le, d);
}

static void fix_parameters(MY_RTL_USER_PROCESS_PARAMETERS *p,
                           ULONG_PTR local_base, LONG_PTR delta)
{
    ULONG_PTR lb = local_base;
    ULONG_PTR le = lb + p->MaximumLength;

    fix_us(&p->CurrentDirectory.DosPath, lb, le, delta);
    fix_us(&p->DllPath,        lb, le, delta);
    fix_us(&p->ImagePathName,  lb, le, delta);
    fix_us(&p->CommandLine,    lb, le, delta);
    fix_pointer((ULONG_PTR *)&p->Environment, lb, le, delta);
    fix_us(&p->WindowTitle,    lb, le, delta);
    fix_us(&p->DesktopInfo,    lb, le, delta);
    fix_us(&p->ShellInfo,      lb, le, delta);
    fix_us(&p->RuntimeData,    lb, le, delta);
    fix_pointer((ULONG_PTR *)&p->PackageDependencyData, lb, le, delta);
    fix_us(&p->RedirectionDllName, lb, le, delta);
    fix_us(&p->HeapPartitionName,  lb, le, delta);

    for (int i = 0; i < 32; i++)
        fix_us(&p->CurrentDirectories[i].DosPath, lb, le, delta);

    /* tail pointers beyond known struct fields */
    size_t struct_sz = sizeof(MY_RTL_USER_PROCESS_PARAMETERS);
    if (p->MaximumLength > struct_sz) {
        BYTE *tail = (BYTE *)p + struct_sz;
        size_t tail_len = p->MaximumLength - struct_sz;
        size_t word = sizeof(ULONG_PTR);
        for (size_t off = 0; off + word <= tail_len; off += word) {
            ULONG_PTR *slot = (ULONG_PTR *)(tail + off);
            if (*slot >= lb && *slot < le)
                *slot = (ULONG_PTR)((LONG_PTR)*slot + delta);
        }
    }
}

/* ================================================================
 *  spawn_process
 * ================================================================ */
static void spawn_process(const char *unit, ULONGLONG frn)
{
    resolve_modules();

    HANDLE hVol = open_volume(unit);
    if (hVol == INVALID_HANDLE_VALUE) return;

    HANDLE hFile = open_by_frn(hVol, frn);
    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hVol); return; }
    printf("[+] Successfully opened handle to file by FRN '0x%llx' on volume '\\\\.\\%s:'.\n", frn, unit);

    /* NT API pointers */
    pfnNtCreateSection pNtCS = (pfnNtCreateSection)GetProcAddress(g_ntdll, "NtCreateSection");
    pfnNtMapViewOfSection pNtMV = (pfnNtMapViewOfSection)GetProcAddress(g_ntdll, "NtMapViewOfSection");
    pfnNtCreateProcessEx pNtCP = (pfnNtCreateProcessEx)GetProcAddress(g_ntdll, "NtCreateProcessEx");
    pfnNtCreateThreadEx pNtCT = (pfnNtCreateThreadEx)GetProcAddress(g_ntdll, "NtCreateThreadEx");
    pfnNtQueryInformationProcess pNtQIP = (pfnNtQueryInformationProcess)GetProcAddress(g_ntdll, "NtQueryInformationProcess");
    pfnNtReadVirtualMemory pNtRVM = (pfnNtReadVirtualMemory)GetProcAddress(g_ntdll, "NtReadVirtualMemory");
    pfnNtWriteVirtualMemory pNtWVM = (pfnNtWriteVirtualMemory)GetProcAddress(g_ntdll, "NtWriteVirtualMemory");
    pfnNtAllocateVirtualMemory pNtAVM = (pfnNtAllocateVirtualMemory)GetProcAddress(g_ntdll, "NtAllocateVirtualMemory");
    pfnRtlCreateProcessParametersEx pRtlCPP = (pfnRtlCreateProcessParametersEx)GetProcAddress(g_ntdll, "RtlCreateProcessParametersEx");

    /* create image section */
    HANDLE hSection = NULL;
    NTSTATUS st = pNtCS(&hSection, MY_SECTION_ALL_ACCESS, NULL, NULL,
                        MY_PAGE_EXECUTE_READ, MY_SEC_IMAGE, hFile);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to create section. NTSTATUS: 0x%lx.\n", (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }

    /* map into self to read EP */
    PVOID view_base = NULL;
    SIZE_T view_size = 0;
    LARGE_INTEGER sec_offset = {0};
    st = pNtMV(hSection, GetCurrentProcess(), &view_base, 0, 0,
               &sec_offset, &view_size, 2, 0, MY_PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to map view of section. NTSTATUS: 0x%lx.\n", (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    printf("[+] File section mapped into current process. Base address: 0x%llx.\n",
           (unsigned long long)(ULONG_PTR)view_base);
    ULONG ep_rva = get_entry_point_rva(view_base);

    /* create process from section */
    HANDLE hProc = NULL;
    st = pNtCP(&hProc, MY_PROCESS_ALL_ACCESS, NULL,
               GetCurrentProcess(), 0, hSection, NULL, NULL, 0);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to create process from section. NTSTATUS: 0x%lx.\n", (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    printf("[+] Process created from section. Handle: 0x%llx.\n",
           (unsigned long long)(ULONG_PTR)hProc);

    /* get PEB address */
    PROCESS_BASIC_INFORMATION pbi = {0};
    st = pNtQIP(hProc, 0, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(st)) {
        printf("[x] Call to NtQueryInformationProcess failed.\n");
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    ULONG_PTR peb_addr = (ULONG_PTR)pbi.PebBaseAddress;
    printf("[+] New process PEB address obtained: 0x%llx\n",
           (unsigned long long)peb_addr);

    /* read ImageBaseAddress from PEB+0x10 */
    ULONG_PTR image_base = 0;
    st = pNtRVM(hProc, (PVOID)(peb_addr + 0x10), &image_base,
                sizeof(image_base), NULL);
    if (!NT_SUCCESS(st)) {
        printf("[x] Call to NtReadVirtualMemory failed.\n");
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    printf("[+] Remote process image base address: 0x%llx\n",
           (unsigned long long)image_base);

    /* get file path for process parameters */
    pfnGetFinalPathNameByHandleW pGetPath =
        (pfnGetFinalPathNameByHandleW)GetProcAddress(g_k32,
            "GetFinalPathNameByHandleW");
    WCHAR path_buf[32768];
    DWORD path_len = pGetPath(hFile, path_buf, 32768, 0);
    if (path_len == 0 || path_len >= 32768) {
        printf("[x] Retrieval of file path failed.\n");
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    /* strip \\?\ prefix */
    WCHAR *final_path = path_buf;
    if (wcsncmp(final_path, L"\\\\?\\", 4) == 0) final_path += 4;
    else if (wcsncmp(final_path, L"\\??\\", 4) == 0) final_path += 4;

    /* create environment block */
    HMODULE hUserenv = LoadLibraryA("userenv.dll");
    pfnCreateEnvironmentBlock pCEB =
        (pfnCreateEnvironmentBlock)GetProcAddress(hUserenv,
            "CreateEnvironmentBlock");
    PVOID env_block = NULL;
    if (!pCEB || !pCEB(&env_block, NULL, TRUE)) {
        printf("[x] Call to CreateEnvironmentBlock failed.\n");
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    size_t env_size = get_env_size((const WCHAR *)env_block);
    printf("[+] New environment block created. Size: %llu bytes.\n",
           (unsigned long long)env_size);

    /* RtlCreateProcessParametersEx */
    UNICODE_STRING us_path;
    init_unicode_string(&us_path, final_path);

    MY_RTL_USER_PROCESS_PARAMETERS *params = NULL;
    st = pRtlCPP(&params, &us_path, NULL, NULL, &us_path,
                  NULL, NULL, NULL, NULL, NULL,
                  RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
    if (!NT_SUCCESS(st)) {
        printf("[x] Call to RtlCreateProcessParametersEx failed. NTSTATUS: %lx.\n",
               (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    printf("[+] RtlUserProcessParameters structure populated. Size: %lu bytes.\n",
           params->MaximumLength);

    /* allocate and write env block in remote process */
    PVOID remote_env = NULL;
    SIZE_T env_alloc = env_size;
    st = pNtAVM(hProc, &remote_env, 0, &env_alloc,
                MY_MEM_COMMIT | MY_MEM_RESERVE, MY_PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to allocate memory for env block. NTSTATUS: %lx.\n",
               (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    st = pNtWVM(hProc, remote_env, env_block, env_size, NULL);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to write environment block. NTSTATUS: %lx.\n",
               (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    printf("[+] New environment block successfully written to the remote process. Address: 0x%llx\n",
           (unsigned long long)(ULONG_PTR)remote_env);

    params->ConsoleHandle = HANDLE_CREATE_NEW_CONSOLE;
    params->Environment = remote_env;

    /* allocate and write parameters in remote process */
    PVOID remote_params = NULL;
    SIZE_T params_alloc = params->MaximumLength;
    st = pNtAVM(hProc, &remote_params, 0, &params_alloc,
                MY_MEM_COMMIT | MY_MEM_RESERVE, MY_PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to allocate memory for parameters. NTSTATUS: %lx.\n",
               (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }

    LONG_PTR delta = (LONG_PTR)((ULONG_PTR)remote_params - (ULONG_PTR)params);
    fix_parameters(params, (ULONG_PTR)params, delta);

    st = pNtWVM(hProc, remote_params, params, params->MaximumLength, NULL);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to write parameters. NTSTATUS: %lx.\n",
               (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    printf("[+] RtlUserProcessParameters structure written to the remote process. Address: 0x%llx\n",
           (unsigned long long)(ULONG_PTR)remote_params);

    /* patch PEB.ProcessParameters (offset 0x20) */
    ULONG_PTR remote_params_addr = (ULONG_PTR)remote_params;
    st = pNtWVM(hProc, (PVOID)(peb_addr + 0x20), &remote_params_addr,
                sizeof(remote_params_addr), NULL);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to patch the PEB. NTSTATUS: %lx.\n",
               (unsigned long)st);
        CloseHandle(hFile); CloseHandle(hVol); return;
    }
    printf("[+] New process' PEB patched.\n");

    /* create initial thread */
    HANDLE hThread = NULL;
    st = pNtCT(&hThread, MY_THREAD_ALL_ACCESS, NULL, hProc,
               (PVOID)(image_base + ep_rva), NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(st)) {
        printf("[x] Failed to create thread. NTSTATUS: 0x%lx.\n",
               (unsigned long)st);
    } else {
        printf("[+] Initial thread launched.\n");
    }

    CloseHandle(hFile);
    CloseHandle(hVol);
}

/* ================================================================
 *  manual PE mapping helpers
 * ================================================================ */
static void process_relocations(BYTE *base, IMAGE_NT_HEADERS *nt, LONG_PTR delta)
{
    DWORD reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!reloc_rva || !reloc_size) return;

    IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)(base + reloc_rva);
    while ((BYTE *)block < base + reloc_rva + reloc_size && block->SizeOfBlock) {
        DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entries = (WORD *)((BYTE *)block + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < count; i++) {
            int type = entries[i] >> 12;
            int off  = entries[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                *(ULONG_PTR *)(base + block->VirtualAddress + off) += (ULONG_PTR)delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                *(DWORD *)(base + block->VirtualAddress + off) += (DWORD)delta;
            }
        }
        block = (IMAGE_BASE_RELOCATION *)((BYTE *)block + block->SizeOfBlock);
    }
}

static int resolve_imports(BYTE *base, IMAGE_NT_HEADERS *nt)
{
    DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!imp_rva) return 1;

    IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + imp_rva);
    while (imp->Name) {
        char *dll_name = (char *)(base + imp->Name);
        HMODULE hDll = LoadLibraryA(dll_name);
        if (!hDll) {
            printf("[x] Failed to load import DLL: %s\n", dll_name);
            return 0;
        }

        IMAGE_THUNK_DATA *orig = (IMAGE_THUNK_DATA *)(base +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);

        while (orig->u1.AddressOfData) {
            FARPROC func;
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) {
                func = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal));
            } else {
                IMAGE_IMPORT_BY_NAME *ibn =
                    (IMAGE_IMPORT_BY_NAME *)(base + orig->u1.AddressOfData);
                func = GetProcAddress(hDll, ibn->Name);
            }
            if (!func) {
                printf("[x] Failed to resolve import from %s\n", dll_name);
                return 0;
            }
            thunk->u1.Function = (ULONG_PTR)func;
            orig++; thunk++;
        }
        imp++;
    }
    return 1;
}

static void set_section_protections(BYTE *base, IMAGE_NT_HEADERS *nt)
{
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        DWORD ch = sec[i].Characteristics;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE))
            protect = PAGE_EXECUTE_READWRITE;
        else if (ch & IMAGE_SCN_MEM_EXECUTE)
            protect = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)
            protect = PAGE_READWRITE;
        DWORD old;
        VirtualProtect(base + sec[i].VirtualAddress,
                       sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData,
                       protect, &old);
    }
}

/* ================================================================
 *  map_and_run_entry_point
 * ================================================================ */
typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);

static void map_and_run(const char *unit, ULONGLONG frn)
{
    resolve_modules();

    HANDLE hVol = open_volume(unit);
    if (hVol == INVALID_HANDLE_VALUE) return;
    HANDLE hFile = open_by_frn(hVol, frn);
    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hVol); return; }
    printf("[+] Successfully opened handle to file by FRN '0x%llx' on volume '\\\\.\\%s:'.\n",
           frn, unit);

    /* read file into memory */
    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE *raw = (BYTE *)malloc(file_size);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD rd;
    ReadFile(hFile, raw, file_size, &rd, NULL);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[x] Not a valid PE file.\n");
        free(raw); CloseHandle(hFile); CloseHandle(hVol); return;
    }
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[x] Invalid NT headers.\n");
        free(raw); CloseHandle(hFile); CloseHandle(hVol); return;
    }

    /* allocate at preferred base or anywhere */
    BYTE *base = (BYTE *)VirtualAlloc(
        (PVOID)nt->OptionalHeader.ImageBase,
        nt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base)
        base = (BYTE *)VirtualAlloc(NULL,
            nt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) {
        printf("[x] VirtualAlloc failed.\n");
        free(raw); CloseHandle(hFile); CloseHandle(hVol); return;
    }

    /* copy headers */
    memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);

    /* copy sections */
    IMAGE_SECTION_HEADER *secs = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (secs[i].SizeOfRawData > 0)
            memcpy(base + secs[i].VirtualAddress,
                   raw + secs[i].PointerToRawData,
                   secs[i].SizeOfRawData);
    }

    /* fix the NT headers pointer for the mapped image */
    IMAGE_NT_HEADERS *mapped_nt =
        (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    /* relocations */
    LONG_PTR delta = (LONG_PTR)((ULONG_PTR)base - nt->OptionalHeader.ImageBase);
    if (delta != 0)
        process_relocations(base, mapped_nt, delta);

    /* imports */
    if (!resolve_imports(base, mapped_nt)) {
        printf("[x] Import resolution failed.\n");
        VirtualFree(base, 0, MEM_RELEASE);
        free(raw); CloseHandle(hFile); CloseHandle(hVol); return;
    }

    /* set protections */
    set_section_protections(base, mapped_nt);
    free(raw);

    printf("[+] File mapped to the current process. Press any key to run the entry point...");
    fflush(stdout);
    getchar();

    ULONG ep_rva = mapped_nt->OptionalHeader.AddressOfEntryPoint;
    DllMain_t entry = (DllMain_t)(base + ep_rva);
    entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);

    printf("[-] Press any key to exit...");
    fflush(stdout);
    getchar();

    CloseHandle(hFile);
    CloseHandle(hVol);
}

/* ================================================================
 *  main
 * ================================================================ */
int main(void)
{
    char mode[16], drive[8], frn_s[64];
    prompt("Select mode (spawn/load): ", mode, sizeof(mode));
    prompt("Select volume (e.g. 'C'): ", drive, sizeof(drive));
    prompt("Insert FRN: ",               frn_s, sizeof(frn_s));

    /* parse hex FRN */
    char *hex = frn_s;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    char *end;
    ULONGLONG frn = _strtoui64(hex, &end, 16);
    if (*end) {
        printf("[x] Invalid hex for FRN.\n");
        return 1;
    }

    for (char *p = mode; *p; p++) *p = (char)tolower((unsigned char)*p);

    if (strcmp(mode, "spawn") == 0)
        spawn_process(drive, frn);
    else if (strcmp(mode, "load") == 0)
        map_and_run(drive, frn);
    else
        printf("[x] Unknown mode. Only 'spawn' and 'load' are allowed.\n");

    return 0;
}

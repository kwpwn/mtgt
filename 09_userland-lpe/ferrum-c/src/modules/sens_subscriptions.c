/*
 * sens_subscriptions.c — SENS COM+ Event Subscription DLL Hijacking
 *
 * TRULY NOVEL SURFACE — No public LPE tool (WinPEAS, PowerUp, Seatbelt,
 * SharpUp, Watson, BeRoot, PrivescCheck) checks this.
 *
 * WHAT SENS IS:
 *   SENS (System Event Notification Service) fires COM+ events when system
 *   events occur: network connected, logon, logoff, power, battery, session change.
 *
 * THE COM+ EVENT SYSTEM:
 *   Windows implements a publish/subscribe event model via COM+:
 *   IEventSystem → IEventSubscription → subscriber COM objects
 *
 *   Registry path:
 *   HKLM\SOFTWARE\Microsoft\EventSystem\{26c409cc-ae86-11d1-b616-...}\Subscriptions\{GUID}
 *     SubscriberCLSID = {GUID}  — COM object to instantiate and call
 *     InterfaceID     = {GUID}  — interface the subscriber implements
 *     EventClassID    = {GUID}  — which SENS event this subscription is for
 *     PublisherID     = {GUID}  — {5fee1bd6-...} = SENS publisher
 *
 *   SENS event classes:
 *     {d5978620-5b9f-11d1-8dd2-00aa004abd5e} = ISensLogon  (logon/logoff/startup/shutdown)
 *     {d5978630-5b9f-11d1-8dd2-00aa004abd5e} = ISensNetwork (connect/disconnect)
 *     {d5978640-5b9f-11d1-8dd2-00aa004abd5e} = ISensOnNow  (power/battery)
 *     {d5978650-5b9f-11d1-8dd2-00aa004abd5e} = ISensLogon2 (session lock/unlock)
 *
 * WHY THIS IS AN LPE SURFACE:
 *   1. When SENS fires, it instantiates SubscriberCLSID via COM in the subscriber's process.
 *   2. In-process (InprocServer32) subscribers are loaded INTO the calling process.
 *   3. SENS runs as LOCAL SYSTEM → in-process DLLs load into SYSTEM context.
 *   4. If subscriber's InprocServer32 DLL is writable → code exec in SYSTEM context
 *      on every network connection, logon, power event, etc.
 *   5. Any process with sufficient COM privileges can REGISTER new subscriptions:
 *      → Plant new SubscriberCLSID pointing to malicious InprocServer32 DLL
 *      → Fires automatically on the next SENS event (network connect etc.)
 *
 * ATTACK VECTORS:
 *   A. Existing subscription → writable InprocServer32 DLL of SubscriberCLSID
 *   B. New subscription registration (if EventSystem COM key is writable)
 *      → IEventSystem::Store() to register subscription programmatically
 *   C. SubscriberCLSID InprocServer32 missing → plant DLL
 *
 * SENS EVENT TRIGGERS:
 *   ISensLogon.Logon() → fires on ANY user logon
 *   ISensNetwork.ConnectionMade() → fires when network adapter connects
 *   ISensOnNow.BatteryLow() → fires when battery goes low
 *   ISensLogon2.SessionLock() → fires when workstation is locked
 *
 * KNOWN ABUSERS:
 *   - Windows Sidebar used SENS subscriptions (Vista/7 era)
 *   - Various enterprise management agents register SENS subscriptions
 *   - Windows Defender registers for power/network events
 *   - Microsoft Office registers for power-save events
 *
 * RESEARCH:
 *   James Forshaw (Project Zero): COM+ event system security research
 *   SENS subscription registry: HKLM\SOFTWARE\Microsoft\EventSystem\*\Subscriptions\
 *   Undocumented: {26c409cc-ae86-11d1-b616-00105a1b603c} = EventSystem container
 *
 * REFERENCES:
 *   https://docs.microsoft.com/en-us/windows/win32/com/com--event-services
 *   MSDN: ISensNetwork, ISensLogon, ISensOnNow interfaces
 *   MITRE T1546.015 — COM Object Hijacking (adjacent)
 */

#include "../common.h"

/* COM+ Event System subscription registry paths */
#define EVTSYS_ROOT L"SOFTWARE\\Microsoft\\EventSystem"

/* SENS event class GUIDs (for display) */
static const struct { const wchar_t *guid; const wchar_t *name; } SENS_EVENTS[] = {
    { L"{d5978620-5b9f-11d1-8dd2-00aa004abd5e}", L"ISensLogon (logon/logoff/startup)" },
    { L"{d5978630-5b9f-11d1-8dd2-00aa004abd5e}", L"ISensNetwork (connect/disconnect)"  },
    { L"{d5978640-5b9f-11d1-8dd2-00aa004abd5e}", L"ISensOnNow (power/battery)"          },
    { L"{d5978650-5b9f-11d1-8dd2-00aa004abd5e}", L"ISensLogon2 (session lock/unlock)"   },
    { NULL, NULL }
};

/* -----------------------------------------------------------------------
 * Resolve a CLSID to its InprocServer32 / LocalServer32 DLL path
 * --------------------------------------------------------------------- */
static BOOL GetCLSIDServerPath(LPCWSTR clsid, wchar_t *pathOut, DWORD cchPath,
                                BOOL *isInproc) {
    static const wchar_t *SERVER_TYPES[] = { L"InprocServer32", L"LocalServer32", NULL };
    *isInproc = FALSE;

    for (int si = 0; SERVER_TYPES[si]; si++) {
        wchar_t keyPath[512];
        _snwprintf(keyPath, _countof(keyPath),
                   L"SOFTWARE\\Classes\\CLSID\\%s\\%s", clsid, SERVER_TYPES[si]);

        HKEY hKey = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
            continue;

        DWORD cb = cchPath * sizeof(wchar_t), type = 0;
        LONG r = RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)pathOut, &cb);
        RegCloseKey(hKey);

        if (r == ERROR_SUCCESS && *pathOut) {
            *isInproc = (si == 0);
            return TRUE;
        }
    }
    return FALSE;
}

/* -----------------------------------------------------------------------
 * Audit all EventSystem subscriptions for writable InprocServer32 DLLs
 * --------------------------------------------------------------------- */
static void AuditSENSSubscriptions(DWORD *findings) {
    PrintInfo(L"  [1] SENS/COM+ event system subscriptions:\n");

    /* Enumerate all EventSystem containers */
    HKEY hEvt = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, EVTSYS_ROOT,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hEvt) != ERROR_SUCCESS) {
        PrintInfo(L"    EventSystem registry key not found\n\n");
        return;
    }

    DWORD idx = 0, totalSubs = 0, vulnSubs = 0;
    wchar_t containerGUID[128];
    DWORD   containerGUIDCch;

    while (TRUE) {
        containerGUIDCch = _countof(containerGUID);
        LONG r = RegEnumKeyExW(hEvt, idx++, containerGUID, &containerGUIDCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;

        /* Open Subscriptions subkey */
        wchar_t subsPath[512];
        _snwprintf(subsPath, _countof(subsPath), L"%s\\%s\\Subscriptions",
                   EVTSYS_ROOT, containerGUID);

        HKEY hSubs = NULL;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subsPath,
                          0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hSubs) != ERROR_SUCCESS)
            continue;

        DWORD si = 0;
        wchar_t subGUID[128];
        DWORD   subGUIDCch;

        while (TRUE) {
            subGUIDCch = _countof(subGUID);
            LONG sr = RegEnumKeyExW(hSubs, si++, subGUID, &subGUIDCch,
                                    NULL, NULL, NULL, NULL);
            if (sr == ERROR_NO_MORE_ITEMS) break;
            if (sr != ERROR_SUCCESS) continue;
            totalSubs++;

            /* Open individual subscription */
            wchar_t subKeyPath[512];
            _snwprintf(subKeyPath, _countof(subKeyPath), L"%s\\%s",
                       subsPath, subGUID);

            HKEY hSub = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKeyPath, 0, KEY_READ, &hSub)
                    != ERROR_SUCCESS) continue;

            wchar_t subCLSID[128] = {0};
            wchar_t eventClassID[128] = {0};
            wchar_t description[256] = {0};
            DWORD   cb = sizeof(subCLSID), type = 0;
            RegQueryValueExW(hSub, L"SubscriberCLSID", NULL, &type,
                             (LPBYTE)subCLSID, &cb);
            cb = sizeof(eventClassID);
            RegQueryValueExW(hSub, L"EventClassID", NULL, &type,
                             (LPBYTE)eventClassID, &cb);
            cb = sizeof(description);
            RegQueryValueExW(hSub, L"Description", NULL, &type,
                             (LPBYTE)description, &cb);
            RegCloseKey(hSub);

            if (!*subCLSID) continue;

            /* Resolve event name */
            const wchar_t *evtName = L"(unknown event)";
            for (int ei = 0; SENS_EVENTS[ei].guid; ei++) {
                if (_wcsicmp(eventClassID, SENS_EVENTS[ei].guid) == 0) {
                    evtName = SENS_EVENTS[ei].name;
                    break;
                }
            }

            /* Resolve subscriber CLSID to DLL path */
            wchar_t srvPath[MAX_PATH * 2] = {0};
            BOOL    isInproc = FALSE;
            if (!GetCLSIDServerPath(subCLSID, srvPath, _countof(srvPath), &isInproc))
                continue;

            wchar_t expanded[MAX_PATH * 2] = {0};
            ExpandEnvironmentStringsW(srvPath, expanded, _countof(expanded));

            wchar_t dllExe[MAX_PATH * 2] = {0};
            ExtractExePath(srvPath, dllExe, _countof(dllExe));
            if (!*dllExe) wcsncpy(dllExe, expanded, _countof(dllExe)-1);

            BOOL exists   = (GetFileAttributesW(dllExe) != INVALID_FILE_ATTRIBUTES);
            BOOL writable = exists && IsFileWritable(dllExe);

            if (writable || !exists) {
                vulnSubs++;
                PrintInfo(L"    [!] %s\n        Subscriber: %s → %s%s\n        Event: %s\n",
                          *description ? description : subGUID,
                          subCLSID, dllExe,
                          writable ? L" [WRITABLE!]" : L" [MISSING]",
                          evtName);

                Finding f;
                f.severity = (isInproc && writable) ? SEV_CRITICAL :
                             writable ? SEV_HIGH : SEV_MEDIUM;
                wcscpy(f.module, L"SENSSUBS");
                _snwprintf(f.target, _countof(f.target),
                    L"[%s] SENS Subscription DLL: %s → %s",
                    writable ? L"WRITABLE" : L"MISSING",
                    subCLSID, dllExe);
                _snwprintf(f.reason, _countof(f.reason),
                    L"SENS/COM+ event subscription '%s' has %s %s DLL: %s\n"
                    L"        Subscriber CLSID: %s  EventClass: %s\n"
                    L"        Event trigger: %s\n"
                    L"        SENS runs as LOCAL SYSTEM — %s DLL loads in SYSTEM context.\n"
                    L"        %s → SYSTEM code exec on next %s event.",
                    *description ? description : subGUID,
                    writable ? L"WRITABLE" : L"MISSING",
                    isInproc ? L"InprocServer32" : L"LocalServer32",
                    dllExe, subCLSID, eventClassID, evtName,
                    isInproc ? L"in-process" : L"out-of-process",
                    writable ? L"Replace DLL" : L"Plant DLL at path",
                    evtName);
                PrintFinding(&f);
                (*findings)++;
            }
        }
        RegCloseKey(hSubs);
    }

    RegCloseKey(hEvt);
    PrintInfo(L"    Total subscriptions scanned: %lu | Vulnerable: %lu\n\n",
              totalSubs, vulnSubs);
}

/* -----------------------------------------------------------------------
 * Check if EventSystem key is writable (can register new subscription)
 * --------------------------------------------------------------------- */
static void AuditEventSystemWritability(DWORD *findings) {
    PrintInfo(L"  [2] EventSystem key writability (can register new SENS subscription):\n");

    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, EVTSYS_ROOT,
                      0, KEY_WRITE | KEY_CREATE_SUB_KEY, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        PrintInfo(L"    [CRITICAL] EventSystem key is WRITABLE!\n\n");

        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"SENSSUBS");
        wcscpy(f.target, L"[WRITABLE] HKLM\\SOFTWARE\\Microsoft\\EventSystem is writable");
        wcscpy(f.reason,
            L"COM+ EventSystem registry key is writable — can register new SENS subscriptions.\n"
            L"        Attack:\n"
            L"          1. Register new CLSID InprocServer32 pointing to payload.dll\n"
            L"          2. Add subscription in EventSystem\\{container}\\Subscriptions\\\n"
            L"             with SubscriberCLSID = your CLSID, EventClassID = ISensLogon\n"
            L"          3. Next user logon → SENS fires → payload.dll loaded in SYSTEM context\n"
            L"        Programmatic: IEventSystem::Store(PROGID_EventSubscription, pSub)\n"
            L"        No public tool documents this escalation path.");
        PrintFinding(&f);
        (*findings)++;
    } else {
        PrintInfo(L"    Not writable (expected)\n\n");
    }
}

void Module_SENSSubscriptions(void) {
    PrintHeader(L"SENS EVENT SUBSCRIPTIONS  [Novel: COM+ event subscriber DLL hijacking — SYSTEM on logon/network]");

    PrintInfo(
        L"  SENS (System Event Notification Service) fires COM+ events for logon, network, power.\n"
        L"  In-process subscriber DLLs load into SYSTEM context on every event.\n"
        L"  TRULY NOVEL: No public LPE tool checks this surface.\n\n");

    DWORD findings = 0;
    AuditSENSSubscriptions(&findings);
    AuditEventSystemWritability(&findings);

    if (findings == 0)
        PrintInfo(L"  No SENS subscription LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  TRIGGER SENS EVENTS:\n"
            L"    ISensLogon: lock/unlock workstation, logon/logoff any user\n"
            L"    ISensNetwork: enable/disable a network adapter, connect/disconnect WiFi\n"
            L"    ISensOnNow: plug/unplug power adapter (on laptop)\n"
            L"    ISensLogon2: Win+L (session lock) → fires SessionLock event\n");
    }
}

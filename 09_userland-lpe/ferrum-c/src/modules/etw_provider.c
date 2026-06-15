/*
 * etw_provider.c — ETW Provider DLL Path Audit
 *
 * WHY THIS MATTERS:
 *   ETW (Event Tracing for Windows) providers register DLLs under:
 *     HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}\
 *         MessageFileName  = "C:\path\to\provider.dll"
 *         ResourceFileName = "C:\path\to\provider.dll"
 *
 *   The Windows Event Log service (EventLog, runs as SYSTEM) loads these
 *   DLLs when:
 *     - Event Viewer opens and decodes events from a channel
 *     - wevtutil.exe queries events (can be triggered by low-priv user)
 *     - Any application calls EvtFormatMessage / EvtGetPublisherMetadata
 *     - The event collection pipeline processes messages
 *
 *   Additionally, PdhEnumObjects / performance correlation code loads
 *   ETW provider DLLs in the calling process context (monitoring tools
 *   often run elevated).
 *
 * ATTACK CHAIN:
 *   1. Tool finds provider DLL in user-writable location
 *   2. Replace DLL (or plant if missing) — minimal export: DllMain only
 *   3. Trigger: run "wevtutil.exe qe <ChannelName> /c:1" as any user
 *      → Event Log service (SYSTEM) loads provider DLL to format messages
 *   4. Code executes as SYSTEM
 *
 * WHY NO CURRENT TOOL CHECKS THIS:
 *   WinPEAS, PowerUp, Seatbelt, Ferrum-Go: none enumerate WINEVT\Publishers.
 *   This is a blind spot in automated LPE scanning.
 *
 * NOVELTY POTENTIAL:
 *   Third-party software (AV, EDR, monitoring agents, hardware drivers)
 *   frequently registers ETW providers. These vendors rarely audit the
 *   ACL of the DLL they register. Finding one with a writable path =
 *   genuine novel finding specific to that software version.
 */

#include "../common.h"

#define ETW_PUBLISHERS_KEY \
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers"

/* -----------------------------------------------------------------------
 * Check one ETW publisher entry
 * --------------------------------------------------------------------- */
static void CheckPublisher(LPCWSTR guidStr, HKEY hPubRoot, DWORD *findings) {
    HKEY hPub = NULL;
    if (RegOpenKeyExW(hPubRoot, guidStr, 0, KEY_READ, &hPub) != ERROR_SUCCESS)
        return;

    /* Read publisher friendly name */
    wchar_t pubName[256] = {0};
    DWORD   cb = sizeof(pubName), type = 0;
    RegQueryValueExW(hPub, NULL, NULL, &type, (LPBYTE)pubName, &cb);

    /* DLL values to check */
    static const wchar_t *dllValues[] = {
        L"MessageFileName",
        L"ResourceFileName",
        L"ParameterFileName",
        NULL
    };

    for (int vi = 0; dllValues[vi]; vi++) {
        wchar_t rawPath[MAX_PATH * 2] = {0};
        cb = sizeof(rawPath);
        if (RegQueryValueExW(hPub, dllValues[vi], NULL, &type,
                             (LPBYTE)rawPath, &cb) != ERROR_SUCCESS)
            continue;
        if (!*rawPath) continue;

        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(rawPath, expanded, _countof(expanded));

        BOOL missing  = (GetFileAttributesW(expanded) == INVALID_FILE_ATTRIBUTES);
        BOOL writable = !missing && IsFileWritable(expanded);
        BOOL userPath = IsUserWritablePath(expanded);

        if (!missing && !writable && !userPath) continue;

        Finding f;
        wcscpy(f.module, L"ETW_PROVIDER");

        if (missing) {
            f.severity = SEV_HIGH;
            _snwprintf(f.target, _countof(f.target),
                L"[MISSING] %s  (%s)",
                *pubName ? pubName : guidStr, dllValues[vi]);
            _snwprintf(f.reason, _countof(f.reason),
                L"ETW provider DLL not found on disk — phantom load. "
                L"Plant DLL in any dir searched by Event Log service. "
                L"Trigger: wevtutil qe <channel> /c:1  "
                L"Missing: %s", expanded);
        } else if (writable) {
            f.severity = SEV_CRITICAL;
            _snwprintf(f.target, _countof(f.target),
                L"[WRITABLE] %s  (%s)",
                *pubName ? pubName : guidStr, dllValues[vi]);
            _snwprintf(f.reason, _countof(f.reason),
                L"ETW provider DLL is WRITABLE by current user! "
                L"Loaded by EventLog service (SYSTEM) when events decoded. "
                L"Trigger: wevtutil qe <channel> /c:1  "
                L"DLL: %s  "
                L"SYSTEM execution guaranteed on trigger.", expanded);
        } else {
            f.severity = SEV_MEDIUM;
            _snwprintf(f.target, _countof(f.target),
                L"[USER-PATH] %s  (%s)",
                *pubName ? pubName : guidStr, dllValues[vi]);
            _snwprintf(f.reason, _countof(f.reason),
                L"ETW provider DLL in user-writable location. "
                L"Check if file itself is replaceable. DLL: %s", expanded);
        }

        PrintFinding(&f);
        (*findings)++;
    }

    RegCloseKey(hPub);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_ETWProvider(void) {
    PrintHeader(L"ETW PROVIDER DLL AUDIT  [Not checked by WinPEAS/PowerUp/Seatbelt]");

    PrintInfo(
        L"  Registry: HKLM\\" ETW_PUBLISHERS_KEY L"\n"
        L"  Trigger:  EventLog service (SYSTEM) loads DLLs when decoding events.\n"
        L"            Any user can trigger via: wevtutil qe Application /c:1\n\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ETW_PUBLISHERS_KEY,
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS,
                      &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"  [!] Cannot open WINEVT\\Publishers key\n");
        return;
    }

    DWORD idx = 0, total = 0, pubCount = 0;
    wchar_t guidStr[128];
    DWORD   guidCch;

    while (TRUE) {
        guidCch = _countof(guidStr);
        LONG ret = RegEnumKeyExW(hRoot, idx++, guidStr, &guidCch,
                                  NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS)       continue;
        pubCount++;
        CheckPublisher(guidStr, hRoot, &total);
    }

    RegCloseKey(hRoot);

    PrintInfo(L"  ETW providers enumerated: %lu\n", pubCount);

    if (total == 0)
        PrintInfo(L"  No ETW provider DLL issues found.\n");
    else {
        PrintInfo(L"  Findings: %lu\n\n", total);
        PrintInfo(
            L"  EXPLOIT STEPS (if CRITICAL finding):\n"
            L"    1. Craft proxy DLL exporting the same symbols as the original\n"
            L"       (DllMain payload + original exports forwarded)\n"
            L"    2. Replace the writable DLL\n"
            L"    3. Run from ANY user context:\n"
            L"       wevtutil qe Application /c:1\n"
            L"       OR: Get-WinEvent -LogName Application -MaxEvents 1\n"
            L"    4. EventLog service (SYSTEM) loads DLL to format event message\n"
            L"    5. DllMain runs as NT AUTHORITY\\SYSTEM\n");
    }
}

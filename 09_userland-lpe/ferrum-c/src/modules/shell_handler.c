/*
 * shell_handler.c — Shell Extension / ProgID / Verb Handler Audit
 *
 * ATTACK CLASS:
 *   The Windows Shell (explorer.exe) loads registered shell extensions
 *   (InprocServer32 DLLs) into explorer.exe context (HIGH IL) whenever:
 *     - A user opens a folder containing associated file types
 *     - A context menu is shown (right-click)
 *     - The shell processes file associations (ProgID handlers)
 *
 *   This is a HIGH-VALUE target because explorer.exe runs at HIGH integrity
 *   (UIAccess=true) and in many configurations runs as the user's desktop process.
 *   Any shell extension DLL loaded by explorer is loaded into the HIGH IL process.
 *
 *   If a shell extension DLL registered in HKCU (per-user) or HKLM (system-wide)
 *   is in a user-writable location:
 *   → Replace DLL → explorer opens a folder with that file type → DLL loaded
 *   → Code runs in HIGH IL explorer context → EFFECTIVELY escalated
 *
 * ATTACK SURFACES:
 *   1. HKCU\SOFTWARE\Classes\{ProgID}\shell\{verb}\command → verb handler path
 *      Writable by user, and some ProgIDs for elevated operations use this
 *
 *   2. HKCR\{ProgID}\shell\open\command → system-level file handler
 *      If registered DLL/EXE is in user-writable path: shell loads it when
 *      file type opened → user process can trigger loading
 *
 *   3. Shell extensions (HKCR\CLSID\{GUID}\InprocServer32 in context menus)
 *      Loaded by explorer when right-clicking matching files.
 *      If DLL path is writable → code exec in explorer (High IL).
 *
 *   4. HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved
 *      Per-user shell extension approval list — if writable, can add extension.
 *
 *   5. thumbnail handlers, property handlers, preview handlers
 *      HKCR\{ext}\ShellEx\{HandlerClass}\(default) = CLSID
 *      Loaded by Windows Explorer when files of that type are viewed.
 *
 * WHY NOVEL:
 *   Most tools check HKCU ProgID for UAC bypass (fodhelper pattern) but
 *   DO NOT check writable DLL paths of installed shell extensions —
 *   the DLL replacement vector is completely overlooked.
 *
 * REFERENCES:
 *   MITRE ATT&CK: T1546.015 — Component Object Model Hijacking
 *   T1055 — Process Injection (via shell extension DLL replacement)
 *   Didier Stevens: Shell Extension persistence via HKCU
 */

#include "../common.h"

/* Shell extension handler GUIDs of interest */
static const wchar_t *HANDLER_GUIDS[] = {
    L"{00021500-0000-0000-C000-000000000046}", /* IContextMenu */
    L"{000214F4-0000-0000-C000-000000000046}", /* IContextMenu2 */
    L"{00021501-0000-0000-C000-000000000046}", /* ICopyHook */
    L"{0000000C-0000-0000-C000-000000000046}", /* IMoniker */
    L"{E357FCCD-A995-4576-B01F-234630154E96}", /* IThumbnailProvider */
    L"{8895B1C6-B41F-4C1C-A562-0D564250836F}", /* IPreviewHandler */
    L"{B8323370-FF27-11D2-97B8-00A0C9A06D2D}", /* INameExtender */
    NULL
};

/* -----------------------------------------------------------------------
 * Check a CLSID's InprocServer32 DLL for writability
 * --------------------------------------------------------------------- */
static void CheckCLSIDInprocDLL(LPCWSTR clsid, LPCWSTR context, DWORD *findings) {
    wchar_t keyPath[512];
    _snwprintf(keyPath, _countof(keyPath),
               L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", clsid);

    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) {
        /* Try HKCU */
        r = RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hKey);
        if (r != ERROR_SUCCESS) return;
    }

    wchar_t dllPath[MAX_PATH * 2] = {0};
    DWORD cb = sizeof(dllPath), type = 0;
    RegQueryValueExW(hKey, NULL, NULL, &type, (LPBYTE)dllPath, &cb);
    RegCloseKey(hKey);

    if (!*dllPath) return;

    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(dllPath, expanded, _countof(expanded));

    BOOL exists   = (GetFileAttributesW(expanded) != INVALID_FILE_ATTRIBUTES);
    BOOL writable = exists && IsFileWritable(expanded);

    wchar_t dllDir[MAX_PATH * 2] = {0};
    wcsncpy(dllDir, expanded, _countof(dllDir) - 1);
    wchar_t *sl = wcsrchr(dllDir, L'\\');
    BOOL dirWritable = FALSE;
    if (sl) { *sl = L'\0'; dirWritable = IsDirWritable(dllDir); }

    if (!exists) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"SHELLEXT");
        _snwprintf(f.target, _countof(f.target),
            L"[MISSING] Shell Extension DLL: %s [%s]", clsid, context);
        _snwprintf(f.reason, _countof(f.reason),
            L"Shell extension CLSID %s has missing InprocServer32 DLL: %s\n"
            L"        Context: %s. Plant DLL → loaded into explorer.exe (High IL).",
            clsid, expanded, context);
        PrintFinding(&f);
        (*findings)++;
    } else if (writable) {
        Finding f;
        f.severity = SEV_CRITICAL;
        wcscpy(f.module, L"SHELLEXT");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE] Shell Extension DLL: %s [%s]", clsid, context);
        _snwprintf(f.reason, _countof(f.reason),
            L"Shell extension CLSID %s InprocServer32 DLL is WRITABLE: %s\n"
            L"        Context: %s\n"
            L"        Replace DLL → explorer.exe (High IL) loads payload → code exec at High IL.\n"
            L"        Trigger: right-click any file of associated type, or open folder.",
            clsid, expanded, context);
        PrintFinding(&f);
        (*findings)++;
    } else if (dirWritable) {
        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"SHELLEXT");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE DIR] Shell Extension: %s [%s]", clsid, context);
        _snwprintf(f.reason, _countof(f.reason),
            L"Shell extension DLL directory is writable: %s\n"
            L"        CLSID: %s  Context: %s. DLL planting opportunity.",
            dllDir, clsid, context);
        PrintFinding(&f);
        (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * Enumerate file-type shell extensions from HKCR
 * --------------------------------------------------------------------- */
static void AuditFileTypeHandlers(DWORD *findings) {
    PrintInfo(L"  [1] File-type shell extension handlers:\n");

    /* For each handler GUID type: enumerate HKCR extensions (.*) */
    static const struct { const wchar_t *guid; const wchar_t *name; } handlerTypes[] = {
        { L"{000214F4-0000-0000-C000-000000000046}", L"ContextMenu"   },
        { L"{E357FCCD-A995-4576-B01F-234630154E96}", L"ThumbnailHandler" },
        { L"{8895B1C6-B41F-4C1C-A562-0D564250836F}", L"PreviewHandler"},
        { NULL, NULL }
    };

    HKEY hHKCR = NULL;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"", 0,
                      KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hHKCR) != ERROR_SUCCESS) {
        PrintInfo(L"    Cannot open HKCR\n\n");
        return;
    }

    DWORD ext_idx = 0;
    wchar_t extName[256];
    DWORD   extCch;
    DWORD   local_findings = 0;

    while (TRUE) {
        extCch = _countof(extName);
        LONG r = RegEnumKeyExW(hHKCR, ext_idx++, extName, &extCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        if (extName[0] != L'.') continue; /* Only file extensions */

        /* For each handler type */
        for (int ht = 0; handlerTypes[ht].guid; ht++) {
            wchar_t shellexPath[512];
            _snwprintf(shellexPath, _countof(shellexPath),
                       L"%s\\ShellEx\\%s", extName, handlerTypes[ht].guid);

            HKEY hHandler = NULL;
            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, shellexPath,
                              0, KEY_READ, &hHandler) != ERROR_SUCCESS)
                continue;

            wchar_t clsid[64] = {0};
            DWORD   cb = sizeof(clsid), type = 0;
            RegQueryValueExW(hHandler, NULL, NULL, &type, (LPBYTE)clsid, &cb);
            RegCloseKey(hHandler);

            if (*clsid) {
                wchar_t ctx[128];
                _snwprintf(ctx, _countof(ctx), L"%s/%s", extName, handlerTypes[ht].name);
                CheckCLSIDInprocDLL(clsid, ctx, &local_findings);
            }
        }
    }
    RegCloseKey(hHKCR);
    *findings += local_findings;
    PrintInfo(L"    Found %lu shell extension DLL issues\n\n", local_findings);
}

/* -----------------------------------------------------------------------
 * Check HKCU verb handlers (UAC bypass via shell verb)
 * --------------------------------------------------------------------- */
static void AuditHKCUVerbHandlers(DWORD *findings) {
    PrintInfo(L"  [2] HKCU ProgID verb command handlers:\n");

    HKEY hRoot = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Classes",
                      0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &hRoot) != ERROR_SUCCESS) {
        PrintInfo(L"    (HKCU\\Classes not accessible)\n\n");
        return;
    }

    DWORD idx = 0, count = 0;
    wchar_t progID[256];
    DWORD   progIDCch;

    while (TRUE) {
        progIDCch = _countof(progID);
        LONG r = RegEnumKeyExW(hRoot, idx++, progID, &progIDCch,
                               NULL, NULL, NULL, NULL);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) continue;
        count++;

        /* Check shell\open\command or shell\runas\command */
        static const wchar_t *verbs[] = {
            L"open", L"runas", L"print", L"edit", NULL
        };
        for (int vi = 0; verbs[vi]; vi++) {
            wchar_t cmdKeyPath[512];
            _snwprintf(cmdKeyPath, _countof(cmdKeyPath),
                       L"SOFTWARE\\Classes\\%s\\shell\\%s\\command",
                       progID, verbs[vi]);

            HKEY hCmd = NULL;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, cmdKeyPath,
                              0, KEY_READ, &hCmd) != ERROR_SUCCESS) continue;

            wchar_t cmdLine[MAX_PATH * 2] = {0};
            DWORD   cb = sizeof(cmdLine), type = 0;
            RegQueryValueExW(hCmd, NULL, NULL, &type, (LPBYTE)cmdLine, &cb);
            RegCloseKey(hCmd);

            if (*cmdLine) {
                wchar_t exePath[MAX_PATH * 2] = {0};
                ExtractExePath(cmdLine, exePath, _countof(exePath));
                if (*exePath && IsFileWritable(exePath)) {
                    Finding f;
                    f.severity = SEV_HIGH;
                    wcscpy(f.module, L"SHELLEXT");
                    _snwprintf(f.target, _countof(f.target),
                        L"[HKCU WRITABLE] %s\\%s: %s", progID, verbs[vi], exePath);
                    _snwprintf(f.reason, _countof(f.reason),
                        L"HKCU ProgID verb handler EXE is writable: %s\n"
                        L"        ProgID: %s  Verb: %s  Cmd: %s\n"
                        L"        When shell opens this file type with %s verb → payload executes.",
                        exePath, progID, verbs[vi], cmdLine, verbs[vi]);
                    PrintFinding(&f);
                    (*findings)++;
                }
            }
        }
    }

    RegCloseKey(hRoot);
    PrintInfo(L"    HKCU ProgIDs checked: %lu\n\n", count);
}

void Module_ShellHandler(void) {
    PrintHeader(L"SHELL EXTENSION AUDIT  [Shell extension DLL writability → explorer.exe High IL injection]");

    PrintInfo(
        L"  Shell extensions are DLLs loaded by explorer.exe (High IL) on file interaction.\n"
        L"  Writable extension DLL = code execution in High IL explorer context.\n"
        L"  Also checks HKCU verb handler paths (UAC bypass surface).\n\n");

    DWORD findings = 0;
    AuditFileTypeHandlers(&findings);
    AuditHKCUVerbHandlers(&findings);

    if (findings == 0)
        PrintInfo(L"  No shell extension LPE surface found.\n");
    else {
        PrintInfo(L"  Total findings: %lu\n\n", findings);
        PrintInfo(
            L"  TRIGGER METHODS:\n"
            L"    ContextMenu handler: right-click any file with associated extension\n"
            L"    ThumbnailHandler: open folder containing associated file in Details pane\n"
            L"    PreviewHandler: click file in Explorer Preview pane\n"
            L"    Verb handler: double-click / open file with associated ProgID\n"
            L"    Wait ~30s after DLL replacement → Explorer may auto-reload on navigation\n");
    }
}

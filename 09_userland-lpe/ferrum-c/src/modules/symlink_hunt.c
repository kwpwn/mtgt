/*
 * symlink_hunt.c — Passive Hunt for Symlink/Race Attack Candidates
 *
 * Systematically identifies SYSTEM service file/registry/pipe operations
 * that are vulnerable to the junction+symlink BaitAndSwitch technique.
 *
 * WHAT WE LOOK FOR:
 *   1. SYSTEM services that write to user-writable directories
 *      → parent can be junctioned → arbitrary file write primitive
 *
 *   2. SYSTEM services that CREATE files at predictable user-writable paths
 *      → plant oplock before service creates → swap on create
 *
 *   3. Writable directories that SYSTEM services LoadLibrary from
 *      → classic DLL planting, but also via symlink chain
 *
 *   4. Named pipes with predictable names that SYSTEM creates
 *      → we create pipe first → SYSTEM connects → ImpersonateNamedPipeClient
 *
 *   5. Registry keys in HKCU that SYSTEM services read
 *      → inject malicious values → SYSTEM executes our path
 *
 * SOURCES:
 *   James Forshaw (Project Zero): symboliclink-testing-tools methodology
 *   Known CVE patterns (2015-2024) that used these techniques
 *   ProcMon-derived knowledge of common SYSTEM service file patterns
 *
 * IMPORTANT: This is PASSIVE enumeration only. Use --SYMLINKPRIM and
 * --OPLOCKRACE modules to actually exploit found candidates.
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * Check if a path exists, is a directory, and is writable
 * (or if its parent is writable — can create files there)
 * --------------------------------------------------------------------- */
static void CheckPathWritability(LPCWSTR path, const wchar_t *service,
                                  const wchar_t *trigger,
                                  const wchar_t *attackVector,
                                  DWORD *findings) {
    DWORD attrs = GetFileAttributesW(path);
    BOOL  exists = (attrs != INVALID_FILE_ATTRIBUTES);
    BOOL  isDir  = exists && (attrs & FILE_ATTRIBUTE_DIRECTORY);
    BOOL  writable = FALSE;

    if (exists) {
        writable = isDir ? IsDirWritable(path) : IsFileWritable(path);
    } else {
        /* Check if parent is writable (can create here) */
        wchar_t parent[MAX_PATH * 2] = {0};
        wcsncpy(parent, path, _countof(parent)-1);
        wchar_t *lastSep = wcsrchr(parent, L'\\');
        if (lastSep) {
            *lastSep = L'\0';
            DWORD pAttrs = GetFileAttributesW(parent);
            if (pAttrs != INVALID_FILE_ATTRIBUTES &&
                (pAttrs & FILE_ATTRIBUTE_DIRECTORY))
                writable = IsDirWritable(parent);
        }
    }

    PrintInfo(L"    [%s] %s\n"
              L"           Service: %s\n"
              L"           Trigger: %s\n",
              !exists ? L"NOT FOUND" :
              (writable ? L"WRITABLE!" : L"exists/protected"),
              path, service, trigger);

    if (writable && exists) {
        PrintInfo(L"           Attack:  %s\n\n", attackVector);

        Finding f;
        f.severity = SEV_HIGH;
        wcscpy(f.module, L"SYMLINKCAN");
        _snwprintf(f.target, _countof(f.target),
            L"[WRITABLE] Symlink race candidate: %s", path);
        _snwprintf(f.reason, _countof(f.reason),
            L"SYSTEM service '%s' accesses writable path: %s\n"
            L"        Trigger: %s\n"
            L"        Attack:  %s\n"
            L"        Method: --SYMLINKPRIM (junction+symlink) + --OPLOCKRACE (race window)",
            service, path, trigger, attackVector);
        PrintFinding(&f);
        (*findings)++;
    } else {
        PrintInfo(L"\n");
    }
}

/* -----------------------------------------------------------------------
 * 1. Audit writable SYSTEM service log/temp paths
 * --------------------------------------------------------------------- */
static void AuditSystemWritePaths(DWORD *findings) {
    PrintInfo(L"  [1] SYSTEM service writable path candidates:\n\n");

    typedef struct {
        const wchar_t *path;
        const wchar_t *service;
        const wchar_t *trigger;
        const wchar_t *attack;
    } PATH_CANDIDATE;

    static const PATH_CANDIDATE PATHS[] = {
        {
            L"%SystemRoot%\\Temp",
            L"Windows Update (TiWorker.exe, SYSTEM)",
            L"wuauclt.exe /detectnow  OR  Start-Process ms-settings: (triggers DISM)",
            L"Junction Temp\\ → \\RPC Control\\; symlink update file → System32 DLL"
        },
        {
            L"%SystemRoot%\\System32\\spool\\PRINTERS",
            L"Print Spooler (spoolsv.exe, SYSTEM)",
            L"Send a print job: notepad → print to any printer",
            L"Junction PRINTERS\\ → \\RPC Control\\; symlink EMF file → System32 DLL"
        },
        {
            L"%SystemRoot%\\System32\\LogFiles\\WMI",
            L"WMI (WmiApSrv, NETWORK SERVICE)",
            L"Enable WMI tracing or run WMI query triggering trace log",
            L"Junction WMI\\ → \\RPC Control\\; symlink trace file → config DLL"
        },
        {
            L"%ProgramData%\\Microsoft\\Windows\\WER\\ReportQueue",
            L"Windows Error Reporting (WerSvc, LOCAL SYSTEM)",
            L"Crash any application: taskkill /f /im notepad.exe",
            L"Junction ReportQueue\\ → \\RPC Control\\; symlink WER report → SYSTEM file"
        },
        {
            L"%ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive",
            L"Windows Error Reporting (WerSvc, LOCAL SYSTEM)",
            L"Crash any application",
            L"Same as ReportQueue approach"
        },
        {
            L"%SystemRoot%\\ServiceProfiles\\LocalService\\AppData\\Local\\Temp",
            L"Services running as LOCAL SERVICE",
            L"Trigger any LOCAL SERVICE (AudioSrv, SSDPSRV, etc.) temp write",
            L"Junction Temp\\ → \\RPC Control\\; target service DLL"
        },
        {
            L"%SystemRoot%\\ServiceProfiles\\NetworkService\\AppData\\Local\\Temp",
            L"Services running as NETWORK SERVICE",
            L"Trigger any NETWORK SERVICE (DNS, MSDTC, etc.) temp write",
            L"Junction Temp\\ → \\RPC Control\\; target NETWORK SERVICE DLL"
        },
        {
            L"%SystemRoot%\\System32\\Tasks",
            L"Task Scheduler (Schedule service, SYSTEM)",
            L"Register a scheduled task with high privileges",
            L"Junction Tasks\\ → \\RPC Control\\; task XML → arbitrary SYSTEM exec"
        },
        {
            L"%LocalAppData%\\Temp",
            L"User-context SYSTEM services (Windows Installer, etc.)",
            L"Trigger installer or user-scoped SYSTEM service",
            L"Plant oplock; junction on break → redirect DLL load"
        },
        {
            L"%SystemRoot%\\SoftwareDistribution\\Download",
            L"Windows Update (BITS, WuAuServ — SYSTEM)",
            L"wuauclt.exe /detectnow — triggers update download check",
            L"Junction Download\\ → \\RPC Control\\; redirect downloaded update → evil EXE"
        },
        {
            L"%SystemRoot%\\System32\\catroot2",
            L"Crypto service (CryptSvc — NETWORK SERVICE)",
            L"Install any signed software or run certutil",
            L"Junction catroot2\\ → \\RPC Control\\; symlink cat file → trusted cert bypass"
        },
        {
            L"%SystemRoot%\\CbsTemp",
            L"Windows Servicing (TrustedInstaller — SYSTEM/TI)",
            L"Install any Windows component or run DISM",
            L"Junction CbsTemp\\ → \\RPC Control\\; symlink CBS log → System32 DLL"
        },
        { NULL, NULL, NULL, NULL }
    };

    for (int i = 0; PATHS[i].path; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(PATHS[i].path, expanded, _countof(expanded));
        CheckPathWritability(expanded, PATHS[i].service,
                              PATHS[i].trigger, PATHS[i].attack, findings);
    }
}

/* -----------------------------------------------------------------------
 * 2. Audit named pipes that SYSTEM services may create predictably
 *    If we create the pipe first, SYSTEM connects → impersonation → SYSTEM token
 * --------------------------------------------------------------------- */
static void AuditPipeImpersonationCandidates(DWORD *findings) {
    PrintInfo(L"  [2] Named pipe impersonation candidates:\n\n");

    typedef struct {
        const wchar_t *pipeName;
        const wchar_t *service;
        const wchar_t *trigger;
        BOOL        tested;
    } PIPE_CANDIDATE;

    static PIPE_CANDIDATE PIPES[] = {
        {
            L"\\\\.\\pipe\\Winsock2\\CatalogChangeListener-XXX-0",
            L"Winsock service (any process with WSAStartup)",
            L"Create new process that calls WSAStartup()",
            FALSE
        },
        {
            L"\\\\.\\pipe\\spoolss",
            L"Print Spooler (SYSTEM) — connects back to SpoolFool",
            L"Call RpcOpenPrinter() from medium IL — triggers spooler to connect our pipe",
            FALSE
        },
        {
            L"\\\\.\\pipe\\msFteWds",
            L"Windows Search (WSearch, SYSTEM)",
            L"Trigger search indexing operation",
            FALSE
        },
        {
            L"\\\\.\\pipe\\epmapper",
            L"RPC Endpoint Mapper (RpcSs, NETWORK SERVICE)",
            L"Make any RPC call targeting this endpoint",
            FALSE
        },
        {
            L"\\\\.\\pipe\\SessEnvPublicRpc",
            L"Remote Desktop Session Environment (SessionEnv, NETWORK SERVICE)",
            L"Connect RDP session or call TermSrv RPC interface",
            FALSE
        },
        {
            L"\\\\.\\pipe\\lsass",
            L"LSASS (SYSTEM) — credential pipe",
            L"Any authentication operation (NTLM challenge/response)",
            FALSE
        },
        { NULL, NULL, NULL, FALSE }
    };

    for (int i = 0; PIPES[i].pipeName; i++) {
        /* Check if pipe currently exists (SYSTEM already created it) */
        HANDLE hPipe = CreateFileW(PIPES[i].pipeName,
            GENERIC_READ, FILE_SHARE_READ, NULL,
            OPEN_EXISTING, 0, NULL);

        BOOL pipeExists = (hPipe != INVALID_HANDLE_VALUE);
        if (pipeExists) CloseHandle(hPipe);

        PrintInfo(L"    [%s] %s\n"
                  L"           Service: %s\n"
                  L"           Trigger: %s\n\n",
                  pipeExists ? L"EXISTS" : L"NOT FOUND",
                  PIPES[i].pipeName,
                  PIPES[i].service,
                  PIPES[i].trigger);

        if (pipeExists) (*findings)++;
    }

    /* Enumerate actual pipes on this system */
    PrintInfo(L"    Active named pipes on this system:\n");
    WIN32_FIND_DATAW fd = {0};
    HANDLE hFind = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
    DWORD pipeCount = 0;
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            pipeCount++;
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    PrintInfo(L"    Total named pipes: %lu (use Process Hacker or pipelist.exe for details)\n\n",
              pipeCount);
}

/* -----------------------------------------------------------------------
 * 3. Audit HKCU registry keys that SYSTEM services read
 *    HKCU is per-user — writable by current user, readable by SYSTEM context
 *    if running as current user (e.g. services launched from user session)
 * --------------------------------------------------------------------- */
static void AuditHKCUSystemReads(DWORD *findings) {
    PrintInfo(L"  [3] HKCU registry keys that SYSTEM services read:\n\n");

    typedef struct {
        const wchar_t *keyPath;
        const wchar_t *valueName;
        const wchar_t *service;
        const wchar_t *desc;
    } HKCU_KEY;

    static const HKCU_KEY KEYS[] = {
        {
            L"Software\\Classes\\CLSID",
            NULL,
            L"COM server (any SYSTEM process creating COM objects)",
            L"HKCU CLSID overrides HKLM — plant CLSID with InprocServer32 = payload.dll"
        },
        {
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers",
            NULL,
            L"AppCompat (ShimEng, SYSTEM)",
            L"Plant compatibility layer that injects DLL into SYSTEM process"
        },
        {
            L"Environment",
            L"PATH",
            L"Any process inheriting environment from this user session",
            L"Prepend writable dir to PATH → DLL search order hijack in SYSTEM process"
        },
        {
            L"Environment",
            L"COR_ENABLE_PROFILING",
            L"Any .NET process run as this user (COR_PROFILER injection)",
            L"Set COR_ENABLE_PROFILING=1, COR_PROFILER={GUID}, COR_PROFILER_PATH=evil.dll"
        },
        {
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            NULL,
            L"Explorer (SYSTEM logon in some configs) / current user logon",
            L"Persist payload execution at logon"
        },
        {
            L"Software\\Classes\\ms-settings\\shell\\open\\command",
            NULL,
            L"UAC bypass target — fodhelper.exe reads HKCU first",
            L"Plant command here → run fodhelper.exe → auto-elevated SYSTEM exec (UAC bypass)"
        },
        {
            L"Software\\Classes\\mscfile\\shell\\open\\command",
            NULL,
            L"UAC bypass target — eventvwr.exe reads HKCU first",
            L"Plant command → run eventvwr.exe → auto-elevated SYSTEM exec (UAC bypass)"
        },
        { NULL, NULL, NULL, NULL }
    };

    for (int i = 0; KEYS[i].keyPath; i++) {
        HKEY hKey = NULL;
        BOOL writable = (RegOpenKeyExW(HKEY_CURRENT_USER, KEYS[i].keyPath,
                                        0, KEY_WRITE | KEY_SET_VALUE, &hKey) == ERROR_SUCCESS);
        if (writable) RegCloseKey(hKey);

        BOOL exists = (RegOpenKeyExW(HKEY_CURRENT_USER, KEYS[i].keyPath,
                                      0, KEY_READ, &hKey) == ERROR_SUCCESS);
        if (exists) RegCloseKey(hKey);

        PrintInfo(L"    HKCU\\%s [%s]\\%s\n"
                  L"           Service: %s\n"
                  L"           Attack:  %s\n\n",
                  KEYS[i].keyPath,
                  writable ? L"WRITABLE" : L"read-only",
                  KEYS[i].valueName ? KEYS[i].valueName : L"(any value)",
                  KEYS[i].service,
                  KEYS[i].desc);

        if (writable && exists) (*findings)++;
    }
}

/* -----------------------------------------------------------------------
 * 4. Audit files/dirs in SYSTEM service executable search paths
 *    that are writable — symlink-able or directly plantable
 * --------------------------------------------------------------------- */
static void AuditSystemServiceSearchPaths(DWORD *findings) {
    PrintInfo(L"  [4] Writable directories in SYSTEM service DLL search paths:\n\n");

    /* Check PATH for writable directories */
    wchar_t pathEnv[32768] = {0};
    GetEnvironmentVariableW(L"PATH", pathEnv, _countof(pathEnv));

    wchar_t copy[32768];
    wcsncpy(copy, pathEnv, _countof(copy)-1);
    wchar_t *ctx = NULL;
    wchar_t *token = wcstok(copy, L";", &ctx);
    DWORD writablePathDirs = 0;

    while (token) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(token, expanded, _countof(expanded));

        if (*expanded) {
            DWORD attrs = GetFileAttributesW(expanded);
            BOOL exists = (attrs != INVALID_FILE_ATTRIBUTES) &&
                          (attrs & FILE_ATTRIBUTE_DIRECTORY);
            BOOL writable = exists && IsDirWritable(expanded);

            if (writable) {
                writablePathDirs++;
                PrintInfo(L"    [WRITABLE PATH] %s\n", expanded);
                PrintInfo(L"           Plant DLL here → loaded by any process using this PATH entry\n");
                PrintInfo(L"           If SYSTEM service in PATH uses LoadLibrary(name) without full path\n");
                PrintInfo(L"           → DLL planting leads to SYSTEM code exec\n\n");

                Finding f;
                f.severity = SEV_HIGH;
                wcscpy(f.module, L"SYMLINKCAN");
                _snwprintf(f.target, _countof(f.target),
                    L"[WRITABLE PATH DIR] %s", expanded);
                _snwprintf(f.reason, _countof(f.reason),
                    L"Writable directory in system PATH: %s\n"
                    L"        Any SYSTEM service doing LoadLibrary(\"name.dll\") without full path\n"
                    L"        will search PATH and load from this writable directory.\n"
                    L"        Also: junction this dir → \\RPC Control\\ for symlink chain attacks.",
                    expanded);
                PrintFinding(&f);
                (*findings)++;
            }
        }
        token = wcstok(NULL, L";", &ctx);
    }
    if (writablePathDirs == 0)
        PrintInfo(L"    No writable PATH directories found\n\n");
}

/* -----------------------------------------------------------------------
 * 5. Check for hardlink-able SYSTEM files (read arbitrary SYSTEM-only file)
 *    Hard links can be created by any user to ANY file they have READ access to
 *    → Even SAM/SYSTEM hive files if HiveNightmare applies
 * --------------------------------------------------------------------- */
static void AuditHardLinkCandidates(DWORD *findings) {
    PrintInfo(L"  [5] Hard link candidates (read privileged files via link):\n\n");

    static const wchar_t *PRIV_FILES[] = {
        L"%SystemRoot%\\System32\\config\\SAM",
        L"%SystemRoot%\\System32\\config\\SYSTEM",
        L"%SystemRoot%\\System32\\config\\SECURITY",
        L"%SystemRoot%\\repair\\SAM",
        L"%SystemRoot%\\System32\\config\\RegBack\\SAM",
        L"%SystemRoot%\\NTDS\\ntds.dit",
        NULL
    };

    for (int i = 0; PRIV_FILES[i]; i++) {
        wchar_t expanded[MAX_PATH * 2] = {0};
        ExpandEnvironmentStringsW(PRIV_FILES[i], expanded, _countof(expanded));

        /* Try to open for read — if we can, we can hard link it */
        HANDLE hFile = CreateFileW(expanded,
            GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        BOOL readable = (hFile != INVALID_HANDLE_VALUE);
        if (readable) CloseHandle(hFile);

        PrintInfo(L"    [%s] %s\n",
                  readable ? L"READABLE — hardlink viable!" : L"protected",
                  expanded);

        if (readable) {
            (*findings)++;
            wchar_t tempPath[MAX_PATH] = {0};
            GetTempPathW(_countof(tempPath), tempPath);

            Finding f;
            f.severity = SEV_CRITICAL;
            wcscpy(f.module, L"SYMLINKCAN");
            _snwprintf(f.target, _countof(f.target),
                L"[READABLE] Privileged file readable (HiveNightmare?): %s", expanded);
            _snwprintf(f.reason, _countof(f.reason),
                L"Privileged file is readable by current user: %s\n"
                L"        Hard link attack: CreateHardLinkW(\"%s\\SAM_copy\", \"%s\")\n"
                L"        → Access file content without VSS shadow copy.\n"
                L"        Use impacket secretsdump or pypykatz to extract NTLM hashes.\n"
                L"        Also viable: CVE-2021-36934 (HiveNightmare/SeriousSAM)",
                expanded, tempPath, expanded);
            PrintFinding(&f);
        }
    }
    PrintInfo(L"\n");
}

/* -----------------------------------------------------------------------
 * 6. Service binary writable parent directory audit
 *    (Classic: service loads DLL from writable dir in binary's directory)
 * --------------------------------------------------------------------- */
static void AuditServiceBinaryDirs(DWORD *findings) {
    PrintInfo(L"  [6] SYSTEM service binary directory writability (DLL planting):\n\n");

    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;

    DWORD needed = 0, returned = 0;
    EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                           SERVICE_ACTIVE, NULL, 0, &needed, &returned, NULL, NULL);

    BYTE *buf = (BYTE*)malloc(needed + 4096);
    if (!buf) { CloseServiceHandle(hSCM); return; }

    if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                SERVICE_ACTIVE, buf, needed + 4096,
                                &needed, &returned, NULL, NULL)) {
        free(buf); CloseServiceHandle(hSCM); return;
    }

    LPENUM_SERVICE_STATUS_PROCESSW svc = (LPENUM_SERVICE_STATUS_PROCESSW)buf;
    DWORD vulnCount = 0;

    for (DWORD i = 0; i < returned; i++) {
        /* Only care about SYSTEM account services */
        SC_HANDLE hSvc = OpenServiceW(hSCM, svc[i].lpServiceName,
                                       SERVICE_QUERY_CONFIG);
        if (!hSvc) continue;

        BYTE cfgBuf[8192] = {0};
        DWORD cfgNeeded = 0;
        if (!QueryServiceConfigW(hSvc, (LPQUERY_SERVICE_CONFIGW)cfgBuf,
                                  sizeof(cfgBuf), &cfgNeeded)) {
            CloseServiceHandle(hSvc); continue;
        }
        LPQUERY_SERVICE_CONFIGW cfg = (LPQUERY_SERVICE_CONFIGW)cfgBuf;

        /* Filter: LocalSystem only */
        if (!cfg->lpServiceStartName ||
            _wcsicmp(cfg->lpServiceStartName, L"LocalSystem") != 0) {
            CloseServiceHandle(hSvc); continue;
        }

        /* Get binary directory */
        wchar_t binExe[MAX_PATH * 2] = {0};
        ExtractExePath(cfg->lpBinaryPathName, binExe, _countof(binExe));
        if (!*binExe) { CloseServiceHandle(hSvc); continue; }

        wchar_t binDir[MAX_PATH * 2] = {0};
        wcsncpy(binDir, binExe, _countof(binDir)-1);
        wchar_t *lastSep = wcsrchr(binDir, L'\\');
        if (lastSep) *lastSep = L'\0';

        /* Skip System32 and Windows dirs (not writable normally) */
        wchar_t sysDir[MAX_PATH] = {0};
        GetSystemDirectoryW(sysDir, _countof(sysDir));
        if (_wcsnicmp(binDir, sysDir, wcslen(sysDir)) == 0) {
            CloseServiceHandle(hSvc); continue;
        }

        BOOL writable = IsDirWritable(binDir);
        if (writable) {
            vulnCount++;
            if (vulnCount <= 20) { /* cap output */
                PrintInfo(L"    [WRITABLE DIR] %s (%s)\n", binDir, svc[i].lpServiceName);
                (*findings)++;

                Finding f;
                f.severity = SEV_CRITICAL;
                wcscpy(f.module, L"SYMLINKCAN");
                _snwprintf(f.target, _countof(f.target),
                    L"[WRITABLE SYSTEM SVC DIR] %s (%s)", binDir, svc[i].lpServiceName);
                _snwprintf(f.reason, _countof(f.reason),
                    L"SYSTEM service '%s' binary dir is writable: %s\n"
                    L"        Plant DLL with same name as any DLL the service imports.\n"
                    L"        → DLL load from writable dir → SYSTEM code exec on service restart.\n"
                    L"        Or: junction the dir → \\RPC Control\\ + symlink for file redirect.",
                    svc[i].lpServiceName, binDir);
                PrintFinding(&f);
            }
        }
        CloseServiceHandle(hSvc);
    }
    if (vulnCount == 0)
        PrintInfo(L"    No writable SYSTEM service binary directories found\n");
    PrintInfo(L"\n");

    free(buf);
    CloseServiceHandle(hSCM);
}

/* -----------------------------------------------------------------------
 * Module entry point
 * --------------------------------------------------------------------- */
void Module_SymlinkHunt(void) {
    PrintHeader(
        L"SYMLINK RACE CANDIDATES  "
        L"[Passive hunt: SYSTEM service paths/pipes/registry for junction+symlink attack]");

    PrintInfo(
        L"  Systematically identifies surfaces for the Forshaw junction+symlink technique.\n"
        L"  Combines: writable SYSTEM paths + oplock race + NT symlink chain.\n"
        L"  Use --SYMLINKPRIM to verify primitives, --OPLOCKRACE to exploit.\n\n");

    DWORD findings = 0;
    AuditSystemWritePaths(&findings);
    AuditPipeImpersonationCandidates(&findings);
    AuditHKCUSystemReads(&findings);
    AuditSystemServiceSearchPaths(&findings);
    AuditHardLinkCandidates(&findings);
    AuditServiceBinaryDirs(&findings);

    if (findings == 0)
        PrintInfo(L"  No symlink race candidates found.\n");
    else
        PrintInfo(
            L"  Total candidates: %lu\n\n"
            L"  NEXT STEPS:\n"
            L"    1. ferrum.exe --SYMLINKPRIM  → verify junction+symlink chain works\n"
            L"    2. ferrum.exe --OPLOCKRACE   → test oplock primitive\n"
            L"    3. Use ProcMon to confirm SYSTEM service access patterns\n"
            L"    4. Trigger service operation → race → arbitrary SYSTEM file access\n",
            findings);
}

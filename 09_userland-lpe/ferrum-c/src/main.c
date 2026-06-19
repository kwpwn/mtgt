/*
 * ferrum.c — Windows LPE Surface Enumerator (C port of kernelstub/Ferrum)
 *
 * Usage:
 *   ferrum.exe [--SERVICES] [--TOKENS] [--CLSID] [--PIPES] [--DLLSEARCH]
 *              [--REGISTRY] [--SCHEDULED] [--DRIVERS] [--ENV]
 *              [--PERFLIB] [--COMSURR] [--ETW] [--OBJNS] [--TOCTOU]
 *              [--PRINT] [--LSA] [--APPCERT] [--CREDPROV] [--NETPROV]
 *              [--AUTORUN] [--WMIPROV] [--ALPC] [--RPCSVC] [--DRIVERIOCTL]
 *              [--IMPERSONATE] [--COMELE] [--SECTIONS]
 *              [--WMSG] [--MSIINSTALL] [--APPINITDLL] [--UACBYPASS] [--LOCALSVC]
 *              [--WER] [--SDB] [--PROCDACL] [--DCOMHIJACK] [--SHELLEXT]
 *              [--BITS] [--TELEMETRY] [--SECLOGON] [--FONTPROV]
 *              [--HANDLES] [--DOTNETCLR] [--COMPLUS]
 *              [--ZERODAY] [--ALL] [--OUTPUT <file>] [--NO-COLOR]
 *
 * Compile: run build.bat from a Visual Studio Developer Command Prompt.
 *   build.bat auto-detects MSVC (cl.exe) or MinGW (gcc.exe).
 */

#include "common.h"
#include <fcntl.h>
#include <io.h>

/* -----------------------------------------------------------------------
 * Enable VT100 colour in modern Windows consoles
 * --------------------------------------------------------------------- */
static void EnableVTColor(void) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  mode = 0;
    if (GetConsoleMode(hOut, &mode))
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

/* -----------------------------------------------------------------------
 * Print usage
 * --------------------------------------------------------------------- */
static void Usage(const wchar_t *prog) {
    wprintf(
        L"\n"
        CLR_BOLD CLR_CYAN
        L"  Ferrum/C — Windows LPE Surface Enumerator\n"
        CLR_RESET
        L"  C port of github.com/kernelstub/Ferrum\n\n"
        L"  Usage: %s [modules] [options]\n\n"
        L"  Modules (at least one required, or --ALL):\n"
        L"    --SERVICES     Service misconfigurations (unquoted paths, weak DACLs)\n"
        L"    --TOKENS       Process token privilege scoring\n"
        L"    --CLSID        COM hijack candidates (HKCU override missing)\n"
        L"    --PIPES        Named pipe security surface\n"
        L"    --DLLSEARCH    DLL search path & KnownDLLs analysis\n"
        L"    --REGISTRY     Registry permission LPE checks\n"
        L"    --SCHEDULED    Scheduled task misconfiguration\n"
        L"    --DRIVERS      Kernel driver enumeration\n"
        L"    --ENV          Environment variable surface\n"
        L"    --PERFLIB      Performance counter DLL writability (underexplored)\n"
        L"    --COMSURR      COM Surrogate (dllhost.exe) DLL audit\n"
        L"    --ETW          ETW provider DLL writability (0-day surface)\n"
        L"    --OBJNS        NT Object Namespace directory ACL audit (novel)\n"
        L"    --TOCTOU       Shared-write dir / oplock race surface\n"
        L"    --PRINT        Print monitor/processor DLLs (PrintNightmare class)\n"
        L"    --LSA          LSA auth/security package DLLs (lsass.exe)\n"
        L"    --APPCERT      AppCert DLLs (every CreateProcess)\n"
        L"    --CREDPROV     Credential provider DLLs (logonui.exe/SYSTEM)\n"
        L"    --NETPROV      Network provider DLLs (credential intercept)\n"
        L"    --AUTORUN      Startup items with writable paths\n"
        L"    --WMIPROV      WMI provider DLLs (WmiPrvSE.exe/SYSTEM)\n"
        L"    --ALPC         ALPC port DACL audit (novel — no public tool does this)\n"
        L"    --RPCSVC       RPC endpoint mapper + server account + unauth access test\n"
        L"    --DRIVERIOCTL  Kernel driver IOCTL surface + BYOVD driver detection\n"
        L"    --IMPERSONATE  Dangerous token privilege audit (Potato/SeLoadDriver/SeTcb)\n"
        L"    --COMELE       COM auto-elevation surface (UAC bypass / logic-bug surface)\n"
        L"    --SECTIONS     Named section object ACL audit (shared-memory logic bugs)\n"
        L"\n  Extended 0-day Modules (novel surfaces, no public tool covers):\n"
        L"    --WMSG         WM_COPYDATA/WM_DDE cross-IL window message surface\n"
        L"    --MSIINSTALL   AlwaysInstallElevated MSI policy (SYSTEM via MSI)\n"
        L"    --APPINITDLL   AppInit_DLLs injection surface (loaded by every process)\n"
        L"    --UACBYPASS    UAC bypass via HKCU class hijack (fodhelper/eventvwr/etc)\n"
        L"    --LOCALSVC     Localhost privileged TCP service scan (gRPC/WebSocket/HTTP)\n"
        L"    --WER          WER/AeDebug JIT debugger + crash handler DLL surface\n"
        L"    --SDB          AppCompat shim database injection (Duqu 2.0 technique)\n"
        L"    --PROCDACL     Process DACL audit (DUP_HANDLE/VM_WRITE on SYSTEM procs)\n"
        L"    --DCOMHIJACK   DCOM LocalServer32 EXE path hijacking (RunAs=SYSTEM)\n"
        L"    --SHELLEXT     Shell extension DLL writability (explorer.exe High IL)\n"
        L"    --BITS         BITS service notification + plugin DLL surface\n"
        L"    --TELEMETRY    DiagTrack perf counter DLL + telemetry scheduled tasks\n"
        L"    --SECLOGON     Secondary Logon seclogon SYSTEM token leakage\n"
        L"    --FONTPROV     Font provider DLL + font cache + per-user font surface\n"
        L"    --HANDLES      Inheritable handle leakage from SYSTEM processes\n"
        L"    --DOTNETCLR    COR_PROFILER DLL injection into .NET SYSTEM services\n"
        L"    --COMPLUS      COM+ server app DLL writability (enterprise middleware)\n"
        L"    --ZERODAY      0-day research mode: enable all novel modules + guidance\n"
        L"    --ALL          Run all 44 modules\n\n"
        L"  Options:\n"
        L"    --OUTPUT <file>  Write findings to file (in addition to stdout)\n"
        L"    --NO-COLOR       Disable ANSI colour output\n\n"
        L"  Examples:\n"
        L"    ferrum.exe --ALL --OUTPUT report.txt\n"
        L"    ferrum.exe --TOKENS --SERVICES\n"
        L"    ferrum.exe --CLSID --NO-COLOR > clsid_candidates.txt\n\n",
        prog);
}

/* -----------------------------------------------------------------------
 * Banner
 * --------------------------------------------------------------------- */
static void Banner(void) {
    wprintf(
        CLR_BOLD CLR_MAGENTA
        L"\n"
        L"  ███████╗███████╗██████╗ ██████╗ ██╗   ██╗███╗   ███╗\n"
        L"  ██╔════╝██╔════╝██╔══██╗██╔══██╗██║   ██║████╗ ████║\n"
        L"  █████╗  █████╗  ██████╔╝██████╔╝██║   ██║██╔████╔██║\n"
        L"  ██╔══╝  ██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║╚██╔╝██║\n"
        L"  ██║     ███████╗██║  ██║██║  ██║╚██████╔╝██║ ╚═╝ ██║\n"
        L"  ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝\n"
        CLR_RESET
        CLR_CYAN
        L"  Windows LPE Surface Enumerator  |  C Edition\n"
        L"  Based on: github.com/kernelstub/Ferrum (Go)\n"
        CLR_RESET L"\n");
}

/* -----------------------------------------------------------------------
 * Argument matching helper
 * --------------------------------------------------------------------- */
static BOOL ArgIs(LPCWSTR arg, LPCWSTR name) {
    return _wcsicmp(arg, name) == 0;
}

/* -----------------------------------------------------------------------
 * Entry point
 * --------------------------------------------------------------------- */
int wmain(int argc, wchar_t *argv[]) {
    /* stdout in wide mode */
    _setmode(_fileno(stdout), _O_U16TEXT);

    EnableVTColor();

    /* ---- Parse arguments ---- */
    BOOL doServices  = FALSE;
    BOOL doTokens    = FALSE;
    BOOL doCLSID     = FALSE;
    BOOL doPipes     = FALSE;
    BOOL doDLLSearch = FALSE;
    BOOL doRegistry  = FALSE;
    BOOL doScheduled = FALSE;
    BOOL doDrivers   = FALSE;
    BOOL doEnv       = FALSE;
    BOOL doAll       = FALSE;
    BOOL doPerfLib   = FALSE;
    BOOL doComSurr   = FALSE;
    BOOL doETW       = FALSE;
    BOOL doObjNS     = FALSE;
    BOOL doTOCTOU    = FALSE;
    BOOL doPrintSpl  = FALSE;
    BOOL doLSAPkg    = FALSE;
    BOOL doAppCert   = FALSE;
    BOOL doCredProv  = FALSE;
    BOOL doNetProv   = FALSE;
    BOOL doAutorun      = FALSE;
    BOOL doWmiProv      = FALSE;
    BOOL doALPC         = FALSE;
    BOOL doRPCSvc       = FALSE;
    BOOL doDriverIOCTL  = FALSE;
    BOOL doImpersonate  = FALSE;
    BOOL doCOMElevate   = FALSE;
    BOOL doSections     = FALSE;
    BOOL doZeroDay      = FALSE;
    /* New extended modules */
    BOOL doWinMsg       = FALSE;
    BOOL doMSIInstall   = FALSE;
    BOOL doAppInitDLL   = FALSE;
    BOOL doUACBypass    = FALSE;
    BOOL doLocalSvc     = FALSE;
    BOOL doWER          = FALSE;
    BOOL doSDB          = FALSE;
    BOOL doProcDACL     = FALSE;
    BOOL doDCOMHijack   = FALSE;
    BOOL doShellExt     = FALSE;
    BOOL doBITS         = FALSE;
    BOOL doTelemetry    = FALSE;
    BOOL doSecLogon     = FALSE;
    BOOL doFontProv     = FALSE;
    BOOL doHandles      = FALSE;
    BOOL doDotNetCLR    = FALSE;
    BOOL doCOMPlus      = FALSE;
    BOOL doIFEO         = FALSE;
    BOOL doWinlogon     = FALSE;
    BOOL doLSANotify    = FALSE;
    BOOL doHiveNM       = FALSE;
    BOOL doTimeProv     = FALSE;
    BOOL doActiveSetup  = FALSE;
    BOOL doCryptoProv   = FALSE;
    BOOL doPSHijack     = FALSE;
    BOOL doEAPProv      = FALSE;
    BOOL doVSSWriter    = FALSE;
    BOOL doUACPolicy    = FALSE;
    BOOL doSYSVOL       = FALSE;
    /* Wave 3 — additional novel modules */
    BOOL doSENSSubs     = FALSE;
    BOOL doWinSearch    = FALSE;
    BOOL doMMCodec      = FALSE;
    BOOL doMSDTC        = FALSE;
    BOOL doIISSurf      = FALSE;
    BOOL doBioWBF       = FALSE;
    BOOL doWinsockNSP   = FALSE;
    BOOL doCOMTreatAs   = FALSE;
    BOOL doMFTransform  = FALSE;
    BOOL doLAPSCG       = FALSE;
    wchar_t outFile[MAX_PATH] = {0};

    for (int i = 1; i < argc; i++) {
        if (ArgIs(argv[i], L"--ALL"))        doAll       = TRUE;
        else if (ArgIs(argv[i], L"--SERVICES"))   doServices  = TRUE;
        else if (ArgIs(argv[i], L"--TOKENS"))     doTokens    = TRUE;
        else if (ArgIs(argv[i], L"--CLSID"))      doCLSID     = TRUE;
        else if (ArgIs(argv[i], L"--PIPES"))      doPipes     = TRUE;
        else if (ArgIs(argv[i], L"--DLLSEARCH"))  doDLLSearch = TRUE;
        else if (ArgIs(argv[i], L"--REGISTRY"))   doRegistry  = TRUE;
        else if (ArgIs(argv[i], L"--SCHEDULED"))  doScheduled = TRUE;
        else if (ArgIs(argv[i], L"--DRIVERS"))    doDrivers   = TRUE;
        else if (ArgIs(argv[i], L"--ENV"))        doEnv       = TRUE;
        else if (ArgIs(argv[i], L"--PERFLIB"))    doPerfLib   = TRUE;
        else if (ArgIs(argv[i], L"--COMSURR"))    doComSurr   = TRUE;
        else if (ArgIs(argv[i], L"--ETW"))        doETW       = TRUE;
        else if (ArgIs(argv[i], L"--OBJNS"))      doObjNS     = TRUE;
        else if (ArgIs(argv[i], L"--TOCTOU"))     doTOCTOU    = TRUE;
        else if (ArgIs(argv[i], L"--PRINT"))      doPrintSpl  = TRUE;
        else if (ArgIs(argv[i], L"--LSA"))        doLSAPkg    = TRUE;
        else if (ArgIs(argv[i], L"--APPCERT"))    doAppCert   = TRUE;
        else if (ArgIs(argv[i], L"--CREDPROV"))   doCredProv  = TRUE;
        else if (ArgIs(argv[i], L"--NETPROV"))    doNetProv   = TRUE;
        else if (ArgIs(argv[i], L"--AUTORUN"))    doAutorun   = TRUE;
        else if (ArgIs(argv[i], L"--WMIPROV"))     doWmiProv      = TRUE;
        else if (ArgIs(argv[i], L"--ALPC"))        doALPC         = TRUE;
        else if (ArgIs(argv[i], L"--RPCSVC"))      doRPCSvc       = TRUE;
        else if (ArgIs(argv[i], L"--DRIVERIOCTL")) doDriverIOCTL  = TRUE;
        else if (ArgIs(argv[i], L"--IMPERSONATE")) doImpersonate  = TRUE;
        else if (ArgIs(argv[i], L"--COMELE"))      doCOMElevate   = TRUE;
        else if (ArgIs(argv[i], L"--SECTIONS"))    doSections     = TRUE;
        else if (ArgIs(argv[i], L"--ZERODAY"))     doZeroDay      = TRUE;
        else if (ArgIs(argv[i], L"--WMSG"))        doWinMsg       = TRUE;
        else if (ArgIs(argv[i], L"--MSIINSTALL"))  doMSIInstall   = TRUE;
        else if (ArgIs(argv[i], L"--APPINITDLL"))  doAppInitDLL   = TRUE;
        else if (ArgIs(argv[i], L"--UACBYPASS"))   doUACBypass    = TRUE;
        else if (ArgIs(argv[i], L"--LOCALSVC"))    doLocalSvc     = TRUE;
        else if (ArgIs(argv[i], L"--WER"))         doWER          = TRUE;
        else if (ArgIs(argv[i], L"--SDB"))         doSDB          = TRUE;
        else if (ArgIs(argv[i], L"--PROCDACL"))    doProcDACL     = TRUE;
        else if (ArgIs(argv[i], L"--DCOMHIJACK"))  doDCOMHijack   = TRUE;
        else if (ArgIs(argv[i], L"--SHELLEXT"))    doShellExt     = TRUE;
        else if (ArgIs(argv[i], L"--BITS"))        doBITS         = TRUE;
        else if (ArgIs(argv[i], L"--TELEMETRY"))   doTelemetry    = TRUE;
        else if (ArgIs(argv[i], L"--SECLOGON"))    doSecLogon     = TRUE;
        else if (ArgIs(argv[i], L"--FONTPROV"))    doFontProv     = TRUE;
        else if (ArgIs(argv[i], L"--HANDLES"))     doHandles      = TRUE;
        else if (ArgIs(argv[i], L"--DOTNETCLR"))   doDotNetCLR    = TRUE;
        else if (ArgIs(argv[i], L"--COMPLUS"))     doCOMPlus      = TRUE;
        else if (ArgIs(argv[i], L"--IFEO"))        doIFEO         = TRUE;
        else if (ArgIs(argv[i], L"--WINLOGON"))    doWinlogon     = TRUE;
        else if (ArgIs(argv[i], L"--LSANOTIFY"))   doLSANotify    = TRUE;
        else if (ArgIs(argv[i], L"--HIVENM"))      doHiveNM       = TRUE;
        else if (ArgIs(argv[i], L"--TIMEPROV"))    doTimeProv     = TRUE;
        else if (ArgIs(argv[i], L"--ACTIVESETUP")) doActiveSetup  = TRUE;
        else if (ArgIs(argv[i], L"--CRYPTOPROV"))  doCryptoProv   = TRUE;
        else if (ArgIs(argv[i], L"--PSHIJACK"))    doPSHijack     = TRUE;
        else if (ArgIs(argv[i], L"--EAPPROV"))     doEAPProv      = TRUE;
        else if (ArgIs(argv[i], L"--VSSWRITER"))   doVSSWriter    = TRUE;
        else if (ArgIs(argv[i], L"--UACPOLICY"))   doUACPolicy    = TRUE;
        else if (ArgIs(argv[i], L"--SYSVOL"))      doSYSVOL       = TRUE;
        else if (ArgIs(argv[i], L"--SENSSUBS"))    doSENSSubs     = TRUE;
        else if (ArgIs(argv[i], L"--WINSEARCH"))   doWinSearch    = TRUE;
        else if (ArgIs(argv[i], L"--MMCODEC"))     doMMCodec      = TRUE;
        else if (ArgIs(argv[i], L"--MSDTC"))       doMSDTC        = TRUE;
        else if (ArgIs(argv[i], L"--IIS"))         doIISSurf      = TRUE;
        else if (ArgIs(argv[i], L"--BIOWBF"))      doBioWBF       = TRUE;
        else if (ArgIs(argv[i], L"--WINSOCKNSP"))  doWinsockNSP   = TRUE;
        else if (ArgIs(argv[i], L"--COMTREATAS"))  doCOMTreatAs   = TRUE;
        else if (ArgIs(argv[i], L"--MFTRANSFORM")) doMFTransform  = TRUE;
        else if (ArgIs(argv[i], L"--LAPSCG"))      doLAPSCG       = TRUE;
        else if (ArgIs(argv[i], L"--NO-COLOR"))    g_noColor      = TRUE;
        else if (ArgIs(argv[i], L"--OUTPUT") && i + 1 < argc) {
            wcsncpy(outFile, argv[++i], _countof(outFile) - 1);
        }
        else if (ArgIs(argv[i], L"--help") || ArgIs(argv[i], L"-h") ||
                 ArgIs(argv[i], L"/?")) {
            Banner();
            Usage(argv[0]);
            return 0;
        }
    }

    if (!doAll && !doZeroDay &&
        !doServices && !doTokens && !doCLSID  && !doPipes  &&
        !doDLLSearch && !doRegistry && !doScheduled && !doDrivers && !doEnv &&
        !doPerfLib && !doComSurr && !doETW && !doObjNS && !doTOCTOU &&
        !doPrintSpl && !doLSAPkg && !doAppCert && !doCredProv &&
        !doNetProv && !doAutorun && !doWmiProv &&
        !doALPC && !doRPCSvc && !doDriverIOCTL &&
        !doImpersonate && !doCOMElevate && !doSections &&
        !doWinMsg && !doMSIInstall && !doAppInitDLL && !doUACBypass && !doLocalSvc &&
        !doWER && !doSDB && !doProcDACL && !doDCOMHijack && !doShellExt &&
        !doBITS && !doTelemetry && !doSecLogon && !doFontProv &&
        !doHandles && !doDotNetCLR && !doCOMPlus &&
        !doIFEO && !doWinlogon && !doLSANotify && !doHiveNM && !doTimeProv &&
        !doActiveSetup && !doCryptoProv && !doPSHijack && !doEAPProv &&
        !doVSSWriter && !doUACPolicy && !doSYSVOL &&
        !doSENSSubs && !doWinSearch && !doMMCodec && !doMSDTC && !doIISSurf &&
        !doBioWBF && !doWinsockNSP && !doCOMTreatAs && !doMFTransform && !doLAPSCG)
    {
        Banner();
        Usage(argv[0]);
        return 1;
    }

    /* --ZERODAY: enable all novel/research modules (not the standard Ferrum-Go set) */
    if (doZeroDay) {
        doPerfLib = doComSurr = doETW = doObjNS = doTOCTOU =
        doPrintSpl = doLSAPkg = doAppCert = doCredProv =
        doNetProv = doAutorun = doWmiProv =
        doALPC = doRPCSvc = doDriverIOCTL =
        doImpersonate = doCOMElevate = doSections =
        /* New extended modules */
        doWinMsg = doMSIInstall = doAppInitDLL = doUACBypass = doLocalSvc =
        doWER = doSDB = doProcDACL = doDCOMHijack = doShellExt =
        doBITS = doTelemetry = doSecLogon = doFontProv =
        doHandles = doDotNetCLR = doCOMPlus =
        doIFEO = doWinlogon = doLSANotify = doHiveNM = doTimeProv =
        doActiveSetup = doCryptoProv = doPSHijack = doEAPProv =
        doVSSWriter = doUACPolicy = doSYSVOL =
        doSENSSubs = doWinSearch = doMMCodec = doMSDTC = doIISSurf =
        doBioWBF = doWinsockNSP = doCOMTreatAs = doMFTransform = doLAPSCG = TRUE;
    }

    if (doAll) {
        doServices = doTokens = doCLSID = doPipes = doDLLSearch =
        doRegistry = doScheduled = doDrivers = doEnv =
        doPerfLib  = doComSurr  = doETW = doObjNS = doTOCTOU =
        doPrintSpl = doLSAPkg   = doAppCert = doCredProv =
        doNetProv  = doAutorun  = doWmiProv =
        doALPC     = doRPCSvc   = doDriverIOCTL =
        doImpersonate = doCOMElevate = doSections =
        /* New extended modules */
        doWinMsg = doMSIInstall = doAppInitDLL = doUACBypass = doLocalSvc =
        doWER = doSDB = doProcDACL = doDCOMHijack = doShellExt =
        doBITS = doTelemetry = doSecLogon = doFontProv =
        doHandles = doDotNetCLR = doCOMPlus =
        doIFEO = doWinlogon = doLSANotify = doHiveNM = doTimeProv =
        doActiveSetup = doCryptoProv = doPSHijack = doEAPProv =
        doVSSWriter = doUACPolicy = doSYSVOL =
        doSENSSubs = doWinSearch = doMMCodec = doMSDTC = doIISSurf =
        doBioWBF = doWinsockNSP = doCOMTreatAs = doMFTransform = doLAPSCG = TRUE;
    }

    /* ---- Open output file if requested ---- */
    if (*outFile) {
        g_outFile = _wfopen(outFile, L"w, ccs=UTF-16LE");
        if (!g_outFile)
            wprintf(L"[!] Cannot open output file: %s\n", outFile);
    }

    /* ---- Banner ---- */
    if (!g_noColor) Banner();

    /* ---- System info header ---- */
    wchar_t username[128] = {0}, hostname[128] = {0};
    DWORD   uCch = _countof(username), hCch = _countof(hostname);
    GetUserNameW(username, &uCch);
    GetComputerNameW(hostname, &hCch);

    OSVERSIONINFOEXW vi = { .dwOSVersionInfoSize = sizeof(vi) };
#pragma warning(suppress: 4996)
    GetVersionExW((LPOSVERSIONINFOW)&vi);

    wprintf(L"  Host : %s\\%s\n", hostname, username);
    wprintf(L"  OS   : Windows %lu.%lu Build %lu\n",
            vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);

    /* Check if running as admin */
    BOOL isAdmin = FALSE;
    PSID adminGrp = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0,0,0,0,0,0, &adminGrp)) {
        CheckTokenMembership(NULL, adminGrp, &isAdmin);
        FreeSid(adminGrp);
    }
    wprintf(L"  Admin: %s\n", isAdmin ? L"YES" : L"No (some checks may be limited)");
    wprintf(L"\n");

    /* ---- Zero-day research mode preamble ---- */
    if (doZeroDay) {
        wprintf(
            CLR_BOLD CLR_MAGENTA
            L"\n  ╔══════════════════════════════════════════════════════════╗\n"
            L"  ║         0-DAY RESEARCH MODE  (--ZERODAY)                ║\n"
            L"  ╚══════════════════════════════════════════════════════════╝\n"
            CLR_RESET
            CLR_YELLOW
            L"  Running all novel attack-surface modules.\n"
            L"  Each finding is a CANDIDATE — not a confirmed vulnerability.\n"
            L"  Workflow: Ferrum/C → ProcMon → IDA Pro → WinDbg → WinAFL\n"
            L"  See: docs/0DAY_RESEARCH_WORKFLOW.md for full methodology.\n\n"
            CLR_RESET);
    }

    /* ---- Run modules ---- */
    if (doTokens)    Module_Tokens();
    if (doServices)  Module_Services();
    if (doCLSID)     Module_CLSID();
    if (doPipes)     Module_Pipes();
    if (doDLLSearch) Module_DLLSearch();
    if (doRegistry)  Module_Registry();
    if (doScheduled) Module_Scheduled();
    if (doDrivers)   Module_Drivers();
    if (doEnv)       Module_Env();
    if (doPerfLib)   Module_PerfLib();
    if (doComSurr)   Module_ComSurrogate();
    if (doETW)       Module_ETWProvider();
    if (doObjNS)     Module_ObjNamespace();
    if (doTOCTOU)    Module_TOCTOU();
    if (doPrintSpl)  Module_PrintSpooler();
    if (doLSAPkg)    Module_LSAPackage();
    if (doAppCert)   Module_AppCertDLL();
    if (doCredProv)  Module_CredentialProvider();
    if (doNetProv)   Module_NetworkProvider();
    if (doAutorun)      Module_Autorun();
    if (doWmiProv)      Module_WmiProvider();
    if (doALPC)         Module_ALPCSurface();
    if (doRPCSvc)       Module_RPCEndpoint();
    if (doDriverIOCTL)  Module_DriverIOCTL();
    if (doImpersonate)  Module_ImpersonateHunter();
    if (doCOMElevate)   Module_COMAutoElevate();
    if (doSections)     Module_SectionAudit();
    /* New extended modules */
    if (doWinMsg)       Module_WinMsgSurface();
    if (doMSIInstall)   Module_AlwaysInstallElevated();
    if (doAppInitDLL)   Module_AppInitDLL();
    if (doUACBypass)    Module_UACBypassHKCU();
    if (doLocalSvc)     Module_LocalServiceScan();
    if (doWER)          Module_WERHandler();
    if (doSDB)          Module_AppCompatSDB();
    if (doProcDACL)     Module_ProcessDACL();
    if (doDCOMHijack)   Module_DcomHijack();
    if (doShellExt)     Module_ShellHandler();
    if (doBITS)         Module_BitsSurface();
    if (doTelemetry)    Module_TelemetrySurface();
    if (doSecLogon)     Module_SecondaryLogon();
    if (doFontProv)     Module_FontProvider();
    if (doHandles)      Module_HandleInherit();
    if (doDotNetCLR)    Module_DotNetCLR();
    if (doCOMPlus)      Module_ComPlus();
    /* Wave 2 — extended novel modules */
    if (doIFEO)         Module_IFEOHijack();
    if (doWinlogon)     Module_WinlogonPlugins();
    if (doLSANotify)    Module_LSANotify();
    if (doHiveNM)       Module_HiveNightmare();
    if (doTimeProv)     Module_TimeProvider();
    if (doActiveSetup)  Module_ActiveSetup();
    if (doCryptoProv)   Module_CryptoProvider();
    if (doPSHijack)     Module_PSHijack();
    if (doEAPProv)      Module_EAPProvider();
    if (doVSSWriter)    Module_VSSWriter();
    if (doUACPolicy)    Module_UACPolicy();
    if (doSYSVOL)       Module_SYSVOLScripts();
    /* Wave 3 — additional novel modules */
    if (doSENSSubs)     Module_SENSSubscriptions();
    if (doWinSearch)    Module_WinSearchIFilter();
    if (doMMCodec)      Module_MultimediaCodec();
    if (doMSDTC)        Module_MSDTCSurface();
    if (doIISSurf)      Module_IISSurface();
    if (doBioWBF)       Module_BiometricWBF();
    if (doWinsockNSP)   Module_WinsockNSP();
    if (doCOMTreatAs)   Module_COMTreatAs();
    if (doMFTransform)  Module_MFTransform();
    if (doLAPSCG)       Module_LAPSCredGuard();

    wprintf(L"\n");
    if (!g_noColor)
        wprintf(CLR_GREEN L"  [+] Scan complete.\n" CLR_RESET);
    else
        wprintf(L"  [+] Scan complete.\n");

    /* ---- Zero-day research mode postamble ---- */
    if (doZeroDay) {
        wprintf(
            CLR_BOLD CLR_CYAN
            L"\n  ═══════════════════════ NEXT STEPS ════════════════════════\n"
            CLR_RESET
            L"  1. Review each CRITICAL/HIGH finding above.\n"
            L"  2. For DLL/EXE path findings: confirm writability in a shell,\n"
            L"     then write a minimal LPE payload DLL.\n"
            L"  3. For ALPC/RPC findings: open in RpcView or Process Hacker,\n"
            L"     identify hosting process, load DLL in IDA Pro.\n"
            L"  4. For driver IOCTL findings: enumerate IOCTL codes in IDA,\n"
            L"     fuzz with WinAFL or custom ioctl harness.\n"
            L"  5. For registry persistence findings: test write access, then\n"
            L"     craft minimal DLL with required export.\n"
            L"  6. Correlate with ProcMon: run ProcMon with filters for the\n"
            L"     target process to watch actual filesystem/registry activity.\n"
            L"  7. Kernel debug with WinDbg for any crash during testing.\n"
            L"  Full workflow: docs/0DAY_RESEARCH_WORKFLOW.md\n"
            CLR_RESET L"\n");
    }

    if (*outFile && g_outFile) {
        fclose(g_outFile);
        wprintf(L"  Report saved to: %s\n", outFile);
    }

    return 0;
}

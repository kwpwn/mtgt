#pragma once
#ifndef FERRUM_COMMON_H
#define FERRUM_COMMON_H

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601   /* Windows 7+ */
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <sddl.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* -----------------------------------------------------------------------
 * Console colour codes (VT100, enabled explicitly in main)
 * --------------------------------------------------------------------- */
#define CLR_RED     L"\033[91m"
#define CLR_YELLOW  L"\033[93m"
#define CLR_GREEN   L"\033[92m"
#define CLR_CYAN    L"\033[96m"
#define CLR_MAGENTA L"\033[95m"
#define CLR_WHITE   L"\033[97m"
#define CLR_BOLD    L"\033[1m"
#define CLR_RESET   L"\033[0m"

/* -----------------------------------------------------------------------
 * Severity
 * --------------------------------------------------------------------- */
typedef enum {
    SEV_INFO     = 0,
    SEV_LOW      = 1,
    SEV_MEDIUM   = 2,
    SEV_HIGH     = 3,
    SEV_CRITICAL = 4
} Severity;

/* -----------------------------------------------------------------------
 * A single enumerated finding
 * --------------------------------------------------------------------- */
typedef struct {
    Severity    severity;
    wchar_t     module[64];
    wchar_t     target[MAX_PATH * 2];
    wchar_t     reason[512];
} Finding;

/* -----------------------------------------------------------------------
 * Global output file (NULL = stdout only)
 * --------------------------------------------------------------------- */
extern FILE *g_outFile;
extern BOOL  g_noColor;

/* -----------------------------------------------------------------------
 * Output helpers
 * --------------------------------------------------------------------- */
void PrintHeader(const wchar_t *title);
void PrintFinding(const Finding *f);
void PrintInfo(const wchar_t *fmt, ...);

/* -----------------------------------------------------------------------
 * ACL / writability helpers
 * --------------------------------------------------------------------- */

/* Returns TRUE if the current process token has GENERIC_WRITE access to
 * the named filesystem object (file or directory).                       */
BOOL IsFileWritable(LPCWSTR path);

/* Returns TRUE if the current user can write to a directory (create files). */
BOOL IsDirWritable(LPCWSTR dir);

/* Returns TRUE if the current user has KEY_SET_VALUE on a registry key.  */
BOOL IsRegKeyWritable(HKEY hRoot, LPCWSTR subkey);

/* Returns TRUE if path starts with a user-writable base:
 * \Users\  \Temp\  \ProgramData\  %TEMP%  %APPDATA%                     */
BOOL IsUserWritablePath(LPCWSTR path);

/* -----------------------------------------------------------------------
 * Token / process helpers
 * --------------------------------------------------------------------- */

/* Fill username (DOMAIN\user) for the given process id.
 * Returns FALSE if process can't be opened / token query fails.          */
BOOL GetProcessUser(DWORD pid, LPWSTR buf, DWORD bufCch);

/* Returns the mandatory integrity level (TOKEN_MANDATORY_LABEL SID RID)
 * e.g. SECURITY_MANDATORY_SYSTEM_RID (0x4000) or 0 on error.           */
DWORD GetProcessIntegrityRID(HANDLE hProc);

/* Returns TRUE if the token is marked as elevated (UAC full admin token). */
BOOL IsProcessElevated(HANDLE hProc);

/* -----------------------------------------------------------------------
 * String helpers
 * --------------------------------------------------------------------- */

/* Case-insensitive wchar substring search. */
BOOL WcsContainsI(LPCWSTR haystack, LPCWSTR needle);

/* Split wide-char string on delimiters, calls cb for each token.
 * cb receives the token (null-terminated) and the user ctx pointer.
 * Returns the number of tokens found.                                    */
typedef void (*SplitCb)(LPCWSTR token, void *ctx);
int WcsSplit(LPCWSTR str, wchar_t delim, SplitCb cb, void *ctx);

/* Extract the bare executable path from a service ImagePath (strip args,
 * expand environment variables, remove surrounding quotes).             */
BOOL ExtractExePath(LPCWSTR imagePath, LPWSTR out, DWORD outCch);

/* -----------------------------------------------------------------------
 * Module entry points
 * --------------------------------------------------------------------- */
void Module_Services(void);
void Module_Tokens(void);
void Module_CLSID(void);
void Module_Pipes(void);
void Module_DLLSearch(void);
void Module_Registry(void);
void Module_Scheduled(void);
void Module_Drivers(void);
void Module_Env(void);
void Module_PerfLib(void);       /* Perf counter DLL — underexplored surface */
void Module_ComSurrogate(void);  /* COM Surrogate dllhost DLL paths          */
void Module_ETWProvider(void);       /* ETW publisher DLL writability             */
void Module_ObjNamespace(void);      /* NT Object Namespace directory ACL audit   */
void Module_TOCTOU(void);            /* Shared-write dir / oplock race surface    */
void Module_PrintSpooler(void);      /* Print monitor/processor DLLs (spoolsv)   */
void Module_LSAPackage(void);        /* LSA auth/security package DLLs (lsass)   */
void Module_AppCertDLL(void);        /* AppCert DLLs (every CreateProcess)        */
void Module_CredentialProvider(void);/* Credential provider DLLs (logonui/SYSTEM) */
void Module_NetworkProvider(void);   /* Network provider DLLs (mpr.dll)           */
void Module_Autorun(void);           /* Startup/autorun path writability           */
void Module_WmiProvider(void);       /* WMI provider DLLs (WmiPrvSE.exe SYSTEM)   */
void Module_ALPCSurface(void);       /* ALPC port DACL audit (novel, no public tool)*/
void Module_RPCEndpoint(void);       /* RPC endpoint mapper + unauth access test   */
void Module_DriverIOCTL(void);       /* Kernel driver IOCTL surface + BYOVD DB    */
void Module_ImpersonateHunter(void); /* Dangerous token privilege audit (Potato+)  */
void Module_COMAutoElevate(void);    /* COM auto-elevation surface (UAC bypass)    */
void Module_SectionAudit(void);      /* Named section object ACL audit             */

/* -----------------------------------------------------------------------
 * New modules — 0-day research extensions
 * --------------------------------------------------------------------- */
void Module_WinMsgSurface(void);     /* WM_COPYDATA/WM_DDE cross-IL window message */
void Module_AlwaysInstallElevated(void); /* AlwaysInstallElevated MSI policy       */
void Module_AppInitDLL(void);        /* AppInit_DLLs injection surface             */
void Module_UACBypassHKCU(void);     /* UAC bypass via HKCU class hijack          */
void Module_LocalServiceScan(void);  /* Localhost privileged TCP service scan      */
void Module_WERHandler(void);        /* WER/AeDebug JIT debugger + crash DLLs     */
void Module_AppCompatSDB(void);      /* AppCompat shim database DLL injection      */
void Module_ProcessDACL(void);       /* Process DACL audit (DUP_HANDLE/VM_WRITE)  */
void Module_DcomHijack(void);        /* DCOM LocalServer32 EXE path hijacking      */
void Module_ShellHandler(void);      /* Shell extension DLL → explorer High IL     */
void Module_BitsSurface(void);       /* BITS service DLL/notification LPE          */
void Module_TelemetrySurface(void);  /* DiagTrack perf counter DLL surface         */
void Module_SecondaryLogon(void);    /* seclogon service SYSTEM token leakage      */
void Module_FontProvider(void);      /* Font provider DLL + font cache surface     */
void Module_HandleInherit(void);     /* Inheritable handle leakage from SYSTEM     */
void Module_DotNetCLR(void);         /* COR_PROFILER DLL injection into .NET SYSTEM*/
void Module_ComPlus(void);           /* COM+ server app DLL writability            */
void Module_IFEOHijack(void);        /* IFEO debugger/VerifierDll injection T1546.012 */
void Module_WinlogonPlugins(void);   /* Winlogon Notify/Userinit/Shell hijack T1547.004 */
void Module_LSANotify(void);         /* LSA Notification Packages + lsass PPL audit */
void Module_HiveNightmare(void);     /* CVE-2021-36934 SAM/SYSTEM hive readability  */
void Module_TimeProvider(void);      /* W32Time provider DLL hijacking (novel)       */
void Module_ActiveSetup(void);       /* Active Setup StubPath T1547.014              */
void Module_CryptoProvider(void);    /* CryptoAPI CSP / SCHANNEL DLL hijacking       */
void Module_PSHijack(void);          /* PowerShell profile + PSModulePath hijack     */
void Module_EAPProvider(void);       /* RAS/VPN EAP method DLL hijacking (novel)     */
void Module_VSSWriter(void);         /* VSS Writer COM server EXE hijacking (novel)  */
void Module_UACPolicy(void);         /* UAC policy + Defender exclusion audit        */
void Module_SYSVOLScripts(void);     /* Domain SYSVOL/GPO logon script writability   */

/* -----------------------------------------------------------------------
 * Wave 3 — extended novel + undiscovered surfaces (10 additional modules)
 * --------------------------------------------------------------------- */
void Module_SENSSubscriptions(void); /* NOVEL: SENS/COM+ event subscription DLL hijack (SYSTEM on logon/net) */
void Module_WinSearchIFilter(void);  /* SearchIndexer.exe (SYSTEM) IFilter/Protocol Handler DLL hijack       */
void Module_MultimediaCodec(void);   /* Drivers32 multimedia codec DLL hijacking + Media Foundation handlers */
void Module_MSDTCSurface(void);      /* MSDTC XA transaction DLL hijacking (NetworkService → Potato → SYSTEM)*/
void Module_IISSurface(void);        /* IIS native module/ISAPI DLL hijacking + applicationHost.config write */
void Module_BiometricWBF(void);      /* NOVEL: WBF sensor/engine/storage adapter DLL hijacking (SYSTEM)     */
void Module_WinsockNSP(void);        /* Winsock NSP provider DLL hijacking (loads into all socket processes)  */
void Module_COMTreatAs(void);        /* COM TreatAs/AutoConvertTo CLSID redirect + Elevation Moniker audit   */
void Module_MFTransform(void);       /* Media Foundation Transform DLL hijacking (FrameServer/Recall=SYSTEM) */
void Module_LAPSCredGuard(void);     /* LAPS config + Credential Guard + VBS/HVCI + Secure Boot status       */

#endif /* FERRUM_COMMON_H */

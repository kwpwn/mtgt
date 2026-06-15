/*
 * alpc_surface.c — ALPC Port Security Surface Audit
 *
 * WHAT IS ALPC:
 *   Advanced Local Procedure Call (ALPC) is the kernel-mode IPC mechanism
 *   underlying ALL Windows local communication: RPC, COM, named pipes,
 *   csrss, lsass, Task Scheduler, etc. Every significant Windows subsystem
 *   communicates via ALPC internally.
 *
 * WHY ALPC IS A 0-DAY GOLDMINE:
 *   - ALPC is complex, undocumented, and constantly evolving
 *   - Every SYSTEM service that accepts connections via ALPC is a potential
 *     privilege escalation target if:
 *     a) The port DACL allows non-admin connection
 *     b) The server processes messages without proper validation
 *   - Historical bugs: multiple LPE CVEs exploited via ALPC message
 *     handling bugs in csrss.exe, lsass.exe, win32k, etc.
 *   - NO public automated tool enumerates ALPC port accessibility
 *
 * THIS MODULE:
 *   1. Enumerates named ALPC ports in \RPC Control\ object directory
 *      (where most named ALPC ports live)
 *   2. For each port, attempts NtAlpcConnectPort with 100ms timeout
 *   3. Classifies result:
 *      - STATUS_SUCCESS or STATUS_TIMEOUT → DACL allows connection
 *        (timeout = server not processing our connect msg, but ACL ok)
 *      - STATUS_ACCESS_DENIED → DACL blocks us (expected for protected ports)
 *      - STATUS_OBJECT_NAME_NOT_FOUND → port gone (race condition)
 *   4. Reports all ports where current user CAN connect as attack surface
 *
 * WHAT TO DO WITH FINDINGS:
 *   Any ALPC port accessible to non-admin users AND owned by a SYSTEM
 *   service is worth manual research. The question is:
 *   "What happens if I send a malformed message to this port?"
 *
 *   Research tool: AlpcMon (by Alex Ionescu) to log ALPC traffic.
 *   Fuzzing: use the NtAlpcSendWaitReceivePort primitive.
 *
 * NT ALPC TYPES (from leaked/reversed headers):
 *   NtAlpcConnectPort is exported from ntdll.dll on all Windows versions.
 *   The ALPC_PORT_ATTRIBUTES and PORT_MESSAGE structures below are derived
 *   from Windows Internals book and public research (Alex Ionescu, etc.).
 *
 * REFERENCES:
 *   Alex Ionescu — ALPC Windows Internals
 *   CVE-2018-8440 — ALPC LPE in Task Scheduler
 *   CVE-2017-0213 — COM Aggregate Marshaler ALPC
 *   SandboxEscaper — multiple ALPC-based bugs (2018-2019)
 */

#include "../common.h"

/* -----------------------------------------------------------------------
 * ALPC structures (not in public SDK headers)
 * Derived from Windows Internals + ntddk.h reverse
 * --------------------------------------------------------------------- */
typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG                       Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T                      MaxMessageLength;
    SIZE_T                      MemoryBandwidth;
    SIZE_T                      MaxPoolUsage;
    SIZE_T                      MaxSectionSize;
    SIZE_T                      MaxViewSize;
    SIZE_T                      MaxTotalSectionSize;
    ULONG                       DupObjectTypes;
#ifdef _WIN64
    ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

#ifndef PORT_MESSAGE_DEFINED
#define PORT_MESSAGE_DEFINED
typedef struct _PORT_MESSAGE {
    union {
        struct { SHORT DataLength; SHORT TotalLength; } s1;
        ULONG Length;
    } u1;
    union {
        struct { SHORT Type; SHORT DataInfoOffset; } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE, *PPORT_MESSAGE;
#endif

/* NT STATUS codes */
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED    ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT          ((NTSTATUS)0x00000102L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES  ((NTSTATUS)0x8000001AL)
#endif

typedef NTSTATUS (NTAPI *PFN_NtAlpcConnectPort)(
    PHANDLE                PortHandle,
    PUNICODE_STRING        PortName,
    POBJECT_ATTRIBUTES     ObjectAttributes,
    PALPC_PORT_ATTRIBUTES  PortAttributes,
    ULONG                  Flags,
    PSID                   RequiredServerSid,
    PPORT_MESSAGE          ConnectionMessage,
    PULONG                 BufferLength,
    PVOID                  OutMessageAttributes,
    PVOID                  InMessageAttributes,
    PLARGE_INTEGER         Timeout
);

typedef NTSTATUS (NTAPI *PFN_NtOpenDirectoryObject)(
    PHANDLE            DirectoryHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION_ALPC, *POBJECT_DIRECTORY_INFORMATION_ALPC;

typedef NTSTATUS (NTAPI *PFN_NtQueryDirectoryObject)(
    HANDLE  DirectoryHandle,
    PVOID   Buffer,
    ULONG   BufferLength,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG  Context,
    PULONG  ReturnLength
);

#define DIRECTORY_QUERY     0x0001
#define DIRECTORY_TRAVERSE  0x0002

static PFN_NtAlpcConnectPort    g_NtAlpcConnect  = NULL;
static PFN_NtOpenDirectoryObject g_NtOpenDir2     = NULL;
static PFN_NtQueryDirectoryObject g_NtQueryDir2   = NULL;

static BOOL AlpcInit(void) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) return FALSE;
    g_NtAlpcConnect = (PFN_NtAlpcConnectPort) GetProcAddress(h, "NtAlpcConnectPort");
    g_NtOpenDir2    = (PFN_NtOpenDirectoryObject) GetProcAddress(h, "NtOpenDirectoryObject");
    g_NtQueryDir2   = (PFN_NtQueryDirectoryObject)GetProcAddress(h, "NtQueryDirectoryObject");
    return (g_NtAlpcConnect && g_NtOpenDir2 && g_NtQueryDir2);
}

/* -----------------------------------------------------------------------
 * Try to connect to a named ALPC port.
 * Returns:
 *   0 = connected (DACL allowed)
 *   1 = timeout (DACL allowed, server didn't reply)
 *   2 = access denied
 *   3 = port not found / other error
 * --------------------------------------------------------------------- */
static int TryAlpcConnect(LPCWSTR ntPortPath) {
    UNICODE_STRING portName;
    portName.Buffer        = (PWSTR)ntPortPath;
    portName.Length        = (USHORT)(wcslen(ntPortPath) * sizeof(wchar_t));
    portName.MaximumLength = portName.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    PORT_MESSAGE connMsg;
    ZeroMemory(&connMsg, sizeof(connMsg));
    connMsg.u1.s1.TotalLength = (SHORT)sizeof(PORT_MESSAGE);
    connMsg.u1.s1.DataLength  = 0;

    ALPC_PORT_ATTRIBUTES portAttrs;
    ZeroMemory(&portAttrs, sizeof(portAttrs));
    portAttrs.MaxMessageLength = 0x1000;
    portAttrs.SecurityQos.Length              = sizeof(SECURITY_QUALITY_OF_SERVICE);
    portAttrs.SecurityQos.ImpersonationLevel  = SecurityIdentification;
    portAttrs.SecurityQos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    portAttrs.SecurityQos.EffectiveOnly       = TRUE;

    LARGE_INTEGER timeout;
    timeout.QuadPart = -1000000LL; /* 100ms in 100-nanosecond units */

    HANDLE hPort = NULL;
    ULONG  bufLen = sizeof(PORT_MESSAGE);

    NTSTATUS st = g_NtAlpcConnect(
        &hPort, &portName, &oa, &portAttrs,
        0,   /* Flags: 0 = synchronous connect */
        NULL,
        &connMsg, &bufLen,
        NULL, NULL,
        &timeout
    );

    if (hPort) {
        CloseHandle(hPort);
        return 0; /* connected */
    }

    if (st == STATUS_TIMEOUT)      return 1; /* timeout = DACL ok, server not responding */
    if (st == STATUS_ACCESS_DENIED) return 2; /* DACL blocked */
    return 3; /* other: port gone, wrong type, etc. */
}

/* -----------------------------------------------------------------------
 * Enumerate named ALPC ports in a directory (e.g. \RPC Control\)
 * --------------------------------------------------------------------- */
static void EnumAlpcDirectory(LPCWSTR ntDirPath, DWORD *findings) {
    UNICODE_STRING ustr;
    ustr.Buffer        = (PWSTR)ntDirPath;
    ustr.Length        = (USHORT)(wcslen(ntDirPath) * sizeof(wchar_t));
    ustr.MaximumLength = ustr.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &ustr, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    NTSTATUS st = g_NtOpenDir2(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if (st != 0 || !hDir) {
        PrintInfo(L"    [skip] %s — cannot open (0x%08lX)\n", ntDirPath, (ULONG)st);
        return;
    }

    BYTE   buf[2048];
    ULONG  ctx = 0, retLen = 0;
    BOOL   restart = TRUE;
    DWORD  total = 0, accessible = 0;

    PrintInfo(L"    Enumerating: %s\n", ntDirPath);

    while (TRUE) {
        st = g_NtQueryDir2(hDir, buf, sizeof(buf), TRUE, restart, &ctx, &retLen);
        restart = FALSE;
        if (st == STATUS_NO_MORE_ENTRIES || (st != 0 && st != 0x00000105)) break;

        POBJECT_DIRECTORY_INFORMATION_ALPC info = (POBJECT_DIRECTORY_INFORMATION_ALPC)buf;
        if (!info->Name.Buffer || info->Name.Length == 0) break;

        /* Only process "ALPC Port" typed objects */
        wchar_t typeName[64] = {0};
        if (info->TypeName.Buffer && info->TypeName.Length > 0) {
            int n = min(info->TypeName.Length / 2, 63);
            wcsncpy(typeName, info->TypeName.Buffer, n);
        }
        if (_wcsicmp(typeName, L"ALPC Port") != 0) continue;

        wchar_t portName[256] = {0};
        {
            int n = min(info->Name.Length / 2, 255);
            wcsncpy(portName, info->Name.Buffer, n);
        }
        total++;

        /* Build full NT path */
        wchar_t fullPath[512] = {0};
        _snwprintf(fullPath, _countof(fullPath), L"%s\\%s", ntDirPath, portName);

        /* Try to connect */
        int result = TryAlpcConnect(fullPath);

        if (result == 0 || result == 1) {
            accessible++;
            Finding f;
            f.severity = SEV_HIGH;
            wcscpy(f.module, L"ALPC_SURFACE");
            wcsncpy(f.target, fullPath, _countof(f.target) - 1);
            _snwprintf(f.reason, _countof(f.reason),
                L"ALPC port is %s by current user. "
                L"This port accepts connections from non-admin processes. "
                L"Research target: send malformed ALPC messages → check for "
                L"heap corruption, uninitialized memory, type confusion. "
                L"Tool: NtAlpcSendWaitReceivePort with fuzzed PORT_MESSAGE. "
                L"Status: %s",
                result == 0 ? L"CONNECTABLE" : L"ACCESSIBLE (timeout, server not responding)",
                result == 0 ? L"STATUS_SUCCESS (full connection)" : L"STATUS_TIMEOUT (DACL ok)");
            PrintFinding(&f);
            (*findings)++;
        }
        /* result == 2 (access denied): expected, not reported */
        /* result == 3 (other error): skip */
    }

    CloseHandle(hDir);
    PrintInfo(L"    ALPC ports found: %lu  |  Accessible to current user: %lu\n",
              total, accessible);
}

/* -----------------------------------------------------------------------
 * Module entry
 * --------------------------------------------------------------------- */
void Module_ALPCSurface(void) {
    PrintHeader(L"ALPC PORT SURFACE AUDIT  [Novel — no public tool enumerates this]");

    PrintInfo(
        L"  ALPC is the kernel IPC backbone for ALL Windows subsystems.\n"
        L"  Ports accessible to non-admin = attack surface for message fuzzing.\n"
        L"  Historical 0-days: CVE-2018-8440 (Task Scheduler), SandboxEscaper class.\n\n");

    if (!AlpcInit()) {
        PrintInfo(L"  [!] Failed to load NtAlpcConnectPort from ntdll.dll\n");
        return;
    }

    DWORD findings = 0;

    /* Primary ALPC port directories */
    static const wchar_t *dirs[] = {
        L"\\RPC Control",
        L"\\Windows",
        NULL
    };

    for (int i = 0; dirs[i]; i++)
        EnumAlpcDirectory(dirs[i], &findings);

    PrintInfo(L"\n");
    if (findings == 0) {
        PrintInfo(L"  No accessible ALPC ports found (all DACL-protected — expected on patched systems).\n");
    } else {
        PrintInfo(L"  Accessible ALPC ports: %lu\n\n", findings);
        PrintInfo(
            L"  RESEARCH METHODOLOGY:\n"
            L"    1. Identify which service owns the port:\n"
            L"       Process Hacker → Find Handles → ALPC Port\n"
            L"       OR: WinObj.exe → \\RPC Control\\ → Properties\n"
            L"    2. Capture normal ALPC traffic:\n"
            L"       AlpcMon.exe (Alex Ionescu) or Process Monitor\n"
            L"    3. Replay + mutate messages:\n"
            L"       Use NtAlpcSendWaitReceivePort with modified PORT_MESSAGE\n"
            L"       Fuzz: message type, data length, port section references\n"
            L"    4. Monitor for crashes / privilege mismatches:\n"
            L"       WinDbg kernel debugging + page heap on target service\n"
            L"    References:\n"
            L"      CVE-2018-8440: ALPC in Task Scheduler (SandboxEscaper)\n"
            L"      Alex Ionescu ALPC research: recon.cx/2008/a/aionescu.pdf\n");
    }
}

